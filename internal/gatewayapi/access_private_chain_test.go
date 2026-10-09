/*
Copyright 2026 The Flareway Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gatewayapi

import (
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// privateWildcardInputs makes "https" a private TLS listener for
// *.example.com backed by a ready VirtualNetwork, so applications can claim
// the hosts routed on it.
func privateWildcardInputs(t *testing.T) Inputs {
	t.Helper()
	in := accessInputs(false)
	in.Gateway.Spec.Listeners[0] = gatewayv1.Listener{
		Name: "https", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}},
	}
	in.Secrets = []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "private-cert", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       validTLSSecretData(t),
	}}
	in.CloudflareTunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
		Name: "https", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "private"},
	}}
	in.CloudflareTunnel.Spec.AccountRef = corev1.LocalObjectReference{Name: "account"}
	in.VirtualNetworks = []v1alpha1.VirtualNetwork{{
		ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: "default"},
		Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
		Status: v1alpha1.VirtualNetworkStatus{
			VirtualNetworkID: "vnet-private",
			Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
		},
	}}
	in.CloudflareAccount.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	return in
}

// privateWildcardRoute serves host on the private listener; ruleName names
// its single rule so an AccessApplication can target it.
func privateWildcardRoute(name string, ruleName gatewayv1.SectionName, host string) gatewayv1.HTTPRoute {
	route := routeWithBackend(name, "backend", 8080)
	route.Spec.Hostnames = []gatewayv1.Hostname{gatewayv1.Hostname(host)}
	route.Spec.Rules[0].Name = &ruleName
	return route
}

// accessApplicationTargeting builds an AccessApplication like accessApplication
// but leaves the section unset for HTTPRoute targets so the whole route is
// claimed, and marks private listeners as terminating TLS at the Gateway.
func accessApplicationTargeting(name, kind, targetName, section string) v1alpha1.AccessApplication {
	application := accessApplication(name, kind, targetName, section)
	if kind == "HTTPRoute" {
		application.Spec.TargetRefs[0].SectionName = nil
	}
	application.Spec.OriginJWT.AssumeGatewayTLSDecryption = true
	return application
}

// privateChainHosts builds gateway's snapshot and returns the virtual hosts
// of the private listener's single filter chain by domain, with that chain's
// jwt_authn config, or nil when the chain verifies no JWT.
func privateChainHosts(t *testing.T, gateway *ir.Gateway) (map[string]*routev3.VirtualHost, *jwtauthnv3.JwtAuthentication) {
	t.Helper()
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("xDS snapshot must build: %v", err)
	}
	listener, ok := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-443"].(*listenerv3.Listener)
	if !ok || len(listener.FilterChains) != 1 {
		t.Fatalf("private listener = %#v, want one filter chain for its server name", listener)
	}
	hcm := &hcmv3.HttpConnectionManager{}
	if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	var jwt *jwtauthnv3.JwtAuthentication
	for _, filter := range hcm.HttpFilters {
		if filter.Name == "envoy.filters.http.jwt_authn" {
			jwt = &jwtauthnv3.JwtAuthentication{}
			if err := filter.GetTypedConfig().UnmarshalTo(jwt); err != nil {
				t.Fatal(err)
			}
		}
	}
	routes, ok := snapshot.GetResources(resourcev3.RouteType)[hcm.GetRds().RouteConfigName].(*routev3.RouteConfiguration)
	if !ok {
		t.Fatalf("route config %q missing", hcm.GetRds().RouteConfigName)
	}
	hosts := make(map[string]*routev3.VirtualHost, len(routes.VirtualHosts))
	for _, virtualHost := range routes.VirtualHosts {
		hosts[virtualHost.Domains[0]] = virtualHost
	}
	return hosts, jwt
}

// assertHostOnlyBlocked checks that every request for host gets a local 403.
func assertHostOnlyBlocked(t *testing.T, hosts map[string]*routev3.VirtualHost, host string) {
	t.Helper()
	virtualHost := hosts[host]
	if virtualHost == nil {
		t.Fatalf("no virtual host for %s", host)
	}
	for _, route := range virtualHost.Routes {
		if route.GetDirectResponse().GetStatus() != 403 {
			t.Fatalf("%s route %q = %v, want a direct 403", host, route.Name, route.Action)
		}
	}
}

// assertHostForwardsBehindAUD checks that host forwards and requires a JWT
// for exactly aud. On a shared chain the requirement is the virtual host's
// per-route jwt_authn config; on a chain of one it is the filter's catch-all
// rule.
func assertHostForwardsBehindAUD(t *testing.T, hosts map[string]*routev3.VirtualHost, jwt *jwtauthnv3.JwtAuthentication, host, aud string) {
	t.Helper()
	virtualHost := hosts[host]
	if virtualHost == nil || len(virtualHost.Routes) == 0 || virtualHost.Routes[0].GetRoute() == nil {
		t.Fatalf("%s virtual host = %#v, want a forwarding route", host, virtualHost)
	}
	if jwt == nil {
		t.Fatalf("%s forwards on a chain without jwt_authn", host)
	}
	audiences := func(provider string) []string { return jwt.Providers[provider].GetAudiences() }
	var got []string
	if typed := virtualHost.TypedPerFilterConfig["envoy.filters.http.jwt_authn"]; typed != nil {
		config := &jwtauthnv3.PerRouteConfig{}
		if err := typed.UnmarshalTo(config); err != nil {
			t.Fatal(err)
		}
		got = audiences(jwt.RequirementMap[config.GetRequirementName()].GetProviderName())
	} else {
		got = audiences(jwt.Rules[len(jwt.Rules)-1].GetRequires().GetProviderName())
	}
	if len(got) != 1 || got[0] != aud {
		t.Fatalf("%s JWT audiences = %v, want [%s]", host, got, aud)
	}
}

// On a private listener every host shares the listener's SNI, so the
// listener's own Blocked wildcard host and the hosts app-b forwards ride one
// filter chain. Each host still enforces its own guard: the wildcard answers
// locally while both claimed hosts require app-b's JWT.
func TestPrivateWildcardListenerServesEveryHostFromOneChain(t *testing.T) {
	in := privateWildcardInputs(t)
	route := privateWildcardRoute("apps", "apps", "api.example.com")
	route.Spec.Hostnames = append(route.Spec.Hostnames, "b.example.com")
	in.HTTPRoutes = []gatewayv1.HTTPRoute{route}
	key := types.NamespacedName{Namespace: "default", Name: "app-b"}
	in.AccessApplications = []v1alpha1.AccessApplication{accessApplicationTargeting(key.Name, "Gateway", "gateway", "https")}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-b", ApplicationID: "app-b", Ready: true}}

	gateway, statuses := Translate(in)
	if compiled := statuses.AccessApplications[key]; !compiled.Accepted {
		t.Fatalf("app-b compilation = %#v", compiled)
	}
	hosts, jwt := privateChainHosts(t, gateway)
	assertHostOnlyBlocked(t, hosts, "*.example.com")
	assertHostForwardsBehindAUD(t, hosts, jwt, "api.example.com", "aud-b")
	assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-b")
}

// Two AccessApplications on one private listener forward different hosts on
// the shared chain. One jwt_authn filter carries a provider per application
// and each host requires its own application's audience, not the other's.
func TestPrivateWildcardListenerEnforcesEachApplicationAudience(t *testing.T) {
	in := privateWildcardInputs(t)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		privateWildcardRoute("route-b", "rule-b", "b.example.com"),
		privateWildcardRoute("route-c", "rule-c", "c.example.com"),
	}
	keyB := types.NamespacedName{Namespace: "default", Name: "app-b"}
	keyC := types.NamespacedName{Namespace: "default", Name: "app-c"}
	in.AccessApplications = []v1alpha1.AccessApplication{
		accessApplicationTargeting(keyB.Name, "HTTPRoute", "route-b", ""),
		accessApplicationTargeting(keyC.Name, "HTTPRoute", "route-c", ""),
	}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		keyB: {AUD: "aud-b", ApplicationID: "app-b", Ready: true},
		keyC: {AUD: "aud-c", ApplicationID: "app-c", Ready: true},
	}

	gateway, statuses := Translate(in)
	for _, key := range []types.NamespacedName{keyB, keyC} {
		if compiled := statuses.AccessApplications[key]; !compiled.Accepted {
			t.Fatalf("%s compilation = %#v", key, compiled)
		}
	}
	hosts, jwt := privateChainHosts(t, gateway)
	assertHostOnlyBlocked(t, hosts, "*.example.com")
	assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-b")
	assertHostForwardsBehindAUD(t, hosts, jwt, "c.example.com", "aud-c")
	if jwt != nil && len(jwt.Providers) != 2 {
		t.Fatalf("shared chain JWT providers = %d, want one per application", len(jwt.Providers))
	}
}

// An application whose AUD secret is not ready yet holds its host Blocked on
// the shared chain: it answers 403 without a JWT check while the ready
// application on the same chain keeps forwarding behind its own audience.
func TestPrivateWildcardListenerBlocksAccessHostUntilAUDReady(t *testing.T) {
	in := privateWildcardInputs(t)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		privateWildcardRoute("route-a", "rule-a", "api.example.com"),
		privateWildcardRoute("route-b", "rule-b", "b.example.com"),
	}
	keyA := types.NamespacedName{Namespace: "default", Name: "app-a"}
	keyB := types.NamespacedName{Namespace: "default", Name: "app-b"}
	in.AccessApplications = []v1alpha1.AccessApplication{
		accessApplicationTargeting(keyA.Name, "HTTPRoute", "route-a", ""),
		accessApplicationTargeting(keyB.Name, "HTTPRoute", "route-b", ""),
	}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		keyB: {AUD: "aud-b", ApplicationID: "app-b", Ready: true},
	}
	gateway, statuses := Translate(in)
	if compiled := statuses.AccessApplications[keyB]; !compiled.Accepted {
		t.Fatalf("app-b compilation = %#v", compiled)
	}
	hosts, jwt := privateChainHosts(t, gateway)
	assertHostOnlyBlocked(t, hosts, "*.example.com")
	assertHostOnlyBlocked(t, hosts, "api.example.com")
	assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-b")
}
