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
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// One AccessApplication on a public wildcard listener gives every concrete
// host its own Envoy port, and cloudflared sends each host to that port. The
// Envoy listener on each port must serve that host's routes; if the ports
// share one route table, every host but one answers 404 after the JWT check.
func TestAccessOnWildcardListenerRoutesEveryHostOnItsOwnPort(t *testing.T) {
	in := accessInputs(false)
	wildcard := gatewayv1.Hostname("*.example.com")
	in.Gateway.Spec.Listeners = append(in.Gateway.Spec.Listeners, gatewayv1.Listener{
		Name: "preview", Hostname: &wildcard, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	})
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"api.example.com", "*.example.com"}
	hosts := []string{"app1.example.com", "app2.example.com", "app3.example.com"}
	for _, host := range hosts {
		route := routeWithBackend(host[:4], "backend", 8080)
		route.Spec.Hostnames = []gatewayv1.Hostname{gatewayv1.Hostname(host)}
		in.HTTPRoutes = append(in.HTTPRoutes, route)
	}
	key := types.NamespacedName{Namespace: "default", Name: "preview"}
	in.AccessApplications = []v1alpha1.AccessApplication{accessApplication(key.Name, "Gateway", "gateway", "preview")}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-preview", ApplicationID: "app-preview", Ready: true}}

	gateway, statuses := Translate(in)
	compiled := statuses.AccessApplications[key]
	if !compiled.Accepted || len(compiled.DataPlanes) != len(hosts) {
		t.Fatalf("application compilation = %#v, want one data plane per host", compiled)
	}
	dataPlaneDomains := make(map[string]int32)
	for _, dataPlane := range compiled.DataPlanes {
		if port, seen := dataPlaneDomains[dataPlane.ProtectionDomain]; seen {
			t.Fatalf("protection domain %q reported on ports %d and %d", dataPlane.ProtectionDomain, port, dataPlane.EnvoyPort)
		}
		dataPlaneDomains[dataPlane.ProtectionDomain] = dataPlane.EnvoyPort
	}

	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	portHosts := routedHostsByPort(t, snapshot.GetResources(resourcev3.ListenerType), snapshot.GetResources(resourcev3.RouteType))
	for _, domain := range gateway.Domains {
		if domain.AccessApplication != key.String() {
			continue
		}
		if len(domain.VirtualHosts) != 1 {
			t.Fatalf("protected domain %q carries %d virtual hosts", domain.Name, len(domain.VirtualHosts))
		}
		host := domain.VirtualHosts[0].Hostname
		if !slices.Contains(portHosts[domain.EnvoyPort], host) {
			t.Errorf("Envoy port %d (cloudflared target for %s) routes %v, not %s", domain.EnvoyPort, host, portHosts[domain.EnvoyPort], host)
		}
		if dataPlaneDomains[domain.Name] != domain.EnvoyPort {
			t.Errorf("status reports domain %q on port %d, Envoy serves it on %d", domain.Name, dataPlaneDomains[domain.Name], domain.EnvoyPort)
		}
	}
}

// A public carve-out on listener "http" is a domain named "http-public",
// which is also the name of a second listener. Both used to share one route
// table name, so one port silently served the other's hosts; with the
// translator's duplicate-name check the whole Gateway would fail instead.
// The derived name must be made unique so both listeners keep working.
func TestDerivedDomainNameThatEqualsAnotherListenerStaysRoutable(t *testing.T) {
	in := accessInputs(true)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "tools", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: new(gatewayv1.SectionName("http"))}}},
			Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("dashboard", "/", "dashboard"), namedRouteRule("api-v1", "/v1", "api")},
		},
	}}
	key := types.NamespacedName{Namespace: "default", Name: "dashboard"}
	in.AccessApplications = []v1alpha1.AccessApplication{accessApplication(key.Name, "HTTPRoute", "tools", "dashboard")}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-dashboard", ApplicationID: "app-dashboard", Ready: true}}
	in.Gateway.Spec.Listeners = append(in.Gateway.Spec.Listeners, gatewayv1.Listener{
		Name: "http-public", Hostname: new(gatewayv1.Hostname("other.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	})
	grant := &in.CloudflareAccount.Spec.Grants[0]
	grant.Hostnames = append(grant.Hostnames, "other.example.com")
	grant.UnprotectedHostnames = append(grant.UnprotectedHostnames, "other.example.com")
	other := routeWithBackend("other", "backend", 8080)
	other.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("http-public"))
	in.HTTPRoutes = append(in.HTTPRoutes, other)

	gateway, statuses := Translate(in)
	if compiled := statuses.AccessApplications[key]; !compiled.Accepted {
		t.Fatalf("application compilation = %#v", compiled)
	}
	listenerOf := make(map[string]string)
	for _, domain := range gateway.Domains {
		if listener, seen := listenerOf[domain.Name]; seen && listener != domain.ListenerName {
			t.Fatalf("protection domain name %q is used by listeners %q and %q", domain.Name, listener, domain.ListenerName)
		}
		listenerOf[domain.Name] = domain.ListenerName
	}

	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	portHosts := routedHostsByPort(t, snapshot.GetResources(resourcev3.ListenerType), snapshot.GetResources(resourcev3.RouteType))
	for _, domain := range gateway.Domains {
		if domain.Guard != ir.GuardUnprotected {
			continue
		}
		want := domain.VirtualHosts[0].Hostname
		if !slices.Equal(portHosts[domain.EnvoyPort], []string{want}) {
			t.Errorf("domain %q (listener %s): Envoy port %d routes %v, want only %s", domain.Name, domain.ListenerName, domain.EnvoyPort, portHosts[domain.EnvoyPort], want)
		}
	}
}

func routedHostsByPort(t *testing.T, listeners, routes map[string]cachetypes.Resource) map[int32][]string {
	t.Helper()
	out := make(map[int32][]string)
	for name, resource := range listeners {
		listener := resource.(*listenerv3.Listener)
		port := int32(listener.GetAddress().GetSocketAddress().GetPortValue())
		for _, chain := range listener.FilterChains {
			hcm := &hcmv3.HttpConnectionManager{}
			if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
				t.Fatalf("decode HCM on %s: %v", name, err)
			}
			routeConfig, ok := routes[hcm.GetRds().GetRouteConfigName()].(*routev3.RouteConfiguration)
			if !ok {
				t.Fatalf("listener %s references missing route config %q", name, hcm.GetRds().GetRouteConfigName())
			}
			for _, virtualHost := range routeConfig.VirtualHosts {
				for _, domain := range virtualHost.Domains {
					if virtualHost.Name == "" || len(virtualHost.Routes) == 0 || virtualHost.Routes[0].GetDirectResponse() != nil {
						continue
					}
					out[port] = append(out[port], domain)
				}
			}
		}
	}
	return out
}
