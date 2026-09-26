//go:build envoy

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

package envoy_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/xds/translator"
)

// One AccessApplication on a public wildcard listener covers several
// hostnames. cloudflared sends each hostname to its own Envoy port, so a
// request that passes the origin JWT check on any of those ports must reach
// the backend. This drives the real Gateway API translation, so it fails if
// the per-host listeners end up sharing one route table.
func TestEnvoyRoutesEveryHostOfAWildcardAccessApplication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	originPort, _ := startJWTOrigin(t, &key.PublicKey)

	hosts := []string{"app1.example.com", "app2.example.com", "app3.example.com"}
	application := types.NamespacedName{Namespace: "demo", Name: "preview"}
	gateway, _ := gatewayapi.Translate(wildcardAccessInputs(hosts, application))
	hostPorts := make(map[string]int)
	for _, domain := range gateway.Domains {
		if domain.AccessApplication != application.String() {
			continue
		}
		for _, virtualHost := range domain.VirtualHosts {
			hostPorts[virtualHost.Hostname] = int(domain.EnvoyPort)
		}
	}
	if len(hostPorts) != len(hosts) {
		t.Fatalf("Access ports by host = %v, want one per host %v", hostPorts, hosts)
	}

	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert snapshot to static Envoy bootstrap: %v", err)
	}
	uri := localOriginURI(originPort)
	for _, listener := range bootstrap.StaticResources.Listeners {
		// Cloudflare-mode listeners bind loopback for the sidecar cloudflared;
		// the container port mapping needs them on every interface.
		listener.GetAddress().GetSocketAddress().Address = "0.0.0.0"
		if err := rewriteJWTFilter(listener, uri); err != nil && !strings.Contains(err.Error(), "not found") {
			t.Fatal(err)
		}
	}
	for _, cluster := range bootstrap.StaticResources.Clusters {
		setClusterEndpoint(cluster, "host.docker.internal", originPort)
		if strings.HasPrefix(cluster.Name, "flareway-jwks-") {
			cluster.TransportSocket = nil
		}
	}

	ports := make([]int, 0, len(hosts))
	for _, host := range hosts {
		ports = append(ports, hostPorts[host])
	}
	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), ports[0], ports[1:]...)

	token := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	for _, host := range hosts {
		baseURL := envoy.listenerURLs[hostPorts[host]]
		err := waitForHTTP(readyCtx, 250*time.Millisecond, func() (int, string, error) {
			return hostRequest(baseURL, host, token)
		}, http.StatusOK)
		if err != nil {
			t.Fatalf("%s on Envoy port %d did not route after JWT: %v\ncontainer logs:\n%s", host, hostPorts[host], err, containerLogs(envoy.name))
		}
		status, body, err := hostRequest(baseURL, host, token)
		if err != nil || status != http.StatusOK || body != "backend-ok" {
			t.Fatalf("%s authenticated request = status %d body %q err %v, want 200 backend-ok", host, status, body, err)
		}
		status, _, err = hostRequest(baseURL, host, "")
		if err != nil || status != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated request = status %d err %v, want 401", host, status, err)
		}
	}
}

func hostRequest(baseURL, host, token string) (int, string, error) {
	request, err := http.NewRequest(http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = host
	if token != "" {
		request.Header.Set("Cf-Access-Jwt-Assertion", token)
	}
	return doEnvoyRequest(request)
}

func wildcardAccessInputs(hosts []string, application types.NamespacedName) gatewayapi.Inputs {
	namespace := application.Namespace
	wildcard := gatewayv1.Hostname("*.example.com")
	port := gatewayv1.PortNumber(8080)
	pathType := gatewayv1.PathMatchPathPrefix
	path := "/"
	routes := make([]gatewayv1.HTTPRoute, 0, len(hosts))
	for _, host := range hosts {
		routes = append(routes, gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: strings.Split(host, ".")[0], Namespace: namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(host)},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: "backend", Port: &port,
					}}}},
				}},
			},
		})
	}
	section := gatewayv1.SectionName("preview")
	return gatewayapi.Inputs{
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespace, UID: types.UID("gateway-uid"), Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "flareway",
				Listeners:        []gatewayv1.Listener{{Name: section, Hostname: &wildcard, Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		},
		GatewayClass:       &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}},
		GatewayClassConfig: &v1alpha1.GatewayClassConfig{},
		Now:                metav1.NewTime(time.Unix(100, 0).UTC()),
		Namespaces:         []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: namespace}}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: namespace},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}},
		CloudflareTunnel: &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespace}},
		CloudflareAccount: &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Grants: []v1alpha1.CloudflareAccountGrant{{
				Hostnames: []string{"*.example.com"}, Zones: []string{"example.com"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				Backends: &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			}}},
			Status: v1alpha1.CloudflareAccountStatus{Verified: v1alpha1.CloudflareAccountVerifiedStatus{
				TeamName: "team", AuthDomain: strings.TrimPrefix(jwtIssuer, "https://"),
			}},
		},
		HTTPRoutes: routes,
		AccessApplications: []v1alpha1.AccessApplication{{
			ObjectMeta: metav1.ObjectMeta{Name: application.Name, Namespace: namespace, UID: types.UID("preview-uid"), CreationTimestamp: metav1.NewTime(time.Unix(10, 0))},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: "account"},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: "gateway"},
					SectionName:                &section,
				}},
				OriginJWT: v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			},
		}},
		AUDSecrets: map[types.NamespacedName]gatewayapi.AUDSecret{
			application: {AUD: jwtAudience, ApplicationID: "app-preview", Ready: true},
		},
	}
}
