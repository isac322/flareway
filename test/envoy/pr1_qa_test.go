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
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// QA-1A-1: A Public wildcard listener with an AccessApplication on /admin and
// an unprotected carve-out on /health allocates a distinct loopback port for
// web-public rather than copying base.EnvoyPort (avoiding bindCollisionError in
// translator.Build) and real Envoy routes each port cleanly.
func TestEnvoyPublicWildcardCarveOutDoesNotCollideWithBasePort(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	originPort, _ := startJWTOrigin(t, &key.PublicKey)

	appKey := types.NamespacedName{Namespace: "demo", Name: "admin"}
	in := wildcardAccessInputs([]string{"app1.example.com"}, appKey)
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"app1.example.com"}

	pathType := gatewayv1.PathMatchPathPrefix
	adminRule := gatewayv1.SectionName("admin")
	healthRule := gatewayv1.SectionName("health")
	port := gatewayv1.PortNumber(8080)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: appKey.Namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Hostnames:       []gatewayv1.Hostname{"app1.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Name:        &adminRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				},
				{
					Name:        &healthRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/health")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				},
			},
		},
	}}
	in.AccessApplications[0].Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app1"},
		SectionName:                &adminRule,
	}}

	gw, statuses := gatewayapi.Translate(in)
	if !statuses.AccessApplications[appKey].Accepted {
		t.Fatalf("AccessApplication rejected: %#v", statuses.AccessApplications[appKey])
	}
	var basePort, publicPort, protectedPort int
	for _, domain := range gw.Domains {
		switch {
		case domain.Name == "preview":
			basePort = int(domain.EnvoyPort)
		case domain.Guard == ir.GuardUnprotected && !domain.Protected:
			publicPort = int(domain.EnvoyPort)
		case domain.AccessApplication == appKey.String():
			protectedPort = int(domain.EnvoyPort)
		}
	}
	if basePort == 0 || publicPort == 0 || protectedPort == 0 {
		t.Fatalf("missing expected domains: %#v", gw.Domains)
	}
	if publicPort == basePort || publicPort == protectedPort || basePort == protectedPort {
		t.Fatalf("ports must all be distinct: base=%d public=%d protected=%d", basePort, publicPort, protectedPort)
	}

	snapshot, err := translator.Build(gw, nil)
	if err != nil {
		t.Fatalf("translator.Build failed: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("staticBootstrap failed: %v", err)
	}
	uri := localOriginURI(originPort)
	for _, listener := range bootstrap.StaticResources.Listeners {
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

	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), basePort, publicPort, protectedPort)
	token := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Public carve-out /health serves 200 without JWT.
	if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, envoy.listenerURLs[publicPort]+"/health", nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = "app1.example.com"
		return doEnvoyRequest(req)
	}, http.StatusOK); err != nil {
		t.Fatalf("public carve-out port %d failed: %v\n%s", publicPort, err, containerLogs(envoy.name))
	}

	// Protected /admin requires JWT on protectedPort.
	if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, envoy.listenerURLs[protectedPort]+"/admin", nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = "app1.example.com"
		req.Header.Set("Cf-Access-Jwt-Assertion", token)
		return doEnvoyRequest(req)
	}, http.StatusOK); err != nil {
		t.Fatalf("protected port %d failed with valid JWT: %v\n%s", protectedPort, err, containerLogs(envoy.name))
	}
	unauthReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[protectedPort]+"/admin", nil)
	unauthReq.Host = "app1.example.com"
	if status, _, err := doEnvoyRequest(unauthReq); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("protected port without JWT = %d err=%v, want 401", status, err)
	}

	// Base wildcard domain returns 403 for unknown hosts.
	baseReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[basePort]+"/", nil)
	baseReq.Host = "unknown.example.com"
	if status, _, err := doEnvoyRequest(baseReq); err != nil || status != http.StatusForbidden {
		t.Fatalf("base wildcard port = %d err=%v, want 403", status, err)
	}
}

// QA-1A-2: A Public wildcard listener with an AccessApplication on /admin and
// no unprotected grant allocates a distinct loopback port for web-blocked rather
// than copying base.EnvoyPort (avoiding bindCollisionError in translator.Build).
func TestEnvoyPublicWildcardBlockedDomainDoesNotCollideWithBasePort(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	originPort, _ := startJWTOrigin(t, &key.PublicKey)

	appKey := types.NamespacedName{Namespace: "demo", Name: "admin"}
	in := wildcardAccessInputs([]string{"app1.example.com"}, appKey)
	pathType := gatewayv1.PathMatchPathPrefix
	adminRule := gatewayv1.SectionName("admin")
	port := gatewayv1.PortNumber(8080)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: appKey.Namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Hostnames:       []gatewayv1.Hostname{"app1.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{{
				Name:        &adminRule,
				Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
			}},
		},
	}}
	in.AccessApplications[0].Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app1"},
		SectionName:                &adminRule,
	}}

	gw, statuses := gatewayapi.Translate(in)
	if !statuses.AccessApplications[appKey].Accepted {
		t.Fatalf("AccessApplication rejected: %#v", statuses.AccessApplications[appKey])
	}
	var basePort, blockedPort, protectedPort int
	for _, domain := range gw.Domains {
		switch {
		case domain.Name == "preview":
			basePort = int(domain.EnvoyPort)
		case domain.Guard == ir.GuardBlocked && !domain.Protected && domain.ListenerName == "preview":
			blockedPort = int(domain.EnvoyPort)
		case domain.AccessApplication == appKey.String():
			protectedPort = int(domain.EnvoyPort)
		}
	}
	if basePort == 0 || blockedPort == 0 || protectedPort == 0 {
		t.Fatalf("missing expected domains: %#v", gw.Domains)
	}
	if blockedPort == basePort || blockedPort == protectedPort || basePort == protectedPort {
		t.Fatalf("ports must all be distinct: base=%d blocked=%d protected=%d", basePort, blockedPort, protectedPort)
	}

	snapshot, err := translator.Build(gw, nil)
	if err != nil {
		t.Fatalf("translator.Build failed: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("staticBootstrap failed: %v", err)
	}
	uri := localOriginURI(originPort)
	for _, listener := range bootstrap.StaticResources.Listeners {
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

	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), basePort, blockedPort, protectedPort)
	token := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, envoy.listenerURLs[protectedPort]+"/admin", nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = "app1.example.com"
		req.Header.Set("Cf-Access-Jwt-Assertion", token)
		return doEnvoyRequest(req)
	}, http.StatusOK); err != nil {
		t.Fatalf("protected port %d failed: %v\n%s", protectedPort, err, containerLogs(envoy.name))
	}

	blockedReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[blockedPort]+"/", nil)
	blockedReq.Host = "app1.example.com"
	if status, _, err := doEnvoyRequest(blockedReq); err != nil || status != http.StatusForbidden {
		t.Fatalf("blocked port = %d err=%v, want 403", status, err)
	}
	baseReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[basePort]+"/", nil)
	baseReq.Host = "unknown.example.com"
	if status, _, err := doEnvoyRequest(baseReq); err != nil || status != http.StatusForbidden {
		t.Fatalf("base wildcard port = %d err=%v, want 403", status, err)
	}
}

// QA-1E-2 & QA-1-REG-3: Unclaimed unprotected routes alongside sibling
// AccessApplications strip all cf-access-* headers (from both incoming client
// requests and Route/Backend RequestHeaderModifier Set/Add filters) in real
// Envoy, while Protected Forwarding routes preserve Cf-Access-* headers and
// Conformance mode leaves RequestHeaderModifier headers intact.
func TestEnvoyUnprotectedAndProtectedHeaderStrippingEndToEnd(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	jwksJSON := mustJWKS(t, &key.PublicKey)
	echoPort := startHeaderEchoOrigin(t, jwksJSON)

	buildInputs := func(conformance bool) gatewayapi.Inputs {
		namespace := "demo"
		port := gatewayv1.PortNumber(8080)
		pathType := gatewayv1.PathMatchPathPrefix
		path := "/"
		protectedSection := gatewayv1.SectionName("protected")
		unprotectedSection := gatewayv1.SectionName("unprotected")
		protectedHost := gatewayv1.Hostname("protected.example.com")
		unprotectedHost := gatewayv1.Hostname("unprotected.example.com")

		unprotectedRoute := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "unprotected", Namespace: namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &unprotectedSection}}},
				Hostnames:       []gatewayv1.Hostname{unprotectedHost},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
					Filters: []gatewayv1.HTTPRouteFilter{{
						Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
						RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
							Set: []gatewayv1.HTTPHeader{
								{Name: "Cf-Access-Authenticated-User-Email", Value: "spoofed@attacker.test"},
								{Name: "X-Keep-Route", Value: "route-ok"},
							},
							Add: []gatewayv1.HTTPHeader{
								{Name: "cf-access-custom-role", Value: "superadmin"},
							},
						},
					}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}},
						Filters: []gatewayv1.HTTPRouteFilter{{
							Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "Cf-Access-Jwt-Assertion", Value: "forged-backend-jwt"},
									{Name: "X-Keep-Backend", Value: "backend-ok"},
								},
								Add: []gatewayv1.HTTPHeader{
									{Name: "cf-access-custom-group", Value: "root"},
								},
							},
						}},
					}},
				}},
			},
		}
		protectedRoute := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "protected", Namespace: namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &protectedSection}}},
				Hostnames:       []gatewayv1.Hostname{protectedHost},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		appKey := types.NamespacedName{Namespace: namespace, Name: "protected-app"}
		in := gatewayapi.Inputs{
			Gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespace, UID: types.UID("gw-uid"), Generation: 1},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "flareway",
					Listeners: []gatewayv1.Listener{
						{Name: protectedSection, Hostname: &protectedHost, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
						{Name: unprotectedSection, Hostname: &unprotectedHost, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			GatewayClass:       &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}},
			GatewayClassConfig: &v1alpha1.GatewayClassConfig{Spec: v1alpha1.GatewayClassConfigSpec{ConformanceMode: conformance}},
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
					Hostnames:            []string{"protected.example.com", "unprotected.example.com"},
					UnprotectedHostnames: []string{"unprotected.example.com"},
					Zones:                []string{"example.com"},
					Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
					Backends:             &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
				}}},
				Status: v1alpha1.CloudflareAccountStatus{Verified: v1alpha1.CloudflareAccountVerifiedStatus{
					TeamName: "team", AuthDomain: strings.TrimPrefix(jwtIssuer, "https://"),
				}},
			},
			HTTPRoutes: []gatewayv1.HTTPRoute{protectedRoute, unprotectedRoute},
		}
		if !conformance {
			in.AccessApplications = []v1alpha1.AccessApplication{{
				ObjectMeta: metav1.ObjectMeta{Name: appKey.Name, Namespace: namespace, UID: types.UID("app-uid"), CreationTimestamp: metav1.NewTime(time.Unix(10, 0))},
				Spec: v1alpha1.AccessApplicationSpec{
					AccountRef: corev1.LocalObjectReference{Name: "account"},
					Type:       v1alpha1.AccessApplicationTypeSelfHosted,
					SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: "gateway"},
						SectionName:                &protectedSection,
					}},
					OriginJWT: v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
				},
			}}
			in.AUDSecrets = map[types.NamespacedName]gatewayapi.AUDSecret{
				appKey: {AUD: jwtAudience, ApplicationID: "app-protected", Ready: true},
			}
		}
		return in
	}

	t.Run("non-conformance strips cf-access-* on unprotected while preserving on protected", func(t *testing.T) {
		gw, _ := gatewayapi.Translate(buildInputs(false))
		var protectedPort, unprotectedPort int
		for _, d := range gw.Domains {
			if d.ListenerName == "protected" {
				protectedPort = int(d.EnvoyPort)
			} else if d.ListenerName == "unprotected" {
				unprotectedPort = int(d.EnvoyPort)
			}
		}
		snapshot, err := translator.Build(gw, nil)
		if err != nil {
			t.Fatalf("translator.Build: %v", err)
		}
		bootstrap, err := staticBootstrap(snapshot)
		if err != nil {
			t.Fatalf("staticBootstrap: %v", err)
		}
		uri := localOriginURI(echoPort)
		for _, listener := range bootstrap.StaticResources.Listeners {
			listener.GetAddress().GetSocketAddress().Address = "0.0.0.0"
			if err := rewriteJWTFilter(listener, uri); err != nil && !strings.Contains(err.Error(), "not found") {
				t.Fatal(err)
			}
		}
		for _, cluster := range bootstrap.StaticResources.Clusters {
			setClusterEndpoint(cluster, "host.docker.internal", echoPort)
			if strings.HasPrefix(cluster.Name, "flareway-jwks-") {
				cluster.TransportSocket = nil
			}
		}

		envoy := startEnvoy(t, writeBootstrap(t, bootstrap), unprotectedPort, protectedPort)
		token := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		var unprotBody string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[unprotectedPort]+"/", nil)
			req.Host = "unprotected.example.com"
			req.Header.Set("Cf-Access-Jwt-Assertion", "client-forged-jwt")
			req.Header.Set("Cf-Access-Authenticated-User-Email", "client-forged@attacker.test")
			status, body, err := doEnvoyRequest(req)
			if err == nil && status == http.StatusOK {
				unprotBody = body
			}
			return status, body, err
		}, http.StatusOK); err != nil {
			t.Fatalf("unprotected request failed: %v\n%s", err, containerLogs(envoy.name))
		}
		received := map[string][]string{}
		if err := json.Unmarshal([]byte(unprotBody), &received); err != nil {
			t.Fatalf("decode echoed headers %q: %v", unprotBody, err)
		}
		for k := range received {
			if strings.HasPrefix(strings.ToLower(k), "cf-access-") {
				t.Fatalf("unprotected backend received cf-access-* header %q: %v", k, received)
			}
		}
		if !slices.Equal(received["X-Keep-Route"], []string{"route-ok"}) || !slices.Equal(received["X-Keep-Backend"], []string{"backend-ok"}) {
			t.Fatalf("non-access headers were not preserved on unprotected route: %v", received)
		}

		var protBody string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[protectedPort]+"/", nil)
			req.Host = "protected.example.com"
			req.Header.Set("Cf-Access-Jwt-Assertion", token)
			status, body, err := doEnvoyRequest(req)
			if err == nil && status == http.StatusOK {
				protBody = body
			}
			return status, body, err
		}, http.StatusOK); err != nil {
			t.Fatalf("protected request failed: %v\n%s", err, containerLogs(envoy.name))
		}
		protHeaders := map[string][]string{}
		if err := json.Unmarshal([]byte(protBody), &protHeaders); err != nil {
			t.Fatalf("decode protected echoed headers %q: %v", protBody, err)
		}
		if !slices.Equal(protHeaders["Cf-Access-Jwt-Assertion"], []string{token}) {
			t.Fatalf("protected backend did not receive Cf-Access-Jwt-Assertion: %v", protHeaders)
		}
	})

	t.Run("QA-1-REG-3: Conformance mode skips header stripping", func(t *testing.T) {
		gw, _ := gatewayapi.Translate(buildInputs(true))
		snapshot, err := translator.Build(gw, nil)
		if err != nil {
			t.Fatalf("translator.Build: %v", err)
		}
		bootstrap, err := staticBootstrap(snapshot)
		if err != nil {
			t.Fatalf("staticBootstrap: %v", err)
		}
		for _, cluster := range bootstrap.StaticResources.Clusters {
			setClusterEndpoint(cluster, "host.docker.internal", echoPort)
		}
		port, err := listenerPort(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		envoy := startEnvoy(t, writeBootstrap(t, bootstrap), port)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var body string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURL+"/", nil)
			req.Host = "unprotected.example.com"
			status, respBody, err := doEnvoyRequest(req)
			if err == nil && status == http.StatusOK {
				body = respBody
			}
			return status, respBody, err
		}, http.StatusOK); err != nil {
			t.Fatalf("conformance request failed: %v", err)
		}
		received := map[string][]string{}
		if err := json.Unmarshal([]byte(body), &received); err != nil {
			t.Fatalf("decode conformance headers %q: %v", body, err)
		}
		if !slices.Equal(received["Cf-Access-Authenticated-User-Email"], []string{"spoofed@attacker.test"}) {
			t.Fatalf("conformance mode stripped RequestHeaderModifier header: %v", received)
		}
	})
}

func startHeaderEchoOrigin(t *testing.T, jwks []byte) int {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen echo origin: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.Header)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener.Addr().(*net.TCPAddr).Port
}
