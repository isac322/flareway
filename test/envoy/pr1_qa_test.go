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
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// QA-1A-1 & QA-1A-2: A Public wildcard listener with two hosts having
// AccessApplications on /admin and unprotected carve-outs (/health, /status)
// allocates distinct loopback ports for web-public and protected domains rather
// than copying base.EnvoyPort (avoiding bindCollisionError in translator.Build),
// matches cloudflared ingress rules in order, strips cf-access-* headers on
// carve-out paths, and rejects unauthenticated or non-carve-out paths.
func TestEnvoyPublicWildcardCarveOutDoesNotCollideWithBasePort(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	echoPort := startHeaderEchoOrigin(t, mustJWKS(t, &key.PublicKey))

	app1Key := types.NamespacedName{Namespace: "demo", Name: "admin-1"}
	app2Key := types.NamespacedName{Namespace: "demo", Name: "admin-2"}
	in := wildcardAccessInputs([]string{"app1.example.com", "app2.example.com"}, app1Key)
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"app1.example.com", "app2.example.com"}

	pathType := gatewayv1.PathMatchPathPrefix
	adminRule := gatewayv1.SectionName("admin")
	healthRule := gatewayv1.SectionName("health")
	statusRule := gatewayv1.SectionName("status")
	port := gatewayv1.PortNumber(8080)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: app1Key.Namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
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
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "app2", Namespace: app2Key.Namespace, Generation: 2, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"app2.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Name:        &adminRule,
						Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
						BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
					},
					{
						Name:        &statusRule,
						Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/status")}}},
						BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
					},
				},
			},
		},
	}
	app1 := in.AccessApplications[0]
	app1.Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app1"},
		SectionName:                &adminRule,
	}}
	app2 := *app1.DeepCopy()
	app2.Name = app2Key.Name
	app2.UID = types.UID("app2-uid")
	app2.CreationTimestamp = metav1.NewTime(time.Unix(20, 0))
	app2.Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app2"},
		SectionName:                &adminRule,
	}}
	in.AccessApplications = []v1alpha1.AccessApplication{app1, app2}
	in.AUDSecrets[app2Key] = in.AUDSecrets[app1Key]

	gw, statuses := gatewayapi.Translate(in)
	for _, key := range []types.NamespacedName{app1Key, app2Key} {
		if !statuses.AccessApplications[key].Accepted {
			t.Fatalf("AccessApplication %s rejected: %#v", key, statuses.AccessApplications[key])
		}
	}
	var basePort, protected1Port, protected2Port int
	publicPorts := map[string]int{}
	for _, domain := range gw.Domains {
		switch {
		case domain.Name == "preview":
			basePort = int(domain.EnvoyPort)
		case domain.Guard == ir.GuardUnprotected && !domain.Protected && len(domain.VirtualHosts) > 0:
			publicPorts[domain.VirtualHosts[0].Hostname] = int(domain.EnvoyPort)
		case domain.AccessApplication == app1Key.String():
			protected1Port = int(domain.EnvoyPort)
		case domain.AccessApplication == app2Key.String():
			protected2Port = int(domain.EnvoyPort)
		}
	}
	public1Port := publicPorts["app1.example.com"]
	public2Port := publicPorts["app2.example.com"]
	if basePort == 0 || public1Port == 0 || public2Port == 0 || protected1Port == 0 || protected2Port == 0 {
		t.Fatalf("missing expected domains: %#v", gw.Domains)
	}
	ports := []int{basePort, public1Port, public2Port, protected1Port, protected2Port}
	slices.Sort(ports)
	if len(slices.Compact(ports)) != 5 {
		t.Fatalf("ports must all be distinct: base=%d pub1=%d pub2=%d prot1=%d prot2=%d", basePort, public1Port, public2Port, protected1Port, protected2Port)
	}

	// Verify compiled cloudflared first-matching ingress rules route each host/path
	// to its exact intended Envoy port or 403 block.
	if gw.Cloudflare == nil {
		gw.Cloudflare = &ir.Cloudflare{AccountID: in.CloudflareAccount.Spec.AccountID}
	}
	cfParams, _, err := cloudflared.Compile(gw)
	if err != nil {
		t.Fatalf("cloudflared.Compile failed: %v", err)
	}
	if got := firstMatchingIngressService(t, cfParams, "app1.example.com", "/admin"); got != fmt.Sprintf("http://127.0.0.1:%d", protected1Port) {
		t.Fatalf("app1 /admin ingress = %s, want protected1Port %d", got, protected1Port)
	}
	if got := firstMatchingIngressService(t, cfParams, "app1.example.com", "/health"); got != fmt.Sprintf("http://127.0.0.1:%d", public1Port) {
		t.Fatalf("app1 /health ingress = %s, want public1Port %d", got, public1Port)
	}
	if got := firstMatchingIngressService(t, cfParams, "app2.example.com", "/admin"); got != fmt.Sprintf("http://127.0.0.1:%d", protected2Port) {
		t.Fatalf("app2 /admin ingress = %s, want protected2Port %d", got, protected2Port)
	}
	if got := firstMatchingIngressService(t, cfParams, "app2.example.com", "/status"); got != fmt.Sprintf("http://127.0.0.1:%d", public2Port) {
		t.Fatalf("app2 /status ingress = %s, want public2Port %d", got, public2Port)
	}
	if got := firstMatchingIngressService(t, cfParams, "app1.example.com", "/other"); got != "http_status:403" {
		t.Fatalf("app1 /other ingress = %s, want http_status:403", got)
	}
	if got := firstMatchingIngressService(t, cfParams, "unknown.example.com", "/"); got != "http_status:403" {
		t.Fatalf("unknown.example.com ingress = %s, want http_status:403", got)
	}

	snapshot, err := translator.Build(gw, nil)
	if err != nil {
		t.Fatalf("translator.Build failed: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("staticBootstrap failed: %v", err)
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

	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), basePort, public1Port, public2Port, protected1Port, protected2Port)
	token := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Both hosts' unprotected carve-outs serve 200 without JWT and strip cf-access-* headers.
	for _, tc := range []struct {
		host, path string
		port       int
	}{
		{"app1.example.com", "/health", public1Port},
		{"app2.example.com", "/status", public2Port},
	} {
		var body string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[tc.port]+tc.path, nil)
			req.Host = tc.host
			req.Header.Set("Cf-Access-Jwt-Assertion", "spoofed-jwt")
			req.Header.Set("Cf-Access-Authenticated-User-Email", "spoofed@attacker.test")
			status, respBody, err := doEnvoyRequest(req)
			if err == nil && status == http.StatusOK {
				body = respBody
			}
			return status, respBody, err
		}, http.StatusOK); err != nil {
			t.Fatalf("carve-out %s%s failed: %v\n%s", tc.host, tc.path, err, containerLogs(envoy.name))
		}
		received := map[string][]string{}
		if err := json.Unmarshal([]byte(body), &received); err != nil {
			t.Fatalf("decode headers %q: %v", body, err)
		}
		for k := range received {
			if strings.HasPrefix(strings.ToLower(k), "cf-access-") {
				t.Fatalf("carve-out %s%s forwarded cf-access-* header %q: %v", tc.host, tc.path, k, received)
			}
		}
		// Non-carve-out paths on publicPort must NOT forward (404).
		nonCarveReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[tc.port]+"/admin", nil)
		nonCarveReq.Host = tc.host
		if status, _, err := doEnvoyRequest(nonCarveReq); err != nil || status != http.StatusNotFound {
			t.Fatalf("non-carve-out %s/admin on public port %d = %d err=%v, want 404", tc.host, tc.port, status, err)
		}
	}

	// Both protected /admin endpoints require JWT (200 with JWT, 401 without).
	for _, tc := range []struct {
		host string
		port int
	}{
		{"app1.example.com", protected1Port},
		{"app2.example.com", protected2Port},
	} {
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[tc.port]+"/admin", nil)
			req.Host = tc.host
			req.Header.Set("Cf-Access-Jwt-Assertion", token)
			return doEnvoyRequest(req)
		}, http.StatusOK); err != nil {
			t.Fatalf("protected %s port %d failed with valid JWT: %v\n%s", tc.host, tc.port, err, containerLogs(envoy.name))
		}
		unauthReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[tc.port]+"/admin", nil)
		unauthReq.Host = tc.host
		if status, _, err := doEnvoyRequest(unauthReq); err != nil || status != http.StatusUnauthorized {
			t.Fatalf("protected %s without JWT = %d err=%v, want 401", tc.host, status, err)
		}
	}

	// Base wildcard domain returns 403 for unknown hosts.
	baseReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[basePort]+"/", nil)
	baseReq.Host = "unknown.example.com"
	if status, _, err := doEnvoyRequest(baseReq); err != nil || status != http.StatusForbidden {
		t.Fatalf("base wildcard port = %d err=%v, want 403", status, err)
	}
}

// QA-1A-1 (blocked carve-out matrix): A Public wildcard listener with an
// AccessApplication on /admin and no unprotected grant allocates a distinct
// loopback port for web-blocked rather than copying base.EnvoyPort, and Envoy +
// cloudflared enforce 200 (JWT), 401 (no JWT), 403 (same-host non-/admin fallback
// and unknown wildcard host).
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

	// Assert cloudflared first matching ingress rule order.
	if gw.Cloudflare == nil {
		gw.Cloudflare = &ir.Cloudflare{AccountID: in.CloudflareAccount.Spec.AccountID}
	}
	cfParams, _, err := cloudflared.Compile(gw)
	if err != nil {
		t.Fatalf("cloudflared.Compile failed: %v", err)
	}
	if got := firstMatchingIngressService(t, cfParams, "app1.example.com", "/admin"); got != fmt.Sprintf("http://127.0.0.1:%d", protectedPort) {
		t.Fatalf("app1 /admin ingress = %s, want protectedPort %d", got, protectedPort)
	}
	if got := firstMatchingIngressService(t, cfParams, "app1.example.com", "/other"); got != "http_status:403" {
		t.Fatalf("app1 /other ingress = %s, want http_status:403", got)
	}
	if got := firstMatchingIngressService(t, cfParams, "unknown.example.com", "/"); got != "http_status:403" {
		t.Fatalf("unknown.example.com ingress = %s, want http_status:403", got)
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

	unauthReq, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[protectedPort]+"/admin", nil)
	unauthReq.Host = "app1.example.com"
	if status, _, err := doEnvoyRequest(unauthReq); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("protected port without JWT = %d err=%v, want 401", status, err)
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
	certPEM, keyPEM := selfSignedCertificate(t)

	buildInputs := func(conformance bool) gatewayapi.Inputs {
		namespace := "demo"
		port := gatewayv1.PortNumber(8080)
		pathType := gatewayv1.PathMatchPathPrefix
		path := "/"
		protectedSection := gatewayv1.SectionName("protected")
		unprotectedSection := gatewayv1.SectionName("unprotected")
		privUnprotectedSection := gatewayv1.SectionName("priv-unprot")
		protectedHost := gatewayv1.Hostname("protected.example.com")
		unprotectedHost := gatewayv1.Hostname("unprotected.example.com")
		privUnprotectedHost := gatewayv1.Hostname("priv-unprot.example.com")

		headerFilters := func() ([]gatewayv1.HTTPRouteFilter, []gatewayv1.HTTPRouteFilter) {
			return []gatewayv1.HTTPRouteFilter{{
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
				}}, []gatewayv1.HTTPRouteFilter{{
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
				}}
		}
		routeFilters, backendFilters := headerFilters()
		privRouteFilters, privBackendFilters := headerFilters()

		unprotectedRoute := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "unprotected", Namespace: namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &unprotectedSection}}},
				Hostnames:       []gatewayv1.Hostname{unprotectedHost},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
					Filters: routeFilters,
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}},
						Filters:    backendFilters,
					}},
				}},
			},
		}
		privUnprotectedRoute := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-unprotected", Namespace: namespace, Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(3, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &privUnprotectedSection}}},
				Hostnames:       []gatewayv1.Hostname{privUnprotectedHost},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
					Filters: privRouteFilters,
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}},
						Filters:    privBackendFilters,
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
						{
							Name: privUnprotectedSection, Hostname: &privUnprotectedHost, Port: 10443, Protocol: gatewayv1.HTTPSProtocolType,
							TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "priv-cert"}}},
						},
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
			Secrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{Name: "priv-cert", Namespace: namespace},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM},
			}},
			VirtualNetworks: []v1alpha1.VirtualNetwork{{
				ObjectMeta: metav1.ObjectMeta{Name: "vnet-priv", Namespace: namespace},
				Spec:       v1alpha1.VirtualNetworkSpec{Name: "vnet-priv", AccountRef: corev1.LocalObjectReference{Name: "account"}},
				Status: v1alpha1.VirtualNetworkStatus{
					VirtualNetworkID: "vnet-id",
					Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
				},
			}},
			CloudflareTunnel: &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespace},
				Spec: v1alpha1.CloudflareTunnelSpec{Listeners: []v1alpha1.CloudflareTunnelListener{{
					Name: privUnprotectedSection, Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet-priv"},
				}}},
			},
			CloudflareAccount: &v1alpha1.CloudflareAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "account"},
				Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Grants: []v1alpha1.CloudflareAccountGrant{{
					Hostnames:            []string{"protected.example.com", "unprotected.example.com", "priv-unprot.example.com"},
					UnprotectedHostnames: []string{"unprotected.example.com", "priv-unprot.example.com"},
					Zones:                []string{"example.com"},
					Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
					Backends:             &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
				}}},
				Status: v1alpha1.CloudflareAccountStatus{Verified: v1alpha1.CloudflareAccountVerifiedStatus{
					TeamName: "team", AuthDomain: strings.TrimPrefix(jwtIssuer, "https://"),
				}},
			},
			HTTPRoutes: []gatewayv1.HTTPRoute{protectedRoute, unprotectedRoute, privUnprotectedRoute},
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

	t.Run("non-conformance strips cf-access-* on Public HTTP and Private HTTPS unprotected while preserving on protected", func(t *testing.T) {
		gw, _ := gatewayapi.Translate(buildInputs(false))
		var protectedPort, unprotectedPort, privUnprotectedPort int
		for _, d := range gw.Domains {
			switch d.ListenerName {
			case "protected":
				protectedPort = int(d.EnvoyPort)
			case "unprotected":
				unprotectedPort = int(d.EnvoyPort)
			case "priv-unprot":
				privUnprotectedPort = 10443
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

		envoy := startEnvoy(t, writeBootstrap(t, bootstrap), unprotectedPort, protectedPort, privUnprotectedPort)
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
			t.Fatalf("unprotected public request failed: %v\n%s", err, containerLogs(envoy.name))
		}
		assertStrippedAccessHeaders(t, unprotBody, "public unprotected")

		// Verify Private HTTPS unprotected route also strips client + Route + Backend cf-access-* headers.
		tlsClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: "priv-unprot.example.com", InsecureSkipVerify: true}, //nolint:gosec
		}}
		privURL := "https://" + strings.TrimPrefix(envoy.listenerURLs[privUnprotectedPort], "http://") + "/"
		var privBody string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, privURL, nil)
			req.Host = "priv-unprot.example.com"
			req.Header.Set("Cf-Access-Jwt-Assertion", "client-forged-jwt")
			req.Header.Set("Cf-Access-Authenticated-User-Email", "client-forged@attacker.test")
			resp, err := tlsClient.Do(req)
			if err != nil {
				return 0, "", err
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			if resp.StatusCode == http.StatusOK {
				privBody = string(b)
			}
			return resp.StatusCode, string(b), nil
		}, http.StatusOK); err != nil {
			t.Fatalf("unprotected private HTTPS request failed: %v\n%s", err, containerLogs(envoy.name))
		}
		assertStrippedAccessHeaders(t, privBody, "private HTTPS unprotected")

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
		var unprotPort int
		for _, d := range gw.Domains {
			if d.ListenerName == "unprotected" {
				unprotPort = int(d.EnvoyPort)
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
		for _, listener := range bootstrap.StaticResources.Listeners {
			listener.GetAddress().GetSocketAddress().Address = "0.0.0.0"
		}
		for _, cluster := range bootstrap.StaticResources.Clusters {
			setClusterEndpoint(cluster, "host.docker.internal", echoPort)
		}
		envoy := startEnvoy(t, writeBootstrap(t, bootstrap), unprotPort)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var body string
		if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
			req, _ := http.NewRequest(http.MethodGet, envoy.listenerURLs[unprotPort]+"/", nil)
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

// QA-1D-1 (CoreDNS runtime precedence): Real CoreDNS 1.15.0 answers exact
// hostnames ahead of overlapping wildcards regardless of PodIP vs Loopback
// binding order, and prefers 127.0.0.1 for duplicate exact hostnames.
func TestCoreDNSPrivateMixedExactAndWildcardPrecedence(t *testing.T) {
	requireDocker(t)
	gw := &ir.Gateway{
		Key: types.NamespacedName{Namespace: "demo", Name: "dns"},
		Listeners: []ir.Listener{
			{Name: "wild-pod", Hostname: "*.internal.example", Port: 9443, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
			{Name: "exact-loop", Hostname: "api.internal.example", Port: 8443, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
			{Name: "wild-loop", Hostname: "*.loop.example", Port: 8444, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
			{Name: "exact-pod", Hostname: "podexact.loop.example", Port: 9444, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
			{Name: "dup-pod", Hostname: "dup.internal.example", Port: 9445, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
			{Name: "dup-loop", Hostname: "dup.internal.example", Port: 8445, Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
		},
	}
	cm := dataplane.BuildPrivateDNSConfigMap(gw)
	if cm == nil {
		t.Fatal("BuildPrivateDNSConfigMap returned nil")
	}
	corefile := strings.ReplaceAll(cm.Data["Corefile"], ".:53 {", ".:5353 {")
	// Bind wildcard inside the container so host UDP port forwarding can reach CoreDNS.
	corefile = strings.ReplaceAll(corefile, "    bind 127.0.0.1\n", "")
	corefilePath := filepath.Join(t.TempDir(), "Corefile")
	if err := os.WriteFile(corefilePath, []byte(corefile), 0o600); err != nil {
		t.Fatalf("write Corefile: %v", err)
	}

	name := "flareway-coredns-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{
		"run", "-d", "--name", name,
		"-e", "POD_IP=192.0.2.7",
		"-p", "127.0.0.1::5353/udp",
		"-v", corefilePath + ":/Corefile:ro",
		"coredns/coredns:1.15.0@sha256:0a9d8c8ddf34347eb59aad9a8784f0710de88d6d112726d11d271f9bc6daca26",
		"-conf", "/Corefile",
	}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start CoreDNS container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		cCtx, cCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cCancel()
		_ = exec.CommandContext(cCtx, "docker", "rm", "-f", name).Run()
	})

	addrOut, err := exec.CommandContext(ctx, "docker", "port", name, "5353/udp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port 5353/udp: %v\n%s", err, addrOut)
	}
	dnsAddr := strings.TrimSpace(strings.Split(string(addrOut), "\n")[0])
	if h, p, err := net.SplitHostPort(dnsAddr); err == nil && (h == "0.0.0.0" || h == "::") {
		dnsAddr = net.JoinHostPort("127.0.0.1", p)
	}

	cases := []struct {
		host string
		want string
	}{
		{"api.internal.example", "127.0.0.1"},
		{"other.internal.example", "192.0.2.7"},
		{"podexact.loop.example", "192.0.2.7"},
		{"other.loop.example", "127.0.0.1"},
		{"dup.internal.example", "127.0.0.1"},
	}
	for _, tc := range cases {
		var got string
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			ip, err := queryDNSA(dnsAddr, tc.host)
			if err == nil && ip != "" {
				got = ip
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if got != tc.want {
			t.Fatalf("CoreDNS A(%s) = %q, want %q\nCorefile:\n%s\nLogs:\n%s", tc.host, got, tc.want, corefile, containerLogs(name))
		}
	}
}

func assertStrippedAccessHeaders(t *testing.T, body, label string) {
	t.Helper()
	received := map[string][]string{}
	if err := json.Unmarshal([]byte(body), &received); err != nil {
		t.Fatalf("decode %s headers %q: %v", label, body, err)
	}
	for k := range received {
		if strings.HasPrefix(strings.ToLower(k), "cf-access-") {
			t.Fatalf("%s backend received cf-access-* header %q: %v", label, k, received)
		}
	}
	if !slices.Equal(received["X-Keep-Route"], []string{"route-ok"}) || !slices.Equal(received["X-Keep-Backend"], []string{"backend-ok"}) {
		t.Fatalf("%s did not preserve non-access headers: %v", label, received)
	}
}

func firstMatchingIngressService(t *testing.T, params zero_trust.TunnelCloudflaredConfigurationUpdateParams, host, path string) string {
	t.Helper()
	raw, err := json.Marshal(params.Config.Raw)
	if err != nil {
		t.Fatalf("marshal cloudflared config: %v", err)
	}
	var decoded struct {
		Ingress []struct {
			Hostname string `json:"hostname"`
			Path     string `json:"path"`
			Service  string `json:"service"`
		} `json:"ingress"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal cloudflared config: %v", err)
	}
	for _, rule := range decoded.Ingress {
		matchedHost := rule.Hostname == "" || strings.EqualFold(rule.Hostname, host) ||
			(strings.HasPrefix(rule.Hostname, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(rule.Hostname[1:])))
		if !matchedHost {
			continue
		}
		if rule.Path != "" {
			re, err := regexp.Compile(rule.Path)
			if err != nil {
				t.Fatalf("invalid cloudflared path regex %q: %v", rule.Path, err)
			}
			if !re.MatchString(path) {
				continue
			}
		}
		return rule.Service
	}
	return ""
}

func queryDNSA(serverAddr, host string) (string, error) {
	conn, err := net.DialTimeout("udp", serverAddr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	pkt := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(pkt[0:2], 0x1234)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT=1
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN
	if _, err := conn.Write(pkt); err != nil {
		return "", err
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return "", err
	}
	if n < 12 {
		return "", fmt.Errorf("short DNS response %d", n)
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	skipName := func() error {
		for off < n {
			l := int(resp[off])
			if l == 0 {
				off++
				return nil
			}
			if l&0xC0 == 0xC0 {
				off += 2
				return nil
			}
			off += 1 + l
		}
		return fmt.Errorf("truncated DNS name")
	}
	for range qd {
		if err := skipName(); err != nil {
			return "", err
		}
		off += 4
	}
	for range an {
		if err := skipName(); err != nil {
			return "", err
		}
		if off+10 > n {
			return "", fmt.Errorf("truncated RR header")
		}
		rrType := binary.BigEndian.Uint16(resp[off : off+2])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10
		if off+rdLen > n {
			return "", fmt.Errorf("truncated RR data")
		}
		if rrType == 1 && rdLen == 4 {
			return net.IP(resp[off : off+4]).String(), nil
		}
		off += rdLen
	}
	return "", fmt.Errorf("no A record in DNS response (ancount=%d)", an)
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
