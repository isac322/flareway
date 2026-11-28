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
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// QA-1B-2: Private HTTPS listeners have L4 host+port Access semantics on
// Cloudflare and share one SNI TLS filter chain per listener port. Same-host
// pathScope, per-rule target splits, and multiple AccessApplications targeting
// the same Private hostname must be rejected with Invalid while keeping
// translator.Build healthy and sibling hosts/listeners unaffected.
func TestPrivateListenerRejectsPathScopePerRuleSplitAndSameHostMultiApp(t *testing.T) {
	t.Run("pathScope on Private Gateway target rejected as Invalid", func(t *testing.T) {
		in := privateWildcardInputs(t)
		in.HTTPRoutes = []gatewayv1.HTTPRoute{privateWildcardRoute("app-a", "app-a", "a.example.com")}
		key := types.NamespacedName{Namespace: "default", Name: "scoped-gw"}
		app := accessApplicationTargeting(key.Name, "Gateway", "gateway", "https")
		app.Spec.PathScope = &v1alpha1.AccessTargetPath{Type: gatewayv1.PathMatchPathPrefix, Value: "/admin"}
		in.AccessApplications = []v1alpha1.AccessApplication{app}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-a", ApplicationID: "app-a", Ready: true}}

		compiled := CompileAccessApplication(in, &app)
		if compiled.Accepted || compiled.Reason != "Invalid" {
			t.Fatalf("CompileAccessApplication(pathScope on Private) = %#v, want Accepted=false Reason=Invalid", compiled)
		}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[key]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("Translate status = %#v, want Accepted=false Reason=Invalid", got)
		}
		if _, err := translator.Build(gw, nil); err != nil {
			t.Fatalf("translator.Build must succeed when invalid Private app is rejected: %v", err)
		}
		if domain := findAccessDomain(gw.Domains, key.String()); domain != nil {
			t.Fatalf("rejected Private app produced protection domain: %#v", domain)
		}
	})

	t.Run("pathScope on Private HTTPRoute target rejected as Invalid", func(t *testing.T) {
		in := privateWildcardInputs(t)
		in.HTTPRoutes = []gatewayv1.HTTPRoute{privateWildcardRoute("app-a", "app-a", "a.example.com")}
		key := types.NamespacedName{Namespace: "default", Name: "scoped-route"}
		app := accessApplicationTargeting(key.Name, "HTTPRoute", "app-a", "")
		app.Spec.PathScope = &v1alpha1.AccessTargetPath{Type: gatewayv1.PathMatchPathPrefix, Value: "/admin"}
		in.AccessApplications = []v1alpha1.AccessApplication{app}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-a", ApplicationID: "app-a", Ready: true}}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[key]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("Translate status = %#v, want Accepted=false Reason=Invalid", got)
		}
		if _, err := translator.Build(gw, nil); err != nil {
			t.Fatalf("translator.Build failed: %v", err)
		}
	})

	t.Run("per-rule HTTPRoute sectionName split on Private listener rejected as Invalid", func(t *testing.T) {
		in := privateWildcardInputs(t)
		route := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "split", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"a.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					namedRouteRule("admin", "/admin", "backend"),
					namedRouteRule("public", "/public", "backend"),
				},
			},
		}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{
			route,
			privateWildcardRoute("healthy-b", "healthy-b", "b.example.com"),
		}
		badKey := types.NamespacedName{Namespace: "default", Name: "split-app"}
		badApp := accessApplication(badKey.Name, "HTTPRoute", "split", "admin")
		badApp.Spec.OriginJWT.AssumeGatewayTLSDecryption = true
		goodKey := types.NamespacedName{Namespace: "default", Name: "good-app"}
		goodApp := accessApplicationTargeting(goodKey.Name, "HTTPRoute", "healthy-b", "")
		in.AccessApplications = []v1alpha1.AccessApplication{badApp, goodApp}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{
			badKey:  {AUD: "aud-bad", ApplicationID: "app-bad", Ready: true},
			goodKey: {AUD: "aud-good", ApplicationID: "app-good", Ready: true},
		}

		compiled := CompileAccessApplication(in, &badApp)
		if compiled.Accepted || compiled.Reason != "Invalid" {
			t.Fatalf("CompileAccessApplication(per-rule split on Private) = %#v, want Accepted=false Reason=Invalid", compiled)
		}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[badKey]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("badApp status = %#v, want Accepted=false Reason=Invalid", got)
		}
		if got := statuses.AccessApplications[goodKey]; !got.Accepted {
			t.Fatalf("sibling healthy app status = %#v, want Accepted=true", got)
		}
		hosts, jwt := privateChainHosts(t, gw)
		assertHostOnlyBlocked(t, hosts, "a.example.com")
		assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-good")
	})

	t.Run("partial HTTPRoute targeting across two routes sharing a Private hostname rejected as Invalid", func(t *testing.T) {
		in := privateWildcardInputs(t)
		r1 := privateWildcardRoute("route-a1", "r1", "a.example.com")
		r1.Spec.Rules[0].Matches[0].Path.Value = new("/v1")
		r2 := privateWildcardRoute("route-a2", "r2", "a.example.com")
		r2.Spec.Rules[0].Matches[0].Path.Value = new("/v2")
		in.HTTPRoutes = []gatewayv1.HTTPRoute{r1, r2}

		key := types.NamespacedName{Namespace: "default", Name: "partial"}
		app := accessApplicationTargeting(key.Name, "HTTPRoute", "route-a1", "")
		in.AccessApplications = []v1alpha1.AccessApplication{app}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-a", ApplicationID: "app-a", Ready: true}}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[key]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("partial-route status = %#v, want Accepted=false Reason=Invalid", got)
		}
		if _, err := translator.Build(gw, nil); err != nil {
			t.Fatalf("translator.Build failed: %v", err)
		}
	})

	t.Run("multiple AccessApplications targeting the same Private hostname reject later app as Invalid regardless of specificity", func(t *testing.T) {
		in := privateWildcardInputs(t)
		r1 := privateWildcardRoute("route-a1", "r1", "a.example.com")
		r1.Spec.Rules[0].Matches[0].Path.Value = new("/v1")
		r2 := privateWildcardRoute("route-a2", "r2", "a.example.com")
		r2.Spec.Rules[0].Matches[0].Path.Value = new("/v2")
		in.HTTPRoutes = []gatewayv1.HTTPRoute{
			r1,
			r2,
			privateWildcardRoute("route-b", "rb", "b.example.com"),
		}
		firstKey := types.NamespacedName{Namespace: "default", Name: "first-gw"}
		first := accessApplicationTargeting(firstKey.Name, "Gateway", "gateway", "https")
		first.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))

		secondKey := types.NamespacedName{Namespace: "default", Name: "second-route"}
		second := accessApplicationTargeting(secondKey.Name, "HTTPRoute", "route-a1", "")
		second.Spec.TargetRefs = append(second.Spec.TargetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "route-a2"},
		})
		second.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))

		in.AccessApplications = []v1alpha1.AccessApplication{second, first}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{
			firstKey:  {AUD: "aud-first", ApplicationID: "app-first", Ready: true},
			secondKey: {AUD: "aud-second", ApplicationID: "app-second", Ready: true},
		}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[firstKey]; !got.Accepted {
			t.Fatalf("older app status = %#v, want Accepted=true", got)
		}
		if got := statuses.AccessApplications[secondKey]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("overlapping Private app status = %#v, want Accepted=false Reason=Invalid", got)
		}
		hosts, jwt := privateChainHosts(t, gw)
		assertHostForwardsBehindAUD(t, hosts, jwt, "a.example.com", "aud-first")
		assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-first")
	})

	t.Run("same-specificity duplicate AccessApplications on same Private host reject later app as Invalid", func(t *testing.T) {
		in := privateWildcardInputs(t)
		in.HTTPRoutes = []gatewayv1.HTTPRoute{
			privateWildcardRoute("route-a", "ra", "a.example.com"),
			privateWildcardRoute("route-b", "rb", "b.example.com"),
		}
		firstKey := types.NamespacedName{Namespace: "default", Name: "first"}
		first := accessApplicationTargeting(firstKey.Name, "HTTPRoute", "route-a", "")
		first.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
		secondKey := types.NamespacedName{Namespace: "default", Name: "second"}
		second := accessApplicationTargeting(secondKey.Name, "HTTPRoute", "route-a", "")
		second.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
		otherKey := types.NamespacedName{Namespace: "default", Name: "other"}
		other := accessApplicationTargeting(otherKey.Name, "HTTPRoute", "route-b", "")
		other.CreationTimestamp = metav1.NewTime(time.Unix(3, 0))

		in.AccessApplications = []v1alpha1.AccessApplication{second, first, other}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{
			firstKey:  {AUD: "aud-first", ApplicationID: "app-first", Ready: true},
			secondKey: {AUD: "aud-second", ApplicationID: "app-second", Ready: true},
			otherKey:  {AUD: "aud-other", ApplicationID: "app-other", Ready: true},
		}

		gw, statuses := Translate(in)
		if !statuses.AccessApplications[firstKey].Accepted || !statuses.AccessApplications[otherKey].Accepted {
			t.Fatalf("healthy apps rejected: %#v", statuses.AccessApplications)
		}
		if got := statuses.AccessApplications[secondKey]; got.Accepted || got.Reason != "Invalid" {
			t.Fatalf("duplicate Private app status = %#v, want Accepted=false Reason=Invalid", got)
		}
		hosts, jwt := privateChainHosts(t, gw)
		assertHostForwardsBehindAUD(t, hosts, jwt, "a.example.com", "aud-first")
		assertHostForwardsBehindAUD(t, hosts, jwt, "b.example.com", "aud-other")
	})
}

// QA-1-REG-2: Public hierarchical pathScope & per-rule splits keep working,
// and Private single-rule non-root HTTPRoute + multi-app on different hosts
// keep working on the shared Private TLS filter chain.
func TestPublicListenerKeepsPathScopePerRuleSplitAndPrivateMultiHostStillWorks(t *testing.T) {
	t.Run("Private non-root single-rule HTTPRoute builds without priv-blocked collision", func(t *testing.T) {
		in := privateWildcardInputs(t)
		r := privateWildcardRoute("route-api", "api", "api.example.com")
		r.Spec.Rules[0].Matches[0].Path.Value = new("/api")
		in.HTTPRoutes = []gatewayv1.HTTPRoute{r}
		key := types.NamespacedName{Namespace: "default", Name: "api-app"}
		app := accessApplicationTargeting(key.Name, "HTTPRoute", "route-api", "")
		in.AccessApplications = []v1alpha1.AccessApplication{app}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{key: {AUD: "aud-api", ApplicationID: "app-api", Ready: true}}

		gw, statuses := Translate(in)
		if got := statuses.AccessApplications[key]; !got.Accepted {
			t.Fatalf("non-root Private app rejected: %#v", got)
		}
		hosts, jwt := privateChainHosts(t, gw)
		assertHostOnlyBlocked(t, hosts, "*.example.com")
		assertHostForwardsBehindAUD(t, hosts, jwt, "api.example.com", "aud-api")
	})

	t.Run("Public listener retains pathScope overlay and per-rule split", func(t *testing.T) {
		in := accessInputs(true)
		in.HTTPRoutes = []gatewayv1.HTTPRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "routes", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Rules: []gatewayv1.HTTPRouteRule{
					namedRouteRule("admin", "/admin", "backend"),
					namedRouteRule("health", "/health", "backend"),
				},
			},
		}}
		parentKey := types.NamespacedName{Namespace: "default", Name: "parent"}
		parent := accessApplication(parentKey.Name, "HTTPRoute", "routes", "admin")
		parent.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
		overlayKey := types.NamespacedName{Namespace: "default", Name: "overlay"}
		overlay := accessApplication(overlayKey.Name, "HTTPRoute", "routes", "admin")
		overlay.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
		overlay.Spec.PathScope = &v1alpha1.AccessTargetPath{Type: gatewayv1.PathMatchPathPrefix, Value: "/admin/super"}
		in.AccessApplications = []v1alpha1.AccessApplication{parent, overlay}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{
			parentKey:  {AUD: "aud-parent", ApplicationID: "app-parent", Ready: true},
			overlayKey: {AUD: "aud-overlay", ApplicationID: "app-overlay", Ready: true},
		}

		gw, statuses := Translate(in)
		if !statuses.AccessApplications[parentKey].Accepted || !statuses.AccessApplications[overlayKey].Accepted {
			t.Fatalf("Public pathScope/per-rule split failed: %#v", statuses.AccessApplications)
		}
		if _, err := translator.Build(gw, nil); err != nil {
			t.Fatalf("translator.Build failed on Public pathScope/per-rule split: %v", err)
		}
	})
}

// QA-1E-1: Unclaimed unprotected routes alongside sibling AccessApplications
// must always run sanitizeUnprotectedRoute (stripping cf-access-* Set/Add
// headers at both Route and Backend levels), while Protected Forwarding domains
// keep StripAccessHeaders=false and ConformanceMode skips stripping.
// Also verifies partitionAccessVirtualHost evaluates unprotected carve-out
// authorization using the base listener's Exposure rather than hardcoded Public.
func TestPartitionAccessVirtualHostUsesListenerExposureAndSanitizesUnclaimedUnprotectedRoutes(t *testing.T) {
	t.Run("unclaimed unprotected routes alongside sibling AccessApplication strip cf-access-* at route and backend levels", func(t *testing.T) {
		in := accessInputs(true)
		in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"protected.example.com", "unprotected.example.com"}
		in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"unprotected.example.com"}
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{
			{Name: "protected", Hostname: new(gatewayv1.Hostname("protected.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "unprotected", Hostname: new(gatewayv1.Hostname("unprotected.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		}

		protectedRoute := routeWithBackend("protected-route", "backend", 8080)
		protectedRoute.Spec.Hostnames = []gatewayv1.Hostname{"protected.example.com"}
		protectedRoute.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("protected"))

		unprotectedRoute := routeWithBackend("unprotected-route", "backend", 8080)
		unprotectedRoute.Spec.Hostnames = []gatewayv1.Hostname{"unprotected.example.com"}
		unprotectedRoute.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("unprotected"))
		unprotectedRoute.Spec.Rules[0].Filters = []gatewayv1.HTTPRouteFilter{{
			Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
			RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{
					{Name: "Cf-Access-Authenticated-User-Email", Value: "spoof@attacker.test"},
					{Name: "X-Keep-Route", Value: "yes"},
				},
				Add: []gatewayv1.HTTPHeader{
					{Name: "cf-access-custom-role", Value: "admin"},
				},
			},
		}}
		unprotectedRoute.Spec.Rules[0].BackendRefs[0].Filters = []gatewayv1.HTTPRouteFilter{{
			Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
			RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{
					{Name: "Cf-Access-Jwt-Assertion", Value: "forged-jwt"},
					{Name: "X-Keep-Backend", Value: "yes"},
				},
				Add: []gatewayv1.HTTPHeader{
					{Name: "Cf-Access-Client-Id", Value: "forged-id"},
				},
			},
		}}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{protectedRoute, unprotectedRoute}

		appKey := types.NamespacedName{Namespace: "default", Name: "app"}
		in.AccessApplications = []v1alpha1.AccessApplication{accessApplication(appKey.Name, "Gateway", "gateway", "protected")}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{appKey: {AUD: "aud-1", ApplicationID: "app-1", Ready: true}}

		gw, statuses := Translate(in)
		if !statuses.AccessApplications[appKey].Accepted {
			t.Fatalf("protected app not accepted: %#v", statuses.AccessApplications[appKey])
		}
		protectedDomain := findAccessDomain(gw.Domains, appKey.String())
		if protectedDomain == nil || protectedDomain.StripAccessHeaders {
			t.Fatalf("protected domain should keep StripAccessHeaders=false: %#v", protectedDomain)
		}
		unprotectedDomain := findDomain(gw.Domains, false, ir.GuardUnprotected)
		if unprotectedDomain == nil || !unprotectedDomain.StripAccessHeaders {
			t.Fatalf("unprotected domain should set StripAccessHeaders=true: %#v", unprotectedDomain)
		}
		route := unprotectedDomain.VirtualHosts[0].Routes[0]
		if route.Filters.RequestHeaders == nil {
			t.Fatal("route.Filters.RequestHeaders unexpectedly nil")
		}
		for _, hdr := range append(slices.Clone(route.Filters.RequestHeaders.Set), route.Filters.RequestHeaders.Add...) {
			if strings.HasPrefix(strings.ToLower(hdr.Name), "cf-access-") {
				t.Fatalf("unprotected route retained cf-access-* Set/Add header %q", hdr.Name)
			}
		}
		if len(route.Filters.RequestHeaders.Set) != 1 || !strings.EqualFold(route.Filters.RequestHeaders.Set[0].Name, "X-Keep-Route") {
			t.Fatalf("unprotected route Set headers = %#v, want only X-Keep-Route", route.Filters.RequestHeaders.Set)
		}
		if !containsStringFold(route.Filters.RequestHeaders.Remove, "cf-access-authenticated-user-email") {
			t.Fatalf("unprotected route Remove headers missing reserved access headers: %#v", route.Filters.RequestHeaders.Remove)
		}
		backendHeaders := route.Backends[0].Filters.RequestHeaders
		if backendHeaders == nil {
			t.Fatal("backend.Filters.RequestHeaders unexpectedly nil")
		}
		for _, hdr := range append(slices.Clone(backendHeaders.Set), backendHeaders.Add...) {
			if strings.HasPrefix(strings.ToLower(hdr.Name), "cf-access-") {
				t.Fatalf("unprotected backend retained cf-access-* Set/Add header %q", hdr.Name)
			}
		}
		if len(backendHeaders.Set) != 1 || !strings.EqualFold(backendHeaders.Set[0].Name, "X-Keep-Backend") {
			t.Fatalf("unprotected backend Set headers = %#v, want only X-Keep-Backend", backendHeaders.Set)
		}
	})

	t.Run("partitionAccessVirtualHost evaluates unprotected carve-out with base listener Exposure", func(t *testing.T) {
		in := privateWildcardInputs(t)
		in.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("api.example.com"))
		// Grant UnprotectedHostnames ONLY on Public exposure (NOT Private!).
		// If partitionAccessVirtualHost hardcodes ExposurePublic, it would
		// wrongly treat Private api.example.com as unprotected-allowed!
		in.CloudflareAccount.Spec.Grants = []v1alpha1.CloudflareAccountGrant{
			{
				NamespaceSelector:    metav1.LabelSelector{},
				Hostnames:            []string{"api.example.com"},
				Zones:                []string{"example.com"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"api.example.com"},
				Backends:             &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			},
			{
				NamespaceSelector: metav1.LabelSelector{},
				Hostnames:         []string{"api.example.com"},
				Zones:             []string{"example.com"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
				Backends:          &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			},
		}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "tools", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Rules: []gatewayv1.HTTPRouteRule{
					namedRouteRule("dashboard", "/", "backend"),
					namedRouteRule("public-health", "/health", "backend"),
				},
			},
		}}
		// Directly exercise partitionAccessVirtualHost with a claimed Private
		// rule + unclaimed carve-out rule to verify ExposurePrivate is used.
		gw := &ir.Gateway{
			Key:       types.NamespacedName{Namespace: "default", Name: "gateway"},
			Listeners: []ir.Listener{{Name: "https", Hostname: "api.example.com", Port: 443, EnvoyPort: 443, Protocol: "HTTPS", Exposure: ir.ExposurePrivate}},
		}
		appKey := types.NamespacedName{Namespace: "default", Name: "dash"}
		statuses := &Statuses{
			AccessApplications: map[types.NamespacedName]AccessApplicationCompilation{
				appKey: {
					Accepted: true,
					claims: []accessClaim{{
						listener: "https", hostname: "api.example.com", routeName: "tools/dashboard/0",
						region: accessRegion{kind: accessRegionPrefix, path: "/"}, wholeHost: false, specificity: 20,
					}},
				},
			},
			HTTPRoutes: map[types.NamespacedName]gatewayv1.HTTPRouteStatus{},
		}
		base := ir.ProtectionDomain{Name: "https", ListenerName: "https", EnvoyPort: 443, Protected: true, Guard: ir.GuardBlocked}
		host := ir.VirtualHost{
			Name:     "https-api",
			Hostname: "api.example.com",
			Routes: []ir.Route{
				{Name: "tools/dashboard/0", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}, Source: ir.RouteSource{Namespace: "default", Name: "tools", RuleName: "dashboard"}},
				{Name: "tools/public-health/0", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/health"}, Source: ir.RouteSource{Namespace: "default", Name: "tools", RuleName: "public-health"}},
			},
		}
		dropped := map[routeListenerKey][]string{}
		rlKey := routeListenerKey{route: types.NamespacedName{Namespace: "default", Name: "tools"}, listener: "https"}
		remaining := map[routeListenerKey]int{rlKey: 2}
		partitionAccessVirtualHost(in, gw, statuses, base, host, nil, dropped, remaining)
		if public := findDomain(gw.Domains, false, ir.GuardUnprotected); public != nil {
			t.Fatalf("Private carve-out allowed using Public UnprotectedHostnames grant: %#v", public)
		}
		if len(dropped[rlKey]) != 1 {
			t.Fatalf("expected Private carve-out without Private unprotected grant to be dropped, got dropped=%#v", dropped)
		}
	})

	t.Run("Translate evaluates Private unprotected authorization in both grant directions", func(t *testing.T) {
		buildInputs := func(grantExposures []v1alpha1.Exposure) Inputs {
			in := privateWildcardInputs(t)
			in.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("api.example.com"))
			in.CloudflareAccount.Spec.Grants = []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{},
				Hostnames:         []string{"api.example.com"},
				Zones:             []string{"example.com"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
				Backends:          &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			}, {
				NamespaceSelector:    metav1.LabelSelector{},
				Hostnames:            []string{"api.example.com"},
				Zones:                []string{"example.com"},
				Exposures:            grantExposures,
				UnprotectedHostnames: []string{"api.example.com"},
				Backends:             &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			}}
			in.HTTPRoutes = []gatewayv1.HTTPRoute{privateWildcardRoute("api", "api", "api.example.com")}
			return in
		}

		// Public-only UnprotectedHostnames grant must NOT make Private listener unprotected.
		gwPublicOnly, _ := Translate(buildInputs([]v1alpha1.Exposure{v1alpha1.ExposurePublic}))
		if len(gwPublicOnly.Domains) != 1 || gwPublicOnly.Domains[0].Guard != ir.GuardBlocked {
			t.Fatalf("Private listener allowed Public-only UnprotectedHostnames grant: %#v", gwPublicOnly.Domains)
		}

		// Private-only UnprotectedHostnames grant allows Private listener unprotected
		// and enables cf-access-* stripping.
		gwPrivateOnly, _ := Translate(buildInputs([]v1alpha1.Exposure{v1alpha1.ExposurePrivate}))
		if len(gwPrivateOnly.Domains) != 1 || gwPrivateOnly.Domains[0].Guard != ir.GuardUnprotected || !gwPrivateOnly.Domains[0].StripAccessHeaders {
			t.Fatalf("Private listener rejected Private UnprotectedHostnames grant or skipped header strip: %#v", gwPrivateOnly.Domains)
		}
	})
}

// QA-1F-1: When applyAccessRouteDrops drops all rules of an HTTPRoute on a
// listener, Gateway.Status.Listeners[*].AttachedRoutes excludes that route on
// that listener while keeping unaffected listeners and partial drops counted and
// scoping PartiallyInvalid/Accepted=False to the affected parentRefs.
func TestApplyAccessRouteDropsUpdatesListenerAttachedRoutes(t *testing.T) {
	in := accessInputs(false)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"a.example.com", "b.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"b.example.com"}
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: "a", Hostname: new(gatewayv1.Hostname("a.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "b", Hostname: new(gatewayv1.Hostname("b.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
	}

	sectionA := gatewayv1.SectionName("a")
	sectionB := gatewayv1.SectionName("b")

	protectedOnA := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "protected-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &sectionA}}},
			Hostnames:       []gatewayv1.Hostname{"a.example.com"},
			Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("admin", "/admin", "backend")},
		},
	}
	fullyDroppedOnA := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "dropped-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &sectionA}}},
			Hostnames:       []gatewayv1.Hostname{"a.example.com"},
			Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("public-only", "/health", "backend")},
		},
	}
	partialOnA := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "partial-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(3, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &sectionA}}},
			Hostnames:       []gatewayv1.Hostname{"a.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("kept", "/kept", "backend"),
				namedRouteRule("dropped", "/v1", "backend"),
			},
		},
	}
	// Multi-listener route: dropped completely on listener "a", kept on listener "b".
	mixedMulti := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "mixed-multi", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(4, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{
				{Name: "gateway", SectionName: &sectionA},
				{Name: "gateway", SectionName: &sectionB},
			}},
			Hostnames: []gatewayv1.Hostname{"a.example.com", "b.example.com"},
			Rules:     []gatewayv1.HTTPRouteRule{namedRouteRule("shared-rule", "/shared", "backend")},
		},
	}
	unaffectedOnB := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "unaffected-b", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(5, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: &sectionB}}},
			Hostnames:       []gatewayv1.Hostname{"b.example.com"},
			Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("ok", "/ok", "backend")},
		},
	}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{protectedOnA, fullyDroppedOnA, partialOnA, mixedMulti, unaffectedOnB}
	appKey := types.NamespacedName{Namespace: "default", Name: "admin-app"}
	app := accessApplication(appKey.Name, "HTTPRoute", "protected-a", "admin")
	app.Spec.TargetRefs = append(app.Spec.TargetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "partial-a"},
		SectionName:                new(gatewayv1.SectionName("kept")),
	})
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{appKey: {AUD: "aud-1", ApplicationID: "app-1", Ready: true}}

	_, statuses := Translate(in)

	// Fully dropped route on "a": Accepted=False, PartiallyInvalid=True.
	droppedKey := types.NamespacedName{Namespace: "default", Name: "dropped-a"}
	if cond := findRouteCondition(statuses.HTTPRoutes[droppedKey], gatewayv1.RouteConditionAccepted); cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("dropped-a Accepted = %#v, want False", cond)
	}
	if cond := findRouteCondition(statuses.HTTPRoutes[droppedKey], gatewayv1.RouteConditionPartiallyInvalid); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("dropped-a PartiallyInvalid = %#v, want True", cond)
	}

	// Partially dropped route on "a": Accepted=True, PartiallyInvalid=True.
	partialKey := types.NamespacedName{Namespace: "default", Name: "partial-a"}
	if cond := findRouteCondition(statuses.HTTPRoutes[partialKey], gatewayv1.RouteConditionAccepted); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("partial-a Accepted = %#v, want True", cond)
	}
	if cond := findRouteCondition(statuses.HTTPRoutes[partialKey], gatewayv1.RouteConditionPartiallyInvalid); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("partial-a PartiallyInvalid = %#v, want True", cond)
	}

	// Multi-listener route: parent "a" is Accepted=False & PartiallyInvalid=True,
	// while parent "b" stays Accepted=True with NO PartiallyInvalid condition.
	mixedStatus := statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "mixed-multi"}]
	if len(mixedStatus.Parents) != 2 {
		t.Fatalf("mixed-multi parents = %#v, want 2", mixedStatus.Parents)
	}
	for _, parent := range mixedStatus.Parents {
		var acc, partial *metav1.Condition
		for index := range parent.Conditions {
			switch parent.Conditions[index].Type {
			case string(gatewayv1.RouteConditionAccepted):
				acc = &parent.Conditions[index]
			case string(gatewayv1.RouteConditionPartiallyInvalid):
				partial = &parent.Conditions[index]
			}
		}
		if *parent.ParentRef.SectionName == sectionA {
			if acc == nil || acc.Status != metav1.ConditionFalse {
				t.Fatalf("mixed-multi parent a Accepted = %#v, want False", acc)
			}
			if partial == nil || partial.Status != metav1.ConditionTrue {
				t.Fatalf("mixed-multi parent a PartiallyInvalid = %#v, want True", partial)
			}
		} else {
			if acc == nil || acc.Status != metav1.ConditionTrue {
				t.Fatalf("mixed-multi parent b Accepted = %#v, want True", acc)
			}
			if partial != nil {
				t.Fatalf("mixed-multi parent b unexpectedly tainted with PartiallyInvalid: %#v", partial)
			}
		}
	}

	// Listener "a" keeps only protected-a + partial-a (2); listener "b" keeps mixed-multi + unaffected-b (2).
	if got := statuses.Gateway.Listeners[0].AttachedRoutes; got != 2 {
		t.Fatalf("listener a AttachedRoutes = %d, want 2 (protected-a + partial-a)", got)
	}
	if got := statuses.Gateway.Listeners[1].AttachedRoutes; got != 2 {
		t.Fatalf("listener b AttachedRoutes = %d, want 2 (mixed-multi + unaffected-b)", got)
	}
}

// QA-1-REG-1: Public -public and -blocked protection domains receive distinct
// loopback ports via publicPorts.takeDomain and preserve sticky ports across
// reconciles (without stickyBase stealing -public/-blocked ports).
func TestPublicDerivedDomainsPreserveStickyPortsAcrossReconciles(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"a.example.com"}
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
		Name: "web", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	}}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"a.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					namedRouteRule("admin", "/admin", "backend"),
					namedRouteRule("health", "/health", "backend"),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "route-b", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"b.example.com"},
				Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("admin", "/admin", "backend")},
			},
		},
	}
	appA := accessApplication("app-a", "HTTPRoute", "route-a", "admin")
	appB := accessApplication("app-b", "HTTPRoute", "route-b", "admin")
	in.AccessApplications = []v1alpha1.AccessApplication{appA, appB}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		{Namespace: "default", Name: "app-a"}: {AUD: "aud-a", ApplicationID: "id-a", Ready: true},
		{Namespace: "default", Name: "app-b"}: {AUD: "aud-b", ApplicationID: "id-b", Ready: true},
	}

	gw1, _ := Translate(in)
	if _, err := translator.Build(gw1, nil); err != nil {
		t.Fatalf("first translator.Build failed: %v", err)
	}
	var recorded []v1alpha1.CloudflareProtectionDomainStatus
	ports1 := make(map[string]int32)
	for _, d := range gw1.Domains {
		ports1[d.Name] = d.EnvoyPort
		recorded = append(recorded, v1alpha1.CloudflareProtectionDomainStatus{
			Name: d.Name, EnvoyPort: d.EnvoyPort, Protected: d.Protected,
		})
	}

	// Simulate second reconcile with persisted status (plus an unrelated new
	// public listener added ahead of "web"): every derived domain must keep its
	// exact port, including -public and -blocked.
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name: "web", Exposure: v1alpha1.ExposurePublic, ProtectionDomains: recorded,
	}}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = append(in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames, "extra.example.com")
	in.Gateway.Spec.Listeners = append([]gatewayv1.Listener{{
		Name: "extra", Hostname: new(gatewayv1.Hostname("extra.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
	}}, in.Gateway.Spec.Listeners...)

	gw2, _ := Translate(in)
	if _, err := translator.Build(gw2, nil); err != nil {
		t.Fatalf("second translator.Build failed: %v", err)
	}
	for _, d := range gw2.Domains {
		if d.ListenerName != "web" {
			continue
		}
		if want, ok := ports1[d.Name]; !ok || d.EnvoyPort != want {
			t.Fatalf("domain %q shifted port from %d to %d", d.Name, want, d.EnvoyPort)
		}
	}

	// Also verify exact-listener case where base "web" is absent from Status.Listeners
	// and only "web-public" and "web-access-..." exist: stickyBase must not steal
	// web-public's port.
	inExact := accessInputs(true)
	inExact.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "tools", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("dashboard", "/", "backend"),
				namedRouteRule("health", "/health", "backend"),
			},
		},
	}}
	appDash := accessApplication("dash", "HTTPRoute", "tools", "dashboard")
	inExact.AccessApplications = []v1alpha1.AccessApplication{appDash}
	inExact.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "dash"}: {AUD: "aud-d", ApplicationID: "id-d", Ready: true}}
	gwExact1, _ := Translate(inExact)
	exactPublic := findDomain(gwExact1.Domains, false, ir.GuardUnprotected)
	exactProtected := findAccessDomain(gwExact1.Domains, "default/dash")
	inExact.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name: "http", Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: exactPublic.Name, EnvoyPort: exactPublic.EnvoyPort},
			{Name: exactProtected.Name, EnvoyPort: exactProtected.EnvoyPort, Protected: true},
		},
	}}
	gwExact2, _ := Translate(inExact)
	if got := findDomain(gwExact2.Domains, false, ir.GuardUnprotected).EnvoyPort; got != exactPublic.EnvoyPort {
		t.Fatalf("exact listener %s shifted port across reconcile: got %d, want %d", exactPublic.Name, got, exactPublic.EnvoyPort)
	}
}

// QA-1-REG-5: Validate reserved dataplane pod ports (53, 2000, 18000, 19000,
// 19001) are rejected on Private listeners when !ConformanceMode, while
// non-reserved Private ports and all ConformanceMode ports stay accepted.
func TestPrivateListenerReservedPortValidationAndConformanceExemption(t *testing.T) {
	reservedPorts := []gatewayv1.PortNumber{53, 2000, 18000, 19000, 19001}
	for _, port := range reservedPorts {
		in := privateWildcardInputs(t)
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{
			{
				Name: "bad-private", Hostname: new(gatewayv1.Hostname("bad.example.com")), Port: port, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}},
			},
			{
				Name: "good-private", Hostname: new(gatewayv1.Hostname("good.example.com")), Port: 8443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}},
			},
		}
		in.CloudflareTunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "bad-private", Exposure: v1alpha1.ExposurePrivate},
			{Name: "good-private", Exposure: v1alpha1.ExposurePrivate},
		}
		gw, statuses := Translate(in)
		badCond := findListenerCondition(statuses.Gateway, "bad-private", gatewayv1.ListenerConditionAccepted)
		if badCond == nil || badCond.Status != metav1.ConditionFalse || badCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
			t.Fatalf("port %d Accepted = %#v, want False/PortUnavailable", port, badCond)
		}
		goodCond := findListenerCondition(statuses.Gateway, "good-private", gatewayv1.ListenerConditionAccepted)
		if goodCond == nil || goodCond.Status != metav1.ConditionTrue {
			t.Fatalf("sibling good-private Accepted = %#v, want True", goodCond)
		}
		if len(gw.Listeners) != 1 || gw.Listeners[0].Name != "good-private" {
			t.Fatalf("IR listeners = %#v, want only good-private", gw.Listeners)
		}

		// ConformanceMode exempts reserved ports.
		in.GatewayClassConfig.Spec.ConformanceMode = true
		_, confStatuses := Translate(in)
		confCond := findListenerCondition(confStatuses.Gateway, "bad-private", gatewayv1.ListenerConditionAccepted)
		if confCond == nil || confCond.Status != metav1.ConditionTrue {
			t.Fatalf("conformance mode port %d Accepted = %#v, want True", port, confCond)
		}
	}

	// Non-reserved Private port (e.g. 19002) remains Accepted.
	in := privateWildcardInputs(t)
	in.Gateway.Spec.Listeners[0].Port = 19002
	_, statuses := Translate(in)
	if cond := findListenerCondition(statuses.Gateway, "https", gatewayv1.ListenerConditionAccepted); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("non-reserved private port 19002 Accepted = %#v, want True", cond)
	}
}

// Finding 1: Adding AccessApplication to one path on an exact Public hostname
// creates a "<listener>-public" carve-out for remaining unprotected routes;
// it must preserve the previously published base port rather than shifting off it.
func TestExactPublicCarveOutPreservesBasePort(t *testing.T) {
	in := accessInputs(true)
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
		Name: "http", Hostname: new(gatewayv1.Hostname("app.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	}}
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"app.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"app.example.com"}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "tools", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("admin", "/admin", "backend"),
				namedRouteRule("health", "/health", "backend"),
			},
		},
	}}

	// Before AccessApplication exists, exact listener "http" publishes base port 18085.
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name:              "http",
		Exposure:          v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: "http", EnvoyPort: 18085}},
	}}

	// Add AccessApplication targeting only the "admin" rule, leaving "/health" unprotected.
	appAdmin := accessApplication("admin-app", "HTTPRoute", "tools", "admin")
	in.AccessApplications = []v1alpha1.AccessApplication{appAdmin}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "admin-app"}: {AUD: "aud-admin", ApplicationID: "id-admin", Ready: true}}

	gw1, _ := Translate(in)
	if _, err := translator.Build(gw1, nil); err != nil {
		t.Fatalf("first translator.Build failed: %v", err)
	}
	pub := findDomain(gw1.Domains, false, ir.GuardUnprotected)
	if pub == nil {
		t.Fatal("expected unprotected carve-out domain")
	}
	prot := findAccessDomain(gw1.Domains, "default/admin-app")
	if prot == nil {
		t.Fatal("expected protected domain")
	}
	if pub.EnvoyPort != 18085 {
		t.Fatalf("carve-out domain %q shifted from base port 18085 to %d", pub.Name, pub.EnvoyPort)
	}
	if prot.EnvoyPort == pub.EnvoyPort {
		t.Fatalf("protected domain collided on base port %d", prot.EnvoyPort)
	}

	// Next reconcile sees http-public + http-access-... recorded in Status.Listeners;
	// both must keep their exact ports cleanly.
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name:     "http",
		Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: pub.Name, EnvoyPort: pub.EnvoyPort},
			{Name: prot.Name, EnvoyPort: prot.EnvoyPort, Protected: true},
		},
	}}
	gw2, _ := Translate(in)
	if _, err := translator.Build(gw2, nil); err != nil {
		t.Fatalf("second translator.Build failed: %v", err)
	}
	if got := findDomain(gw2.Domains, false, ir.GuardUnprotected).EnvoyPort; got != 18085 {
		t.Fatalf("reconciled carve-out domain shifted from 18085 to %d", got)
	}
	if got := findAccessDomain(gw2.Domains, "default/admin-app").EnvoyPort; got != prot.EnvoyPort {
		t.Fatalf("reconciled protected domain shifted from %d to %d", prot.EnvoyPort, got)
	}
}

// #4722620648: Transitioning an exact Public listener from split
// (<listener>-public + <listener>-access-...) back to unsplit must reuse the
// recorded <listener>-public Envoy port for the unsplit base domain instead of
// allocating a fresh port.
func TestExactPublicUnsplitReusesCarveOutPort(t *testing.T) {
	in := accessInputs(true)
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
		Name: "web", Hostname: new(gatewayv1.Hostname("app.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	}}
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"app.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"app.example.com"}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "tools", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("admin", "/admin", "backend"),
				namedRouteRule("health", "/health", "backend"),
			},
		},
	}}

	// Split state recorded in CloudflareTunnel.Status.Listeners (no base "web" entry,
	// only "web-public" on 18120 and "web-access-..." on 18121).
	const splitPublicPort int32 = 18120
	const splitProtectedPort int32 = 18121
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name:     "web",
		Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: "web-public", EnvoyPort: splitPublicPort},
			{Name: "web-access-default-admin-app", EnvoyPort: splitProtectedPort, Protected: true},
		},
	}}

	// Remove AccessApplication targeting /admin so "web" becomes unsplit (/admin + /health).
	in.AccessApplications = nil
	in.AUDSecrets = nil

	gw, _ := Translate(in)
	if _, err := translator.Build(gw, nil); err != nil {
		t.Fatalf("translator.Build failed: %v", err)
	}
	base := findDomain(gw.Domains, false, ir.GuardUnprotected)
	if base == nil || base.Name != "web" {
		t.Fatalf("expected unsplit base domain \"web\", got %#v", gw.Domains)
	}
	if base.EnvoyPort != splitPublicPort {
		t.Fatalf("unsplit base domain %q allocated port %d, want reused -public port %d", base.Name, base.EnvoyPort, splitPublicPort)
	}
}

// #4723260033: Upgrading a wildcard Public listener from v0.5.0 where persisted
// status lists a derived alias ("web-public") before the literal base ("web")
// sharing the same Envoy port must prioritize literal "web" so the base domain
// keeps its recorded port while derived domains allocate distinct unused ports.
func TestWildcardPublicLiteralBaseTakesPriorityOverLegacyDerivedAlias(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"a.example.com", "b.example.com"}
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
		Name: "web", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	}}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"a.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					namedRouteRule("admin", "/admin", "backend"),
					namedRouteRule("health", "/health", "backend"),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "route-b", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"b.example.com"},
				Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("home", "/", "backend")},
			},
		},
	}
	appA := accessApplication("app-a", "HTTPRoute", "route-a", "admin")
	in.AccessApplications = []v1alpha1.AccessApplication{appA}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "app-a"}: {AUD: "aud-a", ApplicationID: "id-a", Ready: true}}

	const legacyBasePort int32 = 18080
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name:     "web",
		Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: "web-public", EnvoyPort: legacyBasePort},
			{Name: "web", EnvoyPort: legacyBasePort},
		},
	}}

	gw, _ := Translate(in)
	if _, err := translator.Build(gw, nil); err != nil {
		t.Fatalf("translator.Build failed: %v", err)
	}
	var baseDomain *ir.ProtectionDomain
	var derivedPorts []int32
	for index := range gw.Domains {
		d := &gw.Domains[index]
		if d.Name == "web" {
			baseDomain = d
			continue
		}
		derivedPorts = append(derivedPorts, d.EnvoyPort)
	}
	if baseDomain == nil {
		t.Fatalf("expected literal base domain \"web\", got %#v", gw.Domains)
	}
	if baseDomain.EnvoyPort != legacyBasePort {
		t.Fatalf("literal base domain \"web\" shifted from %d to %d", legacyBasePort, baseDomain.EnvoyPort)
	}
	if len(derivedPorts) != 2 {
		t.Fatalf("expected 2 derived domains (-public and -access), got %#v", gw.Domains)
	}
	for _, port := range derivedPorts {
		if port == legacyBasePort {
			t.Fatalf("derived domain collided on literal base port %d: %#v", legacyBasePort, gw.Domains)
		}
	}
	if derivedPorts[0] == derivedPorts[1] {
		t.Fatalf("derived domains collided on port %d: %#v", derivedPorts[0], gw.Domains)
	}
}

// #4723566864: During an in-place v0.5.0 upgrade on a wildcard Public listener
// where base ("web") and an exact-host carve-out ("web-public") shared 18080,
// keep a ShadowOnly domain on 18080 serving app.example.com /health until
// Status.Hostnames records the new dedicated web-public-<hostHash> domain, while
// compiling cloudflared ingress exclusively against the new port.
func TestWildcardPublicLegacyCarveOutShadowDuringUpgrade(t *testing.T) {
	firstIngressService := func(t *testing.T, gw *ir.Gateway, host, path string) (string, string) {
		t.Helper()
		if gw.Cloudflare == nil {
			gw.Cloudflare = &ir.Cloudflare{AccountID: "0123456789abcdef0123456789abcdef"}
		}
		params, hash, err := cloudflared.Compile(gw)
		if err != nil {
			t.Fatalf("cloudflared.Compile failed: %v", err)
		}
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
					t.Fatalf("compile path %q: %v", rule.Path, err)
				}
				if !re.MatchString(path) {
					continue
				}
			}
			return rule.Service, hash
		}
		return "", hash
	}

	makeInputs := func(includeBaseRoute, includeHealthRoute bool, unprotectedHosts []string) Inputs {
		in := accessInputs(true)
		in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
		in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = unprotectedHosts
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
			Name: "web", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
		}}
		rulesA := []gatewayv1.HTTPRouteRule{namedRouteRule("admin", "/admin", "backend")}
		if includeHealthRoute {
			rulesA = append(rulesA, namedRouteRule("health", "/health", "backend"))
		}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Hostnames:       []gatewayv1.Hostname{"app.example.com"},
				Rules:           rulesA,
			},
		}}
		if includeBaseRoute {
			in.HTTPRoutes = append(in.HTTPRoutes, gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route-b", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
					Hostnames:       []gatewayv1.Hostname{"other.example.com"},
					Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("home", "/", "backend")},
				},
			})
		}
		appA := accessApplication("app-a", "HTTPRoute", "route-a", "admin")
		in.AccessApplications = []v1alpha1.AccessApplication{appA}
		in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "app-a"}: {AUD: "aud-a", ApplicationID: "id-a", Ready: true}}
		in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "web",
			Exposure: v1alpha1.ExposurePublic,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
				{Name: "web", EnvoyPort: 18080},
				{Name: "web-public", EnvoyPort: 18080},
			},
		}}
		in.CloudflareTunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{
			{Hostname: "app.example.com", ProtectionDomain: "web-public", Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
			{Hostname: "app.example.com", ProtectionDomain: "web-access-default-app-a", AccessApplication: "default/app-a", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1},
			{Hostname: "other.example.com", ProtectionDomain: "web", Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
		}
		return in
	}

	// Case A: base ("web") + carve-out ("web-public") share 18080 during upgrade rollout.
	in := makeInputs(true, true, []string{"*.example.com"})
	gw1, _ := Translate(in)
	if _, err := translator.Build(gw1, nil); err != nil {
		t.Fatalf("translator.Build(gw1) failed: %v", err)
	}
	var newPubDomain *ir.ProtectionDomain
	var shadowDomain *ir.ProtectionDomain
	for i := range gw1.Domains {
		d := &gw1.Domains[i]
		if d.Guard == ir.GuardUnprotected && !d.Protected && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
			if d.EnvoyPort == 18080 {
				shadowDomain = d
			} else {
				newPubDomain = d
			}
		}
	}
	if newPubDomain == nil {
		t.Fatalf("expected dedicated new web-public-<hostHash> domain for app.example.com != 18080: %#v", gw1.Domains)
	}
	if shadowDomain == nil {
		t.Fatalf("expected ShadowOnly domain keeping app.example.com /health on 18080 during upgrade: %#v", gw1.Domains)
	}
	if !shadowDomain.ShadowOnly || !shadowDomain.StripAccessHeaders || shadowDomain.Protected || shadowDomain.Name != "web-public" {
		t.Fatalf("unexpected shadow domain attributes: %#v", shadowDomain)
	}
	svc1, hash1 := firstIngressService(t, gw1, "app.example.com", "/health")
	wantSvc := fmt.Sprintf("http://127.0.0.1:%d", newPubDomain.EnvoyPort)
	if svc1 != wantSvc {
		t.Fatalf("cloudflared ingress = %q, want dedicated new port %q (never shadow 18080)", svc1, wantSvc)
	}

	// Post-ACK: Status.Hostnames now points to newPubDomain.Name -> shadow disappears, cloudflared hash unchanged.
	in.CloudflareTunnel.Status.Hostnames[0].ProtectionDomain = newPubDomain.Name
	in.CloudflareTunnel.Status.Hostnames[0].AppliedVersion = 2
	gw2, _ := Translate(in)
	if _, err := translator.Build(gw2, nil); err != nil {
		t.Fatalf("translator.Build(gw2) failed: %v", err)
	}
	for _, d := range gw2.Domains {
		if d.EnvoyPort == 18080 && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
			t.Fatalf("post-ACK re-translation must drop shadow domain on 18080: %#v", d)
		}
	}
	_, hash2 := firstIngressService(t, gw2, "app.example.com", "/health")
	if hash2 != hash1 {
		t.Fatalf("cloudflared hash shifted when shadow domain was removed: before=%s after=%s", hash1, hash2)
	}

	// Edge cases: carve-out route removed, unprotected grant revoked, base GuardBlocked, revocation tombstone, and Case B (no base domain).
	t.Run("carve-out route removed drops shadow", func(t *testing.T) {
		edgeIn := makeInputs(true, false, []string{"*.example.com"})
		gwEdge, _ := Translate(edgeIn)
		if _, err := translator.Build(gwEdge, nil); err != nil {
			t.Fatalf("translator.Build failed: %v", err)
		}
		for _, d := range gwEdge.Domains {
			if d.EnvoyPort == 18080 && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
				t.Fatalf("unexpected shadow domain when /health removed: %#v", d)
			}
		}
	})
	t.Run("unprotected grant revoked drops shadow", func(t *testing.T) {
		edgeIn := makeInputs(true, true, []string{"other.example.com"})
		gwEdge, _ := Translate(edgeIn)
		if _, err := translator.Build(gwEdge, nil); err != nil {
			t.Fatalf("translator.Build failed: %v", err)
		}
		for _, d := range gwEdge.Domains {
			if d.EnvoyPort == 18080 && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
				t.Fatalf("unexpected shadow domain when unprotected grant revoked: %#v", d)
			}
		}
	})
	t.Run("wildcard unprotected revoked making base GuardBlocked filters colliding shadow", func(t *testing.T) {
		edgeIn := makeInputs(true, true, []string{"app.example.com"})
		gwEdge, _ := Translate(edgeIn)
		if _, err := translator.Build(gwEdge, nil); err != nil {
			t.Fatalf("translator.Build must not bindCollide when base becomes GuardBlocked: %v", err)
		}
		for _, d := range gwEdge.Domains {
			if d.EnvoyPort == 18080 && d.Guard == ir.GuardUnprotected {
				t.Fatalf("unexpected Unprotected shadow domain on GuardBlocked port 18080: %#v", d)
			}
		}
	})
	t.Run("revocation tombstone drops shadow", func(t *testing.T) {
		edgeIn := makeInputs(true, true, []string{"*.example.com"})
		now := metav1.Now()
		edgeIn.AccessApplications[0].DeletionTimestamp = &now
		edgeIn.AccessApplications[0].Finalizers = []string{v1alpha1.AccessApplicationFinalizer}
		edgeIn.AccessApplications[0].Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel: edgeIn.CloudflareTunnel.Name, Listener: "web", ProtectionDomain: "web-access-default-app-a", EnvoyPort: 18081,
		}}
		edgeIn.AccessApplications[0].Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type: v1alpha1.AccessApplicationDestinationPublic, Hostname: "app.example.com",
		}}
		gwEdge, _ := Translate(edgeIn)
		if _, err := translator.Build(gwEdge, nil); err != nil {
			t.Fatalf("translator.Build failed with tombstone: %v", err)
		}
		for _, d := range gwEdge.Domains {
			if d.EnvoyPort == 18080 && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
				t.Fatalf("revocation tombstone must drop shadow domain on 18080: %#v", d)
			}
		}
	})
	t.Run("Case B without base domain keeps shadow on 18080 and moves web-public to new port", func(t *testing.T) {
		edgeIn := makeInputs(false, true, []string{"*.example.com"})
		edgeIn.CloudflareTunnel.Status.Listeners[0].ProtectionDomains = []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: "web-public", EnvoyPort: 18080},
		}
		gwEdge, _ := Translate(edgeIn)
		if _, err := translator.Build(gwEdge, nil); err != nil {
			t.Fatalf("translator.Build failed in Case B: %v", err)
		}
		var sawShadow, sawNew bool
		for _, d := range gwEdge.Domains {
			if d.Guard == ir.GuardUnprotected && len(d.VirtualHosts) > 0 && d.VirtualHosts[0].Hostname == "app.example.com" {
				if d.EnvoyPort == 18080 {
					sawShadow = true
				} else {
					sawNew = true
				}
			}
		}
		if !sawShadow || !sawNew {
			t.Fatalf("Case B expected both shadow on 18080 and new web-public port, got sawShadow=%v sawNew=%v domains=%#v", sawShadow, sawNew, gwEdge.Domains)
		}
	})
}

func TestCanReconstructPublicPortsUsesRawNameBeforeDisambiguation(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: "web", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "web-public-5134f5ea", Hostname: new(gatewayv1.Hostname("sibling.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
	}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "route-tpvb", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: new(gatewayv1.SectionName("web"))}}},
			Hostnames:       []gatewayv1.Hostname{"tpvb.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("admin", "/admin", "backend"),
				namedRouteRule("health", "/health", "backend"),
			},
		},
	}}
	in.AccessApplications = []v1alpha1.AccessApplication{accessApplication("app-a", "HTTPRoute", "route-tpvb", "admin")}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "app-a"}: {AUD: "aud-a", ApplicationID: "id-a", Ready: true}}
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name:     "web",
		Exposure: v1alpha1.ExposurePublic,
		ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
			{Name: "web-public", EnvoyPort: 18080},
		},
	}}

	gw, _ := Translate(in)

	var carveOutIdx = -1
	for i, d := range gw.Domains {
		if d.ListenerName == "web" && !d.Protected && d.Name != "web" && !d.ShadowOnly {
			carveOutIdx = i
			break
		}
	}
	if carveOutIdx < 0 {
		t.Fatalf("expected unprotected disambiguated carve-out domain, got: %#v", gw.Domains)
	}
	carveOut := gw.Domains[carveOutIdx]
	wantRenamed := "web-public-5134f5ea-" + disambiguateListenerHash("web")
	if carveOut.Name != wantRenamed {
		t.Fatalf("carveOut.Name = %q, want %q", carveOut.Name, wantRenamed)
	}
	if carveOut.EnvoyPort != 21349 {
		t.Fatalf("carveOut.EnvoyPort = %d, want 21349 (21348 blocked by takeBase)", carveOut.EnvoyPort)
	}

	// Build projected listeners omitting the disambiguated carve-out row.
	var projected []v1alpha1.CloudflareTunnelListenerStatus
	for _, l := range gw.Listeners {
		var pds []v1alpha1.CloudflareProtectionDomainStatus
		for _, d := range gw.Domains {
			if d.ListenerName != l.Name || d.Name == carveOut.Name {
				continue
			}
			pds = append(pds, v1alpha1.CloudflareProtectionDomainStatus{Name: d.Name, EnvoyPort: d.EnvoyPort, Protected: d.Protected})
		}
		projected = append(projected, v1alpha1.CloudflareTunnelListenerStatus{
			Name:              gatewayv1.SectionName(l.Name),
			Exposure:          v1alpha1.Exposure(l.Exposure),
			ProtectionDomains: pds,
		})
	}

	if !CanReconstructPublicPorts(gw, projected) {
		t.Fatalf("expected CanReconstructPublicPorts to accept raw-allocated port %d when %q is omitted", carveOut.EnvoyPort, carveOut.Name)
	}

	// Simulate an unapplied checkpoint holding the hash of the renamed string instead of raw 21349:
	// omitting it would shift to raw-allocated 21349 on Pass 2, so replay MUST reject it.
	renamedHashPort := PublicDomainHashPort("web", carveOut.Name)
	if renamedHashPort == carveOut.EnvoyPort {
		t.Fatalf("unexpected hash collision between renamed port %d and raw port %d", renamedHashPort, carveOut.EnvoyPort)
	}
	inMismatch := in
	inMismatch.CloudflareTunnel = in.CloudflareTunnel.DeepCopy()
	inMismatch.CloudflareTunnel.Status.Listeners[0].ProtectionDomains = append(
		inMismatch.CloudflareTunnel.Status.Listeners[0].ProtectionDomains,
		v1alpha1.CloudflareProtectionDomainStatus{Name: carveOut.Name, EnvoyPort: renamedHashPort},
	)
	gwMismatch, _ := Translate(inMismatch)
	if CanReconstructPublicPorts(gwMismatch, projected) {
		t.Fatalf("expected CanReconstructPublicPorts to reject renamed-hash port %d (omitting %q would shift to %d)", renamedHashPort, carveOut.Name, carveOut.EnvoyPort)
	}

	// PublicPortSpec is json:"-" and must leave serialized IR and xDS snapshot identical.
	withSpecJSON, err := json.Marshal(gw)
	if err != nil {
		t.Fatal(err)
	}
	snapWithSpec, err := translator.Build(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	gwNoSpec := *gw
	gwNoSpec.PublicPortSpec = nil
	withoutSpecJSON, err := json.Marshal(&gwNoSpec)
	if err != nil {
		t.Fatal(err)
	}
	snapWithoutSpec, err := translator.Build(&gwNoSpec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(withSpecJSON) != string(withoutSpecJSON) {
		t.Fatalf("PublicPortSpec altered serialized IR JSON")
	}
	if fmt.Sprintf("%v", snapWithSpec) != fmt.Sprintf("%v", snapWithoutSpec) {
		t.Fatalf("PublicPortSpec altered translator.Build snapshot")
	}
}
