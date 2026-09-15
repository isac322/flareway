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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

func TestTranslateAccessListenerTargetAndMissingAUD(t *testing.T) {
	in := accessInputs(false)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("dashboard", "backend", 8080)}
	app := accessApplication("admin", "Gateway", "gateway", "http")
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "admin"}: {AUD: "aud-admin", ApplicationID: "app-admin", Ready: true}}

	gateway, statuses := Translate(in)
	compiled := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "admin"}]
	if !compiled.Accepted || len(compiled.Destinations) != 1 || compiled.Destinations[0].URI != "api.example.com" {
		t.Fatalf("listener target compilation = %#v", compiled)
	}
	protected := findAccessDomain(gateway.Domains, "default/admin")
	if protected == nil || protected.Guard != ir.GuardForwarding || protected.Access == nil {
		t.Fatalf("protected domain = %#v", protected)
	}
	if len(protected.Access.AUDs) != 1 || protected.Access.AUDs[0] != "aud-admin" ||
		protected.Access.TeamName != "team" || protected.Access.AuthDomain != "team.cloudflareaccess.com" {
		t.Fatalf("origin JWT guard = %#v", protected.Access)
	}
	if len(protected.IngressPaths) != 1 || protected.IngressPaths[0].Value != "/" {
		t.Fatalf("listener target ingress paths = %#v", protected.IngressPaths)
	}

	in.AUDSecrets = nil
	gateway, _ = Translate(in)
	protected = findAccessDomain(gateway.Domains, "default/admin")
	if protected == nil || protected.Guard != ir.GuardBlocked || protected.Access != nil {
		t.Fatalf("missing AUD did not fail closed: %#v", protected)
	}
}

func TestTranslateMixedHostnameNestedPublicCarveOut(t *testing.T) {
	in := accessInputs(true)
	dashboard := namedRouteRule("dashboard", "/", "dashboard")
	api := namedRouteRule("api-v1", "/v1", "api")
	api.Filters = []gatewayv1.HTTPRouteFilter{{
		Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{
			Name: "Cf-Access-Authenticated-User-Email", Value: "attacker@example.com",
		}}},
	}}
	codex := namedRouteRule("api-codex", "/backend-api/codex", "api")
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "codex", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules:           []gatewayv1.HTTPRouteRule{dashboard, api, codex},
		},
	}}
	app := accessApplication("dashboard", "HTTPRoute", "codex", "dashboard")
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "dashboard"}: {AUD: "aud-dashboard", ApplicationID: "app-dashboard", Ready: true}}

	gateway, statuses := Translate(in)
	compiled := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "dashboard"}]
	if !compiled.Accepted {
		t.Fatalf("mixed hostname application rejected: %#v", compiled)
	}
	if len(compiled.Bypass) != 2 || compiled.Bypass[0].Path != "/backend-api/codex" || compiled.Bypass[1].Path != "/v1" {
		t.Fatalf("bypass children = %#v", compiled.Bypass)
	}
	protected := findAccessDomain(gateway.Domains, "default/dashboard")
	public := findDomain(gateway.Domains, false, ir.GuardUnprotected)
	if protected == nil || public == nil {
		t.Fatalf("mixed protection domains = %#v", gateway.Domains)
	}
	if protected.EnvoyPort == public.EnvoyPort {
		t.Fatalf("protected and public paths share Envoy listener port %d", protected.EnvoyPort)
	}
	if len(protected.VirtualHosts[0].Routes) != 1 || protected.VirtualHosts[0].Routes[0].Source.RuleName != "dashboard" {
		t.Fatalf("protected listener routes crossed over: %#v", protected.VirtualHosts)
	}
	if len(public.VirtualHosts[0].Routes) != 2 || !public.StripAccessHeaders {
		t.Fatalf("public carve-out routes/security = %#v", public)
	}
	var publicHeaders *ir.HeaderModifier
	for _, route := range public.VirtualHosts[0].Routes {
		if route.Source.RuleName == "api-v1" {
			publicHeaders = route.Filters.RequestHeaders
		}
	}
	if publicHeaders == nil || len(publicHeaders.Set) != 0 || !containsStringFold(publicHeaders.Remove, "cf-access-authenticated-user-email") {
		t.Fatalf("public route can spoof Access identity headers: %#v", publicHeaders)
	}
}
func TestTranslateRejectsLaterOverlappingAccessApplication(t *testing.T) {
	in := accessInputs(false)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("dashboard", "backend", 8080)}
	first := accessApplication("first", "HTTPRoute", "dashboard", "")
	first.Spec.TargetRefs[0].SectionName = nil
	first.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
	second := accessApplication("second", "HTTPRoute", "dashboard", "")
	second.Spec.TargetRefs[0].SectionName = nil
	second.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	in.AccessApplications = []v1alpha1.AccessApplication{second, first}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		{Namespace: "default", Name: "first"}:  {AUD: "aud-first", ApplicationID: "app-first", Ready: true},
		{Namespace: "default", Name: "second"}: {AUD: "aud-second", ApplicationID: "app-second", Ready: true},
	}

	gateway, statuses := Translate(in)
	if !statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "first"}].Accepted {
		t.Fatal("oldest AccessApplication did not win")
	}
	rejected := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "second"}]
	if rejected.Accepted || rejected.Reason != "Conflicted" || len(rejected.Destinations) == 0 {
		t.Fatalf("later overlapping AccessApplication = %#v", rejected)
	}
	if domain := findAccessDomain(gateway.Domains, "default/second"); domain != nil {
		t.Fatalf("rejected AccessApplication produced a protection domain: %#v", domain)
	}
}

func TestTranslatePrivateListenerPreparesJWTProtectionDomain(t *testing.T) {
	in := accessInputs(false)
	in.Gateway.Spec.Listeners[0] = gatewayv1.Listener{
		Name: "https", Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
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
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("private", "backend", 8080)}
	app := accessApplication("private", "Gateway", "gateway", "https")
	app.Spec.OriginJWT.AssumeGatewayTLSDecryption = true
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "private"}: {AUD: "aud-private", ApplicationID: "app-private", Ready: true}}

	gateway, statuses := Translate(in)
	compiled := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "private"}]
	if !compiled.Accepted || len(compiled.Destinations) != 1 {
		t.Fatalf("private application compilation = %#v", compiled)
	}
	destination := compiled.Destinations[0]
	if destination.Type != v1alpha1.AccessApplicationDestinationPrivate || destination.Hostname != "api.example.com" || destination.PortRange != "443" || destination.L4Protocol == nil || *destination.L4Protocol != v1alpha1.AccessL4ProtocolTCP || destination.VNetID != "vnet-private" {
		t.Fatalf("private destination = %#v", destination)
	}
	protected := findAccessDomain(gateway.Domains, "default/private")
	if protected == nil || protected.EnvoyPort != 443 || protected.Access == nil || protected.Guard != ir.GuardForwarding {
		t.Fatalf("private JWT protection domain = %#v", protected)
	}
}

func TestOriginJWTDisabledStillRequiresReadyApplication(t *testing.T) {
	in := accessInputs(false)
	in.Namespaces[0].Labels = map[string]string{allowOriginJWTDisableLabel: "true"}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("dashboard", "backend", 8080)}
	app := accessApplication("disabled", "Gateway", "gateway", "http")
	app.Spec.OriginJWT.Mode = v1alpha1.AccessOriginJWTModeDisabled
	in.AccessApplications = []v1alpha1.AccessApplication{app}

	gateway, _ := Translate(in)
	protected := findAccessDomain(gateway.Domains, "default/disabled")
	if protected == nil || protected.Guard != ir.GuardBlocked {
		t.Fatalf("originJWT Disabled forwarded without remote application readiness: %#v", protected)
	}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{
		Namespace: "default", Name: "disabled",
	}: {Ready: true}}
	gateway, _ = Translate(in)
	protected = findAccessDomain(gateway.Domains, "default/disabled")
	if protected == nil || protected.Guard != ir.GuardBlocked {
		t.Fatalf("originJWT Disabled forwarded without remote application ID: %#v", protected)
	}
	in.AUDSecrets[types.NamespacedName{Namespace: "default", Name: "disabled"}] = AUDSecret{ApplicationID: "app-disabled", Ready: true}
	gateway, _ = Translate(in)
	protected = findAccessDomain(gateway.Domains, "default/disabled")
	if protected == nil || protected.Guard != ir.GuardForwarding || !protected.OriginJWTDisabled || protected.Access != nil {
		t.Fatalf("ready originJWT Disabled application = %#v", protected)
	}
}

func TestRouteSpecificAccessApplicationOverridesGatewayWideApplication(t *testing.T) {
	in := accessInputs(false)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "routes", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("admin", "/admin", "backend"),
				namedRouteRule("other", "/other", "backend"),
			},
		},
	}}
	parent := accessApplication("parent", "Gateway", "gateway", "http")
	parent.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
	child := accessApplication("child", "HTTPRoute", "routes", "admin")
	child.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	in.AccessApplications = []v1alpha1.AccessApplication{parent, child}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		{Namespace: "default", Name: "parent"}: {AUD: "aud-parent", ApplicationID: "app-parent", Ready: true},
		{Namespace: "default", Name: "child"}:  {AUD: "aud-child", ApplicationID: "app-child", Ready: true},
	}

	gateway, statuses := Translate(in)
	if !statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "parent"}].Accepted ||
		!statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "child"}].Accepted {
		t.Fatalf("hierarchical Access applications conflicted: %#v", statuses.AccessApplications)
	}
	parentDomain := findAccessDomain(gateway.Domains, "default/parent")
	childDomain := findAccessDomain(gateway.Domains, "default/child")
	if parentDomain == nil || childDomain == nil {
		t.Fatalf("hierarchical protection domains = %#v", gateway.Domains)
	}
	if len(parentDomain.VirtualHosts[0].Routes) != 1 || parentDomain.VirtualHosts[0].Routes[0].Source.RuleName != "other" ||
		len(childDomain.VirtualHosts[0].Routes) != 1 || childDomain.VirtualHosts[0].Routes[0].Source.RuleName != "admin" {
		t.Fatalf("route-specific precedence failed: parent=%#v child=%#v", parentDomain.VirtualHosts, childDomain.VirtualHosts)
	}
}

func TestPathScopeAccessApplicationShadowsParentRouteWithoutConsumingIt(t *testing.T) {
	in := accessInputs(false)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "routes", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules:           []gatewayv1.HTTPRouteRule{namedRouteRule("redash", "/", "backend")},
		},
	}}
	parent := accessApplication("parent", "Gateway", "gateway", "http")
	parent.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
	overlay := accessApplication("overlay", "HTTPRoute", "routes", "redash")
	overlay.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	overlay.Spec.PathScope = &v1alpha1.AccessTargetPath{Type: gatewayv1.PathMatchPathPrefix, Value: "/api"}
	in.AccessApplications = []v1alpha1.AccessApplication{parent, overlay}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		{Namespace: "default", Name: "parent"}:  {AUD: "aud-parent", ApplicationID: "app-parent", Ready: true},
		{Namespace: "default", Name: "overlay"}: {AUD: "aud-overlay", ApplicationID: "app-overlay", Ready: true},
	}

	gateway, statuses := Translate(in)
	if !statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "parent"}].Accepted ||
		!statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "overlay"}].Accepted {
		t.Fatalf("pathScope overlay conflicted with parent: %#v", statuses.AccessApplications)
	}
	parentDomain := findAccessDomain(gateway.Domains, "default/parent")
	overlayDomain := findAccessDomain(gateway.Domains, "default/overlay")
	if parentDomain == nil || overlayDomain == nil {
		t.Fatalf("pathScope protection domains = %#v", gateway.Domains)
	}
	if len(parentDomain.VirtualHosts[0].Routes) != 1 || parentDomain.VirtualHosts[0].Routes[0].Source.RuleName != "redash" ||
		len(overlayDomain.VirtualHosts[0].Routes) != 1 || overlayDomain.VirtualHosts[0].Routes[0].Source.RuleName != "redash" {
		t.Fatalf("pathScope did not shadow the existing backend: parent=%#v overlay=%#v", parentDomain.VirtualHosts, overlayDomain.VirtualHosts)
	}
	if len(parentDomain.IngressPaths) != 1 || parentDomain.IngressPaths[0].Value != "/" ||
		len(overlayDomain.IngressPaths) != 1 || overlayDomain.IngressPaths[0].Value != "/api" {
		t.Fatalf("pathScope ingress paths = parent %#v overlay %#v", parentDomain.IngressPaths, overlayDomain.IngressPaths)
	}
}

func TestPublicRegexCarveOutIsRejectedBeforeAccessWidening(t *testing.T) {
	in := accessInputs(true)
	regexType := gatewayv1.PathMatchRegularExpression
	regexRule := namedRouteRule("regex-public", "/unused", "backend")
	regexRule.Matches[0].Path = &gatewayv1.HTTPPathMatch{Type: &regexType, Value: new("^/v1/.*$")}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "routes", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("protected", "/", "backend"),
				regexRule,
			},
		},
	}}
	app := accessApplication("protected", "HTTPRoute", "routes", "protected")
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "protected"}: {
		AUD: "aud", ApplicationID: "app", Ready: true,
	}}

	gateway, statuses := Translate(in)
	if public := findDomain(gateway.Domains, false, ir.GuardUnprotected); public != nil {
		t.Fatalf("RegularExpression carve-out reached public listener: %#v", public)
	}
	condition := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "routes"}], gatewayv1.RouteConditionPartiallyInvalid)
	if condition == nil || !strings.Contains(condition.Message, "public carve-outs must use Exact or PathPrefix") {
		t.Fatalf("regex carve-out status = %#v", condition)
	}
}

func TestTranslateMixedHostnameWithoutGrantDropsPublicRules(t *testing.T) {
	in := accessInputs(false)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "codex", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{
				namedRouteRule("dashboard", "/", "dashboard"),
				namedRouteRule("api", "/v1", "api"),
			},
		},
	}}
	app := accessApplication("dashboard", "HTTPRoute", "codex", "dashboard")
	in.AccessApplications = []v1alpha1.AccessApplication{app}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{{Namespace: "default", Name: "dashboard"}: {AUD: "aud-dashboard", ApplicationID: "app-dashboard", Ready: true}}

	gateway, statuses := Translate(in)
	if public := findDomain(gateway.Domains, false, ir.GuardUnprotected); public != nil {
		t.Fatalf("public route forwarded without grant: %#v", public)
	}
	condition := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "codex"}], gatewayv1.RouteConditionPartiallyInvalid)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Message != "Dropped Rule: rule \"api\" public carve-out requires unprotected grant for api.example.com" {
		t.Fatalf("PartiallyInvalid condition = %#v", condition)
	}
}

func TestAccessPathProofTreatsV1AndV10AsDisjoint(t *testing.T) {
	protected := accessRegion{kind: accessRegionPrefix, path: "/v1"}
	public := accessRegion{kind: accessRegionPrefix, path: "/v10"}
	if accessRegionsOverlap(protected, public) {
		t.Fatal("/v1 and /v10 must be prefix-disjoint")
	}
	if normalized, err := normalizeAccessPath("/public//x/../v1/"); err != nil || normalized != "/public/v1" {
		t.Fatalf("normalized path = %q, %v", normalized, err)
	}
	if normalized, err := normalizeAccessPath("/public/%2e%2e/admin"); err != nil || normalized != "/admin" {
		t.Fatalf("percent-decoded traversal normalization = %q, %v", normalized, err)
	}
}

func accessInputs(unprotected bool) Inputs {
	in := baseInputs()
	in.GatewayClassConfig.Spec.ConformanceMode = false
	in.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}}
	in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
	in.CloudflareTunnel = &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"}}
	grant := v1alpha1.CloudflareAccountGrant{
		NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"api.example.com"}, Zones: []string{"example.com"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		Backends: &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
	}
	if unprotected {
		grant.UnprotectedHostnames = []string{"api.example.com"}
	}
	in.CloudflareAccount = &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec:       v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Grants: []v1alpha1.CloudflareAccountGrant{grant}},
		Status:     v1alpha1.CloudflareAccountStatus{Verified: v1alpha1.CloudflareAccountVerifiedStatus{TeamName: "team", AuthDomain: "team.cloudflareaccess.com"}},
	}
	return in
}

func accessApplication(name, kind, targetName, section string) v1alpha1.AccessApplication {
	return v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(name + "-uid"), CreationTimestamp: metav1.NewTime(time.Unix(10, 0))},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: gatewayv1.Kind(kind), Name: gatewayv1.ObjectName(targetName)},
				SectionName:                new(gatewayv1.SectionName(section)),
			}},
			OriginJWT: v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
		},
	}
}

func namedRouteRule(name, path, _ string) gatewayv1.HTTPRouteRule {
	pathType := gatewayv1.PathMatchPathPrefix
	return gatewayv1.HTTPRouteRule{
		Name:    new(gatewayv1.SectionName(name)),
		Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
		BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
			Name: gatewayv1.ObjectName("backend"), Port: new(gatewayv1.PortNumber(8080)),
		}}}},
	}
}

func findAccessDomain(domains []ir.ProtectionDomain, application string) *ir.ProtectionDomain {
	for index := range domains {
		if domains[index].AccessApplication == application {
			return &domains[index]
		}
	}
	return nil
}

func findDomain(domains []ir.ProtectionDomain, protected bool, guard string) *ir.ProtectionDomain {
	for index := range domains {
		if domains[index].Protected == protected && domains[index].Guard == guard {
			return &domains[index]
		}
	}
	return nil
}

func containsStringFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}
