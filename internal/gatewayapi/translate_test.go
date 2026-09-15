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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

func TestSupportedFeaturesSortedAndCopySafe(t *testing.T) {
	first := SupportedFeatures()
	if len(first) == 0 {
		t.Fatal("SupportedFeatures returned no features")
	}
	for i := 1; i < len(first); i++ {
		if first[i-1] > first[i] {
			t.Fatalf("features are not sorted: %q before %q", first[i-1], first[i])
		}
	}
	original := first[0]
	first[0] = "mutated"
	if SupportedFeatures()[0] != original {
		t.Fatal("SupportedFeatures returned mutable package state")
	}
}

var updateGoldens = flag.Bool("update", false, "update translator golden files")

func TestComputeHosts(t *testing.T) {
	tests := []struct {
		name     string
		route    []gatewayv1.Hostname
		listener *gatewayv1.Hostname
		want     []gatewayv1.Hostname
	}{
		{name: "both empty", want: []gatewayv1.Hostname{"*"}},
		{name: "listener only", listener: new(gatewayv1.Hostname("api.example.com")), want: []gatewayv1.Hostname{"api.example.com"}},
		{name: "route only", route: []gatewayv1.Hostname{"api.example.com"}, want: []gatewayv1.Hostname{"api.example.com"}},
		{name: "exact", route: []gatewayv1.Hostname{"api.example.com"}, listener: new(gatewayv1.Hostname("api.example.com")), want: []gatewayv1.Hostname{"api.example.com"}},
		{name: "listener wildcard", route: []gatewayv1.Hostname{"deep.api.example.com"}, listener: new(gatewayv1.Hostname("*.example.com")), want: []gatewayv1.Hostname{"deep.api.example.com"}},
		{name: "no intersection", route: []gatewayv1.Hostname{"api.example.net"}, listener: new(gatewayv1.Hostname("*.example.com")), want: []gatewayv1.Hostname{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ComputeHosts(test.route, test.listener, nil); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ComputeHosts() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestTranslateRoutePrecedence(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
	paths := []struct {
		name      string
		pathType  gatewayv1.PathMatchType
		path      string
		method    *gatewayv1.HTTPMethod
		headers   []gatewayv1.HTTPHeaderMatch
		query     []gatewayv1.HTTPQueryParamMatch
		createdAt time.Time
	}{
		{name: "prefix-v1", pathType: gatewayv1.PathMatchPathPrefix, path: "/v1", createdAt: time.Unix(10, 0)},
		{name: "prefix-v10", pathType: gatewayv1.PathMatchPathPrefix, path: "/v10", createdAt: time.Unix(10, 0)},
		{name: "exact", pathType: gatewayv1.PathMatchExact, path: "/v1", createdAt: time.Unix(10, 0)},
		{name: "regex", pathType: gatewayv1.PathMatchRegularExpression, path: "^/v[0-9]+$", createdAt: time.Unix(10, 0)},
		{name: "method", pathType: gatewayv1.PathMatchPathPrefix, path: "/", method: new(gatewayv1.HTTPMethodGet), createdAt: time.Unix(10, 0)},
		{name: "header", pathType: gatewayv1.PathMatchPathPrefix, path: "/", headers: []gatewayv1.HTTPHeaderMatch{{Name: "x-version", Value: "v1"}}, createdAt: time.Unix(10, 0)},
		{name: "query", pathType: gatewayv1.PathMatchPathPrefix, path: "/", query: []gatewayv1.HTTPQueryParamMatch{{Name: "version", Value: "v1"}}, createdAt: time.Unix(10, 0)},
		{name: "oldest", pathType: gatewayv1.PathMatchPathPrefix, path: "/", createdAt: time.Unix(1, 0)},
	}
	for _, item := range paths {
		in.HTTPRoutes = append(in.HTTPRoutes, routeWithMatch(item.name, item.pathType, item.path, item.method, item.headers, item.query, item.createdAt))
	}
	gateway, _ := Translate(in)
	got := gateway.Domains[0].VirtualHosts[0].Routes
	wantNames := []string{
		"default/exact/0/0",
		"default/regex/0/0",
		"default/prefix-v10/0/0",
		"default/prefix-v1/0/0",
		"default/method/0/0",
		"default/header/0/0",
		"default/query/0/0",
		"default/oldest/0/0",
	}
	if len(got) != len(wantNames) {
		t.Fatalf("got %d routes, want %d", len(got), len(wantNames))
	}
	for i, want := range wantNames {
		if got[i].Name != want {
			t.Fatalf("route %d = %q, want %q", i, got[i].Name, want)
		}
	}
}

func TestTranslateReferenceGrantAndInvalidBackendWeights(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{
		service("backend", "allowed", 8080, nil),
		service("default", "valid", 8080, nil),
	}
	backendNamespace := gatewayv1.Namespace("backend")
	in.HTTPRoutes = []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "weighted", Namespace: "default", Generation: 1},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
				Rules: []gatewayv1.HTTPRouteRule{
					{BackendRefs: []gatewayv1.HTTPBackendRef{
						{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "valid", Port: new(gatewayv1.PortNumber(8080))}, Weight: new(int32(80))}},
						{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "missing", Port: new(gatewayv1.PortNumber(8080))}, Weight: new(int32(20))}},
						{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "allowed", Namespace: &backendNamespace, Port: new(gatewayv1.PortNumber(8080))}, Weight: new(int32(10))}},
					}},
				},
			},
		},
	}

	gateway, statuses := Translate(in)
	backends := gateway.Domains[0].VirtualHosts[0].Routes[0].Backends
	if backends[0].Weight != 80 || backends[1].Weight != 20 || backends[1].Invalid == nil {
		t.Fatalf("invalid backend weights were not preserved: %#v", backends)
	}
	if backends[2].Invalid == nil || backends[2].Invalid.Code != string(gatewayv1.RouteReasonRefNotPermitted) {
		t.Fatalf("cross-namespace backend without grant = %#v", backends[2])
	}
	condition := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "weighted"}], gatewayv1.RouteConditionResolvedRefs)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != string(gatewayv1.RouteReasonBackendNotFound) {
		t.Fatalf("ResolvedRefs condition = %#v", condition)
	}

	in.ReferenceGrants = []gatewayv1.ReferenceGrant{{
		ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: "backend"},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{Group: gatewayv1.Group(gatewayGroup), Kind: "HTTPRoute", Namespace: "default"}},
			To:   []gatewayv1.ReferenceGrantTo{{Group: "", Kind: "Service", Name: new(gatewayv1.ObjectName("allowed"))}},
		},
	}}
	gateway, _ = Translate(in)
	backends = gateway.Domains[0].VirtualHosts[0].Routes[0].Backends
	if backends[2].Invalid != nil {
		t.Fatalf("granted backend remained invalid: %#v", backends[2])
	}
}

func TestTranslateExactAndWildcardRoutesShareListenerWithoutCrossRouting(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{
		service("default", "v1", 8080, nil),
		service("default", "v3", 8080, nil),
	}
	specific := routeWithBackend("specific", "v1", 8080)
	specific.Spec.Hostnames = []gatewayv1.Hostname{"api.example.com"}
	specific.Spec.Rules[0].Matches[0].Path.Value = new("/s1")
	wildcard := routeWithBackend("wildcard", "v3", 8080)
	wildcard.Spec.Hostnames = []gatewayv1.Hostname{"*.example.com"}
	wildcard.Spec.Rules[0].Matches[0].Path.Value = new("/s3")
	in.HTTPRoutes = []gatewayv1.HTTPRoute{wildcard, specific}
	gateway, _ := Translate(in)
	routes := gateway.Domains[0].VirtualHosts[0].Routes
	if len(routes) != 2 || routes[0].Match.Value != "/s1" || routes[0].Backends[0].Name != "v1" || routes[1].Match.Value != "/s3" || routes[1].Backends[0].Name != "v3" {
		t.Fatalf("hostname intersection routes = %#v", routes)
	}
}

func TestTranslateAllowedRoutesSelectorAndParentPort(t *testing.T) {
	in := baseInputs()
	in.Gateway.Spec.Listeners[0].AllowedRoutes = &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{
		From:     new(gatewayv1.NamespacesFromSelector),
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"attach": "yes"}},
	}}
	in.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"attach": "yes"}}}}
	in.Services = []corev1.Service{service("app", "backend", 8080, nil)}
	port := gatewayv1.PortNumber(80)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "app", Generation: 1},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", Namespace: new(gatewayv1.Namespace("default")), SectionName: new(gatewayv1.SectionName("http")), Port: &port}}},
			Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: new(gatewayv1.PortNumber(8080))}}}}}},
		},
	}}
	gateway, statuses := Translate(in)
	if len(gateway.Domains[0].VirtualHosts) != 1 {
		t.Fatalf("selected Route was not attached: %#v", gateway.Domains[0])
	}
	condition := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "app", Name: "selected"}], gatewayv1.RouteConditionAccepted)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted condition = %#v", condition)
	}
	port = 443
	gateway, statuses = Translate(in)
	if len(gateway.Domains[0].VirtualHosts) != 0 {
		t.Fatalf("sectionName/port mismatch attached Route: %#v", gateway.Domains[0].VirtualHosts)
	}
	condition = findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "app", Name: "selected"}], gatewayv1.RouteConditionAccepted)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
		t.Fatalf("sectionName/port mismatch Accepted = %#v", condition)
	}
}

func TestTranslatePreservesOtherControllerRouteStatus(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
	route := routeWithMatch("route", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))
	route.Status.Parents = []gatewayv1.RouteParentStatus{
		{
			ParentRef:      gatewayv1.ParentReference{Name: "other"},
			ControllerName: "other.example/controller",
			Conditions:     []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted"}},
		},
		{
			ParentRef:      gatewayv1.ParentReference{Name: "gateway"},
			ControllerName: ControllerName,
			Conditions:     []metav1.Condition{{Type: string(gatewayv1.RouteConditionPartiallyInvalid), Status: metav1.ConditionTrue, Reason: string(gatewayv1.RouteReasonUnsupportedValue)}},
		},
	}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{route}
	_, statuses := Translate(in)
	parents := statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route"}].Parents
	if len(parents) != 2 || parents[0].ControllerName != "other.example/controller" || parents[1].ControllerName != ControllerName {
		t.Fatalf("parent statuses were not replaced deterministically: %#v", parents)
	}
	if stale := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route"}], gatewayv1.RouteConditionPartiallyInvalid); stale != nil {
		t.Fatalf("stale PartiallyInvalid condition was retained: %#v", stale)
	}
}
func TestTranslateListenerTLSModes(t *testing.T) {
	in := baseInputs()
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
		Name: "https", Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "cert"}}},
	}}
	in.Secrets = []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       validTLSSecretData(t),
	}}
	gateway, statuses := Translate(in)
	if len(gateway.Listeners) != 1 || gateway.Listeners[0].TLS == nil || len(gateway.Secrets) != 1 {
		t.Fatalf("conformance HTTPS listener = %#v, secrets = %#v", gateway.Listeners, gateway.Secrets)
	}
	if condition := findListenerCondition(statuses.Gateway, "https", gatewayv1.ListenerConditionResolvedRefs); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("HTTPS ResolvedRefs condition = %#v", condition)
	}

	in.Secrets[0].Data = map[string][]byte{corev1.TLSCertKey: []byte("malformed"), corev1.TLSPrivateKeyKey: []byte("malformed")}
	_, statuses = Translate(in)
	if condition := findListenerCondition(statuses.Gateway, "https", gatewayv1.ListenerConditionResolvedRefs); condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
		t.Fatalf("malformed certificate ResolvedRefs condition = %#v", condition)
	}

	in.Secrets = nil
	gateway, statuses = Translate(in)
	if len(gateway.Listeners) != 0 {
		t.Fatalf("missing certificate produced listener: %#v", gateway.Listeners)
	}
	if condition := findListenerCondition(statuses.Gateway, "https", gatewayv1.ListenerConditionResolvedRefs); condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
		t.Fatalf("missing certificate ResolvedRefs condition = %#v", condition)
	}

	in.GatewayClassConfig.Spec.ConformanceMode = false
	in.Gateway.Spec.Listeners[0].TLS = &gatewayv1.ListenerTLSConfig{Options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{"flareway.bhyoo.com/edge-tls-mode": "Strict"}}
	gateway, _ = Translate(in)
	if len(gateway.Listeners) != 1 || gateway.Listeners[0].EnvoyPort != 18080 || gateway.Listeners[0].TLS != nil {
		t.Fatalf("edge-terminated HTTPS listener = %#v", gateway.Listeners)
	}
}

func TestTranslateListenerSecretReferenceGrant(t *testing.T) {
	certNamespace := gatewayv1.Namespace("certs")
	for _, test := range []struct {
		name string
		to   gatewayv1.ReferenceGrantTo
	}{
		{name: "specific", to: gatewayv1.ReferenceGrantTo{Group: "", Kind: "Secret", Name: new(gatewayv1.ObjectName("cert"))}},
		{name: "all in namespace", to: gatewayv1.ReferenceGrantTo{Group: "", Kind: "Secret"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := baseInputs()
			in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
				Name: "https", Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "cert", Namespace: &certNamespace}}},
			}}
			in.Secrets = []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "certs"}, Type: corev1.SecretTypeTLS, Data: validTLSSecretData(t)}}
			in.ReferenceGrants = []gatewayv1.ReferenceGrant{{
				ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: "certs"},
				Spec: gatewayv1.ReferenceGrantSpec{
					From: []gatewayv1.ReferenceGrantFrom{{Group: gatewayv1.Group(gatewayGroup), Kind: "Gateway", Namespace: "default"}},
					To:   []gatewayv1.ReferenceGrantTo{test.to},
				},
			}}
			gateway, statuses := Translate(in)
			condition := findListenerCondition(statuses.Gateway, "https", gatewayv1.ListenerConditionResolvedRefs)
			if len(gateway.Listeners) != 1 || condition == nil || condition.Status != metav1.ConditionTrue {
				t.Fatalf("granted listener = %#v, ResolvedRefs = %#v", gateway.Listeners, condition)
			}
		})
	}
}

func TestTranslateDroppedRules(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
	valid := routeWithMatch("partial", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))
	valid.Spec.Rules = append(valid.Spec.Rules, gatewayv1.HTTPRouteRule{
		Retry:       &gatewayv1.HTTPRouteRetry{},
		BackendRefs: valid.Spec.Rules[0].BackendRefs,
	})
	in.HTTPRoutes = []gatewayv1.HTTPRoute{valid}
	gateway, statuses := Translate(in)
	if got := len(gateway.Domains[0].VirtualHosts[0].Routes); got != 1 {
		t.Fatalf("valid rule count = %d, want 1", got)
	}
	routeStatus := statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "partial"}]
	accepted := findRouteCondition(routeStatus, gatewayv1.RouteConditionAccepted)
	partial := findRouteCondition(routeStatus, gatewayv1.RouteConditionPartiallyInvalid)
	if accepted == nil || accepted.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted condition = %#v", accepted)
	}
	if partial == nil || partial.Status != metav1.ConditionTrue || len(partial.Message) < len("Dropped Rule") || partial.Message[:len("Dropped Rule")] != "Dropped Rule" {
		t.Fatalf("PartiallyInvalid condition = %#v", partial)
	}

	invalid := routeWithMatch("invalid", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))
	invalid.Spec.Rules[0].Retry = &gatewayv1.HTTPRouteRetry{}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{invalid}
	gateway, statuses = Translate(in)
	if len(gateway.Domains[0].VirtualHosts) != 0 {
		t.Fatalf("fully invalid Route produced configuration: %#v", gateway.Domains[0].VirtualHosts)
	}
	routeStatus = statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "invalid"}]
	accepted = findRouteCondition(routeStatus, gatewayv1.RouteConditionAccepted)
	partial = findRouteCondition(routeStatus, gatewayv1.RouteConditionPartiallyInvalid)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || partial != nil {
		t.Fatalf("fully invalid conditions: Accepted=%#v PartiallyInvalid=%#v", accepted, partial)
	}
}

func TestTranslateInvalidBackendTLSPolicyFailsClosed(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithMatch("tls", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))}
	in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: "", Kind: "Service", Name: "backend"}}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:          "backend.default.svc.cluster.local",
				CACertificateRefs: []gatewayv1.LocalObjectReference{{Group: "", Kind: "ConfigMap", Name: "missing"}},
			},
		},
	}}
	gateway, statuses := Translate(in)
	backend := gateway.Domains[0].VirtualHosts[0].Routes[0].Backends[0]
	if backend.Invalid == nil || backend.Invalid.Code != string(gatewayv1.RouteReasonUnsupportedProtocol) {
		t.Fatalf("invalid BackendTLSPolicy did not fail closed: %#v", backend)
	}
	if len(gateway.Clusters) != 0 {
		t.Fatalf("invalid TLS backend produced a plaintext cluster: %#v", gateway.Clusters)
	}
	policyStatus := statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: "tls"}]
	accepted := findPolicyCondition(policyStatus, gatewayv1.PolicyConditionAccepted)
	resolved := findPolicyCondition(policyStatus, gatewayv1.BackendTLSPolicyConditionResolvedRefs)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || resolved == nil || resolved.Status != metav1.ConditionFalse {
		t.Fatalf("BackendTLSPolicy conditions: Accepted=%#v ResolvedRefs=%#v", accepted, resolved)
	}
}
func TestBackendTLSPolicyStatusConformance(t *testing.T) {
	t.Run("invalid CA kind and malformed certificate", func(t *testing.T) {
		for _, test := range []struct {
			name           string
			caRef          gatewayv1.LocalObjectReference
			configMaps     []corev1.ConfigMap
			resolvedReason gatewayv1.PolicyConditionReason
		}{
			{
				name:           "invalid kind",
				caRef:          gatewayv1.LocalObjectReference{Group: "invalid.io", Kind: "InvalidKind", Name: "invalid"},
				resolvedReason: gatewayv1.BackendTLSPolicyReasonInvalidKind,
			},
			{
				name:           "malformed certificate",
				caRef:          gatewayv1.LocalObjectReference{Group: "", Kind: "ConfigMap", Name: "malformed"},
				configMaps:     []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "malformed", Namespace: "default"}, Data: map[string]string{"ca.crt": "malformed"}}},
				resolvedReason: gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				https := "HTTPS"
				in := baseInputs()
				in.Services = []corev1.Service{service("default", "backend", 443, &https)}
				in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("route", "backend", 443)}
				policy := policyForService("policy", "backend", nil, time.Unix(1, 0))
				policy.Spec.Validation.WellKnownCACertificates = nil
				policy.Spec.Validation.CACertificateRefs = []gatewayv1.LocalObjectReference{test.caRef}
				in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{policy}
				in.ConfigMaps = test.configMaps
				gateway, statuses := Translate(in)
				if len(gateway.Clusters) != 0 || gateway.Domains[0].VirtualHosts[0].Routes[0].Backends[0].Invalid == nil {
					t.Fatalf("invalid policy did not fail closed: clusters=%#v backend=%#v", gateway.Clusters, gateway.Domains[0].VirtualHosts[0].Routes[0].Backends[0])
				}
				policyStatus := statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: "policy"}]
				accepted := findPolicyCondition(policyStatus, gatewayv1.PolicyConditionAccepted)
				resolved := findPolicyCondition(policyStatus, gatewayv1.BackendTLSPolicyConditionResolvedRefs)
				if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate) {
					t.Fatalf("Accepted = %#v", accepted)
				}
				if resolved == nil || resolved.Status != metav1.ConditionFalse || resolved.Reason != string(test.resolvedReason) {
					t.Fatalf("ResolvedRefs = %#v", resolved)
				}
			})
		}
	})

	t.Run("conflicts and observed generation", func(t *testing.T) {
		https := "HTTPS"
		in := baseInputs()
		in.Services = []corev1.Service{service("default", "backend", 443, &https)}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithBackend("route", "backend", 443)}
		first := policyForService("first", "backend", nil, time.Unix(1, 0))
		second := policyForService("second", "backend", nil, time.Unix(2, 0))
		in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{second, first}
		gateway, statuses := Translate(in)
		if len(gateway.Clusters) != 1 || gateway.Clusters[0].TLS == nil || gateway.Clusters[0].TLS.ServerName != "first.example.com" {
			t.Fatalf("winning policy was not used: %#v", gateway.Clusters)
		}
		firstStatus := statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: "first"}]
		secondStatus := statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: "second"}]
		if condition := findPolicyCondition(firstStatus, gatewayv1.PolicyConditionAccepted); condition == nil || condition.Status != metav1.ConditionTrue {
			t.Fatalf("first Accepted = %#v", condition)
		}
		if condition := findPolicyCondition(secondStatus, gatewayv1.PolicyConditionAccepted); condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != string(gatewayv1.PolicyReasonConflicted) {
			t.Fatalf("second Accepted = %#v", condition)
		}

		first.Generation = 2
		first.Status = firstStatus
		in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{first, second}
		_, statuses = Translate(in)
		updated := findPolicyCondition(statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: "first"}], gatewayv1.PolicyConditionAccepted)
		if updated == nil || updated.ObservedGeneration != 2 {
			t.Fatalf("observedGeneration = %#v, want 2", updated)
		}
	})

	t.Run("section policy and whole-Service policy do not conflict", func(t *testing.T) {
		https := "HTTPS"
		in := baseInputs()
		in.Services = []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
				{Name: "https-1", Port: 443, AppProtocol: &https},
				{Name: "https-2", Port: 8443, AppProtocol: &https},
			}},
		}}
		route := routeWithBackend("route", "backend", 443)
		route.Spec.Rules = append(route.Spec.Rules, routeWithBackend("other", "backend", 8443).Spec.Rules[0])
		in.HTTPRoutes = []gatewayv1.HTTPRoute{route}
		section := gatewayv1.SectionName("https-1")
		sectionPolicy := policyForService("section", "backend", &section, time.Unix(1, 0))
		wholePolicy := policyForService("whole", "backend", nil, time.Unix(2, 0))
		in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{sectionPolicy, wholePolicy}
		_, statuses := Translate(in)
		for _, name := range []string{"section", "whole"} {
			condition := findPolicyCondition(statuses.BackendTLSPolicies[types.NamespacedName{Namespace: "default", Name: name}], gatewayv1.PolicyConditionAccepted)
			if condition == nil || condition.Status != metav1.ConditionTrue {
				t.Fatalf("%s Accepted = %#v", name, condition)
			}
		}
	})
}

func TestTranslateGatewayServiceAddress(t *testing.T) {
	in := baseInputs()
	in.Services = []corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway-gw-gateway", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.96.0.10"},
	}}
	_, statuses := Translate(in)
	if len(statuses.Gateway.Addresses) != 1 || statuses.Gateway.Addresses[0].Value != "10.96.0.10" || statuses.Gateway.Addresses[0].Type == nil || *statuses.Gateway.Addresses[0].Type != gatewayv1.IPAddressType {
		t.Fatalf("Gateway addresses = %#v", statuses.Gateway.Addresses)
	}
}
func TestTranslateInfrastructurePropagation(t *testing.T) {
	in := baseInputs()
	in.Gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		Labels:      map[gatewayv1.LabelKey]gatewayv1.LabelValue{"team.example/owner": "platform"},
		Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{"example.com/note": "preserve me"},
	}
	gateway, _ := Translate(in)
	if gateway.InfrastructureLabels["team.example/owner"] != "platform" || gateway.InfrastructureAnnotations["example.com/note"] != "preserve me" {
		t.Fatalf("infrastructure metadata = labels %#v annotations %#v", gateway.InfrastructureLabels, gateway.InfrastructureAnnotations)
	}
	in.Gateway.Spec.Infrastructure.Labels["team.example/owner"] = "mutated"
	if gateway.InfrastructureLabels["team.example/owner"] != "platform" {
		t.Fatal("translated infrastructure labels alias Gateway input")
	}
}
func TestTranslateInvalidInfrastructureParametersRef(t *testing.T) {
	in := baseInputs()
	in.Gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
		Group: "invalid.io",
		Kind:  "InvalidParameters",
		Name:  "invalid",
	}}
	gateway, statuses := Translate(in)
	if len(gateway.Listeners) != 0 {
		t.Fatalf("invalid parametersRef produced listeners: %#v", gateway.Listeners)
	}
	accepted := findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted)
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
		t.Fatalf("invalid parametersRef Accepted = %#v", accepted)
	}
	in.Gateway.Spec.Infrastructure.ParametersRef.Group = "flareway.bhyoo.com"
	in.Gateway.Spec.Infrastructure.ParametersRef.Kind = "CloudflareTunnel"
	gateway, statuses = Translate(in)
	accepted = findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted)
	if len(gateway.Listeners) != 0 || accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
		t.Fatalf("supported-looking parametersRef must still be rejected in M1: IR=%#v Accepted=%#v", gateway.Listeners, accepted)
	}
}

func TestTranslateListenerIsolationAndStatusEdges(t *testing.T) {
	t.Run("wildcard hostname has one owner", func(t *testing.T) {
		in := baseInputs()
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{
			{Name: "fallback", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "wildcard", Hostname: new(gatewayv1.Hostname("*.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		}
		in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
		route := routeWithMatch("wildcard", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))
		route.Spec.Hostnames = []gatewayv1.Hostname{"*.example.com"}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{route}
		gateway, _ := Translate(in)
		owners := 0
		for _, domain := range gateway.Domains {
			for _, virtualHost := range domain.VirtualHosts {
				if virtualHost.Hostname == "*.example.com" {
					owners++
				}
			}
		}
		if owners != 1 {
			t.Fatalf("wildcard hostname owners = %d, want 1: %#v", owners, gateway.Domains)
		}
	})

	t.Run("unresolved listener still counts attachment", func(t *testing.T) {
		in := baseInputs()
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{{
			Name: "https", Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "missing"}}},
		}}
		in.Services = []corev1.Service{service("default", "backend", 8080, nil)}
		in.HTTPRoutes = []gatewayv1.HTTPRoute{routeWithMatch("route", gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))}
		_, statuses := Translate(in)
		if got := statuses.Gateway.Listeners[0].AttachedRoutes; got != 1 {
			t.Fatalf("AttachedRoutes = %d, want 1", got)
		}
	})

	t.Run("invalid route kind is not reported supported", func(t *testing.T) {
		in := baseInputs()
		in.Gateway.Spec.Listeners[0].AllowedRoutes = &gatewayv1.AllowedRoutes{Kinds: []gatewayv1.RouteGroupKind{{Kind: "GRPCRoute"}}}
		_, statuses := Translate(in)
		if got := statuses.Gateway.Listeners[0].SupportedKinds; len(got) != 0 {
			t.Fatalf("SupportedKinds = %#v, want empty", got)
		}
	})

	t.Run("same port different protocols conflict", func(t *testing.T) {
		in := baseInputs()
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "https", Port: 80, Protocol: gatewayv1.HTTPSProtocolType, TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "cert"}}}},
		}
		in.Secrets = []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "default"}, Type: corev1.SecretTypeTLS, Data: validTLSSecretData(t)}}
		gateway, statuses := Translate(in)
		if len(gateway.Listeners) != 0 {
			t.Fatalf("conflicting listeners produced IR: %#v", gateway.Listeners)
		}
		for _, listener := range statuses.Gateway.Listeners {
			condition := findListenerCondition(statuses.Gateway, listener.Name, gatewayv1.ListenerConditionConflicted)
			if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != string(gatewayv1.ListenerReasonProtocolConflict) {
				t.Fatalf("listener %s conflict condition = %#v", listener.Name, condition)
			}
		}
	})
	t.Run("Gateway remains accepted with one valid listener", func(t *testing.T) {
		in := baseInputs()
		in.Gateway.Spec.Listeners = []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		}
		_, statuses := Translate(in)
		accepted := findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted)
		if accepted == nil || accepted.Status != metav1.ConditionTrue || accepted.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
			t.Fatalf("partially valid Gateway Accepted = %#v", accepted)
		}
		if got := statuses.Gateway.Listeners[1].SupportedKinds; len(got) != 0 {
			t.Fatalf("protocol-invalid listener SupportedKinds = %#v, want empty", got)
		}

		in.Gateway.Spec.Listeners = in.Gateway.Spec.Listeners[1:]
		_, statuses = Translate(in)
		accepted = findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted)
		if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
			t.Fatalf("fully invalid Gateway Accepted = %#v", accepted)
		}
	})

}

func TestCompileCORSDefaultAndFilterOnlyRule(t *testing.T) {
	cors := compileCORS(gatewayv1.HTTPCORSFilter{})
	if cors.MaxAge == nil || *cors.MaxAge != 5 {
		t.Fatalf("default CORS max age = %#v, want 5", cors.MaxAge)
	}
	wildcard := compileCORS(gatewayv1.HTTPCORSFilter{
		AllowOrigins:     []gatewayv1.CORSOrigin{"*"},
		AllowMethods:     []gatewayv1.HTTPMethodWithWildcard{"*"},
		AllowHeaders:     []gatewayv1.HTTPHeaderName{"*"},
		AllowCredentials: new(true),
	})
	if len(wildcard.AllowOrigins) != 1 || wildcard.AllowOrigins[0] != "*" ||
		len(wildcard.AllowMethods) != 1 || wildcard.AllowMethods[0] != "*" ||
		len(wildcard.AllowHeaders) != 1 || wildcard.AllowHeaders[0] != "*" ||
		!wildcard.AllowCredentials {
		t.Fatalf("credentialed CORS wildcards were not preserved: %#v", wildcard)
	}

	in := baseInputs()
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "filter-only", Namespace: "default", Generation: 1},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{{Filters: []gatewayv1.HTTPRouteFilter{{
				Type:                  gatewayv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{Name: "x-test", Value: "value"}}},
			}}}},
		},
	}}
	gateway, statuses := Translate(in)
	translated := gateway.Domains[0].VirtualHosts[0].Routes[0]
	if translated.Invalid != nil {
		t.Fatalf("filter-only rule marked invalid: %#v", translated.Invalid)
	}
	resolved := findRouteCondition(statuses.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "filter-only"}], gatewayv1.RouteConditionResolvedRefs)
	if resolved == nil || resolved.Status != metav1.ConditionTrue {
		t.Fatalf("filter-only ResolvedRefs = %#v", resolved)
	}
}
func TestTranslateBackendClusterIdentitiesRemainDistinct(t *testing.T) {
	in := baseInputs()
	in.Gateway.Spec.Listeners[0].AllowedRoutes = &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{
		From: new(gatewayv1.NamespacesFromAll),
	}}
	in.Services = []corev1.Service{
		service("team", "api--admin", 80, nil),
		service("team--api", "admin", 80, nil),
	}

	ready := true
	endpointName := "http"
	firstEndpointPort := int32(8081)
	secondEndpointPort := int32(8082)
	in.EndpointSlices = []discoveryv1.EndpointSlice{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "api-admin", Namespace: "team", Labels: map[string]string{discoveryv1.LabelServiceName: "api--admin"}},
			Ports:      []discoveryv1.EndpointPort{{Name: &endpointName, Port: &firstEndpointPort}},
			Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "team--api", Labels: map[string]string{discoveryv1.LabelServiceName: "admin"}},
			Ports:      []discoveryv1.EndpointPort{{Name: &endpointName, Port: &secondEndpointPort}},
			Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
	}
	in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "api-admin-tls", Namespace: "team", Generation: 1},
			Spec: gatewayv1.BackendTLSPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: "", Kind: "Service", Name: "api--admin"}}},
				Validation: gatewayv1.BackendTLSPolicyValidation{
					Hostname:                "api-admin.team.example.com",
					WellKnownCACertificates: new(gatewayv1.WellKnownCACertificatesSystem),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-tls", Namespace: "team--api", Generation: 1},
			Spec: gatewayv1.BackendTLSPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: "", Kind: "Service", Name: "admin"}}},
				Validation: gatewayv1.BackendTLSPolicyValidation{
					Hostname:                "admin.team-api.example.com",
					WellKnownCACertificates: new(gatewayv1.WellKnownCACertificatesSystem),
				},
			},
		},
	}

	mirrorNamespace := gatewayv1.Namespace("team--api")
	gatewayNamespace := gatewayv1.Namespace("default")
	in.ReferenceGrants = []gatewayv1.ReferenceGrant{{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-admin-mirror", Namespace: "team--api"},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{Group: gatewayv1.Group(gatewayGroup), Kind: "HTTPRoute", Namespace: "team"}},
			To:   []gatewayv1.ReferenceGrantTo{{Group: "", Kind: "Service", Name: new(gatewayv1.ObjectName("admin"))}},
		},
	}}
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "collision", Namespace: "team", Generation: 1},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", Namespace: &gatewayNamespace}}},
			Rules: []gatewayv1.HTTPRouteRule{{
				Filters: []gatewayv1.HTTPRouteFilter{{
					Type: gatewayv1.HTTPRouteFilterRequestMirror,
					RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{BackendRef: gatewayv1.BackendObjectReference{
						Name: "admin", Namespace: &mirrorNamespace, Port: new(gatewayv1.PortNumber(80)),
					}},
				}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
					Name: "api--admin", Port: new(gatewayv1.PortNumber(80)),
				}}}},
			}},
		},
	}}

	gateway, statuses := Translate(in)
	if len(gateway.Domains) != 1 || len(gateway.Domains[0].VirtualHosts) != 1 || len(gateway.Domains[0].VirtualHosts[0].Routes) != 1 {
		t.Fatalf("translated collision route = %#v", gateway.Domains)
	}
	translated := gateway.Domains[0].VirtualHosts[0].Routes[0]
	firstName := "k8s://team/api--admin:80"
	secondName := "k8s://team--api/admin:80"
	if len(translated.Backends) != 1 || translated.Backends[0].ClusterName != firstName {
		t.Fatalf("route backend = %#v, want cluster %q", translated.Backends, firstName)
	}
	if len(translated.Filters.Mirrors) != 1 || translated.Filters.Mirrors[0].Backend.ClusterName != secondName {
		t.Fatalf("route mirrors = %#v, want cluster %q", translated.Filters.Mirrors, secondName)
	}

	clusters := make(map[string]ir.Cluster, len(gateway.Clusters))
	for _, cluster := range gateway.Clusters {
		clusters[cluster.Name] = cluster
	}
	if len(clusters) != 2 {
		t.Fatalf("clusters = %#v, want two distinct clusters", gateway.Clusters)
	}
	firstCluster, firstFound := clusters[firstName]
	secondCluster, secondFound := clusters[secondName]
	if !firstFound || firstCluster.Namespace != "team" || firstCluster.Service != "api--admin" || firstCluster.Port != 80 ||
		!reflect.DeepEqual(firstCluster.Endpoints, []ir.Endpoint{{Address: "10.0.0.1", Port: 8081}}) ||
		firstCluster.TLS == nil || firstCluster.TLS.ServerName != "api-admin.team.example.com" {
		t.Fatalf("first cluster = %#v", firstCluster)
	}
	if !secondFound || secondCluster.Namespace != "team--api" || secondCluster.Service != "admin" || secondCluster.Port != 80 ||
		!reflect.DeepEqual(secondCluster.Endpoints, []ir.Endpoint{{Address: "10.0.0.2", Port: 8082}}) ||
		secondCluster.TLS == nil || secondCluster.TLS.ServerName != "admin.team-api.example.com" {
		t.Fatalf("second cluster = %#v", secondCluster)
	}
	for _, key := range []types.NamespacedName{
		{Namespace: "team", Name: "api-admin-tls"},
		{Namespace: "team--api", Name: "admin-tls"},
	} {
		condition := findPolicyCondition(statuses.BackendTLSPolicies[key], gatewayv1.PolicyConditionAccepted)
		if condition == nil || condition.Status != metav1.ConditionTrue {
			t.Fatalf("BackendTLSPolicy %s Accepted = %#v", key, condition)
		}
	}
}

func TestTranslateFeaturesGolden(t *testing.T) {
	in := baseInputs()
	h2c := "kubernetes.io/h2c"
	in.Services = []corev1.Service{
		service("default", "backend", 8080, &h2c),
		service("default", "mirror", 9090, nil),
	}
	ready := true
	endpointPort := int32(8081)
	endpointName := "http"
	in.EndpointSlices = []discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-a", Namespace: "default", Labels: map[string]string{discoveryv1.LabelServiceName: "backend"}},
		Ports:      []discoveryv1.EndpointPort{{Name: &endpointName, Port: &endpointPort}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.2", "10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
	}}
	in.ConfigMaps = nil
	in.BackendTLSPolicies = []gatewayv1.BackendTLSPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-tls", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: "", Kind: "Service", Name: "backend"}, SectionName: new(gatewayv1.SectionName("http"))}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:                "backend.default.svc.cluster.local",
				WellKnownCACertificates: new(gatewayv1.WellKnownCACertificatesSystem),
				SubjectAltNames:         []gatewayv1.SubjectAltName{{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "backend.default.svc.cluster.local"}},
			},
		},
	}}
	method := gatewayv1.HTTPMethodGet
	requestTimeout := gatewayv1.Duration("15s")
	backendTimeout := gatewayv1.Duration("5s")
	in.HTTPRoutes = []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "features", Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Hostnames:       []gatewayv1.Hostname{"api.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchPathPrefix), Value: new("/v1")}, Method: &method, Headers: []gatewayv1.HTTPHeaderMatch{{Name: "X-Tenant", Value: "blue"}}, QueryParams: []gatewayv1.HTTPQueryParamMatch{{Name: "verbose", Value: "true"}}}},
				Filters: []gatewayv1.HTTPRouteFilter{
					{Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier, RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{Name: "X-Route", Value: "features"}}}},
					{Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier, ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{Remove: []string{"Server"}}},
					{Type: gatewayv1.HTTPRouteFilterURLRewrite, URLRewrite: &gatewayv1.HTTPURLRewriteFilter{Hostname: new(gatewayv1.PreciseHostname("upstream.example.com")), Path: &gatewayv1.HTTPPathModifier{Type: gatewayv1.PrefixMatchHTTPPathModifier, ReplacePrefixMatch: new("/")}}},
					{Type: gatewayv1.HTTPRouteFilterRequestMirror, RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{BackendRef: gatewayv1.BackendObjectReference{Name: "mirror", Port: new(gatewayv1.PortNumber(9090))}, Percent: new(int32(25))}},
					{Type: gatewayv1.HTTPRouteFilterCORS, CORS: &gatewayv1.HTTPCORSFilter{AllowOrigins: []gatewayv1.CORSOrigin{"https://app.example.com"}, AllowMethods: []gatewayv1.HTTPMethodWithWildcard{"GET", "OPTIONS"}, AllowHeaders: []gatewayv1.HTTPHeaderName{"X-Tenant"}, ExposeHeaders: []gatewayv1.HTTPHeaderName{"X-Request-ID"}, MaxAge: 600, AllowCredentials: new(true)}},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: new(gatewayv1.PortNumber(8080))}, Weight: new(int32(100))}}},
				Timeouts:    &gatewayv1.HTTPRouteTimeouts{Request: &requestTimeout, BackendRequest: &backendTimeout},
			}},
		},
	}}
	gateway, _ := Translate(in)
	got, err := json.MarshalIndent(gateway, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	assertGolden(t, "translate-features.golden.json", got)
}

func TestTranslateCloudflareExposureAndGrants(t *testing.T) {
	in := baseInputs()
	in.GatewayClassConfig.Spec.ConformanceMode = false
	in.Gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
		Group: v1alpha1.Group,
		Kind:  "CloudflareTunnel",
		Name:  "edge",
	}}
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: "public", Hostname: new(gatewayv1.Hostname("public.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "protected", Hostname: new(gatewayv1.Hostname("protected.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "private", Hostname: new(gatewayv1.Hostname("private.example.com")), Port: 443, Protocol: gatewayv1.HTTPSProtocolType, TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}}},
	}
	in.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"tenant": "apps"}}}}
	in.Secrets = []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "private-cert", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       validTLSSecretData(t),
	}}
	in.CloudflareAccount = &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "apps"}},
				Hostnames:            []string{"*.example.com"},
				Zones:                []string{"example.com"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				UnprotectedHostnames: []string{"public.example.com"},
			}},
		},
	}
	in.CloudflareTunnel = &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Listeners: []v1alpha1.CloudflareTunnelListener{{
				Name: "private", Exposure: v1alpha1.ExposurePrivate,
			}},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID: "11111111-1111-1111-1111-111111111111", OwnershipVerified: true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "flareway-tunnel-edge"},
			GatewayRef:              &corev1.LocalObjectReference{Name: in.Gateway.Name}, GatewayUID: in.Gateway.UID,
		},
	}

	gateway, statuses := Translate(in)
	if accepted := findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted); accepted == nil || accepted.Status != metav1.ConditionTrue {
		t.Fatalf("Gateway Accepted = %#v", accepted)
	}
	if gateway.Cloudflare == nil || gateway.Cloudflare.TunnelID != in.CloudflareTunnel.Status.TunnelID || gateway.Cloudflare.TokenSecretName != "flareway-tunnel-edge" {
		t.Fatalf("Cloudflare IR = %#v", gateway.Cloudflare)
	}
	if len(gateway.Listeners) != 3 || gateway.Listeners[2].Exposure != ir.ExposurePrivate || gateway.Listeners[2].EnvoyPort != 443 {
		t.Fatalf("listener exposure/ports = %#v", gateway.Listeners)
	}
	guards := map[string]string{}
	for _, domain := range gateway.Domains {
		guards[domain.ListenerName] = domain.Guard
	}
	if guards["public"] != ir.GuardUnprotected || guards["protected"] != ir.GuardBlocked || guards["private"] != ir.GuardBlocked {
		t.Fatalf("domain guards = %#v", guards)
	}

	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"public.example.com"}
	gateway, statuses = Translate(in)
	if len(gateway.Listeners) != 1 {
		t.Fatalf("denied hostnames produced listeners: %#v", gateway.Listeners)
	}
	if accepted := findGatewayCondition(statuses.Gateway, gatewayv1.GatewayConditionAccepted); accepted == nil || accepted.Status != metav1.ConditionTrue || accepted.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
		t.Fatalf("Gateway partial acceptance after hostname denial = %#v", accepted)
	}
}

func TestTranslateDoesNotUseUnverifiedObserveOnlyOrDeletedTunnelIdentity(t *testing.T) {
	in := baseInputs()
	in.GatewayClassConfig.Spec.ConformanceMode = false
	in.CloudflareAccount = &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{AccountID: "account"}}
	in.CloudflareTunnel = &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: in.Gateway.Namespace},
		Spec:       v1alpha1.CloudflareTunnelSpec{ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID: "observed", GatewayRef: &corev1.LocalObjectReference{Name: in.Gateway.Name}, GatewayUID: in.Gateway.UID,
		},
	}
	gateway, _ := Translate(in)
	if gateway.Cloudflare != nil {
		t.Fatalf("ObserveOnly Tunnel produced managed Cloudflare IR: %#v", gateway.Cloudflare)
	}
	in.CloudflareTunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
	gateway, _ = Translate(in)
	if gateway.Cloudflare != nil {
		t.Fatalf("unverified Tunnel produced managed Cloudflare IR: %#v", gateway.Cloudflare)
	}
	deletedAt := metav1.NewTime(time.Unix(200, 0))
	in.CloudflareTunnel.Status.OwnershipVerified = true
	in.CloudflareTunnel.Status.ConnectorTokenSecretRef = &corev1.LocalObjectReference{Name: "connector-token"}
	in.CloudflareTunnel.Status.DeletedAt = &deletedAt
	addressType := gatewayv1.HostnameAddressType
	in.CloudflareTunnel.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "observed.cfargotunnel.com"}}
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
		Name: "http", Exposure: v1alpha1.ExposurePrivate, Binding: v1alpha1.ListenerBindingPodIP,
	}}
	in.Services = []corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway-gw-" + in.Gateway.Name, Namespace: in.Gateway.Namespace},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.96.0.10"},
	}}
	gateway, statuses := Translate(in)
	if gateway.Cloudflare != nil {
		t.Fatalf("remotely deleted Tunnel produced connector-bearing Cloudflare IR: %#v", gateway.Cloudflare)
	}
	for _, listener := range gateway.Listeners {
		if listener.Binding == ir.ListenerBindingPodIP {
			t.Fatalf("remotely deleted Tunnel retained private listener binding: %#v", gateway.Listeners)
		}
	}
	if len(statuses.Gateway.Addresses) != 0 {
		t.Fatalf("remotely deleted Tunnel published Gateway addresses: %#v", statuses.Gateway.Addresses)
	}
}

func TestTranslateGatewayOriginRequest(t *testing.T) {
	in := baseInputs()
	in.GatewayClassConfig.Spec.ConformanceMode = false
	connectTimeout := metav1.Duration{Duration: 30 * time.Second}
	keepAliveTimeout := metav1.Duration{Duration: 90 * time.Second}
	tcpKeepAlive := metav1.Duration{Duration: 15 * time.Second}
	keepAliveConnections := int64(100)
	noHappyEyeballs := false
	disableChunked := true
	http2Origin := true
	in.GatewayClassConfig.Spec.OriginRequest = v1alpha1.GatewayOriginRequestSpec{
		ConnectTimeout: &connectTimeout, KeepAliveTimeout: &keepAliveTimeout, TCPKeepAlive: &tcpKeepAlive,
		KeepAliveConnections: &keepAliveConnections, NoHappyEyeballs: &noHappyEyeballs,
		DisableChunkedEncoding: &disableChunked, HTTP2Origin: &http2Origin,
	}
	in.CloudflareAccount = &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef"}}
	in.CloudflareTunnel = &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID: "11111111-1111-1111-1111-111111111111", OwnershipVerified: true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "flareway-tunnel-edge"},
			GatewayRef:              &corev1.LocalObjectReference{Name: in.Gateway.Name}, GatewayUID: in.Gateway.UID,
		},
	}

	gateway, _ := Translate(in)
	if gateway == nil || gateway.Cloudflare == nil {
		t.Fatal("Cloudflare IR was not produced")
	}
	origin := gateway.Cloudflare.OriginRequest
	if origin.ConnectTimeout == nil || *origin.ConnectTimeout != 30*time.Second ||
		origin.KeepAliveTimeout == nil || *origin.KeepAliveTimeout != 90*time.Second ||
		origin.TCPKeepAlive == nil || *origin.TCPKeepAlive != 15*time.Second ||
		origin.KeepAliveConnections == nil || *origin.KeepAliveConnections != 100 ||
		origin.NoHappyEyeballs == nil || *origin.NoHappyEyeballs ||
		origin.DisableChunkedEncoding == nil || !*origin.DisableChunkedEncoding ||
		origin.HTTP2Origin == nil || !*origin.HTTP2Origin {
		t.Fatalf("Gateway origin request IR = %#v", origin)
	}
	keepAliveConnections = 7
	if *origin.KeepAliveConnections != 100 {
		t.Fatal("Gateway origin request IR retained mutable API pointers")
	}
}

func baseInputs() Inputs {
	return Inputs{
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default", UID: types.UID("gateway-uid"), Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "flareway",
				Listeners:        []gatewayv1.Listener{{Name: "http", Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		},
		GatewayClass:       &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: ControllerName}},
		GatewayClassConfig: &v1alpha1.GatewayClassConfig{Spec: v1alpha1.GatewayClassConfigSpec{ConformanceMode: true}},
		Now:                metav1.NewTime(time.Unix(100, 0).UTC()),
	}
}

func service(namespace, name string, port int32, appProtocol *string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: port, AppProtocol: appProtocol}}},
	}
}

func routeWithMatch(name string, pathType gatewayv1.PathMatchType, path string, method *gatewayv1.HTTPMethod, headers []gatewayv1.HTTPHeaderMatch, query []gatewayv1.HTTPQueryParamMatch, createdAt time.Time) gatewayv1.HTTPRoute {
	return gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(createdAt)},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}}},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}, Method: method, Headers: headers, QueryParams: query}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: new(gatewayv1.PortNumber(8080))}}}},
			}},
		},
	}
}
func routeWithBackend(name, backend string, port gatewayv1.PortNumber) gatewayv1.HTTPRoute {
	route := routeWithMatch(name, gatewayv1.PathMatchPathPrefix, "/", nil, nil, nil, time.Unix(1, 0))
	route.Spec.Rules[0].BackendRefs[0].Name = gatewayv1.ObjectName(backend)
	route.Spec.Rules[0].BackendRefs[0].Port = &port
	return route
}

func policyForService(name, serviceName string, sectionName *gatewayv1.SectionName, createdAt time.Time) gatewayv1.BackendTLSPolicy {
	return gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1, CreationTimestamp: metav1.NewTime(createdAt)},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: "", Kind: "Service", Name: gatewayv1.ObjectName(serviceName)},
				SectionName:                sectionName,
			}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				WellKnownCACertificates: new(gatewayv1.WellKnownCACertificatesSystem),
				Hostname:                gatewayv1.PreciseHostname(name + ".example.com"),
			},
		},
	}
}

func findGatewayCondition(gatewayStatus gatewayv1.GatewayStatus, conditionType gatewayv1.GatewayConditionType) *metav1.Condition {
	for index := range gatewayStatus.Conditions {
		if gatewayStatus.Conditions[index].Type == string(conditionType) {
			return &gatewayStatus.Conditions[index]
		}
	}
	return nil
}

func findRouteCondition(routeStatus gatewayv1.HTTPRouteStatus, conditionType gatewayv1.RouteConditionType) *metav1.Condition {
	for _, parent := range routeStatus.Parents {
		if parent.ControllerName != ControllerName {
			continue
		}
		for i := range parent.Conditions {
			if parent.Conditions[i].Type == string(conditionType) {
				return &parent.Conditions[i]
			}
		}
	}
	return nil
}

func findPolicyCondition(policyStatus gatewayv1.PolicyStatus, conditionType gatewayv1.PolicyConditionType) *metav1.Condition {
	for _, ancestor := range policyStatus.Ancestors {
		if ancestor.ControllerName != ControllerName {
			continue
		}
		for i := range ancestor.Conditions {
			if ancestor.Conditions[i].Type == string(conditionType) {
				return &ancestor.Conditions[i]
			}
		}
	}
	return nil
}

func findListenerCondition(gatewayStatus gatewayv1.GatewayStatus, name gatewayv1.SectionName, conditionType gatewayv1.ListenerConditionType) *metav1.Condition {
	for _, listener := range gatewayStatus.Listeners {
		if listener.Name != name {
			continue
		}
		for index := range listener.Conditions {
			if listener.Conditions[index].Type == string(conditionType) {
				return &listener.Conditions[index]
			}
		}
	}
	return nil
}

func validTLSSecretData(t *testing.T) map[string][]byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(3600, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"api.example.com"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}),
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
