/*
Copyright 2026 Byeonghoon Yoo.

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

package authz

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func TestEvaluateRequiresNamespaceGrantForEmptyRequest(t *testing.T) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"tenant": "blue"}}}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "green"}},
		}}},
	}

	decision := Evaluate(account, namespace, Request{})
	if decision.Allowed || decision.Reason != ReasonRefNotPermitted {
		t.Fatalf("expected an empty request without a namespace grant to be denied, got %#v", decision)
	}

	account.Spec.Grants[0].NamespaceSelector = metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}}
	decision = Evaluate(account, namespace, Request{})
	if !decision.Allowed || decision.GrantIndex != 0 {
		t.Fatalf("expected an empty request with a namespace grant to be allowed, got %#v", decision)
	}
}

func TestEvaluateRequiresOneGrantToAllowEveryGate(t *testing.T) {
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{
			{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
				Hostnames:         []string{"*.example.com"},
				Zones:             []string{"example.com"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			},
			{
				NamespaceSelector:            metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
				Hostnames:                    []string{"other.example.com"},
				Zones:                        []string{"example.com"},
				Exposures:                    []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				AccessPolicyRefs:             v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs:         v1alpha1.GrantPermissionAllowed,
				DevicePostureIntegrationRefs: v1alpha1.GrantPermissionAllowed,
			},
		}},
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"tenant": "blue"}}}

	decision := Evaluate(account, namespace, Request{
		Hostname:                    "api.example.com",
		Zone:                        "example.com",
		Exposure:                    v1alpha1.ExposurePublic,
		AccessPolicyRef:             true,
		AccessCustomPageRef:         true,
		DevicePostureIntegrationRef: true,
	})
	if decision.Allowed {
		t.Fatalf("expected split grants to deny request, got %#v", decision)
	}
}

func TestEvaluateRequiresOneGrantForManagedReferenceGates(t *testing.T) {
	tests := []struct {
		name      string
		request   Request
		authorize func(*v1alpha1.CloudflareAccountGrant)
	}{
		{
			name:    "Access custom page",
			request: Request{AccessCustomPageRef: true, PlatformObject: true},
			authorize: func(grant *v1alpha1.CloudflareAccountGrant) {
				grant.AccessCustomPageRefs = v1alpha1.GrantPermissionAllowed
			},
		},
		{
			name:    "device posture integration",
			request: Request{DevicePostureIntegrationRef: true, PlatformObject: true},
			authorize: func(grant *v1alpha1.CloudflareAccountGrant) {
				grant.DevicePostureIntegrationRefs = v1alpha1.GrantPermissionAllowed
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := &v1alpha1.CloudflareAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "account"},
				Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{
					{NamespaceSelector: metav1.LabelSelector{}, PlatformObjects: v1alpha1.GrantPermissionAllowed},
					{NamespaceSelector: metav1.LabelSelector{}},
				}},
			}
			test.authorize(&account.Spec.Grants[1])
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}}

			decision := Evaluate(account, namespace, test.request)
			if decision.Allowed {
				t.Fatalf("expected split %s and platform-object grants to deny request, got %#v", test.name, decision)
			}
		})
	}
}

func TestEvaluateAllGrantGates(t *testing.T) {
	emptySelector := &metav1.LabelSelector{}
	backendSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"backend-for": "blue"}}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector:            metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
			Hostnames:                    []string{"*.example.com"},
			Zones:                        []string{"example.com"},
			Exposures:                    []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			UnprotectedHostnames:         []string{"public.example.com"},
			AccessPolicyRefs:             v1alpha1.GrantPermissionAllowed,
			AccessCustomPageRefs:         v1alpha1.GrantPermissionAllowed,
			DevicePostureIntegrationRefs: v1alpha1.GrantPermissionAllowed,
			PlatformObjects:              v1alpha1.GrantPermissionAllowed,
			PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
				NetworkRouteSelector:  emptySelector,
				HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
			},
			Backends: &v1alpha1.CloudflareBackendGrant{
				Namespaces: v1alpha1.BackendNamespaceSelector,
				Selector:   backendSelector,
				Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
			},
		}}},
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"tenant": "blue"}}}
	backendNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"backend-for": "blue"}}}

	decision := Evaluate(account, namespace, Request{
		Hostname:                    "public.example.com",
		Zone:                        "example.com",
		Exposure:                    v1alpha1.ExposurePublic,
		Unprotected:                 true,
		AccessPolicyRef:             true,
		AccessCustomPageRef:         true,
		DevicePostureIntegrationRef: true,
		PlatformObject:              true,
		PrivateRoute:                &PrivateRouteRequest{Kind: PrivateRouteHostname, Labels: map[string]string{"tenant": "blue"}},
		Backend:                     &BackendRequest{Namespace: backendNamespace, Kind: v1alpha1.BackendKindService},
	})
	if !decision.Allowed || decision.GrantIndex != 0 {
		t.Fatalf("expected request to be allowed by grant 0, got %#v", decision)
	}
}

func TestEvaluateDeniesEachAccountBoundary(t *testing.T) {
	newGrant := func() v1alpha1.CloudflareAccountGrant {
		return v1alpha1.CloudflareAccountGrant{
			NamespaceSelector:            metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
			Hostnames:                    []string{"public.example.com"},
			Zones:                        []string{"example.com"},
			Exposures:                    []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			UnprotectedHostnames:         []string{"public.example.com"},
			AccessPolicyRefs:             v1alpha1.GrantPermissionAllowed,
			AccessCustomPageRefs:         v1alpha1.GrantPermissionAllowed,
			DevicePostureIntegrationRefs: v1alpha1.GrantPermissionAllowed,
			PlatformObjects:              v1alpha1.GrantPermissionAllowed,
			PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
				HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"route": "allowed"}},
			},
			Backends: &v1alpha1.CloudflareBackendGrant{
				Namespaces: v1alpha1.BackendNamespaceSame,
				Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
			},
		}
	}
	newRequest := func(namespace *corev1.Namespace) Request {
		return Request{
			Hostname:                    "public.example.com",
			Zone:                        "example.com",
			Exposure:                    v1alpha1.ExposurePublic,
			Unprotected:                 true,
			AccessPolicyRef:             true,
			AccessCustomPageRef:         true,
			DevicePostureIntegrationRef: true,
			PlatformObject:              true,
			PrivateRoute:                &PrivateRouteRequest{Kind: PrivateRouteHostname, Labels: map[string]string{"route": "allowed"}},
			Backend:                     &BackendRequest{Namespace: namespace, Kind: v1alpha1.BackendKindService},
		}
	}

	tests := []struct {
		name   string
		alter  func(*v1alpha1.CloudflareAccountGrant)
		reason string
	}{
		{name: "hostname", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.Hostnames = []string{"other.example.com"} }, reason: ReasonUnsupportedValue},
		{name: "zone", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.Zones = []string{"other.example"} }, reason: ReasonUnsupportedValue},
		{name: "exposure", alter: func(grant *v1alpha1.CloudflareAccountGrant) {
			grant.Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
		}, reason: ReasonUnsupportedValue},
		{name: "unprotected", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.UnprotectedHostnames = nil }, reason: ReasonRefNotPermitted},
		{name: "access policy", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.AccessPolicyRefs = v1alpha1.GrantPermissionDenied }, reason: ReasonRefNotPermitted},
		{name: "access custom page", alter: func(grant *v1alpha1.CloudflareAccountGrant) {
			grant.AccessCustomPageRefs = v1alpha1.GrantPermissionDenied
		}, reason: ReasonRefNotPermitted},
		{name: "device posture integration", alter: func(grant *v1alpha1.CloudflareAccountGrant) {
			grant.DevicePostureIntegrationRefs = v1alpha1.GrantPermissionDenied
		}, reason: ReasonRefNotPermitted},
		{name: "platform object", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.PlatformObjects = v1alpha1.GrantPermissionDenied }, reason: ReasonRefNotPermitted},
		{name: "private route", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.PrivateRoutes = nil }, reason: ReasonRefNotPermitted},
		{name: "backend kind", alter: func(grant *v1alpha1.CloudflareAccountGrant) { grant.Backends.Kinds = nil }, reason: ReasonRefNotPermitted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"tenant": "blue"}}}
			grant := newGrant()
			test.alter(&grant)
			account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{grant}}}
			decision := Evaluate(account, namespace, newRequest(namespace))
			if decision.Allowed || decision.Reason != test.reason {
				t.Fatalf("expected %s denial, got %#v", test.reason, decision)
			}
		})
	}
}

func TestEvaluateDeniesBackendOutsideSelector(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"backend-for": "blue"}}
	account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
		NamespaceSelector: metav1.LabelSelector{},
		Hostnames:         []string{"*"},
		Zones:             []string{"*"},
		Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		Backends: &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSelector,
			Selector:   selector,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		},
	}}}}

	decision := Evaluate(account,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "source"}},
		Request{Backend: &BackendRequest{
			Namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target", Labels: map[string]string{"backend-for": "red"}}},
			Kind:      v1alpha1.BackendKindService,
		}},
	)
	if decision.Allowed || decision.Reason != ReasonRefNotPermitted {
		t.Fatalf("expected backend selector denial, got %#v", decision)
	}
}

func TestHostnameMatchesSingleLabelWildcard(t *testing.T) {
	for _, test := range []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		{name: "exact", pattern: "API.Example.com.", hostname: "api.example.com", want: true},
		{name: "one label", pattern: "*.example.com", hostname: "api.example.com", want: true},
		{name: "not apex", pattern: "*.example.com", hostname: "example.com", want: false},
		{name: "not deep", pattern: "*.example.com", hostname: "deep.api.example.com", want: false},
		{name: "same wildcard", pattern: "*.example.com", hostname: "*.example.com", want: true},
		{name: "all", pattern: "*", hostname: "deep.api.example.com", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HostnameMatches(test.pattern, test.hostname); got != test.want {
				t.Fatalf("HostnameMatches(%q, %q) = %t, want %t", test.pattern, test.hostname, got, test.want)
			}
		})
	}
}
