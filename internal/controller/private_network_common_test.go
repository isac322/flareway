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

package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestParseMaskedPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "IPv4", value: "10.96.0.0/12", want: "10.96.0.0/12"},
		{name: "IPv6", value: "fd00:1234::/48", want: "fd00:1234::/48"},
		{name: "host bits", value: "10.96.1.1/12", wantErr: true},
		{name: "invalid", value: "10.96.0.0", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix, err := parseMaskedPrefix(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseMaskedPrefix(%q) succeeded, want error", test.value)
				}
				return
			}
			if err != nil || prefix.String() != test.want {
				t.Fatalf("parseMaskedPrefix(%q) = %q, %v; want %q", test.value, prefix, err, test.want)
			}
		})
	}
}

func TestPrivateHostnameValidationAndOverlap(t *testing.T) {
	for _, valid := range []string{"admin.example.internal", "*.example.internal"} {
		if got, err := normalizedPrivateHostname(valid); err != nil || got != valid {
			t.Fatalf("normalizedPrivateHostname(%q) = %q, %v", valid, got, err)
		}
	}
	for _, invalid := range []string{"*.*.example.internal", "api.*.internal", "partial*.example.internal", "example", "Example.Internal", "example.internal.", "*.internal", "a..example.internal", "-bad.example.internal", "bad-.example.internal", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.internal"} {
		if _, err := normalizedPrivateHostname(invalid); err == nil {
			t.Fatalf("normalizedPrivateHostname(%q) succeeded, want error", invalid)
		}
	}
	if !privateHostnamesOverlap("*.example.internal", "admin.example.internal") {
		t.Fatal("single-label wildcard did not overlap its exact child")
	}
	if privateHostnamesOverlap("*.example.internal", "deep.admin.example.internal") {
		t.Fatal("single-label wildcard overlapped a multi-label child")
	}
	if got := cloudflarePrivateHostname("*.example.internal"); got != "example.internal" {
		t.Fatalf("cloudflarePrivateHostname() = %q", got)
	}
}

func TestPrivateRouteAllowsNamespace(t *testing.T) {
	routeNamespace := "platform"
	tenant := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "blue"}}}
	platform := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: routeNamespace}}

	allowed, err := privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{}, platform)
	if err != nil || !allowed {
		t.Fatalf("Same namespace = %t, %v", allowed, err)
	}
	allowed, err = privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{}, tenant)
	if err != nil || allowed {
		t.Fatalf("different namespace under Same = %t, %v", allowed, err)
	}
	allowed, err = privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromAll}, tenant)
	if err != nil || !allowed {
		t.Fatalf("All namespace = %t, %v", allowed, err)
	}
	allowed, err = privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}}}, tenant)
	if err != nil || !allowed {
		t.Fatalf("Selector namespace = %t, %v", allowed, err)
	}
	if _, err := privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector}, tenant); err == nil {
		t.Fatal("Selector without a selector succeeded, want error")
	}
	if _, err := privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{From: "Bogus"}, tenant); err == nil {
		t.Fatal("unsupported from succeeded, want error")
	}
	if _, err := privateRouteAllowsNamespace(routeNamespace, v1alpha1.AllowedNamespaces{}, nil); err == nil {
		t.Fatal("nil namespace succeeded, want error")
	}
}

func TestPrefixesOverlap(t *testing.T) {
	for _, test := range []struct {
		name  string
		left  string
		right string
		want  bool
	}{
		{name: "contained", left: "10.96.0.0/12", right: "10.100.0.0/16", want: true},
		{name: "contains", left: "10.100.0.0/16", right: "10.96.0.0/12", want: true},
		{name: "identical", left: "10.96.0.0/12", right: "10.96.0.0/12", want: true},
		{name: "disjoint", left: "10.96.0.0/12", right: "10.200.0.0/16", want: false},
		{name: "adjacent", left: "10.96.0.0/16", right: "10.97.0.0/16", want: false},
		{name: "cross family", left: "10.96.0.0/12", right: "fd00::/48", want: false},
		{name: "IPv6 contained", left: "fd00::/16", right: "fd00:1234::/48", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			left, leftErr := parseMaskedPrefix(test.left)
			right, rightErr := parseMaskedPrefix(test.right)
			if leftErr != nil || rightErr != nil {
				t.Fatalf("fixture prefixes failed to parse: %v, %v", leftErr, rightErr)
			}
			if got := prefixesOverlap(left, right); got != test.want {
				t.Fatalf("prefixesOverlap(%s, %s) = %t, want %t", test.left, test.right, got, test.want)
			}
		})
	}
}

func TestPrivateCommentOwnership(t *testing.T) {
	owner := "flareway cluster/namespace/name"
	if !privateCommentOwnedBy(owner, owner) {
		t.Fatal("exact owner comment was not recognized as owned")
	}
	if !privateCommentOwnedBy(owner+" | operator note", owner+" | different note") {
		t.Fatal("owner comment with a user suffix was not recognized as owned")
	}
	for _, foreign := range []string{"", owner + "-2", "other " + owner, "other | " + owner} {
		if privateCommentOwnedBy(foreign, owner) {
			t.Fatalf("foreign comment %q was recognized as owned by %q", foreign, owner)
		}
	}
}

func TestValidatePrivateTunnelType(t *testing.T) {
	if conflict := validatePrivateTunnelType(flarecloudflare.NetworkTunnelTypeCloudflareTunnel, flarecloudflare.NetworkTunnelTypeWARPConnector, "network route", "id-1"); conflict == "" {
		t.Fatal("mismatched remote tunnel type was accepted")
	}
	if conflict := validatePrivateTunnelType(flarecloudflare.NetworkTunnelTypeCloudflareTunnel, "", "network route", "id-1"); conflict != "" {
		t.Fatalf("unreported remote tunnel type was rejected: %s", conflict)
	}
	if conflict := validatePrivateTunnelType("bogus", flarecloudflare.NetworkTunnelTypeCloudflareTunnel, "network route", "id-1"); conflict == "" {
		t.Fatal("unsupported expected tunnel type was accepted")
	}
}

func TestPrivateObjectPrecedes(t *testing.T) {
	earlier := metav1.NewTime(time.Unix(100, 0))
	later := metav1.NewTime(time.Unix(200, 0))
	keyA := types.NamespacedName{Namespace: "ns", Name: "a"}
	keyB := types.NamespacedName{Namespace: "ns", Name: "b"}
	if !privateObjectPrecedes(earlier, keyB, later, keyA) {
		t.Fatal("earlier creation did not precede regardless of key order")
	}
	if privateObjectPrecedes(later, keyA, earlier, keyB) {
		t.Fatal("later creation preceded")
	}
	if !privateObjectPrecedes(earlier, keyA, earlier, keyB) {
		t.Fatal("creation tie did not fall back to namespaced-name order")
	}
	if privateObjectPrecedes(earlier, keyB, earlier, keyA) {
		t.Fatal("creation tie ignored namespaced-name order")
	}
}
