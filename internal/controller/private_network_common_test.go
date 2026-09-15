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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
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
	for _, invalid := range []string{"*.*.example.internal", "api.*.internal", "partial*.example.internal", "example", "Example.Internal", "example.internal."} {
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
}
