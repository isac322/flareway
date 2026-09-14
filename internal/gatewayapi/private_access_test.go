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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func TestCompilePrivateDestinationsResolvesAuthorizedRoutes(t *testing.T) {
	inputs := privateAccessInputs()
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "tenant"},
		Spec: v1alpha1.AccessApplicationSpec{
			PrivateDestinations: []v1alpha1.AccessPrivateDestinationSpec{
				{NetworkRouteRef: &corev1.LocalObjectReference{Name: "services"}, CIDR: "10.96.12.34/32", PortRange: "5432", L4Protocol: v1alpha1.AccessL4ProtocolTCP},
				{HostnameRouteRef: &corev1.LocalObjectReference{Name: "database"}, PortRange: "5432-5433", L4Protocol: v1alpha1.AccessL4ProtocolTCP},
			},
		},
	}

	compiled := CompilePrivateDestinations(inputs, application)
	if !compiled.Accepted {
		t.Fatalf("private destinations rejected: %#v", compiled)
	}
	if len(compiled.Destinations) != 2 {
		t.Fatalf("destinations = %#v", compiled.Destinations)
	}
	if got := compiled.Destinations[0]; got.CIDR != "10.96.12.34/32" || got.VNetID != "vnet-prod" || got.PortRange != "5432" {
		t.Fatalf("network destination = %#v", got)
	}
	if got := compiled.Destinations[1]; got.Hostname != "db.internal.example" || got.PortRange != "5432-5433" || got.VNetID != "" {
		t.Fatalf("hostname destination = %#v", got)
	}
	if len(compiled.Ancestors) != 2 || compiled.OriginJWTEnforced {
		t.Fatalf("ancestors/origin JWT = %#v / %v", compiled.Ancestors, compiled.OriginJWTEnforced)
	}
}

func TestCompilePrivateDestinationsCannotBypassRouteBoundary(t *testing.T) {
	inputs := privateAccessInputs()
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "tenant"},
		Spec: v1alpha1.AccessApplicationSpec{PrivateDestinations: []v1alpha1.AccessPrivateDestinationSpec{{
			NetworkRouteRef: &corev1.LocalObjectReference{Name: "services"}, CIDR: "10.97.0.1/32", PortRange: "5432",
		}}},
	}
	compiled := CompilePrivateDestinations(inputs, application)
	if compiled.Accepted || compiled.Reason != "RefNotPermitted" || !strings.Contains(compiled.Message, "not contained") {
		t.Fatalf("out-of-route CIDR = %#v", compiled)
	}

	application.Spec.PrivateDestinations[0].NetworkRouteRef = nil
	compiled = CompilePrivateDestinations(inputs, application)
	if compiled.Accepted || compiled.Reason != "Invalid" {
		t.Fatalf("caller CIDR without route reference = %#v", compiled)
	}
}

func TestCompilePrivateDestinationsRequiresBothNamespaceAndAccountGrants(t *testing.T) {
	inputs := privateAccessInputs()
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "tenant"},
		Spec: v1alpha1.AccessApplicationSpec{PrivateDestinations: []v1alpha1.AccessPrivateDestinationSpec{{
			HostnameRouteRef: &corev1.LocalObjectReference{Name: "database"}, PortRange: "443",
		}}},
	}

	inputs.HostnameRoutes[0].Spec.AllowedNamespaces.From = v1alpha1.AllowedNamespaceFromSelector
	inputs.HostnameRoutes[0].Spec.AllowedNamespaces.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"private-access": "allowed"}}
	compiled := CompilePrivateDestinations(inputs, application)
	if compiled.Accepted || !strings.Contains(compiled.Message, "allowedNamespaces") {
		t.Fatalf("namespace denial = %#v", compiled)
	}

	inputs.Namespaces[0].Labels = map[string]string{"private-access": "allowed"}
	inputs.CloudflareAccount.Spec.Grants[0].PrivateRoutes.HostnameRouteSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "other"}}
	compiled = CompilePrivateDestinations(inputs, application)
	if compiled.Accepted || !strings.Contains(compiled.Message, "labels are not granted") {
		t.Fatalf("account selector denial = %#v", compiled)
	}
}

func privateAccessInputs() Inputs {
	all := metav1.LabelSelector{}
	return Inputs{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}},
		CloudflareAccount: &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
				PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
					NetworkRouteSelector: &all, HostnameRouteSelector: &all,
				},
			}}},
		},
		NetworkRoutes: []v1alpha1.NetworkRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "services", Namespace: "tenant", Generation: 1, Labels: map[string]string{"tenant": "llm"}},
			Spec: v1alpha1.NetworkRouteSpec{
				AccountRef: corev1.LocalObjectReference{Name: "account"}, Network: "10.96.0.0/16",
				AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame},
			},
			Status: v1alpha1.NetworkRouteStatus{
				RouteID: "network-route", OwnershipVerified: true, ObservedGeneration: 1,
				Applied: v1alpha1.NetworkRouteAppliedStatus{
					Network: "10.96.0.0/16", TunnelID: "tunnel", VirtualNetworkID: "vnet-prod", ObservedGeneration: 1,
				},
				Conditions: []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 1}},
			},
		}},
		HostnameRoutes: []v1alpha1.HostnameRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "tenant", Generation: 1, Labels: map[string]string{"tenant": "llm"}},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: corev1.LocalObjectReference{Name: "account"}, Hostname: "db.internal.example",
				AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame},
			},
			Status: v1alpha1.HostnameRouteStatus{
				RouteID: "hostname-route", OwnershipVerified: true, ObservedGeneration: 1,
				Applied: v1alpha1.HostnameRouteAppliedStatus{
					Hostname: "db.internal.example", TunnelID: "tunnel", ObservedGeneration: 1,
				},
				Conditions: []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 1}},
			},
		}},
	}
}
