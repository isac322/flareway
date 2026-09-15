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

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

func TestBlockPrivateDomainsPreservesPublicForwarding(t *testing.T) {
	gateway := &ir.Gateway{
		Listeners: []ir.Listener{
			{Name: "public", Exposure: ir.ExposurePublic},
			{Name: "private", Exposure: ir.ExposurePrivate},
		},
		Domains: []ir.ProtectionDomain{
			{Name: "public", ListenerName: "public", Guard: ir.GuardForwarding, Access: &ir.AccessGuard{AUDs: []string{"public"}}},
			{Name: "private", ListenerName: "private", Guard: ir.GuardForwarding, Access: &ir.AccessGuard{AUDs: []string{"private"}}},
		},
	}
	blockPrivateDomains(gateway)
	if gateway.Domains[0].Guard != ir.GuardForwarding || gateway.Domains[0].Access == nil {
		t.Fatalf("public domain changed: %#v", gateway.Domains[0])
	}
	if gateway.Domains[1].Guard != ir.GuardBlocked || gateway.Domains[1].Access != nil {
		t.Fatalf("private domain did not fail closed: %#v", gateway.Domains[1])
	}
}

func TestPrivateOriginJWTRequiresExplicitTLSDecryptionContract(t *testing.T) {
	gateway := &ir.Gateway{
		Listeners: []ir.Listener{{Name: "private", Exposure: ir.ExposurePrivate}},
		Domains:   []ir.ProtectionDomain{{ListenerName: "private", AccessApplication: "tenant/access"}},
	}
	application := v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: "tenant"},
		Spec:       v1alpha1.AccessApplicationSpec{OriginJWT: v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired}},
	}
	if got := privateOriginJWTWithoutTLSContract(gateway, []v1alpha1.AccessApplication{application}); got != "tenant/access" {
		t.Fatalf("missing contract result = %q", got)
	}
	application.Spec.OriginJWT.AssumeGatewayTLSDecryption = true
	if got := privateOriginJWTWithoutTLSContract(gateway, []v1alpha1.AccessApplication{application}); got != "" {
		t.Fatalf("explicit contract remained blocked: %q", got)
	}
}

func TestPrivateListenerVirtualNetworkMustBeReadyAndSameAccount(t *testing.T) {
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Listeners: []v1alpha1.CloudflareTunnelListener{{
				Name: "private", Exposure: v1alpha1.ExposurePrivate,
				VirtualNetworkRef: &corev1.LocalObjectReference{Name: "prod"},
			}},
		},
	}
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}}
	vnet := v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: "tenant"},
		Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
		Status: v1alpha1.VirtualNetworkStatus{
			VirtualNetworkID: "vnet-prod",
			Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
		},
	}
	if !privateListenerHasReadyVNet("private", tunnel, account, []v1alpha1.VirtualNetwork{vnet}) {
		t.Fatal("ready same-account VirtualNetwork was rejected")
	}
	vnet.Spec.AccountRef.Name = "other"
	if privateListenerHasReadyVNet("private", tunnel, account, []v1alpha1.VirtualNetwork{vnet}) {
		t.Fatal("different-account VirtualNetwork was accepted")
	}
}

func TestPrivateRouteTargetsOnlyCloudflareTunnels(t *testing.T) {
	tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant"}}
	for name, testCase := range map[string]struct {
		ref  v1alpha1.TunnelReference
		want bool
	}{
		"default kind": {
			ref:  v1alpha1.TunnelReference{Name: "tunnel"},
			want: true,
		},
		"CloudflareTunnel": {
			ref:  v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: "tunnel"},
			want: true,
		},
		"WARPConnector": {
			ref: v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindWARPConnector, Name: "tunnel"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := privateRouteTargetsTunnel(testCase.ref, "tenant", tunnel); got != testCase.want {
				t.Fatalf("privateRouteTargetsTunnel() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestGatewayRouteWatchIgnoresWARPConnectorReferences(t *testing.T) {
	route := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "tenant"},
		Spec: v1alpha1.NetworkRouteSpec{TunnelRef: v1alpha1.TunnelReference{
			Kind: v1alpha1.TunnelReferenceKindWARPConnector,
			Name: "connector",
		}},
	}
	if requests := (&GatewayReconciler{}).mapPrivateRouteToGateways(context.Background(), route); len(requests) != 0 {
		t.Fatalf("WARPConnector route enqueued Gateway reconciles: %#v", requests)
	}
}
