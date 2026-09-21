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
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func networkRouteForOverlap(namespace, name, network string, created time.Time, virtualNetworkRef *corev1.LocalObjectReference) *v1alpha1.NetworkRoute {
	return &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			UID:               types.UID("networkroute-" + namespace + "-" + name),
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef:        corev1.LocalObjectReference{Name: "account"},
			Network:           network,
			TunnelRef:         v1alpha1.TunnelReference{Name: "edge"},
			VirtualNetworkRef: virtualNetworkRef,
		},
	}
}

func runNetworkRouteOverlapCheck(t *testing.T, object *v1alpha1.NetworkRoute, virtualNetworkID string, peers ...*v1alpha1.NetworkRoute) error {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1alpha1 to scheme: %v", err)
	}
	objects := []client.Object{object}
	for _, peer := range peers {
		objects = append(objects, peer)
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	reconciler := &NetworkRouteReconciler{Client: kube, Scheme: scheme}
	prefix, err := netip.ParsePrefix(object.Spec.Network)
	if err != nil {
		t.Fatalf("parse object network %q: %v", object.Spec.Network, err)
	}
	return reconciler.checkOverlap(context.Background(), object, prefix, virtualNetworkID)
}

// Routes that omit spec.virtualNetworkRef all claim the single account-wide
// default virtual network, so unprogrammed peers must be compared across
// namespaces. Named references stay namespace-scoped.
func TestNetworkRouteCheckOverlapDefaultVirtualNetworkCrossNamespace(t *testing.T) {
	earlier := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	later := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)

	t.Run("rejects a later overlapping route in another namespace", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-a", "10.96.0.0/16", earlier, nil)
		object := networkRouteForOverlap("ns-2", "route-b", "10.96.10.0/24", later, nil)
		err := runNetworkRouteOverlapCheck(t, object, "", peer)
		if err == nil || !strings.Contains(err.Error(), "overlaps earlier unprogrammed NetworkRoute") {
			t.Fatalf("checkOverlap = %v, want overlap rejection against ns-1/route-a", err)
		}
	})

	t.Run("accepts the earlier route when a later peer overlaps", func(t *testing.T) {
		object := networkRouteForOverlap("ns-1", "route-a", "10.96.0.0/16", earlier, nil)
		peer := networkRouteForOverlap("ns-2", "route-b", "10.96.10.0/24", later, nil)
		if err := runNetworkRouteOverlapCheck(t, object, "", peer); err != nil {
			t.Fatalf("checkOverlap = %v, want nil for the earlier route", err)
		}
	})

	t.Run("accepts a disjoint route in another namespace", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-a", "10.96.0.0/16", earlier, nil)
		object := networkRouteForOverlap("ns-2", "route-b", "192.168.10.0/24", later, nil)
		if err := runNetworkRouteOverlapCheck(t, object, "", peer); err != nil {
			t.Fatalf("checkOverlap = %v, want nil for a disjoint network", err)
		}
	})

	t.Run("keeps named virtual network references namespace scoped", func(t *testing.T) {
		ref := &corev1.LocalObjectReference{Name: "shared"}
		peer := networkRouteForOverlap("ns-1", "route-a", "10.96.0.0/16", earlier, ref)
		object := networkRouteForOverlap("ns-2", "route-b", "10.96.10.0/24", later, ref)
		if err := runNetworkRouteOverlapCheck(t, object, "", peer); err != nil {
			t.Fatalf("checkOverlap = %v, want nil: same-named refs in different namespaces are distinct virtual networks", err)
		}
	})

	t.Run("rejects an overlap on the same named reference in one namespace", func(t *testing.T) {
		ref := &corev1.LocalObjectReference{Name: "shared"}
		peer := networkRouteForOverlap("ns-1", "route-a", "10.96.0.0/16", earlier, ref)
		object := networkRouteForOverlap("ns-1", "route-b", "10.96.10.0/24", later, ref)
		err := runNetworkRouteOverlapCheck(t, object, "", peer)
		if err == nil || !strings.Contains(err.Error(), "overlaps earlier unprogrammed NetworkRoute") {
			t.Fatalf("checkOverlap = %v, want overlap rejection against ns-1/route-a", err)
		}
	})
}

// A programmed peer whose virtual-network claim is indeterminate cannot prove
// same-network membership, but a known disjoint CIDR already proves no
// collision is possible. Fail-closed denials stay for peers whose network
// identity is missing, unparseable, or overlapping.
func TestNetworkRouteCheckOverlapIndeterminatePeerClaim(t *testing.T) {
	earlier := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	later := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)

	indeterminatePeer := func() *v1alpha1.NetworkRoute {
		peer := networkRouteForOverlap("ns-1", "route-broken", "10.0.0.0/24", earlier, &corev1.LocalObjectReference{Name: "vnet"})
		peer.Status.RouteID = "remote-route-1"
		peer.Status.Network = "10.0.0.0/24"
		return peer
	}

	t.Run("accepts a route disjoint from a peer with an indeterminate claim", func(t *testing.T) {
		object := networkRouteForOverlap("ns-2", "route-valid", "192.168.10.0/24", later, nil)
		if err := runNetworkRouteOverlapCheck(t, object, "", indeterminatePeer()); err != nil {
			t.Fatalf("checkOverlap = %v, want nil: disjoint peer cannot collide regardless of its virtual network", err)
		}
	})

	t.Run("rejects a route overlapping a peer with an indeterminate claim", func(t *testing.T) {
		object := networkRouteForOverlap("ns-2", "route-valid", "10.0.0.128/25", later, nil)
		err := runNetworkRouteOverlapCheck(t, object, "", indeterminatePeer())
		if err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("checkOverlap = %v, want fail-closed incomplete-claim rejection", err)
		}
	})

	t.Run("rejects when the peer has no recorded network identity", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-broken", "10.0.0.0/24", earlier, &corev1.LocalObjectReference{Name: "vnet"})
		peer.Status.RouteID = "remote-route-1"
		object := networkRouteForOverlap("ns-2", "route-valid", "192.168.10.0/24", later, nil)
		err := runNetworkRouteOverlapCheck(t, object, "", peer)
		if err == nil || !strings.Contains(err.Error(), "no recorded remote network identity") {
			t.Fatalf("checkOverlap = %v, want fail-closed missing-identity rejection", err)
		}
	})

	t.Run("rejects when the peer network is unparseable", func(t *testing.T) {
		peer := indeterminatePeer()
		peer.Status.Network = "not-a-cidr"
		object := networkRouteForOverlap("ns-2", "route-valid", "192.168.10.0/24", later, nil)
		err := runNetworkRouteOverlapCheck(t, object, "", peer)
		if err == nil || !strings.Contains(err.Error(), "invalid observed network") {
			t.Fatalf("checkOverlap = %v, want fail-closed invalid-network rejection", err)
		}
	})

	t.Run("accepts an overlap confined to a different virtual network", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-a", "10.0.0.0/24", earlier, &corev1.LocalObjectReference{Name: "vnet"})
		peer.Status.RouteID = "remote-route-1"
		peer.Status.Applied = v1alpha1.NetworkRouteAppliedStatus{Network: "10.0.0.0/24", VirtualNetworkID: "vnet-a"}
		object := networkRouteForOverlap("ns-2", "route-b", "10.0.0.128/25", later, &corev1.LocalObjectReference{Name: "vnet"})
		if err := runNetworkRouteOverlapCheck(t, object, "vnet-b", peer); err != nil {
			t.Fatalf("checkOverlap = %v, want nil: overlapping CIDRs in different virtual networks do not collide", err)
		}
	})

	t.Run("rejects an overlap in the same virtual network", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-a", "10.0.0.0/24", earlier, &corev1.LocalObjectReference{Name: "vnet"})
		peer.Status.RouteID = "remote-route-1"
		peer.Status.Applied = v1alpha1.NetworkRouteAppliedStatus{Network: "10.0.0.0/24", VirtualNetworkID: "vnet-a"}
		object := networkRouteForOverlap("ns-2", "route-b", "10.0.0.128/25", later, &corev1.LocalObjectReference{Name: "vnet"})
		err := runNetworkRouteOverlapCheck(t, object, "vnet-a", peer)
		if err == nil || !strings.Contains(err.Error(), "overlaps applied NetworkRoute") {
			t.Fatalf("checkOverlap = %v, want same-virtual-network overlap rejection", err)
		}
	})

	t.Run("rejects an overlap against observed identity when applied is absent", func(t *testing.T) {
		peer := networkRouteForOverlap("ns-1", "route-a", "10.0.0.0/24", earlier, &corev1.LocalObjectReference{Name: "vnet"})
		peer.Status.RouteID = "remote-route-1"
		peer.Status.Network = "10.0.0.0/24"
		peer.Status.VirtualNetworkID = "vnet-a"
		object := networkRouteForOverlap("ns-2", "route-b", "10.0.0.128/25", later, &corev1.LocalObjectReference{Name: "vnet"})
		err := runNetworkRouteOverlapCheck(t, object, "vnet-a", peer)
		if err == nil || !strings.Contains(err.Error(), "overlaps observed NetworkRoute") {
			t.Fatalf("checkOverlap = %v, want observed-identity overlap rejection", err)
		}
	})
}
