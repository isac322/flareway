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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// racingRouteAPI simulates another writer that changes a route between the
// controller's update and the update's read-back, while racing is set.
type racingRouteAPI struct {
	*fakePrivateNetworkCloudflare
	racing bool
}

func (a *racingRouteAPI) Client(_, _ string) (flarecloudflare.NetworkAPI, error) { return a, nil }

func (a *racingRouteAPI) UpdateNetworkRoute(ctx context.Context, id string, input flarecloudflare.NetworkRouteInput) (flarecloudflare.NetworkRoute, error) {
	updated, err := a.fakePrivateNetworkCloudflare.UpdateNetworkRoute(ctx, id, input)
	if err != nil || !a.racing {
		return updated, err
	}
	updated.Network = "10.201.0.0/24"
	a.putNetworkRoute(updated)
	return a.GetNetworkRoute(ctx, id)
}

func (a *racingRouteAPI) UpdateHostnameRoute(ctx context.Context, id string, input flarecloudflare.HostnameRouteInput) (flarecloudflare.HostnameRoute, error) {
	updated, err := a.fakePrivateNetworkCloudflare.UpdateHostnameRoute(ctx, id, input)
	if err != nil || !a.racing {
		return updated, err
	}
	updated.TunnelID = "tunnel-other"
	a.putHostnameRoute(updated)
	return a.GetHostnameRoute(ctx, id)
}

// A drift repair whose read-back shows another writer's value must not record
// that value as applied or report the route Ready; the next pass repairs it.
func TestNetworkRouteConcurrentWriteIsNotRecordedAsApplied(t *testing.T) {
	ctx := context.Background()
	route := networkBaselineNetworkRoute("services", "10.96.0.0/12")
	kube, scheme := networkBaselineKube(t, networkBaselineTunnel(), route)
	api := &racingRouteAPI{fakePrivateNetworkCloudflare: newFakePrivateNetworkCloudflare()}
	latch := freshness.NewLatch()
	reconciler := &NetworkRouteReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return virtualNetworkTestClock },
		Freshness:   freshness.DefaultPolicy(),
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(route)
	reconcile := func() error {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		return err
	}
	stored := func(t *testing.T) v1alpha1.NetworkRoute {
		t.Helper()
		var current v1alpha1.NetworkRoute
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get NetworkRoute: %v", err)
		}
		return current
	}

	for _, label := range []string{"create", "rebind"} {
		if err := reconcile(); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
	}
	converged := stored(t)
	if converged.Status.Applied.Network != "10.96.0.0/12" {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	drifted := networkBaselineRemoteNetworkRoute(api.fakePrivateNetworkCloudflare, converged.Status.RouteID)
	drifted.Network = "10.200.0.0/24"
	api.putNetworkRoute(drifted)
	latch.Invalidate("NetworkRoute", key, "drift")
	api.racing = true
	if err := reconcile(); err == nil {
		t.Fatal("a repair whose read-back differs from the write reported success")
	}
	raced := stored(t)
	if raced.Status.Applied.Network != "10.96.0.0/12" {
		t.Fatalf("status.applied.network = %q, want the last applied 10.96.0.0/12", raced.Status.Applied.Network)
	}
	if meta.IsStatusConditionTrue(raced.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
		t.Fatal("route reported Ready while the remote differs from the spec")
	}

	api.racing = false
	if err := reconcile(); err != nil {
		t.Fatalf("repair reconcile: %v", err)
	}
	repaired := stored(t)
	remote := networkBaselineRemoteNetworkRoute(api.fakePrivateNetworkCloudflare, repaired.Status.RouteID)
	if remote.Network != "10.96.0.0/12" || repaired.Status.Applied.Network != "10.96.0.0/12" ||
		!meta.IsStatusConditionTrue(repaired.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
		t.Fatalf("route did not converge after the race: remote=%+v status=%+v", remote, repaired.Status)
	}
}

func TestHostnameRouteConcurrentWriteIsNotRecordedAsApplied(t *testing.T) {
	ctx := context.Background()
	route := networkBaselineHostnameRoute("app", "app.example.internal")
	kube, scheme := networkBaselineKube(t, networkBaselineTunnel(), route)
	api := &racingRouteAPI{fakePrivateNetworkCloudflare: newFakePrivateNetworkCloudflare()}
	latch := freshness.NewLatch()
	reconciler := &HostnameRouteReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return virtualNetworkTestClock },
		Freshness:   freshness.DefaultPolicy(),
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(route)
	reconcile := func() error {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		return err
	}
	stored := func(t *testing.T) v1alpha1.HostnameRoute {
		t.Helper()
		var current v1alpha1.HostnameRoute
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get HostnameRoute: %v", err)
		}
		return current
	}

	for _, label := range []string{"create", "rebind"} {
		if err := reconcile(); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
	}
	converged := stored(t)
	if converged.Status.Applied.TunnelID != "tunnel-1" {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	drifted := networkBaselineRemoteHostnameRoute(api.fakePrivateNetworkCloudflare, converged.Status.RouteID)
	drifted.TunnelID = "tunnel-drifted"
	api.putHostnameRoute(drifted)
	latch.Invalidate("HostnameRoute", key, "drift")
	api.racing = true
	if err := reconcile(); err == nil {
		t.Fatal("a repair whose read-back differs from the write reported success")
	}
	raced := stored(t)
	if raced.Status.Applied.TunnelID != "tunnel-1" {
		t.Fatalf("status.applied.tunnelId = %q, want the last applied tunnel-1", raced.Status.Applied.TunnelID)
	}
	if meta.IsStatusConditionTrue(raced.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
		t.Fatal("route reported Ready while the remote differs from the spec")
	}

	api.racing = false
	if err := reconcile(); err != nil {
		t.Fatalf("repair reconcile: %v", err)
	}
	repaired := stored(t)
	remote := networkBaselineRemoteHostnameRoute(api.fakePrivateNetworkCloudflare, repaired.Status.RouteID)
	if remote.TunnelID != "tunnel-1" || repaired.Status.Applied.TunnelID != "tunnel-1" ||
		!meta.IsStatusConditionTrue(repaired.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
		t.Fatalf("route did not converge after the race: remote=%+v status=%+v", remote, repaired.Status)
	}
}
