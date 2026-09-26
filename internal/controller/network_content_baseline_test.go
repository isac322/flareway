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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// These tests pin the PR-B contract for the private-network kinds: after a
// converged pass registers a content baseline, a sweep listing that still
// matches it keeps the gate open across TTL boundaries so the object never
// reads Cloudflare itself, and a listing that no longer matches is reported
// as drift so the object re-verifies (and repairs) on its next pass. The
// ConfirmContent call stands in for the sweep's classify hook, which passes
// the listed remote object verbatim.

func networkBaselineScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add flareway v1alpha1 to scheme: %v", err)
	}
	return scheme
}

// networkBaselineAccount grants every gate the private-network controllers
// activate: platform objects on the object's own namespace plus private
// exposure and route selectors on the (same-namespace) tunnel.
func networkBaselineAccount() *v1alpha1.CloudflareAccount {
	return &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"}, Zones: []string{"*"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
				PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
					NetworkRouteSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
					HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
				},
				PlatformObjects: v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)},
		}},
	}
}

func networkBaselineKube(t *testing.T, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := networkBaselineScheme(t)
	seed := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
		networkBaselineAccount(),
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(
			&v1alpha1.VirtualNetwork{}, &v1alpha1.NetworkRoute{},
			&v1alpha1.HostnameRoute{}, &v1alpha1.ZeroTrustGatewayPolicy{},
		).
		WithObjects(append(seed, objects...)...).
		Build()
	return kube, scheme
}

// networkBaselineTunnel is the tunnel the route fixtures resolve: already
// Accepted and ownership-verified so the routes can program immediately.
func networkBaselineTunnel() *v1alpha1.CloudflareTunnel {
	return &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "edge"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:          "tunnel-1",
			OwnershipVerified: true,
			Conditions:        []metav1.Condition{{Type: v1alpha1.CloudflareTunnelConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(virtualNetworkTestClock)}},
		},
	}
}

func networkBaselineNetworkRoute(name, network string) *v1alpha1.NetworkRoute {
	return &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: name, UID: types.UID("nr-" + name),
			CreationTimestamp: metav1.NewTime(virtualNetworkTestClock),
			Finalizers:        []string{v1alpha1.NetworkRouteFinalizer},
			Labels:            map[string]string{"private-route": "allowed"},
		},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Network:          network,
			TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: "edge", Namespace: "tenant"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
}

func networkBaselineHostnameRoute(name, hostname string) *v1alpha1.HostnameRoute {
	return &v1alpha1.HostnameRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: name, UID: types.UID("hr-" + name),
			CreationTimestamp: metav1.NewTime(virtualNetworkTestClock),
			Finalizers:        []string{v1alpha1.HostnameRouteFinalizer},
			Labels:            map[string]string{"private-route": "allowed"},
		},
		Spec: v1alpha1.HostnameRouteSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Hostname:         hostname,
			TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: "edge", Namespace: "tenant"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
}

func networkBaselineRemoteVirtualNetwork(api *fakePrivateNetworkCloudflare, id string) flarecloudflare.VirtualNetwork {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.virtualNetworks[id]
}

func networkBaselineRemoteNetworkRoute(api *fakePrivateNetworkCloudflare, id string) flarecloudflare.NetworkRoute {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.networkRoutes[id]
}

func networkBaselineRemoteHostnameRoute(api *fakePrivateNetworkCloudflare, id string) flarecloudflare.HostnameRoute {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.hostnameRoutes[id]
}

// A sweep confirmation of the remote a converged pass just verified must
// hold the gate open after the verify TTL expires, and the same listing with
// a compared field changed must come back as drift.
func TestVirtualNetworkContentBaselineKeepsGateOpen(t *testing.T) {
	ctx := context.Background()
	vnet := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock)
	kube, scheme := networkBaselineKube(t, vnet)
	api := newFakePrivateNetworkCloudflare()

	now := virtualNetworkTestClock
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	reconciler := &VirtualNetworkReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   policy,
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(vnet)
	pass := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}
	stored := func(t *testing.T) v1alpha1.VirtualNetwork {
		t.Helper()
		var current v1alpha1.VirtualNetwork
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get VirtualNetwork: %v", err)
		}
		return current
	}

	pass(t, "create")
	now = now.Add(10 * time.Second)
	pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	// Without a sweep confirmation an expired gate re-verifies on its own;
	// that pass registers the baseline the sweep confirms below.
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut without a sweep confirmation")
	}

	// A sweep pass now lists what the reconciler last verified and reports
	// it unchanged, so the next TTL expiry opens the gate instead of reading.
	remote := networkBaselineRemoteVirtualNetwork(api, converged.Status.VirtualNetworkID)
	if remote.ID == "" {
		t.Fatal("fixture created no remote virtual network")
	}
	if latch.ConfirmContent("VirtualNetwork", key, remote, now) {
		t.Fatal("the sweep's own listing was reported as drift")
	}
	if _, ok := latch.ConfirmedAt("VirtualNetwork", key, converged.Status.AppliedHash); !ok {
		t.Fatal("the confirmation was not recorded for the converged hash")
	}
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "confirmed"); len(calls) != 0 {
		t.Fatalf("sweep-confirmed pass still read the remote: %v", calls)
	}

	// The same listing with a compared field changed out of band is drift:
	// the invalidation the sweep then raises must re-open verification.
	remote.IsDefault = !remote.IsDefault
	api.putVirtualNetwork(remote)
	if !latch.ConfirmContent("VirtualNetwork", key, remote, now) {
		t.Fatal("an out-of-band change to a compared field was not reported as drift")
	}
	latch.Invalidate("VirtualNetwork", key, "sweep found drift")
	if calls := pass(t, "drifted"); len(calls) == 0 {
		t.Fatal("drifted object did not re-verify")
	}
}

// NetworkRoute registers a baseline only while spec.ipLookup is unset: the
// route itself is fully visible in the listing, but the lookup answer is a
// separate remote read.
func TestNetworkRouteContentBaselineKeepsGateOpen(t *testing.T) {
	ctx := context.Background()
	route := networkBaselineNetworkRoute("services", "10.96.0.0/12")
	kube, scheme := networkBaselineKube(t, networkBaselineTunnel(), route)
	api := newFakePrivateNetworkCloudflare()

	now := virtualNetworkTestClock
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	reconciler := &NetworkRouteReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   policy,
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(route)
	pass := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}
	stored := func(t *testing.T) v1alpha1.NetworkRoute {
		t.Helper()
		var current v1alpha1.NetworkRoute
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get NetworkRoute: %v", err)
		}
		return current
	}

	pass(t, "create")
	now = now.Add(10 * time.Second)
	pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut without a sweep confirmation")
	}

	remote := networkBaselineRemoteNetworkRoute(api, converged.Status.RouteID)
	if remote.ID == "" {
		t.Fatal("fixture created no remote network route")
	}
	if latch.ConfirmContent("NetworkRoute", key, remote, now) {
		t.Fatal("the sweep's own listing was reported as drift")
	}
	if _, ok := latch.ConfirmedAt("NetworkRoute", key, converged.Status.AppliedHash); !ok {
		t.Fatal("the confirmation was not recorded for the converged hash")
	}
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "confirmed"); len(calls) != 0 {
		t.Fatalf("sweep-confirmed pass still read the remote: %v", calls)
	}

	remote.TunnelID = "tunnel-drifted"
	api.putNetworkRoute(remote)
	if !latch.ConfirmContent("NetworkRoute", key, remote, now) {
		t.Fatal("an out-of-band change to a compared field was not reported as drift")
	}
	latch.Invalidate("NetworkRoute", key, "sweep found drift")
	if calls := pass(t, "drifted"); len(calls) == 0 {
		t.Fatal("drifted object did not re-verify")
	}
}

// An ipLookup route's verify reads LookupNetworkRoute, which the listed
// route cannot show, so it registers no baseline and keeps its own verify.
func TestNetworkRouteIPLookupRegistersNoBaseline(t *testing.T) {
	ctx := context.Background()
	route := networkBaselineNetworkRoute("lookup", "10.96.0.0/12")
	route.Spec.IPLookup = &v1alpha1.NetworkRouteIPLookupSpec{IP: "10.96.1.7"}
	kube, scheme := networkBaselineKube(t, networkBaselineTunnel(), route)
	api := newFakePrivateNetworkCloudflare()

	now := virtualNetworkTestClock
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	reconciler := &NetworkRouteReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   policy,
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(route)
	pass := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}
	stored := func(t *testing.T) v1alpha1.NetworkRoute {
		t.Helper()
		var current v1alpha1.NetworkRoute
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get NetworkRoute: %v", err)
		}
		return current
	}

	pass(t, "create")
	now = now.Add(10 * time.Second)
	pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}
	if converged.Status.IPLookup == nil || converged.Status.IPLookup.Result == nil {
		t.Fatalf("ipLookup status was not recorded: %+v", converged.Status)
	}

	remote := networkBaselineRemoteNetworkRoute(api, converged.Status.RouteID)
	if remote.ID == "" {
		t.Fatal("fixture created no remote network route")
	}
	// Without a baseline the sweep's listing neither confirms nor drifts the
	// object, and the expired gate re-reads the remote on its own.
	if latch.ConfirmContent("NetworkRoute", key, remote, now) {
		t.Fatal("a route with no baseline was reported as drifted")
	}
	if _, ok := latch.ConfirmedAt("NetworkRoute", key, converged.Status.AppliedHash); ok {
		t.Fatal("an ipLookup route recorded a sweep confirmation")
	}
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut without a sweep confirmation")
	}
}

func TestHostnameRouteContentBaselineKeepsGateOpen(t *testing.T) {
	ctx := context.Background()
	route := networkBaselineHostnameRoute("app", "app.example.internal")
	kube, scheme := networkBaselineKube(t, networkBaselineTunnel(), route)
	api := newFakePrivateNetworkCloudflare()

	now := virtualNetworkTestClock
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	reconciler := &HostnameRouteReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   policy,
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(route)
	pass := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}
	stored := func(t *testing.T) v1alpha1.HostnameRoute {
		t.Helper()
		var current v1alpha1.HostnameRoute
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get HostnameRoute: %v", err)
		}
		return current
	}

	pass(t, "create")
	now = now.Add(10 * time.Second)
	pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut without a sweep confirmation")
	}

	remote := networkBaselineRemoteHostnameRoute(api, converged.Status.RouteID)
	if remote.ID == "" {
		t.Fatal("fixture created no remote hostname route")
	}
	if latch.ConfirmContent("HostnameRoute", key, remote, now) {
		t.Fatal("the sweep's own listing was reported as drift")
	}
	if _, ok := latch.ConfirmedAt("HostnameRoute", key, converged.Status.AppliedHash); !ok {
		t.Fatal("the confirmation was not recorded for the converged hash")
	}
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "confirmed"); len(calls) != 0 {
		t.Fatalf("sweep-confirmed pass still read the remote: %v", calls)
	}

	remote.Hostname = "other.example.internal"
	api.putHostnameRoute(remote)
	if !latch.ConfirmContent("HostnameRoute", key, remote, now) {
		t.Fatal("an out-of-band change to a compared field was not reported as drift")
	}
	latch.Invalidate("HostnameRoute", key, "sweep found drift")
	if calls := pass(t, "drifted"); len(calls) == 0 {
		t.Fatal("drifted object did not re-verify")
	}
}

func TestZeroTrustGatewayPolicyContentBaselineKeepsGateOpen(t *testing.T) {
	ctx := context.Background()
	enabled := true
	policy := &v1alpha1.ZeroTrustGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "allow-egress", UID: types.UID("gp-allow-egress"),
			CreationTimestamp: metav1.NewTime(virtualNetworkTestClock),
			Finalizers:        []string{v1alpha1.ZeroTrustGatewayPolicyFinalizer},
		},
		Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Name:             "allow-egress",
			Enabled:          &enabled,
			Filters:          []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterL4},
			Action:           v1alpha1.ZeroTrustGatewayAction("allow"),
			Traffic:          "net.dst.ip == 198.51.100.0/24",
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	kube, scheme := networkBaselineKube(t, policy)
	api := newFakeGlobalGatewayCloudflare()

	now := virtualNetworkTestClock
	latch := freshness.NewLatch()
	freshnessPolicy := freshness.DefaultPolicy()
	reconciler := &ZeroTrustGatewayPolicyReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   freshnessPolicy,
		Invalidator: latch,
	}
	key := client.ObjectKeyFromObject(policy)
	pass := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}
	stored := func(t *testing.T) v1alpha1.ZeroTrustGatewayPolicy {
		t.Helper()
		var current v1alpha1.ZeroTrustGatewayPolicy
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatalf("get ZeroTrustGatewayPolicy: %v", err)
		}
		return current
	}

	pass(t, "create")
	now = now.Add(10 * time.Second)
	pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}

	now = now.Add(freshnessPolicy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut without a sweep confirmation")
	}

	remote, found := api.rule(converged.Status.RuleID)
	if !found {
		t.Fatal("fixture created no remote Gateway rule")
	}
	if latch.ConfirmContent("ZeroTrustGatewayPolicy", key, remote, now) {
		t.Fatal("the sweep's own listing was reported as drift")
	}
	if _, ok := latch.ConfirmedAt("ZeroTrustGatewayPolicy", key, converged.Status.AppliedHash); !ok {
		t.Fatal("the confirmation was not recorded for the converged hash")
	}
	now = now.Add(freshnessPolicy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := pass(t, "confirmed"); len(calls) != 0 {
		t.Fatalf("sweep-confirmed pass still read the remote: %v", calls)
	}

	remote.Traffic = "net.dst.ip == 203.0.113.0/24"
	api.putRule(remote)
	if !latch.ConfirmContent("ZeroTrustGatewayPolicy", key, remote, now) {
		t.Fatal("an out-of-band change to a compared field was not reported as drift")
	}
	latch.Invalidate("ZeroTrustGatewayPolicy", key, "sweep found drift")
	if calls := pass(t, "drifted"); len(calls) == 0 {
		t.Fatal("drifted object did not re-verify")
	}
}
