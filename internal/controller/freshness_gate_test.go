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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/freshness"
)

// The freshness gate is the whole point of the reduction, and every way it can
// fail is silent: the build, the linter, and the rest of the suite stay green
// while a converged object keeps reading Cloudflare on every pass. This test
// exercises the contract end to end on one representative controller.
//
// It exists because the gate shipped broken once. Every reconciler assigned the
// stamp to the object before calling a status helper that captured its merge
// base from that same object, so the patch carried no change, the stamp was
// never stored, and the gate never opened. Nothing failed; the saving was
// simply zero. Only counting remote calls across passes catches that.
func TestFreshnessGateSuppressesSteadyStateReads(t *testing.T) {
	ctx := context.Background()
	vnet := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock)
	kube, scheme := virtualNetworkWriterClient(t, vnet)
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

	remoteCalls := func(t *testing.T, label string) []string {
		t.Helper()
		before := len(api.calls)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.calls[before:]
	}

	// The first pass creates the remote object and must persist the stamp; a
	// stamp that stays empty is the failure this test was written for.
	if calls := remoteCalls(t, "create"); len(calls) == 0 {
		t.Fatal("first pass made no remote calls, so the fixture never converged")
	}
	var stored v1alpha1.VirtualNetwork
	if err := kube.Get(ctx, key, &stored); err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if stored.Status.AppliedHash == "" || stored.Status.AppliedAt == nil {
		t.Fatalf("gate stamp was not stored: appliedHash=%q appliedAt=%v",
			stored.Status.AppliedHash, stored.Status.AppliedAt)
	}

	// The create pass hashed a desired state that had no remote ID yet, so the
	// stored stamp only settles once the bound ID is part of it.
	now = now.Add(10 * time.Second)
	remoteCalls(t, "rebind")

	now = now.Add(10 * time.Second)
	if calls := remoteCalls(t, "steady"); len(calls) != 0 {
		t.Fatalf("converged pass still read the remote: %v", calls)
	}

	// Drift found by the sweep must reopen the gate immediately, otherwise the
	// sweep can detect drift it can never repair.
	latch.Invalidate("VirtualNetwork", key, "sweep found drift")
	if calls := remoteCalls(t, "invalidated"); len(calls) == 0 {
		t.Fatal("invalidated gate stayed shut, so sweep-detected drift is unrepairable")
	}

	// Past the TTL the object re-reads on its own, which is the only drift
	// backstop for kinds the sweep cannot list.
	now = now.Add(policy.TTL(freshness.GradeTraffic) + time.Second)
	if calls := remoteCalls(t, "expired"); len(calls) == 0 {
		t.Fatal("expired gate stayed shut, so out-of-band drift would never be re-read")
	}

	// Zeroing the policy is the documented rollback and must restore the
	// pre-gate behaviour rather than leaving the object gated or unreconciled.
	reconciler.Freshness = freshness.Policy{}
	now = now.Add(time.Second)
	if calls := remoteCalls(t, "rollback"); len(calls) == 0 {
		t.Fatal("zero policy still gated reads, so --freshness-*=0 does not roll back")
	}
}

// applyGateStamp decides whether a gated kind can persist its stamp at all. A
// kind missing from it reaches persistGateStamp, writes nothing, and loses its
// saving with no symptom, so the miss must surface as an error.
func TestApplyGateStampRejectsUngatedKind(t *testing.T) {
	stamp := newGateStamp("hash", virtualNetworkTestClock)

	vnet := &v1alpha1.VirtualNetwork{}
	if !applyGateStamp(vnet, stamp) {
		t.Fatal("applyGateStamp rejected a gated kind")
	}
	if vnet.Status.AppliedHash != "hash" || vnet.Status.AppliedAt == nil {
		t.Fatalf("stamp not applied: %+v", vnet.Status)
	}

	if applyGateStamp(&v1alpha1.CloudflareAccount{}, stamp) {
		t.Fatal("applyGateStamp accepted a kind that carries no gate stamp fields")
	}
}
