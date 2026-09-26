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
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
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

// The gate is wired per controller, so proving it on one kind proves only that
// kind. IdentityProvider is the other shape worth pinning: its status helper
// returns early when the status it just built equals the one it started from,
// which is exactly the path that used to swallow the stamp.
func TestFreshnessGateSuppressesSteadyStateReadsForIdentityProvider(t *testing.T) {
	ctx := context.Background()
	api := &identityProviderFakeAPI{providers: map[string]flarecloudflare.IdentityProvider{}}
	now := virtualNetworkTestClock
	world := newIdentityProviderWorld(t, api, now, v1alpha1.ManagementPolicyManaged, "")
	world.reconciler.Now = func() time.Time { return now }
	world.reconciler.Freshness = freshness.DefaultPolicy()
	world.reconciler.Invalidator = freshness.NewLatch()

	reads := func(t *testing.T, label string) int {
		t.Helper()
		before := api.gets
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return api.gets - before
	}

	reads(t, "create")
	var stored v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &stored); err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if stored.Status.AppliedHash == "" || stored.Status.AppliedAt == nil {
		t.Fatalf("gate stamp was not stored: appliedHash=%q appliedAt=%v",
			stored.Status.AppliedHash, stored.Status.AppliedAt)
	}

	now = now.Add(5 * time.Second)
	reads(t, "rebind")

	now = now.Add(5 * time.Second)
	if got := reads(t, "steady"); got != 0 {
		t.Fatalf("converged pass issued %d remote reads", got)
	}
}

// statusWriteCounter counts status patches and updates that change the stored
// object. An empty merge patch reaches the API server but changes nothing, so
// it produces no watch event and is not counted.
type statusWriteCounter struct {
	writes int
}

func (c *statusWriteCounter) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, kube client.Client, sub string, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
			if data, err := patch.Data(object); err != nil || string(data) != "{}" {
				c.writes++
			}
			return kube.SubResource(sub).Patch(ctx, object, patch, options...)
		},
		SubResourceUpdate: func(ctx context.Context, kube client.Client, sub string, object client.Object, options ...client.SubResourceUpdateOption) error {
			c.writes++
			return kube.SubResource(sub).Update(ctx, object, options...)
		},
	}
}

// A converged object whose re-verify finds nothing to change must not write
// status. Every rewrite of appliedAt is a watch event that other controllers
// react to, and the field documents when the hash was recorded, not when the
// remote was last read. The gate must still open between re-verifies, which
// only works if the verify time is kept somewhere other than status.
func TestFreshnessGateReverifyWithoutChangeWritesNoStatus(t *testing.T) {
	ctx := context.Background()
	vnet := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock)
	scheme := virtualNetworkTestScheme(t)
	counter := &statusWriteCounter{}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.VirtualNetwork{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("value")}},
			virtualNetworkTestAccount(),
			vnet,
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	api := newFakePrivateNetworkCloudflare()
	now := virtualNetworkTestClock
	reconciler := &VirtualNetworkReconciler{
		Client: kube, Scheme: scheme, NewCloudflareClient: api.Client,
		Now:         func() time.Time { return now },
		Freshness:   freshness.DefaultPolicy(),
		Invalidator: freshness.NewLatch(),
	}
	key := client.ObjectKeyFromObject(vnet)
	pass := func(t *testing.T, label string) (int, ctrl.Result) {
		t.Helper()
		before := len(api.calls)
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("%s reconcile: %v", label, err)
		}
		return len(api.calls) - before, result
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
	_, result := pass(t, "rebind")
	converged := stored(t)
	if converged.Status.AppliedHash == "" || converged.Status.AppliedAt == nil {
		t.Fatalf("fixture never converged: %+v", converged.Status)
	}
	counter.writes = 0

	// Follow the reconciler's own requeue across several TTLs. Each wake-up
	// re-verifies the remote, finds it unchanged, and must leave status alone.
	for cycle := range 3 {
		now = now.Add(result.RequeueAfter)
		var calls int
		calls, result = pass(t, "re-verify")
		if calls == 0 {
			t.Fatalf("cycle %d: expired gate did not re-verify the remote", cycle)
		}
		if result.RequeueAfter <= 0 {
			t.Fatalf("cycle %d: converged object stopped requeueing", cycle)
		}
	}
	if counter.writes != 0 {
		t.Fatalf("unchanged re-verifies wrote status %d times", counter.writes)
	}
	if got := stored(t).Status.AppliedAt; !got.Equal(converged.Status.AppliedAt) {
		t.Fatalf("appliedAt moved from %v to %v although appliedHash did not change", converged.Status.AppliedAt, got)
	}

	// Between re-verifies the gate still opens: the verify time is anchored in
	// memory rather than in status.
	now = now.Add(10 * time.Second)
	if calls, _ := pass(t, "between re-verifies"); calls != 0 {
		t.Fatalf("gate stayed closed after an unchanged re-verify: %d remote calls", calls)
	}

	// A restart loses the in-memory record. The stored appliedAt is older than
	// the TTL, so the first pass must read the remote rather than trust it.
	reconciler.Invalidator = freshness.NewLatch()
	now = now.Add(10 * time.Second)
	if calls, _ := pass(t, "after restart"); calls == 0 {
		t.Fatal("first pass after a restart trusted a stale appliedAt")
	}
	if counter.writes != 0 {
		t.Fatalf("post-restart re-verify wrote status %d times", counter.writes)
	}

	// A spec change records a new hash, and appliedAt moves with it.
	current := stored(t)
	current.Spec.Comment = "changed"
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	now = now.Add(time.Second)
	pass(t, "spec change")
	changed := stored(t)
	if changed.Status.AppliedHash == converged.Status.AppliedHash {
		t.Fatal("spec change did not record a new applied hash")
	}
	if changed.Status.AppliedAt == nil || !changed.Status.AppliedAt.Time.Equal(now) {
		t.Fatalf("appliedAt = %v, want the time the new hash was recorded (%v)", changed.Status.AppliedAt, now)
	}
}

// failingVirtualNetworkAPI fails remote updates on demand, so a pass can go to
// Cloudflare for a new desired state and not converge.
type failingVirtualNetworkAPI struct {
	*fakePrivateNetworkCloudflare
	failUpdates bool
}

func (f *failingVirtualNetworkAPI) UpdateVirtualNetwork(ctx context.Context, id string, input flarecloudflare.VirtualNetworkInput) (flarecloudflare.VirtualNetwork, error) {
	if f.failUpdates {
		return flarecloudflare.VirtualNetwork{}, errors.New("injected update failure")
	}
	return f.fakePrivateNetworkCloudflare.UpdateVirtualNetwork(ctx, id, input)
}

// gatedVirtualNetworkWorld is a converged VirtualNetwork whose latest verify
// lives only in memory: status.appliedAt is older than the TTL.
func gatedVirtualNetworkWorld(t *testing.T) (*VirtualNetworkReconciler, *failingVirtualNetworkAPI, client.Client, types.NamespacedName, *time.Time) {
	t.Helper()
	vnet := virtualNetworkFixture("tenant", "prod", virtualNetworkTestClock)
	kube, scheme := virtualNetworkWriterClient(t, vnet)
	api := &failingVirtualNetworkAPI{fakePrivateNetworkCloudflare: newFakePrivateNetworkCloudflare()}
	now := virtualNetworkTestClock
	reconciler := &VirtualNetworkReconciler{
		Client: kube, Scheme: scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.NetworkAPI, error) { return api, nil },
		Now:                 func() time.Time { return now },
		Freshness:           freshness.DefaultPolicy(),
		Invalidator:         freshness.NewLatch(),
	}
	key := client.ObjectKeyFromObject(vnet)
	for _, step := range []time.Duration{0, 10 * time.Second, reconciler.Freshness.TTL(freshness.GradeTraffic) + time.Second} {
		now = now.Add(step)
		if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("converge: %v", err)
		}
	}
	return reconciler, api, kube, key, &now
}

// A pass that goes to Cloudflare for a new desired state and fails must void
// the earlier verify. If the spec then changes back, the old in-memory record
// must not re-open the gate and hide the failed state behind a skipped pass.
func TestFreshnessGateRevertAfterFailedPassReadsAgain(t *testing.T) {
	ctx := context.Background()
	reconciler, api, kube, key, now := gatedVirtualNetworkWorld(t)
	pass := func() (int, error) {
		before := len(api.calls)
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		return len(api.calls) - before, err
	}
	setComment := func(comment string) {
		var current v1alpha1.VirtualNetwork
		if err := kube.Get(ctx, key, &current); err != nil {
			t.Fatal(err)
		}
		current.Spec.Comment = comment
		if err := kube.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(10 * time.Second)
	if calls, err := pass(); err != nil || calls != 0 {
		t.Fatalf("fixture gate is not open from its in-memory verify: calls=%d err=%v", calls, err)
	}

	api.failUpdates = true
	setComment("changed")
	*now = now.Add(time.Second)
	if _, err := pass(); err == nil {
		t.Fatal("the injected update failure did not fail the pass")
	}

	api.failUpdates = false
	setComment("")
	*now = now.Add(time.Second)
	if calls, err := pass(); err != nil || calls == 0 {
		t.Fatalf("after a failed pass, reverting the spec re-opened the gate on the old verify: calls=%d err=%v", calls, err)
	}
}

// A deleted object must not keep freshness records for the life of the
// process; the latch would otherwise grow with every object ever created.
func TestDeletedObjectReleasesFreshnessRecords(t *testing.T) {
	ctx := context.Background()
	reconciler, _, kube, key, now := gatedVirtualNetworkWorld(t)
	var stored v1alpha1.VirtualNetwork
	if err := kube.Get(ctx, key, &stored); err != nil {
		t.Fatal(err)
	}
	if _, ok := reconciler.Invalidator.VerifiedAt("VirtualNetwork", key, stored.Status.AppliedHash); !ok {
		t.Fatal("fixture recorded no verify")
	}
	reconciler.Invalidator.Invalidate("VirtualNetwork", key, "drift")

	stored.Finalizers = nil
	if err := kube.Update(ctx, &stored); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &stored); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile of a deleted object: %v", err)
	}
	if _, ok := reconciler.Invalidator.VerifiedAt("VirtualNetwork", key, stored.Status.AppliedHash); ok {
		t.Fatal("a deleted object kept its verify record")
	}
	if reconciler.Invalidator.IsInvalidated("VirtualNetwork", key) {
		t.Fatal("a deleted object kept its invalidation")
	}
}

// The in-memory verify record may only extend the gate for the exact desired
// state it verified, and never past what the policy and latch allow.
func TestEvaluateGateInMemoryVerification(t *testing.T) {
	key := types.NamespacedName{Namespace: "tenant", Name: "prod"}
	policy := freshness.DefaultPolicy()
	ttl := policy.TTL(freshness.GradeTraffic)
	now := virtualNetworkTestClock
	stale := metav1.NewTime(now.Add(-2 * ttl))
	evaluate := func(latch *freshness.Latch, policy freshness.Policy, desired string) freshness.Gate {
		return evaluateGateWithHash(policy, latch, freshness.GradeTraffic, "VirtualNetwork", key, "applied", desired, &stale, now).Gate
	}

	latch := freshness.NewLatch()
	latch.MarkVerified("VirtualNetwork", key, "applied", now.Add(-time.Minute))
	if gate := evaluate(latch, policy, "applied"); !gate.Open || gate.Requeue != ttl-time.Minute {
		t.Fatalf("recent verify of the applied hash did not open the gate: %+v", gate)
	}
	if gate := evaluate(latch, policy, "changed"); gate.Open {
		t.Fatal("verify of an older desired state opened the gate for a new one")
	}

	superseded := freshness.NewLatch()
	superseded.MarkVerified("VirtualNetwork", key, "superseded", now.Add(-time.Minute))
	if gate := evaluate(superseded, policy, "applied"); gate.Open {
		t.Fatal("verify recorded for a different hash opened the gate")
	}

	latch.Invalidate("VirtualNetwork", key, "sweep found drift")
	if gate := evaluate(latch, policy, "applied"); gate.Open || gate.Decision != freshness.DecisionClosedInvalidated {
		t.Fatalf("invalidation did not take precedence over the verify record: %+v", gate)
	}
	// Drift found after the verify voids it: releasing the invalidation
	// without a new verify must not re-open the gate on the old record.
	latch.Clear("VirtualNetwork", key)
	if gate := evaluate(latch, policy, "applied"); gate.Open {
		t.Fatal("a verify recorded before the drift re-opened the gate")
	}

	future := freshness.NewLatch()
	future.MarkVerified("VirtualNetwork", key, "applied", now.Add(time.Minute))
	if gate := evaluate(future, policy, "applied"); gate.Open {
		t.Fatal("a verify time in the future was trusted")
	}

	recent := freshness.NewLatch()
	recent.MarkVerified("VirtualNetwork", key, "applied", now.Add(-time.Minute))
	if gate := evaluate(recent, freshness.Policy{}, "applied"); gate.Open {
		t.Fatal("zero policy was bypassed by the verify record")
	}
}

// A sweep confirmation keeps the gate open past the TTL, up to the
// confirmation window. Once a pass has gone to the remote for another desired
// state, the old confirmation must not re-open the gate when the desired state
// changes back: that pass may have left status describing a failure, and only
// a new converged pass may bring it back in line.
func TestEvaluateGateSweepConfirmation(t *testing.T) {
	key := types.NamespacedName{Namespace: "tenant", Name: "app"}
	policy := freshness.DefaultPolicy()
	ttl := policy.TTL(freshness.GradeAuthz)
	now := virtualNetworkTestClock
	stale := metav1.NewTime(now.Add(-3 * ttl))
	evaluate := func(latch *freshness.Latch, desired string, at time.Time) freshness.Gate {
		return evaluateGateWithHash(policy, latch, freshness.GradeAuthz, "AccessApplication", key, "h1", desired, &stale, at).Gate
	}
	confirmed := func() *freshness.Latch {
		latch := freshness.NewLatch()
		latch.SetBaseline("AccessApplication", key, "h1", func(any) bool { return true })
		latch.ConfirmContent("AccessApplication", key, "listed", now.Add(-ttl-time.Second))
		return latch
	}

	latch := confirmed()
	if gate := evaluate(latch, "h1", now); !gate.Open || gate.Requeue != ttl-time.Second {
		t.Fatalf("gate past the TTL but inside the confirmation window = %+v, want open until the window ends", gate)
	}
	if gate := evaluate(latch, "h1", now.Add(ttl)); gate.Open {
		t.Fatal("a confirmation older than two TTLs kept the gate open")
	}

	latch = confirmed()
	if gate := evaluate(latch, "h2", now); gate.Open {
		t.Fatal("a confirmation of h1 opened the gate for h2")
	}
	if gate := evaluate(latch, "h1", now); gate.Open {
		t.Fatal("after a pass went to the remote for h2, the old confirmation of h1 re-opened the gate")
	}
}

// gateStampFields decides whether a gated kind can persist its stamp at all,
// and under which latch kind its verify time is kept. A kind missing from it
// writes nothing and loses its saving with no symptom, and a kind name that
// differs from the gate's would record verifications the gate never reads.
func TestGateStampFieldsCoverEveryGatedKind(t *testing.T) {
	for _, object := range []client.Object{
		&v1alpha1.VirtualNetwork{}, &v1alpha1.NetworkRoute{}, &v1alpha1.HostnameRoute{},
		&v1alpha1.IdentityProvider{}, &v1alpha1.AccessGroup{}, &v1alpha1.AccessPolicy{},
		&v1alpha1.AccessCustomPage{}, &v1alpha1.AccessInfrastructureTarget{},
		&v1alpha1.AccessStandaloneApplication{}, &v1alpha1.AccessApplication{},
		&v1alpha1.DeviceSettings{}, &v1alpha1.DeviceProfile{}, &v1alpha1.DevicePostureRule{},
		&v1alpha1.DevicePostureIntegration{}, &v1alpha1.ServiceToken{}, &v1alpha1.WARPConnector{},
		&v1alpha1.ZeroTrustList{}, &v1alpha1.ZeroTrustGatewayPolicy{}, &v1alpha1.ZeroTrustOrganization{},
	} {
		kind, hash, at, ok := gateStampFields(object)
		if !ok || hash == nil || at == nil {
			t.Fatalf("%T has no gate stamp fields", object)
		}
		if _, graded := freshness.GradeForKind(kind); !graded {
			t.Fatalf("%T records verifications under %q, which has no freshness grade", object, kind)
		}
	}
	if _, _, _, ok := gateStampFields(&v1alpha1.CloudflareAccount{}); ok {
		t.Fatal("gateStampFields accepted a kind that carries no gate stamp fields")
	}
}
