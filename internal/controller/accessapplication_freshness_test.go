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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// accessFreshnessWorld is a Managed SelfHosted AccessApplication with two
// externalRef policies that converges to Programmed=True against the fake
// Cloudflare Access API. A Worker destination keeps the fixture free of
// Gateway and tunnel data-plane plumbing, which the gate does not depend on.
type accessFreshnessWorld struct {
	kube       client.Client
	remote     *fakeAccessApplicationCloudflare
	reconciler *AccessApplicationReconciler
	counter    *statusWriteCounter
	request    ctrl.Request
	now        time.Time
}

const (
	accessFreshnessPolicyA = "policy-external-a"
	accessFreshnessPolicyB = "policy-external-b"
)

func newAccessFreshnessWorld(t *testing.T, configure ...func(*v1alpha1.AccessApplication)) *accessFreshnessWorld {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	epoch := metav1.NewTime(start)
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 1},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef:  corev1.LocalObjectReference{Name: "account"},
			Type:        v1alpha1.AccessApplicationTypeSelfHosted,
			Application: v1alpha1.AccessApplicationSettings{Name: "tenant/app", SessionDuration: "1h"},
			Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
				Type:   v1alpha1.AccessApplicationDestinationWorker,
				Worker: &v1alpha1.AccessWorkerDestinationSpec{WorkerID: "worker-1"},
			}},
			Policies: []v1alpha1.AccessApplicationPolicyReference{
				{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: accessFreshnessPolicyA}},
				{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: accessFreshnessPolicyB}},
			},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	for _, apply := range configure {
		apply(application)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*"}, Zones: []string{"*"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: epoch},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: epoch},
		}},
	}
	counter := &statusWriteCounter{}
	kube := accessApplicationTestClientBuilder(scheme).
		WithStatusSubresource(&v1alpha1.AccessApplication{}).
		WithObjects(application, account,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
		).
		WithInterceptorFuncs(counter.funcs()).
		Build()
	remote := newFakeAccessApplicationCloudflare()
	remote.SetPolicy(flarecloudflare.AccessPolicy{ID: accessFreshnessPolicyA, Name: "a", Decision: "Allow"})
	remote.SetPolicy(flarecloudflare.AccessPolicy{ID: accessFreshnessPolicyB, Name: "b", Decision: "Allow"})
	world := &accessFreshnessWorld{
		kube: kube, remote: remote, counter: counter, now: start,
		request: ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)},
	}
	world.reconciler = &AccessApplicationReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, OperatorNamespace: accessApplicationAUDNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 func() time.Time { return world.now },
		Freshness:           freshness.DefaultPolicy(),
		Invalidator:         freshness.NewLatch(),
	}
	return world
}

// pass runs one reconcile and returns the remote calls it made.
func (w *accessFreshnessWorld) pass(t *testing.T, label string) ([]string, ctrl.Result) {
	t.Helper()
	before := len(w.remote.Calls())
	result, err := w.reconciler.Reconcile(context.Background(), w.request)
	if err != nil {
		t.Fatalf("%s reconcile: %v", label, err)
	}
	return w.remote.Calls()[before:], result
}

func (w *accessFreshnessWorld) stored(t *testing.T) v1alpha1.AccessApplication {
	t.Helper()
	var application v1alpha1.AccessApplication
	if err := w.kube.Get(context.Background(), w.request.NamespacedName, &application); err != nil {
		t.Fatalf("get AccessApplication: %v", err)
	}
	return application
}

// converge drives the fixture to Programmed=True with a settled gate stamp and
// returns the requeue of the last converging pass.
func (w *accessFreshnessWorld) converge(t *testing.T) ctrl.Result {
	t.Helper()
	w.pass(t, "finalizer")
	w.pass(t, "create")
	// The create pass hashed a desired state without the remote ID, so the
	// stamp only settles once the bound ID is part of it.
	w.now = w.now.Add(10 * time.Second)
	_, result := w.pass(t, "rebind")
	application := w.stored(t)
	if !meta.IsStatusConditionTrue(application.Status.Conditions, accessApplicationConditionProgrammed) {
		t.Fatalf("fixture never converged: %+v", meta.FindStatusCondition(application.Status.Conditions, accessApplicationConditionProgrammed))
	}
	if application.Status.AppliedHash == "" || application.Status.AppliedAt == nil {
		t.Fatalf("gate stamp was not stored: %+v", application.Status)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("converged object does not requeue: %+v", result)
	}
	return result
}

func (w *accessFreshnessWorld) deletePolicy(id string) {
	w.remote.mu.Lock()
	defer w.remote.mu.Unlock()
	delete(w.remote.policies, id)
}

func callsWithPrefix(calls []string, prefix string) []string {
	var matches []string
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			matches = append(matches, call)
		}
	}
	return matches
}

// A converged AccessApplication re-verifies Cloudflare once per TTL. A
// re-verify that finds nothing to change must not rewrite status: every
// appliedAt rewrite is a watch event that wakes the Gateway, DeviceProfile,
// and AccessCustomPage controllers. The gate must still open between
// re-verifies, so the verify time has to live outside status.
func TestAccessApplicationSteadyStateReverifyWritesNoStatus(t *testing.T) {
	world := newAccessFreshnessWorld(t)
	result := world.converge(t)
	converged := world.stored(t)
	world.counter.writes = 0

	for cycle := range 3 {
		world.now = world.now.Add(result.RequeueAfter)
		var calls []string
		calls, result = world.pass(t, "re-verify")
		if len(callsWithPrefix(calls, "Get:"+converged.Status.ApplicationID)) == 0 {
			t.Fatalf("cycle %d: expired gate did not re-read the remote application: %v", cycle, calls)
		}
		if result.RequeueAfter <= 0 {
			t.Fatalf("cycle %d: converged object stopped requeueing", cycle)
		}
	}
	if world.counter.writes != 0 {
		t.Fatalf("unchanged re-verifies wrote status %d times", world.counter.writes)
	}
	current := world.stored(t)
	if current.Status.AppliedHash != converged.Status.AppliedHash {
		t.Fatalf("appliedHash moved from %q to %q without a spec change", converged.Status.AppliedHash, current.Status.AppliedHash)
	}
	if !current.Status.AppliedAt.Equal(converged.Status.AppliedAt) {
		t.Fatalf("appliedAt moved from %v to %v although appliedHash did not change", converged.Status.AppliedAt, current.Status.AppliedAt)
	}
	if !meta.IsStatusConditionTrue(current.Status.Conditions, accessApplicationConditionProgrammed) {
		t.Fatal("re-verify withdrew Programmed on an unchanged remote")
	}

	// The last re-verify is recent although status.appliedAt is three TTLs
	// old, so the gate must open and skip Cloudflare entirely.
	world.now = world.now.Add(10 * time.Second)
	if calls, _ := world.pass(t, "between re-verifies"); len(calls) != 0 {
		t.Fatalf("pass inside the TTL after a re-verify still called Cloudflare: %v", calls)
	}
}

// External policies are referenced by ID only, so their existence check is a
// remote read. It must be paid only when the pass goes to Cloudflare anyway;
// otherwise every open-gate pass costs one read per external policy. The
// deferred check must still fail closed when a policy disappears.
func TestAccessApplicationExternalPolicyReadDeferredBehindGate(t *testing.T) {
	world := newAccessFreshnessWorld(t)
	result := world.converge(t)

	world.now = world.now.Add(10 * time.Second)
	calls, _ := world.pass(t, "open gate")
	if reads := callsWithPrefix(calls, "GetPolicy:"); len(reads) != 0 {
		t.Fatalf("open-gate pass read external policies: %v", reads)
	}

	world.now = world.now.Add(result.RequeueAfter)
	calls, result = world.pass(t, "expired gate")
	for _, id := range []string{accessFreshnessPolicyA, accessFreshnessPolicyB} {
		if len(callsWithPrefix(calls, "GetPolicy:"+id)) == 0 {
			t.Fatalf("closed-gate pass did not verify external policy %q: %v", id, calls)
		}
	}
	if !meta.IsStatusConditionTrue(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed) {
		t.Fatal("verified external policies withdrew Programmed")
	}

	// The policy vanishes remotely inside the TTL. The next expiry must
	// notice it and withdraw Programmed.
	world.deletePolicy(accessFreshnessPolicyB)
	world.now = world.now.Add(result.RequeueAfter)
	world.pass(t, "policy removed")
	programmed := meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "TargetNotFound" {
		t.Fatalf("missing external policy did not fail closed: %+v", programmed)
	}

	// The failed pass verified nothing, so the gate stays shut: a pass inside
	// the next window must check the policy again rather than re-open.
	world.now = world.now.Add(10 * time.Second)
	calls, _ = world.pass(t, "next window")
	if len(callsWithPrefix(calls, "GetPolicy:"+accessFreshnessPolicyB)) == 0 {
		t.Fatalf("pass after the failure skipped the external policy check: %v", calls)
	}
	application := world.stored(t)
	programmed = meta.FindStatusCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "TargetNotFound" {
		t.Fatalf("missing external policy re-opened the application: %+v", programmed)
	}
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		t.Fatal("missing external policy released the revocation latch")
	}
}

// A latched revocation goes to Cloudflare regardless of the gate and, once
// acknowledged, releases the latch. Releasing it while an external policy is
// missing would re-open an application whose policy set is broken, so the
// deferred external policy check must run before the latch branch acts.
func TestAccessApplicationLatchedRevocationChecksExternalPolicyFirst(t *testing.T) {
	world := newAccessFreshnessWorld(t)
	world.converge(t)

	// An acknowledged revocation: no data-plane claims remain to wait on, so
	// the latch branch would revoke and clear the latch on a valid object.
	application := world.stored(t)
	before := application.DeepCopy()
	application.Annotations = map[string]string{accessApplicationRevocationAnnotation: `{"claims":[]}`}
	if err := world.kube.Patch(context.Background(), &application, client.MergeFrom(before)); err != nil {
		t.Fatal(err)
	}
	world.deletePolicy(accessFreshnessPolicyA)

	world.now = world.now.Add(10 * time.Second)
	calls, _ := world.pass(t, "latched")
	if len(callsWithPrefix(calls, "GetPolicy:"+accessFreshnessPolicyA)) == 0 {
		t.Fatalf("latched pass did not verify the external policy: %v", calls)
	}
	application = world.stored(t)
	programmed := meta.FindStatusCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "TargetNotFound" {
		t.Fatalf("missing external policy under a latched revocation did not invalidate: %+v", programmed)
	}
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		t.Fatal("latched revocation was released although an external policy is missing")
	}
}

// ObserveOnly applies nothing, so it has no applied hash to record. A pass
// that stamped appliedAt=now anyway rewrote status on every reconcile and woke
// every watcher of AccessApplications for an object that never changes.
func TestAccessApplicationObserveOnlyRecordsNoStamp(t *testing.T) {
	world := newAccessFreshnessWorld(t, func(application *v1alpha1.AccessApplication) {
		application.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		application.Spec.ExternalRef = &v1alpha1.AccessApplicationExternalReference{ApplicationID: "external-observed"}
	})
	world.remote.Put(flarecloudflare.AccessApplication{
		ID: "external-observed", AUD: "aud-external-observed", Name: "external-app",
		Type: flarecloudflare.AccessApplicationTypeSelfHosted,
	})
	world.pass(t, "finalizer")
	world.pass(t, "observe")
	world.now = world.now.Add(time.Second)
	world.pass(t, "settle")
	application := world.stored(t)
	if application.Status.ApplicationID != "external-observed" ||
		!meta.IsStatusConditionTrue(application.Status.Conditions, accessApplicationConditionProgrammed) {
		t.Fatalf("ObserveOnly fixture never converged: id=%q programmed=%+v", application.Status.ApplicationID,
			meta.FindStatusCondition(application.Status.Conditions, accessApplicationConditionProgrammed))
	}
	world.counter.writes = 0

	for cycle := range 3 {
		world.now = world.now.Add(10 * time.Second)
		calls, _ := world.pass(t, "observe again")
		if len(callsWithPrefix(calls, "Get:external-observed")) == 0 {
			t.Fatalf("cycle %d: ObserveOnly pass did not read the remote: %v", cycle, calls)
		}
	}
	if world.counter.writes != 0 {
		t.Fatalf("unchanged ObserveOnly passes wrote status %d times", world.counter.writes)
	}
	application = world.stored(t)
	if application.Status.AppliedHash != "" || application.Status.AppliedAt != nil {
		t.Fatalf("ObserveOnly recorded a gate stamp: appliedHash=%q appliedAt=%v", application.Status.AppliedHash, application.Status.AppliedAt)
	}
}
