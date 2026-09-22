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

// Observable-contract tests for the remote-identity checkpoint that follows
// the non-idempotent CreateTunnel (issue #92 regression: a conditions
// transaction that vetoes the capture leaves status.tunnelId empty, so the
// next pass creates a duplicate remote tunnel). Each spec boots its OWN
// envtest control plane — independent etcd + apiserver, same CRDs as the
// suite — and drives the production writers directly: commitTunnelConditions
// for the pre-create commit, ensureRemoteTunnel against the deterministic
// fake for the create boundary, and persistRemoteIdentity for the capture.
//
// Coverage map (docs/qa/issue-92-status-consistency.md):
//   QA-92-46 — a generation bump between create and checkpoint still captures
//              the full remote identity; the next pass takes the managed path
//              and never calls CreateTunnel again
//   QA-92-47 — delete/recreate between commit and checkpoint: the UID test op
//              fails the whole patch; the replacement object stays untouched
//   QA-92-48 — the capture touches only remote-identity fields: condition
//              values and field-manager ownership are unchanged
//   QA-92-46/48 — volatile observation timestamps (connectionsActiveAt /
//              connectionsInactiveAt) are not latched by the checkpoint: the
//              next data apply with a nil projection clears them
//   QA-92-49 — the first Direct reconcile commits conditions before the
//              non-idempotent CreateTunnel, and a vetoed pre-create commit
//              prevents the create entirely

import (
	"fmt"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// newDirectReconcileFixture provisions everything a real first Reconcile of a
// Direct-mode CloudflareTunnel needs on the isolated plane: the kube-system
// namespace (cluster ID source), a credential Secret, a verified
// CloudflareAccount granting platform objects to the fixture namespace, and
// the tunnel itself with the finalizer pre-set so one Reconcile call drives
// the full create path. wrapReader optionally wraps the reconciler's APIReader
// to inject a mid-pass mutation.
func newDirectReconcileFixture(direct client.Client, factory *fakeTunnelCloudflareFactory, wrapReader func(client.Reader) client.Reader) (*tunnelConditionsFixture, *CloudflareTunnelReconciler) {
	err := direct.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}})
	gomega.Expect(err == nil || apierrors.IsAlreadyExists(err)).To(gomega.BeTrue(),
		"kube-system must exist for the cluster ID read")

	accountName := fmt.Sprintf("qa-account-%d", fixtureCounter.Add(1))
	spec := directTunnelSpec()
	spec.AccountRef = corev1.LocalObjectReference{Name: accountName}
	fixture := newTunnelConditionsFixture(direct, spec)

	var namespace corev1.Namespace
	gomega.Expect(direct.Get(testContext, types.NamespacedName{Name: fixture.namespace}, &namespace)).To(gomega.Succeed())
	namespace.Labels = map[string]string{"flareway.bhyoo.com/tenant": fixture.namespace}
	gomega.Expect(direct.Update(testContext, &namespace)).To(gomega.Succeed())

	gomega.Expect(direct.Create(testContext, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: fixture.namespace},
		Data:       map[string][]byte{"token": []byte("api-token")},
	})).To(gomega.Succeed())

	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cloudflare-token", Namespace: fixture.namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"flareway.bhyoo.com/tenant": fixture.namespace}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	gomega.Expect(direct.Create(testContext, account)).To(gomega.Succeed())
	var seeded v1alpha1.CloudflareAccount
	gomega.Expect(direct.Get(testContext, types.NamespacedName{Name: accountName}, &seeded)).To(gomega.Succeed())
	seeded.Status.Conditions = []metav1.Condition{{
		Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted",
		ObservedGeneration: seeded.Generation, LastTransitionTime: metav1.Now(),
	}, {
		Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid",
		ObservedGeneration: seeded.Generation, LastTransitionTime: metav1.Now(),
	}}
	gomega.Expect(direct.Status().Update(testContext, &seeded)).To(gomega.Succeed())

	// Pre-set the finalizer so a single Reconcile reaches the active path.
	var tunnel v1alpha1.CloudflareTunnel
	gomega.Expect(direct.Get(testContext, fixture.key, &tunnel)).To(gomega.Succeed())
	tunnel.Finalizers = []string{v1alpha1.CloudflareTunnelFinalizer}
	gomega.Expect(direct.Update(testContext, &tunnel)).To(gomega.Succeed())

	reader := client.Reader(direct)
	if wrapReader != nil {
		reader = wrapReader(direct)
	}
	reconciler := &CloudflareTunnelReconciler{
		Client:              direct,
		APIReader:           reader,
		Scheme:              direct.Scheme(),
		NewCloudflareClient: factory.Client,
	}
	return fixture, reconciler
}

var _ = ginkgo.Describe("CloudflareTunnel remote identity checkpoint", func() {

	ginkgo.It("QA-92-46: captures the full remote identity across a generation bump so the next pass never re-creates", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		writer := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}

		const accountID = "0123456789abcdef0123456789abcdef"
		const clusterID = "qa-cluster"
		factory := newFakeTunnelCloudflareFactory()
		cf, err := factory.Client("token", accountID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// The pre-create commit runs first: it establishes the status
		// subresource the checkpoint patches into.
		observed := fixture.live()
		now := metav1.NewTime(time.Date(2026, 9, 22, 11, 0, 0, 0, time.UTC))
		gomega.Expect(writer.commitTunnelConditions(testContext, observed, []metav1.Condition{
			tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", "authorized", observed.Generation, now),
		}, true)).To(gomega.Succeed())

		// The remote create boundary: a fresh Managed tunnel with no recorded
		// identity takes the create path exactly once.
		desiredName := desiredTunnelName(observed, clusterID)
		remote, conflict, err := writer.ensureRemoteTunnel(testContext, cf, observed, clusterID, accountID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(conflict).To(gomega.BeEmpty())
		gomega.Expect(countCall(factory.Calls(), "CreateTunnel")).To(gomega.Equal(1))

		// A spec edit lands between the create and the checkpoint: the
		// observed snapshot's generation is now stale, but the created remote
		// object still belongs to THIS object — the capture must not be
		// vetoed by generation skew.
		var live v1alpha1.CloudflareTunnel
		gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
		live.Spec.DNS.RecordComment = "edited between create and checkpoint"
		gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
		gomega.Expect(fixture.live().Generation).To(gomega.BeNumerically(">", observed.Generation))

		// The checkpoint must not restamp status.observedGeneration: that
		// field records which spec generation the controller observed, not
		// remote truth, and belongs to the full data apply. Seed a live value
		// distinct from both generations so a checkpoint that wrongly carries
		// the projected observedGeneration is caught.
		gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
		live.Status.ObservedGeneration = live.Generation + 41
		gomega.Expect(direct.Status().Update(testContext, &live)).To(gomega.Succeed())
		seededObservedGeneration := live.Status.ObservedGeneration

		checkpoint := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&checkpoint, remote, observed.Generation)
		gomega.Expect(writer.persistRemoteIdentity(testContext, observed, checkpoint)).To(gomega.Succeed(),
			"the identity checkpoint must tolerate spec churn — only identity (UID) binds it")

		captured := fixture.live()
		gomega.Expect(captured.Status.TunnelID).To(gomega.Equal(remote.ID))
		gomega.Expect(captured.Status.OwnershipVerified).To(gomega.BeTrue(),
			"capturing tunnelId without ownershipVerified would wedge the next pass into the adoption-conflict path")
		gomega.Expect(captured.Status.AccountID).To(gomega.Equal(accountID))
		gomega.Expect(captured.Status.Name).To(gomega.Equal(desiredName))
		gomega.Expect(captured.Status.CreatedAt).NotTo(gomega.BeNil())
		gomega.Expect(captured.Status.ObservedGeneration).To(gomega.Equal(seededObservedGeneration),
			"the checkpoint writes remote identity only; observedGeneration stays with the data apply")

		// The next reconcile observes the durable identity and takes the
		// managed GetTunnel path — CreateTunnel is never called again.
		next, nextConflict, err := writer.ensureRemoteTunnel(testContext, cf, captured, clusterID, accountID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(nextConflict).To(gomega.BeEmpty())
		gomega.Expect(next.ID).To(gomega.Equal(remote.ID))
		gomega.Expect(countCall(factory.Calls(), "CreateTunnel")).To(gomega.Equal(1),
			"a captured identity must route the next pass to the managed path, not a duplicate create")
		gomega.Expect(countCall(factory.Calls(), "GetTunnel")).To(gomega.BeNumerically(">=", 1),
			"the next pass observes the recorded tunnel through GetTunnel")
	})

	ginkgo.It("QA-92-47: refuses to attach the captured identity to a recreated object", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		writer := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}

		observed := fixture.live()
		now := metav1.NewTime(time.Date(2026, 9, 22, 11, 10, 0, 0, time.UTC))
		gomega.Expect(writer.commitTunnelConditions(testContext, observed, []metav1.Condition{
			tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", "authorized", observed.Generation, now),
		}, true)).To(gomega.Succeed())

		// The object is deleted and recreated between the pre-create commit
		// and the checkpoint: the observed snapshot's UID no longer matches
		// the live object, so the whole patch must fail atomically.
		gomega.Expect(direct.Delete(testContext, fixture.live())).To(gomega.Succeed())
		gomega.Expect(direct.Create(testContext, &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: fixture.name, Namespace: fixture.namespace},
			Spec:       managedTunnelSpec(),
		})).To(gomega.Succeed())
		replacement := fixture.live()
		gomega.Expect(replacement.UID).NotTo(gomega.Equal(observed.UID))

		remote := RemoteTunnel{
			ID:           "tunnel-recreated-boundary",
			AccountTag:   "0123456789abcdef0123456789abcdef",
			Name:         desiredTunnelName(observed, "qa-cluster"),
			Status:       flarecloudflare.TunnelStatusHealthy,
			Type:         flarecloudflare.TunnelTypeCloudflared,
			ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
			CreatedAt:    time.Unix(100, 0),
		}
		checkpoint := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&checkpoint, remote, observed.Generation)
		err := writer.persistRemoteIdentity(testContext, observed, checkpoint)
		gomega.Expect(err).To(gomega.HaveOccurred(),
			"the UID test op must reject a capture bound to a deleted object")
		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(),
			"a failed JSON Patch test op surfaces as Invalid")

		// The replacement object is untouched: JSON Patch applies
		// atomically, so no identity field may leak onto the new UID.
		after := fixture.live()
		gomega.Expect(after.UID).To(gomega.Equal(replacement.UID))
		gomega.Expect(after.Status.TunnelID).To(gomega.BeEmpty())
		gomega.Expect(after.Status.OwnershipVerified).To(gomega.BeFalse())
		gomega.Expect(after.Status.Conditions).To(gomega.BeEmpty())
	})

	ginkgo.It("QA-92-48: the capture writes only remote-identity fields and leaves conditions and their ownership untouched", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		writer := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}

		// Seed a converged condition set under the shared manager plus a
		// foreign-owned condition the checkpoint must not disturb.
		now := metav1.NewTime(time.Date(2026, 9, 22, 11, 20, 0, 0, time.UTC))
		observed := fixture.live()
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
		})).To(gomega.Succeed())
		applyTunnelConditions(direct, fixture.key, "external-manager", metav1.Condition{
			Type:               "example.com/Custom",
			Status:             metav1.ConditionTrue,
			Reason:             "Custom",
			Message:            "foreign-owned condition",
			ObservedGeneration: observed.Generation,
			LastTransitionTime: now,
		})
		before := fixture.live()

		remote := RemoteTunnel{
			ID:           "tunnel-conditions-untouched",
			AccountTag:   "0123456789abcdef0123456789abcdef",
			Name:         desiredTunnelName(observed, "qa-cluster"),
			Status:       flarecloudflare.TunnelStatusHealthy,
			Type:         flarecloudflare.TunnelTypeCloudflared,
			ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
			CreatedAt:    time.Unix(100, 0),
		}
		checkpoint := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&checkpoint, remote, observed.Generation)
		gomega.Expect(writer.persistRemoteIdentity(testContext, observed, checkpoint)).To(gomega.Succeed())

		after := fixture.live()
		gomega.Expect(after.Status.TunnelID).To(gomega.Equal(remote.ID),
			"the checkpoint did write the remote identity")
		gomega.Expect(after.Status.Conditions).To(gomega.Equal(before.Status.Conditions),
			"the JSON Patch cannot add, remove, or restamp condition entries")
		gomega.Expect(tunnelConditionOwners(after)).To(gomega.Equal(tunnelConditionOwners(before)),
			"the checkpoint must not claim or release condition ownership")
	})

	ginkgo.It("QA-92-46/48: a volatile timestamp captured at create is cleared by the next observation, not latched", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		writer := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}

		observed := fixture.live()
		now := metav1.NewTime(time.Date(2026, 9, 22, 11, 40, 0, 0, time.UTC))
		gomega.Expect(writer.commitTunnelConditions(testContext, observed, []metav1.Condition{
			tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", "authorized", observed.Generation, now),
		}, true)).To(gomega.Succeed())

		// The remote reports both connection timestamps at create time; the
		// production checkpoint captures the identity.
		activeAt := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
		inactiveAt := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
		remote := RemoteTunnel{
			ID:                    "tunnel-volatile-timestamps",
			AccountTag:            "0123456789abcdef0123456789abcdef",
			Name:                  desiredTunnelName(observed, "qa-cluster"),
			Status:                flarecloudflare.TunnelStatusHealthy,
			Type:                  flarecloudflare.TunnelTypeCloudflared,
			ConfigSource:          flarecloudflare.TunnelConfigSourceCloudflare,
			CreatedAt:             time.Unix(100, 0),
			ConnectionsActiveAt:   &activeAt,
			ConnectionsInactiveAt: &inactiveAt,
		}
		checkpoint := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&checkpoint, remote, observed.Generation)
		gomega.Expect(writer.persistRemoteIdentity(testContext, observed, checkpoint)).To(gomega.Succeed())
		gomega.Expect(fixture.live().Status.TunnelID).To(gomega.Equal(remote.ID),
			"the checkpoint did write the remote identity")

		// The first real pass after create projects the same observation
		// through the normal data apply: both timestamps are visible.
		live := fixture.live()
		first := tunnelOwnedStatus(live, live.Status.GatewayRef, live.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&first, remote, live.Generation)
		gomega.Expect(writer.patchOwnedStatus(testContext, live, first, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.live().Status.ConnectionsActiveAt).NotTo(gomega.BeNil(),
			"the data apply publishes the observed connectionsActiveAt")
		gomega.Expect(fixture.live().Status.ConnectionsInactiveAt).NotTo(gomega.BeNil(),
			"the data apply publishes the observed connectionsInactiveAt")

		// The next observation reports no connection timestamps. These fields
		// are deliberately unprotected and authoritatively rewritten by each
		// fresh projection, so the apply must persist nil — a value latched
		// by the checkpoint's field claim would survive here.
		remoteNil := remote
		remoteNil.ConnectionsActiveAt = nil
		remoteNil.ConnectionsInactiveAt = nil
		live = fixture.live()
		next := tunnelOwnedStatus(live, live.Status.GatewayRef, live.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&next, remoteNil, live.Generation)
		gomega.Expect(writer.patchOwnedStatus(testContext, live, next, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.live().Status.ConnectionsActiveAt).To(gomega.BeNil(),
			"a nil projection must clear connectionsActiveAt")
		gomega.Expect(fixture.live().Status.ConnectionsInactiveAt).To(gomega.BeNil(),
			"a nil projection must clear connectionsInactiveAt")

		// A follow-up identical pass stays stable: still nil, no resurrection.
		live = fixture.live()
		next = tunnelOwnedStatus(live, live.Status.GatewayRef, live.Status.GatewayUID, nil)
		projectRemoteTunnelStatus(&next, remoteNil, live.Generation)
		gomega.Expect(writer.patchOwnedStatus(testContext, live, next, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.live().Status.ConnectionsActiveAt).To(gomega.BeNil())
		gomega.Expect(fixture.live().Status.ConnectionsInactiveAt).To(gomega.BeNil())
	})

	ginkgo.It("QA-92-49: the first Direct reconcile commits conditions before CreateTunnel, and a vetoed commit prevents the create", func() {
		direct := startIsolatedConditionsPlane()

		// (a) A real first Reconcile on a Direct tunnel with no seeded status:
		// the pre-create conditions commit must have materialized the status
		// subresource before the non-idempotent remote create runs.
		factory := newFakeTunnelCloudflareFactory()
		fixture, reconciler := newDirectReconcileFixture(direct, factory, nil)

		statusExistedAtCreate := false
		factory.Before("CreateTunnel", func() {
			var live v1alpha1.CloudflareTunnel
			if err := direct.Get(testContext, fixture.key, &live); err == nil {
				statusExistedAtCreate = len(live.Status.Conditions) > 0
			}
		})

		_, err := reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(countCall(factory.Calls(), "CreateTunnel")).To(gomega.Equal(1))
		gomega.Expect(statusExistedAtCreate).To(gomega.BeTrue(),
			"the conditions commit must run before CreateTunnel so the identity checkpoint has a status subresource to write")
		created := fixture.live()
		gomega.Expect(created.Status.TunnelID).NotTo(gomega.BeEmpty(),
			"the identity checkpoint captured the created remote tunnel")
		gomega.Expect(created.Status.OwnershipVerified).To(gomega.BeTrue())

		// (b) A generation bump inside the pre-create commit's read-to-apply
		// window vetoes the commit; the reconcile must abort before any remote
		// mutation — CreateTunnel is never called.
		vetoFactory := newFakeTunnelCloudflareFactory()
		var vetoFixture *tunnelConditionsFixture
		var vetoReconciler *CloudflareTunnelReconciler
		vetoFixture, vetoReconciler = newDirectReconcileFixture(direct, vetoFactory, func(inner client.Reader) client.Reader {
			bumped := false
			return &interposingReader{inner: inner, onGet: func(key types.NamespacedName) {
				if key != vetoFixture.key || bumped {
					return
				}
				bumped = true
				var live v1alpha1.CloudflareTunnel
				gomega.Expect(direct.Get(testContext, vetoFixture.key, &live)).To(gomega.Succeed())
				live.Spec.DNS.RecordComment = "edited inside the pre-create commit"
				gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
			}}
		})

		_, err = vetoReconciler.Reconcile(testContext, ctrl.Request{NamespacedName: vetoFixture.key})
		gomega.Expect(err).To(gomega.HaveOccurred(),
			"the stale observation must abort the pass before the remote create")
		gomega.Expect(countCall(vetoFactory.Calls(), "CreateTunnel")).To(gomega.Equal(0),
			"a vetoed pre-create commit must prevent the non-idempotent create")
		gomega.Expect(vetoFixture.live().Status.TunnelID).To(gomega.BeEmpty(),
			"no remote identity may be recorded for a create that never ran")
	})
})
