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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
)

// This file is the envtest-component tier of the issue-92 status-consistency
// QA plan (docs/qa/issue-92-status-consistency.md). Every spec drives the real
// GatewayReconciler against a dedicated envtest control plane owned by the
// fixture; the fixture's own CloudflareAccountReconciler and
// CloudflareTunnelReconciler are stepped explicitly so provisioning and
// tunnel-owned status writes can never interleave with a fault scenario. Only
// the outer dependency boundaries (Cloudflare API, dataplane prober, xDS ACK
// tracker, clock) are faked. Assertions read persisted state through an
// uncached client and never pin message wording beyond the documented
// reason/lag categories.

var _ = ginkgo.Describe("Gateway tunnel status consistency (issue 92)", func() {

	// QA-92-01 + QA-92-03: an unchanged converged pass must not persist
	// ConfigApplied=False at any observable point, must not touch the remote,
	// and must leave lastTransitionTime at the original transition.
	ginkgo.It("QA-92-01/03 keeps ConfigApplied=True and its transition time across unchanged passes", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		converged := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(converged.Status).To(gomega.Equal(metav1.ConditionTrue))
		transition := converged.LastTransitionTime

		updatesBefore := f.remote.updates
		for pass := 0; pass < 2; pass++ {
			f.prober.observed = nil
			f.prober.record = true
			f.clock = f.clock.Add(time.Minute)
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			f.prober.record = false
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(f.prober.observed).NotTo(gomega.BeEmpty(),
				"pass %d: the convergence gate must still evaluate on an unchanged pass", pass)
			for _, mid := range f.prober.observed {
				condition := meta.FindStatusCondition(mid.conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
				gomega.Expect(condition).NotTo(gomega.BeNil())
				gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue),
					"mid-gate pass %d persisted ConfigApplied=%s reason=%q", pass, condition.Status, condition.Reason)
			}
			final := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
			gomega.Expect(final.Status).To(gomega.Equal(metav1.ConditionTrue))
			gomega.Expect(final.LastTransitionTime).To(gomega.Equal(transition),
				"unchanged pass %d rewrote lastTransitionTime", pass)
			gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
			gomega.Expect(f.remote.updates).To(gomega.Equal(updatesBefore))
		}
	})

	// QA-92-05: a snapshot that is never ACKed keeps the gate open; the
	// persisted condition is an honest Pending, not a transient artifact.
	ginkgo.It("QA-92-05 reports ConfigApplied=False Pending while the xDS snapshot stays unACKed", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Reason).To(gomega.Equal("Pending"))
		gomega.Expect(condition.Message).To(gomega.ContainSubstring("Envoy xDS ACK"))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.BeZero())
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))
	})

	// QA-92-06: a real False→True transition advances lastTransitionTime to the
	// actual transition moment and Ready follows in the same persisted state.
	ginkgo.It("QA-92-06 promotes ConfigApplied and Ready atomically on first convergence", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		pending := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(pending.Status).To(gomega.Equal(metav1.ConditionFalse))

		f.clock = f.clock.Add(time.Minute)
		f.converge()
		applied := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(applied.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(applied.LastTransitionTime.After(pending.LastTransitionTime.Time)).To(gomega.BeTrue())
		ready := f.condition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(ready.LastTransitionTime).To(gomega.Equal(applied.LastTransitionTime),
			"Ready must transition in the same commit as ConfigApplied")
	})

	// QA-92-07: while the gate stays open, changing only the lagging set
	// updates the message without a status transition or timestamp rewrite.
	ginkgo.It("QA-92-07 preserves lastTransitionTime when only the lagging set changes", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		first := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(first.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(first.Message).To(gomega.ContainSubstring("Envoy xDS ACK"))

		f.prober.readyErr = errors.New("connection refused")
		f.clock = f.clock.Add(time.Minute)
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		second := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(second.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(second.Message).To(gomega.ContainSubstring("not ready"))
		gomega.Expect(second.Message).NotTo(gomega.Equal(first.Message))
		gomega.Expect(second.LastTransitionTime).To(gomega.Equal(first.LastTransitionTime))
	})

	// QA-92-08: after the convergence timeout the message escalates to the
	// timeout category while status and transition time stay put.
	ginkgo.It("QA-92-08 escalates the pending message to the timeout category without a transition", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		first := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(first.Status).To(gomega.Equal(metav1.ConditionFalse))

		f.clock = f.clock.Add(cloudflareConvergenceTimeout + time.Minute)
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		escalated := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(escalated.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(escalated.Message).To(gomega.ContainSubstring("Timed out"))
		gomega.Expect(escalated.LastTransitionTime).To(gomega.Equal(first.LastTransitionTime))
	})

	// QA-92-09: the durable demotion (ConfigApplied+Ready=False) must be
	// persisted before UpdateTunnelConfiguration runs. The recorded desired
	// hash stays at the last successful value until the remote write commits;
	// the intent hash is informational (condition message) only.
	ginkgo.It("QA-92-09 persists demotion before the provider write", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldHash := f.tunnel().Status.ConfigVersion.DesiredHash
		oldVersion := f.remote.remoteVersion

		var preWrite *qa92TunnelSnapshot
		f.remote.beforeUpdate = func() {
			snapshot := f.snapshotTunnel()
			preWrite = &snapshot
		}
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(preWrite).NotTo(gomega.BeNil(), "provider write never ran")
		applied := meta.FindStatusCondition(preWrite.conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(applied).NotTo(gomega.BeNil())
		gomega.Expect(applied.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(applied.Message).To(gomega.ContainSubstring("desired hash"),
			"the intent hash is carried by the condition message, not configVersion")
		ready := meta.FindStatusCondition(preWrite.conditions, v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready).NotTo(gomega.BeNil())
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(preWrite.config.DesiredHash).To(gomega.Equal(oldHash),
			"the last-successful desired hash must persist until the remote write commits")
		gomega.Expect(preWrite.config.Desired).To(gomega.Equal(oldVersion),
			"the provider assigns the new version; intent must not pre-claim it")
		gomega.Expect(preWrite.config.Applied).To(gomega.Equal(oldVersion))
	})

	// QA-92-10: the provider-returned version is checkpointed (desired=remote,
	// applied still old, ConfigApplied=False) before the gate evaluates.
	ginkgo.It("QA-92-10 checkpoints the returned version before gate evaluation", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldVersion := f.remote.remoteVersion

		var gateObservation *qa92TunnelSnapshot
		f.prober.onReady = func() {
			snapshot := f.snapshotTunnel()
			gateObservation = &snapshot
		}
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(gateObservation).NotTo(gomega.BeNil(), "gate never probed")
		newVersion := f.remote.remoteVersion
		gomega.Expect(newVersion).To(gomega.BeNumerically(">", oldVersion))
		gomega.Expect(gateObservation.config.Desired).To(gomega.Equal(newVersion))
		gomega.Expect(gateObservation.config.Remote).To(gomega.Equal(newVersion))
		gomega.Expect(gateObservation.config.Applied).To(gomega.Equal(oldVersion))
		condition := meta.FindStatusCondition(gateObservation.conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition).NotTo(gomega.BeNil())
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
	})

	// QA-92-11: abort matrix at the five outer-boundary sites. Every site must
	// leave no persisted revision claiming the ungated version as applied, keep
	// Ready consistent with ConfigApplied, and let the next pass converge.
	ginkgo.DescribeTable("QA-92-11 aborts fail-closed at every boundary",
		func(inject func(f *qa92Fixture, ctx context.Context, cancel context.CancelFunc)) {
			f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
			f.converge()
			oldVersion := f.remote.remoteVersion
			oldHash := f.tunnel().Status.ConfigVersion.DesiredHash
			f.setListenerHostname("edge-b.example.com")

			passCtx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			inject(f, passCtx, cancel)
			_, err := f.reconciler.Reconcile(passCtx, f.request)
			gomega.Expect(err).To(gomega.HaveOccurred())
			// Disarm every injected fault so the recovery pass runs clean.
			f.remote.onGetConfig = nil
			f.remote.updateErr = nil
			f.remote.beforeUpdate = nil
			f.remote.afterUpdate = nil
			f.prober.onReady = nil
			f.prober.onConfigVersion = nil
			f.snapshots.onIsACKed = nil
			f.fault.disarm()

			persisted := f.tunnel()
			newVersion := f.remote.remoteVersion
			if newVersion == oldVersion {
				// The provider write never committed: the recorded desired hash
				// must still be the last successful one so the retry actually
				// pushes the new configuration instead of no-oping on a hash
				// that was never applied remotely.
				gomega.Expect(persisted.Status.ConfigVersion.Applied).To(gomega.Equal(oldVersion))
				gomega.Expect(persisted.Status.ConfigVersion.DesiredHash).To(gomega.Equal(oldHash),
					"failed mutation must not record an unapplied desired hash")
			} else {
				gomega.Expect(persisted.Status.ConfigVersion.Applied).NotTo(gomega.Equal(newVersion),
					"ungated version %d must never be recorded as applied", newVersion)
			}
			applied := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
			ready := f.condition(v1alpha1.CloudflareTunnelConditionReady)
			gomega.Expect(ready.Status == metav1.ConditionTrue && applied.Status == metav1.ConditionFalse).To(gomega.BeFalse(),
				"torn pair persisted: Ready=True with ConfigApplied=False")

			f.prober.version = f.remote.remoteVersion
			f.converge()
			final := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
			gomega.Expect(final.Status).To(gomega.Equal(metav1.ConditionTrue))
			gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
		},
		// (a) abort inside the lock after the demotion commit: the second
		// tunnel status write fails.
		ginkgo.Entry("after invalidation persisted", func(f *qa92Fixture, _ context.Context, _ context.CancelFunc) {
			f.remote.onGetConfig = func() { f.fault.arm(2) }
		}),
		// (b) abort at the provider write after the pre-mutation writes.
		ginkgo.Entry("at provider write", func(f *qa92Fixture, _ context.Context, _ context.CancelFunc) {
			f.remote.updateErr = errors.New("provider write failed")
		}),
		// (c) abort after the provider write, before the version checkpoint:
		// the remote is ahead of the recorded state; the next pass must
		// re-read the remote inside the lock and reconcile the drift.
		ginkgo.Entry("after provider write", func(f *qa92Fixture, _ context.Context, cancel context.CancelFunc) {
			f.remote.afterUpdate = cancel
		}),
		// (d) abort after the version checkpoint, mid gate evaluation.
		ginkgo.Entry("after version checkpoint", func(f *qa92Fixture, _ context.Context, cancel context.CancelFunc) {
			f.prober.onReady = cancel
		}),
		// (e) abort just before the promotion commit: the gate already
		// decided ready when the last observation runs.
		ginkgo.Entry("before promotion commit", func(f *qa92Fixture, _ context.Context, cancel context.CancelFunc) {
			f.snapshots.onIsACKed = cancel
		}),
	)

	// QA-92-12: a desired-hash change invalidates the applied state even when
	// the provider write then fails; the stale True must not cover the new
	// desired.
	ginkgo.It("QA-92-12 invalidates the applied state on a desired hash change", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldHash := f.tunnel().Status.ConfigVersion.DesiredHash

		f.remote.updateErr = errors.New("provider write failed")
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).To(gomega.HaveOccurred())

		persisted := f.tunnel()
		gomega.Expect(persisted.Status.ConfigVersion.DesiredHash).To(gomega.Equal(oldHash),
			"a failed mutation must not record the unapplied desired hash")
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		ready := f.condition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
	})

	// QA-92-13: a full V→V+1 cycle keeps the demotion→checkpoint→gate→promotion
	// order, monotonic timestamps, and Ready atomically tracking ConfigApplied.
	ginkgo.It("QA-92-13 keeps ordering and monotonic transitions through a full version cycle", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldVersion := f.remote.remoteVersion
		oldHash := f.tunnel().Status.ConfigVersion.DesiredHash
		oldTransition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).LastTransitionTime

		var preWrite, atGate *qa92TunnelSnapshot
		f.remote.beforeUpdate = func() {
			snapshot := f.snapshotTunnel()
			preWrite = &snapshot
		}
		f.remote.afterUpdate = func() {
			gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
			f.prober.version = f.remote.remoteVersion
		}
		f.prober.onReady = func() {
			// Capture only the first gate evaluation: the promotion guard's
			// Tier-2 recheck probes again after the data apply has already
			// recorded the new Applied version.
			if atGate == nil {
				snapshot := f.snapshotTunnel()
				atGate = &snapshot
			}
		}
		f.clock = f.clock.Add(time.Minute)
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(preWrite).NotTo(gomega.BeNil())
		gomega.Expect(meta.FindStatusCondition(preWrite.conditions, v1alpha1.CloudflareTunnelConditionConfigApplied).Status).
			To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(preWrite.config.Applied).To(gomega.Equal(oldVersion))
		gomega.Expect(preWrite.config.DesiredHash).To(gomega.Equal(oldHash),
			"the last-successful desired hash must persist until the remote write commits")

		gomega.Expect(atGate).NotTo(gomega.BeNil())
		gomega.Expect(atGate.config.Desired).To(gomega.Equal(f.remote.remoteVersion))
		gomega.Expect(atGate.config.DesiredHash).NotTo(gomega.Equal(oldHash),
			"the checkpoint must record the hash of the configuration just written")
		gomega.Expect(atGate.config.Applied).To(gomega.Equal(oldVersion))
		gomega.Expect(meta.FindStatusCondition(atGate.conditions, v1alpha1.CloudflareTunnelConditionConfigApplied).Status).
			To(gomega.Equal(metav1.ConditionFalse))

		final := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(final.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(final.LastTransitionTime.After(oldTransition.Time)).To(gomega.BeTrue())
		ready := f.condition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(ready.LastTransitionTime).To(gomega.Equal(final.LastTransitionTime))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
	})

	// QA-92-14a: a remote read failure returns an error and commits a
	// distinguishable False instead of leaving a stale True to mask it.
	ginkgo.It("QA-92-14a surfaces remote read failures as an error and a distinct False reason", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()

		f.remote.getConfigErr = errors.New("cloudflare api unavailable")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).To(gomega.HaveOccurred())

		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Reason).To(gomega.Equal("RemoteError"))
		ready := f.condition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
	})

	// QA-92-14b: a non-error probe lag stays Pending without a reconcile error.
	ginkgo.It("QA-92-14b treats probe lag as pending, not an error", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()

		f.prober.readyErr = errors.New("timeout")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Reason).To(gomega.Equal("Pending"))
		gomega.Expect(condition.Message).To(gomega.ContainSubstring("not ready"))
	})

	// QA-92-15: a failed provider write keeps ConfigApplied/Ready False, never
	// advances applied, and the next pass retries idempotently.
	ginkgo.It("QA-92-15 keeps ConfigApplied=False after a provider write failure and retries", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldVersion := f.remote.remoteVersion
		oldHash := f.tunnel().Status.ConfigVersion.DesiredHash
		updatesBefore := f.remote.updates

		f.remote.updateErr = errors.New("provider write failed")
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).To(gomega.HaveOccurred())
		persisted := f.tunnel()
		gomega.Expect(persisted.Status.ConfigVersion.Applied).To(gomega.Equal(oldVersion))
		gomega.Expect(persisted.Status.ConfigVersion.DesiredHash).To(gomega.Equal(oldHash),
			"a failed mutation must not record the unapplied desired hash")
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionFalse))

		f.remote.updateErr = nil
		f.converge()
		gomega.Expect(f.remote.updates).To(gomega.BeNumerically(">", updatesBefore),
			"the retry must actually attempt the new configuration")
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-16a (Gateway promotion): a CAS conflict on the promotion
	// conditions commit must retry against the fresh live object and commit
	// once — the status retry must never replay the provider write. The
	// conflict is armed when the promotion guard's IsACKed runs (the second
	// gate-side ACK check in the pass), so it lands on the apply inside
	// patchTunnelConditionsValidated.
	ginkgo.It("QA-92-16a retries a CAS conflict on the promotion commit without replaying the provider write", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		updatesBefore := f.remote.updates

		f.remote.afterUpdate = func() {
			gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
			f.prober.version = f.remote.remoteVersion
		}
		calls := 0
		f.snapshots.onIsACKed = func() {
			calls++
			if calls == 2 {
				f.fault.armConflictOnce()
			}
		}
		f.setListenerHostname("edge-b.example.com")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.fault.injected()).To(gomega.Equal(1),
			"the injected CAS conflict must fire exactly once on the promotion commit")
		gomega.Expect(f.remote.updates).To(gomega.Equal(updatesBefore+1),
			"the status retry must not replay UpdateTunnelConfiguration")
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-17: with DriftPolicy=Overwrite an out-of-band remote change is
	// detected, overwritten, and the tunnel reconverges.
	ginkgo.It("QA-92-17 detects out-of-band drift and overwrites it", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{driftPolicy: DriftPolicyOverwrite})
		f.converge()

		f.remote.remoteVersion += 5 // out-of-band remote write
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		drift := f.condition(v1alpha1.CloudflareTunnelConditionDriftDetected)
		gomega.Expect(drift.Status).To(gomega.Equal(metav1.ConditionTrue))

		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionDriftDetected).Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
	})

	// QA-92-18: with DriftPolicy=Hold the pass stops before the gate, reports
	// DriftDetected and DriftHold, and never touches the remote.
	ginkgo.It("QA-92-18 holds drifted remote state without writing", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{driftPolicy: DriftPolicyHold})
		f.converge()

		f.remote.remoteVersion += 5 // out-of-band remote write
		updatesBefore := f.remote.updates
		result, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.RequeueAfter).To(gomega.BeNumerically(">", 0))

		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionDriftDetected).Status).To(gomega.Equal(metav1.ConditionTrue))
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Reason).To(gomega.Equal("DriftHold"))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.remote.updates).To(gomega.Equal(updatesBefore), "Hold must not write the remote")
	})

	// QA-92-19: losing the xDS ACK after convergence demotes ConfigApplied to a
	// real False transition; re-ACKing reconverges.
	ginkgo.It("QA-92-19 demotes ConfigApplied when the ACKed snapshot is lost", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		transition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).LastTransitionTime

		gomega.Expect(f.snapshots.NACK(f.gatewayKey.String(), "stream reset")).To(gomega.Succeed())
		f.clock = f.clock.Add(time.Minute)
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		demoted := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(demoted.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(demoted.Reason).To(gomega.Equal("Pending"))
		gomega.Expect(demoted.LastTransitionTime.After(transition.Time)).To(gomega.BeTrue())
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionFalse))

		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-20: an unready Pod or a stale /config version keeps the gate open.
	ginkgo.It("QA-92-20 keeps ConfigApplied=False while dataplane Pods lag", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()

		f.prober.readyErr = errors.New("not ready")
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Message).To(gomega.ContainSubstring("not ready"))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))

		f.prober.readyErr = nil
		f.prober.version = f.remote.remoteVersion - 1
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		condition = f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Message).To(gomega.ContainSubstring("version"))

		f.prober.version = f.remote.remoteVersion
		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-21: in managed DNS mode a missing record keeps the gate open until
	// the tunnel controller creates it. The CreateCNAME failure is armed on
	// the fixture's own tunnel Cloudflare fake before provisioning so the
	// record is absent from the first pass.
	ginkgo.It("QA-92-21 keeps ConfigApplied=False while managed DNS records are absent", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			dnsMode: v1alpha1.DNSModeManaged,
			beforeProvision: func(f *qa92Fixture) {
				f.tunnelRemote.FailNext("CreateCNAME", errors.New("dns backend unavailable"))
			},
		})

		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Message).To(gomega.ContainSubstring("DNS"))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))

		f.tunnelRemote.ClearFailure("CreateCNAME")
		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-22: a pending private listener blocks the gate and reports the
	// private-listener category on the tunnel condition.
	ginkgo.It("QA-92-22 blocks the gate while a private listener is pending", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{privateListener: true})
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))
		degraded := f.condition(v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded)
		gomega.Expect(degraded.Reason).To(gomega.Equal("Pending"))
		gomega.Expect(degraded.Message).NotTo(gomega.BeEmpty())
	})

	// QA-92-26: a spec change that lands between the observed tunnel snapshot
	// and the writer revalidation must abort the pass: no remote mutation and
	// no promotion of state compiled from the stale snapshot.
	ginkgo.It("QA-92-26 aborts when the tunnel generation changes before writer validation", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.converge()
		oldHash := f.tunnel().Status.ConfigVersion.DesiredHash
		updatesBefore := f.remote.updates

		race := &qa92GenerationRaceReader{reader: f.direct, tunnelKey: f.tunnelKey, direct: f.direct}
		f.reconciler.APIReader = race

		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).To(gomega.HaveOccurred(),
			"a generation change before writer validation must abort the pass")
		gomega.Expect(race.fired).To(gomega.BeTrue(), "the interposed spec change never ran")
		gomega.Expect(f.remote.updates).To(gomega.Equal(updatesBefore),
			"stale observed state must never reach the remote")
		persisted := f.tunnel()
		gomega.Expect(persisted.Status.ConfigVersion.DesiredHash).To(gomega.Equal(oldHash))
		gomega.Expect(persisted.Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion),
			"no version may be promoted from a stale observed snapshot")

		f.reconciler.APIReader = f.direct
		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
	})

	// QA-92-26/29 provenance: the post-write data checkpoint must not land on
	// a Tunnel whose identity or generation moved after this pass observed
	// it. The mutation is interposed between UpdateTunnelConfiguration's
	// return and the checkpoint apply — the window where an unguarded
	// name-only SSA write would stamp the old pass's
	// configVersion/hostnames/listeners onto a moved object.
	ginkgo.DescribeTable("QA-92-26/29 keeps the post-write checkpoint off a moved Tunnel",
		func(mutate func(f *qa92Fixture), verify func(f *qa92Fixture, oldUID types.UID, oldHash string)) {
			f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
			f.converge()
			oldUID := f.tunnel().UID
			oldHash := f.tunnel().Status.ConfigVersion.DesiredHash

			f.remote.afterUpdate = func() { mutate(f) }
			f.setListenerHostname("edge-b.example.com")
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).To(gomega.HaveOccurred(),
				"a Tunnel identity or generation change before the checkpoint must abort the pass")
			verify(f, oldUID, oldHash)
		},
		// The Tunnel is deleted and recreated under the same name and spec
		// with a fresh UID and empty status: nothing from the old pass may
		// persist onto the replacement object.
		ginkgo.Entry("tunnel deleted and recreated with a new UID",
			func(f *qa92Fixture) {
				var doomed v1alpha1.CloudflareTunnel
				gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &doomed)).To(gomega.Succeed())
				doomed.SetFinalizers(nil)
				gomega.Expect(f.direct.Update(f.ctx, &doomed)).To(gomega.Succeed())
				gomega.Expect(f.direct.Delete(f.ctx, &doomed)).To(gomega.Succeed())
				replacement := &v1alpha1.CloudflareTunnel{
					ObjectMeta: metav1.ObjectMeta{Name: doomed.Name, Namespace: doomed.Namespace},
					Spec:       doomed.Spec,
				}
				gomega.Expect(f.direct.Create(f.ctx, replacement)).To(gomega.Succeed())
			},
			func(f *qa92Fixture, oldUID types.UID, _ string) {
				var current v1alpha1.CloudflareTunnel
				gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &current)).To(gomega.Succeed())
				gomega.Expect(current.UID).NotTo(gomega.Equal(oldUID))
				gomega.Expect(current.Status.ConfigVersion).To(gomega.Equal(v1alpha1.CloudflareTunnelConfigVersion{}),
					"the checkpoint must not stamp the old pass's configVersion onto a replacement Tunnel")
				gomega.Expect(current.Status.Hostnames).To(gomega.BeEmpty())
				gomega.Expect(current.Status.Listeners).To(gomega.BeEmpty())
			}),
		// The same Tunnel object advances a generation between the provider
		// write and the checkpoint: the hash compiled from the stale
		// generation must not be recorded.
		ginkgo.Entry("tunnel generation bumps under the same UID",
			func(f *qa92Fixture) {
				var current v1alpha1.CloudflareTunnel
				gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &current)).To(gomega.Succeed())
				current.Spec.DNS.RecordComment = "qa92 interposed spec change"
				gomega.Expect(f.direct.Update(f.ctx, &current)).To(gomega.Succeed())
			},
			func(f *qa92Fixture, _ types.UID, oldHash string) {
				persisted := f.tunnel()
				gomega.Expect(persisted.Status.ConfigVersion.DesiredHash).To(gomega.Equal(oldHash),
					"the checkpoint must not record a hash compiled from a stale generation")
			}),
	)

	// QA-92-14b/19/20 discriminator: the outer gate passes but convergence is
	// lost before the promotion commit. The pass must demote the tunnel,
	// publish Programmed=False, and requeue as ordinary pending — never
	// surface a raw error that leaves a stale True behind.
	ginkgo.DescribeTable("QA-92-14b/19/20 promotion-gate convergence loss demotes and stays pending",
		func(lose func(f *qa92Fixture)) {
			f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
			f.converge()
			f.setListenerHostname("edge-b.example.com")
			lose(f)

			result, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(),
				"convergence lost before promotion is ordinary pending, not an error")
			gomega.Expect(result.RequeueAfter).To(gomega.BeNumerically(">", 0))

			persisted := f.tunnel()
			// The outer gate did observe convergence to the new version before
			// the promotion guard lost it, so Applied honestly records that
			// observation; readiness is carried by ConfigApplied/Ready, not by
			// withholding the version. Reverting Applied would create a false
			// drift baseline and force a replayed provider write next pass.
			gomega.Expect(persisted.Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion),
				"Applied records the last gate-observed version; ConfigApplied/Ready carry readiness")
			gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionFalse))
			gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionFalse))
			gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse),
				"Programmed=False must be published even when the promotion commit fails")

			f.snapshots.onIsACKed = nil
			f.prober.onConfigVersion = nil
			f.converge()
			gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		},
		// The xDS ACK is lost between the outer gate and the promotion guard.
		// afterUpdate publishes the ACK and the fresh Pod version so the outer
		// gate passes; the second IsACKed call — the promotion guard — NACKs.
		ginkgo.Entry("ACK lost at promotion", func(f *qa92Fixture) {
			f.remote.afterUpdate = func() {
				gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
				f.prober.version = f.remote.remoteVersion
			}
			calls := 0
			f.snapshots.onIsACKed = func() {
				calls++
				if calls == 2 {
					gomega.Expect(f.snapshots.NACK(f.gatewayKey.String(), "stream reset")).To(gomega.Succeed())
				}
			}
		}),
		// The dataplane Pod version regresses between the outer gate and the
		// promotion guard's gate re-evaluation.
		ginkgo.Entry("Pod version regresses at promotion", func(f *qa92Fixture) {
			f.remote.afterUpdate = func() {
				gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
				f.prober.version = f.remote.remoteVersion
			}
			calls := 0
			f.prober.onConfigVersion = func() {
				calls++
				if calls == 2 {
					f.prober.version = f.remote.remoteVersion - 1
				}
			}
		}),
	)
})

// qa92FixtureOptions selects fixture variations per spec.
type qa92FixtureOptions struct {
	dnsMode         v1alpha1.DNSMode
	privateListener bool
	driftPolicy     DriftPolicy
	// beforeProvision runs after the fixture's reconcilers are wired but
	// before the account/tunnel provisioning loop, so a spec can arm a fault
	// on the fixture's own fakes (for example a failing CreateCNAME) that
	// must be present from the first provisioning pass.
	beforeProvision func(f *qa92Fixture)
}

// qa92TunnelSnapshot is the persisted tunnel status observed mid-pass.
type qa92TunnelSnapshot struct {
	conditions []metav1.Condition
	config     v1alpha1.CloudflareTunnelConfigVersion
}

// qa92Fixture wires one Gateway/tunnel pair on a dedicated envtest control
// plane to a dedicated reconciler whose outer boundaries are observable
// fakes. The fixture's own CloudflareAccountReconciler and
// CloudflareTunnelReconciler provision the tunnel through explicit Reconcile
// calls, so ownership, credentials, and tunnel-owned conditions are produced
// by production code without any suite manager racing the spec.
type qa92Fixture struct {
	ctx              context.Context
	direct           client.Client
	fault            *qa92FaultClient
	reconciler       *GatewayReconciler
	tunnelReconciler *CloudflareTunnelReconciler
	request          ctrl.Request
	tunnelRequest    ctrl.Request
	remote           *qa92CloudflareAPI
	accountRemote    *fakeAccountCloudflareFactory
	tunnelRemote     *fakeTunnelCloudflareFactory
	prober           *qa92Prober
	snapshots        *qa92SnapshotPublisher
	clock            time.Time
	gatewayKey       types.NamespacedName
	tunnelKey        types.NamespacedName
}

func newQA92Fixture(t ginkgo.GinkgoTInterface, opts qa92FixtureOptions) *qa92Fixture {
	fixtureID := fixtureCounter.Add(1)
	namespaceName := fmt.Sprintf("qa92-%d", fixtureID)
	tenant := fmt.Sprintf("qa92-%d", fixtureID)
	accountName := fmt.Sprintf("qa92-account-%d", fixtureID)
	accountID := "0123456789abcdef0123456789abcdef"
	configName := fmt.Sprintf("qa92-config-%d", fixtureID)
	className := fmt.Sprintf("qa92-class-%d", fixtureID)
	tunnelName := fmt.Sprintf("qa92-tunnel-%d", fixtureID)
	gatewayName := fmt.Sprintf("qa92-edge-%d", fixtureID)
	hostnames := []string{"edge-a.example.com", "edge-b.example.com"}
	dnsMode := opts.dnsMode
	if dnsMode == "" {
		dnsMode = v1alpha1.DNSModeExternal
	}

	// Each fixture owns its control plane end to end: no suite manager,
	// informer cache, or shared fake can interleave writes with a fault
	// scenario or overwrite a staged condition observation.
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join(gatewayAPIModuleDirectory(), "config", "crd", "standard"),
		},
		ErrorIfCRDPathMissing: true,
	}
	restConfig, err := env.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(restConfig).NotTo(gomega.BeNil())
	ginkgo.DeferCleanup(func() { gomega.Expect(env.Stop()).To(gomega.Succeed()) })

	scheme := runtime.NewScheme()
	gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
	gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
	gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

	ctx, cancel := context.WithCancel(context.Background())
	ginkgo.DeferCleanup(cancel)

	direct, err := client.New(restConfig, client.Options{Scheme: scheme})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	f := &qa92Fixture{
		ctx:        ctx,
		direct:     direct,
		gatewayKey: types.NamespacedName{Namespace: namespaceName, Name: gatewayName},
		tunnelKey:  types.NamespacedName{Namespace: namespaceName, Name: tunnelName},
		clock:      time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	f.remote = &qa92CloudflareAPI{accountID: accountID}
	f.accountRemote = newFakeAccountCloudflareFactory()
	f.tunnelRemote = newFakeTunnelCloudflareFactory()
	f.prober = &qa92Prober{reader: direct, key: f.tunnelKey}
	f.snapshots = &qa92SnapshotPublisher{publisher: newFakeSnapshotPublisher()}
	f.fault = &qa92FaultClient{Client: direct, tunnelName: tunnelName}
	f.reconciler = &GatewayReconciler{
		Client:            f.fault,
		APIReader:         direct,
		Scheme:            scheme,
		Snapshots:         f.snapshots,
		BuildSnapshot:     controlledSnapshotBuild,
		CloudflareFactory: gatewayCloudflareFactory{api: f.remote},
		Prober:            f.prober,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		DriftPolicy:       opts.driftPolicy,
		Now:               func() time.Time { return f.clock },
	}
	f.tunnelReconciler = &CloudflareTunnelReconciler{
		Client:              direct,
		APIReader:           direct,
		Scheme:              scheme,
		NewCloudflareClient: f.tunnelRemote.Client,
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
	}
	accountReconciler := &CloudflareAccountReconciler{
		Client:     direct,
		Scheme:     scheme,
		Cloudflare: f.accountRemote,
	}
	f.request = ctrl.Request{NamespacedName: f.gatewayKey}
	f.tunnelRequest = ctrl.Request{NamespacedName: f.tunnelKey}
	accountRequest := ctrl.Request{NamespacedName: types.NamespacedName{Name: accountName}}

	operatorNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}
	if err := direct.Create(ctx, operatorNamespace); err != nil {
		gomega.Expect(apierrors.IsAlreadyExists(err)).To(gomega.BeTrue())
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName, Labels: map[string]string{"tenant": tenant}}}
	gomega.Expect(direct.Create(ctx, namespace)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = direct.Delete(context.Background(), namespace) })

	credential := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: namespaceName},
		Data:       map[string][]byte{"token": []byte("test-token")},
	}
	gomega.Expect(direct.Create(ctx, credential)).To(gomega.Succeed())

	grant := v1alpha1.CloudflareAccountGrant{
		NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": tenant}},
		Hostnames:            append([]string(nil), hostnames...),
		Zones:                []string{"example.com"},
		Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		UnprotectedHostnames: append([]string(nil), hostnames...),
	}
	if opts.privateListener {
		grant.Hostnames = append(grant.Hostnames, "private.internal.example")
		grant.Exposures = append(grant.Exposures, v1alpha1.ExposurePrivate)
		grant.PlatformObjects = v1alpha1.GrantPermissionAllowed
	}
	// Public listener bindings resolve against the account's verified zones;
	// without them the tunnel reconciler rejects the spec and never
	// provisions. The zones live on the fixture's own account fake.
	f.accountRemote.mu.Lock()
	f.accountRemote.zones = []flarecloudflare.Zone{
		{ID: "zone-example", Name: "example.com", AccountID: accountID},
	}
	f.accountRemote.mu.Unlock()
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: credential.Name, Namespace: credential.Namespace, Key: "token"},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{grant},
		},
	}
	gomega.Expect(direct.Create(ctx, account)).To(gomega.Succeed())

	config := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: configName},
		Spec:       v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: accountName}},
	}
	gomega.Expect(direct.Create(ctx, config)).To(gomega.Succeed())

	class := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: className},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef: &gatewayv1.ParametersReference{
				Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("GatewayClassConfig"), Name: configName,
			},
		},
	}
	gomega.Expect(direct.Create(ctx, class)).To(gomega.Succeed())

	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: namespaceName},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: accountName},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: dnsMode},
		},
	}
	if opts.privateListener {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "listener-cert", Namespace: namespaceName},
			Type:       corev1.SecretTypeTLS,
			Data:       qa92TLSSecretData(t),
		}
		gomega.Expect(direct.Create(ctx, tlsSecret)).To(gomega.Succeed())
		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
			Name: "private", Exposure: v1alpha1.ExposurePrivate,
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: "missing-vnet"},
		}}
	}
	gomega.Expect(direct.Create(ctx, tunnel)).To(gomega.Succeed())

	publicHostname := gatewayv1.Hostname(hostnames[0])
	listeners := []gatewayv1.Listener{
		{Name: "http", Hostname: &publicHostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
	}
	if opts.privateListener {
		privateHostname := gatewayv1.Hostname("private.internal.example")
		listeners = append(listeners, gatewayv1.Listener{
			Name: "private", Hostname: &privateHostname, Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{
				CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}},
			},
		})
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespaceName},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: tunnelName},
			},
			Listeners: listeners,
		},
	}
	gomega.Expect(direct.Create(ctx, gateway)).To(gomega.Succeed())

	var liveGateway gatewayv1.Gateway
	gomega.Expect(direct.Get(ctx, f.gatewayKey, &liveGateway)).To(gomega.Succeed())

	if opts.beforeProvision != nil {
		opts.beforeProvision(f)
	}

	// The fixture's own reconcilers are stepped explicitly: the account pass
	// publishes Verified.Zones, then the tunnel passes provision the remote
	// tunnel, capture credentials, and record the UID-bound Gateway ownership
	// the Gateway writer requires. A tunnel reconcile error (for example an
	// armed CreateCNAME failure) does not abort the loop — the persisted
	// status checkpoint is what must converge.
	var lastReconcileErr error
	gomega.Eventually(func(g gomega.Gomega) {
		_, lastReconcileErr = accountReconciler.Reconcile(ctx, accountRequest)
		g.Expect(lastReconcileErr).NotTo(gomega.HaveOccurred())
		_, lastReconcileErr = f.tunnelReconciler.Reconcile(ctx, f.tunnelRequest)
		var current v1alpha1.CloudflareTunnel
		g.Expect(direct.Get(ctx, f.tunnelKey, &current)).To(gomega.Succeed())
		g.Expect(current.Status.TunnelID).NotTo(gomega.BeEmpty())
		g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		g.Expect(current.Status.ConnectorTokenSecretRef).NotTo(gomega.BeNil())
		g.Expect(current.Status.GatewayRef).NotTo(gomega.BeNil())
		g.Expect(current.Status.GatewayRef.Name).To(gomega.Equal(gatewayName))
		g.Expect(current.Status.GatewayUID).To(gomega.Equal(liveGateway.UID))
	}, 20*time.Second, 100*time.Millisecond).Should(gomega.Succeed(),
		"tunnel provisioning never completed; last reconcile error: %v", lastReconcileErr)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dataplane-0", Namespace: namespaceName,
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: gatewayName},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "example.invalid/cloudflared:latest"}}},
	}
	gomega.Expect(direct.Create(ctx, pod)).To(gomega.Succeed())
	pod.Status.Phase = corev1.PodRunning
	pod.Status.PodIP = "10.0.0.7"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	gomega.Expect(direct.Status().Update(ctx, pod)).To(gomega.Succeed())

	return f
}

// converge reconciles until the programming gate closes: each pass ACKs the
// freshly published snapshot, reports the current remote version from the
// dataplane probe, and steps the fixture's tunnel reconciler so managed DNS
// and other tunnel-owned status keep pace deterministically.
func (f *qa92Fixture) converge() {
	_, err := f.reconciler.Reconcile(f.ctx, f.request)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		f.prober.version = f.remote.remoteVersion
		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		g.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		_, reconcileErr := f.reconciler.Reconcile(f.ctx, f.request)
		g.Expect(reconcileErr).NotTo(gomega.HaveOccurred())
		condition := f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
	}, 30*time.Second, 50*time.Millisecond).Should(gomega.Succeed())
}

func (f *qa92Fixture) tunnel() *v1alpha1.CloudflareTunnel {
	var current v1alpha1.CloudflareTunnel
	gomega.ExpectWithOffset(1, f.direct.Get(f.ctx, f.tunnelKey, &current)).To(gomega.Succeed())
	return &current
}

func (f *qa92Fixture) snapshotTunnel() qa92TunnelSnapshot {
	current := f.tunnel()
	return qa92TunnelSnapshot{conditions: current.Status.Conditions, config: current.Status.ConfigVersion}
}

func (f *qa92Fixture) condition(conditionType string) metav1.Condition {
	condition := meta.FindStatusCondition(f.tunnel().Status.Conditions, conditionType)
	gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil(), "tunnel condition %s missing", conditionType)
	return *condition
}

func (f *qa92Fixture) gatewayProgrammed() metav1.Condition {
	var current gatewayv1.Gateway
	gomega.ExpectWithOffset(1, f.direct.Get(f.ctx, f.gatewayKey, &current)).To(gomega.Succeed())
	condition := meta.FindStatusCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil())
	return *condition
}

// setListenerHostname flips the public listener hostname between the two
// granted names, which changes the compiled cloudflared configuration hash.
func (f *qa92Fixture) setListenerHostname(hostname string) {
	gomega.EventuallyWithOffset(1, func() error {
		var current gatewayv1.Gateway
		if err := f.direct.Get(f.ctx, f.gatewayKey, &current); err != nil {
			return err
		}
		value := gatewayv1.Hostname(hostname)
		current.Spec.Listeners[0].Hostname = &value
		return f.direct.Update(f.ctx, &current)
	}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
}

// qa92TLSSecretData generates a self-signed certificate accepted by the
// listener ResolvedRefs validation.
func qa92TLSSecretData(t ginkgo.GinkgoTInterface) map[string][]byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "private.internal.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"private.internal.example"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}),
	}
}

// qa92CloudflareAPI is a stateful Cloudflare fake: every committed
// UpdateTunnelConfiguration bumps the remote version like the real edge, and
// hooks expose the outer boundaries for observation and fault injection.
type qa92CloudflareAPI struct {
	flarecloudflare.API
	accountID     string
	remoteVersion int64
	updates       int
	locks         int

	getConfigErr error
	updateErr    error
	onGetConfig  func()
	beforeUpdate func()
	afterUpdate  func()
}

var _ flarecloudflare.API = (*qa92CloudflareAPI)(nil)

func (api *qa92CloudflareAPI) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	api.locks++
	return fn()
}

func (api *qa92CloudflareAPI) GetTunnel(_ context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	return flarecloudflare.Tunnel{
		ID:           tunnelID,
		AccountTag:   api.accountID,
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *qa92CloudflareAPI) UpdateTunnelName(ctx context.Context, tunnelID, name string) (flarecloudflare.Tunnel, error) {
	tunnel, err := api.GetTunnel(ctx, tunnelID)
	if err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	tunnel.Name = name
	return tunnel, nil
}

func (api *qa92CloudflareAPI) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	if api.onGetConfig != nil {
		api.onGetConfig()
	}
	if api.getConfigErr != nil {
		return flarecloudflare.TunnelConfiguration{}, api.getConfigErr
	}
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID,
		TunnelID:  tunnelID,
		Version:   api.remoteVersion,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *qa92CloudflareAPI) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	if api.beforeUpdate != nil {
		api.beforeUpdate()
	}
	if api.updateErr != nil {
		return flarecloudflare.TunnelConfiguration{}, api.updateErr
	}
	api.updates++
	api.remoteVersion++
	if api.afterUpdate != nil {
		api.afterUpdate()
	}
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID,
		TunnelID:  tunnelID,
		Version:   api.remoteVersion,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (*qa92CloudflareAPI) IssueTunnelManagementToken(context.Context, string, []flarecloudflare.TunnelManagementResource) (string, error) {
	return "test-management-token", nil
}

func (*qa92CloudflareAPI) GetTunnelConnector(_ context.Context, _ string, connectorID string, _ int64) (flarecloudflare.TunnelConnector, error) {
	return flarecloudflare.TunnelConnector{ID: connectorID}, nil
}

func (*qa92CloudflareAPI) ListTunnelConnections(context.Context, string, int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	return nil, false, nil
}

func (*qa92CloudflareAPI) EvictTunnelConnections(context.Context, string, *string) error {
	return nil
}

func (*qa92CloudflareAPI) GetDeviceSettings(context.Context) (flarecloudflare.DeviceSettings, error) {
	return flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}, nil
}

// qa92Prober reports a configurable dataplane state and can capture the
// persisted tunnel status at the moment the gate probes it.
type qa92Prober struct {
	version         int64
	readyErr        error
	reader          client.Reader
	key             types.NamespacedName
	record          bool
	onReady         func()
	onConfigVersion func()
	observed        []qa92TunnelSnapshot
}

func (prober *qa92Prober) capture(ctx context.Context) {
	if !prober.record {
		return
	}
	var tunnel v1alpha1.CloudflareTunnel
	gomega.Expect(prober.reader.Get(ctx, prober.key, &tunnel)).To(gomega.Succeed())
	condition := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
	gomega.Expect(condition).NotTo(gomega.BeNil())
	prober.observed = append(prober.observed, qa92TunnelSnapshot{conditions: tunnel.Status.Conditions, config: tunnel.Status.ConfigVersion})
}

func (prober *qa92Prober) ConfigVersion(ctx context.Context, _ string) (int64, error) {
	prober.capture(ctx)
	if prober.onConfigVersion != nil {
		prober.onConfigVersion()
	}
	return prober.version, nil
}

func (prober *qa92Prober) Ready(ctx context.Context, _ string) error {
	prober.capture(ctx)
	if prober.onReady != nil {
		prober.onReady()
	}
	return prober.readyErr
}

// qa92SnapshotPublisher wraps the fixture's own fake publisher with an
// observation hook on the ACK check — the last gate input evaluated before
// the promotion commit.
type qa92SnapshotPublisher struct {
	publisher *fakeSnapshotPublisher
	onIsACKed func()
}

var _ SnapshotPublisher = (*qa92SnapshotPublisher)(nil)

func (p *qa92SnapshotPublisher) SetSnapshot(ctx context.Context, key string, snapshot *cachev3.Snapshot) error {
	return p.publisher.SetSnapshot(ctx, key, snapshot)
}

func (p *qa92SnapshotPublisher) ClearSnapshot(key string) { p.publisher.ClearSnapshot(key) }

func (p *qa92SnapshotPublisher) IsACKed(key, version string) bool {
	if p.onIsACKed != nil {
		p.onIsACKed()
	}
	return p.publisher.IsACKed(key, version)
}

func (p *qa92SnapshotPublisher) LastNACK(key string) (string, string, bool) {
	return p.publisher.LastNACK(key)
}

func (p *qa92SnapshotPublisher) ACK(key string) error { return p.publisher.ACK(key) }

func (p *qa92SnapshotPublisher) NACK(key, detail string) error { return p.publisher.NACK(key, detail) }

// qa92FaultClient injects failures into tunnel status writes after arming:
// arm fails the Nth write with a generic error, armConflictOnce fails the
// next write with a real 409 Conflict so the production CAS retry loop runs.
// It faults only the outer client boundary; production logic is untouched.
type qa92FaultClient struct {
	client.Client
	tunnelName string
	mu         sync.Mutex
	armed      bool
	conflict   bool
	failAt     int
	writes     int
	fired      int
}

func (c *qa92FaultClient) arm(failAt int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
	c.conflict = false
	c.failAt = failAt
	c.writes = 0
}

// armConflictOnce makes the next tunnel status write fail with a 409
// Conflict — the error the resourceVersion-pinned conditions apply produces
// when the live object moved between read and apply. The injection self-
// disarms so the production retry commits against the fresh live object.
func (c *qa92FaultClient) armConflictOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
	c.conflict = true
}

func (c *qa92FaultClient) disarm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = false
	c.conflict = false
}

// injected reports how many faults have fired.
func (c *qa92FaultClient) injected() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fired
}

func (c *qa92FaultClient) fail(obj client.Object) error {
	tunnel, ok := obj.(*v1alpha1.CloudflareTunnel)
	if !ok {
		return nil
	}
	return c.failName(tunnel.Name)
}

func (c *qa92FaultClient) failName(name string) error {
	if name != c.tunnelName {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.armed {
		return nil
	}
	if c.conflict {
		c.conflict = false
		c.armed = false
		c.fired++
		return apierrors.NewConflict(v1alpha1.GroupVersion.WithResource("cloudflaretunnels").GroupResource(), name, errors.New("qa92 injected CAS conflict"))
	}
	c.writes++
	if c.writes == c.failAt {
		c.fired++
		return errors.New("qa92 injected status write failure")
	}
	return nil
}

func (c *qa92FaultClient) Status() client.SubResourceWriter {
	return &qa92FaultStatusWriter{writer: c.Client.Status(), owner: c}
}

type qa92FaultStatusWriter struct {
	writer client.SubResourceWriter
	owner  *qa92FaultClient
}

func (w *qa92FaultStatusWriter) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	return w.writer.Create(ctx, obj, subResource, opts...)
}

func (w *qa92FaultStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if err := w.owner.fail(obj); err != nil {
		return err
	}
	return w.writer.Update(ctx, obj, opts...)
}

func (w *qa92FaultStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if err := w.owner.fail(obj); err != nil {
		return err
	}
	return w.writer.Patch(ctx, obj, patch, opts...)
}

func (w *qa92FaultStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	name := ""
	switch typed := obj.(type) {
	case client.Object:
		name = typed.GetName()
	case interface{ GetName() *string }:
		if value := typed.GetName(); value != nil {
			name = *value
		}
	}
	if err := w.owner.failName(name); err != nil {
		return err
	}
	return w.writer.Apply(ctx, obj, opts...)
}

// qa92GenerationRaceReader interposes a CloudflareTunnel spec change the first
// time the reconciler's direct reader fetches the tunnel during a pass — the
// boundary between the observed snapshot and the writer revalidation.
type qa92GenerationRaceReader struct {
	reader    client.Reader
	direct    client.Client
	tunnelKey types.NamespacedName
	fired     bool
}

func (r *qa92GenerationRaceReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*v1alpha1.CloudflareTunnel); ok && key == r.tunnelKey && !r.fired {
		r.fired = true
		// Retry on conflict: a status write between the read and the update
		// bumps the resourceVersion.
		gomega.Eventually(func() error {
			var current v1alpha1.CloudflareTunnel
			if err := r.direct.Get(ctx, r.tunnelKey, &current); err != nil {
				return err
			}
			current.Spec.DNS.RecordComment = "qa92 interposed spec change"
			return r.direct.Update(ctx, &current)
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.Succeed())
	}
	return r.reader.Get(ctx, key, obj, opts...)
}

func (r *qa92GenerationRaceReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return r.reader.List(ctx, list, opts...)
}
