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

// Observable-contract tests for the shared CloudflareTunnel conditions
// transaction (issue #92, design 002). Each spec boots its OWN envtest
// control plane — independent etcd + apiserver, same CRDs as the suite — and
// talks to it through a single uncached client. No manager and no
// reconcilers run against it, so every read-after-write is a deterministic,
// single-threaded, scripted interleaving of the real production status
// writers and the shared patchTunnelConditions helper.
//
// Coverage map (docs/qa/issue-92-status-consistency.md):
//   QA-92-16a/b — transient/persistent CAS conflict with real interleaved writes
//   QA-92-23    — Gateway ConfigApplied=False commit atomically demotes Ready
//   QA-92-24    — stale tunnel snapshot cannot resurrect Ready over live False
//   QA-92-26    — stale generation aborts without writing
//   QA-92-03/26 — no-input pass carries Ready and inputs verbatim across a generation bump
//   QA-92-27    — mutation inside the read-to-apply window: retry or abort
//   QA-92-29    — promotion refused on mode/deletedAt/UID provenance mismatch or a deleted live object
//   QA-92-30a   — ownership migration precedes data-only applies that omit conditions
//   QA-92-30b   — equal values do not skip ownership transfer
//   QA-92-30c   — foreign-owned conditions preserved; no-op passes stay write-free
//   QA-92-31    — legacy torn pair clamped to Ready=False on first pass
//   QA-92-32    — Direct mode: single-transaction ConfigApplied+Ready; Gateway rejected with zero tunnel writes
//   QA-92-33    — ObserveOnly reconcile is read-only; Ready=False/ObserveOnly
//   QA-92-34    — teardown: ConfigApplied never flaps; drain gates finalizer release

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

// startIsolatedConditionsPlane boots a dedicated envtest API server with the
// same CRDs as the suite but no manager: nothing reconciles and nothing
// writes except the spec itself. Returns an uncached client and registers
// env teardown.
func startIsolatedConditionsPlane() client.Client {
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join(gatewayAPIModuleDirectory(), "config", "crd", "standard"),
		},
		ErrorIfCRDPathMissing: true,
	}
	config, err := env.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(config).NotTo(gomega.BeNil())
	ginkgo.DeferCleanup(func() { gomega.Expect(env.Stop()).To(gomega.Succeed()) })

	scheme := runtime.NewScheme()
	gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
	gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
	gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

	direct, err := client.New(config, client.Options{Scheme: scheme})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return direct
}

type tunnelConditionsFixture struct {
	direct    client.Client
	namespace string
	name      string
	key       types.NamespacedName
}

func newTunnelConditionsFixture(direct client.Client, spec v1alpha1.CloudflareTunnelSpec) *tunnelConditionsFixture {
	fixtureID := fixtureCounter.Add(1)
	fixture := &tunnelConditionsFixture{
		direct:    direct,
		namespace: fmt.Sprintf("tunnel-conditions-%d", fixtureID),
		name:      fmt.Sprintf("tunnel-%d", fixtureID),
	}
	fixture.key = types.NamespacedName{Namespace: fixture.namespace, Name: fixture.name}
	gomega.ExpectWithOffset(1, direct.Create(testContext, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: fixture.namespace},
	})).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, direct.Create(testContext, &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: fixture.name, Namespace: fixture.namespace},
		Spec:       spec,
	})).To(gomega.Succeed())
	return fixture
}

func managedTunnelSpec() v1alpha1.CloudflareTunnelSpec {
	return v1alpha1.CloudflareTunnelSpec{
		AccountRef:       corev1.LocalObjectReference{Name: "unused-account"},
		ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
	}
}

func directTunnelSpec() v1alpha1.CloudflareTunnelSpec {
	spec := managedTunnelSpec()
	spec.Configuration = v1alpha1.CloudflareTunnelConfiguration{
		Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
		Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
			Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
				Service: v1alpha1.CloudflareTunnelIngressService{
					HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404},
				},
			}},
		},
	}
	return spec
}

func (f *tunnelConditionsFixture) live() *v1alpha1.CloudflareTunnel {
	var tunnel v1alpha1.CloudflareTunnel
	gomega.ExpectWithOffset(1, f.direct.Get(testContext, f.key, &tunnel)).To(gomega.Succeed())
	return &tunnel
}

func (f *tunnelConditionsFixture) condition(conditionType string) *metav1.Condition {
	return meta.FindStatusCondition(f.live().Status.Conditions, conditionType)
}

func (f *tunnelConditionsFixture) requireCondition(conditionType string) metav1.Condition {
	condition := f.condition(conditionType)
	gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil(), "condition %s must be persisted", conditionType)
	return *condition
}

// createGateway creates the owning Gateway and seeds the verified, UID-bound
// ownership scalars the Gateway status writer requires. Scalar seeding via
// Update is fixture plumbing; every condition in these specs is written by a
// production writer or the shared helper.
func (f *tunnelConditionsFixture) createGateway() (*gatewayv1.Gateway, *ir.Gateway) {
	hostname := gatewayv1.Hostname("edge.example.com")
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: f.namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("no-such-class"),
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: f.name,
				},
			},
			Listeners: []gatewayv1.Listener{{
				Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	gomega.ExpectWithOffset(1, f.direct.Create(testContext, gateway)).To(gomega.Succeed())

	var seeded v1alpha1.CloudflareTunnel
	gomega.ExpectWithOffset(1, f.direct.Get(testContext, f.key, &seeded)).To(gomega.Succeed())
	seeded.Status.TunnelID = "22222222-2222-2222-2222-222222222222"
	seeded.Status.AccountID = "0123456789abcdef0123456789abcdef"
	seeded.Status.OwnershipVerified = true
	seeded.Status.ConnectorTokenSecretRef = &corev1.LocalObjectReference{Name: "connector-token"}
	seeded.Status.GatewayRef = &corev1.LocalObjectReference{Name: gateway.Name}
	seeded.Status.GatewayUID = gateway.UID
	gomega.ExpectWithOffset(1, f.direct.Status().Update(testContext, &seeded)).To(gomega.Succeed())

	return gateway, &ir.Gateway{Key: client.ObjectKeyFromObject(gateway), UID: gateway.UID}
}

// interposingReader wraps the fresh-read path of patchTunnelConditions. onGet
// runs after each real Get returns — between the helper's basis read and its
// CAS apply — so a write performed there deterministically lands inside the
// read-to-apply window.
type interposingReader struct {
	inner client.Reader
	onGet func(key types.NamespacedName)
}

func (r *interposingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.inner.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if r.onGet != nil {
		r.onGet(key)
	}
	return nil
}

func (r *interposingReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return r.inner.List(ctx, list, opts...)
}

// countingApplier wraps a client and counts status Apply calls that reach the
// API server — the observable cost of a conditions pass. A repeated identical
// pass must issue zero applies even while a legacy manager still co-owns the
// condition entries.
type countingApplier struct {
	client.Client
	applies int
}

func (c *countingApplier) Status() client.SubResourceWriter {
	return &countingStatusWriter{inner: c.Client.Status(), count: &c.applies}
}

type countingStatusWriter struct {
	inner client.SubResourceWriter
	count *int
}

func (w *countingStatusWriter) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	return w.inner.Create(ctx, obj, subResource, opts...)
}

func (w *countingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return w.inner.Update(ctx, obj, opts...)
}

func (w *countingStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return w.inner.Patch(ctx, obj, patch, opts...)
}

func (w *countingStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	*w.count++
	return w.inner.Apply(ctx, obj, opts...)
}

// applyTunnelConditions writes status.conditions under an arbitrary field
// manager. It seeds the pre-fix ownership layout (conditions owned by
// flareway-gateway / flareway-tunnel) and foreign-manager conditions.
func applyTunnelConditions(direct client.Client, key types.NamespacedName, manager string, conditions ...metav1.Condition) {
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&v1alpha1.CloudflareTunnelStatus{Conditions: conditions})
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "CloudflareTunnel",
		"metadata":   map[string]any{"name": key.Name, "namespace": key.Namespace},
		"status":     statusMap,
	}}
	gomega.ExpectWithOffset(1, direct.Status().Apply(
		testContext, client.ApplyConfigurationFromUnstructured(apply),
		client.FieldOwner(manager), client.ForceOwnership,
	)).To(gomega.Succeed())
}

// applyTunnelDataOnly applies status data fields under a field manager while
// omitting status.conditions — the post-migration shape of the legacy data
// managers. SSA deletes owned fields omitted from the document, so running
// this before ownership transfer reproduces the QA-92-30a hazard.
func applyTunnelDataOnly(direct client.Client, key types.NamespacedName, manager string, status v1alpha1.CloudflareTunnelStatus) {
	status.Conditions = nil
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	delete(statusMap, "conditions")
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "CloudflareTunnel",
		"metadata":   map[string]any{"name": key.Name, "namespace": key.Namespace},
		"status":     statusMap,
	}}
	gomega.ExpectWithOffset(1, direct.Status().Apply(
		testContext, client.ApplyConfigurationFromUnstructured(apply),
		client.FieldOwner(manager), client.ForceOwnership,
	)).To(gomega.Succeed())
}

// tunnelConditionOwners maps each persisted condition type to the sorted set
// of field managers owning its status.conditions entry.
func tunnelConditionOwners(tunnel *v1alpha1.CloudflareTunnel) map[string][]string {
	owners := map[string][]string{}
	for _, entry := range tunnel.ManagedFields {
		if entry.FieldsV1 == nil {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			continue
		}
		status, ok := fields["f:status"].(map[string]any)
		if !ok {
			continue
		}
		conditions, ok := status["f:conditions"].(map[string]any)
		if !ok {
			continue
		}
		for fieldKey := range conditions {
			// Map keys carry the "k:" prefix: k:{"type":"Ready"}.
			keyJSON, ok := strings.CutPrefix(fieldKey, "k:")
			if !ok {
				continue
			}
			var decoded struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal([]byte(keyJSON), &decoded); err != nil {
				continue
			}
			owners[decoded.Type] = append(owners[decoded.Type], entry.Manager)
		}
	}
	for _, managers := range owners {
		sort.Strings(managers)
	}
	return owners
}

var _ = ginkgo.Describe("CloudflareTunnel shared conditions transaction", func() {

	ginkgo.It("QA-92-16a/27: commits one consistent status after a transient CAS conflict and preserves the interposed write", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC))
		observed := fixture.live()

		interposed := 0
		validateCalls := 0
		reader := &interposingReader{inner: direct, onGet: func(key types.NamespacedName) {
			if key != fixture.key || interposed > 0 {
				return
			}
			interposed++
			// A real interleaved write inside the read-to-apply window: another
			// writer advances configVersion, invalidating the basis RV. The
			// mutation does not break provenance, so the commit must retry and
			// preserve it (QA-92-27).
			var live v1alpha1.CloudflareTunnel
			gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
			live.Status.ConfigVersion.Desired = 9
			live.Status.ConfigVersion.DesiredHash = "interposed-hash"
			gomega.Expect(direct.Status().Update(testContext, &live)).To(gomega.Succeed())
		}}

		err := patchTunnelConditions(testContext, direct, reader, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
			Validate: func(*v1alpha1.CloudflareTunnel) error {
				validateCalls++
				return nil
			},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(interposed).To(gomega.Equal(1), "the interposed write must land inside the read-to-apply window")
		gomega.Expect(validateCalls).To(gomega.BeNumerically(">=", 2), "Validate must re-run against the retried basis")

		tunnelReady := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionTunnelReady)
		gomega.Expect(tunnelReady.Status).To(gomega.Equal(metav1.ConditionTrue))
		// Ready is derived in the same transaction: inputs unmet → False, never absent.
		ready := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(ready.LastTransitionTime.Time).To(gomega.BeTemporally("==", now.Time))
		// The interposed data write survives the retried commit.
		current := fixture.live()
		gomega.Expect(current.Status.ConfigVersion.Desired).To(gomega.Equal(int64(9)))
		gomega.Expect(current.Status.ConfigVersion.DesiredHash).To(gomega.Equal("interposed-hash"))
		// Conditions carry a single owner: the shared conditions manager.
		owners := tunnelConditionOwners(current)
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionTunnelReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
	})

	ginkgo.It("QA-92-16b: returns an error without non-CAS fallback when conflicts exhaust the retry bound", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 1, 10, 0, 0, time.UTC))
		observed := fixture.live()

		interposed := 0
		validateCalls := 0
		reader := &interposingReader{inner: direct, onGet: func(key types.NamespacedName) {
			if key != fixture.key {
				return
			}
			interposed++
			// Every basis read is followed by a real interleaved write, so the
			// CAS apply always meets a newer resourceVersion.
			var live v1alpha1.CloudflareTunnel
			gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
			live.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Value: fmt.Sprintf("churn-%d.example.com", interposed)}}
			gomega.Expect(direct.Status().Update(testContext, &live)).To(gomega.Succeed())
		}}

		err := patchTunnelConditions(testContext, direct, reader, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
			Validate: func(*v1alpha1.CloudflareTunnel) error {
				validateCalls++
				return nil
			},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(validateCalls).To(gomega.Equal(tunnelConditionMaxAttempts),
			"each bounded attempt must re-validate before the helper gives up")
		// No non-CAS fallback, no forced write, no silently dropped delta: the
		// authored condition never persists.
		gomega.Expect(fixture.live().Status.Conditions).To(gomega.BeEmpty())
	})

	ginkgo.It("QA-92-23: a Gateway ConfigApplied=False write demotes Ready in the same commit", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		_, writerGateway := fixture.createGateway()

		gatewayWriter := &GatewayReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		tunnelWriter := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		seedNow := metav1.NewTime(time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC))

		// Seed the converged pair through the production writers.
		observed := fixture.live()
		gomega.Expect(gatewayWriter.patchTunnelGatewayStatus(
			testContext, writerGateway, observed,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7, Remote: 7},
			[]v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "edge.example.com", ProtectionDomain: "http", Guard: v1alpha1.HostnameGuardUnprotected}},
			[]v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}},
			gatewayTunnelCondition(observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "configuration applied", seedNow),
		)).To(gomega.Succeed())
		observed = fixture.live()
		// status.Conditions carries only this-pass authored deltas; the helper
		// carries the live ConfigApplied verbatim and derives Ready.
		seedStatus := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		setStatusCondition(&seedStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", "authorized", observed.Generation, seedNow), seedNow)
		setStatusCondition(&seedStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, seedNow), seedNow)
		setStatusCondition(&seedStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", observed.Generation, seedNow), seedNow)
		gomega.Expect(tunnelWriter.patchOwnedStatus(testContext, observed, seedStatus, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))

		// The production Gateway writer publishes a real ConfigApplied=False.
		falseNow := metav1.NewTime(time.Date(2026, 9, 22, 2, 1, 0, 0, time.UTC))
		observed = fixture.live()
		gomega.Expect(gatewayWriter.patchTunnelGatewayStatus(
			testContext, writerGateway, observed,
			observed.Status.ConfigVersion, observed.Status.Hostnames, observed.Status.Listeners,
			gatewayTunnelCondition(observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "Pending", "waiting for cloudflared configuration", falseNow),
		)).To(gomega.Succeed())

		// No persisted revision may hold Ready=True ∧ ConfigApplied=False.
		configApplied := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		ready := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(configApplied.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse),
			"Ready must be demoted in the same conditions transaction as ConfigApplied=False")
		// Non-authored inputs are carried verbatim from the live object.
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionTunnelReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionDNSReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		owners := tunnelConditionOwners(fixture.live())
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionConfigApplied]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
	})

	ginkgo.It("QA-92-24: a tunnel write built on a stale snapshot cannot resurrect Ready over live ConfigApplied=False", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		_, writerGateway := fixture.createGateway()

		gatewayWriter := &GatewayReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		tunnelWriter := &CloudflareTunnelReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		seedNow := metav1.NewTime(time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC))

		observed := fixture.live()
		gomega.Expect(gatewayWriter.patchTunnelGatewayStatus(
			testContext, writerGateway, observed,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7, Remote: 7},
			[]v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "edge.example.com", ProtectionDomain: "http", Guard: v1alpha1.HostnameGuardUnprotected}},
			[]v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}},
			gatewayTunnelCondition(observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "configuration applied", seedNow),
		)).To(gomega.Succeed())
		observed = fixture.live()
		seedStatus := tunnelOwnedStatus(observed, observed.Status.GatewayRef, observed.Status.GatewayUID, nil)
		setStatusCondition(&seedStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, seedNow), seedNow)
		setStatusCondition(&seedStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", observed.Generation, seedNow), seedNow)
		gomega.Expect(tunnelWriter.patchOwnedStatus(testContext, observed, seedStatus, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))

		// The stale copy: read while (ConfigApplied=True, Ready=True) is live,
		// exactly like a tunnel reconcile running on a lagging informer cache.
		stale := fixture.live()

		falseNow := metav1.NewTime(time.Date(2026, 9, 22, 3, 1, 0, 0, time.UTC))
		observed = fixture.live()
		gomega.Expect(gatewayWriter.patchTunnelGatewayStatus(
			testContext, writerGateway, observed,
			observed.Status.ConfigVersion, observed.Status.Hostnames, observed.Status.Listeners,
			gatewayTunnelCondition(observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "Pending", "waiting for cloudflared configuration", falseNow),
		)).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionFalse))

		// The stale tunnel-owned write: the stale snapshot still carries
		// ConfigApplied=True and Ready=True in its conditions, so a reconcile
		// running on it would author TunnelReady=True from stale inputs. The
		// commit must be based on a fresh read: the authored delta lands, but
		// Ready is derived from the LIVE ConfigApplied=False — the stale
		// Ready=True cannot be republished.
		staleStatus := tunnelOwnedStatus(stale, stale.Status.GatewayRef, stale.Status.GatewayUID, nil)
		setStatusCondition(&staleStatus, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", stale.Generation, falseNow), falseNow)
		gomega.Expect(tunnelWriter.patchOwnedStatus(testContext, stale, staleStatus, tunnelStatusClear{})).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionTunnelReady).Status).To(gomega.Equal(metav1.ConditionTrue),
			"the authored TunnelReady delta must still land — only the stale Ready derivation is rejected")
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionFalse),
			"a stale snapshot must not resurrect Ready=True over live ConfigApplied=False")
	})

	ginkgo.It("QA-92-26: aborts without writing when the observed generation went stale", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 4, 0, 0, 0, time.UTC))
		observed := fixture.live()
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
		})).To(gomega.Succeed())
		before := fixture.live()

		// A spec edit advances the generation after the pass observed it.
		var live v1alpha1.CloudflareTunnel
		gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
		live.Spec.DNS.RecordComment = "edited mid-pass"
		gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
		gomega.Expect(fixture.live().Generation).To(gomega.BeNumerically(">", observed.Generation))

		later := metav1.NewTime(time.Date(2026, 9, 22, 4, 1, 0, 0, time.UTC))
		err := patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Degraded", "stale observation", observed.Generation, later),
			},
			Now: later,
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		// The stale observation must not be re-recorded under the new generation.
		gomega.Expect(fixture.live().Status.Conditions).To(gomega.Equal(before.Status.Conditions))
	})

	ginkgo.It("QA-92-03/26: a no-input pass carries Ready and the inputs verbatim across a generation bump", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		// Converged state at generation G1: every Ready input True, Ready
		// derived True in the same transaction.
		seedNow := metav1.NewTime(time.Date(2026, 9, 22, 4, 20, 0, 0, time.UTC))
		observed := fixture.live()
		generationG1 := observed.Generation
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", generationG1, seedNow),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generationG1, seedNow),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", generationG1, seedNow),
			},
			Now: seedNow,
		})).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))

		// A spec edit advances the generation; the next pass re-reads the
		// object at G2 but authors nothing — no input delta, no lifecycle
		// override. Carried conditions describe G1 observations and must keep
		// their G1 observedGeneration and original lastTransitionTime: a
		// no-input pass may never restamp them to G2.
		var live v1alpha1.CloudflareTunnel
		gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
		live.Spec.DNS.RecordComment = "edited between passes"
		gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
		observedG2 := fixture.live()
		gomega.Expect(observedG2.Generation).To(gomega.BeNumerically(">", generationG1))

		later := metav1.NewTime(time.Date(2026, 9, 22, 4, 21, 0, 0, time.UTC))
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed:   observedG2,
			Conditions: nil,
			Now:        later,
		})).To(gomega.Succeed())

		carried := []string{
			v1alpha1.CloudflareTunnelConditionConfigApplied,
			v1alpha1.CloudflareTunnelConditionTunnelReady,
			v1alpha1.CloudflareTunnelConditionDNSReady,
			v1alpha1.CloudflareTunnelConditionReady,
		}
		for _, conditionType := range carried {
			condition := fixture.requireCondition(conditionType)
			gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue),
				"carried condition %s must keep its live value", conditionType)
			gomega.Expect(condition.ObservedGeneration).To(gomega.Equal(generationG1),
				"carried condition %s still describes the G1 observation; a no-input pass must not restamp it to G2", conditionType)
			gomega.Expect(condition.LastTransitionTime.Time).To(gomega.BeTemporally("==", seedNow.Time),
				"carried condition %s keeps its original transition time", conditionType)
		}
	})

	ginkgo.It("QA-92-27: aborts the commit when a generation bump lands inside the read-to-apply window", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 4, 10, 0, 0, time.UTC))
		observed := fixture.live()

		bumped := false
		reader := &interposingReader{inner: direct, onGet: func(key types.NamespacedName) {
			if key != fixture.key || bumped {
				return
			}
			bumped = true
			var live v1alpha1.CloudflareTunnel
			gomega.Expect(direct.Get(testContext, fixture.key, &live)).To(gomega.Succeed())
			live.Spec.DNS.RecordComment = "in-window edit"
			gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
		}}

		err := patchTunnelConditions(testContext, direct, reader, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(fixture.live().Status.Conditions).To(gomega.BeEmpty(),
			"a commit derived from a stale generation must never persist")
	})

	ginkgo.It("QA-92-29: refuses promotion when mode, remote-deletion, or identity provenance changed", func() {
		direct := startIsolatedConditionsPlane()
		now := metav1.NewTime(time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC))

		// (a) Mode transition: the observed snapshot is Gateway mode, the live
		// object is now Direct — the Gateway-mode authority no longer applies.
		modeFixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		observed := modeFixture.live()
		var live v1alpha1.CloudflareTunnel
		gomega.Expect(direct.Get(testContext, modeFixture.key, &live)).To(gomega.Succeed())
		live.Spec.Configuration = directTunnelSpec().Configuration
		gomega.Expect(direct.Update(testContext, &live)).To(gomega.Succeed())
		err := patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", observed.Generation, now),
			},
			Now: now,
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(modeFixture.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)).To(gomega.BeNil())

		// (b) Remote deletion recorded mid-pass: CAS alone is insufficient —
		// the production Gateway-writer guard re-validates the live object on
		// every commit attempt and refuses once status.deletedAt is set.
		deletedFixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		_, writerGateway := deletedFixture.createGateway()
		observed = deletedFixture.live()
		live = v1alpha1.CloudflareTunnel{}
		gomega.Expect(direct.Get(testContext, deletedFixture.key, &live)).To(gomega.Succeed())
		deletedAt := metav1.NewTime(time.Date(2026, 9, 22, 5, 1, 0, 0, time.UTC))
		live.Status.DeletedAt = &deletedAt
		gomega.Expect(direct.Status().Update(testContext, &live)).To(gomega.Succeed())
		gatewayWriter := &GatewayReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		err = gatewayWriter.patchTunnelGatewayConditionsValidated(
			testContext, writerGateway, observed, now, nil,
			gatewayTunnelCondition(observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", now),
		)
		gomega.Expect(err).To(gomega.HaveOccurred(),
			"the production writer guard must refuse once status.deletedAt is recorded")
		gomega.Expect(deletedFixture.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)).To(gomega.BeNil(),
			"no condition may land when the guard vetoes the commit")

		// (c) Recreation: the live object carries a different UID than the
		// observed snapshot — writes against the old identity must not land.
		recreateFixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		observed = recreateFixture.live()
		gomega.Expect(direct.Delete(testContext, observed)).To(gomega.Succeed())
		gomega.Expect(direct.Create(testContext, &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: recreateFixture.name, Namespace: recreateFixture.namespace},
			Spec:       managedTunnelSpec(),
		})).To(gomega.Succeed())
		gomega.Expect(recreateFixture.live().UID).NotTo(gomega.Equal(observed.UID))
		err = patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", observed.Generation, now),
			},
			Now: now,
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(recreateFixture.condition(v1alpha1.CloudflareTunnelConditionConfigApplied)).To(gomega.BeNil())

		// (d) Deletion mid-pass: the live object is gone entirely. The commit
		// is a durability checkpoint — a caller invalidating before a remote
		// mutation must get an error, never a success report on a deleted
		// object.
		goneFixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		observed = goneFixture.live()
		gomega.Expect(direct.Delete(testContext, observed)).To(gomega.Succeed())
		err = patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", observed.Generation, now),
			},
			Now: now,
		})
		gomega.Expect(err).To(gomega.HaveOccurred(),
			"a commit against a deleted tunnel must fail the durability checkpoint")
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(),
			"the failure must surface the missing live object, not a generic or swallowed error")
		var gone v1alpha1.CloudflareTunnel
		gomega.Expect(apierrors.IsNotFound(direct.Get(testContext, goneFixture.key, &gone))).To(gomega.BeTrue(),
			"the failed commit must not resurrect the deleted object")
	})

	ginkgo.It("QA-92-30a: transfers all Flareway condition ownership before data-only applies may omit conditions", func() {
		direct := startIsolatedConditionsPlane()
		now := metav1.NewTime(time.Date(2026, 9, 22, 6, 0, 0, 0, time.UTC))
		seedLegacy := func(fixture *tunnelConditionsFixture) {
			generation := fixture.live().Generation
			applyTunnelConditions(direct, fixture.key, gatewayFieldManager,
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", generation, now))
			applyTunnelConditions(direct, fixture.key, tunnelFieldManager,
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generation, now),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", generation, now),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionReady, metav1.ConditionTrue, "Ready", "ready", generation, now))
		}
		flarewaySeeded := []string{
			v1alpha1.CloudflareTunnelConditionConfigApplied,
			v1alpha1.CloudflareTunnelConditionTunnelReady,
			v1alpha1.CloudflareTunnelConditionDNSReady,
			v1alpha1.CloudflareTunnelConditionReady,
		}

		// Upgrade path: the first conditions transaction is a pure ownership
		// transfer (no authored delta), committed BEFORE any data-only apply.
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		seedLegacy(fixture)
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed:   fixture.live(),
			Conditions: nil,
			Now:        now,
		})).To(gomega.Succeed())
		applyTunnelDataOnly(direct, fixture.key, gatewayFieldManager, v1alpha1.CloudflareTunnelStatus{
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7, Remote: 7},
		})
		applyTunnelDataOnly(direct, fixture.key, tunnelFieldManager, v1alpha1.CloudflareTunnelStatus{
			TunnelID: "22222222-2222-2222-2222-222222222222",
		})

		current := fixture.live()
		gomega.Expect(current.Status.Conditions).To(gomega.HaveLen(len(flarewaySeeded)),
			"the migration must carry only existing entries and invent none")
		owners := tunnelConditionOwners(current)
		for _, conditionType := range flarewaySeeded {
			gomega.Expect(meta.FindStatusCondition(current.Status.Conditions, conditionType)).NotTo(gomega.BeNil(),
				"condition %s must survive data-only applies after ownership transfer", conditionType)
			gomega.Expect(owners[conditionType]).To(gomega.Equal([]string{tunnelStatusFieldManager}),
				"condition %s must be owned solely by the shared conditions manager", conditionType)
		}

		// Control: the same data-only applies WITHOUT the migration delete the
		// legacy-owned conditions — proving the ordering is what protects them.
		control := newTunnelConditionsFixture(direct, managedTunnelSpec())
		seedLegacy(control)
		applyTunnelDataOnly(direct, control.key, gatewayFieldManager, v1alpha1.CloudflareTunnelStatus{
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7, Remote: 7},
		})
		applyTunnelDataOnly(direct, control.key, tunnelFieldManager, v1alpha1.CloudflareTunnelStatus{
			TunnelID: "22222222-2222-2222-2222-222222222222",
		})
		for _, conditionType := range flarewaySeeded {
			gomega.Expect(meta.FindStatusCondition(control.live().Status.Conditions, conditionType)).To(gomega.BeNil(),
				"control: condition %s must be deleted by a data-only apply that omits it", conditionType)
		}
	})

	ginkgo.It("QA-92-30b: transfers ownership even when condition values already match the desired state", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 6, 10, 0, 0, time.UTC))
		generation := fixture.live().Generation
		applyTunnelConditions(direct, fixture.key, tunnelFieldManager,
			tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generation, now),
			tunnelCondition(v1alpha1.CloudflareTunnelConditionReady, metav1.ConditionFalse, "Pending", "inputs unmet", generation, now))

		// The authored delta is semantically identical to the live value; the
		// equal-value fast path must not skip the ownership transfer while a
		// non-shared manager still owns a Flareway condition type.
		later := metav1.NewTime(time.Date(2026, 9, 22, 6, 11, 0, 0, time.UTC))
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: fixture.live(),
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generation, later),
			},
			Now: later,
		})).To(gomega.Succeed())

		current := fixture.live()
		// Same-status entries keep their live transition time — the transfer
		// must not re-stamp them.
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionTunnelReady).LastTransitionTime.Time).
			To(gomega.BeTemporally("==", now.Time))
		// SSA shares ownership when the applied value is identical, so the
		// equal-value pass adds the shared manager as a co-owner rather than
		// stripping the legacy one. The contract is that the shared manager
		// now owns the type — proven below by a legacy data-only apply that
		// omits conditions and cannot delete them.
		owners := tunnelConditionOwners(current)
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionTunnelReady]).To(gomega.ContainElement(tunnelStatusFieldManager))
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionReady]).To(gomega.ContainElement(tunnelStatusFieldManager))

		// While the legacy manager still co-owns the entries — the permanent
		// state after a Direct transition, where the old owner never issues
		// another apply — a repeated identical conditions pass must be a true
		// no-op: zero Apply calls reach the API server.
		counting := &countingApplier{Client: direct}
		gomega.Expect(patchTunnelConditions(testContext, counting, direct, tunnelConditionUpdate{
			Observed: fixture.live(),
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generation, later),
			},
			Now: later,
		})).To(gomega.Succeed())
		gomega.Expect(counting.applies).To(gomega.Equal(0),
			"a repeated identical pass must not re-apply while a legacy manager co-owns the entries")

		// The legacy manager's data-only apply relinquishes its claim; the
		// entries survive solely under the shared conditions manager.
		applyTunnelDataOnly(direct, fixture.key, tunnelFieldManager, v1alpha1.CloudflareTunnelStatus{
			TunnelID: "22222222-2222-2222-2222-222222222222",
		})
		current = fixture.live()
		gomega.Expect(meta.FindStatusCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)).NotTo(gomega.BeNil(),
			"the equal-value transfer must protect the entry from a legacy omission")
		gomega.Expect(meta.FindStatusCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)).NotTo(gomega.BeNil())
		owners = tunnelConditionOwners(current)
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionTunnelReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
	})

	ginkgo.It("QA-92-30c: preserves foreign-owned conditions and keeps no-op passes write-free", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		now := metav1.NewTime(time.Date(2026, 9, 22, 6, 20, 0, 0, time.UTC))
		observed := fixture.live()
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
			},
			Now: now,
		})).To(gomega.Succeed())
		// A foreign manager owns a custom condition type.
		applyTunnelConditions(direct, fixture.key, "external-manager", metav1.Condition{
			Type:               "example.com/Custom",
			Status:             metav1.ConditionTrue,
			Reason:             "Custom",
			Message:            "foreign-owned condition",
			ObservedGeneration: observed.Generation,
			LastTransitionTime: now,
		})

		before := fixture.live()
		later := metav1.NewTime(time.Date(2026, 9, 22, 6, 21, 0, 0, time.UTC))
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed:   before.DeepCopy(),
			Conditions: nil,
			Now:        later,
		})).To(gomega.Succeed())

		after := fixture.live()
		// Zero writes: nothing changed and ownership is already correct, so the
		// pass must not bump resourceVersion — the foreign entry must not
		// permanently disable the no-op skip.
		gomega.Expect(after.ResourceVersion).To(gomega.Equal(before.ResourceVersion))
		foreign := meta.FindStatusCondition(after.Status.Conditions, "example.com/Custom")
		gomega.Expect(foreign).NotTo(gomega.BeNil(), "the foreign-owned condition must be preserved")
		gomega.Expect(foreign.Status).To(gomega.Equal(metav1.ConditionTrue))
		owners := tunnelConditionOwners(after)
		gomega.Expect(owners["example.com/Custom"]).To(gomega.Equal([]string{"external-manager"}),
			"the shared manager must not steal foreign condition ownership")
	})

	ginkgo.It("QA-92-31: clamps a legacy torn pair to Ready=False on the first pass", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())

		// Seed the torn pair a pre-fix binary could leave behind:
		// ConfigApplied=False (gateway-owned) with Ready=True (tunnel-owned).
		now := metav1.NewTime(time.Date(2026, 9, 22, 7, 0, 0, 0, time.UTC))
		generation := fixture.live().Generation
		applyTunnelConditions(direct, fixture.key, gatewayFieldManager,
			tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "Pending", "waiting", generation, now))
		applyTunnelConditions(direct, fixture.key, tunnelFieldManager,
			tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", generation, now),
			tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", generation, now),
			tunnelCondition(v1alpha1.CloudflareTunnelConditionReady, metav1.ConditionTrue, "Ready", "ready", generation, now))

		// The first conditions transaction after upgrade — no spec change, no
		// remote call — must clamp Ready to False.
		later := metav1.NewTime(time.Date(2026, 9, 22, 7, 1, 0, 0, time.UTC))
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed:   fixture.live(),
			Conditions: nil,
			Now:        later,
		})).To(gomega.Succeed())

		configApplied := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(configApplied.Status).To(gomega.Equal(metav1.ConditionFalse),
			"the live ConfigApplied value must be carried verbatim")
		gomega.Expect(configApplied.LastTransitionTime.Time).To(gomega.BeTemporally("==", now.Time),
			"a carried condition keeps its live transition time")
		ready := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse),
			"the unconditional clamp must repair the torn pair")
		gomega.Expect(ready.LastTransitionTime.Time).To(gomega.BeTemporally("==", later.Time),
			"the clamp is a real transition and must be stamped with the commit time")
	})

	ginkgo.It("QA-92-32: a Direct tunnel commits ConfigApplied and Ready in one transaction; a referencing Gateway is rejected without tunnel writes", func() {
		direct := startIsolatedConditionsPlane()
		factory := newFakeTunnelCloudflareFactory()
		fixture, reconciler := newDirectReconcileFixture(direct, factory, nil)

		// The tunnel writer commits ConfigApplied and Ready through the shared
		// conditions manager in a single transaction.
		_, err := reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		owners := tunnelConditionOwners(fixture.live())
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionConfigApplied]).To(gomega.Equal([]string{tunnelStatusFieldManager}))
		gomega.Expect(owners[v1alpha1.CloudflareTunnelConditionReady]).To(gomega.Equal([]string{tunnelStatusFieldManager}))

		// G4: a Gateway referencing this Direct tunnel is rejected and performs
		// zero tunnel status writes.
		gomega.Expect(direct.Create(testContext, &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
		})).To(gomega.Succeed())
		hostname := gatewayv1.Hostname("edge.example.com")
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: fixture.namespace},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName("flareway"),
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: fixture.name,
					},
				},
				Listeners: []gatewayv1.Listener{{
					Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
				}},
			},
		}
		gomega.Expect(direct.Create(testContext, gateway)).To(gomega.Succeed())

		before := fixture.live()
		gatewayReconciler := &GatewayReconciler{
			Client:    direct,
			APIReader: direct,
			Scheme:    direct.Scheme(),
			Snapshots: newFakeSnapshotPublisher(),
		}
		_, err = gatewayReconciler.Reconcile(testContext, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gateway)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		var persisted gatewayv1.Gateway
		gomega.Expect(direct.Get(testContext, client.ObjectKeyFromObject(gateway), &persisted)).To(gomega.Succeed())
		accepted := meta.FindStatusCondition(persisted.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(accepted).NotTo(gomega.BeNil())
		gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(accepted.Reason).To(gomega.Equal(gatewayReasonUnsupportedValue))

		live := fixture.live()
		gomega.Expect(live.ResourceVersion).To(gomega.Equal(before.ResourceVersion),
			"a rejected Gateway must not perform any tunnel status write")
	})

	ginkgo.It("QA-92-33: an ObserveOnly tunnel reconciles read-only and reports Ready=False/ObserveOnly", func() {
		direct := startIsolatedConditionsPlane()
		factory := newFakeTunnelCloudflareFactory()
		fixture, reconciler := newDirectReconcileFixture(direct, factory, nil)

		// Switch the fixture to ObserveOnly with an externalRef before the
		// first reconcile; the tunnel writer's conditions commit must succeed
		// in this state — the Gateway-only ownership preconditions
		// (deletedAt, ownershipVerified, gatewayRef/UID, live Gateway, drain)
		// must not block it.
		live := fixture.live()
		live.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		live.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-tunnel"}
		gomega.Expect(direct.Update(testContext, live)).To(gomega.Succeed())
		factory.PutTunnel(RemoteTunnel{ID: "observed-tunnel", Name: "observed-tunnel"})

		_, err := reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// Zero remote and credential mutations: observation only.
		for _, mutating := range []string{
			"CreateTunnel", "UpdateTunnelName", "UpdateTunnelConfiguration",
			"DeleteTunnel", "EvictTunnelConnections", "GetTunnelToken",
		} {
			gomega.Expect(countCall(factory.Calls(), mutating)).To(gomega.Equal(0),
				"ObserveOnly must not issue %s", mutating)
		}
		gomega.Expect(countCall(factory.Calls(), "GetTunnel")).To(gomega.Equal(1))

		// Ready=False/ObserveOnly is the explicit lifecycle policy, not the
		// derived result: the observed inputs are True yet Ready stays False.
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionTunnelReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		ready := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(ready.Reason).To(gomega.Equal("ObserveOnly"))

		// Status and finalizer updates remain allowed under ObserveOnly.
		gomega.Expect(fixture.live().Status.TunnelID).To(gomega.Equal("observed-tunnel"))
		gomega.Expect(fixture.live().Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
	})

	ginkgo.It("QA-92-34: teardown keeps ConfigApplied without flapping while the dataplane drains", func() {
		direct := startIsolatedConditionsPlane()
		factory := newFakeTunnelCloudflareFactory()
		fixture, reconciler := newDirectReconcileFixture(direct, factory, nil)

		// Switch to Gateway mode and bind the recorded owner Gateway.
		live := fixture.live()
		live.Spec.Configuration = v1alpha1.CloudflareTunnelConfiguration{
			Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway,
		}
		gomega.Expect(direct.Update(testContext, live)).To(gomega.Succeed())
		gateway, _ := fixture.createGateway()

		// Converged state: ConfigApplied plus the Ready inputs, committed
		// through the shared conditions manager.
		now := metav1.NewTime(time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC))
		observed := fixture.live()
		gomega.Expect(patchTunnelConditions(testContext, direct, direct, tunnelConditionUpdate{
			Observed: observed,
			Conditions: []metav1.Condition{
				tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", observed.Generation, now),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", "tunnel exists", observed.Generation, now),
				tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "External", "DNS managed externally", observed.Generation, now),
			},
			Now: now,
		})).To(gomega.Succeed())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))

		// The deny snapshot is ACKed: every recorded hostname is Blocked.
		live = fixture.live()
		live.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: "edge.example.com", ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardBlocked,
		}}
		gomega.Expect(direct.Status().Update(testContext, live)).To(gomega.Succeed())
		factory.PutTunnel(RemoteTunnel{ID: "22222222-2222-2222-2222-222222222222", Name: "recorded"})

		// The recorded dataplane is draining: the Deployment still exists and a
		// cloudflared Pod holding the tunnel token has not terminated.
		replicas := int32(1)
		gomega.Expect(direct.Create(testContext, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "flareway-gw-" + gateway.Name,
				Namespace: fixture.namespace,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(gateway, gatewayControllerGVK()),
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "cloudflared"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "cloudflared"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflared"}}},
				},
			},
		})).To(gomega.Succeed())
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cloudflared-draining",
				Namespace: fixture.namespace,
				Labels:    map[string]string{dataplaneGatewayLabel: fixture.namespace + "--" + gateway.Name},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  "cloudflared",
				Image: "cloudflared",
				Env: []corev1.EnvVar{{
					Name: "TUNNEL_TOKEN",
					ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "connector-token"},
						Key:                  "token",
					}},
				}},
			}}},
		}
		gomega.Expect(direct.Create(testContext, pod)).To(gomega.Succeed())

		// Deletion starts: the finalizer holds the object while teardown runs.
		live = fixture.live()
		gomega.Expect(direct.Delete(testContext, live)).To(gomega.Succeed())
		gomega.Expect(fixture.live().DeletionTimestamp).NotTo(gomega.BeNil())

		// Pass 1 marks the teardown annotation; pass 2 reaches the drain gate.
		_, err := reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		configApplied := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(configApplied.Status).To(gomega.Equal(metav1.ConditionTrue),
			"ConfigApplied must not flap during teardown")
		gomega.Expect(configApplied.LastTransitionTime.Time).To(gomega.BeTemporally("==", now.Time),
			"an untouched condition keeps its original transition time")
		blocked := fixture.requireCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked)
		gomega.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(blocked.Reason).To(gomega.Equal("WaitingForDrain"))
		gomega.Expect(fixture.live().Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer),
			"the finalizer must hold until the drain and remote delete complete")
		gomega.Expect(countCall(factory.Calls(), "DeleteTunnel")).To(gomega.Equal(0),
			"the remote tunnel must not be deleted while the dataplane drains")

		var deployment appsv1.Deployment
		gomega.Expect(direct.Get(testContext,
			types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-gw-" + gateway.Name},
			&deployment)).To(gomega.Succeed())
		gomega.Expect(*deployment.Spec.Replicas).To(gomega.Equal(int32(0)),
			"the recorded dataplane is scaled to zero while its Pods drain")

		// The tunnel writer's conditions commit also succeeds once the remote
		// deletion is recorded: status.deletedAt is a Gateway-writer
		// precondition, not a tunnel-writer one.
		live = fixture.live()
		deletedAt := metav1.NewTime(time.Date(2026, 9, 22, 10, 2, 0, 0, time.UTC))
		live.Status.DeletedAt = &deletedAt
		gomega.Expect(direct.Status().Update(testContext, live)).To(gomega.Succeed())
		_, err = reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fixture.requireCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked).Reason).
			To(gomega.Equal("WaitingForDrain"))

		// A repeated identical teardown pass is a no-op: no churn while draining.
		before := fixture.live()
		_, err = reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fixture.live().ResourceVersion).To(gomega.Equal(before.ResourceVersion))

		// Once the last Pod terminates the remote delete runs and the
		// finalizer releases — ordering preserved.
		gomega.Expect(direct.Delete(testContext, pod)).To(gomega.Succeed())
		_, err = reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: fixture.key})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(countCall(factory.Calls(), "DeleteTunnel")).To(gomega.Equal(1))
		gomega.Expect(factory.HasTunnel("22222222-2222-2222-2222-222222222222")).To(gomega.BeFalse())
		var gone v1alpha1.CloudflareTunnel
		gomega.Expect(apierrors.IsNotFound(direct.Get(testContext, fixture.key, &gone))).To(gomega.BeTrue(),
			"the finalizer releases only after the remote delete")
	})
})
