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

// Isolated envtest-manager harness for issue #92 QA items QA-92-02, QA-92-04,
// QA-92-25, QA-92-28, and QA-92-35 through QA-92-43.
//
// Unlike the shared Ginkgo suite (suite_test.go), every test here runs its own
// controller-runtime manager against a dedicated envtest control plane with
// the real GatewayReconciler and CloudflareTunnelReconciler wired through
// SetupWithManager, a stateful fake Cloudflare API shared by both writers, a
// dynamic-client watch recorder that captures the full persisted status
// sequence, tracing reconciler clients that attribute every client call to
// its reconcile ID, and a log sink that records each reconcile's synchronous
// invocation and result lines. The file intentionally depends only on production
// symbols so it compiles unchanged against the pre-fix baseline (dd322e3) and
// the post-fix tree: the GatewayReconciler APIReader field, which does not
// exist on the baseline, is injected through reflection when present.
//
// These tests assert the post-fix contract. On the unfixed baseline the
// quiescence and no-torn-pair assertions are expected to fail; that failure is
// the defect evidence, matching the QA document convention that a failing
// assertion documents the defect.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// managerQA92Window reproduces the live-audit measurement window recorded in
// the issue (40.7521 seconds) so pre/post runs are directly comparable.
const managerQA92Window = 40752100 * time.Microsecond

// managerQA92MeasureEnv gates the opt-in QA-92-43 measurement spec. It is a
// benchmark-style harness, not a timing SLA: it prints measured outcomes and
// never asserts millisecond budgets.
const managerQA92MeasureEnv = "FLAREWAY_QA92_MEASURE"

// managerQA92ReportEnv optionally names a JSON file the QA-92-43 measurement
// is appended to, so the parent can collect pre/post artifacts outside the
// repository.
const managerQA92ReportEnv = "FLAREWAY_QA92_MEASURE_OUT"

var (
	managerTunnelGVR           = schema.GroupVersionResource{Group: v1alpha1.Group, Version: "v1alpha1", Resource: "cloudflaretunnels"}
	managerGatewayGVR          = schema.GroupVersionResource{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version, Resource: "gateways"}
	managerHTTPRouteGVR        = schema.GroupVersionResource{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version, Resource: "httproutes"}
	managerBackendTLSPolicyGVR = schema.GroupVersionResource{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version, Resource: "backendtlspolicies"}
)

// managerFlarewayConditionTypes is the set of condition types any Flareway
// writer may own on a CloudflareTunnel. Ownership assertions only inspect
// these keys; foreign condition types are out of scope.
var managerFlarewayConditionTypes = []string{
	v1alpha1.CloudflareTunnelConditionAccepted,
	v1alpha1.CloudflareTunnelConditionTunnelReady,
	v1alpha1.CloudflareTunnelConditionConfigApplied,
	v1alpha1.CloudflareTunnelConditionDNSReady,
	v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded,
	v1alpha1.CloudflareTunnelConditionReady,
	v1alpha1.CloudflareTunnelConditionCleanupBlocked,
	v1alpha1.CloudflareTunnelConditionConflict,
	v1alpha1.CloudflareTunnelConditionDriftDetected,
}

// ---------------------------------------------------------------------------
// Fixture naming
// ---------------------------------------------------------------------------

// managerFixtureN allocates unique names across tests so fixtures never
// collide.
var managerFixtureN atomic.Uint64

// managerGatewayAPIDir locates the gateway-api module checkout for its CRDs.
// It mirrors suite_test.go's helper without depending on it so this file stays
// self-contained across the pre/post trees.
func managerGatewayAPIDir() string {
	command := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api")
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// managerEnvtestAssets finds a setup-envtest asset directory when
// KUBEBUILDER_ASSETS is unset, matching the io.kubebuilder.envtest layout.
func managerEnvtestAssets() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	pattern := filepath.Join(home, "Library", "Application Support", "io.kubebuilder.envtest", "k8s", "*")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[len(matches)-1]
}

// ---------------------------------------------------------------------------
// Watch recorder: captures the full persisted status sequence
// ---------------------------------------------------------------------------

type managerWatchEvent struct {
	At   time.Time
	Type watch.EventType
	RV   string
	Obj  *unstructured.Unstructured
}

// managerWatchRecorder maintains reconnecting watches on the objects whose
// persisted status sequence the QA items assert on.
type managerWatchRecorder struct {
	dyn     dynamic.Interface
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	records map[schema.GroupVersionResource][]managerWatchEvent
	lastRV  map[schema.GroupVersionResource]string
	wg      sync.WaitGroup
}

func newManagerWatchRecorder(cfg *rest.Config) (*managerWatchRecorder, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	recorder := &managerWatchRecorder{
		dyn:     dyn,
		ctx:     ctx,
		cancel:  cancel,
		records: map[schema.GroupVersionResource][]managerWatchEvent{},
		lastRV:  map[schema.GroupVersionResource]string{},
	}
	for _, gvr := range []schema.GroupVersionResource{managerTunnelGVR, managerGatewayGVR, managerHTTPRouteGVR, managerBackendTLSPolicyGVR} {
		recorder.wg.Add(1)
		go recorder.loop(gvr)
	}
	return recorder, nil
}

func (r *managerWatchRecorder) loop(gvr schema.GroupVersionResource) {
	defer r.wg.Done()
	resource := r.dyn.Resource(gvr)
	for {
		r.mu.Lock()
		rv := r.lastRV[gvr]
		r.mu.Unlock()
		w, err := resource.Watch(r.ctx, metav1.ListOptions{ResourceVersion: rv})
		if err != nil {
			if r.ctx.Err() != nil {
				return
			}
			select {
			case <-r.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		for event := range w.ResultChan() {
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			r.mu.Lock()
			r.records[gvr] = append(r.records[gvr], managerWatchEvent{
				At:   time.Now(),
				Type: event.Type,
				RV:   object.GetResourceVersion(),
				Obj:  object.DeepCopy(),
			})
			r.lastRV[gvr] = object.GetResourceVersion()
			r.mu.Unlock()
		}
		if r.ctx.Err() != nil {
			return
		}
	}
}

func (r *managerWatchRecorder) close() {
	r.cancel()
	r.wg.Wait()
}

// events returns the recorded events for one GVR, optionally filtered to a
// single object key.
func (r *managerWatchRecorder) events(gvr schema.GroupVersionResource, key *types.NamespacedName) []managerWatchEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []managerWatchEvent
	for _, event := range r.records[gvr] {
		if key != nil && (event.Obj.GetNamespace() != key.Namespace || event.Obj.GetName() != key.Name) {
			continue
		}
		out = append(out, event)
	}
	return out
}

// modifiedAfter returns MODIFIED events for key received after at.
func (r *managerWatchRecorder) modifiedAfter(gvr schema.GroupVersionResource, key types.NamespacedName, at time.Time) []managerWatchEvent {
	var out []managerWatchEvent
	for _, event := range r.events(gvr, &key) {
		if event.Type == watch.Modified && event.At.After(at) {
			out = append(out, event)
		}
	}
	return out
}

func managerTunnelOf(event managerWatchEvent) (*v1alpha1.CloudflareTunnel, error) {
	var tunnel v1alpha1.CloudflareTunnel
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(event.Obj.Object, &tunnel); err != nil {
		return nil, err
	}
	return &tunnel, nil
}

// managerConditionIndex maps condition type to status for one object.
func managerConditionIndex(conditions []metav1.Condition) map[string]metav1.Condition {
	out := make(map[string]metav1.Condition, len(conditions))
	for _, condition := range conditions {
		out[condition.Type] = condition
	}
	return out
}

// managerTunnelTorn reports the forbidden pair: Ready=True while ConfigApplied
// is absent or not True.
func managerTunnelTorn(tunnel *v1alpha1.CloudflareTunnel) bool {
	index := managerConditionIndex(tunnel.Status.Conditions)
	ready, hasReady := index[v1alpha1.CloudflareTunnelConditionReady]
	applied, hasApplied := index[v1alpha1.CloudflareTunnelConditionConfigApplied]
	return hasReady && ready.Status == metav1.ConditionTrue && (!hasApplied || applied.Status != metav1.ConditionTrue)
}

// managerTunnelTupleComplete reports whether the persisted status carries the
// full writer-guard tuple the Gateway consumes: tunnelId, verified ownership,
// connector credentials, the exact live Gateway UID binding, and no remote
// deletion marker.
func managerTunnelTupleComplete(tunnel *v1alpha1.CloudflareTunnel, gateway *gatewayv1.Gateway) bool {
	return tunnel.Status.TunnelID != "" &&
		tunnel.Status.OwnershipVerified &&
		tunnel.Status.ConnectorTokenSecretRef != nil &&
		tunnel.Status.ConnectorTokenSecretRef.Name != "" &&
		tunnel.Status.GatewayRef != nil &&
		tunnel.Status.GatewayRef.Name == gateway.Name &&
		tunnel.Status.GatewayUID == gateway.UID &&
		tunnel.Status.DeletedAt == nil
}

func managerConditionSummary(tunnel *v1alpha1.CloudflareTunnel) string {
	parts := make([]string, 0, len(tunnel.Status.Conditions))
	for _, condition := range tunnel.Status.Conditions {
		parts = append(parts, fmt.Sprintf("%s=%s/%s", condition.Type, condition.Status, condition.Reason))
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// Metrics sampler: timestamps reconcile completions and their results
// ---------------------------------------------------------------------------

// Reconcile results as controller_runtime_reconcile_total labels them.
// managerResult* mirror controller-runtime's reconcile_total result labels.
// managerResultRateLimited covers "error" and "requeue", both rate-limited.
const (
	managerResultRequeueAfter = "requeue_after"
	managerResultSuccess      = "success"
	managerResultRateLimited  = "rate_limited"
)

// ---------------------------------------------------------------------------
// Lifecycle sink: per-reconcile invocation and result through the manager log
// ---------------------------------------------------------------------------

// managerLifecycleSink observes controller-runtime's per-reconcile lifecycle
// log lines, which the reconcile handler emits synchronously on the reconcile
// goroutine at V(5) through the LogConstructor logger: "Reconciling" right
// before invoking Reconcile, "Reconcile done, requeueing after <d>" or
// "Reconcile done, requeueing" or "Reconcile successful" after it returns, and
// "Reconciler error" on failure. That makes each reconcile's invocation and
// result exact: aggregate metric sampling cannot preserve completion order
// when one interval mixes result labels.
//
// Enabled reports true through level 5 so the lifecycle lines reach the sink;
// every non-lifecycle message is discarded, matching the previous behavior
// where the test manager's logs went nowhere.
type managerLifecycleSink struct {
	trace  *managerTrace
	values []any
}

// Init implements logr.LogSink.
func (s *managerLifecycleSink) Init(logr.RuntimeInfo) {}

// Enabled implements logr.LogSink.
func (s *managerLifecycleSink) Enabled(level int) bool { return level <= 5 }

func (s *managerLifecycleSink) controllerName() string {
	for i := 0; i+1 < len(s.values); i += 2 {
		if key, ok := s.values[i].(string); ok && key == "controller" {
			if name, ok := s.values[i+1].(string); ok {
				return name
			}
		}
	}
	return ""
}

func (s *managerLifecycleSink) reconcileID() types.UID {
	for i := 0; i+1 < len(s.values); i += 2 {
		if key, ok := s.values[i].(string); ok && key == "reconcileID" {
			if id, ok := s.values[i+1].(types.UID); ok {
				return id
			}
			if id, ok := s.values[i+1].(string); ok {
				return types.UID(id)
			}
		}
	}
	return ""
}

// Info implements logr.LogSink.
func (s *managerLifecycleSink) Info(_ int, msg string, _ ...any) {
	id := s.reconcileID()
	if id == "" {
		return
	}
	switch {
	case msg == "Reconciling":
		s.trace.invoked(s.controllerName(), id)
	case msg == "Reconcile successful":
		s.trace.ended(id, managerResultSuccess, 0)
	case strings.HasPrefix(msg, "Reconcile done, requeueing after "):
		// The pending timer's duration is the verdict's expiry; a duration
		// that fails to parse records zero, which the verdict fails closed on.
		after, _ := time.ParseDuration(strings.TrimPrefix(msg, "Reconcile done, requeueing after "))
		s.trace.ended(id, managerResultRequeueAfter, after)
	case msg == "Reconcile done, requeueing":
		s.trace.ended(id, managerResultRateLimited, 0)
	}

}

// Error implements logr.LogSink.
func (s *managerLifecycleSink) Error(_ error, msg string, _ ...any) {
	if msg != "Reconciler error" {
		return
	}
	if id := s.reconcileID(); id != "" {
		s.trace.ended(id, managerResultRateLimited, 0)
	}
}

// WithValues implements logr.LogSink.
func (s *managerLifecycleSink) WithValues(kv ...any) logr.LogSink {
	values := make([]any, 0, len(s.values)+len(kv))
	values = append(values, s.values...)
	values = append(values, kv...)
	return &managerLifecycleSink{trace: s.trace, values: values}
}

// WithName implements logr.LogSink.
func (s *managerLifecycleSink) WithName(string) logr.LogSink { return s }

// ---------------------------------------------------------------------------
// Reconcile-activity clocks
// ---------------------------------------------------------------------------

// managerClock records every Now() call the reconciler makes. Clusters of
// calls mark reconcile activity with exact wall-clock times.
type managerClock struct {
	mu    sync.Mutex
	times []time.Time
}

func (c *managerClock) now() time.Time {
	at := time.Now()
	c.mu.Lock()
	c.times = append(c.times, at)
	c.mu.Unlock()
	return at
}

// ---------------------------------------------------------------------------
// Reconcile tracer: per-reconcile start, reads, and writes
// ---------------------------------------------------------------------------

// managerTracedObject is one object revision a traced call observed.
type managerTracedObject struct {
	Kind string
	Key  types.NamespacedName
	RV   int64
	At   time.Time
	// Direct marks reads through the reconciler's APIReader. Those are
	// diagnostic revalidations and write bases, not the reconcile's operative
	// input, so they never prove consumption of a stimulus.
	Direct bool
}

// managerTracedWrite is one successful traced write and the revision the API
// server returned for it; the commit happened inside [Start, End].
type managerTracedWrite struct {
	managerTracedObject
	Start time.Time
	End   time.Time
}

// managerReconcileEntry is one reconcile, keyed by its controller-runtime
// reconcile ID. InvokedAt is when the reconcile handler logged "Reconciling"
// right before calling Reconcile; Start is when its first client call began.
// EndedAt is the synchronous lifecycle timestamp for its result; Last is when
// its latest client call returned. Result mirrors the reconcile_total label.
type managerReconcileEntry struct {
	Controller string
	ID         types.UID
	InvokedAt  time.Time
	Start      time.Time
	Last       time.Time
	EndedAt    time.Time
	ResultSeen bool
	Result     string
	// RequeueAfter is the timer duration the reconcile returned, parsed from
	// "Reconcile done, requeueing after <d>"; zero when absent or unparsed.
	RequeueAfter time.Duration
	Reads        []managerTracedObject
	Writes       []managerTracedWrite
}

// beginAt is the reconcile's invocation, or its first client call when the
// lifecycle line is absent.
func (e *managerReconcileEntry) beginAt() time.Time {
	if !e.InvokedAt.IsZero() {
		return e.InvokedAt
	}
	return e.Start
}

// endAt is when the reconcile result was recorded, or its last client call.
func (e *managerReconcileEntry) endAt() time.Time {
	if !e.EndedAt.IsZero() {
		return e.EndedAt
	}
	return e.Last
}

// consumed reports whether the reconcile read the stimulus object at or after
// the stimulus revision through its cached client. APIReader revalidations
// (Direct) do not count: the gate evaluated its own earlier read, so a
// diagnostic hit does not prove the stimulus drove this pass.
func (e *managerReconcileEntry) consumed(stim managerStimulus) bool {
	for _, read := range e.Reads {
		if !read.Direct && read.Kind == stim.Kind && read.Key == stim.Key && read.RV >= stim.RV {
			return true
		}
	}
	return false
}

// stimulusReadAt returns when the reconcile's first qualifying client read
// observed the stimulus revision, and whether that happened.
func (e *managerReconcileEntry) stimulusReadAt(stim managerStimulus) (time.Time, bool) {
	for _, read := range e.Reads {
		if !read.Direct && read.Kind == stim.Kind && read.Key == stim.Key && read.RV >= stim.RV {
			return read.At, true
		}
	}
	return time.Time{}, false
}

// managerTrace attributes the reconcilers' client calls to reconciles through
// controller.ReconcileIDFromContext. Calls outside a reconcile (watch map
// functions, setup) carry no ID and are not recorded.
type managerTrace struct {
	mu      sync.Mutex
	entries []*managerReconcileEntry
	byID    map[types.UID]*managerReconcileEntry
	// gate, when armed for a controller, holds reconcile invocations at the
	// synchronous "Reconciling" lifecycle line - immediately before Reconcile
	// runs - so a test-controlled write can commit before any new invocation
	// starts. Invocations record their time at release, which is after the
	// write returned, making "commit < invocation" provable instead of
	// ambiguous. Only test-side writes arm it; recorder stimuli never do.
	gateController string
	gateRelease    chan struct{}
}

func newManagerTrace() *managerTrace {
	return &managerTrace{byID: map[types.UID]*managerReconcileEntry{}}
}

func (tr *managerTrace) entryFor(controllerName string, id types.UID) *managerReconcileEntry {
	entry := tr.byID[id]
	if entry == nil {
		entry = &managerReconcileEntry{Controller: controllerName, ID: id}
		tr.byID[id] = entry
		tr.entries = append(tr.entries, entry)
	}
	return entry
}

// armGate holds the next reconcile invocations of controllerName at the
// "Reconciling" lifecycle line until release runs. The caller must run
// release exactly once, on every path, after the controlled write returned.
// Arming while a gate is already armed is a test bug: it would orphan the
// earlier blocked worker, so it fails the test after freeing that worker.
func (tr *managerTrace) armGate(t *testing.T, controllerName string) (release func()) {
	t.Helper()
	releaseCh := make(chan struct{})
	tr.mu.Lock()
	if tr.gateRelease != nil {
		orphaned := tr.gateRelease
		tr.gateController = ""
		tr.gateRelease = nil
		tr.mu.Unlock()
		close(orphaned)
		t.Fatalf("armGate(%q): a gate is already armed; the earlier worker was orphaned", controllerName)
		return func() {}
	}
	tr.gateController = controllerName
	tr.gateRelease = releaseCh
	tr.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			tr.mu.Lock()
			armed := tr.gateRelease == releaseCh
			if armed {
				tr.gateController = ""
				tr.gateRelease = nil
			}
			tr.mu.Unlock()
			if armed {
				close(releaseCh)
			}
		})
	}
}

// releaseAllGates drops any armed gate; used on teardown so a blocked worker
// can exit.
func (tr *managerTrace) releaseAllGates() {
	tr.mu.Lock()
	release := tr.gateRelease
	tr.gateController = ""
	tr.gateRelease = nil
	tr.mu.Unlock()
	if release != nil {
		close(release)
	}
}

// invoked records the "Reconciling" lifecycle line. When a gate is armed for
// this controller the invocation waits at the gate; its recorded time is the
// release instant, which the gate caller guarantees is after the stimulus
// write returned - the invocation provably follows the commit.
func (tr *managerTrace) invoked(controllerName string, id types.UID) {
	tr.mu.Lock()
	gate := tr.gateRelease
	gated := tr.gateController == controllerName && gate != nil
	tr.mu.Unlock()
	if gated {
		<-gate
	}
	invokedAt := time.Now()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	entry := tr.entryFor(controllerName, id)
	entry.InvokedAt = invokedAt
}

// ended records the reconcile's result lifecycle line. after carries the
// RequeueAfter duration for managerResultRequeueAfter results.
func (tr *managerTrace) ended(id types.UID, result string, after time.Duration) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	entry := tr.byID[id]
	if entry == nil {
		return
	}
	entry.ResultSeen = true
	entry.Result = result
	entry.EndedAt = time.Now()
	if result == managerResultRequeueAfter {
		entry.RequeueAfter = after
	}
}

func (tr *managerTrace) record(ctx context.Context, controllerName string, start, end time.Time, reads []managerTracedObject, write *managerTracedWrite) {
	id := controller.ReconcileIDFromContext(ctx)
	if id == "" {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	entry := tr.entryFor(controllerName, id)
	if entry.Start.IsZero() {
		entry.Start = start
	}
	if end.After(entry.Last) {
		entry.Last = end
	}
	entry.Reads = append(entry.Reads, reads...)
	if write != nil {
		entry.Writes = append(entry.Writes, *write)
	}
}

func (tr *managerTrace) get(ctx context.Context, controllerName string, reader client.Reader, key client.ObjectKey, obj client.Object, direct bool, opts ...client.GetOption) error {
	start := time.Now()
	err := reader.Get(ctx, key, obj, opts...)
	var reads []managerTracedObject
	if err == nil {
		if read, ok := managerTracedObjectOf(obj); ok {
			read.At = time.Now()
			read.Direct = direct
			reads = append(reads, read)
		}
	}
	tr.record(ctx, controllerName, start, time.Now(), reads, nil)
	return err
}

func (tr *managerTrace) list(ctx context.Context, controllerName string, reader client.Reader, list client.ObjectList, direct bool, opts ...client.ListOption) error {
	start := time.Now()
	err := reader.List(ctx, list, opts...)
	var reads []managerTracedObject
	if err == nil {
		at := time.Now()
		_ = meta.EachListItem(list, func(item runtime.Object) error {
			if read, ok := managerTracedObjectOf(item); ok {
				read.At = at
				read.Direct = direct
				reads = append(reads, read)
			}
			return nil
		})
	}
	tr.record(ctx, controllerName, start, time.Now(), reads, nil)
	return err
}

// recordWrite records a write call; obj holds the server response after a
// successful call.
func (tr *managerTrace) recordWrite(ctx context.Context, controllerName string, start time.Time, obj any, err error) {
	end := time.Now()
	var write *managerTracedWrite
	if err == nil {
		if written, ok := managerTracedObjectOf(obj); ok {
			write = &managerTracedWrite{managerTracedObject: written, Start: start, End: end}
		}
	}
	tr.record(ctx, controllerName, start, end, nil, write)
}

// snapshot returns copies of one controller's entries in dispatch order.
func (tr *managerTrace) snapshot(controllerName string) []managerReconcileEntry {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := make([]managerReconcileEntry, 0, len(tr.entries))
	for _, entry := range tr.entries {
		if entry.Controller != controllerName {
			continue
		}
		copied := *entry
		copied.Reads = slices.Clone(entry.Reads)
		copied.Writes = slices.Clone(entry.Writes)
		out = append(out, copied)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].beginAt().Before(out[j].beginAt()) })
	return out
}

// writeProducing returns the traced reconciler write whose response carried
// revision rv for the object.
func (tr *managerTrace) writeProducing(kind string, key types.NamespacedName, rv int64) (managerTracedWrite, bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, entry := range tr.entries {
		for _, write := range entry.Writes {
			if write.Kind == kind && write.Key == key && write.RV == rv {
				return write, true
			}
		}
	}
	return managerTracedWrite{}, false
}

// countSince returns how many reconciles of the controller were invoked at or
// after t.
func (tr *managerTrace) countSince(controllerName string, t time.Time) int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	count := 0
	for _, entry := range tr.entries {
		if entry.Controller == controllerName && !entry.beginAt().Before(t) {
			count++
		}
	}
	return count
}

// workSince sums the recorded end-to-invocation spans of the controller's
// reconciles invoked at or after t.
func (tr *managerTrace) workSince(controllerName string, t time.Time) time.Duration {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var total time.Duration
	for _, entry := range tr.entries {
		if entry.Controller != controllerName || entry.beginAt().Before(t) || entry.endAt().IsZero() {
			continue
		}
		total += entry.endAt().Sub(entry.beginAt())
	}
	return total
}

// managerTracedObjectOf reads kind, key, and resourceVersion from a typed
// object, an unstructured object, or an unstructured apply configuration.
func managerTracedObjectOf(obj any) (managerTracedObject, bool) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return managerTracedObject{}, false
	}
	rv, err := strconv.ParseInt(accessor.GetResourceVersion(), 10, 64)
	if err != nil {
		return managerTracedObject{}, false
	}
	return managerTracedObject{
		Kind: managerKindOf(obj),
		Key:  types.NamespacedName{Namespace: accessor.GetNamespace(), Name: accessor.GetName()},
		RV:   rv,
	}, true
}

// managerKindOf names the object kind without a scheme lookup: unstructured
// objects carry it, typed objects are named by their Go type.
func managerKindOf(obj any) string {
	if named, ok := obj.(interface{ GetKind() string }); ok {
		return named.GetKind()
	}
	typ := reflect.TypeOf(obj)
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ.Name()
}

// managerTracingReader traces a reconciler's APIReader.
type managerTracingReader struct {
	client.Reader
	trace      *managerTrace
	controller string
}

func (r *managerTracingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return r.trace.get(ctx, r.controller, r.Reader, key, obj, true, opts...)
}

func (r *managerTracingReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return r.trace.list(ctx, r.controller, r.Reader, list, true, opts...)
}

// managerTracingClient traces a reconciler's Client: reads with the revisions
// they returned, and writes with the revisions the API server returned.
type managerTracingClient struct {
	client.Client
	trace      *managerTrace
	controller string
}

func (c *managerTracingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.trace.get(ctx, c.controller, c.Client, key, obj, false, opts...)
}

func (c *managerTracingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.trace.list(ctx, c.controller, c.Client, list, false, opts...)
}

func (c *managerTracingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	start := time.Now()
	err := c.Client.Create(ctx, obj, opts...)
	c.trace.recordWrite(ctx, c.controller, start, obj, err)
	return err
}

func (c *managerTracingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	start := time.Now()
	err := c.Client.Update(ctx, obj, opts...)
	c.trace.recordWrite(ctx, c.controller, start, obj, err)
	return err
}

func (c *managerTracingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	start := time.Now()
	err := c.Client.Patch(ctx, obj, patch, opts...)
	c.trace.recordWrite(ctx, c.controller, start, obj, err)
	return err
}

func (c *managerTracingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	start := time.Now()
	err := c.Client.Delete(ctx, obj, opts...)
	c.trace.record(ctx, c.controller, start, time.Now(), nil, nil)
	return err
}

func (c *managerTracingClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	start := time.Now()
	err := c.Client.Apply(ctx, obj, opts...)
	c.trace.recordWrite(ctx, c.controller, start, obj, err)
	return err
}

func (c *managerTracingClient) Status() client.SubResourceWriter {
	return &managerTracingStatus{SubResourceWriter: c.Client.Status(), trace: c.trace, controller: c.controller}
}

// managerTracingStatus traces status writes, including unstructured status
// Apply calls whose response is decoded into the apply configuration.
type managerTracingStatus struct {
	client.SubResourceWriter
	trace      *managerTrace
	controller string
}

func (s *managerTracingStatus) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	start := time.Now()
	err := s.SubResourceWriter.Update(ctx, obj, opts...)
	s.trace.recordWrite(ctx, s.controller, start, obj, err)
	return err
}

func (s *managerTracingStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	start := time.Now()
	err := s.SubResourceWriter.Patch(ctx, obj, patch, opts...)
	s.trace.recordWrite(ctx, s.controller, start, obj, err)
	return err
}

func (s *managerTracingStatus) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	start := time.Now()
	err := s.SubResourceWriter.Apply(ctx, obj, opts...)
	s.trace.recordWrite(ctx, s.controller, start, obj, err)
	return err
}

// ---------------------------------------------------------------------------
// Wakeup oracle (QA §6)
// ---------------------------------------------------------------------------

// managerStimulus is the event whose watch wakeup an assertion proves: the
// object revision it committed and bounds on the commit instant.
type managerStimulus struct {
	What     string
	Kind     string
	Key      types.NamespacedName
	RV       int64
	CommitLB time.Time // the write call began; the commit is not earlier
	CommitUB time.Time // the write call returned; the commit is not later
}

func (s managerStimulus) String() string {
	return fmt.Sprintf("%s (%s %s rv=%d, written %s-%s)", s.What, s.Kind, s.Key, s.RV,
		s.CommitLB.Format("15:04:05.000"), s.CommitUB.Format("15:04:05.000"))
}

// managerWakeup is the oracle's verdict. Undecided verdicts wait for more
// reconciles.
type managerWakeup struct {
	Decided  bool
	Pass     bool
	Consumer *managerReconcileEntry
	Deadline time.Time
	Detail   string
}

// managerWakeupVerdict judges the QA §6 causal chain for one stimulus over a
// controller's reconciles in dispatch order: a reconcile invoked after the
// stimulus commit that read the committed revision through its operative
// (cached) client must have been invoked before the periodic expiry pending
// at the stimulus.
//
// The pending expiry comes from the last reconcile invoked at or before the
// write began and its synchronously recorded result (entry.Result). A
// RequeueAfter armed by it cannot dispatch before that reconcile's recorded
// end plus the RequeueAfter it actually returned (entry.RequeueAfter),
// because controller-runtime arms the timer after Reconcile returns; that
// bound is the deadline even when it already elapsed, since an elapsed lower
// bound does not prove the timer fired. A requeue_after result without a
// recorded duration makes the window unknowable. A result without a timer
// (success) leaves the event as the only wakeup: the deadline (CommitUB plus
// interval) stays informational and a qualifying consumer passes on
// causality alone. An error or requeue result arms a rate-limited retry that
// can dispatch at any time, so no wakeup is attributable to the stimulus; a
// missing result makes the pending window unknowable. These return undecided
// terminal verdicts (Decided=false, Detail set) rather than a fabricated
// deadline.
//
// Admission requires a recorded "Reconciling" invocation at or after
// CommitUB: only an invocation provably after the commit satisfies "event
// commit < reconcile start". A consumer without a recorded invocation (the
// lifecycle line renamed or re-leveled, which also disarms the write-time
// gate) cannot prove that order and is terminal-undecided, never admitted on
// its first client call. An entry invoked inside the write call that later
// reads the new revision is ambiguous - it proves no causality - but it is
// not a miss either, so it is skipped. Completion times play no part: the
// timer is consumed by the event's enqueue, so a slow consuming reconcile
// cannot miss it.
func managerWakeupVerdict(entries []managerReconcileEntry, stim managerStimulus, interval time.Duration) managerWakeup {
	deadline := stim.CommitUB.Add(interval)
	timer := false
	for index := len(entries) - 1; index >= 0; index-- {
		previous := entries[index]
		if previous.beginAt().After(stim.CommitLB) {
			continue
		}
		switch {
		case !previous.ResultSeen && index == len(entries)-1:
			// The predecessor may still be running; its result decides
			// whether a periodic timer is pending, so keep waiting.
			return managerWakeup{Deadline: deadline}
		case !previous.ResultSeen:
			// Single-worker dispatch means a completed predecessor always
			// carries a recorded result; its absence makes the pending
			// window unknowable, not a deadline.
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"reconcile %s dispatched before the stimulus has no recorded result, so its pending queue state is unknown", previous.ID)}
		case previous.Result == managerResultSuccess:
			// No timer armed; the event is the only possible wakeup.
		case previous.Result == managerResultRateLimited:
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"reconcile %s dispatched before the stimulus returned a rate-limited retry, which can dispatch at any time", previous.ID)}
		case previous.RequeueAfter <= 0:
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"reconcile %s dispatched before the stimulus returned %q without a recorded RequeueAfter, so the pending expiry is unknown", previous.ID, previous.Result)}
		default:
			timer = true
			deadline = previous.endAt().Add(previous.RequeueAfter)
		}
		break
	}
	// ambiguous marks a reconcile that read the stimulus revision before the
	// deadline but was invoked inside (or before) the write call: it proves
	// nothing about causality, yet it means the revision was consumed before
	// expiry, so a miss can no longer be asserted.
	ambiguous := false
	for index := range entries {
		entry := &entries[index]
		if entry.consumed(stim) && entry.InvokedAt.IsZero() {
			// Without the lifecycle line neither the invocation order nor
			// the write-time gate holds; fail closed.
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"reconcile %s read the revision but has no recorded invocation, so commit < start is unprovable", entry.ID)}
		}
		admitted := !entry.beginAt().Before(stim.CommitUB)
		if entry.consumed(stim) {
			if admitted {
				if !timer {
					// No timer was pending; the event is the only wakeup.
					return managerWakeup{Decided: true, Pass: true, Consumer: entry, Deadline: deadline}
				}
				if entry.beginAt().Before(deadline) {
					return managerWakeup{Decided: true, Pass: true, Consumer: entry, Deadline: deadline}
				}
				return managerWakeup{Decided: true, Consumer: entry, Deadline: deadline, Detail: fmt.Sprintf(
					"the first reconcile that read the revision (%s) was invoked at %s, not before the pending periodic expiry %s",
					entry.ID, entry.beginAt().Format("15:04:05.000"), deadline.Format("15:04:05.000"))}
			}
			if at, ok := entry.stimulusReadAt(stim); ok && at.Before(deadline) {
				ambiguous = true
			}
		}
		if entry.beginAt().Before(deadline) {
			// Still inside the pending window; later entries may consume.
			continue
		}
		// A dispatch at or after the deadline exists; single-worker
		// execution means every earlier reconcile already ran.
		switch {
		case timer && !ambiguous:
			return managerWakeup{Decided: true, Deadline: deadline, Detail: fmt.Sprintf(
				"no reconcile read the revision before the pending periodic expiry %s", deadline.Format("15:04:05.000"))}
		case ambiguous:
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"a reconcile invoked inside the stimulus write read the revision before %s, so causality is unprovable", deadline.Format("15:04:05.000"))}
		default:
			return managerWakeup{Deadline: deadline, Detail: fmt.Sprintf(
				"no admitted consumer by %s and no pending timer bounds the wait", deadline.Format("15:04:05.000"))}
		}
	}
	// Ambiguity alone never ends the wait: a later reconcile may still prove
	// the wakeup. Only a closed window (a dispatch at or after the deadline)
	// makes an ambiguous verdict terminal.
	return managerWakeup{Deadline: deadline}
}

// ---------------------------------------------------------------------------
// Stateful fake Cloudflare API shared by both reconcilers
// ---------------------------------------------------------------------------

type managerRemoteCall struct {
	At  time.Time
	Op  string
	Arg string
}

// managerRemote is the single stateful fake backing both the tunnel
// reconciler's TunnelCloudflareClient and the Gateway reconciler's
// flarecloudflare.API. It records every call with its primary argument so
// tests can prove which writer consumed which status change and when.
type managerRemote struct {
	mu          sync.Mutex
	accountID   string
	token       string
	tunnels     map[string]flarecloudflare.Tunnel
	tokens      map[string]string
	configs     map[string]flarecloudflare.TunnelConfiguration
	connections map[string][]flarecloudflare.TunnelConnector
	dns         map[string]map[string]flarecloudflare.DNSRecord
	calls       []managerRemoteCall
	fail        map[string]error
	next        int
}

func newManagerRemote() *managerRemote {
	return &managerRemote{
		tunnels:     map[string]flarecloudflare.Tunnel{},
		tokens:      map[string]string{},
		configs:     map[string]flarecloudflare.TunnelConfiguration{},
		connections: map[string][]flarecloudflare.TunnelConnector{},
		dns:         map[string]map[string]flarecloudflare.DNSRecord{},
		fail:        map[string]error{},
	}
}

func (f *managerRemote) use(token, accountID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
	f.accountID = accountID
}

func (f *managerRemote) record(op, arg string) error {
	f.calls = append(f.calls, managerRemoteCall{At: time.Now(), Op: op, Arg: arg})
	if err := f.fail[op]; err != nil {
		return err
	}
	return nil
}

// callsSince returns recorded calls after at, optionally filtered by op.
func (f *managerRemote) callsSince(at time.Time, op string) []managerRemoteCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []managerRemoteCall
	for _, call := range f.calls {
		if call.At.After(at) && (op == "" || call.Op == op) {
			out = append(out, call)
		}
	}
	return out
}

func (f *managerRemote) failOp(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[op] = err
}

func (f *managerRemote) clearFail(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fail, op)
}

func (f *managerRemote) putTunnel(tunnel flarecloudflare.Tunnel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tunnel = f.normalize(tunnel)
	f.tunnels[tunnel.ID] = tunnel
	f.tokens[tunnel.ID] = "token-" + tunnel.ID
	f.configs[tunnel.ID] = f.configuration(tunnel.ID, 1)
}

func (f *managerRemote) normalize(tunnel flarecloudflare.Tunnel) flarecloudflare.Tunnel {
	if tunnel.AccountTag == "" {
		tunnel.AccountTag = f.accountID
	}
	if tunnel.Type == "" {
		tunnel.Type = flarecloudflare.TunnelTypeCloudflared
	}
	if tunnel.ConfigSource == "" {
		tunnel.ConfigSource = flarecloudflare.TunnelConfigSourceCloudflare
	}
	if tunnel.Status == "" {
		tunnel.Status = flarecloudflare.TunnelStatusHealthy
	}
	if tunnel.CreatedAt.IsZero() {
		tunnel.CreatedAt = time.Unix(100, 0)
	}
	return tunnel
}

func (f *managerRemote) configuration(tunnelID string, version int64) flarecloudflare.TunnelConfiguration {
	return flarecloudflare.TunnelConfiguration{
		AccountID: f.accountID, TunnelID: tunnelID, Version: version,
		Source: flarecloudflare.TunnelConfigSourceCloudflare, CreatedAt: time.Unix(100, 0),
		Config: []byte(`{"ingress":[{"service":"http_status:404"}]}`),
	}
}

func (f *managerRemote) setConfigVersion(tunnelID string, version int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs[tunnelID] = f.configuration(tunnelID, version)
}

func (f *managerRemote) configVersion(tunnelID string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configs[tunnelID].Version
}

func (f *managerRemote) CreateTunnel(_ context.Context, name string) (flarecloudflare.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateTunnel", name); err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	f.next++
	id := fmt.Sprintf("tunnel-%d", f.next)
	tunnel := f.normalize(flarecloudflare.Tunnel{ID: id, Name: name, Status: flarecloudflare.TunnelStatusHealthy})
	f.tunnels[id] = tunnel
	f.tokens[id] = "token-" + id
	f.configs[id] = f.configuration(id, 0)
	return tunnel, nil
}

func (f *managerRemote) GetTunnel(_ context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnel", tunnelID); err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	tunnel, ok := f.tunnels[tunnelID]
	if !ok {
		return flarecloudflare.Tunnel{}, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	return f.normalize(tunnel), nil
}

func (f *managerRemote) ListTunnels(_ context.Context, _ flarecloudflare.TunnelListOptions) ([]flarecloudflare.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListTunnels", ""); err != nil {
		return nil, err
	}
	out := make([]flarecloudflare.Tunnel, 0, len(f.tunnels))
	for _, tunnel := range f.tunnels {
		out = append(out, tunnel)
	}
	return out, nil
}

func (f *managerRemote) UpdateTunnelName(_ context.Context, tunnelID, name string) (flarecloudflare.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateTunnelName", tunnelID); err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	tunnel, ok := f.tunnels[tunnelID]
	if !ok {
		return flarecloudflare.Tunnel{}, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	tunnel.Name = name
	f.tunnels[tunnelID] = tunnel
	return tunnel, nil
}

func (f *managerRemote) DeleteTunnel(_ context.Context, tunnelID string, cascade bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !cascade {
		return errors.New("cascade must be true")
	}
	if err := f.record("DeleteTunnel", tunnelID); err != nil {
		return err
	}
	delete(f.tunnels, tunnelID)
	delete(f.tokens, tunnelID)
	return nil
}

func (f *managerRemote) GetTunnelToken(_ context.Context, tunnelID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelToken", tunnelID); err != nil {
		return "", err
	}
	token, ok := f.tokens[tunnelID]
	if !ok {
		return "", fmt.Errorf("token for %s not found", tunnelID)
	}
	return token, nil
}

func (f *managerRemote) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelConfiguration", tunnelID); err != nil {
		return flarecloudflare.TunnelConfiguration{}, err
	}
	configuration, ok := f.configs[tunnelID]
	if !ok {
		return flarecloudflare.TunnelConfiguration{}, fmt.Errorf("configuration for %s not found", tunnelID)
	}
	return configuration, nil
}

func (f *managerRemote) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateTunnelConfiguration", tunnelID); err != nil {
		return flarecloudflare.TunnelConfiguration{}, err
	}
	version := f.configs[tunnelID].Version + 1
	configuration := f.configuration(tunnelID, version)
	f.configs[tunnelID] = configuration
	return configuration, nil
}

func (f *managerRemote) IssueTunnelManagementToken(_ context.Context, tunnelID string, resources []flarecloudflare.TunnelManagementResource) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("IssueTunnelManagementToken", tunnelID); err != nil {
		return "", err
	}
	if len(resources) == 0 {
		return "", errors.New("management token resources are empty")
	}
	return "management-token-" + tunnelID, nil
}

func (f *managerRemote) GetTunnelConnector(_ context.Context, tunnelID, connectorID string, _ int64) (flarecloudflare.TunnelConnector, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, connector := range f.connections[tunnelID] {
		if connector.ID == connectorID {
			return connector, nil
		}
	}
	return flarecloudflare.TunnelConnector{}, fmt.Errorf("connector %s not found", connectorID)
}

func (f *managerRemote) ListTunnelConnections(_ context.Context, tunnelID string, limit int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListTunnelConnections", tunnelID); err != nil {
		return nil, false, err
	}
	connectors := append([]flarecloudflare.TunnelConnector(nil), f.connections[tunnelID]...)
	truncated := int64(len(connectors)) > limit
	if truncated {
		connectors = connectors[:limit]
	}
	return connectors, truncated, nil
}

func (f *managerRemote) EvictTunnelConnections(_ context.Context, tunnelID string, connectorID *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("EvictTunnelConnections", tunnelID); err != nil {
		return err
	}
	connectors := f.connections[tunnelID]
	for index := range connectors {
		if connectorID == nil || connectors[index].ID == *connectorID {
			connectors[index].Connections = nil
			connectors[index].ConnectionsTruncated = false
		}
	}
	f.connections[tunnelID] = connectors
	return nil
}

func (f *managerRemote) WithTunnelLock(_ context.Context, tunnelID string, fn func() error) error {
	f.mu.Lock()
	f.calls = append(f.calls, managerRemoteCall{At: time.Now(), Op: "WithTunnelLock", Arg: tunnelID})
	f.mu.Unlock()
	return fn()
}

func (f *managerRemote) ListDNSRecords(_ context.Context, zoneID, name string) ([]flarecloudflare.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListDNSRecords", name); err != nil {
		return nil, err
	}
	var out []flarecloudflare.DNSRecord
	for _, record := range f.dns[zoneID] {
		if flarecloudflare.DNSHostnamesEqual(record.Name, name) {
			out = append(out, record)
		}
	}
	return out, nil
}

func (f *managerRemote) ListDNSRecordsByComment(_ context.Context, zoneID, commentContains string) ([]flarecloudflare.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListDNSRecordsByComment", commentContains); err != nil {
		return nil, err
	}
	var out []flarecloudflare.DNSRecord
	for _, record := range f.dns[zoneID] {
		if strings.Contains(strings.ToLower(record.Comment), strings.ToLower(commentContains)) {
			out = append(out, record)
		}
	}
	return out, nil
}

func (f *managerRemote) CreateCNAME(_ context.Context, zoneID string, input flarecloudflare.DNSRecordInput) (flarecloudflare.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateCNAME", input.Name); err != nil {
		return flarecloudflare.DNSRecord{}, err
	}
	f.next++
	record := managerDNSRecordFromInput(fmt.Sprintf("record-%d", f.next), input)
	if f.dns[zoneID] == nil {
		f.dns[zoneID] = map[string]flarecloudflare.DNSRecord{}
	}
	f.dns[zoneID][record.ID] = record
	return record, nil
}

func (f *managerRemote) UpdateCNAME(_ context.Context, zoneID, recordID string, input flarecloudflare.DNSRecordInput) (flarecloudflare.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateCNAME", recordID); err != nil {
		return flarecloudflare.DNSRecord{}, err
	}
	record := managerDNSRecordFromInput(recordID, input)
	if f.dns[zoneID] == nil {
		f.dns[zoneID] = map[string]flarecloudflare.DNSRecord{}
	}
	f.dns[zoneID][recordID] = record
	return record, nil
}

func (f *managerRemote) DeleteDNSRecord(_ context.Context, zoneID, recordID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DeleteDNSRecord", recordID); err != nil {
		return err
	}
	delete(f.dns[zoneID], recordID)
	return nil
}

// hasDNSRecord reports whether the fake remote holds the record.
func (f *managerRemote) hasDNSRecord(zoneID, recordID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.dns[zoneID][recordID]
	return ok
}

func managerDNSRecordFromInput(id string, input flarecloudflare.DNSRecordInput) flarecloudflare.DNSRecord {
	record := flarecloudflare.DNSRecord{
		ID: id, Name: input.Name, Type: "CNAME", Content: input.Content, Comment: input.Comment,
		Settings: input.Settings,
	}
	if input.Proxied != nil {
		record.Proxied = *input.Proxied
	}
	if input.TTL != nil {
		record.TTL = *input.TTL
	}
	return record
}

// managerGatewayAPI adapts managerRemote to the full flarecloudflare.API the
// Gateway reconciler requires. The embedded nil interface satisfies the
// account/WARP/Access/network/device/organization/gateway surfaces the
// Cloudflare-mode Gateway path never calls; the tunnel and DNS methods are
// forwarded explicitly to the shared stateful fake.
type managerGatewayAPI struct {
	flarecloudflare.API
	remote *managerRemote
}

func (a *managerGatewayAPI) CreateTunnel(ctx context.Context, name string) (flarecloudflare.Tunnel, error) {
	return a.remote.CreateTunnel(ctx, name)
}
func (a *managerGatewayAPI) GetTunnel(ctx context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	return a.remote.GetTunnel(ctx, tunnelID)
}
func (a *managerGatewayAPI) UpdateTunnelName(ctx context.Context, tunnelID, name string) (flarecloudflare.Tunnel, error) {
	return a.remote.UpdateTunnelName(ctx, tunnelID, name)
}
func (a *managerGatewayAPI) DeleteTunnel(ctx context.Context, tunnelID string, cascade bool) error {
	return a.remote.DeleteTunnel(ctx, tunnelID, cascade)
}
func (a *managerGatewayAPI) GetTunnelToken(ctx context.Context, tunnelID string) (string, error) {
	return a.remote.GetTunnelToken(ctx, tunnelID)
}
func (a *managerGatewayAPI) GetTunnelConfiguration(ctx context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	return a.remote.GetTunnelConfiguration(ctx, tunnelID)
}
func (a *managerGatewayAPI) UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	return a.remote.UpdateTunnelConfiguration(ctx, tunnelID, params)
}
func (a *managerGatewayAPI) IssueTunnelManagementToken(ctx context.Context, tunnelID string, resources []flarecloudflare.TunnelManagementResource) (string, error) {
	return a.remote.IssueTunnelManagementToken(ctx, tunnelID, resources)
}
func (a *managerGatewayAPI) GetTunnelConnector(ctx context.Context, tunnelID, connectorID string, limit int64) (flarecloudflare.TunnelConnector, error) {
	return a.remote.GetTunnelConnector(ctx, tunnelID, connectorID, limit)
}
func (a *managerGatewayAPI) ListTunnelConnections(ctx context.Context, tunnelID string, limit int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	return a.remote.ListTunnelConnections(ctx, tunnelID, limit)
}
func (a *managerGatewayAPI) EvictTunnelConnections(ctx context.Context, tunnelID string, connectorID *string) error {
	return a.remote.EvictTunnelConnections(ctx, tunnelID, connectorID)
}
func (a *managerGatewayAPI) WithTunnelLock(ctx context.Context, tunnelID string, fn func() error) error {
	return a.remote.WithTunnelLock(ctx, tunnelID, fn)
}
func (a *managerGatewayAPI) ListTunnels(ctx context.Context, options flarecloudflare.TunnelListOptions) ([]flarecloudflare.Tunnel, error) {
	return a.remote.ListTunnels(ctx, options)
}
func (a *managerGatewayAPI) ListDNSRecords(ctx context.Context, zoneID, name string) ([]flarecloudflare.DNSRecord, error) {
	return a.remote.ListDNSRecords(ctx, zoneID, name)
}
func (a *managerGatewayAPI) ListDNSRecordsByComment(ctx context.Context, zoneID, commentContains string) ([]flarecloudflare.DNSRecord, error) {
	return a.remote.ListDNSRecordsByComment(ctx, zoneID, commentContains)
}
func (a *managerGatewayAPI) CreateCNAME(ctx context.Context, zoneID string, input flarecloudflare.DNSRecordInput) (flarecloudflare.DNSRecord, error) {
	return a.remote.CreateCNAME(ctx, zoneID, input)
}
func (a *managerGatewayAPI) UpdateCNAME(ctx context.Context, zoneID, recordID string, input flarecloudflare.DNSRecordInput) (flarecloudflare.DNSRecord, error) {
	return a.remote.UpdateCNAME(ctx, zoneID, recordID, input)
}
func (a *managerGatewayAPI) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	return a.remote.DeleteDNSRecord(ctx, zoneID, recordID)
}

var _ flarecloudflare.API = (*managerGatewayAPI)(nil)
var _ TunnelCloudflareClient = (*managerRemote)(nil)

// managerGatewayFactory adapts the shared fake to flarecloudflare.ClientFactory.
type managerGatewayFactory struct {
	api *managerGatewayAPI
}

func (f managerGatewayFactory) Client(token, accountID string) flarecloudflare.API {
	f.api.remote.use(token, accountID)
	return f.api
}

// managerProber is the dataplane prober the gate consumes. Its answers are
// mutable so tests can flip Pod readiness and reported config versions.
type managerProber struct {
	mu        sync.Mutex
	ready     bool
	versionFn func() int64
}

func (p *managerProber) ConfigVersion(context.Context, string) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.versionFn != nil {
		return p.versionFn(), nil
	}
	return 0, errors.New("no version configured")
}

func (p *managerProber) Ready(context.Context, string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready {
		return errors.New("not ready")
	}
	return nil
}

func (p *managerProber) set(ready bool, versionFn func() int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ready = ready
	p.versionFn = versionFn
}

// managerSnapshotPublisher is a self-contained SnapshotPublisher with explicit
// ACK control, mirroring the suite fake without depending on it.
type managerSnapshotPublisher struct {
	mu       sync.Mutex
	versions map[string]string
	acked    map[string]string
	nacks    map[string]managerSnapshotNACK
}

func newManagerSnapshotPublisher() *managerSnapshotPublisher {
	return &managerSnapshotPublisher{
		versions: map[string]string{},
		acked:    map[string]string{},
		nacks:    map[string]managerSnapshotNACK{},
	}
}

func (p *managerSnapshotPublisher) SetSnapshot(_ context.Context, key string, snapshot *cachev3.Snapshot) error {
	version, err := translator.SnapshotVersion(snapshot)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.versions[key] != version {
		delete(p.nacks, key)
	}
	p.versions[key] = version
	// Auto-ACK: no assigned QA item exercises the NACK path, and the dataplane
	// gate requires the current version to be ACKed for Programmed=True.
	p.acked[key] = version
	return nil
}

type managerSnapshotNACK struct {
	version string
	detail  string
}

func (p *managerSnapshotPublisher) ClearSnapshot(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.versions, key)
	delete(p.acked, key)
	delete(p.nacks, key)
}

func (p *managerSnapshotPublisher) IsACKed(key, version string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.acked[key] == version
}

func (p *managerSnapshotPublisher) LastNACK(key string) (string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	nack, ok := p.nacks[key]
	return nack.version, nack.detail, ok
}

func (p *managerSnapshotPublisher) ack(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acked[key] = p.versions[key]
}

func (p *managerSnapshotPublisher) version(key string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.versions[key]
}

// ---------------------------------------------------------------------------
// Harness: per-test manager, client, recorders, and reconcilers
// ---------------------------------------------------------------------------

type managerHarness struct {
	t                 *testing.T
	cfg               *rest.Config
	scheme            *runtime.Scheme
	mgr               ctrl.Manager
	client            client.Client
	apiReader         client.Reader
	gatewayReconciler *GatewayReconciler
	direct            client.Client
	recorder          *managerWatchRecorder
	trace             *managerTrace
	remote            *managerRemote
	prober            *managerProber
	snapshots         *managerSnapshotPublisher
	sweep             chan event.GenericEvent
	gwClock           *managerClock
	tunClock          *managerClock
	ctx               context.Context
	cancel            context.CancelFunc
	startErr          atomic.Value
	started           atomic.Bool
	done              chan struct{}
}

func newManagerHarness(t *testing.T) *managerHarness {
	return newManagerHarnessWith(t, nil)
}

// newManagerHarnessWith applies configure to the reconcilers before the
// manager starts, so policy fields are set without racing live reconciles.
func newManagerHarnessWith(t *testing.T, configure func(*GatewayReconciler, *CloudflareTunnelReconciler)) *managerHarness {
	return newManagerHarnessOpts(t, managerHarnessOpts{configure: configure})
}

// managerHarnessOpts carries optional harness wiring beyond the defaults.
type managerHarnessOpts struct {
	// configure mutates the reconcilers before the manager starts.
	configure func(*GatewayReconciler, *CloudflareTunnelReconciler)
	// cacheByObject adds per-object cache options (for example a Transform
	// barrier that holds informer updates for a stale-cache test).
	cacheByObject map[client.Object]cache.ByObject
}

// newManagerHarnessOpts builds the harness with optional wiring.
func newManagerHarnessOpts(t *testing.T, opts managerHarnessOpts) *managerHarness {
	t.Helper()
	// Each test owns its envtest control plane, manager, client, and fake;
	// env.Stop runs via cleanup even when setup fails partway.
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join(managerGatewayAPIDir(), "config", "crd", "standard"),
		},
		ErrorIfCRDPathMissing: true,
	}
	if dir := managerEnvtestAssets(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}
	cfg, err := env.Start()
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("stop envtest: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("start envtest control plane: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("add gateway-api scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add flareway scheme: %v", err)
	}

	trace := newManagerTrace()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// The lifecycle sink sees each reconcile's synchronous invocation and
		// result lines; other manager log output is discarded as before.
		Logger: logr.New(&managerLifecycleSink{trace: trace}),
		// Every test in this package runs its own manager in the same process;
		// controller-runtime's global name registry would otherwise reject the
		// second "gateway"/"cloudflaretunnel" registration.
		Controller: ctrlconfig.Controller{SkipNameValidation: managerPtr(true)},
		Cache:      cache.Options{ByObject: opts.cacheByObject},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create direct client: %v", err)
	}
	// The operator namespace hosts the xDS CA Secret (pki.EnsureCA) and the
	// cluster ownership-key Secret; without it every reconcile fails before
	// dataplane resources are applied.
	if err := direct.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create operator namespace: %v", err)
	}
	recorder, err := newManagerWatchRecorder(cfg)
	if err != nil {
		t.Fatalf("create watch recorder: %v", err)
	}

	remote := newManagerRemote()
	h := &managerHarness{
		t:         t,
		cfg:       cfg,
		scheme:    scheme,
		mgr:       mgr,
		client:    mgr.GetClient(),
		apiReader: mgr.GetAPIReader(),
		direct:    direct,
		recorder:  recorder,
		trace:     trace,
		remote:    remote,
		prober:    &managerProber{ready: true},
		snapshots: newManagerSnapshotPublisher(),
		sweep:     make(chan event.GenericEvent, 16),
		gwClock:   &managerClock{},
		tunClock:  &managerClock{},
		done:      make(chan struct{}),
	}

	// Register teardown before any step that can fail: the manager goroutine,
	// recorder, and sampler must be stopped even when setup dies partway, and
	// env.Stop (registered earlier, so it runs after this cleanup) must not
	// race a live manager.
	h.ctx, h.cancel = context.WithCancel(context.Background())
	t.Cleanup(h.close)

	// Both reconcilers run through tracing clients so every reconcile's start,
	// reads, and writes are attributable to its reconcile ID.
	gatewayReconciler := &GatewayReconciler{
		Client:            &managerTracingClient{Client: mgr.GetClient(), trace: h.trace, controller: "gateway"},
		Scheme:            scheme,
		Snapshots:         h.snapshots,
		BuildSnapshot:     translator.Build,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               h.gwClock.now,
		CloudflareFactory: managerGatewayFactory{api: &managerGatewayAPI{remote: remote}},
		Prober:            h.prober,
		SweepEvents:       h.sweep,
	}
	managerSetAPIReader(gatewayReconciler, &managerTracingReader{Reader: mgr.GetAPIReader(), trace: h.trace, controller: "gateway"})
	h.gatewayReconciler = gatewayReconciler
	if err := gatewayReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayReconciler: %v", err)
	}
	tunnelReconciler := &CloudflareTunnelReconciler{
		Client:            &managerTracingClient{Client: mgr.GetClient(), trace: h.trace, controller: "cloudflaretunnel"},
		Scheme:            scheme,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               h.tunClock.now,
		NewCloudflareClient: func(token, accountID string) (TunnelCloudflareClient, error) {
			remote.use(token, accountID)
			return remote, nil
		},
	}
	managerSetAPIReader(tunnelReconciler, &managerTracingReader{Reader: mgr.GetAPIReader(), trace: h.trace, controller: "cloudflaretunnel"})
	if opts.configure != nil {
		opts.configure(gatewayReconciler, tunnelReconciler)
	}
	if err := tunnelReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup CloudflareTunnelReconciler: %v", err)
	}

	h.started.Store(true)
	go func() {
		defer close(h.done)
		if err := mgr.Start(h.ctx); err != nil {
			h.startErr.Store(err)
		}
	}()
	if !mgr.GetCache().WaitForCacheSync(h.ctx) {
		t.Fatalf("manager cache did not sync")
	}
	return h
}

func (h *managerHarness) close() {
	h.trace.releaseAllGates()
	h.cancel()
	if h.started.Load() {
		select {
		case <-h.done:
		case <-time.After(15 * time.Second):
			h.t.Log("manager did not stop within 15s")
		}
	}
	if err := h.startErr.Load(); err != nil {
		h.t.Errorf("manager exited with error: %v", err)
	}
	h.recorder.close()
}

// managerSetAPIReader injects the manager APIReader into the reconciler when
// the field exists. The pre-fix baseline GatewayReconciler has no APIReader
// field; reflection keeps this file compiling unchanged on both trees without
// altering baseline behavior.
func managerSetAPIReader(reconciler any, reader client.Reader) {
	value := reflect.ValueOf(reconciler)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}
	field := value.Elem().FieldByName("APIReader")
	if !field.IsValid() || !field.CanSet() {
		return
	}
	readerValue := reflect.ValueOf(reader)
	if readerValue.Type().AssignableTo(field.Type()) {
		field.Set(readerValue)
	}
}

// ---------------------------------------------------------------------------
// Fixture builder
// ---------------------------------------------------------------------------

type managerFixtureSpec struct {
	dnsMode        v1alpha1.DNSMode
	withRoutes     bool
	withAccount    bool
	explicitTunnel bool
	mutateTunnel   func(*v1alpha1.CloudflareTunnel)
	mutateGateway  func(*gatewayv1.Gateway)
}

type managerFixture struct {
	namespace   string
	gatewayName string
	className   string
	configName  string
	accountName string
	secretName  string
	hostname    string
	gatewayKey  types.NamespacedName
	tunnelKey   types.NamespacedName
	gateway     *gatewayv1.Gateway
	tunnel      *v1alpha1.CloudflareTunnel
	account     *v1alpha1.CloudflareAccount
	serviceName string
	routeName   string
	policyName  string
	podName     string
}

func (h *managerHarness) buildFixture(t *testing.T, spec managerFixtureSpec) *managerFixture {
	t.Helper()
	id := managerFixtureN.Add(1)
	f := &managerFixture{
		namespace:   fmt.Sprintf("qa92-ns-%d", id),
		gatewayName: fmt.Sprintf("qa92-gw-%d", id),
		className:   fmt.Sprintf("qa92-class-%d", id),
		configName:  fmt.Sprintf("qa92-cfg-%d", id),
		accountName: fmt.Sprintf("qa92-acct-%d", id),
		secretName:  "cf-token",
		hostname:    fmt.Sprintf("edge-%d.example.com", id),
		serviceName: "backend",
		routeName:   "route",
		policyName:  "tls-policy",
		podName:     "dataplane-0",
	}
	f.gatewayKey = types.NamespacedName{Namespace: f.namespace, Name: f.gatewayName}
	f.tunnelKey = f.gatewayKey // implicit tunnel named after the Gateway

	h.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   f.namespace,
		Labels: map[string]string{"tenant": "qa92"},
	}})

	h.create(t, &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: f.configName},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: f.accountName},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: spec.dnsMode},
		},
	})
	group := gatewayv1.Group(v1alpha1.Group)
	kind := gatewayv1.Kind("GatewayClassConfig")
	h.create(t, &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: f.className},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: f.configName},
		},
	})

	h.create(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: f.secretName, Namespace: f.namespace},
		Data:       map[string][]byte{"token": []byte("qa92-token")},
	})

	if spec.withAccount {
		f.account = h.createAccount(t, f)
	}

	if spec.explicitTunnel {
		f.tunnelKey = types.NamespacedName{Namespace: f.namespace, Name: f.gatewayName + "-tunnel"}
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: f.tunnelKey.Name, Namespace: f.namespace},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: f.accountName},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: spec.dnsMode},
			},
		}
		if spec.mutateTunnel != nil {
			spec.mutateTunnel(tunnel)
		}
		h.create(t, tunnel)
	}

	hostname := gatewayv1.Hostname(f.hostname)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: f.gatewayName, Namespace: f.namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(f.className),
			Listeners: []gatewayv1.Listener{{
				Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	if spec.explicitTunnel {
		gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: group, Kind: gatewayv1.Kind("CloudflareTunnel"), Name: f.tunnelKey.Name,
			},
		}
	}
	if spec.mutateGateway != nil {
		spec.mutateGateway(gateway)
	}
	h.create(t, gateway)

	if spec.withRoutes {
		h.create(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: f.serviceName, Namespace: f.namespace},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 443}},
				Selector: map[string]string{"app": "backend"},
			},
		})
		h.create(t, &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: f.routeName, Namespace: f.namespace},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayName)}},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: gatewayv1.ObjectName(f.serviceName),
								Port: (*gatewayv1.PortNumber)(managerPtr(int32(443))),
							},
						},
					}},
				}},
			},
		})
		wellKnown := gatewayv1.WellKnownCACertificatesSystem
		h.create(t, &gatewayv1.BackendTLSPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: f.policyName, Namespace: f.namespace},
			Spec: gatewayv1.BackendTLSPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "", Kind: "Service", Name: gatewayv1.ObjectName(f.serviceName),
					},
				}},
				Validation: gatewayv1.BackendTLSPolicyValidation{
					WellKnownCACertificates: &wellKnown,
					Hostname:                gatewayv1.PreciseHostname("backend.internal"),
				},
			},
		})
	}

	// The Gateway creates the implicit CloudflareTunnel on its first pass.
	h.waitFor(t, 20*time.Second, "CloudflareTunnel to exist", func() (bool, error) {
		var tunnel v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, f.tunnelKey, &tunnel); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		f.tunnel = tunnel.DeepCopy()
		return true, nil
	})

	if spec.withAccount {
		// With no account the tunnel cannot be provisioned, so dataplane
		// wiring is deferred — callers that add the account later invoke
		// ensureDataplane themselves.
		h.ensureDataplane(t, f)
	}

	f.gateway = h.getGateway(t, f.gatewayKey)
	return f
}

// ensureDataplane stands up the fake dataplane Pod, arms the prober, and ACKs
// the published xDS snapshot — the pieces the convergence gate consumes.
func (h *managerHarness) ensureDataplane(t *testing.T, f *managerFixture) {
	t.Helper()
	// The dataplane Deployment must exist before the fake Pod is created.
	deploymentName := dataplane.ResourceName(&ir.Gateway{Key: f.gatewayKey})
	h.waitFor(t, 20*time.Second, "dataplane Deployment", func() (bool, error) {
		var deployment appsv1.Deployment
		if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: deploymentName}, &deployment); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	h.create(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.podName,
			Namespace: f.namespace,
			Labels:    map[string]string{dataplane.StandardGatewayLabelKey: f.gatewayName},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "example.invalid/pause"}}},
	})
	var pod corev1.Pod
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
		t.Fatalf("get dataplane Pod: %v", err)
	}
	pod.Status.PodIP = "10.92.0.1"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := h.direct.Status().Update(h.ctx, &pod); err != nil {
		t.Fatalf("update dataplane Pod status: %v", err)
	}
	h.prober.set(true, h.liveConfigVersionFn(f))

	// ACK the published snapshot once the version exists.
	h.waitFor(t, 20*time.Second, "xDS snapshot version", func() (bool, error) {
		return h.snapshots.version(f.gatewayKey.String()) != "", nil
	})
	h.snapshots.ack(f.gatewayKey.String())
}

// liveConfigVersionFn resolves the tunnel's current remote config version at
// probe time so the dataplane gate sees the version the Gateway just wrote.
func (h *managerHarness) liveConfigVersionFn(f *managerFixture) func() int64 {
	return func() int64 {
		var tunnel v1alpha1.CloudflareTunnel
		if err := h.direct.Get(context.Background(), f.tunnelKey, &tunnel); err != nil {
			return -1
		}
		return h.remote.configVersion(tunnel.Status.TunnelID)
	}
}

func (h *managerHarness) createAccount(t *testing.T, f *managerFixture) *v1alpha1.CloudflareAccount {
	t.Helper()
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: f.accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: f.secretName, Namespace: f.namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "qa92"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				UnprotectedHostnames: []string{"*"},
				AccessPolicyRefs:     v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs: v1alpha1.GrantPermissionAllowed,
				PrivateRoutes:        &v1alpha1.CloudflarePrivateRouteGrant{NetworkRouteSelector: &metav1.LabelSelector{}, HostnameRouteSelector: &metav1.LabelSelector{}},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	h.create(t, account)
	// Seed the verification status the account reconciler would publish; the
	// account controller is not part of this harness.
	h.waitFor(t, 10*time.Second, "seed CloudflareAccount status", func() (bool, error) {
		var current v1alpha1.CloudflareAccount
		if err := h.direct.Get(h.ctx, types.NamespacedName{Name: f.accountName}, &current); err != nil {
			return false, err
		}
		now := metav1.Now()
		current.Status.Verified = v1alpha1.CloudflareAccountVerifiedStatus{
			AccountName: "qa92-account",
			Zones:       []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.com"}},
		}
		current.Status.Conditions = []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: current.Generation, LastTransitionTime: now},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: current.Generation, LastTransitionTime: now},
		}
		if err := h.direct.Status().Update(h.ctx, &current); err != nil {
			return false, nil
		}
		return true, nil
	})
	return account
}

func (h *managerHarness) create(t *testing.T, object client.Object) {
	t.Helper()
	if err := h.direct.Create(h.ctx, object); err != nil {
		t.Fatalf("create %T %s/%s: %v", object, object.GetNamespace(), object.GetName(), err)
	}
}

func (h *managerHarness) getGateway(t *testing.T, key types.NamespacedName) *gatewayv1.Gateway {
	t.Helper()
	var gateway gatewayv1.Gateway
	if err := h.direct.Get(h.ctx, key, &gateway); err != nil {
		t.Fatalf("get Gateway %s: %v", key, err)
	}
	return &gateway
}

func (h *managerHarness) getTunnel(t *testing.T, key types.NamespacedName) *v1alpha1.CloudflareTunnel {
	t.Helper()
	var tunnel v1alpha1.CloudflareTunnel
	if err := h.direct.Get(h.ctx, key, &tunnel); err != nil {
		t.Fatalf("get CloudflareTunnel %s: %v", key, err)
	}
	return &tunnel
}

// updateTunnelStatus performs a status write through the API server, retrying
// on conflict so it composes with concurrent controller writes.
func (h *managerHarness) updateTunnelStatus(t *testing.T, key types.NamespacedName, mutate func(*v1alpha1.CloudflareTunnel)) time.Time {
	t.Helper()
	var committed time.Time
	h.waitFor(t, 15*time.Second, "tunnel status update", func() (bool, error) {
		var tunnel v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, key, &tunnel); err != nil {
			return false, err
		}
		mutate(&tunnel)
		if err := h.direct.Status().Update(h.ctx, &tunnel); err != nil {
			if apierrors.IsConflict(err) {
				return false, nil
			}
			return false, err
		}
		committed = time.Now()
		return true, nil
	})
	return committed
}

// managerDNSStimulusManager owns the status.dnsRecords entry QA-92-38 applies
// as its stimulus. A dedicated server-side-apply manager can release the
// entry; an Update-written one stays co-owned after the tunnel controller
// writes the same key and values, and survives the controller's removal at
// teardown.
const managerDNSStimulusManager = "qa92-38-stimulus"

// applyTunnelDNSRecords server-side-applies status.dnsRecords under
// managerDNSStimulusManager and returns the write as a stimulus. Empty records
// release every field the manager owns.
func (h *managerHarness) applyTunnelDNSRecords(t *testing.T, key types.NamespacedName, records []v1alpha1.CloudflareTunnelDNSRecordStatus) managerStimulus {
	t.Helper()
	tunnel := &unstructured.Unstructured{}
	tunnel.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("CloudflareTunnel"))
	tunnel.SetNamespace(key.Namespace)
	tunnel.SetName(key.Name)
	if len(records) > 0 {
		entries := make([]any, 0, len(records))
		for index := range records {
			entry, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&records[index])
			if err != nil {
				t.Fatalf("convert dnsRecords entry: %v", err)
			}
			entries = append(entries, entry)
		}
		if err := unstructured.SetNestedSlice(tunnel.Object, entries, "status", "dnsRecords"); err != nil {
			t.Fatalf("set dnsRecords: %v", err)
		}
	}
	// Hold Gateway invocations at their synchronous start until the apply
	// returns, so the consuming reconcile provably begins after the commit.
	release := h.trace.armGate(t, "gateway")
	defer release()
	start := time.Now()
	if err := h.direct.Status().Apply(h.ctx, client.ApplyConfigurationFromUnstructured(tunnel), client.FieldOwner(managerDNSStimulusManager), client.ForceOwnership); err != nil {
		t.Fatalf("apply tunnel dnsRecords: %v", err)
	}
	return h.stimulusOf(t, "dnsRecords entry", tunnel, start, time.Now())
}

// deleteFixture removes the fixture objects and waits for the tunnel and
// Gateway to disappear so the next test's manager starts from a clean cache.
func (h *managerHarness) deleteFixture(t *testing.T, f *managerFixture) {
	t.Helper()
	for _, object := range []client.Object{
		&gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: f.gatewayName, Namespace: f.namespace}},
		&v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: f.tunnelKey.Name, Namespace: f.namespace}},
	} {
		if err := h.direct.Delete(h.ctx, object); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("delete %T %s: %v", object, object.GetName(), err)
		}
	}
	h.waitFor(t, 30*time.Second, "fixture teardown", func() (bool, error) {
		var tunnel v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, f.tunnelKey, &tunnel); !apierrors.IsNotFound(err) {
			return false, nil
		}
		var gateway gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, f.gatewayKey, &gateway); !apierrors.IsNotFound(err) {
			return false, nil
		}
		return true, nil
	})
	for _, object := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.namespace}},
		&v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: f.accountName}},
		&v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: f.configName}},
		&gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: f.className}},
	} {
		if err := h.direct.Delete(h.ctx, object); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("delete %T %s: %v", object, object.GetName(), err)
		}
	}
}

// ---------------------------------------------------------------------------
// Wait/assert helpers
// ---------------------------------------------------------------------------

// waitFor polls fn until it reports done or the deadline passes. On timeout it
// dumps the persisted state that explains the stall before failing.
func (h *managerHarness) waitFor(t *testing.T, timeout time.Duration, what string, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ok, err := fn()
		if err != nil {
			lastErr = err
		} else if ok {
			return
		}
		if time.Now().After(deadline) {
			h.dumpDiagnostics(t)
			if lastErr != nil {
				t.Fatalf("timed out waiting for %s: %v", what, lastErr)
			}
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// dumpDiagnostics logs the persisted state that explains a stuck wait: every
// CloudflareTunnel and Gateway condition, recent remote calls, and the
// dataplane objects the reconcile should have produced.
func (h *managerHarness) dumpDiagnostics(t *testing.T) {
	t.Helper()
	var tunnels v1alpha1.CloudflareTunnelList
	if err := h.direct.List(context.Background(), &tunnels); err == nil {
		for i := range tunnels.Items {
			tunnel := &tunnels.Items[i]
			t.Logf("diag tunnel %s/%s rv=%s tunnelId=%q verified=%v tokenRef=%v gatewayRef=%v gatewayUid=%q deletedAt=%v config=%+v conditions=%s",
				tunnel.Namespace, tunnel.Name, tunnel.ResourceVersion,
				tunnel.Status.TunnelID, tunnel.Status.OwnershipVerified,
				tunnel.Status.ConnectorTokenSecretRef != nil,
				tunnel.Status.GatewayRef, tunnel.Status.GatewayUID,
				tunnel.Status.DeletedAt != nil, tunnel.Status.ConfigVersion,
				managerConditionSummary(tunnel))
		}
	}
	var gateways gatewayv1.GatewayList
	if err := h.direct.List(context.Background(), &gateways); err == nil {
		for i := range gateways.Items {
			gateway := &gateways.Items[i]
			parts := make([]string, 0, len(gateway.Status.Conditions))
			for _, condition := range gateway.Status.Conditions {
				parts = append(parts, fmt.Sprintf("%s=%s/%s", condition.Type, condition.Status, condition.Reason))
			}
			t.Logf("diag gateway %s/%s rv=%s conditions=%s", gateway.Namespace, gateway.Name, gateway.ResourceVersion, strings.Join(parts, ","))
		}
	}
	var deployments appsv1.DeploymentList
	if err := h.direct.List(context.Background(), &deployments); err == nil {
		for i := range deployments.Items {
			t.Logf("diag deployment %s/%s", deployments.Items[i].Namespace, deployments.Items[i].Name)
		}
	}
	var secrets corev1.SecretList
	if err := h.direct.List(context.Background(), &secrets); err == nil {
		for i := range secrets.Items {
			t.Logf("diag secret %s/%s", secrets.Items[i].Namespace, secrets.Items[i].Name)
		}
	}
	for _, call := range h.remote.callsSince(time.Now().Add(-time.Minute), "") {
		t.Logf("diag remote call %s(%s) at %s", call.Op, call.Arg, call.At.Format("15:04:05.000"))
	}
}

// managerConsistently fails when fn reports an error or false at any sample
// inside the window.
func managerConsistently(t *testing.T, window time.Duration, what string, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		ok, err := fn()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !ok {
			t.Fatalf("%s: violated inside %s window", what, window)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitConverged waits until the fixture reaches the fully converged state the
// QA premises require: verified writer tuple, applied==desired==remote config
// version, ready managed DNS, ConfigApplied=True, and Programmed=True.
func (h *managerHarness) waitConverged(t *testing.T, f *managerFixture) {
	t.Helper()
	h.waitFor(t, 60*time.Second, "full convergence", func() (bool, error) {
		var tunnel v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, f.tunnelKey, &tunnel); err != nil {
			return false, err
		}
		var gateway gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, f.gatewayKey, &gateway); err != nil {
			return false, err
		}
		if !managerTunnelTupleComplete(&tunnel, &gateway) {
			return false, nil
		}
		config := tunnel.Status.ConfigVersion
		if config.Desired == 0 || config.Desired != config.Applied || config.Desired != config.Remote {
			return false, nil
		}
		if h.remote.configVersion(tunnel.Status.TunnelID) != config.Desired {
			return false, nil
		}
		index := managerConditionIndex(tunnel.Status.Conditions)
		if index[v1alpha1.CloudflareTunnelConditionConfigApplied].Status != metav1.ConditionTrue {
			return false, nil
		}
		if index[v1alpha1.CloudflareTunnelConditionTunnelReady].Status != metav1.ConditionTrue {
			return false, nil
		}
		if tunnel.Spec.DNS.Mode != v1alpha1.DNSModeExternal {
			if len(tunnel.Status.DNSRecords) == 0 {
				return false, nil
			}
			for _, record := range tunnel.Status.DNSRecords {
				if record.State != dnsRecordStateReady {
					return false, nil
				}
			}
		}
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionTrue, nil
	})
	f.gateway = h.getGateway(t, f.gatewayKey)
	f.tunnel = h.getTunnel(t, f.tunnelKey)
}

// assertEventDriven proves the QA §6 causal chain for one stimulus: a
// reconcile of the controller invoked after the stimulus commit that read
// the committed revision through its operative client was invoked before
// the periodic expiry pending at the stimulus (managerWakeupVerdict). The
// verdict uses synchronous lifecycle records only; the 30s poll is a
// harness bound, not an SLA. A verdict carrying Detail without Decided is
// terminal-undecided: polling longer cannot resolve it.
func (h *managerHarness) assertEventDriven(t *testing.T, controllerName string, interval time.Duration, stim managerStimulus) {
	t.Helper()
	timeout := time.Now().Add(30 * time.Second)
	var verdict managerWakeup
	for {
		verdict = managerWakeupVerdict(h.trace.snapshot(controllerName), stim, interval)
		if verdict.Decided || verdict.Detail != "" || time.Now().After(timeout) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !verdict.Pass {
		h.dumpTrace(t, controllerName, stim)
		detail := verdict.Detail
		if !verdict.Decided && detail == "" {
			detail = "no reconcile read the revision within the harness timeout"
		}
		t.Fatalf("%s: %s wakeup not proven: %s", stim, controllerName, detail)
	}
	t.Logf("%s: %s reconcile %s invoked %s, pending expiry %s", stim, controllerName, verdict.Consumer.ID,
		verdict.Consumer.beginAt().Format("15:04:05.000"), verdict.Deadline.Format("15:04:05.000"))
}

// stimulusOf describes a write the test made; obj holds the server response.
func (h *managerHarness) stimulusOf(t *testing.T, what string, obj client.Object, start, end time.Time) managerStimulus {
	t.Helper()
	written, ok := managerTracedObjectOf(obj)
	if !ok {
		t.Fatalf("%s: written %T carries no resourceVersion", what, obj)
	}
	return managerStimulus{What: what, Kind: written.Kind, Key: written.Key, RV: written.RV, CommitLB: start, CommitUB: end}
}

// tunnelEventStimulus correlates a recorded tunnel event with the traced
// reconciler write whose response carried its revision.
func (h *managerHarness) tunnelEventStimulus(t *testing.T, event managerWatchEvent, what string) managerStimulus {
	t.Helper()
	recorded, ok := managerTracedObjectOf(event.Obj)
	if !ok {
		t.Fatalf("%s: recorded event carries no resourceVersion", what)
	}
	var write managerTracedWrite
	h.waitFor(t, 15*time.Second, "traced reconciler write of "+what, func() (bool, error) {
		write, ok = h.trace.writeProducing(recorded.Kind, recorded.Key, recorded.RV)
		return ok, nil
	})
	return managerStimulus{What: what, Kind: recorded.Kind, Key: recorded.Key, RV: recorded.RV, CommitLB: write.Start, CommitUB: write.End}
}

// dumpTrace logs the controller's reconciles around a stimulus as failure
// evidence.
func (h *managerHarness) dumpTrace(t *testing.T, controllerName string, stim managerStimulus) {
	t.Helper()
	for index, entry := range h.trace.snapshot(controllerName) {
		if entry.Last.Before(stim.CommitLB.Add(-5 * time.Second)) {
			continue
		}
		read := int64(-1)
		for _, object := range entry.Reads {
			if object.Kind == stim.Kind && object.Key == stim.Key && object.RV > read {
				read = object.RV
			}
		}
		t.Logf("trace %s #%d %s invoked=%s end=%s result=%q stimulus-object-rv=%d", controllerName, index, entry.ID,
			entry.beginAt().Format("15:04:05.000"), entry.endAt().Format("15:04:05.000"), entry.Result, read)
	}
}

// waitQuiescent waits until a full window passes with no gateway reconcile
// and no tunnel MODIFIED event. Unlike assertQuiescent it tolerates the
// convergence tail: waitConverged's last poll can precede an in-flight
// reconcile completing or a watch event arriving, so the quiescence contract
// is only meaningful once a clean window has been observed. A system that
// never settles still fails here on timeout.
func (h *managerHarness) waitQuiescent(t *testing.T, f *managerFixture, window time.Duration) {
	t.Helper()
	h.waitFor(t, 30*time.Second, "quiescent window", func() (bool, error) {
		start := time.Now()
		base := h.trace.countSince("gateway", start)
		deadline := start.Add(window)
		for time.Now().Before(deadline) {
			if h.trace.countSince("gateway", start) != base {
				return false, nil
			}
			if len(h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, start)) != 0 {
				return false, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return true, nil
	})
}

// freshWindow opens a stimulus window behind a no-event control period (QA §6
// item 4): it waits for a gateway reconcile that started no earlier than its
// predecessor's last client call plus programmedRequeue — no event dispatched
// a reconcile for a full period — and returns once that reconcile completed,
// so the timer it armed leaves the stimulus a full period of headroom.
func (h *managerHarness) freshWindow(t *testing.T) {
	t.Helper()
	since := time.Now()
	var boundary types.UID
	h.waitFor(t, 15*time.Second, "gateway reconcile after a quiet period", func() (bool, error) {
		entries := h.trace.snapshot("gateway")
		for index := 1; index < len(entries); index++ {
			if entries[index].beginAt().After(since) && !entries[index].beginAt().Before(entries[index-1].endAt().Add(programmedRequeue)) {
				boundary = entries[index].ID
				return true, nil
			}
		}
		return false, nil
	})
	h.waitFor(t, 15*time.Second, "quiet-period reconcile completion", func() (bool, error) {
		for _, entry := range h.trace.snapshot("gateway") {
			if entry.ID == boundary {
				return entry.ResultSeen, nil
			}
		}
		return false, nil
	})
}

// assertTunnelIntegrity checks every recorded tunnel revision for the QA-92-23
// invariant: no torn Ready/ConfigApplied pair and no duplicate condition type.
func (h *managerHarness) assertTunnelIntegrity(t *testing.T, f *managerFixture) {
	t.Helper()
	for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
		tunnel, err := managerTunnelOf(event)
		if err != nil {
			t.Fatalf("decode tunnel event: %v", err)
		}
		if managerTunnelTorn(tunnel) {
			t.Fatalf("torn pair persisted at rv=%s: %s", event.RV, managerConditionSummary(tunnel))
		}
		seen := map[string]bool{}
		for _, condition := range tunnel.Status.Conditions {
			if seen[condition.Type] {
				t.Fatalf("duplicate condition %s at rv=%s", condition.Type, event.RV)
			}
			seen[condition.Type] = true
		}
	}
}

// assertSingleConditionOwner verifies managedFields assigns each Flareway
// condition type to exactly one field manager.
func (h *managerHarness) assertSingleConditionOwner(t *testing.T, f *managerFixture) {
	t.Helper()
	tunnel := h.getTunnel(t, f.tunnelKey)
	owners := map[string]map[string]bool{}
	for _, entry := range tunnel.ManagedFields {
		if entry.FieldsV1 == nil {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			continue
		}
		status, _ := fields["f:status"].(map[string]any)
		conditions, _ := status["f:conditions"].(map[string]any)
		for key := range conditions {
			conditionType := strings.TrimSuffix(strings.TrimPrefix(key, `k:{"type":"`), `"}`)
			if owners[conditionType] == nil {
				owners[conditionType] = map[string]bool{}
			}
			owners[conditionType][entry.Manager] = true
		}
	}
	for _, conditionType := range managerFlarewayConditionTypes {
		managers := owners[conditionType]
		if len(managers) > 1 {
			t.Fatalf("condition %s has %d owners: %v", conditionType, len(managers), managers)
		}
	}
}

// dumpTunnelSequence logs the recorded tunnel status sequence for evidence.
func (h *managerHarness) dumpTunnelSequence(t *testing.T, f *managerFixture, since time.Time) {
	t.Helper()
	for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
		if event.At.Before(since) {
			continue
		}
		tunnel, err := managerTunnelOf(event)
		if err != nil {
			continue
		}
		t.Logf("tunnel %s rv=%s %s", event.Type, event.RV, managerConditionSummary(tunnel))
	}
}

func managerPtr[T any](v T) *T { return &v }

// ---------------------------------------------------------------------------
// QA-92-02: converged no-change passes produce zero tunnel status churn
// ---------------------------------------------------------------------------

func TestQA92_02_ConvergedTunnelStatusQuiescent(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// Let any in-flight self-triggered work settle, then measure a no-change
	// window: the post-fix contract is zero MODIFIED events, a stable
	// resourceVersion, and zero self-induced reconciles.
	time.Sleep(1500 * time.Millisecond)
	start := time.Now()
	tunnel := h.getTunnel(t, f.tunnelKey)
	baseRV := tunnel.ResourceVersion

	window := 4 * time.Second
	time.Sleep(window)

	modified := h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, start)
	current := h.getTunnel(t, f.tunnelKey)
	reconciles := h.trace.countSince("gateway", start)
	t.Logf("QA-92-02 window=%s modified=%d rv %s->%s gateway-reconciles=%d",
		window, len(modified), baseRV, current.ResourceVersion, reconciles)
	h.dumpTunnelSequence(t, f, start)
	if len(modified) != 0 {
		t.Fatalf("converged tunnel emitted %d MODIFIED events in %s", len(modified), window)
	}
	if current.ResourceVersion != baseRV {
		t.Fatalf("converged tunnel resourceVersion moved %s -> %s", baseRV, current.ResourceVersion)
	}
	if reconciles != 0 {
		t.Fatalf("converged gateway self-triggered %d reconciles in %s", reconciles, window)
	}
	h.assertTunnelIntegrity(t, f)
}

// ---------------------------------------------------------------------------
// QA-92-04: unrelated Gateway/route status baseline is not rewritten
// ---------------------------------------------------------------------------

func TestQA92_04_UnrelatedStatusBaselineStable(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true, withRoutes: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// An unrelated conformance-mode Gateway in the same control plane: it
	// reconciles on its own cadence but must never rewrite status.
	id := managerFixtureN.Add(1)
	otherNS := fmt.Sprintf("qa92-other-%d", id)
	otherClass := fmt.Sprintf("qa92-other-class-%d", id)
	otherConfig := fmt.Sprintf("qa92-other-cfg-%d", id)
	otherGW := fmt.Sprintf("qa92-other-gw-%d", id)
	h.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: otherNS}})
	h.create(t, &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: otherConfig},
		Spec:       v1alpha1.GatewayClassConfigSpec{ConformanceMode: true},
	})
	group := gatewayv1.Group(v1alpha1.Group)
	kind := gatewayv1.Kind("GatewayClassConfig")
	h.create(t, &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: otherClass},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: otherConfig},
		},
	})
	h.create(t, &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: otherGW, Namespace: otherNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(otherClass),
			Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	})
	h.create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: otherNS},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}},
	})
	h.create(t, &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: otherNS},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(otherGW)}},
			},
		},
	})
	wellKnown := gatewayv1.WellKnownCACertificatesSystem
	h.create(t, &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: otherNS},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: "", Kind: "Service", Name: "backend",
				},
			}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				WellKnownCACertificates: &wellKnown,
				Hostname:                gatewayv1.PreciseHostname("backend.internal"),
			},
		},
	})
	defer func() {
		_ = h.direct.Delete(h.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: otherNS}})
		_ = h.direct.Delete(h.ctx, &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: otherClass}})
		_ = h.direct.Delete(h.ctx, &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: otherConfig}})
	}()

	// Let the unrelated objects reach their first stable status write.
	time.Sleep(3 * time.Second)
	start := time.Now()
	otherGWKey := types.NamespacedName{Namespace: otherNS, Name: otherGW}
	otherRouteKey := types.NamespacedName{Namespace: otherNS, Name: "route"}
	otherPolicyKey := types.NamespacedName{Namespace: otherNS, Name: "policy"}
	fixturePolicyKey := types.NamespacedName{Namespace: f.namespace, Name: f.policyName}
	gwRV := h.getGateway(t, f.gatewayKey).ResourceVersion
	routeRV := ""
	{
		var route gatewayv1.HTTPRoute
		if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.routeName}, &route); err == nil {
			routeRV = route.ResourceVersion
		}
	}
	otherGWRV := h.getGateway(t, otherGWKey).ResourceVersion

	window := 4 * time.Second
	time.Sleep(window)

	checks := []struct {
		name string
		gvr  schema.GroupVersionResource
		key  types.NamespacedName
		rv   string
		get  func() string
	}{
		{"cloudflare Gateway", managerGatewayGVR, f.gatewayKey, gwRV, func() string { return h.getGateway(t, f.gatewayKey).ResourceVersion }},
		{"cloudflare HTTPRoute", managerHTTPRouteGVR, types.NamespacedName{Namespace: f.namespace, Name: f.routeName}, routeRV, func() string {
			var route gatewayv1.HTTPRoute
			if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.routeName}, &route); err != nil {
				return "get-error"
			}
			return route.ResourceVersion
		}},
		{"conformance Gateway", managerGatewayGVR, otherGWKey, otherGWRV, func() string { return h.getGateway(t, otherGWKey).ResourceVersion }},
		{"conformance HTTPRoute", managerHTTPRouteGVR, otherRouteKey, "", func() string {
			var route gatewayv1.HTTPRoute
			if err := h.direct.Get(h.ctx, otherRouteKey, &route); err != nil {
				return "get-error"
			}
			return route.ResourceVersion
		}},
		{"cloudflare BackendTLSPolicy", managerBackendTLSPolicyGVR, fixturePolicyKey, "", func() string {
			var policy gatewayv1.BackendTLSPolicy
			if err := h.direct.Get(h.ctx, fixturePolicyKey, &policy); err != nil {
				return "get-error"
			}
			return policy.ResourceVersion
		}},
		{"conformance BackendTLSPolicy", managerBackendTLSPolicyGVR, otherPolicyKey, "", func() string {
			var policy gatewayv1.BackendTLSPolicy
			if err := h.direct.Get(h.ctx, otherPolicyKey, &policy); err != nil {
				return "get-error"
			}
			return policy.ResourceVersion
		}},
	}
	for _, check := range checks {
		modified := h.recorder.modifiedAfter(check.gvr, check.key, start)
		nowRV := check.get()
		t.Logf("QA-92-04 %s: modified=%d rv %s->%s", check.name, len(modified), check.rv, nowRV)
		if len(modified) != 0 {
			t.Fatalf("%s emitted %d MODIFIED events in %s", check.name, len(modified), window)
		}
		if check.rv != "" && nowRV != check.rv {
			t.Fatalf("%s resourceVersion moved %s -> %s", check.name, check.rv, nowRV)
		}
	}
}

// ---------------------------------------------------------------------------
// QA-92-25: alternating writer passes never tear, duplicate, or ping-pong
// ---------------------------------------------------------------------------

func TestQA92_25_AlternatingWritersConsistent(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	start := time.Now()
	// Alternate external stimuli that drive Gateway-path and tunnel-path
	// reconciles: Pod events map to the Gateway, account events map to both
	// controllers. No test-side tunnel status writes — those would mask the
	// controller-owned write path this item audits.
	for round := 0; round < 3; round++ {
		var pod corev1.Pod
		if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
			t.Fatalf("get pod: %v", err)
		}
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations["qa92.touch"] = fmt.Sprintf("round-%d", round)
		if err := h.direct.Update(h.ctx, &pod); err != nil {
			t.Fatalf("touch pod: %v", err)
		}
		var account v1alpha1.CloudflareAccount
		if err := h.direct.Get(h.ctx, types.NamespacedName{Name: f.accountName}, &account); err != nil {
			t.Fatalf("get account: %v", err)
		}
		if account.Annotations == nil {
			account.Annotations = map[string]string{}
		}
		account.Annotations["qa92.touch"] = fmt.Sprintf("round-%d", round)
		if err := h.direct.Update(h.ctx, &account); err != nil {
			t.Fatalf("touch account: %v", err)
		}
		time.Sleep(1200 * time.Millisecond)
	}

	// RV invariant: every MODIFIED event in the stress window must carry a
	// status that differs from the previous recorded revision — a resource
	// version bump with identical status is exactly the no-op churn this item
	// audits.
	var prevStatus *v1alpha1.CloudflareTunnelStatus
	for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
		tunnel, err := managerTunnelOf(event)
		if err != nil {
			continue
		}
		if !event.At.Before(start) && event.Type == watch.Modified &&
			prevStatus != nil && reflect.DeepEqual(*prevStatus, tunnel.Status) {
			h.dumpTunnelSequence(t, f, start)
			t.Fatalf("tunnel MODIFIED at %s (rv=%s) rewrote identical status", event.At, event.RV)
		}
		status := tunnel.Status
		prevStatus = &status
	}

	// Every sampled persisted revision must be consistent.
	h.assertTunnelIntegrity(t, f)
	h.assertSingleConditionOwner(t, f)

	// After the stress, the object must return to write quiescence.
	time.Sleep(1500 * time.Millisecond)
	quietStart := time.Now()
	time.Sleep(1500 * time.Millisecond)
	modified := h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, quietStart)
	t.Logf("QA-92-25 post-stress modified=%d", len(modified))
	h.dumpTunnelSequence(t, f, start)
	if len(modified) != 0 {
		t.Fatalf("tunnel kept churning after stress: %d MODIFIED in 1.5s", len(modified))
	}
}

// ---------------------------------------------------------------------------
// QA-92-28: Gateway spec change during tunnel commits stays consistent
// ---------------------------------------------------------------------------

func TestQA92_28_GatewayChangeDuringCommit(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// Change the Gateway spec (generation bump) and immediately rewrite tunnel
	// status several times to collide with the in-flight commit window.
	gateway := h.getGateway(t, f.gatewayKey)
	second := gatewayv1.Hostname(fmt.Sprintf("edge-b-%d.example.com", managerFixtureN.Add(1)))
	gateway.Spec.Listeners = append(gateway.Spec.Listeners, gatewayv1.Listener{
		Name: "http-2", Hostname: &second, Port: 8080, Protocol: gatewayv1.HTTPProtocolType,
	})
	if err := h.direct.Update(h.ctx, gateway); err != nil {
		t.Fatalf("update Gateway spec: %v", err)
	}
	for i := 0; i < 4; i++ {
		h.updateTunnelStatus(t, f.tunnelKey, func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Status.ObservedGeneration = tunnel.Generation
		})
	}

	// The bounded-TOCTOU contract: no torn pair in any persisted revision and
	// the Gateway watch produces the correction pass that reconverges.
	h.assertTunnelIntegrity(t, f)
	h.waitConverged(t, f)
	h.assertSingleConditionOwner(t, f)
	h.dumpTunnelSequence(t, f, time.Now().Add(-30*time.Second))
}

// ---------------------------------------------------------------------------
// QA-92-35: status.tunnelId assignment wakes the Gateway
// ---------------------------------------------------------------------------

func TestQA92_35_TunnelIDStatusWakeup(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)

	// The tunnel controller provisions the remote tunnel and records
	// status.tunnelId; that status-only event must wake the Gateway, which
	// then consumes the assigned ID (remote reads/writes against it).
	var idEvent managerWatchEvent
	var idEventAt time.Time
	h.waitFor(t, 30*time.Second, "status.tunnelId write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || tunnel.Status.TunnelID == "" {
				continue
			}
			idEvent, idEventAt = event, event.At
			return true, nil
		}
		return false, nil
	})
	if idEventAt.IsZero() {
		t.Fatal("no tunnelId status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, h.tunnelEventStimulus(t, idEvent, "tunnelId assignment"))

	// Before the tunnelId event the Gateway could not have written remote
	// configuration for this tunnel; after the full tuple lands it must.
	tunnelID := h.getTunnel(t, f.tunnelKey).Status.TunnelID
	if calls := h.remote.callsSince(time.Time{}, "UpdateTunnelConfiguration"); len(calls) != 0 {
		for _, call := range calls {
			if call.At.Before(idEventAt) {
				t.Fatalf("remote config write at %s preceded tunnelId event at %s", call.At, idEventAt)
			}
		}
	}
	h.waitConverged(t, f)
	writes := h.remote.callsSince(idEventAt, "UpdateTunnelConfiguration")
	if len(writes) == 0 {
		t.Fatalf("gateway never consumed tunnelId %s: no UpdateTunnelConfiguration call", tunnelID)
	}
	if writes[0].Arg != tunnelID {
		t.Fatalf("gateway wrote configuration for %s, expected assigned tunnelId %s", writes[0].Arg, tunnelID)
	}
	t.Logf("QA-92-35: tunnelId=%s first remote write at %s (event %s)", tunnelID, writes[0].At, idEventAt)
}

// ---------------------------------------------------------------------------
// QA-92-36: connectorTokenSecretRef capture wakes the Gateway
// ---------------------------------------------------------------------------

func TestQA92_36_ConnectorTokenWakeup(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)

	// The tunnel controller captures the connector token (G6) and records
	// status.connectorTokenSecretRef; that status-only event must wake the
	// Gateway into dataplane verification.
	var refEvent managerWatchEvent
	var refEventAt time.Time
	h.waitFor(t, 30*time.Second, "connectorTokenSecretRef write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || tunnel.Status.ConnectorTokenSecretRef == nil {
				continue
			}
			refEvent, refEventAt = event, event.At
			return true, nil
		}
		return false, nil
	})
	if refEventAt.IsZero() {
		t.Fatal("no connectorTokenSecretRef status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, h.tunnelEventStimulus(t, refEvent, "connectorTokenSecretRef capture"))

	// The Gateway must not write remote configuration before credentials are
	// recorded, and must write once they are.
	for _, call := range h.remote.callsSince(time.Time{}, "UpdateTunnelConfiguration") {
		if call.At.Before(refEventAt) {
			t.Fatalf("remote config write at %s preceded credential capture at %s", call.At, refEventAt)
		}
	}
	h.waitConverged(t, f)
	if len(h.remote.callsSince(refEventAt, "UpdateTunnelConfiguration")) == 0 {
		t.Fatal("gateway never consumed connectorTokenSecretRef: no UpdateTunnelConfiguration call")
	}
}

// ---------------------------------------------------------------------------
// QA-92-37: ownershipVerified=true wakes the Gateway
// ---------------------------------------------------------------------------

func TestQA92_37_OwnershipVerifiedWakeup(t *testing.T) {
	h := newManagerHarness(t)
	// The adoptable remote tunnel must exist before the fixture: the tunnel
	// controller starts reconciling as soon as the CloudflareTunnel lands, and
	// buildFixture blocks on dataplane convergence.
	tunnelID := "adopted-1"
	h.remote.putTunnel(flarecloudflare.Tunnel{ID: tunnelID, Name: "qa92-adopted", AccountTag: "0123456789abcdef0123456789abcdef"})
	// An adopted tunnel still needs a remote configuration object; without it
	// GetTunnelConfiguration fails and ConfigApplied sticks at RemoteError.
	// use() first so configuration() stamps the real accountID — the factory
	// only calls use() lazily on the first client construction.
	h.remote.use("qa92-token", "0123456789abcdef0123456789abcdef")
	h.remote.setConfigVersion(tunnelID, 0)
	f := h.buildFixture(t, managerFixtureSpec{
		dnsMode:        v1alpha1.DNSModeManaged,
		withAccount:    true,
		explicitTunnel: true,
		mutateTunnel: func(tunnel *v1alpha1.CloudflareTunnel) {
			// AdoptById: the tunnel controller verifies remote ownership and
			// flips status.ownershipVerified itself — the status-only wakeup.
			tunnel.Spec.Tunnel.Name = "qa92-adopted"
			tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: tunnelID}
			tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{
				Mode:   v1alpha1.AdoptionModeAdoptByID,
				Expect: v1alpha1.AdoptionExpect{Name: "qa92-adopted"},
			}
		},
	})
	defer h.deleteFixture(t, f)

	var verifiedEvent managerWatchEvent
	var verifiedEventAt time.Time
	h.waitFor(t, 30*time.Second, "ownershipVerified write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || !tunnel.Status.OwnershipVerified {
				continue
			}
			verifiedEvent, verifiedEventAt = event, event.At
			return true, nil
		}
		return false, nil
	})
	if verifiedEventAt.IsZero() {
		t.Fatal("no ownershipVerified status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, h.tunnelEventStimulus(t, verifiedEvent, "ownershipVerified"))

	for _, call := range h.remote.callsSince(time.Time{}, "UpdateTunnelConfiguration") {
		if call.At.Before(verifiedEventAt) {
			t.Fatalf("remote config write at %s preceded ownership verification at %s", call.At, verifiedEventAt)
		}
	}
	h.waitConverged(t, f)
	if len(h.remote.callsSince(verifiedEventAt, "UpdateTunnelConfiguration")) == 0 {
		t.Fatal("gateway never consumed ownershipVerified: no UpdateTunnelConfiguration call")
	}
}

// ---------------------------------------------------------------------------
// QA-92-38: managed dnsRecords entries wake the DNS-gated Gateway
// ---------------------------------------------------------------------------

// managerInjectedDNSRecordID marks the status-only dnsRecords entry QA-92-38
// writes as its stimulus; no remote record carries it.
const managerInjectedDNSRecordID = "qa92-38-injected"

func TestQA92_38_DNSRecordsWakeup(t *testing.T) {
	h := newManagerHarness(t)
	// Force the tunnel controller's DNS creation to fail so the fixture
	// converges everything except the managed dnsRecords entries.
	h.remote.failOp("CreateCNAME", errors.New("dns write blocked for QA-92-38"))
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	defer h.remote.clearFail("CreateCNAME")

	// The Gateway must be DNS-gated: Programmed=False while dnsRecords lacks
	// the compiled public hostname — even if DNSReady were (incorrectly) True.
	h.waitFor(t, 30*time.Second, "DNS-gated Programmed=False", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})
	// Discriminator: seed DNSReady=True with empty dnsRecords. The gate
	// consumes status.dnsRecords (gateway_cloudflare.go publicDNSReady), not
	// the DNSReady condition, so Programmed must stay False.
	h.updateTunnelStatus(t, f.tunnelKey, func(tunnel *v1alpha1.CloudflareTunnel) {
		// listType=map: replace the existing entry, never append a duplicate.
		meta.SetStatusCondition(&tunnel.Status.Conditions, metav1.Condition{
			Type:               v1alpha1.CloudflareTunnelConditionDNSReady,
			Status:             metav1.ConditionTrue,
			Reason:             "Seeded",
			Message:            "seeded without dnsRecords entries",
			ObservedGeneration: tunnel.Generation,
		})
	})
	managerConsistently(t, 1500*time.Millisecond, "Programmed stays False with DNSReady=True and no dnsRecords", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})

	// Stimulus: after a quiet period, apply the compiled hostname's
	// dnsRecords entry while DNS creation still fails, so the test — not the
	// tunnel controller's retry timer — fixes where the event lands in the
	// Gateway's requeue period. The DNS-error path preserves the live entry
	// (it never clears dnsRecords), and clearing the failure afterwards lets
	// the tunnel controller replace it with the real record. Releasing the
	// stimulus manager's fields leaves the entry to the tunnel controller.
	h.freshWindow(t)
	records := h.applyTunnelDNSRecords(t, f.tunnelKey, []v1alpha1.CloudflareTunnelDNSRecordStatus{{
		Hostname: f.hostname, RecordID: managerInjectedDNSRecordID, ZoneID: "zone-1", State: dnsRecordStateReady,
	}})
	defer h.applyTunnelDNSRecords(t, f.tunnelKey, nil)
	h.remote.clearFail("CreateCNAME")
	h.assertEventDriven(t, "gateway", programmedRequeue, records)
	h.waitFor(t, 30*time.Second, "Programmed=True", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionTrue, nil
	})
	// The injected entry must give way to the record the tunnel controller
	// actually created; waitConverged alone would accept the injected one.
	h.waitFor(t, 30*time.Second, "real dnsRecords entry", func() (bool, error) {
		for _, record := range h.getTunnel(t, f.tunnelKey).Status.DNSRecords {
			if record.Hostname == f.hostname && record.RecordID != managerInjectedDNSRecordID && h.remote.hasDNSRecord(record.ZoneID, record.RecordID) {
				return true, nil
			}
		}
		return false, nil
	})
	h.waitConverged(t, f)
}

// ---------------------------------------------------------------------------
// QA-92-39: dataplane probe failure wakes the converged Gateway fail-closed
// ---------------------------------------------------------------------------

func TestQA92_39_PodProbeFailureWakeup(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// Quiescence control: a converged Gateway must not reconcile without an
	// event (post-fix contract; baseline churn fails here as defect evidence).
	h.waitQuiescent(t, f, 1200*time.Millisecond)

	// Flip the prober to not-ready and poke the Pod so the watch delivers the
	// status-only wakeup the gate consumes.
	h.prober.set(false, h.liveConfigVersionFn(f))
	var pod corev1.Pod
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["qa92.probe"] = "down"
	// Hold Gateway invocations at their synchronous start until the write
	// returns, so the consuming reconcile provably begins after the commit.
	release := h.trace.armGate(t, "gateway")
	defer release()
	failureStart := time.Now()
	if err := h.direct.Update(h.ctx, &pod); err != nil {
		t.Fatalf("touch pod: %v", err)
	}
	stimulus := h.stimulusOf(t, "pod probe failure", &pod, failureStart, time.Now())
	release()
	h.assertEventDriven(t, "gateway", programmedRequeue, stimulus)

	h.waitFor(t, 15*time.Second, "Programmed=False", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})
	// Fail-closed must hold without oscillation while the probe is down.
	managerConsistently(t, 1500*time.Millisecond, "Programmed stays False while probe down", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})

	// Recovery: the fail-closed Gateway requeues periodically, so the Pod
	// poke follows a quiet period that leaves it a full period of headroom;
	// probe healthy again, poke the Pod, Programmed returns.
	h.freshWindow(t)
	h.prober.set(true, h.liveConfigVersionFn(f))
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	pod.Annotations["qa92.probe"] = "up"
	// Same write-time gate as the failure poke: the consumer provably
	// begins after the commit.
	release = h.trace.armGate(t, "gateway")
	defer release()
	recoverStart := time.Now()
	if err := h.direct.Update(h.ctx, &pod); err != nil {
		t.Fatalf("touch pod: %v", err)
	}
	stimulus = h.stimulusOf(t, "pod probe recovery", &pod, recoverStart, time.Now())
	release()
	h.assertEventDriven(t, "gateway", programmedRequeue, stimulus)
	h.waitFor(t, 15*time.Second, "Programmed=True after recovery", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionTrue, nil
	})
}

// ---------------------------------------------------------------------------
// QA-92-40: the writer-guard adoption tuple gates remote writes
// ---------------------------------------------------------------------------

func TestQA92_40_AdoptionTupleWakeup(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)

	// The writer guard consumes the whole tuple: tunnelId, accountId,
	// ownershipVerified, connectorTokenSecretRef, gatewayRef/gatewayUid bound
	// to the live Gateway UID, and deletedAt=nil. No remote configuration
	// write may happen before the persisted tuple is complete.
	var tupleEvent managerWatchEvent
	var tupleEventAt time.Time
	h.waitFor(t, 30*time.Second, "complete writer-guard tuple", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil {
				continue
			}
			if managerTunnelTupleComplete(tunnel, gateway) {
				tupleEvent, tupleEventAt = event, event.At
				return true, nil
			}
		}
		return false, nil
	})
	if tupleEventAt.IsZero() {
		t.Fatal("no complete writer-guard tuple event recorded")
	}
	for _, call := range h.remote.callsSince(time.Time{}, "UpdateTunnelConfiguration") {
		if call.At.Before(tupleEventAt) {
			t.Fatalf("remote config write at %s preceded complete tuple at %s", call.At, tupleEventAt)
		}
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, h.tunnelEventStimulus(t, tupleEvent, "writer-guard tuple"))
	h.waitConverged(t, f)
	if len(h.remote.callsSince(tupleEventAt, "UpdateTunnelConfiguration")) == 0 {
		t.Fatal("gateway never consumed the adoption tuple: no UpdateTunnelConfiguration call")
	}
}

// ---------------------------------------------------------------------------
// QA-92-41: SweepEvents GenericEvent wakes drift evaluation (Hold)
// ---------------------------------------------------------------------------

func TestQA92_41_SweepEventWakeup(t *testing.T) {
	// DriftPolicyHold is set before the manager starts so the sweep-triggered
	// drift evaluation exposes the drift without racing a live reconcile.
	h := newManagerHarnessWith(t, func(gw *GatewayReconciler, _ *CloudflareTunnelReconciler) {
		gw.DriftPolicy = DriftPolicyHold
	})
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)
	h.waitQuiescent(t, f, 1200*time.Millisecond)

	// Drift the remote out of band, then deliver the sweep wakeup through the
	// channel the real SetupWithManager wired. The event carries no new
	// revision, so the reconcile it wakes consumes the current one.
	tunnel := h.getTunnel(t, f.tunnelKey)
	h.remote.setConfigVersion(tunnel.Status.TunnelID, tunnel.Status.ConfigVersion.Applied+7)
	// Hold Gateway invocations until the send completes so the consumer
	// provably begins after the stimulus.
	release := h.trace.armGate(t, "gateway")
	defer release()
	eventAt := time.Now()
	h.sweep <- event.GenericEvent{Object: tunnel}
	stimulus := h.stimulusOf(t, "sweep GenericEvent", tunnel, eventAt, time.Now())
	release()
	h.assertEventDriven(t, "gateway", programmedRequeue, stimulus)
	h.waitFor(t, 15*time.Second, "DriftDetected=True with DriftHold", func() (bool, error) {
		current := h.getTunnel(t, f.tunnelKey)
		index := managerConditionIndex(current.Status.Conditions)
		drift := index[v1alpha1.CloudflareTunnelConditionDriftDetected]
		applied := index[v1alpha1.CloudflareTunnelConditionConfigApplied]
		return drift.Status == metav1.ConditionTrue && applied.Status == metav1.ConditionFalse, nil
	})
	// Hold must persist: no remote write repairs the drift while the policy
	// holds, and the exposed state stays stable rather than oscillating.
	managerConsistently(t, 2*time.Second, "DriftHold persists without remote write", func() (bool, error) {
		current := h.getTunnel(t, f.tunnelKey)
		index := managerConditionIndex(current.Status.Conditions)
		if index[v1alpha1.CloudflareTunnelConditionDriftDetected].Status != metav1.ConditionTrue {
			return false, nil
		}
		return len(h.remote.callsSince(eventAt, "UpdateTunnelConfiguration")) == 0, nil
	})
	h.assertTunnelIntegrity(t, f)
}

// ---------------------------------------------------------------------------
// QA-92-42: CloudflareAccount multi-hop mapping wakes the Gateway
// ---------------------------------------------------------------------------

func TestQA92_42_AccountMappingWakeup(t *testing.T) {
	h := newManagerHarness(t)
	// No account: the Gateway stops polling (missingCloudflareAccountError)
	// and relies on the CloudflareAccount watch.
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: false})
	defer h.deleteFixture(t, f)

	h.waitFor(t, 20*time.Second, "gateway waiting on missing account", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})
	// No quiescence control here: while the tunnel tuple is incomplete the
	// The Gateway legitimately requeues on programmedRequeue while the tunnel
	// tuple is incomplete, so a bare "reconcile after event" cannot prove the
	// account watch fired. The causal chain is: CloudflareAccount event →
	// tunnel reconcile (the tunnel controller has no pending timer on the
	// missing-account path) → tuple-complete status event → gateway reconcile.
	// Hold tunnel invocations until the create returns so the consuming
	// reconcile provably begins after the commit.
	release := h.trace.armGate(t, "cloudflaretunnel")
	defer release()
	eventAt := time.Now()
	f.account = h.createAccount(t, f)
	stimulus := h.stimulusOf(t, "CloudflareAccount creation", f.account, eventAt, time.Now())
	release()
	h.assertEventDriven(t, "cloudflaretunnel", tunnelRequeue, stimulus)
	var tupleEvent managerWatchEvent
	var tupleEventAt time.Time
	h.waitFor(t, 30*time.Second, "complete writer-guard tuple", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			if event.At.Before(eventAt) {
				continue
			}
			tunnel, err := managerTunnelOf(event)
			if err != nil {
				continue
			}
			if managerTunnelTupleComplete(tunnel, gateway) {
				tupleEvent, tupleEventAt = event, event.At
				return true, nil
			}
		}
		return false, nil
	})
	if tupleEventAt.IsZero() {
		t.Fatal("no complete writer-guard tuple event recorded after account creation")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, h.tunnelEventStimulus(t, tupleEvent, "tuple-complete status event"))

	// The account-less fixture deferred dataplane wiring; now that the tunnel
	// is provisioned the Deployment exists and the gate inputs can be armed.
	h.ensureDataplane(t, f)

	// Account update: touching the CloudflareAccount re-enqueues the Gateway.
	// Credentials stay valid here so the Secret→CloudflareTunnel→Gateway path
	// cannot supply the wakeup instead of the account watch.
	h.waitConverged(t, f)
	h.waitQuiescent(t, f, 1200*time.Millisecond)
	var account v1alpha1.CloudflareAccount
	if err := h.direct.Get(h.ctx, types.NamespacedName{Name: f.accountName}, &account); err != nil {
		t.Fatalf("get account: %v", err)
	}
	if account.Annotations == nil {
		account.Annotations = map[string]string{}
	}
	account.Annotations["qa92.rotation"] = "1"
	// Hold Gateway invocations until the update returns so the consuming
	// reconcile provably begins after the commit.
	release = h.trace.armGate(t, "gateway")
	defer release()
	touchStart := time.Now()
	if err := h.direct.Update(h.ctx, &account); err != nil {
		t.Fatalf("touch account: %v", err)
	}
	stimulus = h.stimulusOf(t, "CloudflareAccount update", &account, touchStart, time.Now())
	release()
	h.assertEventDriven(t, "gateway", programmedRequeue, stimulus)

	// Credential rotation: a broken credential Secret surfaces as a
	// reconcile error, not silence.
	var secret corev1.Secret
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.secretName}, &secret); err != nil {
		t.Fatalf("get credential secret: %v", err)
	}
	secret.Data["token"] = []byte("")
	if err := h.direct.Update(h.ctx, &secret); err != nil {
		t.Fatalf("break credential secret: %v", err)
	}
	brokenRV, err := strconv.ParseInt(secret.ResourceVersion, 10, 64)
	if err != nil {
		t.Fatalf("broken secret resourceVersion %q: %v", secret.ResourceVersion, err)
	}
	rotateAt := time.Now()
	account.Annotations["qa92.rotation"] = "2"
	if err := h.direct.Update(h.ctx, &account); err != nil {
		t.Fatalf("touch account: %v", err)
	}
	// A reconcile must surface the failure: it observed the broken Secret
	// revision and returned an error (rate-limited result), not silence.
	secretKey := types.NamespacedName{Namespace: f.namespace, Name: f.secretName}
	h.waitFor(t, 15*time.Second, "credential failure surfaced", func() (bool, error) {
		for _, controllerName := range []string{"gateway", "cloudflaretunnel"} {
			for _, entry := range h.trace.snapshot(controllerName) {
				if !entry.ResultSeen || entry.Result != managerResultRateLimited || entry.beginAt().Before(rotateAt) {
					continue
				}
				for _, read := range entry.Reads {
					if !read.Direct && read.Kind == "Secret" && read.Key == secretKey && read.RV == brokenRV {
						return true, nil
					}
				}
			}
		}
		return false, nil
	})
	// Restore credentials; the Gateway recovers through the same watch path.
	secret.Data["token"] = []byte("qa92-token")
	if err := h.direct.Update(h.ctx, &secret); err != nil {
		t.Fatalf("restore credential secret: %v", err)
	}
	account.Annotations["qa92.rotation"] = "3"
	if err := h.direct.Update(h.ctx, &account); err != nil {
		t.Fatalf("touch account: %v", err)
	}
	h.waitConverged(t, f)
}

// ---------------------------------------------------------------------------
// QA-92-43: opt-in pre/post measurement harness (no timing SLA)
// ---------------------------------------------------------------------------

type managerQA92Measurement struct {
	Suite            string  `json:"suite"`
	WindowSeconds    float64 `json:"windowSeconds"`
	GatewayReconcile float64 `json:"gatewayReconcileTotal"`
	TunnelReconcile  float64 `json:"tunnelReconcileTotal"`
	GatewayWorkSum   float64 `json:"gatewayWorkDurationSecondsSum"`
	TunnelWorkSum    float64 `json:"tunnelWorkDurationSecondsSum"`
	TunnelModified   int     `json:"tunnelModifiedEvents"`
	TunnelRVDelta    int     `json:"tunnelResourceVersionDelta"`
	RemoteCalls      int     `json:"remoteCalls"`
	RemoteWrites     int     `json:"remoteConfigWrites"`
}

func TestQA92_43_ManagerChurnMeasurement(t *testing.T) {
	if os.Getenv(managerQA92MeasureEnv) == "" {
		t.Skipf("opt-in measurement; set %s=1 to run", managerQA92MeasureEnv)
	}
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// Settle, then measure the recorded live-audit window shape.
	time.Sleep(2 * time.Second)
	start := time.Now()
	baseTunnel := h.getTunnel(t, f.tunnelKey)
	baseGWReconciles := h.trace.countSince("gateway", time.Time{})
	baseTunReconciles := h.trace.countSince("cloudflaretunnel", time.Time{})
	baseGWWork := h.trace.workSince("gateway", time.Time{})
	baseTunWork := h.trace.workSince("cloudflaretunnel", time.Time{})
	baseCalls := len(h.remote.callsSince(time.Time{}, ""))

	time.Sleep(managerQA92Window)
	end := time.Now()

	modified := h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, start)
	endTunnel := h.getTunnel(t, f.tunnelKey)
	measurement := managerQA92Measurement{
		Suite:            "issue-92-manager",
		WindowSeconds:    end.Sub(start).Seconds(),
		GatewayReconcile: float64(h.trace.countSince("gateway", time.Time{}) - baseGWReconciles),
		TunnelReconcile:  float64(h.trace.countSince("cloudflaretunnel", time.Time{}) - baseTunReconciles),
		GatewayWorkSum:   (h.trace.workSince("gateway", time.Time{}) - baseGWWork).Seconds(),
		TunnelWorkSum:    (h.trace.workSince("cloudflaretunnel", time.Time{}) - baseTunWork).Seconds(),
		TunnelModified:   len(modified),
		RemoteCalls:      len(h.remote.callsSince(time.Time{}, "")) - baseCalls,
		RemoteWrites:     len(h.remote.callsSince(start, "UpdateTunnelConfiguration")),
	}
	measurement.TunnelRVDelta = rvDelta(baseTunnel.ResourceVersion, endTunnel.ResourceVersion)

	encoded, err := json.MarshalIndent(measurement, "", "  ")
	if err != nil {
		t.Fatalf("marshal measurement: %v", err)
	}
	fmt.Printf("QA-92-43 measurement: %s\n", encoded)
	if path := os.Getenv(managerQA92ReportEnv); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open measurement output: %v", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				t.Errorf("close measurement output: %v", err)
			}
		}()
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			t.Fatalf("write measurement output: %v", err)
		}
	}
	// Sanity, not an SLA: the harness itself must have observed the window.
	if measurement.WindowSeconds < 40 {
		t.Fatalf("measurement window too short: %v", measurement.WindowSeconds)
	}
	h.assertTunnelIntegrity(t, f)
}

func rvDelta(before, after string) int {
	var b, a int64
	if _, err := fmt.Sscan(before, &b); err != nil {
		return -1
	}
	if _, err := fmt.Sscan(after, &a); err != nil {
		return -1
	}
	return int(a - b)
}

// TestManagerWakeupVerdict pins the QA §6 wakeup oracle on synthetic traces.
// It judges when the consuming reconcile started against the one periodic
// expiry pending at the stimulus, never when a reconcile completed (#123).
func TestManagerWakeupVerdict(t *testing.T) {
	const interval = 2 * time.Second
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	key := types.NamespacedName{Namespace: "qa", Name: "tunnel"}
	stim := managerStimulus{What: "stimulus", Kind: "CloudflareTunnel", Key: key, RV: 10, CommitLB: at(1000), CommitUB: at(1010)}
	// reconcile builds an entry: invoked at invokedMs, last client call and
	// recorded end at lastMs, and it read the tunnel at revision rv at readMs.
	// result is the recorded lifecycle result ("" means not seen yet); a
	// requeue_after result records interval as its RequeueAfter.
	reconcile := func(invokedMs, lastMs, readMs int, rv int64, direct bool, result string) managerReconcileEntry {
		entry := managerReconcileEntry{
			Controller: "gateway", InvokedAt: at(invokedMs), Start: at(invokedMs + 1), Last: at(lastMs),
			EndedAt: at(lastMs), ResultSeen: result != "", Result: result,
			Reads: []managerTracedObject{{Kind: "CloudflareTunnel", Key: key, RV: rv, At: at(readMs), Direct: direct}},
		}
		if result == managerResultRequeueAfter {
			entry.RequeueAfter = interval
		}
		return entry
	}
	// requeueAfter overrides the RequeueAfter the entry recorded.
	requeueAfter := func(entry managerReconcileEntry, after time.Duration) managerReconcileEntry {
		entry.RequeueAfter = after
		return entry
	}
	// uninvoked drops the "Reconciling" record, leaving only client calls.
	uninvoked := func(entry managerReconcileEntry) managerReconcileEntry {
		entry.InvokedAt = time.Time{}
		return entry
	}
	tests := []struct {
		name     string
		entries  []managerReconcileEntry
		decided  bool
		pass     bool
		terminal bool // Detail set: polling cannot resolve the verdict
		consumer time.Time
	}{{
		// #123: the woken reconcile was invoked right after the commit,
		// before the pending expiry, and finished long after it.
		name:    "invocation before the pending expiry passes regardless of completion",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1015, 2600, 1100, 10, false, managerResultRequeueAfter)},
		decided: true, pass: true, consumer: at(1015),
	}, {
		name:    "a timer dispatch reading the revision fails",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(2200, 2400, 2210, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		// Invoked inside the stimulus write call: it read the revision
		// before the deadline, so no miss can be asserted, but its start
		// is not provably after the commit, so no pass either. The window
		// has not closed, so the verdict keeps waiting.
		name:    "a consumer invoked inside the write call is ambiguous",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1005, 1200, 1050, 10, false, managerResultRequeueAfter)},
	}, {
		// Invoked before the write began and read the old revision; the
		// next reconcile missed the pending expiry.
		name:    "a reconcile in flight at the write does not count",
		entries: []managerReconcileEntry{reconcile(900, 1100, 905, 9, false, managerResultRequeueAfter), reconcile(3150, 3300, 3160, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		name:    "a stale read does not count",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1015, 1100, 1020, 9, false, managerResultRequeueAfter), reconcile(2250, 2300, 2260, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		// After a periodic dispatch the deadline stays the one pending at
		// the stimulus; a newly armed timer does not extend it.
		name:    "a re-dispatch after the pending expiry fails",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(2200, 2400, 2210, 10, false, managerResultRequeueAfter), reconcile(2410, 2500, 2420, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		// The predecessor's recorded end precedes its timer arm, so an
		// elapsed lower bound never proves the timer already fired.
		name:    "a timer armed late after its recorded end still bounds the wakeup",
		entries: []managerReconcileEntry{reconcile(-1000, -990, -995, 9, false, managerResultRequeueAfter), reconcile(1100, 1200, 1110, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		name:    "no pending timer passes any admitted consumer",
		entries: []managerReconcileEntry{reconcile(-500, -400, -490, 9, false, managerResultSuccess), reconcile(2900, 3000, 2910, 10, false, managerResultSuccess)},
		decided: true, pass: true, consumer: at(2900),
	}, {
		// A rate-limited retry can dispatch at any time, so no wakeup is
		// attributable to the stimulus.
		name:     "an error backoff at the stimulus is unmeasurable",
		entries:  []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRateLimited), reconcile(1015, 1200, 1020, 10, false, managerResultRateLimited)},
		terminal: true,
	}, {
		// Single-worker order means a completed predecessor always has a
		// recorded result; none seen means the pending window is unknown.
		name:     "a predecessor without a recorded result is undecided",
		entries:  []managerReconcileEntry{reconcile(-500, -400, -490, 9, false, ""), reconcile(2900, 3000, 2910, 10, false, managerResultRequeueAfter)},
		terminal: true,
	}, {
		// An in-flight predecessor (the last entry has no result yet) can
		// still arm a timer, so the verdict waits for its result.
		name:    "an in-flight predecessor keeps waiting",
		entries: []managerReconcileEntry{reconcile(900, 1100, 905, 9, false, "")},
	}, {
		name:    "an entry still before the deadline without the read stays undecided",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1015, 1020, 1017, 9, false, managerResultRequeueAfter)},
	}, {
		// A diagnostic APIReader read of the fresh revision does not prove
		// the reconcile's operative view consumed the stimulus; the later
		// consumer still missed the pending expiry.
		name:    "a diagnostic direct read does not prove consumption",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1015, 1200, 1100, 9, false, managerResultRequeueAfter), reconcile(1015, 1200, 1150, 10, true, managerResultRequeueAfter), reconcile(2210, 2300, 2220, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		// The ambiguous consumer plus a dispatch past the deadline: the
		// revision was consumed before expiry, but no reconcile proves
		// the event caused it, so the verdict is terminal-undecided.
		name:     "ambiguity past the closed window is terminal",
		entries:  []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1005, 1200, 1050, 10, false, managerResultRequeueAfter), reconcile(2300, 2400, 2310, 9, false, managerResultRequeueAfter)},
		terminal: true,
	}, {
		// An ambiguous read before the deadline does not block a later
		// proven consumer: the admitted entry still wins the pass.
		name:    "an admitted consumer after ambiguity passes",
		entries: []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), reconcile(1005, 1200, 1050, 10, false, managerResultRequeueAfter), reconcile(1500, 1600, 1520, 10, false, managerResultRequeueAfter)},
		decided: true, pass: true, consumer: at(1500),
	}, {
		// The predecessor returned RequeueAfter 1s, not the caller's 2s
		// interval: its timer expires at 200+1000ms, so a consumer invoked
		// at 1300 missed the pending expiry even though end+interval would
		// have admitted it.
		name:    "a shorter recorded RequeueAfter bounds the wakeup",
		entries: []managerReconcileEntry{requeueAfter(reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), time.Second), reconcile(1300, 1400, 1310, 10, false, managerResultRequeueAfter)},
		decided: true,
	}, {
		// A requeue_after result whose duration was not recorded leaves the
		// pending expiry unknown; no fallback to the caller's interval.
		name:     "a requeue_after predecessor without a recorded duration is undecided",
		entries:  []managerReconcileEntry{requeueAfter(reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), 0), reconcile(1015, 1100, 1020, 10, false, managerResultRequeueAfter)},
		terminal: true,
	}, {
		// No "Reconciling" record (the line renamed or re-leveled, which
		// also disarms the write-time gate): the consumer's first client
		// call after the commit cannot prove it was invoked after it, so
		// the verdict fails closed instead of admitting it.
		name:     "a consumer without a recorded invocation fails closed",
		entries:  []managerReconcileEntry{reconcile(0, 200, 10, 9, false, managerResultRequeueAfter), uninvoked(reconcile(1015, 1200, 1050, 10, false, managerResultRequeueAfter))},
		terminal: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := managerWakeupVerdict(tt.entries, stim, interval)
			if verdict.Decided != tt.decided || verdict.Pass != tt.pass {
				t.Fatalf("verdict decided=%v pass=%v (%s), want decided=%v pass=%v", verdict.Decided, verdict.Pass, verdict.Detail, tt.decided, tt.pass)
			}
			if terminal := !verdict.Decided && verdict.Detail != ""; terminal != tt.terminal {
				t.Fatalf("verdict terminal=%v (%s), want %v", terminal, verdict.Detail, tt.terminal)
			}
			if tt.pass && !verdict.Consumer.beginAt().Equal(tt.consumer) {
				t.Fatalf("consumer invoked %s, want %s", verdict.Consumer.beginAt(), tt.consumer)
			}
		})
	}
}
