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
// sequence, and a workqueue/metrics sampler that timestamps queue adds and
// reconcile completions. The file intentionally depends only on production
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	dto "github.com/prometheus/client_model/go"
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
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
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
// Metrics sampler: timestamps queue adds and reconcile completions
// ---------------------------------------------------------------------------

type managerMetricSample struct {
	At         time.Time
	Adds       float64
	Reconciles float64
	WorkSum    float64
}

// managerMetricsSampler polls the controller-runtime registry so queue adds
// and reconcile completions carry wall-clock times. Sampling granularity is a
// few milliseconds, far below the 2s periodic requeue the liveness contract
// distinguishes against.
type managerMetricsSampler struct {
	mu      sync.Mutex
	samples map[string][]managerMetricSample
	done    chan struct{}
	wg      sync.WaitGroup
}

func newManagerMetricsSampler() *managerMetricsSampler {
	sampler := &managerMetricsSampler{
		samples: map[string][]managerMetricSample{},
		done:    make(chan struct{}),
	}
	sampler.wg.Add(1)
	go sampler.run()
	return sampler
}

func (s *managerMetricsSampler) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(3 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.collect()
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
	}
}

func (s *managerMetricsSampler) collect() {
	families, err := controllermetrics.Registry.Gather()
	if err != nil {
		return
	}
	at := time.Now()
	adds := map[string]float64{}
	reconciles := map[string]float64{}
	work := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			name := metricLabel(metric, "name")
			controller := metricLabel(metric, "controller")
			switch family.GetName() {
			case "workqueue_adds_total":
				if name != "" {
					adds[name] += metric.GetCounter().GetValue()
				}
			case "workqueue_work_duration_seconds":
				if name != "" {
					work[name] += metric.GetHistogram().GetSampleSum()
				}
			case "controller_runtime_reconcile_total":
				if controller != "" {
					reconciles[controller] += metric.GetCounter().GetValue()
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, controller := range []string{"gateway", "cloudflaretunnel"} {
		s.samples[controller] = append(s.samples[controller], managerMetricSample{
			At:         at,
			Adds:       adds[controller],
			Reconciles: reconciles[controller],
			WorkSum:    work[controller],
		})
	}
}

func metricLabel(metric *dto.Metric, label string) string {
	for _, pair := range metric.GetLabel() {
		if pair.GetName() == label {
			return pair.GetValue()
		}
	}
	return ""
}

func (s *managerMetricsSampler) close() {
	close(s.done)
	s.wg.Wait()
}

func (s *managerMetricsSampler) snapshot(controller string) []managerMetricSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]managerMetricSample(nil), s.samples[controller]...)
}

// countAt returns the counter value of the last sample at or before t.
func (s *managerMetricsSampler) countAt(controller string, t time.Time, pick func(managerMetricSample) float64) float64 {
	samples := s.snapshot(controller)
	value := 0.0
	for _, sample := range samples {
		if sample.At.After(t) {
			break
		}
		value = pick(sample)
	}
	return value
}

// firstIncreaseAfter returns the sampling time of the first counter increase
// strictly after t, or the zero time when no increase was observed yet.
func (s *managerMetricsSampler) firstIncreaseAfter(controller string, t time.Time, pick func(managerMetricSample) float64) time.Time {
	samples := s.snapshot(controller)
	base := s.countAt(controller, t, pick)
	for _, sample := range samples {
		if !sample.At.After(t) {
			continue
		}
		if pick(sample) > base {
			return sample.At
		}
	}
	return time.Time{}
}

// lastIncreaseBefore returns the sampling time of the most recent counter
// increase at or before t.
func (s *managerMetricsSampler) lastIncreaseBefore(controller string, t time.Time, pick func(managerMetricSample) float64) time.Time {
	samples := s.snapshot(controller)
	var last time.Time
	previous := 0.0
	for _, sample := range samples {
		if sample.At.After(t) {
			break
		}
		if pick(sample) > previous {
			last = sample.At
		}
		previous = pick(sample)
	}
	return last
}

func managerPickAdds(sample managerMetricSample) float64       { return sample.Adds }
func managerPickReconciles(sample managerMetricSample) float64 { return sample.Reconciles }
func managerPickWork(sample managerMetricSample) float64       { return sample.WorkSum }

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
	metrics           *managerMetricsSampler
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

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
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
		metrics:   newManagerMetricsSampler(),
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

	gatewayReconciler := &GatewayReconciler{
		Client:            mgr.GetClient(),
		Scheme:            scheme,
		Snapshots:         h.snapshots,
		BuildSnapshot:     translator.Build,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               h.gwClock.now,
		CloudflareFactory: managerGatewayFactory{api: &managerGatewayAPI{remote: remote}},
		Prober:            h.prober,
		SweepEvents:       h.sweep,
	}
	managerSetAPIReader(gatewayReconciler, mgr.GetAPIReader())
	h.gatewayReconciler = gatewayReconciler
	if err := gatewayReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayReconciler: %v", err)
	}
	tunnelReconciler := &CloudflareTunnelReconciler{
		Client:            mgr.GetClient(),
		Scheme:            scheme,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               h.tunClock.now,
		NewCloudflareClient: func(token, accountID string) (TunnelCloudflareClient, error) {
			remote.use(token, accountID)
			return remote, nil
		},
	}
	managerSetAPIReader(tunnelReconciler, mgr.GetAPIReader())
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
	h.metrics.close()
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

// assertEventDriven proves the QA §6 causal chain for one controller: a
// reconcile completes after the event and before the earlier of (a) the next
// periodic requeue deadline or (b) event+interval. For a quiescent controller
// there is no pending timer, so (b) bounds the evidence. Error backoff is
// excluded because the asserted paths return nil errors.
func (h *managerHarness) assertEventDriven(t *testing.T, controller string, interval time.Duration, eventAt time.Time, what string) time.Time {
	t.Helper()
	deadline := eventAt.Add(interval)
	if last := h.metrics.lastIncreaseBefore(controller, eventAt, managerPickReconciles); !last.IsZero() && last.Add(interval).After(eventAt) {
		deadline = last.Add(interval)
	}
	var doneAt time.Time
	h.waitFor(t, 4*time.Second, controller+" reconcile after "+what, func() (bool, error) {
		doneAt = h.metrics.firstIncreaseAfter(controller, eventAt, managerPickReconciles)
		return !doneAt.IsZero(), nil
	})
	addAt := h.metrics.firstIncreaseAfter(controller, eventAt, managerPickAdds)
	t.Logf("%s: event=%s add=%s reconcile-done=%s deadline=%s", what,
		eventAt.Format("15:04:05.000"), addAt.Format("15:04:05.000"), doneAt.Format("15:04:05.000"), deadline.Format("15:04:05.000"))
	if !doneAt.Before(deadline) {
		t.Fatalf("%s: %s reconcile at %s did not precede periodic deadline %s", what, controller, doneAt, deadline)
	}
	return doneAt
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
		base := h.metrics.countAt("gateway", start, managerPickReconciles)
		deadline := start.Add(window)
		for time.Now().Before(deadline) {
			if h.metrics.countAt("gateway", time.Now(), managerPickReconciles) != base {
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

// freshWindow waits for one more gateway reconcile completion and returns the
// time just after it, giving the following stimulus a full periodic interval
// of headroom so an event-caused reconcile is distinguishable from the timer.
func (h *managerHarness) freshWindow(t *testing.T) time.Time {
	t.Helper()
	now := time.Now()
	var doneAt time.Time
	h.waitFor(t, 4*time.Second, "periodic reconcile boundary", func() (bool, error) {
		doneAt = h.metrics.firstIncreaseAfter("gateway", now, managerPickReconciles)
		return !doneAt.IsZero(), nil
	})
	return time.Now()
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
	baseReconciles := h.metrics.countAt("gateway", start, managerPickReconciles)

	window := 4 * time.Second
	time.Sleep(window)

	modified := h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, start)
	current := h.getTunnel(t, f.tunnelKey)
	reconciles := h.metrics.countAt("gateway", time.Now(), managerPickReconciles) - baseReconciles
	t.Logf("QA-92-02 window=%s modified=%d rv %s->%s gateway-reconciles=%.0f",
		window, len(modified), baseRV, current.ResourceVersion, reconciles)
	h.dumpTunnelSequence(t, f, start)
	if len(modified) != 0 {
		t.Fatalf("converged tunnel emitted %d MODIFIED events in %s", len(modified), window)
	}
	if current.ResourceVersion != baseRV {
		t.Fatalf("converged tunnel resourceVersion moved %s -> %s", baseRV, current.ResourceVersion)
	}
	if reconciles != 0 {
		t.Fatalf("converged gateway self-triggered %.0f reconciles in %s", reconciles, window)
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
	var idEventAt time.Time
	h.waitFor(t, 30*time.Second, "status.tunnelId write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || tunnel.Status.TunnelID == "" {
				continue
			}
			idEventAt = event.At
			return true, nil
		}
		return false, nil
	})
	if idEventAt.IsZero() {
		t.Fatal("no tunnelId status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, idEventAt, "tunnelId assignment")

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
	var refEventAt time.Time
	h.waitFor(t, 30*time.Second, "connectorTokenSecretRef write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || tunnel.Status.ConnectorTokenSecretRef == nil {
				continue
			}
			refEventAt = event.At
			return true, nil
		}
		return false, nil
	})
	if refEventAt.IsZero() {
		t.Fatal("no connectorTokenSecretRef status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, refEventAt, "connectorTokenSecretRef capture")

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

	var verifiedEventAt time.Time
	h.waitFor(t, 30*time.Second, "ownershipVerified write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil || !tunnel.Status.OwnershipVerified {
				continue
			}
			verifiedEventAt = event.At
			return true, nil
		}
		return false, nil
	})
	if verifiedEventAt.IsZero() {
		t.Fatal("no ownershipVerified status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, verifiedEventAt, "ownershipVerified")

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

	// Unblock DNS: the tunnel controller records the compiled hostname entry;
	// that status-only event must wake the Gateway into Programmed=True.
	injectAt := h.freshWindow(t)
	h.remote.clearFail("CreateCNAME")
	var recordsEventAt time.Time
	h.waitFor(t, 30*time.Second, "dnsRecords entry write", func() (bool, error) {
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			if event.At.Before(injectAt) {
				continue
			}
			tunnel, err := managerTunnelOf(event)
			if err != nil {
				continue
			}
			for _, record := range tunnel.Status.DNSRecords {
				if record.Hostname == f.hostname && record.State != dnsRecordStateConflict {
					recordsEventAt = event.At
					return true, nil
				}
			}
		}
		return false, nil
	})
	if recordsEventAt.IsZero() {
		t.Fatal("no dnsRecords status event recorded")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, recordsEventAt, "dnsRecords entry")
	h.waitFor(t, 30*time.Second, "Programmed=True", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionTrue, nil
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
	eventAt := time.Now()
	var pod corev1.Pod
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["qa92.probe"] = "down"
	if err := h.direct.Update(h.ctx, &pod); err != nil {
		t.Fatalf("touch pod: %v", err)
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, eventAt, "pod probe failure")

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

	// Recovery: probe healthy again, poke the Pod, Programmed returns.
	h.prober.set(true, h.liveConfigVersionFn(f))
	recoverAt := time.Now()
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.podName}, &pod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	pod.Annotations["qa92.probe"] = "up"
	if err := h.direct.Update(h.ctx, &pod); err != nil {
		t.Fatalf("touch pod: %v", err)
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, recoverAt, "pod probe recovery")
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
	var tupleEventAt time.Time
	h.waitFor(t, 30*time.Second, "complete writer-guard tuple", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		for _, event := range h.recorder.events(managerTunnelGVR, &f.tunnelKey) {
			tunnel, err := managerTunnelOf(event)
			if err != nil {
				continue
			}
			if managerTunnelTupleComplete(tunnel, gateway) {
				tupleEventAt = event.At
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
	h.assertEventDriven(t, "gateway", programmedRequeue, tupleEventAt, "writer-guard tuple")
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
	// channel the real SetupWithManager wired.
	tunnel := h.getTunnel(t, f.tunnelKey)
	h.remote.setConfigVersion(tunnel.Status.TunnelID, tunnel.Status.ConfigVersion.Applied+7)
	eventAt := time.Now()
	h.sweep <- event.GenericEvent{Object: tunnel}

	h.assertEventDriven(t, "gateway", programmedRequeue, eventAt, "sweep GenericEvent")
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
	eventAt := time.Now()
	f.account = h.createAccount(t, f)
	h.assertEventDriven(t, "cloudflaretunnel", tunnelRequeue, eventAt, "CloudflareAccount creation")
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
				tupleEventAt = event.At
				return true, nil
			}
		}
		return false, nil
	})
	if tupleEventAt.IsZero() {
		t.Fatal("no complete writer-guard tuple event recorded after account creation")
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, tupleEventAt, "tuple-complete status event")

	// The account-less fixture deferred dataplane wiring; now that the tunnel
	// is provisioned the Deployment exists and the gate inputs can be armed.
	h.ensureDataplane(t, f)

	// Credential rotation: touching the account re-enqueues the Gateway; a
	// broken credential Secret surfaces as a reconcile error, not silence.
	h.waitConverged(t, f)
	h.waitQuiescent(t, f, 1200*time.Millisecond)
	var secret corev1.Secret
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: f.namespace, Name: f.secretName}, &secret); err != nil {
		t.Fatalf("get credential secret: %v", err)
	}
	secret.Data["token"] = []byte("")
	if err := h.direct.Update(h.ctx, &secret); err != nil {
		t.Fatalf("break credential secret: %v", err)
	}
	rotateAt := time.Now()
	var account v1alpha1.CloudflareAccount
	if err := h.direct.Get(h.ctx, types.NamespacedName{Name: f.accountName}, &account); err != nil {
		t.Fatalf("get account: %v", err)
	}
	if account.Annotations == nil {
		account.Annotations = map[string]string{}
	}
	account.Annotations["qa92.rotation"] = "1"
	if err := h.direct.Update(h.ctx, &account); err != nil {
		t.Fatalf("touch account: %v", err)
	}
	h.assertEventDriven(t, "gateway", programmedRequeue, rotateAt, "account credential rotation")
	h.waitFor(t, 15*time.Second, "credential failure surfaced", func() (bool, error) {
		base := h.metrics.countAt("gateway", rotateAt, managerPickReconciles)
		return h.metrics.countAt("gateway", time.Now(), managerPickReconciles) > base, nil
	})
	// Restore credentials; the Gateway recovers through the same watch path.
	secret.Data["token"] = []byte("qa92-token")
	if err := h.direct.Update(h.ctx, &secret); err != nil {
		t.Fatalf("restore credential secret: %v", err)
	}
	account.Annotations["qa92.rotation"] = "2"
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
	baseGWReconciles := h.metrics.countAt("gateway", start, managerPickReconciles)
	baseTunReconciles := h.metrics.countAt("cloudflaretunnel", start, managerPickReconciles)
	baseGWWork := h.metrics.countAt("gateway", start, managerPickWork)
	baseTunWork := h.metrics.countAt("cloudflaretunnel", start, managerPickWork)
	baseCalls := len(h.remote.callsSince(time.Time{}, ""))

	time.Sleep(managerQA92Window)
	end := time.Now()

	modified := h.recorder.modifiedAfter(managerTunnelGVR, f.tunnelKey, start)
	endTunnel := h.getTunnel(t, f.tunnelKey)
	measurement := managerQA92Measurement{
		Suite:            "issue-92-manager",
		WindowSeconds:    end.Sub(start).Seconds(),
		GatewayReconcile: h.metrics.countAt("gateway", end, managerPickReconciles) - baseGWReconciles,
		TunnelReconcile:  h.metrics.countAt("cloudflaretunnel", end, managerPickReconciles) - baseTunReconciles,
		GatewayWorkSum:   h.metrics.countAt("gateway", end, managerPickWork) - baseGWWork,
		TunnelWorkSum:    h.metrics.countAt("cloudflaretunnel", end, managerPickWork) - baseTunWork,
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
