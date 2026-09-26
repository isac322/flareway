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

package sweep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/internal/ownership"
	"github.com/isac322/flareway/test/cfstub"
)

// This file implements the QA matrix of
// docs/design/002-dns-sweep-zone-isolation-qa.md (issue #93): per-zone listing
// failures must be isolated so one denied zone cannot discard the healthy
// zones' drift findings. The probe harness injects faults only at the
// flarecloudflare.API boundary; the real sweepDNSRecords, RunTargetOnce, and
// runTarget code paths run against a fake Kubernetes client.

const (
	probeAccountName       = "acct"
	probeOperatorNamespace = "flareway-system"
	probeClusterID         = "cluster-uid-1"
)

// probeOwnershipKey is the fixed HMAC key seeded into the ownership Secret so
// ownership markers are deterministic.
var probeOwnershipKey = bytes.Repeat([]byte{0x2a}, ownership.KeyLengthBytes)

// probeZone describes one account zone: the records a successful listing
// returns, or the error a denied zone returns.
type probeZone struct {
	id      string
	records []flarecloudflare.DNSRecord
	err     error
}

// zonePermAPI is a fake flarecloudflare.API that answers the account zone
// listing and per-zone DNS listings from a permission map, journaling every
// DNS listing call in order. Unimplemented methods panic through the embedded
// nil interface, which keeps the harness honest: the DNS sweep must only use
// these two calls.
type zonePermAPI struct {
	flarecloudflare.API

	mu        sync.Mutex
	zones     []flarecloudflare.Zone
	zonesErr  error
	byZone    map[string]probeZone
	dnsCalls  []string
	onDNSCall func(zoneID string)
}

func (api *zonePermAPI) ListZones(context.Context) ([]flarecloudflare.Zone, error) {
	if api.zonesErr != nil {
		return nil, api.zonesErr
	}
	return api.zones, nil
}

func (api *zonePermAPI) ListDNSRecordsByComment(_ context.Context, zoneID, _ string) ([]flarecloudflare.DNSRecord, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.dnsCalls = append(api.dnsCalls, zoneID)
	if api.onDNSCall != nil {
		api.onDNSCall(zoneID)
	}
	zone := api.byZone[zoneID]
	if zone.err != nil {
		return nil, zone.err
	}
	return zone.records, nil
}

func (api *zonePermAPI) calls() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return slices.Clone(api.dnsCalls)
}

// setZoneErr changes one zone's listing outcome between passes.
func (api *zonePermAPI) setZoneErr(zoneID string, err error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	zone := api.byZone[zoneID]
	zone.err = err
	api.byZone[zoneID] = zone
}

// zonePermFactory returns the same fake API for every account. It deliberately
// does not implement sweepClientFactory, so the sweeper's own limiter paces
// remote calls — QA-10(c) depends on that pacing path existing.
type zonePermFactory struct{ api *zonePermAPI }

func (f zonePermFactory) Client(string, string) flarecloudflare.API { return f.api }

// recordingInvalidator counts Invalidate calls; the latch semantics are
// irrelevant here, only whether the sweep dispatched.
type recordingInvalidator struct {
	mu    sync.Mutex
	calls []types.NamespacedName
}

func (r *recordingInvalidator) Invalidate(_ string, key types.NamespacedName, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, key)
}

func (r *recordingInvalidator) IsInvalidated(string, types.NamespacedName) bool { return false }
func (r *recordingInvalidator) Clear(string, types.NamespacedName)              {}

func (r *recordingInvalidator) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// dnsProbeConfig tunes one probe fixture.
type dnsProbeConfig struct {
	zones     []probeZone
	zonesErr  error
	objects   []client.Object
	rateLimit float64
	onDNSCall func(zoneID string)
	// withoutKubeSystem drops the kube-system Namespace so clusterID fails.
	withoutKubeSystem bool
	// listErr fails CloudflareTunnelList reads through the fake client.
	listErr error
	// forbidWrites fails every mutating Kubernetes call, proving the sweep
	// is read-only (QA-15).
	forbidWrites bool
	// factory overrides the probe factory (QA-07 uses a real SDK client).
	factory flarecloudflare.ClientFactory
	// grantZones sets the zones of the seeded CloudflareAccount's single
	// grant; nil grants "*" (full enumeration). The account is seeded only
	// when objects carries none and withoutAccount is false.
	grantZones []string
	// withoutAccount drops the seeded CloudflareAccount so its read fails.
	withoutAccount bool
}

type dnsProbeFixture struct {
	sweeper     *AccountSweeper
	api         *zonePermAPI
	kube        client.Client
	invalidator *recordingInvalidator
	events      chan event.GenericEvent
}

func newDNSProbeFixture(t *testing.T, cfg dnsProbeConfig) *dnsProbeFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := append([]client.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: probeOperatorNamespace, Name: ownership.SecretName},
			Data:       map[string][]byte{ownership.SecretKey: probeOwnershipKey},
		},
	}, cfg.objects...)
	if !cfg.withoutAccount && !slices.ContainsFunc(cfg.objects, func(object client.Object) bool {
		_, ok := object.(*v1alpha1.CloudflareAccount)
		return ok
	}) {
		zones := cfg.grantZones
		if zones == nil {
			zones = []string{"*"}
		}
		objects = append(objects, probeAccount(zones))
	}
	if !cfg.withoutKubeSystem {
		objects = append(objects, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(probeClusterID)},
		})
	}
	funcs := interceptor.Funcs{}
	if cfg.forbidWrites {
		writeDenied := errors.New("sweep must not write to the API server")
		funcs.Create = func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return writeDenied
		}
		funcs.Update = func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return writeDenied
		}
		funcs.Patch = func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
			return writeDenied
		}
		funcs.Delete = func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			return writeDenied
		}
	}
	if cfg.listErr != nil {
		funcs.List = func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*v1alpha1.CloudflareTunnelList); ok {
				return cfg.listErr
			}
			return c.List(ctx, list, opts...)
		}
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithInterceptorFuncs(funcs).Build()

	api := &zonePermAPI{
		zonesErr:  cfg.zonesErr,
		byZone:    make(map[string]probeZone, len(cfg.zones)),
		onDNSCall: cfg.onDNSCall,
	}
	for _, zone := range cfg.zones {
		api.zones = append(api.zones, flarecloudflare.Zone{ID: zone.id, Name: zone.id + ".example.com", AccountID: "account-1"})
		api.byZone[zone.id] = zone
	}
	factory := cfg.factory
	if factory == nil {
		factory = zonePermFactory{api: api}
	}
	rateLimit := cfg.rateLimit
	if rateLimit == 0 {
		rateLimit = 1e9 // effectively unpaced
	}
	fixture := &dnsProbeFixture{
		api:         api,
		kube:        kube,
		invalidator: &recordingInvalidator{},
		events:      make(chan event.GenericEvent, 16),
	}
	fixture.sweeper = NewAccountSweeper(AccountSweeperOptions{
		AccountName:       probeAccountName,
		AccountID:         "account-1",
		Token:             "token",
		Factory:           factory,
		Client:            kube,
		APIReader:         kube,
		Invalidator:       fixture.invalidator,
		OperatorNamespace: probeOperatorNamespace,
		RateLimit:         rateLimit,
		RateBurst:         1,
		Events:            fixture.events,
		Logger:            logr.Discard(),
	})
	return fixture
}

// dnsTarget is the real DNS sweep target descriptor.
func dnsTarget() TargetDescriptor {
	grade, ok := freshness.GradeForKind("DNSRecord")
	if !ok {
		panic("DNSRecord has no freshness grade")
	}
	return TargetDescriptor{Kind: "DNSRecord", Grade: grade, SweepFunc: sweepDNSRecords}
}

// probeTunnel builds a managed CloudflareTunnel owned by this sweeper's
// account, carrying the given DNS checkpoints.
func probeTunnel(name string, checkpoints ...v1alpha1.CloudflareTunnelDNSRecordStatus) *v1alpha1.CloudflareTunnel {
	return &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:   "tid-" + name,
			DNSRecords: checkpoints,
		},
	}
}

// probeAccount builds this sweeper's CloudflareAccount with one grant over
// the given zones.
func probeAccount(zones []string) *v1alpha1.CloudflareAccount {
	return &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: probeAccountName},
		Spec: v1alpha1.CloudflareAccountSpec{AccountID: "account-1", Grants: []v1alpha1.CloudflareAccountGrant{{
			Hostnames: []string{"*"}, Zones: zones,
		}}},
	}
}

// probeMarker returns the ownership marker the sweeper computes for a tunnel
// in namespace "ns" under the seeded ownership key.
func probeMarker(tunnelName string) string {
	return flarecloudflare.SignDNSRecordComment(probeOwnershipKey, probeClusterID, "ns", tunnelName)
}

// dnsListError wraps an HTTP status the same way the real adapter does so
// flarecloudflare.StatusCode classifies it identically.
func dnsListError(status int) error {
	return fmt.Errorf("list Cloudflare DNS records by comment: %w", &cloudflaresdk.Error{StatusCode: status})
}

// deniedZoneError builds a zone listing failure that carries both an
// identifiable cause (for errors.Is assertions) and an HTTP status.
func deniedZoneError(cause error, status int) error {
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "api.cloudflare.com", Path: "/client/v4/zones/synthetic-zone/dns_records"},
	}
	return fmt.Errorf("list Cloudflare DNS records by comment: %w: %w", cause, &cloudflaresdk.Error{
		StatusCode: status,
		Request:    request,
		Response:   &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Request: request},
	})
}

// transportZoneError builds a zone listing failure with no HTTP status, like
// a connection reset surfaced through the adapter.
func transportZoneError(cause error) error {
	return fmt.Errorf("list Cloudflare DNS records by comment: %w", cause)
}

// requireScopedError asserts err is a scopedListingError that still matches
// errIncompleteListing, and returns it for structural assertions.
func requireScopedError(t *testing.T, err error) *scopedListingError {
	t.Helper()
	var scoped *scopedListingError
	if !errors.As(err, &scoped) {
		t.Fatalf("error %v is not a scopedListingError", err)
	}
	if !errors.Is(err, errIncompleteListing) {
		t.Fatalf("scoped error %v does not match errIncompleteListing", err)
	}
	return scoped
}

// requireScopedFailures asserts the aggregate carries exactly the injected
// per-zone causes in discovery order.
func requireScopedFailures(t *testing.T, err error, causes ...error) {
	t.Helper()
	scoped := requireScopedError(t, err)
	if len(scoped.failures) != len(causes) {
		t.Fatalf("scoped failures = %d, want %d (%v)", len(scoped.failures), len(causes), err)
	}
	for i, cause := range causes {
		if !errors.Is(scoped.failures[i], cause) {
			t.Fatalf("scoped failure %d = %v, want cause %v", i, scoped.failures[i], cause)
		}
		if !errors.Is(err, cause) {
			t.Fatalf("aggregate %v does not wrap cause %v", err, cause)
		}
	}
}

func requireItems(t *testing.T, items []DriftItem, want ...DriftItem) {
	t.Helper()
	if len(items) != len(want) {
		t.Fatalf("items = %#v, want %d item(s)", items, len(want))
	}
	for i, w := range want {
		got := items[i]
		if got.Case != w.Case || got.RemoteID != w.RemoteID ||
			got.TargetKind != w.TargetKind || got.NamespacedName != w.NamespacedName {
			t.Fatalf("items[%d] = %#v, want case=%s remote=%s target=%s %s",
				i, got, w.Case, w.RemoteID, w.TargetKind, w.NamespacedName)
		}
	}
}

func requireDNSCalls(t *testing.T, api *zonePermAPI, want ...string) {
	t.Helper()
	if got := api.calls(); !slices.Equal(got, want) {
		t.Fatalf("DNS listing calls = %v, want %v", got, want)
	}
}

// requireDispatch asserts the worker dispatched exactly this many invalidator
// latches and wakeup events.
func requireDispatch(t *testing.T, f *dnsProbeFixture, invalidations, events int) {
	t.Helper()
	if got := f.invalidator.count(); got != invalidations {
		t.Fatalf("invalidations = %d, want %d", got, invalidations)
	}
	if got := len(f.events); got != events {
		t.Fatalf("pending events = %d, want %d", got, events)
	}
}

func missingItem(remoteID, name string) DriftItem {
	return DriftItem{
		Case:           DriftCaseMissing,
		RemoteID:       remoteID,
		TargetKind:     "CloudflareTunnel",
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: name},
	}
}

// sweepPassCount reads the global flareway_sweep_total counter. Only the
// designated serial tests (QA-09b, QA-18a) may call this: parallel tests would
// race other passes on the shared Default registry.
func sweepPassCount(t *testing.T, kind, result string) float64 {
	t.Helper()
	families, err := controllermetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "flareway_sweep_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			var k, r string
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "kind":
					k = label.GetValue()
				case "result":
					r = label.GetValue()
				}
			}
			if k == kind && r == result {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// sweepLastSuccess reads the global last-success gauge; same serial-only rule
// as sweepPassCount.
func sweepLastSuccess(t *testing.T, kind string) float64 {
	t.Helper()
	families, err := controllermetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "flareway_sweep_last_success_timestamp" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "kind" && label.GetValue() == kind {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

// QA-01(a): single healthy zone — the control case proving the fix is purely
// additive. result=ok also proves the pass reached the only code path that
// advances last-success.
func TestDNSSweepHealthySingleZone(t *testing.T) {
	t.Parallel()
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-a", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones:   []probeZone{{id: "zone-a"}},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if err != nil || result != observability.SweepResultOK {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
	}
	requireItems(t, items, missingItem("rec-1", "gw"))
	requireDNSCalls(t, f.api, "zone-a")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-01(b): every zone healthy — the listing spans all zones.
func TestDNSSweepHealthyMultiZone(t *testing.T) {
	t.Parallel()
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones:   []probeZone{{id: "zone-a"}, {id: "zone-b"}},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if err != nil || result != observability.SweepResultOK {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
	}
	requireItems(t, items, missingItem("rec-b", "gw"))
	requireDNSCalls(t, f.api, "zone-a", "zone-b")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-02: a denied first zone must not abort the pass — the healthy zone's
// findings are judged and dispatched (issue #93 reproduction).
func TestDNSSweepZoneDeniedFirst(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)},
			{id: "zone-b"},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA)
	if status, ok := flarecloudflare.StatusCode(err); !ok || status != http.StatusForbidden {
		t.Fatalf("aggregate status = %d %t, want 403", status, ok)
	}
	requireItems(t, items, missingItem("rec-b", "gw"))
	requireDNSCalls(t, f.api, "zone-a", "zone-b")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-03: a denied last zone must not discard the findings already collected
// from healthy zones.
func TestDNSSweepZoneDeniedLast(t *testing.T) {
	t.Parallel()
	causeB := errors.New("zone-b denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-a", "zone-a", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a"},
			{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeB)
	requireItems(t, items, missingItem("rec-a", "gw"))
	requireDNSCalls(t, f.api, "zone-a", "zone-b")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-04: a checkpoint whose zone was never listed must produce no judgement —
// the listedZones fail-closed guard keeps it out of missing classification,
// and the checkpoint itself is left untouched.
func TestDNSSweepDeniedZoneCheckpoint(t *testing.T) {
	t.Parallel()
	causeB := errors.New("zone-b denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	tunnel := probeTunnel("gw", checkpoint)
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a"},
			{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
		},
		objects: []client.Object{tunnel},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeB)
	if len(items) != 0 {
		t.Fatalf("items = %#v, want none for an unlisted zone's checkpoint", items)
	}

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 0, 0)

	current := &v1alpha1.CloudflareTunnel{}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), current); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current.Status.DNSRecords, tunnel.Status.DNSRecords) {
		t.Fatalf("checkpoint mutated: %#v -> %#v", tunnel.Status.DNSRecords, current.Status.DNSRecords)
	}
}

// QA-05: a 404 on an unrelated zone is isolated the same way; the healthy
// zone's content drift is still reported.
func TestDNSSweepZoneNotFound(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a gone")
	marker := probeMarker("gw")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", marker)
	drifted := flarecloudflare.DNSRecord{
		ID: "rec-b", Type: "CNAME", Name: "app.example.com",
		Content: "192.0.2.9", Comment: marker,
	}
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusNotFound)},
			{id: "zone-b", records: []flarecloudflare.DNSRecord{drifted}},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA)
	requireItems(t, items, DriftItem{
		Case: DriftCaseMismatch, RemoteID: "rec-b",
		TargetKind: "CloudflareTunnel", NamespacedName: types.NamespacedName{Namespace: "ns", Name: "gw"},
	})

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-06(a): a zone-local 5xx is isolated; the healthy zone's findings ship.
func TestDNSSweepZoneServerError(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a upstream")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusInternalServerError)},
			{id: "zone-b"},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA)
	requireItems(t, items, missingItem("rec-b", "gw"))

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-06(b): a transport error that carries no HTTP status is isolated too.
func TestDNSSweepZoneTransportError(t *testing.T) {
	t.Parallel()
	causeA := errors.New("connection reset by peer")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: transportZoneError(causeA)},
			{id: "zone-b"},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA)
	requireItems(t, items, missingItem("rec-b", "gw"))

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-07: a failure mid-pagination discards the whole zone's partial page —
// the adapter returns (nil, err) for the zone, so nothing it listed may reach
// judgement. This is the one case that needs the real SDK paginator: a test
// proxy fails only zone-a's page=2 terminator request while cfstub serves
// everything else.
func TestDNSSweepMidPaginationFailure(t *testing.T) {
	t.Parallel()
	stub := cfstub.New(t)
	stub.State.AddZone(cfstub.Zone{ID: "zone-a", Name: "a.example.com", AccountID: "account-1"})
	stub.State.AddZone(cfstub.Zone{ID: "zone-b", Name: "b.example.com", AccountID: "account-1"})
	// A record that would be an orphan candidate if zone-a's partial page
	// leaked into judgement.
	stub.State.AddDNSRecord(cfstub.DNSRecord{
		ID: "rec-a", ZoneID: "zone-a", Type: "CNAME",
		Name: "ghost.example.com", Content: "tid-gw.cfargotunnel.com",
		Comment: probeMarker("gw"),
	})

	upstream, err := url.Parse(stub.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var proxyMu sync.Mutex
	var proxyCalls []string
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyMu.Lock()
		proxyCalls = append(proxyCalls, r.Method+" "+r.URL.RequestURI())
		proxyMu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/zones/zone-a/dns_records" && r.URL.Query().Get("page") == "2" {
			cfstub.WriteError(w, http.StatusInternalServerError, 10000, "injected page-2 failure")
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		factory: flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(front.URL)),
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	scoped := requireScopedError(t, err)
	if len(scoped.failures) != 1 {
		t.Fatalf("scoped failures = %d, want 1 (%v)", len(scoped.failures), err)
	}
	if status, ok := flarecloudflare.StatusCode(scoped.failures[0]); !ok || status != http.StatusInternalServerError {
		t.Fatalf("zone-a failure status = %d %t, want 500", status, ok)
	}
	// Zone-a's page-1 record must not appear as an orphan; only zone-b's
	// missing checkpoint is judged.
	requireItems(t, items, missingItem("rec-b", "gw"))

	proxyMu.Lock()
	calls := slices.Clone(proxyCalls)
	proxyMu.Unlock()
	var page1, page2 int
	for _, call := range calls {
		if !strings.HasPrefix(call, "GET /zones/zone-a/dns_records") {
			continue
		}
		if strings.Contains(call, "page=2") {
			page2++
		} else {
			page1++
		}
	}
	if page1 != 1 || page2 == 0 {
		t.Fatalf("zone-a pagination calls: page1=%d page2=%d, want 1 and >=1 (%v)", page1, page2, calls)
	}
}

// QA-08(a): a healthy zone's orphan is still detected on a partial pass —
// isolation narrows findings, it does not suppress them. Orphans are
// observe-only, so the worker dispatches nothing for them.
func TestDNSSweepOrphanInHealthyZone(t *testing.T) {
	t.Parallel()
	causeB := errors.New("zone-b denied")
	orphan := flarecloudflare.DNSRecord{
		ID: "rec-orphan", Type: "CNAME", Name: "ghost.example.com",
		Content: "tid-gw.cfargotunnel.com", Comment: probeMarker("gw"),
	}
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", records: []flarecloudflare.DNSRecord{orphan}},
			{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
		},
		objects: []client.Object{probeTunnel("gw")},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeB)
	requireItems(t, items, DriftItem{
		Case: DriftCaseOrphan, RemoteID: "rec-orphan",
		TargetKind: "CloudflareTunnel", NamespacedName: types.NamespacedName{Namespace: "ns", Name: "gw"},
	})

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 0, 0)
}

// QA-08(b): strict ownership — a record without a valid marker, or whose
// CNAME does not point at the tunnel, is never an orphan candidate.
func TestDNSSweepOrphanStrictMarker(t *testing.T) {
	t.Parallel()
	marker := probeMarker("gw")
	cases := []struct {
		name   string
		record flarecloudflare.DNSRecord
	}{
		{"no ownership marker", flarecloudflare.DNSRecord{
			ID: "rec-x", Type: "CNAME", Name: "ghost.example.com",
			Content: "tid-gw.cfargotunnel.com", Comment: "someone else's record",
		}},
		{"foreign cname target", flarecloudflare.DNSRecord{
			ID: "rec-x", Type: "CNAME", Name: "ghost.example.com",
			Content: "other.cfargotunnel.com", Comment: marker,
		}},
		{"forged marker on A record", flarecloudflare.DNSRecord{
			ID: "rec-x", Type: "A", Name: "ghost.example.com",
			Content: "203.0.113.9", Comment: marker,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			causeB := errors.New("zone-b denied")
			f := newDNSProbeFixture(t, dnsProbeConfig{
				zones: []probeZone{
					{id: "zone-a", records: []flarecloudflare.DNSRecord{tc.record}},
					{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
				},
				objects: []client.Object{probeTunnel("gw")},
			})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if result != observability.SweepResultPartial {
				t.Fatalf("result = %q, want partial (err=%v)", result, err)
			}
			requireScopedFailures(t, err, causeB)
			if len(items) != 0 {
				t.Fatalf("items = %#v, want no orphan candidate", items)
			}
		})
	}
}

// QA-08(c): the claimed set stays account-wide — a record in a healthy zone
// claimed by a checkpoint whose zone failed is neither missing nor orphan.
// Narrowing claimed to listed zones would turn it into a false orphan.
func TestDNSSweepClaimedRecordAcrossZones(t *testing.T) {
	t.Parallel()
	causeB := errors.New("zone-b denied")
	marker := probeMarker("gw")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-b", marker)
	claimed := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "app.example.com",
		Content: "tid-gw.cfargotunnel.com", Comment: marker,
	}
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", records: []flarecloudflare.DNSRecord{claimed}},
			{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeB)
	if len(items) != 0 {
		t.Fatalf("items = %#v, want none: claimed records are not orphans", items)
	}
}

// QA-09(a): multiple denied zones aggregate in deterministic discovery order,
// each wrapping its own cause, while the healthy zone's findings ship.
func TestDNSSweepMultipleDeniedZones(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a denied")
	causeC := errors.New("zone-c denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)},
			{id: "zone-b"},
			{id: "zone-c", err: deniedZoneError(causeC, http.StatusForbidden)},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA, causeC)
	requireItems(t, items, missingItem("rec-b", "gw"))
	requireDNSCalls(t, f.api, "zone-a", "zone-b", "zone-c")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-09(b): every zone denied — an honest partial with an empty item list and
// a stale last-success, not a quiet ok. SERIAL: reads the process-global
// metrics registry, so it must not run in parallel with other sweeps.
func TestDNSSweepAllZonesDenied(t *testing.T) {
	causeA := errors.New("zone-a denied")
	causeB := errors.New("zone-b denied")
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)},
			{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
		},
		objects: []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "rec-a", "zone-a", probeMarker("gw")))},
	})
	partialsBefore := sweepPassCount(t, "DNSRecord", observability.SweepResultPartial)
	lastBefore := sweepLastSuccess(t, "DNSRecord")

	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA, causeB)
	if len(items) != 0 {
		t.Fatalf("items = %#v, want none when every zone failed", items)
	}

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 0, 0)

	if got := sweepPassCount(t, "DNSRecord", observability.SweepResultPartial) - partialsBefore; got != 2 {
		t.Fatalf("partial sweep count delta = %v, want 2", got)
	}
	if got := sweepLastSuccess(t, "DNSRecord"); got != lastBefore {
		t.Fatalf("last-success advanced on partial passes: %v -> %v", lastBefore, got)
	}
}

// QA-10(a): context cancellation aborts the pass immediately — it is never
// absorbed into a scoped aggregate, and no further zones are queried.
func TestDNSSweepContextCancelStopsPass(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{{id: "zone-a"}, {id: "zone-b"}, {id: "zone-c"}},
		onDNSCall: func(string) {
			calls++
			if calls == 2 {
				cancel()
			}
		},
		objects: []client.Object{probeTunnel("gw")},
	})
	items, result, err := f.sweeper.RunTargetOnce(ctx, dnsTarget())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	var scoped *scopedListingError
	if errors.As(err, &scoped) {
		t.Fatalf("cancellation absorbed into scoped error: %v", err)
	}
	if result != "" {
		t.Fatalf("result = %q, want empty (no metric recorded)", result)
	}
	if items != nil {
		t.Fatalf("items = %#v, want nil", items)
	}
	requireDNSCalls(t, f.api, "zone-a", "zone-b")

	f.sweeper.runTarget(ctx, dnsTarget())
	requireDispatch(t, f, 0, 0)
}

// QA-10(c): a pacing wait failure is a global terminal error, not a scoped
// zone failure. The real limiter is kept (rate ~0, burst 1): the zone-listing
// wait consumes the single token and the next wait's reservation exceeds the
// short deadline, returning x/time's bare "would exceed context deadline"
// error — which wraps neither Canceled nor DeadlineExceeded.
func TestDNSSweepPacingWaitFailure(t *testing.T) {
	t.Parallel()
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones:     []probeZone{{id: "zone-a"}, {id: "zone-b"}},
		rateLimit: 1e-9,
		objects:   []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "rec-a", "zone-a", probeMarker("gw")))},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	items, result, err := f.sweeper.RunTargetOnce(ctx, dnsTarget())
	if err == nil {
		t.Fatal("expected a pacing failure, got nil error")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pacing error %v must not wrap a context error", err)
	}
	var scoped *scopedListingError
	if errors.As(err, &scoped) {
		t.Fatalf("pacing failure absorbed into scoped error: %v", err)
	}
	if result != observability.SweepResultError {
		t.Fatalf("result = %q, want error", result)
	}
	if items != nil {
		t.Fatalf("items = %#v, want nil", items)
	}
	requireDNSCalls(t, f.api)
}

// QA-10(d): a pacing failure surfaced by the real adapter middleware is
// terminal at the zone boundary, not a scoped zone failure. The error is
// produced by an actual cloudflare-go client whose limiter has already
// consumed its single token: Wait's reservation exceeds the short context
// and the middleware returns ErrRateLimitWait before any request is sent
// (no network). Injecting that real error on a later zone must abort the
// pass — without the sentinel the classifier treats it as an ordinary
// status-less transport error and absorbs it into the scoped aggregate.
func TestDNSSweepRealMiddlewarePacingFailure(t *testing.T) {
	t.Parallel()
	limiter := rate.NewLimiter(rate.Limit(1e-9), 1)
	if !limiter.Allow() {
		t.Fatal("fresh limiter must admit its burst token")
	}
	adapter := flarecloudflare.New("token", "account-1", logr.Discard(),
		flarecloudflare.WithLimiter(limiter),
		flarecloudflare.WithRequestOptions(option.WithMaxRetries(0)))
	pacingCtx, pacingCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer pacingCancel()
	_, pacingErr := adapter.ListZones(pacingCtx)
	if !errors.Is(pacingErr, flarecloudflare.ErrRateLimitWait) {
		t.Fatalf("adapter pacing error = %v, want ErrRateLimitWait", pacingErr)
	}
	if errors.Is(pacingErr, context.Canceled) || errors.Is(pacingErr, context.DeadlineExceeded) {
		t.Fatalf("pacing error %v must not wrap a context sentinel", pacingErr)
	}
	if _, ok := flarecloudflare.StatusCode(pacingErr); ok {
		t.Fatalf("pacing error %v must not carry an HTTP status", pacingErr)
	}
	// A canceled context must stay discoverable through the middleware wrap
	// so RunTargetOnce's shutdown branch keeps precedence over the scoped
	// branch.
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, canceledErr := adapter.ListZones(canceledCtx); !errors.Is(canceledErr, context.Canceled) {
		t.Fatalf("canceled pacing error = %v, want context.Canceled discoverable", canceledErr)
	}

	// Inject the real pacing error on zone-b: the pass must abort, discard
	// zone-a's findings, and never reach zone-c.
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a"},
			{id: "zone-b", err: pacingErr},
			{id: "zone-c"},
		},
		objects: []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "rec-a", "zone-a", probeMarker("gw")))},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if !errors.Is(err, flarecloudflare.ErrRateLimitWait) {
		t.Fatalf("err = %v, want ErrRateLimitWait", err)
	}
	var scoped *scopedListingError
	if errors.As(err, &scoped) {
		t.Fatalf("pacing failure absorbed into scoped error: %v", err)
	}
	if result != observability.SweepResultError {
		t.Fatalf("result = %q, want error", result)
	}
	if items != nil {
		t.Fatalf("items = %#v, want nil", items)
	}
	requireDNSCalls(t, f.api, "zone-a", "zone-b")

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 0, 0)
}

// QA-11: errors outside the isolation allowlist abort the pass at the first
// failing zone — 401 (conservative auth-uncertainty stop), 429 (account-level
// throttling), and unlisted 4xx (systemic request defects) are all terminal.
func TestDNSSweepTerminalZoneErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"http 401", http.StatusUnauthorized},
		{"http 429", http.StatusTooManyRequests},
		{"http 400", http.StatusBadRequest},
		{"http 422", http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
			f := newDNSProbeFixture(t, dnsProbeConfig{
				zones: []probeZone{
					{id: "zone-a", err: dnsListError(tc.status)},
					{id: "zone-b"},
				},
				objects: []client.Object{probeTunnel("gw", checkpoint)},
			})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if result != observability.SweepResultError || err == nil {
				t.Fatalf("RunTargetOnce = (%v, %q, %v), want terminal error", items, result, err)
			}
			var scoped *scopedListingError
			if errors.As(err, &scoped) {
				t.Fatalf("terminal %d absorbed into scoped error: %v", tc.status, err)
			}
			if status, ok := flarecloudflare.StatusCode(err); !ok || status != tc.status {
				t.Fatalf("error status = %d %t, want %d", status, ok, tc.status)
			}
			if items != nil {
				t.Fatalf("items = %#v, want nil", items)
			}
			requireDNSCalls(t, f.api, "zone-a")

			f.sweeper.runTarget(context.Background(), dnsTarget())
			requireDispatch(t, f, 0, 0)
		})
	}
}

// QA-12: account-level failures keep their existing contracts — the zone
// isolation change must not alter them.
func TestDNSSweepAccountLevelFailures(t *testing.T) {
	t.Parallel()
	// Each subtest gets a fresh tunnel: the fake client tracker may mutate
	// the objects it stores, so sharing one pointer across parallel subtests
	// would race.
	newTunnel := func() *v1alpha1.CloudflareTunnel {
		return probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "rec-a", "zone-a", probeMarker("gw")))
	}

	t.Run("zone listing 5xx is generic partial", func(t *testing.T) {
		t.Parallel()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zonesErr: dnsListError(http.StatusInternalServerError),
			objects:  []client.Object{newTunnel()},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultPartial || err != nil || items != nil {
			t.Fatalf("RunTargetOnce = (%v, %q, %v), want (nil, partial, nil)", items, result, err)
		}
		requireDNSCalls(t, f.api)
	})

	t.Run("zone listing transport is generic partial", func(t *testing.T) {
		t.Parallel()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zonesErr: errors.New("connection reset"),
			objects:  []client.Object{newTunnel()},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultPartial || err != nil || items != nil {
			t.Fatalf("RunTargetOnce = (%v, %q, %v), want (nil, partial, nil)", items, result, err)
		}
		requireDNSCalls(t, f.api)
	})

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("zone listing %d is error", status), func(t *testing.T) {
			t.Parallel()
			f := newDNSProbeFixture(t, dnsProbeConfig{
				zonesErr: dnsListError(status),
				objects:  []client.Object{newTunnel()},
			})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if result != observability.SweepResultError || err == nil || items != nil {
				t.Fatalf("RunTargetOnce = (%v, %q, %v), want error", items, result, err)
			}
			requireDNSCalls(t, f.api)
		})
	}

	t.Run("tunnel list failure is error before any DNS listing", func(t *testing.T) {
		t.Parallel()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones:   []probeZone{{id: "zone-a"}},
			listErr: errors.New("kube api unavailable"),
			objects: []client.Object{newTunnel()},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultError || err == nil || items != nil {
			t.Fatalf("RunTargetOnce = (%v, %q, %v), want error", items, result, err)
		}
		requireDNSCalls(t, f.api)
	})

	t.Run("cluster id failure is error", func(t *testing.T) {
		t.Parallel()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones:             []probeZone{{id: "zone-a"}},
			withoutKubeSystem: true,
			objects:           []client.Object{newTunnel()},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultError || err == nil || items != nil {
			t.Fatalf("RunTargetOnce = (%v, %q, %v), want error", items, result, err)
		}
	})
}

// QA-13: only the typed scoped error may carry safe items. A single-scope
// target returning items alongside generic errIncompleteListing gets them
// discarded — the partial contract stays nil-items for everything else.
func TestRunTargetDiscardsUnsafePartialItems(t *testing.T) {
	t.Parallel()
	invalidator := &recordingInvalidator{}
	events := make(chan event.GenericEvent, 4)
	as := NewAccountSweeper(AccountSweeperOptions{
		Logger:      logr.Discard(),
		Invalidator: invalidator,
		Events:      events,
	})
	target := TargetDescriptor{
		Kind: "CloudflareTunnel",
		SweepFunc: func(context.Context, *AccountSweeper) ([]DriftItem, error) {
			return []DriftItem{{
				Kind: "CloudflareTunnel", TargetKind: "CloudflareTunnel",
				NamespacedName: types.NamespacedName{Namespace: "ns", Name: "gw"},
				RemoteID:       "tun-1", Case: DriftCaseMissing,
			}}, errIncompleteListing
		},
	}
	as.runTarget(context.Background(), target)
	if got := invalidator.count(); got != 0 {
		t.Fatalf("invalidations = %d, want 0 for unsafe partial items", got)
	}
	if got := len(events); got != 0 {
		t.Fatalf("events = %d, want 0 for unsafe partial items", got)
	}
}

// QA-14: grant revocation is metamorphic — the sweep never consults account
// grants, so identical remote/local state must produce identical findings
// whether the namespace grant exists or was revoked.
func TestDNSSweepGrantRevocationKeepsFindings(t *testing.T) {
	t.Parallel()
	marker := probeMarker("gw")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-a", marker)
	drifted := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "app.example.com",
		Content: "192.0.2.9", Comment: marker,
	}
	account := func(grants []v1alpha1.CloudflareAccountGrant) *v1alpha1.CloudflareAccount {
		return &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: probeAccountName},
			Spec:       v1alpha1.CloudflareAccountSpec{AccountID: "account-1", Grants: grants},
		}
	}
	sweep := func(t *testing.T, account *v1alpha1.CloudflareAccount) ([]DriftItem, string, *dnsProbeFixture) {
		t.Helper()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones:   []probeZone{{id: "zone-a", records: []flarecloudflare.DNSRecord{drifted}}},
			objects: []client.Object{account, probeTunnel("gw", checkpoint)},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if err != nil {
			t.Fatalf("RunTargetOnce err = %v", err)
		}
		f.sweeper.runTarget(context.Background(), dnsTarget())
		return items, result, f
	}
	granted := account([]v1alpha1.CloudflareAccountGrant{{
		Hostnames: []string{"*"}, Zones: []string{"*"},
	}})
	revoked := account(nil)

	itemsGranted, resultGranted, fGranted := sweep(t, granted)
	itemsRevoked, resultRevoked, fRevoked := sweep(t, revoked)

	want := DriftItem{
		Case: DriftCaseMismatch, RemoteID: "rec-1",
		TargetKind: "CloudflareTunnel", NamespacedName: types.NamespacedName{Namespace: "ns", Name: "gw"},
	}
	requireItems(t, itemsGranted, want)
	requireItems(t, itemsRevoked, want)
	if resultGranted != observability.SweepResultOK || resultRevoked != resultGranted {
		t.Fatalf("results = %q / %q, want identical ok", resultGranted, resultRevoked)
	}
	requireDispatch(t, fGranted, 1, 1)
	requireDispatch(t, fRevoked, 1, 1)
}

// QA-15: same metamorphic pair with the checkpoint's zone denied — identical
// empty findings and partial result, and the sweep performs no Kubernetes
// writes at all (the fake client fails any mutating call).
func TestDNSSweepGrantRevocationDeniedZone(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-a", probeMarker("gw"))
	account := func(grants []v1alpha1.CloudflareAccountGrant) *v1alpha1.CloudflareAccount {
		return &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: probeAccountName},
			Spec:       v1alpha1.CloudflareAccountSpec{AccountID: "account-1", Grants: grants},
		}
	}
	sweep := func(t *testing.T, account *v1alpha1.CloudflareAccount) ([]DriftItem, string, *dnsProbeFixture) {
		t.Helper()
		tunnel := probeTunnel("gw", checkpoint)
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones:        []probeZone{{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)}},
			objects:      []client.Object{account, tunnel},
			forbidWrites: true,
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultPartial {
			t.Fatalf("result = %q, want partial (err=%v)", result, err)
		}
		requireScopedFailures(t, err, causeA)
		f.sweeper.runTarget(context.Background(), dnsTarget())

		current := &v1alpha1.CloudflareTunnel{}
		if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), current); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(current.Status.DNSRecords, tunnel.Status.DNSRecords) {
			t.Fatalf("checkpoint mutated: %#v -> %#v", tunnel.Status.DNSRecords, current.Status.DNSRecords)
		}
		return items, result, f
	}
	granted := account([]v1alpha1.CloudflareAccountGrant{{
		Hostnames: []string{"*"}, Zones: []string{"*"},
	}})
	revoked := account(nil)

	itemsGranted, resultGranted, fGranted := sweep(t, granted)
	itemsRevoked, resultRevoked, fRevoked := sweep(t, revoked)

	if len(itemsGranted) != 0 || len(itemsRevoked) != 0 {
		t.Fatalf("items = %#v / %#v, want none for a denied zone", itemsGranted, itemsRevoked)
	}
	if resultGranted != resultRevoked {
		t.Fatalf("results = %q / %q, want identical", resultGranted, resultRevoked)
	}
	requireDispatch(t, fGranted, 0, 0)
	requireDispatch(t, fRevoked, 0, 0)
}

// QA-16: tunnels outside this sweep's authority are never judged, whatever
// the zone health.
func TestDNSSweepTunnelExclusions(t *testing.T) {
	t.Parallel()
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-a", probeMarker("gw"))
	causeA := errors.New("zone-a denied")
	deletingNow := metav1.Now()
	cases := []struct {
		name       string
		mutate     func(tunnel *v1alpha1.CloudflareTunnel)
		zoneErr    error
		wantResult string
	}{
		{"observe only", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		}, nil, observability.SweepResultOK},
		{"deleting", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Finalizers = []string{"flareway.io/test-finalizer"}
			tunnel.DeletionTimestamp = &deletingNow
		}, nil, observability.SweepResultOK},
		{"foreign account", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Spec.AccountRef.Name = "other-account"
		}, nil, observability.SweepResultOK},
		{"foreign account on denied zone", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Spec.AccountRef.Name = "other-account"
		}, deniedZoneError(causeA, http.StatusForbidden), observability.SweepResultPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tunnel := probeTunnel("gw", checkpoint)
			tc.mutate(tunnel)
			f := newDNSProbeFixture(t, dnsProbeConfig{
				zones:   []probeZone{{id: "zone-a", err: tc.zoneErr}},
				objects: []client.Object{tunnel},
			})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if result != tc.wantResult {
				t.Fatalf("result = %q, want %q (err=%v)", result, tc.wantResult, err)
			}
			if len(items) != 0 {
				t.Fatalf("items = %#v, want none for an excluded tunnel", items)
			}
		})
	}
}

// QA-17(a): a checkpoint whose zone left the account inventory is skipped —
// never a false missing.
func TestDNSSweepCheckpointZoneAbsent(t *testing.T) {
	t.Parallel()
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-gone", "zone-gone", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones:   []probeZone{{id: "zone-a"}},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultOK || err != nil {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
	}
	if len(items) != 0 {
		t.Fatalf("items = %#v, want none for a zone that left the account", items)
	}
	requireDNSCalls(t, f.api, "zone-a")
}

// QA-17(b): an account with no zones is a complete empty listing — ok, not
// partial.
func TestDNSSweepNoZones(t *testing.T) {
	t.Parallel()
	f := newDNSProbeFixture(t, dnsProbeConfig{
		objects: []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "rec-1", "zone-a", probeMarker("gw")))},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultOK || err != nil {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
	}
	if items == nil || len(items) != 0 {
		t.Fatalf("items = %#v, want an empty non-nil slice", items)
	}
	requireDNSCalls(t, f.api)
}

// QA-18(a): a pass after a partial recovers fully — result returns to ok,
// findings dispatch, and last-success advances again. SERIAL: reads the
// process-global metrics registry.
func TestDNSSweepRecoveryAfterPartial(t *testing.T) {
	causeA := errors.New("zone-a denied")
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-b", "zone-b", probeMarker("gw"))
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)},
			{id: "zone-b"},
		},
		objects: []client.Object{probeTunnel("gw", checkpoint)},
	})
	lastBefore := sweepLastSuccess(t, "DNSRecord")

	_, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("first pass result = %q, want partial (err=%v)", result, err)
	}
	if got := sweepLastSuccess(t, "DNSRecord"); got != lastBefore {
		t.Fatalf("last-success advanced on a partial pass: %v -> %v", lastBefore, got)
	}

	f.api.setZoneErr("zone-a", nil)
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultOK || err != nil {
		t.Fatalf("second pass = (%v, %q, %v), want ok", items, result, err)
	}
	requireItems(t, items, missingItem("rec-b", "gw"))
	if got := sweepLastSuccess(t, "DNSRecord"); got <= lastBefore {
		t.Fatalf("last-success did not advance on recovery: %v -> %v", lastBefore, got)
	}

	f.sweeper.runTarget(context.Background(), dnsTarget())
	requireDispatch(t, f, 1, 1)
}

// QA-18(b): a saturated event buffer drops the wakeup but never the
// invalidation latch, and the next pass re-emits while drift persists.
// The real freshness.Latch asserts the gate actually stays closed — a
// counting invalidator would only prove Invalidate was invoked.
func TestRunTargetEventBufferFullKeepsLatch(t *testing.T) {
	t.Parallel()
	latch := freshness.NewLatch()
	events := make(chan event.GenericEvent, 1)
	events <- event.GenericEvent{Object: &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sentinel"},
	}}
	as := NewAccountSweeper(AccountSweeperOptions{
		Logger:      logr.Discard(),
		Invalidator: latch,
		Events:      events,
	})
	key := types.NamespacedName{Namespace: "ns", Name: "gw"}
	target := TargetDescriptor{
		Kind: "CloudflareTunnel",
		SweepFunc: func(context.Context, *AccountSweeper) ([]DriftItem, error) {
			return []DriftItem{{
				Kind: "CloudflareTunnel", TargetKind: "CloudflareTunnel",
				NamespacedName: key, RemoteID: "tun-1", Case: DriftCaseMissing,
			}}, nil
		},
	}
	as.runTarget(context.Background(), target)
	if !latch.IsInvalidated("CloudflareTunnel", key) {
		t.Fatal("latch must stay closed even when the event drops")
	}
	if got := len(events); got != 1 {
		t.Fatalf("events = %d, want 1: the drift event must drop on a full buffer", got)
	}
	if drained := (<-events).Object.GetName(); drained != "sentinel" {
		t.Fatalf("drained event = %q, want the sentinel (drift event was dropped)", drained)
	}

	as.runTarget(context.Background(), target)
	if !latch.IsInvalidated("CloudflareTunnel", key) {
		t.Fatal("latch must still be closed after the re-emission pass")
	}
	select {
	case emitted := <-events:
		if emitted.Object.GetName() != "gw" {
			t.Fatalf("re-emitted event object = %q, want gw", emitted.Object.GetName())
		}
	default:
		t.Fatal("drift event was not re-emitted on the next pass")
	}
}
