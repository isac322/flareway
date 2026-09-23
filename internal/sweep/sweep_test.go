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
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/observability"
)

func TestInitialDelayBounds(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	for _, ttl := range []time.Duration{time.Nanosecond, 4 * time.Second, 60 * time.Second, 300 * time.Second, time.Hour} {
		for i := 0; i < 2000; i++ {
			got := initialDelay(ttl, rng)
			bound := ttl
			if bound > time.Minute {
				bound = time.Minute
			}
			if got < 0 || got >= bound {
				t.Fatalf("initialDelay(%s) = %s, want [0, %s)", ttl, got, bound)
			}
		}
	}
	// A TTL so small the bound collapses must return 0, never panic.
	if got := initialDelay(time.Nanosecond, rng); got != 0 {
		t.Fatalf("initialDelay(1ns) = %s, want 0", got)
	}
}

func TestJitteredIntervalBounds(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(3, 4))
	for _, ttl := range []time.Duration{4 * time.Second, 60 * time.Second, 300 * time.Second, time.Hour} {
		for i := 0; i < 2000; i++ {
			got := jitteredInterval(ttl, rng)
			if got < ttl || got >= ttl+ttl/5 {
				t.Fatalf("jitteredInterval(%s) = %s, want [%s, %s)", ttl, got, ttl, ttl+ttl/5)
			}
		}
	}
	// ttl/5 == 0 must not panic and must return the base interval.
	for _, ttl := range []time.Duration{time.Nanosecond, 4 * time.Nanosecond} {
		if got := jitteredInterval(ttl, rng); got != ttl {
			t.Fatalf("jitteredInterval(%s) = %s, want %s", ttl, got, ttl)
		}
	}
}

type classifyRemote struct {
	id   string
	name string
}

func classifyTestOptions() classifyOptions[classifyRemote] {
	return classifyOptions[classifyRemote]{
		kind:   "Widget",
		idOf:   func(r classifyRemote) string { return r.id },
		listed: func(localRef) bool { return true },
		nameOf: func(r classifyRemote) string { return r.name },
	}
}

func TestClassifyMissing(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	items := classify(refs, []classifyRemote{}, classifyTestOptions())
	if len(items) != 1 || items[0].Case != DriftCaseMissing || items[0].RemoteID != "r1" {
		t.Fatalf("classify() = %#v, want one missing item for r1", items)
	}
	if items[0].TargetKind != "Widget" || items[0].NamespacedName.Name != "a" {
		t.Fatalf("missing item target = %#v", items[0])
	}
}

func TestClassifyMismatch(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	items := classify(refs, []classifyRemote{{id: "r1", name: "renamed"}}, classifyTestOptions())
	if len(items) != 1 || items[0].Case != DriftCaseMismatch {
		t.Fatalf("classify() = %#v, want one mismatch item", items)
	}
}

func TestClassifySkipsUnlistedScope(t *testing.T) {
	t.Parallel()
	opts := classifyTestOptions()
	opts.listed = func(ref localRef) bool { return ref.scope == "" }
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", scope: "zone-9",
	}}
	items := classify(refs, []classifyRemote{}, opts)
	if len(items) != 0 {
		t.Fatalf("classify() = %#v, want no items for an unlisted scope", items)
	}
}

func TestClassifyNoRemoteIDNoJudgement(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
	}}
	items := classify(refs, []classifyRemote{}, classifyTestOptions())
	if len(items) != 0 {
		t.Fatalf("classify() = %#v, want no items for unconverged ref", items)
	}
}

func TestClassifyOrphan(t *testing.T) {
	t.Parallel()
	opts := classifyTestOptions()
	opts.orphan = func(remote classifyRemote, _ map[string]bool) (types.NamespacedName, bool) {
		return types.NamespacedName{Namespace: "ns", Name: "ghost"}, remote.name == "ours"
	}
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	remotes := []classifyRemote{{id: "r1", name: "w-a"}, {id: "r2", name: "ours"}, {id: "r3", name: "foreign"}}
	items := classify(refs, remotes, opts)
	if len(items) != 1 || items[0].Case != DriftCaseOrphan || items[0].RemoteID != "r2" {
		t.Fatalf("classify() = %#v, want one orphan item for r2", items)
	}
}

func TestListFailureClassification(t *testing.T) {
	t.Parallel()
	generic := errors.New("connection reset")
	if got := listFailure(generic); !errors.Is(got, errIncompleteListing) {
		t.Fatalf("listFailure(generic) = %v, want errIncompleteListing", got)
	}
	forbidden := &cloudflaresdk.Error{StatusCode: 403}
	if got := listFailure(forbidden); got != forbidden {
		t.Fatalf("listFailure(403) = %v, want the raw error", got)
	}
	if got := listFailure(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Fatalf("listFailure(canceled) = %v, want context.Canceled", got)
	}
	if got := listFailure(nil); got != nil {
		t.Fatalf("listFailure(nil) = %v, want nil", got)
	}
}

// TestZoneFailureIsolation covers the per-zone classifier used by
// sweepDNSRecords: only HTTP 403/404, zone-local 5xx, and transport errors
// (no decodable status) are isolated per zone; context errors, 429, 401,
// every other 4xx, and client-side pacing failures (ErrRateLimitWait) abort
// the whole pass (QA-10/QA-11).
func TestZoneFailureIsolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"403 forbidden", dnsListError(403), true},
		{"404 not found", dnsListError(404), true},
		{"500 internal", dnsListError(500), true},
		{"503 unavailable", dnsListError(503), true},
		{"transport error", transportZoneError(errors.New("connection reset")), true},
		{"bare transport error", errors.New("connection reset"), true},
		{"context canceled", context.Canceled, false},
		{"wrapped canceled", fmt.Errorf("zone list: %w", context.Canceled), false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped deadline", fmt.Errorf("zone list: %w", context.DeadlineExceeded), false},
		{"rate limit wait", fmt.Errorf("zone list: %w: %w", flarecloudflare.ErrRateLimitWait, errors.New("would exceed context deadline")), false},
		{"rate limit wait canceled", fmt.Errorf("zone list: %w: %w", flarecloudflare.ErrRateLimitWait, context.Canceled), false},
		{"401 unauthorized", dnsListError(401), false},
		{"429 rate limited", dnsListError(429), false},
		{"400 bad request", dnsListError(400), false},
		{"409 conflict", dnsListError(409), false},
		{"422 unprocessable", dnsListError(422), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := zoneFailureIsolatable(tc.err); got != tc.want {
				t.Fatalf("zoneFailureIsolatable(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestRunTargetOnceResultMapping(t *testing.T) {
	t.Parallel()
	as := NewAccountSweeper(AccountSweeperOptions{Logger: logr.Discard()})
	ctx := context.Background()

	cases := []struct {
		name         string
		items        []DriftItem
		err          error
		wantResult   string
		wantErr      bool
		wantItemsNil bool
		wantItemsLen int
	}{
		{name: "complete listing", items: []DriftItem{}, wantResult: observability.SweepResultOK},
		{name: "nil items is partial", items: nil, wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "incomplete listing error is partial", err: errIncompleteListing, wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "wrapped incomplete listing is partial", err: fmt.Errorf("list: %w", errIncompleteListing), wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "definitive error", err: errors.New("403 forbidden"), wantResult: observability.SweepResultError, wantErr: true, wantItemsNil: true},
		// QA-10(b): a deadline exceeded reaches the generic error branch —
		// the existing asymmetry with context.Canceled is deliberate.
		{name: "deadline exceeded is error", err: context.DeadlineExceeded, wantResult: observability.SweepResultError, wantErr: true, wantItemsNil: true},
		// QA-13: items returned with a generic incomplete-listing error are
		// unsafe and must be discarded; only the typed scoped error may
		// carry safe items.
		{name: "unsafe items on generic partial are discarded",
			items: []DriftItem{{Case: DriftCaseMissing, RemoteID: "r1"}}, err: errIncompleteListing,
			wantResult: observability.SweepResultPartial, wantItemsNil: true},
		// Scoped partial: the typed aggregate carries the safe items through.
		{name: "scoped listing error carries safe items",
			items: []DriftItem{{Case: DriftCaseMissing, RemoteID: "r1"}},
			err: &scopedListingError{failures: []error{
				&zoneFailure{zoneID: "zone-a", err: errors.New("denied")},
			}},
			wantResult: observability.SweepResultPartial, wantErr: true, wantItemsLen: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := TargetDescriptor{
				Kind: "Widget",
				SweepFunc: func(context.Context, *AccountSweeper) ([]DriftItem, error) {
					return tc.items, tc.err
				},
			}
			got, result, err := as.RunTargetOnce(ctx, target)
			if result != tc.wantResult {
				t.Fatalf("RunTargetOnce result = %q, want %q", result, tc.wantResult)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("RunTargetOnce err = %v, wantErr %t", err, tc.wantErr)
			}
			if (got == nil) != tc.wantItemsNil {
				t.Fatalf("RunTargetOnce items = %#v, wantItemsNil %t", got, tc.wantItemsNil)
			}
			if tc.wantItemsLen > 0 && len(got) != tc.wantItemsLen {
				t.Fatalf("RunTargetOnce items = %#v, want %d item(s)", got, tc.wantItemsLen)
			}
		})
	}
}

func TestParseAccessRemoteName(t *testing.T) {
	t.Parallel()
	cluster, ns, name, ok := parseAccessRemoteName("flareway/cluster-1/team-a/some spec name")
	if !ok || cluster != "cluster-1" || ns != "team-a" || name != "some spec name" {
		t.Fatalf("parseAccessRemoteName = %q %q %q %t", cluster, ns, name, ok)
	}
	if _, _, _, ok := parseAccessRemoteName("other/cluster-1/a/b"); ok {
		t.Fatal("non-flareway name parsed")
	}
	if _, _, _, ok := parseAccessRemoteName("flareway/cluster-1/only-two"); ok {
		t.Fatal("two-segment name parsed")
	}
}

func TestParsePrivateOwnerComment(t *testing.T) {
	t.Parallel()
	cluster, ns, name, ok := parsePrivateOwnerComment("flareway cluster-1/team-a/widget | human note")
	if !ok || cluster != "cluster-1" || ns != "team-a" || name != "widget" {
		t.Fatalf("parsePrivateOwnerComment = %q %q %q %t", cluster, ns, name, ok)
	}
	if _, _, _, ok := parsePrivateOwnerComment("flareway hmac:0123456789abcdef0123456789abcdef ns/name"); ok {
		t.Fatal("hmac marker parsed as legacy")
	}
	if _, _, _, ok := parsePrivateOwnerComment("flareway sha256:0123456789abcdef0123456789abcdef"); ok {
		t.Fatal("sha256 marker parsed as legacy")
	}
	if _, _, _, ok := parsePrivateOwnerComment("unrelated comment"); ok {
		t.Fatal("foreign comment parsed")
	}
}

func TestParseTunnelTarget(t *testing.T) {
	t.Parallel()
	id, ok := parseTunnelTarget("abc123.cfargotunnel.com")
	if !ok || id != "abc123" {
		t.Fatalf("parseTunnelTarget = %q %t", id, ok)
	}
	if _, ok := parseTunnelTarget("203.0.113.9"); ok {
		t.Fatal("IP content parsed as tunnel target")
	}
	if _, ok := parseTunnelTarget(""); ok {
		t.Fatal("empty content parsed")
	}
}

func TestDNSOrphanCandidate(t *testing.T) {
	t.Parallel()
	markers := []string{"flareway cluster-1/ns/gw"}
	tunnel := dnsTunnelInfo{
		key:      types.NamespacedName{Namespace: "ns", Name: "gw"},
		tunnelID: "tid-1",
		markers:  markers,
	}
	// Marker + matching tunnel target: orphan candidate.
	candidate := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "ghost.example.com",
		Content: "tid-1.cfargotunnel.com", Comment: "flareway cluster-1/ns/gw",
	}
	item, ok := dnsOrphanCandidate(candidate, []dnsTunnelInfo{tunnel})
	if !ok || item.Case != DriftCaseOrphan || item.NamespacedName != tunnel.key {
		t.Fatalf("dnsOrphanCandidate = %#v %t", item, ok)
	}
	// Marker but foreign target (forged marker on a foreign record): not a
	// candidate — the content check must reject it.
	forged := candidate
	forged.Content = "other.cfargotunnel.com"
	if _, ok := dnsOrphanCandidate(forged, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("forged-target record accepted as orphan")
	}
	// Marker but not a CNAME (the QA-017 forged A record): not a candidate.
	forgedType := candidate
	forgedType.Type = "A"
	forgedType.Content = "203.0.113.9"
	if _, ok := dnsOrphanCandidate(forgedType, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("forged A record accepted as orphan")
	}
	// Unknown tunnel ID: never owned, never a candidate (C14#3).
	noID := tunnel
	noID.tunnelID = ""
	if _, ok := dnsOrphanCandidate(candidate, []dnsTunnelInfo{noID}); ok {
		t.Fatal("record accepted as orphan without a tunnel target")
	}
	// No marker: foreign record, not a candidate.
	foreign := candidate
	foreign.Comment = "someone else's record"
	if _, ok := dnsOrphanCandidate(foreign, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("foreign record accepted as orphan")
	}
}

func TestDNSMismatchReason(t *testing.T) {
	t.Parallel()
	tunnel := dnsTunnelInfo{
		key:      types.NamespacedName{Namespace: "ns", Name: "gw"},
		tunnelID: "tid-1",
		markers:  []string{"flareway cluster-1/ns/gw"},
	}
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-1", "flareway cluster-1/ns/gw")
	remote := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "app.example.com",
		Content: "tid-1.cfargotunnel.com", Comment: "flareway cluster-1/ns/gw",
	}
	if reason := dnsMismatchReason(tunnel, checkpoint, remote); reason != "" {
		t.Fatalf("matching record reported mismatch: %q", reason)
	}
	// Content drift (QA-015): CNAME target changed out-of-band.
	drifted := remote
	drifted.Content = "192.0.2.1"
	if reason := dnsMismatchReason(tunnel, checkpoint, drifted); reason == "" {
		t.Fatal("content drift not reported")
	}
	// Type swap with forged marker (QA-017): the strict check must reject.
	forged := remote
	forged.Type = "A"
	forged.Content = "203.0.113.9"
	if reason := dnsMismatchReason(tunnel, checkpoint, forged); reason == "" {
		t.Fatal("forged A record not reported")
	}
	// Unknown tunnel ID: the content check is impossible, so no verdict is
	// returned — never "owned by default" and never a false mismatch (C14#3).
	noID := tunnel
	noID.tunnelID = ""
	if reason := dnsMismatchReason(noID, checkpoint, drifted); reason != "" {
		t.Fatalf("expected no verdict without tunnel ID, got %q", reason)
	}
	commentDrift := remote
	commentDrift.Comment = "attacker note"
	if reason := dnsMismatchReason(tunnel, checkpoint, commentDrift); reason == "" {
		t.Fatal("comment drift not reported")
	}
}

// v1alpha1Checkpoint builds a DNS checkpoint status entry for tests.
func v1alpha1Checkpoint(hostname, recordID, zoneID, comment string) v1alpha1.CloudflareTunnelDNSRecordStatus {
	return v1alpha1.CloudflareTunnelDNSRecordStatus{
		Hostname:         hostname,
		RecordID:         recordID,
		ZoneID:           zoneID,
		OwnershipComment: comment,
	}
}
