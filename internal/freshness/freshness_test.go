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

package freshness

import (
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// invalidatorShape mirrors the sweep.Invalidator contract
// (00-architecture.md §5). Latch must satisfy it structurally; the sweep
// package cannot be imported here without an import cycle.
type invalidatorShape interface {
	Invalidate(kind string, key types.NamespacedName, reason string)
	IsInvalidated(kind string, key types.NamespacedName) bool
	Clear(kind string, key types.NamespacedName)
}

var _ invalidatorShape = (*Latch)(nil)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("DefaultPolicy().Validate() = %v, want nil", err)
	}
	if p.Authz != 60*time.Second || p.Traffic != 300*time.Second || p.Indirect != 1800*time.Second || p.Display != 0 {
		t.Fatalf("DefaultPolicy() = %+v, want 60s/300s/1800s/0", p)
	}
}

func TestPolicyTTL(t *testing.T) {
	p := Policy{Authz: time.Second, Traffic: 2 * time.Second, Indirect: 3 * time.Second, Display: 4 * time.Second}
	cases := []struct {
		grade Grade
		want  time.Duration
	}{
		{GradeAlways, 0},
		{GradeAuthz, time.Second},
		{GradeTraffic, 2 * time.Second},
		{GradeIndirect, 3 * time.Second},
		{GradeDisplay, 4 * time.Second},
		{Grade(99), 0}, // unknown grades fail closed
	}
	for _, tc := range cases {
		if got := p.TTL(tc.grade); got != tc.want {
			t.Errorf("TTL(%v) = %v, want %v", tc.grade, got, tc.want)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{"default", DefaultPolicy(), false},
		{"all zero is valid (everything on-demand)", Policy{}, false},
		{"negative authz", Policy{Authz: -time.Second}, true},
		{"negative traffic", Policy{Traffic: -time.Second}, true},
		{"negative indirect", Policy{Indirect: -time.Second}, true},
		{"negative display", Policy{Display: -time.Second}, true},
		{"authz > traffic", Policy{Authz: 100 * time.Second, Traffic: 50 * time.Second}, true},
		{"traffic > indirect", Policy{Traffic: 100 * time.Second, Indirect: 50 * time.Second}, true},
		{"authz > indirect", Policy{Authz: 100 * time.Second, Indirect: 50 * time.Second}, true},
		{"zero authz exempt from ordering", Policy{Authz: 0, Traffic: time.Second}, false},
		{"zero indirect exempt from ordering", Policy{Authz: time.Second, Traffic: 2 * time.Second, Indirect: 0}, false},
		{"equal boundaries allowed", Policy{Authz: time.Second, Traffic: time.Second, Indirect: time.Second}, false},
	}
	for _, tc := range cases {
		err := tc.policy.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() = %v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestEvaluate(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1_000_000, 0)
	applied := now.Add(-10 * time.Second)

	cases := []struct {
		name         string
		grade        Grade
		appliedHash  string
		desiredHash  string
		appliedAt    time.Time
		now          time.Time
		invalidated  bool
		wantOpen     bool
		wantRequeue  time.Duration
		wantDecision Decision
	}{
		{
			name:         "T0 is never gated even with a perfect stamp",
			grade:        GradeAlways,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionNotGated,
		},
		{
			name:         "T4 zero TTL is on-demand",
			grade:        GradeDisplay,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "invalidated latch closes despite fresh matching hash",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			invalidated:  true,
			wantOpen:     false,
			wantDecision: DecisionClosedInvalidated,
		},
		{
			name:         "empty appliedHash",
			grade:        GradeAuthz,
			appliedHash:  "",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedHash,
		},
		{
			name:         "empty desiredHash",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedHash,
		},
		{
			name:         "hash mismatch",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "def",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedHash,
		},
		{
			name:         "zero appliedAt means never applied (C11)",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    time.Time{},
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "age exactly at TTL is expired",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    now.Add(-p.Authz),
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "age beyond TTL is expired",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    now.Add(-p.Authz - time.Second),
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "appliedAt in the future (clock skew) fails closed",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    now.Add(time.Second),
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "fresh matching hash opens with self-expiry requeue",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			wantOpen:     true,
			wantRequeue:  p.Authz - 10*time.Second,
			wantDecision: DecisionOpen,
		},
		{
			name:         "one nanosecond before expiry still opens with positive requeue",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    now.Add(-p.Authz + time.Nanosecond),
			now:          now,
			wantOpen:     true,
			wantRequeue:  time.Nanosecond,
			wantDecision: DecisionOpen,
		},
		{
			name:         "unknown grade fails closed",
			grade:        Grade(42),
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
		{
			name:         "invalidated wins over hash mismatch",
			grade:        GradeAuthz,
			appliedHash:  "abc",
			desiredHash:  "def",
			appliedAt:    applied,
			now:          now,
			invalidated:  true,
			wantOpen:     false,
			wantDecision: DecisionClosedInvalidated,
		},
		{
			name:         "zero TTL wins over invalidation",
			grade:        GradeDisplay,
			appliedHash:  "abc",
			desiredHash:  "abc",
			appliedAt:    applied,
			now:          now,
			invalidated:  true,
			wantOpen:     false,
			wantDecision: DecisionClosedTTL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := p.Evaluate(tc.grade, tc.appliedHash, tc.desiredHash, tc.appliedAt, tc.now, tc.invalidated)
			if gate.Open != tc.wantOpen {
				t.Errorf("Open = %v, want %v", gate.Open, tc.wantOpen)
			}
			if gate.Requeue != tc.wantRequeue {
				t.Errorf("Requeue = %v, want %v", gate.Requeue, tc.wantRequeue)
			}
			if gate.Decision != tc.wantDecision {
				t.Errorf("Decision = %q, want %q", gate.Decision, tc.wantDecision)
			}
			if gate.Open && gate.Requeue <= 0 {
				t.Errorf("open gate must carry a positive requeue, got %v", gate.Requeue)
			}
		})
	}
}

func TestDesiredHashDeterministic(t *testing.T) {
	spec := map[string]any{
		"name":    "example",
		"comment": "managed by flareway",
		"nested":  map[string]any{"b": 2, "a": 1},
		"list":    []any{"x", "y"},
	}
	input := HashEnvelope{
		Spec:      spec,
		UID:       types.UID("uid-1"),
		RemoteID:  "remote-1",
		AccountID: "acct-1",
		ClusterID: "cluster-1",
	}

	first, err := DesiredHash(input)
	if err != nil {
		t.Fatalf("DesiredHash() error = %v", err)
	}
	if len(first) != 64 {
		t.Fatalf("DesiredHash() = %q, want 64 hex chars", first)
	}
	for i := 0; i < 1000; i++ {
		got, err := DesiredHash(input)
		if err != nil {
			t.Fatalf("DesiredHash() error = %v", err)
		}
		if got != first {
			t.Fatalf("DesiredHash() not deterministic: %q != %q", got, first)
		}
	}
}

func TestDesiredHashMapKeyOrder(t *testing.T) {
	a := map[string]any{"z": 1, "a": 2, "m": 3}
	b := map[string]any{"m": 3, "z": 1, "a": 2}

	ha, err := DesiredHash(a)
	if err != nil {
		t.Fatalf("DesiredHash() error = %v", err)
	}
	hb, err := DesiredHash(b)
	if err != nil {
		t.Fatalf("DesiredHash() error = %v", err)
	}
	if ha != hb {
		t.Errorf("map key order changed the hash: %q != %q", ha, hb)
	}
}

func TestDesiredHashDistinguishesInputs(t *testing.T) {
	type spec struct {
		Name string `json:"name"`
	}

	nilHash, err := DesiredHash(nil)
	if err != nil {
		t.Fatalf("DesiredHash(nil) error = %v", err)
	}
	emptyHash, err := DesiredHash(spec{})
	if err != nil {
		t.Fatalf("DesiredHash(empty) error = %v", err)
	}
	if nilHash == emptyHash {
		t.Error("nil input and empty value must not share a hash")
	}

	var nilPtr *spec
	nilPtrHash, err := DesiredHash(nilPtr)
	if err != nil {
		t.Fatalf("DesiredHash(typed nil) error = %v", err)
	}
	ptrHash, err := DesiredHash(&spec{})
	if err != nil {
		t.Fatalf("DesiredHash(ptr) error = %v", err)
	}
	if nilPtrHash == ptrHash {
		t.Error("nil pointer and non-nil pointer to empty value must not share a hash")
	}

	base := HashEnvelope{Spec: spec{Name: "a"}, UID: "u", RemoteID: "r", AccountID: "acct", ClusterID: "c"}
	baseHash, err := DesiredHash(base)
	if err != nil {
		t.Fatalf("DesiredHash() error = %v", err)
	}

	variants := map[string]HashEnvelope{
		"spec changed":      {Spec: spec{Name: "b"}, UID: "u", RemoteID: "r", AccountID: "acct", ClusterID: "c"},
		"uid changed":       {Spec: spec{Name: "a"}, UID: "u2", RemoteID: "r", AccountID: "acct", ClusterID: "c"},
		"remoteID changed":  {Spec: spec{Name: "a"}, UID: "u", RemoteID: "r2", AccountID: "acct", ClusterID: "c"},
		"accountID changed": {Spec: spec{Name: "a"}, UID: "u", RemoteID: "r", AccountID: "acct2", ClusterID: "c"},
		"clusterID changed": {Spec: spec{Name: "a"}, UID: "u", RemoteID: "r", AccountID: "acct", ClusterID: "c2"},
	}
	for name, v := range variants {
		h, err := DesiredHash(v)
		if err != nil {
			t.Fatalf("DesiredHash(%s) error = %v", name, err)
		}
		if h == baseHash {
			t.Errorf("%s did not change the hash", name)
		}
	}
}

func TestDesiredHashUnserializable(t *testing.T) {
	if _, err := DesiredHash(func() {}); err == nil {
		t.Error("DesiredHash(func) must return an error")
	}
	if _, err := DesiredHash(make(chan int)); err == nil {
		t.Error("DesiredHash(chan) must return an error")
	}
}

func TestLatch(t *testing.T) {
	l := NewLatch()
	key := types.NamespacedName{Namespace: "ns", Name: "obj"}

	if l.IsInvalidated("AccessPolicy", key) {
		t.Error("fresh latch must not report invalidation")
	}

	l.Invalidate("AccessPolicy", key, "drift")
	if !l.IsInvalidated("AccessPolicy", key) {
		t.Error("IsInvalidated = false after Invalidate")
	}

	// Kind is part of the key: a different kind on the same object is unaffected.
	if l.IsInvalidated("AccessGroup", key) {
		t.Error("invalidation must be scoped to the kind")
	}

	// Repeated invalidation keeps the latest reason.
	l.Invalidate("AccessPolicy", key, "newer-reason")
	if got := l.reasons[latchKey{kind: "AccessPolicy", namespace: "ns", name: "obj"}]; got != "newer-reason" {
		t.Errorf("reason = %q, want latest %q", got, "newer-reason")
	}

	l.Clear("AccessPolicy", key)
	if l.IsInvalidated("AccessPolicy", key) {
		t.Error("IsInvalidated = true after Clear")
	}
}

func TestLatchNilReceiver(t *testing.T) {
	var l *Latch
	key := types.NamespacedName{Namespace: "ns", Name: "obj"}

	// None of these may panic.
	l.Invalidate("AccessPolicy", key, "drift")
	if l.IsInvalidated("AccessPolicy", key) {
		t.Error("nil latch must report no invalidation")
	}
	l.Clear("AccessPolicy", key)
}

func TestLatchConcurrent(*testing.T) {
	l := NewLatch()
	key := types.NamespacedName{Namespace: "ns", Name: "obj"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Invalidate("AccessPolicy", key, "drift")
				l.IsInvalidated("AccessPolicy", key)
				l.Clear("AccessPolicy", key)
			}
		}()
	}
	wg.Wait()
}
