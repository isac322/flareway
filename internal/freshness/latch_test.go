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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

func TestLatchCompleteVerificationRespectsInvalidationEpoch(t *testing.T) {
	latch := NewLatch()
	key := types.NamespacedName{Namespace: "tenant", Name: "obj"}
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	if got := latch.InvalidationEpoch("VirtualNetwork", key); got != 0 {
		t.Fatalf("initial InvalidationEpoch = %d, want 0", got)
	}

	// Capture epoch 0 before a concurrent sweep invalidates the key.
	latch.Invalidate("VirtualNetwork", key, "sweep-drift-1")
	epoch1 := latch.InvalidationEpoch("VirtualNetwork", key)
	if epoch1 == 0 {
		t.Fatalf("expected non-zero epoch after Invalidate, got %d", epoch1)
	}

	// Stale epoch 0 must NOT clear the latch or record verification/baseline.
	if latch.CompleteVerification("VirtualNetwork", key, 0, "h1", now, func(any) bool { return true }) {
		t.Fatal("CompleteVerification returned true for stale epoch 0")
	}
	if !latch.IsInvalidated("VirtualNetwork", key) {
		t.Fatal("stale CompleteVerification cleared invalidation latch")
	}
	if _, ok := latch.VerifiedAt("VirtualNetwork", key, "h1"); ok {
		t.Fatal("stale CompleteVerification recorded VerifiedAt")
	}
	if latch.ConfirmContent("VirtualNetwork", key, "obs", now) {
		t.Fatal("ConfirmContent reported drift without baseline")
	}
	if _, ok := latch.ConfirmedAt("VirtualNetwork", key, "h1"); ok {
		t.Fatal("stale CompleteVerification recorded baseline/ConfirmedAt")
	}

	// Capture epoch1, then invalidate again before completion arrives.
	latch.Invalidate("VirtualNetwork", key, "sweep-drift-2")
	epoch2 := latch.InvalidationEpoch("VirtualNetwork", key)
	if epoch2 <= epoch1 {
		t.Fatalf("expected strictly increasing epoch (%d <= %d)", epoch2, epoch1)
	}
	if latch.CompleteVerification("VirtualNetwork", key, epoch1, "h1", now, func(any) bool { return true }) {
		t.Fatal("CompleteVerification returned true for superseded epoch1")
	}
	if !latch.IsInvalidated("VirtualNetwork", key) {
		t.Fatal("superseded CompleteVerification cleared invalidation latch")
	}

	// Matching latest epoch2 clears invalidation, stamps VerifiedAt, and stores baseline.
	if !latch.CompleteVerification("VirtualNetwork", key, epoch2, "h1", now, func(v any) bool { return v == "good" }) {
		t.Fatal("CompleteVerification returned false for matching epoch2")
	}
	if latch.IsInvalidated("VirtualNetwork", key) {
		t.Fatal("matching CompleteVerification left invalidation latch set")
	}
	if got, ok := latch.VerifiedAt("VirtualNetwork", key, "h1"); !ok || !got.Equal(now) {
		t.Fatalf("VerifiedAt = (%v, %v), want (%v, true)", got, ok, now)
	}
	if drift := latch.ConfirmContent("VirtualNetwork", key, "good", now.Add(time.Second)); drift {
		t.Fatal("ConfirmContent reported drift for matching baseline")
	}
	if _, ok := latch.ConfirmedAt("VirtualNetwork", key, "h1"); !ok {
		t.Fatal("expected ConfirmedAt after matching baseline confirmation")
	}

	// Remove + recreate + re-invalidate must produce a strictly newer epoch so
	// an old epoch2 captured prior to deletion can never clear a new invalidation.
	latch.Remove("VirtualNetwork", key)
	latch.Invalidate("VirtualNetwork", key, "recreated-drift")
	epoch3 := latch.InvalidationEpoch("VirtualNetwork", key)
	if epoch3 <= epoch2 {
		t.Fatalf("post-Remove Invalidate epoch = %d, want > %d", epoch3, epoch2)
	}
	if latch.CompleteVerification("VirtualNetwork", key, epoch2, "h1", now.Add(2*time.Second), nil) {
		t.Fatal("pre-Remove epoch2 matched post-Remove invalidation")
	}
	if !latch.IsInvalidated("VirtualNetwork", key) {
		t.Fatal("pre-Remove epoch2 cleared post-Remove invalidation")
	}
}
