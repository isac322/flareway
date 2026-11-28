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

func TestLatchLifetimeTokenIsolationAndCleanup(t *testing.T) {
	latch := NewLatch()
	keyA := types.NamespacedName{Namespace: "tenant", Name: "edge-a"}
	keyB := types.NamespacedName{Namespace: "tenant", Name: "edge-b"}
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	var nilLatch *Latch
	nilTok := nilLatch.BeginLifetime("CloudflareTunnelConfig", keyA)
	nilLatch.EndLifetime(nilTok)
	if nilLatch.ForgetAndInvalidateIfUnretired(nilTok, "demoted") {
		t.Fatal("nil Latch ForgetAndInvalidateIfUnretired returned true")
	}
	if nilLatch.RemoveIfUntouched(nilTok) {
		t.Fatal("nil Latch RemoveIfUntouched returned true")
	}

	// EndLifetime releases per-key guard map cleanly (0 idle memory).
	tokIdle := latch.BeginLifetime("CloudflareTunnelConfig", keyA)
	if len(latch.activeGuards) != 1 {
		t.Fatalf("activeGuards len = %d after BeginLifetime, want 1", len(latch.activeGuards))
	}
	latch.EndLifetime(tokIdle)
	if len(latch.activeGuards) != 0 {
		t.Fatalf("activeGuards len = %d after EndLifetime, want 0", len(latch.activeGuards))
	}

	// Unrelated-key Remove MUST NOT invalidate or block tokA.
	tokA := latch.BeginLifetime("CloudflareTunnelConfig", keyA)
	defer latch.EndLifetime(tokA)
	latch.MarkVerified("CloudflareTunnelConfig", keyA, "h1", now)
	latch.SetBaseline("CloudflareTunnelConfig", keyA, "h1", func(any) bool { return true })
	latch.Invalidate("CloudflareTunnelConfig", keyB, "other-drift")
	latch.Remove("CloudflareTunnelConfig", keyB)
	if !latch.ForgetAndInvalidateIfUnretired(tokA, "demoted") {
		t.Fatal("ForgetAndInvalidateIfUnretired failed on unrelated-key Remove")
	}
	if !latch.IsInvalidated("CloudflareTunnelConfig", keyA) {
		t.Fatal("expected keyA invalidation latch after ForgetAndInvalidateIfUnretired")
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", keyA, "h1"); ok {
		t.Fatal("expected ForgetAndInvalidateIfUnretired to clear VerifiedAt")
	}

	// Same-key Remove marks in-flight token retired -> ForgetAndInvalidateIfUnretired returns false.
	tokRetired := latch.BeginLifetime("CloudflareTunnelConfig", keyA)
	defer latch.EndLifetime(tokRetired)
	latch.Remove("CloudflareTunnelConfig", keyA)
	if latch.ForgetAndInvalidateIfUnretired(tokRetired, "demoted") {
		t.Fatal("ForgetAndInvalidateIfUnretired succeeded after same-key Remove")
	}
	if latch.IsInvalidated("CloudflareTunnelConfig", keyA) {
		t.Fatal("ForgetAndInvalidateIfUnretired recreated invalidation after same-key Remove")
	}
	if gotEpoch := latch.InvalidationEpoch("CloudflareTunnelConfig", keyA); gotEpoch != 0 {
		t.Fatalf("ForgetAndInvalidateIfUnretired set epoch=%d after Remove, want 0", gotEpoch)
	}

	// RemoveIfUntouched returns false and preserves state when touched after BeginLifetime.
	tokTouch := latch.BeginLifetime("CloudflareTunnelConfig", keyA)
	defer latch.EndLifetime(tokTouch)
	latch.Invalidate("CloudflareTunnelConfig", keyA, "replacement-drift")
	epochAfterTouch := latch.InvalidationEpoch("CloudflareTunnelConfig", keyA)
	if latch.RemoveIfUntouched(tokTouch) {
		t.Fatal("RemoveIfUntouched succeeded despite Invalidate after BeginLifetime")
	}
	if !latch.IsInvalidated("CloudflareTunnelConfig", keyA) {
		t.Fatal("RemoveIfUntouched wiped post-BeginLifetime invalidation")
	}
	if got := latch.InvalidationEpoch("CloudflareTunnelConfig", keyA); got != epochAfterTouch {
		t.Fatalf("RemoveIfUntouched altered epoch: got %d, want %d", got, epochAfterTouch)
	}

	// RemoveIfUntouched succeeds when untouched and retires sibling tokens on same key.
	tokRemover := latch.BeginLifetime("CloudflareTunnelConfig", keyB)
	defer latch.EndLifetime(tokRemover)
	tokSibling := latch.BeginLifetime("CloudflareTunnelConfig", keyB)
	defer latch.EndLifetime(tokSibling)
	latch.Invalidate("CloudflareTunnelConfig", keyB, "stale-drift")
	tokClean := latch.BeginLifetime("CloudflareTunnelConfig", keyB)
	defer latch.EndLifetime(tokClean)
	if !latch.RemoveIfUntouched(tokClean) {
		t.Fatal("RemoveIfUntouched failed on untouched key")
	}
	if latch.IsInvalidated("CloudflareTunnelConfig", keyB) {
		t.Fatal("RemoveIfUntouched did not clear keyB state")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokSibling, "demoted") {
		t.Fatal("sibling token succeeded after RemoveIfUntouched")
	}
}

func TestLatchUIDBoundIsolationAndPruning(t *testing.T) {
	latch := NewLatch()
	key := types.NamespacedName{Namespace: "tenant", Name: "edge"}
	otherKey := types.NamespacedName{Namespace: "tenant", Name: "other"}
	const uid1 = types.UID("uid-1")
	const uid2 = types.UID("uid-2")
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	// nil / empty UID safety.
	var nilLatch *Latch
	nilLatch.InvalidateForUID("CloudflareTunnelConfig", key, uid1, "drift")
	if nilLatch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("nil latch IsInvalidatedForUID returned true")
	}
	if nilLatch.InvalidationEpochForUID("CloudflareTunnelConfig", key, uid1) != 0 {
		t.Fatal("nil latch InvalidationEpochForUID non-zero")
	}
	if _, ok := nilLatch.VerifiedAtForUID("CloudflareTunnelConfig", key, uid1, "h1"); ok {
		t.Fatal("nil latch VerifiedAtForUID returned true")
	}
	if nilLatch.CompleteVerificationForUID("CloudflareTunnelConfig", key, uid1, 0, "h1", now, nil) {
		t.Fatal("nil latch CompleteVerificationForUID returned true")
	}
	nilTok := nilLatch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	if nilTok.UID() != uid1 {
		t.Fatalf("nil BeginLifetimeForUID UID = %q, want %q", nilTok.UID(), uid1)
	}
	if nilLatch.HasOtherUIDs("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("nil HasOtherUIDs returned true")
	}
	nilPrune := nilLatch.BeginPrune("CloudflareTunnelConfig", key)
	nilLatch.EndPrune(nilPrune)
	if nilLatch.PruneOtherUIDsIfUntouched(nilPrune, uid2) {
		t.Fatal("nil PruneOtherUIDsIfUntouched returned true")
	}
	latch.InvalidateForUID("CloudflareTunnelConfig", key, "", "empty-uid")
	if latch.IsInvalidated("CloudflareTunnelConfig", key) {
		t.Fatal("empty uid wrote to name-scoped latch")
	}

	// UID1 token cannot mutate UID2 or name-scoped slot.
	tokUID1 := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid2, "replacement-drift")
	uid2Epoch := latch.InvalidationEpochForUID("CloudflareTunnelConfig", key, uid2)
	latch.Invalidate("CloudflareTunnelConfig", key, "name-scoped")
	nameEpoch := latch.InvalidationEpoch("CloudflareTunnelConfig", key)

	if !latch.ForgetAndInvalidateIfUnretired(tokUID1, "demoted") {
		t.Fatal("UID1 ForgetAndInvalidateIfUnretired unexpectedly failed")
	}
	latch.EndLifetime(tokUID1)
	if len(latch.activeGuards) != 0 {
		t.Fatalf("activeGuards not emptied after EndLifetime: len=%d", len(latch.activeGuards))
	}
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("expected UID1 invalidation after ForgetAndInvalidateIfUnretired")
	}
	if got := latch.InvalidationEpochForUID("CloudflareTunnelConfig", key, uid2); got != uid2Epoch {
		t.Fatalf("UID1 demote modified UID2 epoch: got %d, want %d", got, uid2Epoch)
	}
	if got := latch.InvalidationEpoch("CloudflareTunnelConfig", key); got != nameEpoch {
		t.Fatalf("UID1 demote modified name-scoped epoch: got %d, want %d", got, nameEpoch)
	}
	if !latch.CompleteVerificationForUID("CloudflareTunnelConfig", key, uid2, uid2Epoch, "h2", now, nil) {
		t.Fatal("UID2 CompleteVerificationForUID failed")
	}
	if latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("UID2 still invalidated after CompleteVerificationForUID")
	}
	if _, ok := latch.VerifiedAtForUID("CloudflareTunnelConfig", key, uid2, "h2"); !ok {
		t.Fatal("UID2 VerifiedAtForUID missing after CompleteVerificationForUID")
	}

	// HasOtherUIDs + BeginPrune + PruneOtherUIDsIfUntouched drops pre-snapshot UID1
	// and retires pre-snapshot UID1 tokens, while keeping UID2, post-snapshot tokens,
	// and name-scoped entries, and cleans activeGuards to 0 on EndPrune.
	if !latch.HasOtherUIDs("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("expected HasOtherUIDs=true with UID1 present")
	}
	if latch.HasOtherUIDs("CloudflareTunnelConfig", otherKey, uid2) {
		t.Fatal("expected HasOtherUIDs=false for clean otherKey")
	}
	tokUID1Stale := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	tokUID2Live := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid2)
	tokPrune := latch.BeginPrune("CloudflareTunnelConfig", key)
	tokUID1PostSnapshot := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	if !latch.PruneOtherUIDsIfUntouched(tokPrune, uid2) {
		t.Fatal("PruneOtherUIDsIfUntouched returned false for untouched prune")
	}
	latch.EndPrune(tokPrune)
	if latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("PruneOtherUIDsIfUntouched kept UID1 invalidation")
	}
	if !latch.HasOtherUIDs("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("expected HasOtherUIDs=true while post-snapshot UID1 token is still active")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokUID1Stale, "demoted") {
		t.Fatal("retired pre-snapshot UID1 token succeeded after PruneOtherUIDsIfUntouched")
	}
	if !latch.ForgetAndInvalidateIfUnretired(tokUID1PostSnapshot, "post-snapshot") {
		t.Fatal("PruneOtherUIDsIfUntouched retired post-snapshot UID1 token")
	}
	latch.ClearForUID("CloudflareTunnelConfig", key, uid1)
	latch.EndLifetime(tokUID1PostSnapshot)
	if !latch.ForgetAndInvalidateIfUnretired(tokUID2Live, "demoted") {
		t.Fatal("PruneOtherUIDsIfUntouched retired live UID2 token")
	}
	if got := latch.InvalidationEpoch("CloudflareTunnelConfig", key); got != nameEpoch {
		t.Fatalf("PruneOtherUIDsIfUntouched touched name-scoped slot: got %d, want %d", got, nameEpoch)
	}
	latch.EndLifetime(tokUID1Stale)
	latch.EndLifetime(tokUID2Live)
	if len(latch.activeGuards) != 0 {
		t.Fatalf("activeGuards not emptied after EndPrune + EndLifetime: len=%d", len(latch.activeGuards))
	}

	// Concurrent touch after BeginPrune aborts PruneOtherUIDsIfUntouched so UID1/UID2 stay intact.
	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid1, "pre-prune")
	tokAbortPrune := latch.BeginPrune("CloudflareTunnelConfig", key)
	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid2, "concurrent-write")
	if latch.PruneOtherUIDsIfUntouched(tokAbortPrune, uid2) {
		t.Fatal("PruneOtherUIDsIfUntouched succeeded despite concurrent InvalidateForUID")
	}
	latch.EndPrune(tokAbortPrune)
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("aborted PruneOtherUIDsIfUntouched deleted UID1")
	}

	// ForgetAndInvalidateIfUnretired marks name-scoped active guards touched=true,
	// so delayed RemoveIfUntouched cannot wipe UID2's demotion.
	tokAbsent := latch.BeginLifetime("CloudflareTunnelConfig", key)
	tokUID2Demote := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid2)
	if !latch.ForgetAndInvalidateIfUnretired(tokUID2Demote, "demoted") {
		t.Fatal("UID2 ForgetAndInvalidateIfUnretired failed")
	}
	if latch.RemoveIfUntouched(tokAbsent) {
		t.Fatal("RemoveIfUntouched wiped UID2 demotion despite ForgetAndInvalidateIfUnretired")
	}
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("UID2 invalidation missing after rejected RemoveIfUntouched")
	}
	latch.EndLifetime(tokAbsent)
	latch.EndLifetime(tokUID2Demote)

	// Name-scoped BeginLifetime + RemoveIfUntouched is marked touched by InvalidateForUID,
	// and when untouched clears both name-scoped and UID-scoped entries.
	tokName := latch.BeginLifetime("CloudflareTunnelConfig", key)
	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid2, "new-uid2-drift")
	if latch.RemoveIfUntouched(tokName) {
		t.Fatal("RemoveIfUntouched succeeded despite InvalidateForUID after BeginLifetime")
	}
	latch.EndLifetime(tokName)
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid2) {
		t.Fatal("RemoveIfUntouched cleared UID2 state despite InvalidateForUID")
	}

	// Untouched name-scoped token clears UID2 and name-scoped entries, leaving otherKey intact.
	latch.InvalidateForUID("CloudflareTunnelConfig", otherKey, uid1, "other-drift")
	tokClean := latch.BeginLifetime("CloudflareTunnelConfig", key)
	tokUID2Sibling := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid2)
	if !latch.RemoveIfUntouched(tokClean) {
		t.Fatal("untouched RemoveIfUntouched returned false")
	}
	if latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid2) || latch.IsInvalidated("CloudflareTunnelConfig", key) {
		t.Fatal("RemoveIfUntouched did not clear all UID variants for key")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokUID2Sibling, "demoted") {
		t.Fatal("RemoveIfUntouched did not retire sibling UID2 token")
	}
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", otherKey, uid1) {
		t.Fatal("RemoveIfUntouched touched unrelated otherKey")
	}
	latch.EndLifetime(tokClean)
	latch.EndLifetime(tokUID2Sibling)

	// Remove clears both name-scoped and UID-scoped variants for key, leaving otherKey intact.
	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid1, "stale")
	tokForRemove := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	latch.Remove("CloudflareTunnelConfig", key)
	if latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("Remove did not clear UID1 variant")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokForRemove, "demoted") {
		t.Fatal("Remove did not retire UID1 token")
	}
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", otherKey, uid1) {
		t.Fatal("Remove touched unrelated otherKey")
	}
	latch.EndLifetime(tokForRemove)
}

func TestLatchRemoveIfUntouchedPreservesUnseenPostBeginUIDGuard(t *testing.T) {
	latch := NewLatch()
	key := types.NamespacedName{Namespace: "tenant", Name: "edge"}
	const uid1 = types.UID("uid-1")
	const uidPre = types.UID("uid-pre")
	const uid2New = types.UID("uid-2-new")

	latch.InvalidateForUID("CloudflareTunnelConfig", key, uid1, "old-drift")
	tokPre := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uidPre)
	defer latch.EndLifetime(tokPre)

	// Name-scoped absence guard snapshots uid1 and uidPre in knownUIDs.
	tokAbsent := latch.BeginLifetime("CloudflareTunnelConfig", key)
	defer latch.EndLifetime(tokAbsent)

	// After BeginLifetime:
	// - uid2New is an unseen replacement UID (gid > tokAbsent.id, !known)
	// - uid1Late is a late stale-cache guard for deleted uid1 (gid > tokAbsent.id, known)
	tokUID2New := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid2New)
	defer latch.EndLifetime(tokUID2New)
	tokUID1Late := latch.BeginLifetimeForUID("CloudflareTunnelConfig", key, uid1)
	defer latch.EndLifetime(tokUID1Late)

	if !latch.RemoveIfUntouched(tokAbsent) {
		t.Fatal("expected untouched RemoveIfUntouched to apply")
	}
	if latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid1) {
		t.Fatal("RemoveIfUntouched did not delete uid1 state")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokPre, "demoted") {
		t.Fatal("pre-BeginLifetime guard was not retired by RemoveIfUntouched")
	}
	if latch.ForgetAndInvalidateIfUnretired(tokUID1Late, "demoted") {
		t.Fatal("late guard for known uid1 was not retired by RemoveIfUntouched")
	}
	if !latch.ForgetAndInvalidateIfUnretired(tokUID2New, "demoted") {
		t.Fatal("RemoveIfUntouched retired unseen post-BeginLifetime replacement UID2 guard")
	}
	if !latch.IsInvalidatedForUID("CloudflareTunnelConfig", key, uid2New) || latch.InvalidationEpochForUID("CloudflareTunnelConfig", key, uid2New) == 0 {
		t.Fatal("expected unseen replacement UID2 guard to record fail-closed invalidation")
	}

	latch.EndLifetime(tokPre)
	latch.EndLifetime(tokAbsent)
	latch.EndLifetime(tokUID2New)
	latch.EndLifetime(tokUID1Late)
	if len(latch.activeGuards) != 0 {
		t.Fatalf("activeGuards not empty after EndLifetime: len=%d", len(latch.activeGuards))
	}
}
