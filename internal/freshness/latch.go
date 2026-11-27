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
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// latchKey identifies one gated object, optionally scoped to a specific UID.
type latchKey struct {
	kind      string
	namespace string
	name      string
	uid       types.UID
}

// Latch is the thread-safe in-memory freshness store. It holds two records per
// gated object:
//
//   - the drift invalidation. It structurally satisfies the sweep.Invalidator
//     interface (00-architecture.md §5): the sweep calls Invalidate when it
//     finds drift, reconcilers call IsInvalidated while evaluating the gate
//     and Clear after the object re-converges.
//   - the last verification: when a reconciler last confirmed the remote
//     against a desired hash. The gate measures its age from this record so a
//     re-verify that changes nothing need not rewrite status.appliedAt.
//   - the content baseline and the sweep's confirmations of it: the desired
//     content a reconciler last verified, and when a sweep listing last
//     showed the remote still matching it. A confirmation counts as a fresh
//     verify, which is what keeps a converged object from reading Cloudflare
//     itself while the sweep is healthy.
//
// All methods are safe on a nil *Latch so reconcilers can treat an
// uninjected latch as "no invalidations, no verifications" without nil
// checks at the call site. See the package documentation for why in-memory
// storage is sufficient.
type Latch struct {
	mu           sync.RWMutex
	nextEpoch    uint64
	nextGuardID  uint64
	epochs       map[latchKey]uint64
	reasons      map[latchKey]string
	verified     map[latchKey]verification
	baselines    map[latchKey]baseline
	confirmed    map[latchKey]verification
	activeGuards map[latchKey]map[uint64]*guardState
}

// LifetimeToken guards a single in-flight read-and-update cycle on one latch
// key against concurrent retirement or replacement-UID updates without retaining
// any per-key state after EndLifetime.
type LifetimeToken struct {
	kind string
	key  types.NamespacedName
	uid  types.UID
	id   uint64
}

// Key returns the NamespacedName guarded by this LifetimeToken.
func (t LifetimeToken) Key() types.NamespacedName {
	return t.key
}

// UID returns the UID scoped by this LifetimeToken (empty for name-scoped tokens).
func (t LifetimeToken) UID() types.UID {
	return t.uid
}

type guardState struct {
	retired bool
	touched bool
}

// verification is the most recent confirmation of one desired hash.
type verification struct {
	hash string
	at   time.Time
}

// ContentMatcher reports whether a remote object, exactly as the kind's list
// API returns it, still carries the desired content a reconciler verified.
// It must use the same comparison the reconciler's own verify uses, and it
// must report false for any value it does not recognize.
type ContentMatcher func(observed any) bool

// baseline is the desired content a reconciler last verified.
type baseline struct {
	hash    string
	matches ContentMatcher
}

// NewLatch returns an empty latch.
func NewLatch() *Latch {
	return &Latch{
		epochs:       make(map[latchKey]uint64),
		reasons:      make(map[latchKey]string),
		verified:     make(map[latchKey]verification),
		baselines:    make(map[latchKey]baseline),
		confirmed:    make(map[latchKey]verification),
		activeGuards: make(map[latchKey]map[uint64]*guardState),
	}
}

func (l *Latch) markGuardsTouchedLocked(k latchKey) {
	for _, st := range l.activeGuards[k] {
		st.touched = true
	}
	if k.uid != "" {
		nameKey := latchKey{kind: k.kind, namespace: k.namespace, name: k.name}
		for _, st := range l.activeGuards[nameKey] {
			st.touched = true
		}
	}
}

func (l *Latch) beginLifetime(kind string, key types.NamespacedName, uid types.UID) LifetimeToken {
	if l == nil {
		return LifetimeToken{kind: kind, key: key, uid: uid}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextGuardID++
	id := l.nextGuardID
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}
	if l.activeGuards == nil {
		l.activeGuards = make(map[latchKey]map[uint64]*guardState)
	}
	guards := l.activeGuards[k]
	if guards == nil {
		guards = make(map[uint64]*guardState)
		l.activeGuards[k] = guards
	}
	guards[id] = &guardState{}
	return LifetimeToken{kind: kind, key: key, uid: uid, id: id}
}

// BeginLifetime registers an in-flight name-scoped guard token for (kind, key).
// Callers must pair it with defer EndLifetime(tok) so idle keys retain zero bytes.
func (l *Latch) BeginLifetime(kind string, key types.NamespacedName) LifetimeToken {
	return l.beginLifetime(kind, key, "")
}

// BeginLifetimeForUID registers an in-flight UID-scoped guard token for
// (kind, key, uid). Callers must pair it with defer EndLifetime(tok).
func (l *Latch) BeginLifetimeForUID(kind string, key types.NamespacedName, uid types.UID) LifetimeToken {
	return l.beginLifetime(kind, key, uid)
}

// EndLifetime unregisters tok and deletes the per-key guard map when empty.
func (l *Latch) EndLifetime(tok LifetimeToken) {
	if l == nil || tok.id == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: tok.kind, namespace: tok.key.Namespace, name: tok.key.Name, uid: tok.uid}
	guards := l.activeGuards[k]
	if guards == nil {
		return
	}
	delete(guards, tok.id)
	if len(guards) == 0 {
		delete(l.activeGuards, k)
	}
}

func (l *Latch) invalidateKey(k latchKey, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.epochs == nil {
		l.epochs = make(map[latchKey]uint64)
	}
	if l.reasons == nil {
		l.reasons = make(map[latchKey]string)
	}
	l.nextEpoch++
	l.epochs[k] = l.nextEpoch
	l.reasons[k] = reason
	delete(l.verified, k)
	delete(l.confirmed, k)
	l.markGuardsTouchedLocked(k)
}

// Invalidate closes the object's gate and records reason for observability.
// Repeated calls for the same key keep the latest reason and advance its
// monotonic invalidation epoch so an in-flight reconcile cannot clear a newer
// invalidation. It also discards the object's last verification: drift was
// found after that verify, so the record must not re-open the gate if the
// invalidation is cleared early.
func (l *Latch) Invalidate(kind string, key types.NamespacedName, reason string) {
	l.invalidateKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name}, reason)
}

// InvalidateForUID closes the UID-scoped object's gate and records reason.
// It is a no-op when l is nil or uid is empty.
func (l *Latch) InvalidateForUID(kind string, key types.NamespacedName, uid types.UID, reason string) {
	if uid == "" {
		return
	}
	l.invalidateKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}, reason)
}

// InvalidationEpoch returns the object's current invalidation epoch. Callers
// capture it before executing remote reads/writes and pass it to
// CompleteVerification so concurrent sweep invalidations are never overwritten.
func (l *Latch) InvalidationEpoch(kind string, key types.NamespacedName) uint64 {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.epochs[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}]
}

// InvalidationEpochForUID returns the UID-scoped object's current invalidation epoch.
func (l *Latch) InvalidationEpochForUID(kind string, key types.NamespacedName, uid types.UID) uint64 {
	if l == nil || uid == "" {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.epochs[latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}]
}

func (l *Latch) completeVerificationKey(
	k latchKey,
	expectedEpoch uint64,
	hash string,
	at time.Time,
	matches ContentMatcher,
) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.epochs[k] != expectedEpoch {
		return false
	}
	delete(l.reasons, k)
	delete(l.confirmed, k)
	if hash != "" {
		if l.verified == nil {
			l.verified = make(map[latchKey]verification)
		}
		l.verified[k] = verification{hash: hash, at: at}
	}
	if hash == "" || matches == nil {
		delete(l.baselines, k)
	} else {
		if l.baselines == nil {
			l.baselines = make(map[latchKey]baseline)
		}
		l.baselines[k] = baseline{hash: hash, matches: matches}
	}
	l.markGuardsTouchedLocked(k)
	return true
}

// CompleteVerification atomically releases any invalidation matching
// expectedEpoch and records verification metadata and optional sweep content
// baseline. If another Invalidate occurred after expectedEpoch was captured,
// CompleteVerification leaves the newer invalidation untouched and reports
// false.
func (l *Latch) CompleteVerification(
	kind string,
	key types.NamespacedName,
	expectedEpoch uint64,
	hash string,
	at time.Time,
	matches ContentMatcher,
) bool {
	return l.completeVerificationKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name}, expectedEpoch, hash, at, matches)
}

// CompleteVerificationForUID is CompleteVerification scoped to uid.
func (l *Latch) CompleteVerificationForUID(
	kind string,
	key types.NamespacedName,
	uid types.UID,
	expectedEpoch uint64,
	hash string,
	at time.Time,
	matches ContentMatcher,
) bool {
	if uid == "" {
		return false
	}
	return l.completeVerificationKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}, expectedEpoch, hash, at, matches)
}

// IsInvalidated reports whether the object's gate is held closed.
func (l *Latch) IsInvalidated(kind string, key types.NamespacedName) bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.reasons[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}]
	return ok
}

// IsInvalidatedForUID reports whether the UID-scoped object's gate is held closed.
func (l *Latch) IsInvalidatedForUID(kind string, key types.NamespacedName, uid types.UID) bool {
	if l == nil || uid == "" {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.reasons[latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}]
	return ok
}

// Clear releases the latch. Callers must invoke it only after the object
// has re-converged; clearing early re-opens the gate on a still-drifted
// object.
func (l *Latch) Clear(kind string, key types.NamespacedName) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.reasons, latchKey{kind: kind, namespace: key.Namespace, name: key.Name})
}

// ClearForUID releases the UID-scoped latch.
func (l *Latch) ClearForUID(kind string, key types.NamespacedName, uid types.UID) {
	if l == nil || uid == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.reasons, latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid})
}

// Forget drops the object's verification, content baseline, and sweep
// confirmations, keeping any invalidation. Callers use it when a pass is about
// to go to the remote: until that pass converges and records again, nothing
// the object verified earlier may re-open its gate. Without it, a desired
// state that changes and then changes back could find an old record, or a
// sweep confirmation the sweep kept renewing, and skip the pass that would
// bring status back in line.
func (l *Latch) Forget(kind string, key types.NamespacedName) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name}
	delete(l.verified, k)
	delete(l.baselines, k)
	delete(l.confirmed, k)
}

// ForgetForUID drops the UID-scoped object's verification, baseline, and sweep
// confirmations while keeping any invalidation.
func (l *Latch) ForgetForUID(kind string, key types.NamespacedName, uid types.UID) {
	if l == nil || uid == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}
	delete(l.verified, k)
	delete(l.baselines, k)
	delete(l.confirmed, k)
}

func (l *Latch) purgeMatchingLocked(
	kind, ns, name string,
	shouldDeleteUID func(types.UID) bool,
	skipKey latchKey,
	skipID uint64,
) {
	for k := range l.epochs {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			delete(l.epochs, k)
		}
	}
	for k := range l.reasons {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			delete(l.reasons, k)
		}
	}
	for k := range l.verified {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			delete(l.verified, k)
		}
	}
	for k := range l.baselines {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			delete(l.baselines, k)
		}
	}
	for k := range l.confirmed {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			delete(l.confirmed, k)
		}
	}
	for k, guards := range l.activeGuards {
		if k.kind == kind && k.namespace == ns && k.name == name && shouldDeleteUID(k.uid) {
			for id, st := range guards {
				if k == skipKey && id == skipID {
					continue
				}
				st.retired = true
			}
		}
	}
}

// PruneOtherUIDs drops every UID-scoped entry for (kind, key) whose UID differs
// from liveUID and retires any in-flight guard tokens for those old UIDs.
// Name-scoped entries (uid == "") are left untouched.
func (l *Latch) PruneOtherUIDs(kind string, key types.NamespacedName, liveUID types.UID) {
	if l == nil || liveUID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeMatchingLocked(kind, key.Namespace, key.Name, func(u types.UID) bool {
		return u != "" && u != liveUID
	}, latchKey{}, 0)
}

// ForgetAndInvalidateIfUnretired atomically forgets verified/baseline state and
// marks the token's exact key (including its UID when UID-scoped) invalidated
// only if tok is still active and has not been retired. Reports whether the
// update applied.
func (l *Latch) ForgetAndInvalidateIfUnretired(tok LifetimeToken, reason string) bool {
	if l == nil || tok.id == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: tok.kind, namespace: tok.key.Namespace, name: tok.key.Name, uid: tok.uid}
	guards := l.activeGuards[k]
	st, ok := guards[tok.id]
	if !ok || st.retired {
		return false
	}
	if l.epochs == nil {
		l.epochs = make(map[latchKey]uint64)
	}
	if l.reasons == nil {
		l.reasons = make(map[latchKey]string)
	}
	l.nextEpoch++
	l.epochs[k] = l.nextEpoch
	l.reasons[k] = reason
	delete(l.verified, k)
	delete(l.baselines, k)
	delete(l.confirmed, k)
	for id, other := range guards {
		if id != tok.id {
			other.touched = true
		}
	}
	return true
}

// RemoveIfUntouched drops records only if tok is still active and untouched.
// For name-scoped tokens (uid == ""), it deletes all name- and UID-scoped
// entries for (kind, key) and retires every other guard across all UID variants.
// For UID-scoped tokens, it deletes only tok's UID entry and retires sibling
// guards on that UID. Reports whether removal applied.
func (l *Latch) RemoveIfUntouched(tok LifetimeToken) bool {
	if l == nil || tok.id == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: tok.kind, namespace: tok.key.Namespace, name: tok.key.Name, uid: tok.uid}
	guards := l.activeGuards[k]
	st, ok := guards[tok.id]
	if !ok || st.touched {
		return false
	}
	if tok.uid == "" {
		l.purgeMatchingLocked(tok.kind, tok.key.Namespace, tok.key.Name, func(types.UID) bool {
			return true
		}, k, tok.id)
	} else {
		l.purgeMatchingLocked(tok.kind, tok.key.Namespace, tok.key.Name, func(u types.UID) bool {
			return u == tok.uid
		}, k, tok.id)
	}
	return true
}

// Remove drops every record (name-scoped and all UID-scoped variants) for an
// object that no longer exists, and marks all active guards on those entries as
// retired.
func (l *Latch) Remove(kind string, key types.NamespacedName) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeMatchingLocked(kind, key.Namespace, key.Name, func(types.UID) bool {
		return true
	}, latchKey{}, 0)
}

func (l *Latch) markVerifiedKey(k latchKey, hash string, at time.Time) {
	if l == nil || hash == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.verified == nil {
		l.verified = make(map[latchKey]verification)
	}
	l.verified[k] = verification{hash: hash, at: at}
	l.markGuardsTouchedLocked(k)
}

// MarkVerified records that the object's remote state was confirmed to match
// hash at the given time. A later record replaces an earlier one, including one
// for a different hash.
func (l *Latch) MarkVerified(kind string, key types.NamespacedName, hash string, at time.Time) {
	l.markVerifiedKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name}, hash, at)
}

// MarkVerifiedForUID is MarkVerified scoped to uid.
func (l *Latch) MarkVerifiedForUID(kind string, key types.NamespacedName, uid types.UID, hash string, at time.Time) {
	if uid == "" {
		return
	}
	l.markVerifiedKey(latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}, hash, at)
}

// VerifiedAt returns when the object was last confirmed against hash. It
// reports false when nothing was recorded since the process started or when
// the record belongs to a different hash.
func (l *Latch) VerifiedAt(kind string, key types.NamespacedName, hash string) (time.Time, bool) {
	if l == nil || hash == "" {
		return time.Time{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	record, ok := l.verified[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}]
	if !ok || record.hash != hash {
		return time.Time{}, false
	}
	return record.at, true
}

// VerifiedAtForUID is VerifiedAt scoped to uid.
func (l *Latch) VerifiedAtForUID(kind string, key types.NamespacedName, uid types.UID, hash string) (time.Time, bool) {
	if l == nil || uid == "" || hash == "" {
		return time.Time{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	record, ok := l.verified[latchKey{kind: kind, namespace: key.Namespace, name: key.Name, uid: uid}]
	if !ok || record.hash != hash {
		return time.Time{}, false
	}
	return record.at, true
}

// SetBaseline records the desired content the object was just verified
// against, so that a sweep listing can confirm it later without a per-object
// read. A nil matcher removes the baseline: the object's content is not fully
// visible to the sweep, and its own verify stays the only detection path.
// Either way any earlier sweep confirmation is discarded, because it confirmed
// a baseline that no longer applies.
func (l *Latch) SetBaseline(kind string, key types.NamespacedName, hash string, matches ContentMatcher) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name}
	delete(l.confirmed, k)
	if hash == "" || matches == nil {
		delete(l.baselines, k)
		return
	}
	l.baselines[k] = baseline{hash: hash, matches: matches}
}

// ConfirmContent is called by the sweep for an object whose listed remote
// passed the identity checks. Without a baseline it does nothing and reports
// false. When the listed object matches the baseline it records a sweep
// confirmation of the baseline hash at the given time, which must not be
// later than the moment the listing started. It reports true when the listed
// object no longer matches: the caller treats that as drift.
func (l *Latch) ConfirmContent(kind string, key types.NamespacedName, observed any, at time.Time) bool {
	if l == nil {
		return false
	}
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name}
	l.mu.RLock()
	current, ok := l.baselines[k]
	l.mu.RUnlock()
	if !ok {
		return false
	}
	if !current.matches(observed) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// The baseline may have been replaced while the matcher ran; only a
	// confirmation of the baseline that was actually compared is recorded.
	if latest, ok := l.baselines[k]; ok && latest.hash == current.hash {
		if previous, ok := l.confirmed[k]; !ok || previous.hash != current.hash || at.After(previous.at) {
			l.confirmed[k] = verification{hash: current.hash, at: at}
		}
	}
	return false
}

// ConfirmedAt returns when a sweep listing last confirmed the object's content
// for hash. It reports false when no confirmation of that hash exists.
func (l *Latch) ConfirmedAt(kind string, key types.NamespacedName, hash string) (time.Time, bool) {
	if l == nil || hash == "" {
		return time.Time{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	record, ok := l.confirmed[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}]
	if !ok || record.hash != hash {
		return time.Time{}, false
	}
	return record.at, true
}
