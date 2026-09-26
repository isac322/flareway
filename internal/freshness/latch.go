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

// latchKey identifies one gated object.
type latchKey struct {
	kind      string
	namespace string
	name      string
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
	mu        sync.RWMutex
	reasons   map[latchKey]string
	verified  map[latchKey]verification
	baselines map[latchKey]baseline
	confirmed map[latchKey]verification
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
		reasons:   make(map[latchKey]string),
		verified:  make(map[latchKey]verification),
		baselines: make(map[latchKey]baseline),
		confirmed: make(map[latchKey]verification),
	}
}

// Invalidate closes the object's gate and records reason for observability.
// Repeated calls for the same key keep the latest reason. It also discards the
// object's last verification: drift was found after that verify, so the record
// must not re-open the gate if the invalidation is cleared early.
func (l *Latch) Invalidate(kind string, key types.NamespacedName, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name}
	l.reasons[k] = reason
	delete(l.verified, k)
	delete(l.confirmed, k)
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

// Remove drops every record for an object that no longer exists, so a
// cluster that keeps creating and deleting objects does not grow the latch.
// A recreated object starts with nothing recorded, which only closes its gate.
func (l *Latch) Remove(kind string, key types.NamespacedName) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := latchKey{kind: kind, namespace: key.Namespace, name: key.Name}
	delete(l.reasons, k)
	delete(l.verified, k)
	delete(l.baselines, k)
	delete(l.confirmed, k)
}

// MarkVerified records that the object's remote state was confirmed to match
// hash at the given time. A later record replaces an earlier one, including one
// for a different hash.
func (l *Latch) MarkVerified(kind string, key types.NamespacedName, hash string, at time.Time) {
	if l == nil || hash == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verified[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}] = verification{hash: hash, at: at}
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
