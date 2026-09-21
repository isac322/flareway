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

	"k8s.io/apimachinery/pkg/types"
)

// latchKey identifies one gated object.
type latchKey struct {
	kind      string
	namespace string
	name      string
}

// Latch is the thread-safe in-memory drift-invalidation store. It
// structurally satisfies the sweep.Invalidator interface
// (00-architecture.md §5): the sweep calls Invalidate when it finds drift,
// reconcilers call IsInvalidated while evaluating the gate and Clear after
// the object re-converges.
//
// All methods are safe on a nil *Latch so reconcilers can treat an
// uninjected latch as "no invalidations" without nil checks at the call
// site. See the package documentation for why in-memory storage is
// sufficient.
type Latch struct {
	mu      sync.RWMutex
	reasons map[latchKey]string
}

// NewLatch returns an empty latch.
func NewLatch() *Latch {
	return &Latch{reasons: make(map[latchKey]string)}
}

// Invalidate closes the object's gate and records reason for observability.
// Repeated calls for the same key keep the latest reason.
func (l *Latch) Invalidate(kind string, key types.NamespacedName, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reasons[latchKey{kind: kind, namespace: key.Namespace, name: key.Name}] = reason
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
