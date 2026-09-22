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

// QA-92-24: a writer holding a stale cached tunnel snapshot must not resurrect
// Ready=True over a live ConfigApplied=False demotion. The shared conditions
// helper reads the live object through APIReader on every attempt, so the
// stale observed object can only supply identity — never condition content.
//
// The discriminator is a real informer barrier: a cache Transform holds every
// CloudflareTunnel update after the cache is warm, so the manager's cached
// client provably serves a pre-demotion object while the API server already
// carries ConfigApplied=False.
package controller

import (
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// managerCacheBarrier holds informer Transform calls once armed, freezing the
// cached view of the object kind it is installed on. Release unblocks the
// informer; it is registered as test cleanup so a failed assertion cannot
// wedge manager shutdown.
type managerCacheBarrier struct {
	armed atomic.Bool
	gate  chan struct{}
}

func newManagerCacheBarrier() *managerCacheBarrier {
	return &managerCacheBarrier{gate: make(chan struct{})}
}

func (b *managerCacheBarrier) transform(obj any) (any, error) {
	if b.armed.Load() {
		<-b.gate
	}
	return obj, nil
}

func (b *managerCacheBarrier) arm()     { b.armed.Store(true) }
func (b *managerCacheBarrier) release() {
	if b.armed.CompareAndSwap(true, false) {
		close(b.gate)
	}
}

func TestQA92_24_StaleObservedCannotResurrectReady(t *testing.T) {
	barrier := newManagerCacheBarrier()
	h := newManagerHarnessOpts(t, managerHarnessOpts{
		cacheByObject: map[client.Object]cache.ByObject{
			&v1alpha1.CloudflareTunnel{}: {Transform: barrier.transform},
		},
	})
	// Released before h.close (LIFO cleanup) so the informer can drain.
	t.Cleanup(barrier.release)

	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	// Prove the tunnel informer is warm before arming: the cached client must
	// already serve the converged object, otherwise the staleness check below
	// would read a never-populated cache.
	h.waitFor(t, 15*time.Second, "cached tunnel visible", func() (bool, error) {
		var cached v1alpha1.CloudflareTunnel
		if err := h.client.Get(h.ctx, f.tunnelKey, &cached); err != nil {
			return false, nil
		}
		index := managerConditionIndex(cached.Status.Conditions)
		return index[v1alpha1.CloudflareTunnelConditionConfigApplied].Status == metav1.ConditionTrue, nil
	})

	// Freeze the tunnel informer after the cache is warm: every later API
	// write is invisible to the cached client until release.
	barrier.arm()

	// Demote through a fresh API write: ConfigApplied=False with the
	// unconditional Ready clamp, exactly the mid-gate shape from issue #92.
	live := h.getTunnel(t, f.tunnelKey)
	demote := []metav1.Condition{{
		Type:               v1alpha1.CloudflareTunnelConditionConfigApplied,
		Status:             metav1.ConditionFalse,
		Reason:             "Pending",
		Message:            "demoted through fresh API write",
		ObservedGeneration: live.Generation,
	}}
	if err := patchTunnelConditions(h.ctx, h.direct, h.direct, tunnelConditionUpdate{
		Observed:   live,
		Conditions: demote,
		Now:        metav1.Now(),
	}); err != nil {
		t.Fatalf("publish ConfigApplied=False: %v", err)
	}
	h.waitFor(t, 10*time.Second, "live demotion", func() (bool, error) {
		current := h.getTunnel(t, f.tunnelKey)
		index := managerConditionIndex(current.Status.Conditions)
		return index[v1alpha1.CloudflareTunnelConditionConfigApplied].Status == metav1.ConditionFalse &&
			index[v1alpha1.CloudflareTunnelConditionReady].Status == metav1.ConditionFalse, nil
	})

	// The cached client must still serve the pre-demotion object — this is
	// the stale-observed discriminator, not a timing hope.
	var stale v1alpha1.CloudflareTunnel
	if err := h.client.Get(h.ctx, f.tunnelKey, &stale); err != nil {
		t.Fatalf("read cached tunnel: %v", err)
	}
	staleIndex := managerConditionIndex(stale.Status.Conditions)
	if staleIndex[v1alpha1.CloudflareTunnelConditionConfigApplied].Status != metav1.ConditionTrue ||
		staleIndex[v1alpha1.CloudflareTunnelConditionReady].Status != metav1.ConditionTrue {
		h.dumpTunnelSequence(t, f, time.Now().Add(-time.Minute))
		t.Fatalf("cache barrier failed: cached tunnel is not stale (ConfigApplied=%s Ready=%s)",
			staleIndex[v1alpha1.CloudflareTunnelConditionConfigApplied].Status,
			staleIndex[v1alpha1.CloudflareTunnelConditionReady].Status)
	}

	// The stale writer path: observed from the manager cache, write through
	// the manager client, fresh read through the manager APIReader — the same
	// wiring the reconciler uses. The stale snapshot computed Ready=True; the
	// authored delta must land (its reason survives the clamp) while the
	// status is clamped to False against the live unmet input.
	err := patchTunnelConditions(h.ctx, h.client, h.mgr.GetAPIReader(), tunnelConditionUpdate{
		Observed: &stale,
		Conditions: []metav1.Condition{{
			Type:               v1alpha1.CloudflareTunnelConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             "StaleCompute",
			Message:            "stale snapshot computed ready",
			ObservedGeneration: stale.Generation,
		}},
		Now: metav1.Now(),
	})
	if err != nil {
		t.Fatalf("stale-writer conditions update: %v", err)
	}

	final := h.getTunnel(t, f.tunnelKey)
	index := managerConditionIndex(final.Status.Conditions)
	ready := index[v1alpha1.CloudflareTunnelConditionReady]
	if ready.Status == metav1.ConditionTrue {
		t.Fatalf("stale observed resurrected Ready=True over live ConfigApplied=False")
	}
	if ready.Reason != "StaleCompute" {
		t.Fatalf("authored Ready delta did not land: reason=%q status=%s", ready.Reason, ready.Status)
	}
	if index[v1alpha1.CloudflareTunnelConditionConfigApplied].Status != metav1.ConditionFalse {
		t.Fatalf("stale observed resurrected ConfigApplied=%s",
			index[v1alpha1.CloudflareTunnelConditionConfigApplied].Status)
	}

	// After release the informer drains and the controller reconverges the
	// fixture on its own; teardown still asserts a clean delete path.
	barrier.release()
}
