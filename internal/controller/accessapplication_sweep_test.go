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

package controller

import (
	"context"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// sweptAccessWorld drives one AccessApplication through time the way the
// manager does: the reconciler runs when its requeue fires or the sweep wakes
// it, and the sweep lists applications once per period and hands every listed
// object to the latch, exactly as the AccessApplication sweep target does
// through classify and contentCheck.
type sweptAccessWorld struct {
	*accessFreshnessWorld
	latch       *freshness.Latch
	sweepEvery  time.Duration
	sweeping    bool
	nextSweep   time.Time
	nextWake    time.Time
	remoteReads int
}

func newSweptAccessWorld(t *testing.T) *sweptAccessWorld {
	t.Helper()
	world := newAccessFreshnessWorld(t)
	result := world.converge(t)
	ttl := world.reconciler.Freshness.TTL(freshness.GradeAuthz)
	return &sweptAccessWorld{
		accessFreshnessWorld: world,
		latch:                world.reconciler.Invalidator,
		// The sweep's longest regular interval: the period plus the full
		// fifth of jitter.
		sweepEvery: ttl + ttl/5,
		sweeping:   true,
		nextSweep:  world.now.Add(time.Second),
		nextWake:   world.now.Add(result.RequeueAfter),
	}
}

// sweep lists the applications and reports whether the owning object was
// found drifted, invalidating and waking it like handleDriftResults does.
func (w *sweptAccessWorld) sweep(t *testing.T) bool {
	t.Helper()
	id := w.stored(t).Status.ApplicationID
	listing, found := sweepListing(t, w.remote, id)
	if !found {
		return false
	}
	if w.latch.ConfirmContent("AccessApplication", w.request.NamespacedName, listing, w.now) {
		w.latch.Invalidate("AccessApplication", w.request.NamespacedName, "remote content changed")
		return true
	}
	return false
}

// sweepListing builds what the AccessApplication sweep target hands the
// latch for one application: the application as listed, the whole
// application listing (for bypass children), and the identity provider and
// custom page listings.
func sweepListing(t *testing.T, remote *fakeAccessApplicationCloudflare, id string) (flarecloudflare.AccessApplicationListing, bool) {
	t.Helper()
	applications, err := remote.ListAccessApplications(context.Background(), flarecloudflare.AccessScope{})
	if err != nil {
		t.Fatalf("list applications: %v", err)
	}
	listing := flarecloudflare.AccessApplicationListing{
		Applications:      make(map[string]flarecloudflare.AccessApplication, len(applications)),
		IdentityProviders: map[string]struct{}{},
		CustomPages:       map[string]flarecloudflare.AccessCustomPageSummary{},
	}
	for _, application := range applications {
		listing.Applications[application.ID] = application
	}
	remote.mu.Lock()
	for providerID := range remote.providers {
		listing.IdentityProviders[providerID] = struct{}{}
	}
	for pageID, page := range remote.customPages {
		listing.CustomPages[pageID] = page.AccessCustomPageSummary
	}
	remote.mu.Unlock()
	application, found := listing.Applications[id]
	listing.Application = application
	return listing, found
}

// reconcile runs one pass and schedules the next requeue.
func (w *sweptAccessWorld) reconcile(t *testing.T) {
	t.Helper()
	calls, result := w.pass(t, "reconcile")
	w.remoteReads += len(calls)
	if result.RequeueAfter > 0 {
		w.nextWake = w.now.Add(result.RequeueAfter)
	}
}

// runUntil advances the clock through every sweep pass and reconcile wake-up
// until the deadline or until stop reports true after an event.
func (w *sweptAccessWorld) runUntil(t *testing.T, deadline time.Time, stop func() bool) {
	t.Helper()
	for {
		next := w.nextWake
		sweepNext := w.sweeping && !w.nextSweep.After(next)
		if sweepNext {
			next = w.nextSweep
		}
		if next.After(deadline) {
			w.now = deadline
			return
		}
		w.now = next
		if sweepNext {
			w.nextSweep = w.now.Add(w.sweepEvery)
			if w.sweep(t) {
				w.reconcile(t)
			}
		} else {
			w.reconcile(t)
		}
		if stop != nil && stop() {
			return
		}
	}
}

func (w *sweptAccessWorld) attachedPolicies(t *testing.T) []string {
	t.Helper()
	w.remote.mu.Lock()
	defer w.remote.mu.Unlock()
	application := w.remote.applications[w.stored(t).Status.ApplicationID]
	ids := make([]string, 0, len(application.Policies))
	for _, policy := range application.Policies {
		ids = append(ids, policy.ID)
	}
	slices.Sort(ids)
	return ids
}

// detachPolicyOutOfBand removes one policy from the remote application the
// way a dashboard edit would, without touching Kubernetes.
func (w *sweptAccessWorld) detachPolicyOutOfBand(t *testing.T, id string) {
	t.Helper()
	w.remote.mu.Lock()
	defer w.remote.mu.Unlock()
	appID := w.stored(t).Status.ApplicationID
	application := w.remote.applications[appID]
	application.Policies = slices.DeleteFunc(slices.Clone(application.Policies), func(policy flarecloudflare.AccessApplicationPolicy) bool {
		return policy.ID == id
	})
	w.remote.applications[appID] = application
}

// With a healthy sweep, a converged application never reads Cloudflare
// itself: every listing confirms its content and keeps the gate open, so its
// own TTL wake-ups are free. Cloudflare traffic then no longer grows with the
// number of objects.
func TestSweepConfirmationReplacesPerObjectVerify(t *testing.T) {
	world := newSweptAccessWorld(t)
	// The first TTL may still end in the object's own verify when no sweep
	// pass has confirmed it yet; after that it must stay quiet.
	world.runUntil(t, world.now.Add(2*world.sweepEvery), nil)
	world.remoteReads = 0
	world.counter.writes = 0

	world.runUntil(t, world.now.Add(time.Hour), nil)
	if world.remoteReads != 0 {
		t.Fatalf("a sweep-confirmed application still made %d Cloudflare calls in one hour", world.remoteReads)
	}
	if world.counter.writes != 0 {
		t.Fatalf("a sweep-confirmed application wrote status %d times", world.counter.writes)
	}

	// Without the sweep, confirmations stop and the object's own verify
	// comes back within the confirmation window.
	world.sweeping = false
	window := world.reconciler.Freshness.SweepConfirmationWindow(freshness.GradeAuthz)
	world.runUntil(t, world.now.Add(window+time.Second), nil)
	if world.remoteReads == 0 {
		t.Fatal("with the sweep stopped, the application never re-verified itself")
	}
}

// G3: a policy removed out of band must be detected and restored in bounded
// time. With the sweep running that is the next sweep pass; with the sweep
// stopped it is the object's own verify at the end of the confirmation window.
func TestOutOfBandPolicyRemovalIsDetectedWithinBound(t *testing.T) {
	want := []string{accessFreshnessPolicyA, accessFreshnessPolicyB}
	for _, tc := range []struct {
		name     string
		sweeping bool
		bound    func(world *sweptAccessWorld) time.Duration
	}{
		{
			name:     "sweep running",
			sweeping: true,
			bound:    func(world *sweptAccessWorld) time.Duration { return world.sweepEvery },
		},
		{
			name:     "sweep stopped",
			sweeping: false,
			bound: func(world *sweptAccessWorld) time.Duration {
				return world.reconciler.Freshness.SweepConfirmationWindow(freshness.GradeAuthz)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			world := newSweptAccessWorld(t)
			world.runUntil(t, world.now.Add(2*world.sweepEvery), nil)
			if got := world.attachedPolicies(t); !slices.Equal(got, want) {
				t.Fatalf("fixture policies = %v, want %v", got, want)
			}

			world.sweeping = tc.sweeping
			world.detachPolicyOutOfBand(t, accessFreshnessPolicyB)
			removedAt := world.now
			bound := tc.bound(world)
			world.runUntil(t, removedAt.Add(bound+time.Second), func() bool {
				return slices.Equal(world.attachedPolicies(t), want)
			})
			if got := world.attachedPolicies(t); !slices.Equal(got, want) {
				t.Fatalf("policy removed out of band was not restored within %v: remote has %v", bound, got)
			}
			if elapsed := world.now.Sub(removedAt); elapsed > bound {
				t.Fatalf("restored after %v, bound is %v", elapsed, bound)
			}
			if world.latch.IsInvalidated("AccessApplication", world.request.NamespacedName) {
				t.Fatal("the repair pass did not release the invalidation")
			}
		})
	}
}

// A reusable policy deleted out of band disappears from the application's
// embedded policies. The sweep must treat that as drift, and the re-verify
// must then fail closed on the missing reference.
func TestDeletedExternalPolicyIsDriftForTheSweep(t *testing.T) {
	world := newSweptAccessWorld(t)
	world.runUntil(t, world.now.Add(2*world.sweepEvery), nil)

	world.deletePolicy(accessFreshnessPolicyB)
	if !world.sweep(t) {
		t.Fatal("a listing whose attached policy no longer exists was confirmed")
	}
	world.reconcile(t)
	programmed := meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Reason != "TargetNotFound" || programmed.Status == "True" {
		t.Fatalf("Programmed = %+v, want False/TargetNotFound", programmed)
	}
}
