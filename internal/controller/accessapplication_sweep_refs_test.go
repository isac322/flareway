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
	"maps"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
)

// The bypass expectation a converged pass returns is what the sweep checks
// against its application listing in place of re-reading every child. It must
// hold for exactly the state the pass left behind: any out-of-band change to a
// child, a deleted child, or a stray application carrying this owner's bypass
// marker (which the next pass would prune) must break it.
func TestBypassExpectationFollowsListing(t *testing.T) {
	ctx := context.Background()
	ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "parent"},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Type:             v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
			Application:      v1alpha1.AccessApplicationSettings{Name: "tenant/parent"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := accessApplicationTestClientBuilder(scheme).
		WithStatusSubresource(&v1alpha1.AccessApplication{}).
		WithObjects(application.DeepCopy()).
		Build()
	reconciler := &AccessApplicationReconciler{Client: kube, Scheme: scheme}
	remote := newFakeAccessApplicationCloudflare()
	bypasses := []gatewayapi.AccessBypass{
		{Hostname: "api.example.test", Path: "/a"},
		{Hostname: "api.example.test", Path: "/b"},
		{Hostname: "api.example.test", Path: "/c"},
	}

	children, expectation, err := reconciler.reconcileBypassApplications(
		ctx, remote, flarecloudflare.AccessScope{}, application, bypasses, ownerTag, "cluster",
	)
	if err != nil {
		t.Fatalf("bypass reconcile: %v", err)
	}
	if len(children) != len(bypasses) {
		t.Fatalf("bypass children = %#v, want %d", children, len(bypasses))
	}
	listed := func() map[string]flarecloudflare.AccessApplication {
		t.Helper()
		applications, err := remote.ListAccessApplications(ctx, flarecloudflare.AccessScope{})
		if err != nil {
			t.Fatalf("list applications: %v", err)
		}
		result := make(map[string]flarecloudflare.AccessApplication, len(applications))
		for _, listedApplication := range applications {
			result[listedApplication.ID] = listedApplication
		}
		return result
	}
	if !expectation.matches(listed()) {
		t.Fatal("the expectation of a converged pass does not match the listing it produced")
	}

	converged := func() map[string]flarecloudflare.AccessApplication {
		remote.mu.Lock()
		defer remote.mu.Unlock()
		return maps.Clone(remote.applications)
	}()
	childID := children[1].ApplicationID
	for _, tc := range []struct {
		name   string
		mutate func(applications map[string]flarecloudflare.AccessApplication)
		want   bool
	}{
		{
			name: "child domain changed out of band",
			mutate: func(applications map[string]flarecloudflare.AccessApplication) {
				child := applications[childID]
				child.Domain = "api.example.test/elsewhere"
				applications[childID] = child
			},
		},
		{
			name: "child policy replaced out of band",
			mutate: func(applications map[string]flarecloudflare.AccessApplication) {
				child := applications[childID]
				child.Policies = []flarecloudflare.AccessApplicationPolicy{{ID: "policy-allow", Precedence: 1}}
				applications[childID] = child
			},
		},
		{
			name: "child deleted out of band",
			mutate: func(applications map[string]flarecloudflare.AccessApplication) {
				delete(applications, childID)
			},
		},
		{
			name: "stray application carries this owner's bypass marker",
			mutate: func(applications map[string]flarecloudflare.AccessApplication) {
				name := "tenant/parent/stale"
				applications["stray"] = flarecloudflare.AccessApplication{
					ID: "stray", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Name: name,
					Domain: "api.example.test/stale",
					Tags:   []string{accessManagedTag, accessBypassTag(ownerTag, name), ownerTag},
				}
			},
		},
		{
			name: "unrelated application appears",
			mutate: func(applications map[string]flarecloudflare.AccessApplication) {
				applications["foreign"] = flarecloudflare.AccessApplication{
					ID: "foreign", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Name: "someone/else",
					Domain: "api.example.test/foreign",
					Tags:   []string{accessManagedTag, accessBypassTag(accessDigestTag(accessOwnerTagPrefix, "other"), "someone/else")},
				}
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote.mu.Lock()
			remote.applications = maps.Clone(converged)
			tc.mutate(remote.applications)
			remote.mu.Unlock()
			if got := expectation.matches(listed()); got != tc.want {
				t.Fatalf("expectation matches = %v, want %v", got, tc.want)
			}
		})
	}

	var observeOnly *bypassExpectation
	remote.mu.Lock()
	remote.applications = maps.Clone(converged)
	remote.mu.Unlock()
	if observeOnly.matches(listed()) {
		t.Fatal("a nil expectation matched a listing")
	}
}

const (
	sweepRefsIdentityProvider = "idp-external"
	sweepRefsCustomPage       = "page-external"
)

// newSweptAccessWorldWith is newSweptAccessWorld for a fixture whose spec and
// remote state are prepared before it converges.
func newSweptAccessWorldWith(t *testing.T, configure func(*v1alpha1.AccessApplication), prepare func(*accessFreshnessWorld)) *sweptAccessWorld {
	t.Helper()
	world := newAccessFreshnessWorld(t, configure)
	prepare(world)
	result := world.converge(t)
	ttl := world.reconciler.Freshness.TTL(freshness.GradeAuthz)
	return &sweptAccessWorld{
		accessFreshnessWorld: world,
		latch:                world.reconciler.Invalidator,
		sweepEvery:           ttl + ttl/5,
		sweeping:             true,
		nextSweep:            world.now.Add(time.Second),
		nextWake:             world.now.Add(result.RequeueAfter),
	}
}

// requireReferenceDeletionDetectedByNextSweep checks both sides of the sweep
// contract for a referenced Cloudflare object: while it exists the sweep keeps
// the application free of its own Cloudflare reads, and once it is deleted the
// next sweep pass reports drift and the woken reconcile fails closed.
func requireReferenceDeletionDetectedByNextSweep(t *testing.T, world *sweptAccessWorld, remove func()) {
	t.Helper()
	world.runUntil(t, world.now.Add(2*world.sweepEvery), nil)
	world.remoteReads = 0
	world.runUntil(t, world.now.Add(time.Hour), nil)
	if world.remoteReads != 0 {
		t.Fatalf("a sweep-confirmed application with the reference intact made %d Cloudflare calls in one hour", world.remoteReads)
	}

	remove()
	removedAt := world.now
	sweepAt := world.nextSweep
	bound := world.sweepEvery
	programmedFalse := func() bool {
		programmed := meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed)
		return programmed != nil && programmed.Status == metav1.ConditionFalse
	}
	world.runUntil(t, removedAt.Add(bound), programmedFalse)
	programmed := meta.FindStatusCondition(world.stored(t).Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "TargetNotFound" {
		t.Fatalf("Programmed %v after the reference was deleted = %+v, want False/TargetNotFound", bound, programmed)
	}
	if !world.now.Equal(sweepAt) {
		t.Fatalf("drift surfaced at %v, want the next sweep pass at %v", world.now.Sub(removedAt), sweepAt.Sub(removedAt))
	}
	if elapsed := world.now.Sub(removedAt); elapsed > bound {
		t.Fatalf("drift surfaced after %v, bound is %v", elapsed, bound)
	}
}

// G3: an identity provider the application allows is part of what a sweep
// confirmation vouches for. Deleting it out of band must be drift for the
// next sweep, not something only the object's own verify finds.
func TestSweepDetectsDeletedIdentityProviderWithinBound(t *testing.T) {
	world := newSweptAccessWorldWith(t,
		func(application *v1alpha1.AccessApplication) {
			application.Spec.Application.AllowedIDPRefs = []v1alpha1.AccessIdentityProviderReference{{ExternalID: sweepRefsIdentityProvider}}
		},
		func(world *accessFreshnessWorld) {
			world.remote.mu.Lock()
			world.remote.providers[sweepRefsIdentityProvider] = flarecloudflare.IdentityProvider{
				ID: sweepRefsIdentityProvider, Name: "otp", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
			}
			world.remote.mu.Unlock()
		},
	)
	requireReferenceDeletionDetectedByNextSweep(t, world, func() {
		world.remote.mu.Lock()
		defer world.remote.mu.Unlock()
		delete(world.remote.providers, sweepRefsIdentityProvider)
	})
}

// G3: the same holds for a referenced custom page.
func TestSweepDetectsDeletedCustomPageWithinBound(t *testing.T) {
	world := newSweptAccessWorldWith(t,
		func(application *v1alpha1.AccessApplication) {
			application.Spec.Application.CustomPageRefs = []v1alpha1.AccessCustomPageReference{{ExternalID: sweepRefsCustomPage}}
		},
		func(world *accessFreshnessWorld) {
			var account v1alpha1.CloudflareAccount
			if err := world.kube.Get(context.Background(), client.ObjectKey{Name: "account"}, &account); err != nil {
				t.Fatal(err)
			}
			account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
			if err := world.kube.Update(context.Background(), &account); err != nil {
				t.Fatal(err)
			}
			world.remote.SetCustomPage(flarecloudflare.AccessCustomPage{AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{
				ID: sweepRefsCustomPage, Name: "forbidden", Type: v1alpha1.AccessCustomPageTypeForbidden,
			}})
		},
	)
	requireReferenceDeletionDetectedByNextSweep(t, world, func() {
		world.remote.DeleteCustomPage(sweepRefsCustomPage)
	})
}
