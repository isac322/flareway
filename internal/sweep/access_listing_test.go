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
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/test/cfstub"
)

// accessApplicationTarget is the real AccessApplication sweep target.
func accessApplicationTarget() TargetDescriptor {
	grade, ok := freshness.GradeForKind("AccessApplication")
	if !ok {
		panic("AccessApplication has no freshness grade")
	}
	return TargetDescriptor{Kind: "AccessApplication", Grade: grade, SweepFunc: sweepAccessApplications}
}

// An AccessApplication that references identity providers is confirmed from
// the application listing together with the provider listing taken in the
// same pass. If either listing is incomplete the pass proves nothing, so it
// must not count as a fresh verify, however permissive the matcher is.
func TestAccessApplicationPartialListingNeverConfirms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// fail reports whether the proxy answers this request with a 5xx.
		fail func(r *http.Request) bool
		// failedPath must have been requested when fail is set.
		failedPath string
	}{
		{name: "complete listing confirms"},
		{
			name: "identity provider listing fails",
			fail: func(r *http.Request) bool {
				return r.URL.Path == "/accounts/account-1/access/identity_providers"
			},
			failedPath: "/accounts/account-1/access/identity_providers",
		},
		{
			name: "application listing fails mid-pagination",
			fail: func(r *http.Request) bool {
				return r.URL.Path == "/accounts/account-1/access/apps" && r.URL.Query().Get("page") == "2"
			},
			failedPath: "/accounts/account-1/access/apps?page=2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			stub := cfstub.New(t)
			api := flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(stub.URL)).Client("token", "account-1")
			provider, err := api.CreateIdentityProvider(ctx, flarecloudflare.IdentityProviderInput{
				Name: "otp", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
			})
			if err != nil {
				t.Fatalf("seed identity provider: %v", err)
			}

			key := types.NamespacedName{Namespace: "tenant", Name: "app"}
			const uid = "app-uid"
			markers := accessOwnerMarkers(probeOwnershipKey, probeClusterID, key.Namespace, key.Name, uid)
			stub.State.AddAccessApplication("account-1", cfstub.AccessResource{
				"id": "app-1", "name": "tenant/app", "type": "self_hosted", "domain": "app.example.com",
				"tags": []string{accessManagedTag, markers[0]},
			})
			application := &v1alpha1.AccessApplication{
				ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: uid},
				Spec: v1alpha1.AccessApplicationSpec{
					AccountRef: corev1.LocalObjectReference{Name: probeAccountName},
					Type:       v1alpha1.AccessApplicationTypeSelfHosted,
					Application: v1alpha1.AccessApplicationSettings{
						Name:           "tenant/app",
						AllowedIDPRefs: []v1alpha1.AccessIdentityProviderReference{{ExternalID: provider.ID}},
					},
					ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				},
				Status: v1alpha1.AccessApplicationStatus{ApplicationID: "app-1"},
			}

			upstream, err := url.Parse(stub.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(upstream)
			var mu sync.Mutex
			failed := 0
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && tc.fail != nil && tc.fail(r) {
					mu.Lock()
					failed++
					mu.Unlock()
					cfstub.WriteError(w, http.StatusInternalServerError, 10000, "injected listing failure")
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			t.Cleanup(front.Close)

			fixture := newDNSProbeFixture(t, dnsProbeConfig{objects: []client.Object{application, probeAccount([]string{"*"})}})
			latch := freshness.NewLatch()
			sweeper := NewAccountSweeper(AccountSweeperOptions{
				AccountName:       probeAccountName,
				AccountID:         "account-1",
				Token:             "token",
				Factory:           flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(front.URL)),
				Client:            fixture.kube,
				APIReader:         fixture.kube,
				Invalidator:       latch,
				OperatorNamespace: probeOperatorNamespace,
				RateLimit:         1e9,
				RateBurst:         1,
				Logger:            logr.Discard(),
			})
			var matched []flarecloudflare.AccessApplicationListing
			latch.SetBaseline("AccessApplication", key, "h1", func(observed any) bool {
				listing, ok := observed.(flarecloudflare.AccessApplicationListing)
				if ok {
					matched = append(matched, listing)
				}
				return ok
			})

			items, result, err := sweeper.RunTargetOnce(ctx, accessApplicationTarget())
			_, confirmed := latch.ConfirmedAt("AccessApplication", key, "h1")
			if tc.fail == nil {
				if err != nil || result != observability.SweepResultOK || len(items) != 0 {
					t.Fatalf("clean pass = %v, %q, %v; want ok with no drift", items, result, err)
				}
				if !confirmed {
					t.Fatal("a complete listing did not confirm the application")
				}
				if len(matched) != 1 || matched[0].Application.ID != "app-1" {
					t.Fatalf("matcher saw %#v, want the listed application once", matched)
				}
				if _, listed := matched[0].IdentityProviders[provider.ID]; !listed {
					t.Fatalf("matcher listing lacks the referenced provider: %#v", matched[0].IdentityProviders)
				}
				return
			}
			mu.Lock()
			injected := failed
			mu.Unlock()
			if injected == 0 {
				t.Fatalf("the fault on %s was never hit", tc.failedPath)
			}
			if result == observability.SweepResultOK {
				t.Fatalf("pass with a failed listing reported ok (items=%v)", items)
			}
			if len(items) != 0 {
				t.Fatalf("pass with a failed listing judged %v", items)
			}
			if confirmed || len(matched) != 0 {
				t.Fatalf("pass with a failed listing confirmed the application (matcher calls %d)", len(matched))
			}
		})
	}
}

func TestAccessSweepIsolatesZoneForbiddenPreservingAccountAndPermittedZones(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		target         TargetDescriptor
		deniedZonePath string
		objects        func() []client.Object
		wantDriftKeys  []types.NamespacedName
	}{
		{
			name:           "AccessApplication",
			target:         accessApplicationTarget(),
			deniedZonePath: "/zones/zone-denied/access/apps",
			wantDriftKeys: []types.NamespacedName{
				{Namespace: "tenant", Name: "acct-app"},
				{Namespace: "tenant", Name: "ok-zone-app"},
			},
			objects: func() []client.Object {
				return []client.Object{
					&v1alpha1.AccessApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "acct-app", UID: "uid-acct"},
						Spec: v1alpha1.AccessApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Type:             v1alpha1.AccessApplicationTypeSelfHosted,
							Application:      v1alpha1.AccessApplicationSettings{Name: "acct-app"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-acct-app"},
					},
					&v1alpha1.AccessApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "ok-zone-app", UID: "uid-ok"},
						Spec: v1alpha1.AccessApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "ok.example.com",
							Type:             v1alpha1.AccessApplicationTypeSelfHosted,
							Application:      v1alpha1.AccessApplicationSettings{Name: "ok-zone-app"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-ok-app"},
					},
					&v1alpha1.AccessApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "denied-zone-app", UID: "uid-denied"},
						Spec: v1alpha1.AccessApplicationSpec{
							AccountRef: corev1.LocalObjectReference{Name: probeAccountName},
							Zone:       "denied.example.com",
							Type:       v1alpha1.AccessApplicationTypeSelfHosted,
							Application: v1alpha1.AccessApplicationSettings{
								Name:           "denied-zone-app",
								AllowedIDPRefs: []v1alpha1.AccessIdentityProviderReference{{ExternalID: "idp-missing"}},
							},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-denied-app"},
					},
				}
			},
		},
		{
			name: "AccessStandaloneApplication",
			target: TargetDescriptor{
				Kind:      "AccessStandaloneApplication",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepAccessStandaloneApplications,
			},
			deniedZonePath: "/zones/zone-denied/access/apps",
			wantDriftKeys: []types.NamespacedName{
				{Namespace: "tenant", Name: "acct-sa"},
				{Namespace: "tenant", Name: "ok-zone-sa"},
			},
			objects: func() []client.Object {
				return []client.Object{
					&v1alpha1.AccessStandaloneApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "acct-sa", UID: "uid-acct-sa"},
						Spec: v1alpha1.AccessStandaloneApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Type:             v1alpha1.AccessStandaloneApplicationTypeBookmark,
							Application:      v1alpha1.AccessApplicationSettings{Name: "acct-sa"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessStandaloneApplicationStatus{ApplicationID: "remote-acct-sa"},
					},
					&v1alpha1.AccessStandaloneApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "ok-zone-sa", UID: "uid-ok-sa"},
						Spec: v1alpha1.AccessStandaloneApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "ok.example.com",
							Type:             v1alpha1.AccessStandaloneApplicationTypeBookmark,
							Application:      v1alpha1.AccessApplicationSettings{Name: "ok-zone-sa"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessStandaloneApplicationStatus{ApplicationID: "remote-ok-sa"},
					},
					&v1alpha1.AccessStandaloneApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "denied-zone-sa", UID: "uid-denied-sa"},
						Spec: v1alpha1.AccessStandaloneApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "denied.example.com",
							Type:             v1alpha1.AccessStandaloneApplicationTypeBookmark,
							Application:      v1alpha1.AccessApplicationSettings{Name: "denied-zone-sa"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessStandaloneApplicationStatus{ApplicationID: "remote-denied-sa"},
					},
				}
			},
		},
		{
			name: "AccessGroup",
			target: TargetDescriptor{
				Kind:      "AccessGroup",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepAccessGroups,
			},
			deniedZonePath: "/zones/zone-denied/access/groups",
			wantDriftKeys: []types.NamespacedName{
				{Namespace: "tenant", Name: "acct-grp"},
				{Namespace: "tenant", Name: "ok-zone-grp"},
			},
			objects: func() []client.Object {
				return []client.Object{
					&v1alpha1.AccessGroup{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "acct-grp", UID: "uid-acct-grp"},
						Spec: v1alpha1.AccessGroupSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Name:             "acct-grp",
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessGroupStatus{GroupID: "remote-acct-grp"},
					},
					&v1alpha1.AccessGroup{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "ok-zone-grp", UID: "uid-ok-grp"},
						Spec: v1alpha1.AccessGroupSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "ok.example.com",
							Name:             "ok-zone-grp",
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessGroupStatus{GroupID: "remote-ok-grp"},
					},
					&v1alpha1.AccessGroup{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "denied-zone-grp", UID: "uid-denied-grp"},
						Spec: v1alpha1.AccessGroupSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "denied.example.com",
							Name:             "denied-zone-grp",
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessGroupStatus{GroupID: "remote-denied-grp"},
					},
				}
			},
		},
		{
			name: "ServiceToken",
			target: TargetDescriptor{
				Kind:      "ServiceToken",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepServiceTokens,
			},
			deniedZonePath: "/zones/zone-denied/access/service_tokens",
			wantDriftKeys: []types.NamespacedName{
				{Namespace: "tenant", Name: "acct-st"},
				{Namespace: "tenant", Name: "ok-zone-st"},
			},
			objects: func() []client.Object {
				return []client.Object{
					&v1alpha1.ServiceToken{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "acct-st", UID: "uid-acct-st"},
						Spec: v1alpha1.ServiceTokenSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Name:             "acct-st",
							SecretRef:        corev1.LocalObjectReference{Name: "acct-st-secret"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.ServiceTokenStatus{TokenID: "remote-acct-st"},
					},
					&v1alpha1.ServiceToken{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "ok-zone-st", UID: "uid-ok-st"},
						Spec: v1alpha1.ServiceTokenSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "ok.example.com",
							Name:             "ok-zone-st",
							SecretRef:        corev1.LocalObjectReference{Name: "ok-st-secret"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.ServiceTokenStatus{TokenID: "remote-ok-st"},
					},
					&v1alpha1.ServiceToken{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "denied-zone-st", UID: "uid-denied-st"},
						Spec: v1alpha1.ServiceTokenSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             "denied.example.com",
							Name:             "denied-zone-st",
							SecretRef:        corev1.LocalObjectReference{Name: "denied-st-secret"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.ServiceTokenStatus{TokenID: "remote-denied-st"},
					},
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			stub := cfstub.New(t)
			stub.State.AddZone(cfstub.Zone{ID: "zone-denied", Name: "denied.example.com", AccountID: "account-1"})
			stub.State.AddZone(cfstub.Zone{ID: "zone-ok", Name: "ok.example.com", AccountID: "account-1"})
			stub.Fault(http.MethodGet, "^"+tc.deniedZonePath+"$", cfstub.Fault{Status: http.StatusForbidden, Times: -1})

			objs := append(tc.objects(), probeAccount([]string{"*"}))
			fixture := newDNSProbeFixture(t, dnsProbeConfig{objects: objs})
			sweeper := NewAccountSweeper(AccountSweeperOptions{
				AccountName:       probeAccountName,
				AccountID:         "account-1",
				Token:             "token",
				Factory:           flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(stub.URL)),
				Client:            fixture.kube,
				APIReader:         fixture.kube,
				OperatorNamespace: probeOperatorNamespace,
				RateLimit:         1e9,
				RateBurst:         1,
				Logger:            logr.Discard(),
			})

			items, result, err := sweeper.RunTargetOnce(ctx, tc.target)
			if result != observability.SweepResultPartial {
				t.Fatalf("result = %q, want %q (err=%v)", result, observability.SweepResultPartial, err)
			}
			var scoped *scopedListingError
			if !errors.As(err, &scoped) {
				t.Fatalf("err = %v, want *scopedListingError", err)
			}
			if len(items) != len(tc.wantDriftKeys) {
				t.Fatalf("items = %#v, want %d missing items (%v)", items, len(tc.wantDriftKeys), tc.wantDriftKeys)
			}
			got := make(map[types.NamespacedName]DriftCase, len(items))
			for _, item := range items {
				got[item.NamespacedName] = item.Case
			}
			for _, wantKey := range tc.wantDriftKeys {
				if got[wantKey] != DriftCaseMissing {
					t.Fatalf("missing drift for %s in %#v", wantKey, items)
				}
			}
		})
	}
}

func TestAccessSweepCrossScopeSkipsJudgementWhenRecordedScopeUnlisted(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		target         TargetDescriptor
		deniedZonePath string
		specZone       string
		objects        func(specZone string) []client.Object
	}{
		{
			name:           "AccessApplication_cross_zone",
			target:         accessApplicationTarget(),
			deniedZonePath: "/zones/zone-denied/access/apps",
			specZone:       "ok.example.com",
			objects: func(specZone string) []client.Object {
				return []client.Object{
					&v1alpha1.AccessApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "cross-app", UID: "uid-cross-app"},
						Spec: v1alpha1.AccessApplicationSpec{
							AccountRef: corev1.LocalObjectReference{Name: probeAccountName},
							Zone:       specZone,
							Type:       v1alpha1.AccessApplicationTypeSelfHosted,
							Application: v1alpha1.AccessApplicationSettings{
								Name:           "cross-app",
								AllowedIDPRefs: []v1alpha1.AccessIdentityProviderReference{{ExternalID: "idp-missing"}},
								CustomPageRefs: []v1alpha1.AccessCustomPageReference{{ExternalID: "page-missing"}},
							},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-cross-app", ZoneID: "zone-denied"},
					},
				}
			},
		},
		{
			name:           "AccessApplication_to_account",
			target:         accessApplicationTarget(),
			deniedZonePath: "/zones/zone-denied/access/apps",
			specZone:       "",
			objects: func(specZone string) []client.Object {
				return []client.Object{
					&v1alpha1.AccessApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "cross-acct-app", UID: "uid-cross-acct-app"},
						Spec: v1alpha1.AccessApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             specZone,
							Type:             v1alpha1.AccessApplicationTypeSelfHosted,
							Application:      v1alpha1.AccessApplicationSettings{Name: "cross-acct-app"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-cross-acct-app", ZoneID: "zone-denied"},
					},
				}
			},
		},
		{
			name: "AccessStandaloneApplication_cross_zone",
			target: TargetDescriptor{
				Kind:      "AccessStandaloneApplication",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepAccessStandaloneApplications,
			},
			deniedZonePath: "/zones/zone-denied/access/apps",
			specZone:       "ok.example.com",
			objects: func(specZone string) []client.Object {
				return []client.Object{
					&v1alpha1.AccessStandaloneApplication{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "cross-sa", UID: "uid-cross-sa"},
						Spec: v1alpha1.AccessStandaloneApplicationSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             specZone,
							Type:             v1alpha1.AccessStandaloneApplicationTypeBookmark,
							Application:      v1alpha1.AccessApplicationSettings{Name: "cross-sa"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessStandaloneApplicationStatus{ApplicationID: "remote-cross-sa", ZoneID: "zone-denied"},
					},
				}
			},
		},
		{
			name: "AccessGroup_cross_zone",
			target: TargetDescriptor{
				Kind:      "AccessGroup",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepAccessGroups,
			},
			deniedZonePath: "/zones/zone-denied/access/groups",
			specZone:       "ok.example.com",
			objects: func(specZone string) []client.Object {
				return []client.Object{
					&v1alpha1.AccessGroup{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "cross-grp", UID: "uid-cross-grp"},
						Spec: v1alpha1.AccessGroupSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             specZone,
							Name:             "cross-grp",
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.AccessGroupStatus{GroupID: "remote-cross-grp", ZoneID: "zone-denied"},
					},
				}
			},
		},
		{
			name: "ServiceToken_cross_zone",
			target: TargetDescriptor{
				Kind:      "ServiceToken",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepServiceTokens,
			},
			deniedZonePath: "/zones/zone-denied/access/service_tokens",
			specZone:       "ok.example.com",
			objects: func(specZone string) []client.Object {
				return []client.Object{
					&v1alpha1.ServiceToken{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "cross-st", UID: "uid-cross-st"},
						Spec: v1alpha1.ServiceTokenSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Zone:             specZone,
							Name:             "cross-st",
							SecretRef:        corev1.LocalObjectReference{Name: "cross-st-secret"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.ServiceTokenStatus{TokenID: "remote-cross-st", ZoneID: "zone-denied"},
					},
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			stub := cfstub.New(t)
			stub.State.AddZone(cfstub.Zone{ID: "zone-denied", Name: "denied.example.com", AccountID: "account-1"})
			stub.State.AddZone(cfstub.Zone{ID: "zone-ok", Name: "ok.example.com", AccountID: "account-1"})
			stub.Fault(http.MethodGet, "^"+tc.deniedZonePath+"$", cfstub.Fault{Status: http.StatusForbidden, Times: -1})

			var refCalls int
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/accounts/account-1/access/identity_providers" || r.URL.Path == "/accounts/account-1/access/custom_pages" {
					refCalls++
				}
				target, _ := url.Parse(stub.URL)
				httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
			}))
			defer proxy.Close()

			objs := append(tc.objects(tc.specZone), probeAccount([]string{"*"}))
			fixture := newDNSProbeFixture(t, dnsProbeConfig{objects: objs})
			latch := freshness.NewLatch()
			key := types.NamespacedName{Namespace: "tenant", Name: tc.objects(tc.specZone)[0].GetName()}
			if tc.target.Kind == "AccessApplication" {
				latch.SetBaseline("AccessApplication", key, "h1", func(any) bool { return true })
			}
			sweeper := NewAccountSweeper(AccountSweeperOptions{
				AccountName:       probeAccountName,
				AccountID:         "account-1",
				Token:             "token",
				Factory:           flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(proxy.URL)),
				Client:            fixture.kube,
				APIReader:         fixture.kube,
				Invalidator:       latch,
				OperatorNamespace: probeOperatorNamespace,
				RateLimit:         1e9,
				RateBurst:         1,
				Logger:            logr.Discard(),
			})

			items, result, err := sweeper.RunTargetOnce(ctx, tc.target)
			if result != observability.SweepResultPartial {
				t.Fatalf("result = %q, want %q (err=%v)", result, observability.SweepResultPartial, err)
			}
			if len(items) != 0 {
				t.Fatalf("cross-scope CR touching unlisted recordedScope produced unexpected drift: %#v", items)
			}
			if refCalls != 0 {
				t.Fatalf("expected 0 provider/page reference list calls when only ineligible cross-scope app referenced them, got %d", refCalls)
			}
			if _, confirmed := latch.ConfirmedAt("AccessApplication", key, "h1"); confirmed {
				t.Fatal("cross-scope AccessApplication with unlisted recordedScope must not confirm")
			}
		})
	}
}

func TestAccessSweepFailsClosedOnAccountOrNonIsolatableZoneError(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   string
		status int
	}{
		{name: "account_scope_403_aborts", path: "/accounts/account-1/access/service_tokens", status: http.StatusForbidden},
		{name: "zone_401_aborts", path: "/zones/zone-1/access/service_tokens", status: http.StatusUnauthorized},
		{name: "zone_429_aborts", path: "/zones/zone-1/access/service_tokens", status: http.StatusTooManyRequests},
		{name: "zone_400_aborts", path: "/zones/zone-1/access/service_tokens", status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			stub := cfstub.New(t)
			stub.State.AddZone(cfstub.Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
			stub.Fault(http.MethodGet, "^"+tc.path+"$", cfstub.Fault{Status: tc.status, Times: -1})

			fixture := newDNSProbeFixture(t, dnsProbeConfig{
				objects: []client.Object{
					probeAccount([]string{"*"}),
					&v1alpha1.ServiceToken{
						ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "acct-st", UID: "uid-acct-st"},
						Spec: v1alpha1.ServiceTokenSpec{
							AccountRef:       corev1.LocalObjectReference{Name: probeAccountName},
							Name:             "acct-st",
							SecretRef:        corev1.LocalObjectReference{Name: "acct-st-secret"},
							ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						},
						Status: v1alpha1.ServiceTokenStatus{TokenID: "remote-acct-st"},
					},
				},
			})
			sweeper := NewAccountSweeper(AccountSweeperOptions{
				AccountName:       probeAccountName,
				AccountID:         "account-1",
				Token:             "token",
				Factory:           flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(stub.URL), flarecloudflare.WithRequestOptions(option.WithMaxRetries(0))),
				Client:            fixture.kube,
				APIReader:         fixture.kube,
				OperatorNamespace: probeOperatorNamespace,
				RateLimit:         1e9,
				RateBurst:         1,
				Logger:            logr.Discard(),
			})

			items, result, err := sweeper.RunTargetOnce(ctx, TargetDescriptor{
				Kind:      "ServiceToken",
				Grade:     freshness.GradeAuthz,
				SweepFunc: sweepServiceTokens,
			})
			if result != observability.SweepResultError {
				t.Fatalf("result = %q, want %q (err=%v, items=%v)", result, observability.SweepResultError, err, items)
			}
			var scoped *scopedListingError
			if errors.As(err, &scoped) || len(items) != 0 {
				t.Fatalf("non-isolatable error must abort fail-closed: items=%v err=%v", items, err)
			}
		})
	}
}

func TestListAccessScopedClassification(t *testing.T) {
	t.Parallel()

	t.Run("isolates_zone_404_500_and_transport_errors", func(t *testing.T) {
		t.Parallel()
		scopes := []flarecloudflare.AccessScope{
			{},
			{ZoneID: "z-404"},
			{ZoneID: "z-500"},
			{ZoneID: "z-net"},
			{ZoneID: "z-ok"},
		}
		_, listed, err := listAccessScoped(context.Background(), scopes, func(context.Context) error { return nil },
			func(_ context.Context, scope flarecloudflare.AccessScope) ([]string, error) {
				switch scope.ZoneID {
				case "z-404":
					return nil, deniedZoneError(errors.New("gone"), http.StatusNotFound)
				case "z-500":
					return nil, deniedZoneError(errors.New("upstream"), http.StatusInternalServerError)
				case "z-net":
					return nil, errors.New("connection reset by peer")
				default:
					return []string{scope.ZoneID}, nil
				}
			})
		var scoped *scopedListingError
		if !errors.As(err, &scoped) {
			t.Fatalf("err = %v, want *scopedListingError", err)
		}
		if !listed[""] || !listed["z-ok"] || listed["z-404"] || listed["z-500"] || listed["z-net"] {
			t.Fatalf("unexpected listed scope map: %#v", listed)
		}
	})

	t.Run("rate_limit_wait_and_cancel_return_SweepResultError_not_partial", func(t *testing.T) {
		t.Parallel()
		for _, injectErr := range []error{
			fmt.Errorf("%w: wait exceeded", flarecloudflare.ErrRateLimitWait),
			context.DeadlineExceeded,
		} {
			fixture := newDNSProbeFixture(t, dnsProbeConfig{objects: []client.Object{probeAccount([]string{"*"})}})
			sweeper := NewAccountSweeper(AccountSweeperOptions{
				AccountName: probeAccountName,
				AccountID:   "account-1",
				Client:      fixture.kube,
				APIReader:   fixture.kube,
				Logger:      logr.Discard(),
			})
			_, result, err := sweeper.RunTargetOnce(context.Background(), TargetDescriptor{
				Kind:  "ServiceToken",
				Grade: freshness.GradeAuthz,
				SweepFunc: func(ctx context.Context, _ *AccountSweeper) ([]DriftItem, error) {
					_, _, listErr := listAccessScoped(ctx, []flarecloudflare.AccessScope{{}, {ZoneID: "z-1"}},
						func(context.Context) error { return nil },
						func(_ context.Context, scope flarecloudflare.AccessScope) ([]string, error) {
							if scope.ZoneID == "z-1" {
								return nil, injectErr
							}
							return nil, nil
						})
					return nil, listErr
				},
			})
			if result != observability.SweepResultError {
				t.Fatalf("err=%v produced result=%q, want %q", injectErr, result, observability.SweepResultError)
			}
			var scoped *scopedListingError
			if errors.As(err, &scoped) || errors.Is(err, errIncompleteListing) {
				t.Fatalf("err=%v was wrapped as partial: %v", injectErr, err)
			}
		}
	})
}
