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
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"

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
