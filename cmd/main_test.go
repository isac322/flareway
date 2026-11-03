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

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/sweep"
	"github.com/isac322/flareway/test/cfstub"
)

func TestProductionSweeperCompositionSelectsConfiguredGroups(t *testing.T) {
	gatewayRequests := []string{
		"/zones",
		"/zones/zone-1/dns_records",
		"/accounts/account-1/cfd_tunnel",
	}
	accessRequests := []string{
		"/zones",
		"/accounts/account-1/access/apps",
		"/zones/zone-1/access/apps",
		"/accounts/account-1/access/policies",
		"/accounts/account-1/access/groups",
		"/zones/zone-1/access/groups",
		"/accounts/account-1/access/service_tokens",
		"/zones/zone-1/access/service_tokens",
		"/accounts/account-1/access/identity_providers",
		"/accounts/account-1/access/custom_pages",
		"/accounts/account-1/infrastructure/targets",
		"/accounts/account-1/devices/posture",
		"/accounts/account-1/devices/posture/integration",
	}
	allRequests := append(append([]string{}, gatewayRequests...), accessRequests...)
	allRequests = append(allRequests,
		"/accounts/account-1/gateway/rules",
		"/accounts/account-1/gateway/lists",
		"/accounts/account-1/teamnet/virtual_networks",
		"/accounts/account-1/teamnet/routes",
		"/accounts/account-1/zerotrust/routes/hostname",
		"/accounts/account-1/devices/policies",
		"/accounts/account-1/warp_connector",
	)
	testCases := []struct {
		name   string
		groups sweep.ControllerGroups
		want   []string
	}{
		{name: "gateway only", groups: sweep.ControllerGroups{Gateway: true}, want: gatewayRequests},
		{name: "access only", groups: sweep.ControllerGroups{Access: true}, want: accessRequests},
		{
			name: "all enabled",
			groups: sweep.ControllerGroups{
				Gateway: true, Access: true, PrivateNetwork: true, Device: true, Organization: true,
			},
			want: allRequests,
		},
		{name: "all disabled"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stub := cfstub.New(t)
			stub.State.AddZone(cfstub.Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
			stub.State.Set("/accounts/account-1/devices/posture/integration", []cfstub.AccessResource{})
			// These list endpoints have no stateful cfstub implementation yet.
			for _, path := range []string{
				`^/accounts/[^/]+/access/custom_pages$`,
				`^/accounts/[^/]+/infrastructure/targets$`,
				`^/accounts/[^/]+/warp_connector$`,
			} {
				stub.Handle(http.MethodGet, path, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprint(w, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`)
				})
			}
			account := &v1alpha1.CloudflareAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "account"},
				Spec: v1alpha1.CloudflareAccountSpec{
					AccountID: "account-1",
					Credentials: v1alpha1.CloudflareAccountCredentials{
						APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
							Namespace: "operator", Name: "cloudflare-token", Key: "token",
						},
					},
					Grants: []v1alpha1.CloudflareAccountGrant{{Hostnames: []string{"*"}, Zones: []string{"*"}}},
				},
				Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
					{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue},
					{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue},
				}},
			}
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
				account,
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "cloudflare-token"},
					Data:       map[string][]byte{"token": []byte("test-token")},
				},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("test-cluster")}},
				&v1alpha1.CloudflareTunnel{
					ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "tunnel"},
					Spec: v1alpha1.CloudflareTunnelSpec{
						AccountRef:       corev1.LocalObjectReference{Name: account.Name},
						ManagementPolicy: v1alpha1.ManagementPolicyManaged,
					},
					Status: v1alpha1.CloudflareTunnelStatus{TunnelID: "missing-tunnel"},
				},
			).Build()
			requests := make(chan sweepResponse, 256)
			factory := flarecloudflare.NewFactory(logr.Discard(),
				flarecloudflare.WithBaseURL(stub.URL),
				// The sweeper and the SDK have separate limiters. Override both:
				// millisecond target loops otherwise compete for the SDK's
				// production account budget before every target gets a first pass.
				flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 1)),
				flarecloudflare.WithListLimiter(rate.NewLimiter(rate.Inf, 1)),
				flarecloudflare.WithRequestOptions(option.WithHTTPClient(&http.Client{
					Transport: sweepRequestRecorder{requests: requests},
				})),
			)
			// Exercise the same construction path as main, including account
			// discovery and timer-driven target execution. A short grade TTL
			// bounds initial jitter without continuously restarting every pass.
			worker := newProductionSweeper(tc.groups, sweep.SweeperOptions{
				Client:            kube,
				APIReader:         kube,
				Scheme:            scheme,
				CloudflareFactory: factory,
				Policy: freshness.Policy{
					Authz: 100 * time.Millisecond, Traffic: 100 * time.Millisecond,
					Indirect: 100 * time.Millisecond, Display: 100 * time.Millisecond,
				},
				Logger:         logr.Discard(),
				SweepRateLimit: 1e9,
				SweepRateBurst: 100,
			})
			if len(tc.want) == 0 {
				if worker != nil {
					t.Fatal("all-disabled production composition registered a worker")
				}
				if calls := stub.Journal(); len(calls) != 0 {
					t.Fatalf("all-disabled composition called Cloudflare: %v", calls)
				}
				return
			}
			if worker == nil {
				t.Fatal("enabled controllers have no drift sweeper")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if err := worker.Start(ctx); err != nil {
					t.Errorf("sweeper stopped with error: %v", err)
				}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("sweeper did not stop after cancellation")
				}
			})
			pending := make(map[string]bool, len(tc.want))
			allowed := make(map[string]bool, len(tc.want))
			for _, path := range tc.want {
				pending[path] = true
				allowed[path] = true
			}
			// Wait for actual HTTP responses, not sleeps or internal target
			// fields. The final journal below also catches concurrent extra calls.
			for len(pending) != 0 {
				select {
				case response := <-requests:
					if response.method != http.MethodGet || !allowed[response.path] {
						t.Fatalf("unexpected remote API call: %s %s", response.method, response.path)
					}
					if response.status < http.StatusOK || response.status >= http.StatusMultipleChoices {
						t.Fatalf("remote list failed: %s %s returned HTTP %d", response.method, response.path, response.status)
					}
					delete(pending, response.path)
				case <-ctx.Done():
					t.Fatalf("sweep did not reach required endpoints: %v", pending)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("sweeper did not stop after observed remote calls")
			}
			for _, call := range stub.Journal() {
				requestURL, err := url.Parse(call.Path)
				if err != nil {
					t.Fatal(err)
				}
				path := strings.TrimPrefix(requestURL.Path, "/client/v4")
				if call.Method != http.MethodGet || !allowed[path] {
					t.Errorf("unexpected remote API call: %s %s", call.Method, call.Path)
				}
			}
		})
	}
}

type sweepResponse struct {
	method string
	path   string
	status int
}

type sweepRequestRecorder struct {
	requests chan<- sweepResponse
}

func (r sweepRequestRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err == nil {
		select {
		case r.requests <- sweepResponse{
			method: request.Method,
			path:   strings.TrimPrefix(request.URL.Path, "/client/v4"),
			status: response.StatusCode,
		}:
		case <-request.Context().Done():
		}
	}
	return response, err
}
