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
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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
			synctest.Test(t, func(t *testing.T) {
				remote := &sweepRequestRecorder{results: make(map[string]string)}
				for _, path := range allRequests {
					remote.results[path] = "[]"
				}
				remote.results["/zones"] = `[{"id":"zone-1","name":"example.com","account":{"id":"account-1"}}]`
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
				factory := flarecloudflare.NewFactory(logr.Discard(),
					flarecloudflare.WithBaseURL("http://cloudflare.test"),
					// Keep HTTP and rate-limit waits within the synctest bubble.
					// Real sockets would prevent virtual time from advancing.
					flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 1)),
					flarecloudflare.WithListLimiter(rate.NewLimiter(rate.Inf, 1)),
					flarecloudflare.WithRequestOptions(option.WithHTTPClient(&http.Client{
						Transport: remote,
					})),
				)
				const sweepTTL = time.Second
				worker := newProductionSweeper(tc.groups, sweep.SweeperOptions{
					Client:            kube,
					APIReader:         kube,
					Scheme:            scheme,
					CloudflareFactory: factory,
					Policy: freshness.Policy{
						Authz: sweepTTL, Traffic: sweepTTL,
						Indirect: sweepTTL, Display: sweepTTL,
					},
					Logger:         logr.Discard(),
					SweepRateLimit: 1e9,
					SweepRateBurst: 100,
				})
				if len(tc.want) == 0 {
					if worker != nil {
						t.Fatal("all-disabled production composition registered a worker")
					}
					if len(remote.responses) != 0 {
						t.Fatalf("all-disabled composition called Cloudflare: %v", remote.responses)
					}
					return
				}
				if worker == nil {
					t.Fatal("enabled controllers have no drift sweeper")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- worker.Start(ctx)
				}()

				// Every target's first jitter is strictly below sweepTTL.
				// Virtual time advances only after all runnable goroutines finish:
				// synchronous HTTP responses and the rest of each pass therefore
				// complete before the clock reaches this first-pass barrier.
				// Do not cancel when only the expected endpoints have responded;
				// incorrectly selected targets must get their first pass too.
				firstPass := time.NewTimer(sweepTTL)
				defer firstPass.Stop()
				<-firstPass.C
				synctest.Wait()
				cancel()
				synctest.Wait()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("sweeper stopped with error: %v", err)
					}
				default:
					t.Fatal("sweeper did not stop after cancellation")
				}

				pending := make(map[string]bool, len(tc.want))
				allowed := make(map[string]bool, len(tc.want))
				for _, path := range tc.want {
					pending[path] = true
					allowed[path] = true
				}
				for _, response := range remote.responses {
					if response.method != http.MethodGet || !allowed[response.path] {
						t.Errorf("unexpected remote API call: %s %s", response.method, response.path)
					}
					if response.status < http.StatusOK || response.status >= http.StatusMultipleChoices {
						t.Errorf("remote list failed: %s %s returned HTTP %d", response.method, response.path, response.status)
						continue
					}
					delete(pending, response.path)
				}
				if len(pending) != 0 {
					t.Fatalf("sweep did not reach required endpoints: %v", pending)
				}
			})
		})
	}
}

type sweepResponse struct {
	method string
	path   string
	status int
}

// sweepRequestRecorder is an in-process HTTP stub, not a replacement for the
// Cloudflare adapter: real SDK requests still encode and decode its API envelopes.
type sweepRequestRecorder struct {
	results map[string]string

	mu        sync.Mutex
	responses []sweepResponse
}

func (r *sweepRequestRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	path := strings.TrimPrefix(request.URL.Path, "/client/v4")
	page := request.URL.Query().Get("page")
	if page == "" {
		page = "1"
	}
	result, found := r.results[path]
	if path == "/zones" && page != "1" {
		result = "[]"
	}
	status := http.StatusOK
	body := fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":%s,"result_info":{"page":%s,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`, result, page)
	if request.Method != http.MethodGet || !found {
		status = http.StatusNotFound
		body = `{"success":false,"errors":[{"code":10000,"message":"unregistered endpoint"}],"messages":[]}`
	}
	r.mu.Lock()
	r.responses = append(r.responses, sweepResponse{
		method: request.Method,
		path:   path,
		status: status,
	})
	r.mu.Unlock()
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}, nil
}
