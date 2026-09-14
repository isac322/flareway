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

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"golang.org/x/time/rate"

	"github.com/isac322/flareway/test/cfstub"
)

func TestSDKWrappersUseTypedCloudflarePayloads(t *testing.T) {
	server := cfstub.New(t)
	server.State.AddZone(cfstub.Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
	server.State.SetOrganization("account-1", cfstub.Organization{Name: "Example Account", AuthDomain: "team.cloudflareaccess.com"})
	client := New("top-secret", "account-1", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()

	verification, err := client.VerifyToken(ctx)
	if err != nil || !verification.Active() {
		t.Fatalf("VerifyToken() = %#v, %v", verification, err)
	}
	zones, err := client.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].ID != "zone-1" || zones[0].Name != "example.com" {
		t.Fatalf("ListZones() = %#v, %v", zones, err)
	}
	organization, err := client.GetOrganization(ctx)
	if err != nil || organization.AuthDomain != "team.cloudflareaccess.com" {
		t.Fatalf("GetOrganization() = %#v, %v", organization, err)
	}

	tunnel, err := client.CreateTunnel(ctx, "flareway-test")
	if err != nil || tunnel.ID == "" || tunnel.Name != "flareway-test" || tunnel.Status != "inactive" || tunnel.Deleted() {
		t.Fatalf("CreateTunnel() = %#v, %v", tunnel, err)
	}
	renamed, err := client.UpdateTunnelName(ctx, tunnel.ID, "flareway-renamed")
	if err != nil || renamed.Name != "flareway-renamed" {
		t.Fatalf("UpdateTunnelName() = %#v, %v", renamed, err)
	}
	tunnels, err := client.ListTunnels(ctx)
	if err != nil || len(tunnels) != 1 || tunnels[0].ID != tunnel.ID || tunnels[0].Name != renamed.Name {
		t.Fatalf("ListTunnels() = %#v, %v", tunnels, err)
	}
	server.State.SetTunnelToken(tunnel.ID, "connector-secret")
	token, err := client.GetTunnelToken(ctx, tunnel.ID)
	if err != nil || token != "connector-secret" {
		t.Fatalf("GetTunnelToken() returned token length %d, err %v", len(token), err)
	}

	version, err := client.UpdateTunnelConfiguration(ctx, tunnel.ID, zero_trust.TunnelCloudflaredConfigurationUpdateParams{
		Config: cloudflaresdk.F(zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig{
			Ingress: cloudflaresdk.F([]zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{{
				Hostname: cloudflaresdk.F("app.example.com"),
				Service:  cloudflaresdk.F("http://127.0.0.1:18080"),
			}, {
				Hostname: cloudflaresdk.F(""),
				Service:  cloudflaresdk.F("http_status:404"),
			}}),
		}),
	})
	if err != nil || version != 1 {
		t.Fatalf("UpdateTunnelConfiguration() = %d, %v", version, err)
	}
	gotVersion, err := client.GetTunnelConfigurationVersion(ctx, tunnel.ID)
	if err != nil || gotVersion != version {
		t.Fatalf("GetTunnelConfigurationVersion() = %d, %v", gotVersion, err)
	}
	storedConfig, ok := server.State.TunnelConfiguration(tunnel.ID)
	if !ok || !json.Valid(storedConfig.Config) {
		t.Fatalf("stub stored invalid configuration: %#v", storedConfig)
	}

	input := DNSRecordInput{
		Name:    "app.example.com",
		Content: tunnel.ID + ".cfargotunnel.com",
		Comment: "flareway cluster/ns/gateway",
		Proxied: true,
	}
	record, err := client.CreateCNAME(ctx, "zone-1", input)
	if err != nil || record.ID == "" || record.Content != input.Content || !record.Proxied || !IsOwnedDNSRecord(record, input.Comment) {
		t.Fatalf("CreateCNAME() = %#v, %v", record, err)
	}
	records, err := client.ListDNSRecords(ctx, "zone-1", input.Name)
	if err != nil || len(records) != 1 || records[0].ID != record.ID {
		t.Fatalf("ListDNSRecords() = %#v, %v", records, err)
	}
	input.Content = "replacement.cfargotunnel.com"
	updated, err := client.UpdateCNAME(ctx, "zone-1", record.ID, input)
	if err != nil || updated.Content != input.Content {
		t.Fatalf("UpdateCNAME() = %#v, %v", updated, err)
	}
	if err := client.DeleteDNSRecord(ctx, "zone-1", record.ID); err != nil {
		t.Fatalf("DeleteDNSRecord() error = %v", err)
	}
	if err := client.DeleteTunnel(ctx, tunnel.ID, true); err != nil {
		t.Fatalf("DeleteTunnel() error = %v", err)
	}
}

func TestCNAMEParamsOmitEmptyTags(t *testing.T) {
	payload, err := json.Marshal(cnameParams(DNSRecordInput{
		Name: "app.example.com", Content: "tunnel.cfargotunnel.com", Comment: "flareway owner", Proxied: true,
	}))
	if err != nil {
		t.Fatalf("marshal CNAME params: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode CNAME params: %v", err)
	}
	if _, present := fields["tags"]; present {
		t.Fatalf("empty tags must be omitted, payload=%s", payload)
	}
}

func TestGetTunnelPreservesDeletedTimestamp(t *testing.T) {
	deletedAt := time.Date(2026, time.September, 12, 10, 30, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/accounts/account/cfd_tunnel/deleted-tunnel" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"deleted-tunnel","account_tag":"account","name":"deleted","status":"inactive","deleted_at":%q}}`, deletedAt.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	tunnel, err := client.GetTunnel(context.Background(), "deleted-tunnel")
	if err != nil {
		t.Fatalf("GetTunnel() error = %v", err)
	}
	if !tunnel.Deleted() || tunnel.DeletedAt == nil || !tunnel.DeletedAt.Equal(deletedAt) {
		t.Fatalf("GetTunnel() deleted timestamp = %#v, want %s", tunnel.DeletedAt, deletedAt)
	}
}

func TestFactorySharesLimiterByAccountWithoutCachingToken(t *testing.T) {
	factory := NewFactory(logr.Discard())
	first := factory.Client("first-token", "account-1").(*Client)
	second := factory.Client("second-token", "account-1").(*Client)
	other := factory.Client("other-token", "account-2").(*Client)
	if first == second {
		t.Fatal("factory cached a token-bearing client")
	}
	if first.limiter != second.limiter {
		t.Fatal("same account did not share its rate limiter")
	}
	if first.limiter == other.limiter {
		t.Fatal("different accounts unexpectedly shared a rate limiter")
	}
}

func TestClientRetriesThreeTimes(t *testing.T) {
	server := cfstub.New(t)
	server.Fault(http.MethodGet, `/user/tokens/verify$`, cfstub.Fault{
		Status: http.StatusInternalServerError,
		Body:   `{"success":false,"errors":[{"code":1000,"message":"temporary"}]}`,
		Times:  3,
	})
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	verification, err := client.VerifyToken(context.Background())
	if err != nil || !verification.Active() {
		t.Fatalf("VerifyToken() after retries = %#v, %v", verification, err)
	}
	calls := 0
	for _, call := range server.Journal() {
		if strings.HasSuffix(call.Path, "/user/tokens/verify") {
			calls++
		}
	}
	if calls != DefaultMaxRetries+1 {
		t.Fatalf("token verification calls = %d, want %d", calls, DefaultMaxRetries+1)
	}
}

func TestWithTunnelLockSerializesSameTunnel(t *testing.T) {
	client := New("token", "account", logr.Discard(), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 2)

	go func() {
		done <- client.WithTunnelLock(context.Background(), "tunnel", func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	var mu sync.Mutex
	secondEntered := false
	go func() {
		done <- client.WithTunnelLock(context.Background(), "tunnel", func() error {
			mu.Lock()
			secondEntered = true
			mu.Unlock()
			return nil
		})
	}()
	mu.Lock()
	if secondEntered {
		t.Fatal("second critical section entered before first released")
	}
	mu.Unlock()
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !secondEntered {
		t.Fatal("second critical section never entered")
	}
}
func TestLoggingMiddlewareDoesNotLogTokensOrBodies(t *testing.T) {
	var logs strings.Builder
	logger := funcr.New(func(prefix, args string) {
		logs.WriteString(prefix)
		logs.WriteString(args)
	}, funcr.Options{})
	request, err := http.NewRequest(http.MethodPut, "https://api.cloudflare.com/accounts/account/cfd_tunnel/tunnel/configurations", strings.NewReader("request-secret"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer api-token-secret")
	response := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{"Cf-Ray": []string{"test-ray"}}}
	_, gotErr := loggingMiddleware(logger)(request, func(*http.Request) (*http.Response, error) {
		return response, errors.New("response-secret")
	})
	if gotErr == nil {
		t.Fatal("logging middleware unexpectedly discarded the request error")
	}
	text := logs.String()
	for _, secret := range []string{"api-token-secret", "request-secret", "response-secret", "authorization"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(secret)) {
			t.Fatalf("log output exposed %q: %s", secret, text)
		}
	}
	for _, safe := range []string{"configurations", "401", "test-ray"} {
		if !strings.Contains(text, safe) {
			t.Fatalf("log output omitted safe metadata %q: %s", safe, text)
		}
	}
}

func TestCloudflareErrorClassificationSurvivesWrapping(t *testing.T) {
	for _, test := range []struct {
		status int
		check  func(error) bool
	}{
		{status: 404, check: IsNotFound},
		{status: 409, check: IsConflict},
		{status: 429, check: IsRateLimited},
	} {

		err := fmt.Errorf("operation failed: %w", &cloudflaresdk.Error{StatusCode: test.status})
		if !test.check(err) {
			t.Fatalf("status %d was not classified", test.status)
		}
	}
	if IsNotFound(errors.New("not found")) {
		t.Fatal("plain error was classified as Cloudflare 404")
	}
}

func TestOwnershipLedgerUsesExactMarkers(t *testing.T) {
	owner := OwnerTag("cluster-uid", "apps", "gateway", "object-uid")
	if owner != "flareway.bhyoo.com/owner=cluster-uid/apps/gateway/object-uid" {
		t.Fatalf("OwnerTag() = %q", owner)
	}
	comment := DNSRecordComment("cluster-uid", "apps", "gateway")
	record := DNSRecord{Comment: comment}
	if !IsOwnedBy([]string{"other", owner}, owner) || !IsOwnedDNSRecord(record, comment) {
		t.Fatal("exact ownership markers were not recognized without DNS tags")
	}
	record.Comment = comment + " operator note"
	if !IsOwnedDNSRecord(record, comment) {
		t.Fatal("owned DNS comment with user text was not recognized")
	}
	record.Comment = comment + "-foreign"
	if IsOwnedDNSRecord(record, comment) {
		t.Fatal("foreign DNS comment was accepted")
	}
}

func TestDNSRecordCommentStaysWithinCloudflareLimit(t *testing.T) {
	clusterID := strings.Repeat("클러스터", 30)
	namespace := strings.Repeat("네임스페이스", 20)
	gateway := strings.Repeat("게이트웨이", 20)
	first := DNSRecordCommentWithText(clusterID, namespace, gateway, strings.Repeat("사용자 메모", 40))
	second := DNSRecordCommentWithText(clusterID, namespace, gateway+"-other", strings.Repeat("사용자 메모", 40))
	if first == second {
		t.Fatalf("distinct long DNS identities produced the same marker: %q", first)
	}
	if utf8.RuneCountInString(first) > 100 || utf8.RuneCountInString(second) > 100 {
		t.Fatalf("DNS ownership comments exceed 100 code points: first=%d second=%d", utf8.RuneCountInString(first), utf8.RuneCountInString(second))
	}
	owner := DNSRecordComment(clusterID, namespace, gateway)
	otherOwner := DNSRecordComment(clusterID, namespace, gateway+"-other")
	if !strings.HasPrefix(owner, "flareway sha256:") || !strings.HasPrefix(otherOwner, "flareway sha256:") {
		t.Fatalf("long identities did not use SHA-256 markers: owner=%q other=%q", owner, otherOwner)
	}
	if !IsOwnedDNSRecord(DNSRecord{Comment: first}, owner) {
		t.Fatalf("truncated DNS comment was not recognized as owned: %q", first)
	}
	if IsOwnedDNSRecord(DNSRecord{Comment: first}, otherOwner) {
		t.Fatalf("DNS comment for %q was accepted by distinct owner %q", owner, otherOwner)
	}
}
