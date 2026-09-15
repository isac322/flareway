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

package cfstub

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestCloudflareEndpointsPreserveStateAndVersions(t *testing.T) {
	server := New(t)
	server.State.AddZone(Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
	server.State.SetOrganization("account-1", Organization{
		ID: "organization-1", Name: "Example", AuthDomain: "example.cloudflareaccess.com",
	})

	var tunnel Tunnel
	requestResult(t, server, http.MethodPost, "/accounts/account-1/cfd_tunnel", map[string]any{
		"name": "flareway-e2e-a1b2c3d4", "config_src": "cloudflare",
	}, &tunnel)
	if tunnel.ID == "" || tunnel.AccountTag != "account-1" || tunnel.Status != "inactive" {
		t.Fatalf("unexpected tunnel response: %#v", tunnel)
	}

	var first, second TunnelConfiguration
	requestResult(t, server, http.MethodPut, "/accounts/account-1/cfd_tunnel/"+tunnel.ID+"/configurations", map[string]any{
		"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}},
	}, &first)
	requestResult(t, server, http.MethodPut, "/accounts/account-1/cfd_tunnel/"+tunnel.ID+"/configurations", map[string]any{
		"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:403"}}},
	}, &second)
	if first.Version != 1 || second.Version != 2 {
		t.Fatalf("configuration versions = %d, %d; want 1, 2", first.Version, second.Version)
	}
	stored, ok := server.State.TunnelConfiguration(tunnel.ID)
	if !ok || stored.Version != 2 || !bytes.Contains(stored.Config, []byte("http_status:403")) {
		t.Fatalf("stored configuration = %#v", stored)
	}

	var record DNSRecord
	requestResult(t, server, http.MethodPost, "/zones/zone-1/dns_records", map[string]any{
		"type": "CNAME", "name": "e2e-a1b2c3d4.example.com", "content": tunnel.ID + ".cfargotunnel.com",
		"proxied": true, "comment": "flareway flareway-e2e-a1b2c3d4", "tags": []string{"managed-by=flareway"},
	}, &record)
	if record.ID == "" || !record.Proxied || record.ZoneName != "example.com" {
		t.Fatalf("unexpected DNS record: %#v", record)
	}

	var records []DNSRecord
	requestResult(t, server, http.MethodGet, "/zones/zone-1/dns_records?name.exact=e2e-a1b2c3d4.example.com&per_page=1", nil, &records)
	if len(records) != 1 || records[0].ID != record.ID {
		t.Fatalf("filtered records = %#v", records)
	}
	requestResult(t, server, http.MethodGet, "/zones/zone-1/dns_records?page=2&per_page=1", nil, &records)
	if len(records) != 0 {
		t.Fatalf("page beyond results returned %#v", records)
	}

	requestResult[map[string]string](t, server, http.MethodDelete, "/zones/zone-1/dns_records/"+record.ID, nil, nil)
	if got := server.State.DNSRecords("zone-1"); len(got) != 0 {
		t.Fatalf("DNS records after delete = %#v", got)
	}

	requestResult[Tunnel](t, server, http.MethodDelete, "/accounts/account-1/cfd_tunnel/"+tunnel.ID+"?cascade=true", nil, nil)
	if got := server.State.Tunnels("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("tunnels after delete = %#v", got)
	}

	server.AssertOrder(t,
		`/accounts/account-1/cfd_tunnel$`,
		`/configurations$`,
		`/zones/zone-1/dns_records$`,
		`/zones/zone-1/dns_records/`,
		`/accounts/account-1/cfd_tunnel/`,
	)
}

func TestCloudflareEndpointsSupportClientV4PrefixAndFaults(t *testing.T) {
	server := New(t)
	server.Fault(http.MethodGet, `^/user/tokens/verify$`, Fault{
		Status: http.StatusTooManyRequests, RetryAfter: "3", Times: 1,
	})

	response := request(t, server, http.MethodGet, "/client/v4/user/tokens/verify", nil)
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "3" {
		t.Fatalf("fault response status=%d retry-after=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}

	var verified TokenVerification
	requestResult(t, server, http.MethodGet, "/client/v4/user/tokens/verify", nil, &verified)
	if verified.Status != "active" {
		t.Fatalf("token status = %q, want active", verified.Status)
	}
}

func requestResult[T any](t *testing.T, server *Server, method, path string, body any, target *T) {
	t.Helper()
	response := request(t, server, method, path, body)
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("%s %s returned %d: %s", method, path, response.StatusCode, redactBody(content, "application/json"))
	}
	if target == nil {
		return
	}
	var decoded struct {
		Result T `json:"result"`
	}
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode response: %v\n%s", err, redactBody(content, "application/json"))
	}
	*target = decoded.Result
}

func request(t *testing.T, server *Server, method, path string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		content, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(content)
	}
	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return response
}
