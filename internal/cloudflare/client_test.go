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
	"github.com/cloudflare/cloudflare-go/v7/dns"
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
	if err != nil ||
		tunnel.ID == "" ||
		tunnel.AccountTag != "account-1" ||
		tunnel.Name != "flareway-test" ||
		tunnel.Status != TunnelStatusInactive ||
		tunnel.Type != TunnelTypeCloudflared ||
		tunnel.ConfigSource != TunnelConfigSourceCloudflare ||
		tunnel.CreatedAt.IsZero() ||
		tunnel.Deleted() {
		t.Fatalf("CreateTunnel() = %#v, %v", tunnel, err)
	}
	renamed, err := client.UpdateTunnelName(ctx, tunnel.ID, "flareway-renamed")
	if err != nil || renamed.Name != "flareway-renamed" {
		t.Fatalf("UpdateTunnelName() = %#v, %v", renamed, err)
	}
	tunnels, err := client.ListTunnels(ctx, TunnelListOptions{})
	if err != nil || len(tunnels) != 1 || tunnels[0].ID != tunnel.ID || tunnels[0].Name != renamed.Name {
		t.Fatalf("ListTunnels() = %#v, %v", tunnels, err)
	}
	server.State.SetTunnelToken(tunnel.ID, "connector-secret")
	token, err := client.GetTunnelToken(ctx, tunnel.ID)
	if err != nil || token != "connector-secret" {
		t.Fatalf("GetTunnelToken() returned token length %d, err %v", len(token), err)
	}

	configuration, err := client.UpdateTunnelConfiguration(ctx, tunnel.ID, zero_trust.TunnelCloudflaredConfigurationUpdateParams{
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
	if err != nil ||
		configuration.AccountID != "account-1" ||
		configuration.TunnelID != tunnel.ID ||
		configuration.Version != 1 ||
		configuration.Source != TunnelConfigSourceCloudflare ||
		configuration.CreatedAt.IsZero() ||
		!strings.Contains(string(configuration.Config), `"http_status:404"`) {
		t.Fatalf("UpdateTunnelConfiguration() = %#v, %v", configuration, err)
	}
	observedConfiguration, err := client.GetTunnelConfiguration(ctx, tunnel.ID)
	if err != nil ||
		observedConfiguration.AccountID != configuration.AccountID ||
		observedConfiguration.TunnelID != configuration.TunnelID ||
		observedConfiguration.Version != configuration.Version ||
		observedConfiguration.Source != configuration.Source ||
		!json.Valid(observedConfiguration.Config) {
		t.Fatalf("GetTunnelConfiguration() = %#v, %v", observedConfiguration, err)
	}
	storedConfig, ok := server.State.TunnelConfiguration(tunnel.ID)
	if !ok || !json.Valid(storedConfig.Config) {
		t.Fatalf("stub stored invalid configuration: %#v", storedConfig)
	}

	server.State.SetTunnelManagementToken(tunnel.ID, "management-secret")
	managementToken, err := client.IssueTunnelManagementToken(ctx, tunnel.ID, []TunnelManagementResource{TunnelManagementResourceLogs})
	if err != nil || managementToken != "management-secret" {
		t.Fatalf("IssueTunnelManagementToken() returned token length %d, err %v", len(managementToken), err)
	}

	runAt := time.Date(2026, time.September, 12, 10, 0, 0, 0, time.UTC)
	connector := cfstub.TunnelConnector{
		ID: "connector-1", Arch: "arm64", ConfigVersion: configuration.Version,
		Features: []string{"zeta", "alpha", "beta"}, RunAt: runAt, Version: "2026.9.0",
		Conns: []cfstub.TunnelConnection{
			{ID: "connection-3", ClientID: "connector-1", ClientVersion: "2026.9.0", ColoName: "SJC", OpenedAt: runAt, OriginIP: "192.0.2.3", UUID: "uuid-3"},
			{ID: "connection-1", ClientID: "connector-1", ClientVersion: "2026.9.0", ColoName: "LAX", OpenedAt: runAt, OriginIP: "192.0.2.1", UUID: "uuid-1"},
			{ID: "connection-2", ClientID: "connector-1", ClientVersion: "2026.9.0", ColoName: "SEA", OpenedAt: runAt, OriginIP: "192.0.2.2", UUID: "uuid-2"},
		},
	}
	server.State.AddTunnelConnector(tunnel.ID, connector)
	server.State.AddTunnelConnector(tunnel.ID, cfstub.TunnelConnector{ID: "connector-2", Arch: "amd64", RunAt: runAt, Version: "2026.9.0"})
	observedConnector, err := client.GetTunnelConnector(ctx, tunnel.ID, connector.ID, 2)
	if err != nil ||
		observedConnector.ID != connector.ID ||
		len(observedConnector.Connections) != 2 ||
		!observedConnector.ConnectionsTruncated ||
		len(observedConnector.Features) != 2 ||
		!observedConnector.FeaturesTruncated ||
		observedConnector.Connections[0].ID != "connection-1" ||
		observedConnector.Connections[0].PendingReconnect ||
		observedConnector.Features[0] != "alpha" {
		t.Fatalf("GetTunnelConnector() = %#v, %v", observedConnector, err)
	}
	connectors, connectorsTruncated, err := client.ListTunnelConnections(ctx, tunnel.ID, 1)
	if err != nil || len(connectors) != 1 || !connectorsTruncated || connectors[0].ID != "connector-1" {
		t.Fatalf("ListTunnelConnections() = %#v, %t, %v", connectors, connectorsTruncated, err)
	}
	if len(connectors[0].Connections) != 1 ||
		connectors[0].Connections[0].ID != "connection-1" ||
		connectors[0].Connections[0].PendingReconnect {
		t.Fatalf("ListTunnelConnections() connection observations = %#v", connectors[0].Connections)
	}
	connectorID := connector.ID
	if err := client.EvictTunnelConnections(ctx, tunnel.ID, &connectorID); err != nil {
		t.Fatalf("EvictTunnelConnections(connector) error = %v", err)
	}
	remaining := server.State.TunnelConnectors(tunnel.ID)
	if len(remaining) != 1 || remaining[0].ID != "connector-2" {
		t.Fatalf("connectors after targeted eviction = %#v", remaining)
	}
	if err := client.EvictTunnelConnections(ctx, tunnel.ID, nil); err != nil {
		t.Fatalf("EvictTunnelConnections(all) error = %v", err)
	}
	if remaining := server.State.TunnelConnectors(tunnel.ID); len(remaining) != 0 {
		t.Fatalf("connectors after full eviction = %#v", remaining)
	}

	ttl := int64(1)
	proxied := true
	input := DNSRecordInput{
		Name:    "app.example.com",
		Content: tunnel.ID + ".cfargotunnel.com",
		Comment: "flareway cluster/ns/gateway",
		TTL:     &ttl,
		Proxied: &proxied,
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
	server.State.AddTunnelConnector(tunnel.ID, connector)
	if err := client.DeleteTunnel(ctx, tunnel.ID, false); err == nil {
		t.Fatal("DeleteTunnel(cascade=false) succeeded with active connectors")
	}
	if err := client.DeleteTunnel(ctx, tunnel.ID, true); err != nil {
		t.Fatalf("DeleteTunnel(cascade=true) error = %v", err)
	}
	if remaining := server.State.TunnelConnectors(tunnel.ID); len(remaining) != 0 {
		t.Fatalf("cascade delete retained connectors: %#v", remaining)
	}
	var createBody, editBody, managementBody map[string]json.RawMessage
	targetedEviction, fullEviction, nonCascadeDelete, cascadeDelete := false, false, false, false
	for _, call := range server.Journal() {
		switch {
		case call.Method == http.MethodPost && call.Path == "/accounts/account-1/cfd_tunnel":
			_ = json.Unmarshal([]byte(call.Body), &createBody)
		case call.Method == http.MethodPatch && strings.HasSuffix(call.Path, "/cfd_tunnel/"+tunnel.ID):
			_ = json.Unmarshal([]byte(call.Body), &editBody)
		case call.Method == http.MethodPost && strings.HasSuffix(call.Path, "/management"):
			_ = json.Unmarshal([]byte(call.Body), &managementBody)
		case call.Method == http.MethodDelete && strings.Contains(call.Path, "/connections?client_id="+connector.ID):
			targetedEviction = true
		case call.Method == http.MethodDelete && strings.HasSuffix(call.Path, "/connections"):
			fullEviction = true
		case call.Method == http.MethodDelete && call.Path == "/accounts/account-1/cfd_tunnel/"+tunnel.ID:
			nonCascadeDelete = true
		case call.Method == http.MethodDelete && strings.HasSuffix(call.Path, "?cascade=true"):
			cascadeDelete = true
		}
	}
	if string(createBody["config_src"]) != `"cloudflare"` {
		t.Fatalf("create tunnel body = %v", createBody)
	}
	if _, exists := createBody["tunnel_secret"]; exists {
		t.Fatalf("create tunnel body included optional secret: %v", createBody)
	}
	if string(editBody["name"]) != `"flareway-renamed"` {
		t.Fatalf("edit tunnel body = %v", editBody)
	}
	if _, exists := editBody["tunnel_secret"]; exists {
		t.Fatalf("edit tunnel body included optional secret: %v", editBody)
	}
	var managementResources []string
	if err := json.Unmarshal(managementBody["resources"], &managementResources); err != nil ||
		len(managementResources) != 1 ||
		managementResources[0] != "logs" {
		t.Fatalf("management token body = %v", managementBody)
	}
	if _, exists := managementBody["token"]; exists {
		t.Fatalf("management token request included a token: %v", managementBody)
	}
	if !targetedEviction || !fullEviction || !nonCascadeDelete || !cascadeDelete {
		t.Fatalf("connection/cascade queries targeted=%t full=%t nonCascade=%t cascade=%t", targetedEviction, fullEviction, nonCascadeDelete, cascadeDelete)
	}
}

func TestWARPConnectorConnectionsComeFromDedicatedEndpoints(t *testing.T) {
	openedAt := time.Date(2026, time.September, 14, 10, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/accounts/account/warp_connector/warp-id":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"warp-id","account_tag":"account","name":"site","status":"healthy","tun_type":"warp_connector"}}`)
		case "/accounts/account/warp_connector/warp-id/connections":
			_, _ = fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":[{"id":"client-1","arch":"arm64","conns":[{"id":"connection-1","client_id":"client-1","client_version":"2026.9","colo_name":"SFO","opened_at":%q,"origin_ip":"192.0.2.1"}],"features":["ha"],"ha_status":"active","run_at":%q,"version":"2026.9"}]}`, openedAt.Format(time.RFC3339), openedAt.Format(time.RFC3339))
		case "/accounts/account/warp_connector/warp-id/connectors/client-1":
			_, _ = fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"client-1","arch":"arm64","conns":[{"id":"connection-1","client_id":"client-1","client_version":"2026.9","colo_name":"SFO","opened_at":%q,"origin_ip":"192.0.2.1"}],"features":["ha"],"ha_status":"active","run_at":%q,"version":"2026.9"}}`, openedAt.Format(time.RFC3339), openedAt.Format(time.RFC3339))
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))

	lifecycle, err := client.GetWARPConnector(context.Background(), "warp-id")
	if err != nil {
		t.Fatalf("GetWARPConnector() error = %v", err)
	}
	if len(lifecycle.Connections) != 0 {
		t.Fatalf("GetWARPConnector() returned lifecycle connections: %#v", lifecycle.Connections)
	}

	clients, err := client.ListWARPConnectorClients(context.Background(), "warp-id")
	if err != nil {
		t.Fatalf("ListWARPConnectorClients() error = %v", err)
	}
	if len(clients) != 1 ||
		len(clients[0].Connections) != 1 ||
		clients[0].Connections[0].ID != "connection-1" ||
		clients[0].Connections[0].IsPendingReconnect {
		t.Fatalf("ListWARPConnectorClients() = %#v", clients)
	}

	observed, err := client.GetWARPConnectorClient(context.Background(), "warp-id", "client-1")
	if err != nil {
		t.Fatalf("GetWARPConnectorClient() error = %v", err)
	}
	if len(observed.Connections) != 1 ||
		observed.Connections[0].ID != "connection-1" ||
		observed.Connections[0].IsPendingReconnect {
		t.Fatalf("GetWARPConnectorClient() = %#v", observed)
	}
}

func TestCNAMEParamsOmitOptionalFields(t *testing.T) {
	params, err := cnameParams(DNSRecordInput{
		Name: "app.example.com", Content: "tunnel.cfargotunnel.com",
	})
	if err != nil {
		t.Fatalf("cnameParams() error = %v", err)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal CNAME params: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode CNAME params: %v", err)
	}
	for _, field := range []string{"comment", "proxied", "settings", "tags", "ttl"} {
		if _, present := fields[field]; present {
			t.Fatalf("optional field %q must be omitted, payload=%s", field, payload)
		}
	}
}

func TestCNAMEParamsNormalizeAndPreserveDesiredFields(t *testing.T) {
	ttl, proxied, ipv4Only := int64(1), true, true
	params, err := cnameParams(DNSRecordInput{
		Name:    "BÜCHER.Example.",
		Content: "Ziel.BÜCHER.Example.",
		Comment: "flareway owner",
		TTL:     &ttl,
		Proxied: &proxied,
		Settings: &DNSRecordSettings{
			IPv4Only: &ipv4Only,
		},
	})
	if err != nil {
		t.Fatalf("cnameParams() error = %v", err)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal CNAME params: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode CNAME params: %v", err)
	}
	if fields["name"] != "xn--bcher-kva.example" || fields["content"] != "ziel.xn--bcher-kva.example" ||
		fields["ttl"] != float64(1) || fields["proxied"] != true || fields["comment"] != "flareway owner" {
		t.Fatalf("CNAME payload lost desired fields: %#v", fields)
	}
	if _, present := fields["tags"]; present {
		t.Fatalf("CNAME payload must not contain write-side tags: %#v", fields["tags"])
	}
	settings, ok := fields["settings"].(map[string]any)
	if !ok || settings["ipv4_only"] != true {
		t.Fatalf("CNAME settings = %#v", fields["settings"])
	}
	if _, present := settings["ipv6_only"]; present {
		t.Fatalf("unset ipv6Only must be omitted, settings=%#v", settings)
	}
}

func TestListDNSRecordsNormalizesUnicodeNameBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		if request.URL.Path != "/zones/zone/dns_records" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("name.exact"); got != "xn--bcher-kva.example" {
			t.Errorf("name.exact = %q", got)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`)
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	records, err := client.ListDNSRecords(context.Background(), "zone", "BÜCHER.Example.")
	if err != nil {
		t.Fatalf("ListDNSRecords() error = %v", err)
	}
	if !called || len(records) != 0 {
		t.Fatalf("ListDNSRecords() = %#v, request made=%t", records, called)
	}
}

func TestCNAMEParamsRejectCloudflareConstraints(t *testing.T) {
	automatic, tooShort, tooLong, fixed := int64(1), int64(59), int64(86401), int64(300)
	enabled, disabled := true, false
	validBase := DNSRecordInput{Name: "app.example.com", Content: "tunnel.cfargotunnel.com"}
	for name, mutate := range map[string]func(*DNSRecordInput){
		"short TTL": func(input *DNSRecordInput) { input.TTL = &tooShort },
		"long TTL":  func(input *DNSRecordInput) { input.TTL = &tooLong },
		"proxied fixed TTL": func(input *DNSRecordInput) {
			input.TTL, input.Proxied = &fixed, &enabled
		},
		"dual address family": func(input *DNSRecordInput) {
			input.Proxied = &enabled
			input.Settings = &DNSRecordSettings{IPv4Only: &enabled, IPv6Only: &enabled}
		},
		"address family without proxy": func(input *DNSRecordInput) {
			input.Proxied = &disabled
			input.Settings = &DNSRecordSettings{IPv4Only: &enabled}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := validBase
			mutate(&input)
			if _, err := cnameParams(input); err == nil {
				t.Fatal("cnameParams() succeeded")
			}
		})
	}

	validBase.TTL, validBase.Proxied = &automatic, &enabled
	validBase.Settings = &DNSRecordSettings{IPv6Only: &enabled}
	if _, err := cnameParams(validBase); err != nil {
		t.Fatalf("valid proxied CNAME rejected: %v", err)
	}
}

func TestDNSRecordFromSDKObservesActionableCNAMEFields(t *testing.T) {
	created := time.Date(2026, time.September, 10, 1, 2, 3, 0, time.UTC)
	modified := created.Add(time.Hour)
	commentModified := created.Add(30 * time.Minute)
	payload := fmt.Sprintf(`{
		"id":"record","name":"XN--BCHER-KVA.EXAMPLE","type":"CNAME",
		"content":"target.example","comment":"flareway owner","ttl":300,
		"proxied":false,"proxiable":true,
		"settings":{"ipv4_only":true,"ipv6_only":false},
		"tags":["one","two"],"meta":{},
		"created_on":%q,"modified_on":%q,"comment_modified_on":%q
	}`, created.Format(time.RFC3339), modified.Format(time.RFC3339), commentModified.Format(time.RFC3339))
	var remote dns.RecordResponse
	if err := json.Unmarshal([]byte(payload), &remote); err != nil {
		t.Fatalf("decode SDK DNS response: %v", err)
	}
	record := dnsRecordFromSDK(remote)
	if record.Name != "xn--bcher-kva.example" || record.TTL != 300 || record.Proxied || !record.Proxiable ||
		record.Settings == nil || record.Settings.IPv4Only == nil || !*record.Settings.IPv4Only ||
		record.Settings.IPv6Only == nil || *record.Settings.IPv6Only ||
		!record.CreatedOn.Equal(created) || !record.ModifiedOn.Equal(modified) ||
		!record.CommentModifiedOn.Equal(commentModified) {
		t.Fatalf("dnsRecordFromSDK() = %#v", record)
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
		if _, err := fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"deleted-tunnel","account_tag":"account","name":"deleted","status":"inactive","tun_type":"cfd_tunnel","config_src":"cloudflare","deleted_at":%q}}`, deletedAt.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	tunnel, err := client.GetTunnel(context.Background(), "deleted-tunnel")
	if err != nil {
		t.Fatalf("GetTunnel() error = %v", err)
	}
	if !tunnel.Deleted() ||
		tunnel.DeletedAt == nil ||
		!tunnel.DeletedAt.Equal(deletedAt) ||
		tunnel.Status != TunnelStatusInactive ||
		tunnel.Type != TunnelTypeCloudflared ||
		tunnel.ConfigSource != TunnelConfigSourceCloudflare {
		t.Fatalf("GetTunnel() = %#v, want deleted at %s", tunnel, deletedAt)
	}
}

func TestGetTunnelObservesLocalAndForeignTunnelTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/accounts/account/cfd_tunnel/local-tunnel":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"local-tunnel","account_tag":"account","name":"local","status":"inactive","tun_type":"cfd_tunnel","config_src":"local","created_at":"2026-09-01T00:00:00Z","conns_active_at":"2026-09-02T00:00:00Z","conns_inactive_at":"2026-09-03T00:00:00Z"}}`)
		case "/accounts/account/cfd_tunnel/foreign-tunnel":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"foreign-tunnel","account_tag":"account","name":"foreign","status":"down","tun_type":"magic","config_src":"cloudflare"}}`)
		case "/accounts/account/cfd_tunnel/unknown-tunnel":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"unknown-tunnel","account_tag":"account","name":"unknown","status":"inactive","tun_type":"unknown","config_src":"cloudflare"}}`)
		case "/accounts/account/cfd_tunnel/unknown-status":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"unknown-status","account_tag":"account","name":"unknown","status":"unknown","tun_type":"cfd_tunnel","config_src":"cloudflare"}}`)
		case "/accounts/account/cfd_tunnel/unknown-source":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"unknown-source","account_tag":"account","name":"unknown","status":"inactive","tun_type":"cfd_tunnel","config_src":"unknown"}}`)
		case "/accounts/account/cfd_tunnel/missing-id":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"","account_tag":"account","name":"missing","status":"inactive","tun_type":"cfd_tunnel","config_src":"cloudflare"}}`)
		case "/accounts/account/cfd_tunnel/missing-account":
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"missing-account","account_tag":"","name":"missing","status":"inactive","tun_type":"cfd_tunnel","config_src":"cloudflare"}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))

	local, err := client.GetTunnel(context.Background(), "local-tunnel")
	if err != nil ||
		local.AccountTag != "account" ||
		local.Type != TunnelTypeCloudflared ||
		local.ConfigSource != TunnelConfigSourceLocal ||
		local.CreatedAt.IsZero() ||
		local.ConnectionsActiveAt == nil ||
		local.ConnectionsInactiveAt == nil {
		t.Fatalf("local GetTunnel() = %#v, %v", local, err)
	}
	foreign, err := client.GetTunnel(context.Background(), "foreign-tunnel")
	if err != nil || foreign.Type != TunnelTypeMagic || foreign.ConfigSource != TunnelConfigSourceCloudflare || foreign.Status != TunnelStatusDown {
		t.Fatalf("foreign GetTunnel() = %#v, %v", foreign, err)
	}
	if _, err := client.GetTunnel(context.Background(), "unknown-tunnel"); err == nil {
		t.Fatal("GetTunnel() accepted an unknown tunnel type")
	}
	if _, err := client.GetTunnel(context.Background(), "unknown-status"); err == nil {
		t.Fatal("GetTunnel() accepted an unknown tunnel status")
	}
	if _, err := client.GetTunnel(context.Background(), "unknown-source"); err == nil {
		t.Fatal("GetTunnel() accepted an unknown configuration source")
	}
	if _, err := client.GetTunnel(context.Background(), "missing-id"); err == nil {
		t.Fatal("GetTunnel() accepted a response without a tunnel ID")
	}
	if _, err := client.GetTunnel(context.Background(), "missing-account"); err == nil {
		t.Fatal("GetTunnel() accepted a response without an account ID")
	}
}

func TestGetTunnelConfigurationPreservesFullRemoteConfig(t *testing.T) {
	server := cfstub.New(t)
	createdAt := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	server.State.AddTunnel(cfstub.Tunnel{ID: "tunnel", AccountID: "account", CreatedAt: createdAt})
	server.State.SetTunnelConfiguration(cfstub.TunnelConfiguration{
		AccountID: "account",
		TunnelID:  "tunnel",
		Version:   7,
		Source:    "cloudflare",
		CreatedAt: createdAt,
		Config:    json.RawMessage(`{"ingress":[{"service":"http_status:404"}],"warp-routing":{"enabled":true},"future_field":{"nested":"preserved"}}`),
	})
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))

	configuration, err := client.GetTunnelConfiguration(context.Background(), "tunnel")
	if err != nil {
		t.Fatalf("GetTunnelConfiguration() error = %v", err)
	}
	if configuration.AccountID != "account" ||
		configuration.TunnelID != "tunnel" ||
		configuration.Version != 7 ||
		configuration.Source != TunnelConfigSourceCloudflare ||
		!configuration.CreatedAt.Equal(createdAt) ||
		!strings.Contains(string(configuration.Config), `"warp-routing"`) ||
		!strings.Contains(string(configuration.Config), `"future_field"`) {
		t.Fatalf("GetTunnelConfiguration() = %#v", configuration)
	}
}

func TestTunnelConfigurationUsesRequestIdentityWhenResponseOmitsIDs(t *testing.T) {
	createdAt := time.Date(2026, time.September, 15, 0, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/accounts/account/cfd_tunnel/tunnel/configurations" {
			http.NotFound(response, request)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodPut {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"success":  true,
			"errors":   []any{},
			"messages": []any{},
			"result": map[string]any{
				"config": map[string]any{
					"ingress": []any{map[string]any{"service": "http_status:404"}},
				},
				"created_at": createdAt.Format(time.RFC3339),
				"source":     "cloudflare",
				"version":    7,
			},
		})
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))

	observed, err := client.GetTunnelConfiguration(context.Background(), "tunnel")
	if err != nil || observed.AccountID != "account" || observed.TunnelID != "tunnel" {
		t.Fatalf("GetTunnelConfiguration() = %#v, %v", observed, err)
	}
	updated, err := client.UpdateTunnelConfiguration(context.Background(), "tunnel", zero_trust.TunnelCloudflaredConfigurationUpdateParams{
		Config: cloudflaresdk.F(zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig{
			Ingress: cloudflaresdk.F([]zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{{
				Service: cloudflaresdk.F("http_status:404"),
			}}),
		}),
	})
	if err != nil || updated.AccountID != "account" || updated.TunnelID != "tunnel" {
		t.Fatalf("UpdateTunnelConfiguration() = %#v, %v", updated, err)
	}
}

func TestTunnelConfigurationRejectsConflictingResponseIdentity(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		tunnel   string
		contains string
	}{
		{name: "account", account: "other-account", tunnel: "tunnel", contains: "expected \"account\""},
		{name: "tunnel", account: "account", tunnel: "other-tunnel", contains: "expected \"tunnel\""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/accounts/account/cfd_tunnel/tunnel/configurations" {
					http.NotFound(response, request)
					return
				}
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]any{
					"success":  true,
					"errors":   []any{},
					"messages": []any{},
					"result": map[string]any{
						"account_id": test.account,
						"tunnel_id":  test.tunnel,
						"config": map[string]any{
							"ingress": []any{map[string]any{"service": "http_status:404"}},
						},
						"created_at": "2026-09-15T00:00:00Z",
						"source":     "cloudflare",
						"version":    1,
					},
				})
			}))
			t.Cleanup(server.Close)
			client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))

			_, err := client.GetTunnelConfiguration(context.Background(), "tunnel")
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("GetTunnelConfiguration() error = %v, want substring %q", err, test.contains)
			}
		})
	}
}

func TestTunnelListOptionsOmitUnsetFieldsAndMapEveryFilter(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		response.Header().Set("Content-Type", "application/json")
		query := request.URL.Query()
		if calls == 1 {
			if len(query) != 0 {
				t.Errorf("unset tunnel filters were sent: %s", query.Encode())
			}
		} else {
			expected := map[string]string{
				"exclude_prefix":  "skip-",
				"existed_at":      "2026-09-01T00:00:00Z",
				"include_prefix":  "keep-",
				"is_deleted":      "false",
				"name":            "keep-tunnel",
				"page":            "1",
				"per_page":        "25",
				"status":          "healthy",
				"uuid":            "tunnel-uuid",
				"was_active_at":   "2026-09-02T00:00:00Z",
				"was_inactive_at": "2026-09-03T00:00:00Z",
			}
			for key, want := range expected {
				if got := query.Get(key); got != want {
					t.Errorf("%s = %q, want %q; query=%s", key, got, want, query.Encode())
				}
			}
		}
		_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":25,"count":0,"total_count":0,"total_pages":0}}`)
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()

	if _, err := client.ListTunnels(ctx, TunnelListOptions{}); err != nil {
		t.Fatalf("ListTunnels(empty) error = %v", err)
	}
	excludePrefix, includePrefix := "skip-", "keep-"
	existedAt := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	deleted, name, page, perPage := false, "keep-tunnel", int64(1), int64(25)
	status, uuid := TunnelStatusHealthy, "tunnel-uuid"
	wasActiveAt := time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC)
	wasInactiveAt := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC)
	if _, err := client.ListTunnels(ctx, TunnelListOptions{
		ExcludePrefix: &excludePrefix,
		ExistedAt:     &existedAt,
		IncludePrefix: &includePrefix,
		Deleted:       &deleted,
		Name:          &name,
		Page:          &page,
		PerPage:       &perPage,
		Status:        &status,
		UUID:          &uuid,
		WasActiveAt:   &wasActiveAt,
		WasInactiveAt: &wasInactiveAt,
	}); err != nil {
		t.Fatalf("ListTunnels(all filters) error = %v", err)
	}
	invalid := TunnelStatus("Unknown")
	if _, err := client.ListTunnels(ctx, TunnelListOptions{Status: &invalid}); err == nil {
		t.Fatal("ListTunnels() accepted an unsupported status")
	}
	if calls != 2 {
		t.Fatalf("server calls = %d, want 2", calls)
	}
}

func TestTunnelLifecycleRejectsInvalidInputsBeforeRequests(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()
	config := zero_trust.TunnelCloudflaredConfigurationUpdateParams{}
	emptyConnectorID := ""

	checks := []struct {
		name string
		call func() error
	}{
		{name: "get", call: func() error { _, err := client.GetTunnel(ctx, ""); return err }},
		{name: "create name", call: func() error { _, err := client.CreateTunnel(ctx, ""); return err }},
		{name: "update name", call: func() error { _, err := client.UpdateTunnelName(ctx, "", "name"); return err }},
		{name: "update empty name", call: func() error { _, err := client.UpdateTunnelName(ctx, "tunnel", ""); return err }},
		{name: "delete", call: func() error { return client.DeleteTunnel(ctx, "", false) }},
		{name: "connector token", call: func() error { _, err := client.GetTunnelToken(ctx, ""); return err }},
		{name: "get configuration", call: func() error { _, err := client.GetTunnelConfiguration(ctx, ""); return err }},
		{name: "update configuration", call: func() error { _, err := client.UpdateTunnelConfiguration(ctx, "", config); return err }},
		{name: "management token", call: func() error {
			_, err := client.IssueTunnelManagementToken(ctx, "", []TunnelManagementResource{TunnelManagementResourceLogs})
			return err
		}},
		{name: "get connector tunnel", call: func() error { _, err := client.GetTunnelConnector(ctx, "", "connector", 1); return err }},
		{name: "get connector ID", call: func() error { _, err := client.GetTunnelConnector(ctx, "tunnel", "", 1); return err }},
		{name: "list connections", call: func() error { _, _, err := client.ListTunnelConnections(ctx, "", 1); return err }},
		{name: "evict tunnel", call: func() error { return client.EvictTunnelConnections(ctx, "", nil) }},
		{name: "evict connector", call: func() error { return client.EvictTunnelConnections(ctx, "tunnel", &emptyConnectorID) }},
	}
	for _, check := range checks {
		if err := check.call(); err == nil {
			t.Errorf("%s accepted an empty identifier", check.name)
		}
	}
	if _, err := client.IssueTunnelManagementToken(ctx, "tunnel", nil); err == nil {
		t.Error("IssueTunnelManagementToken() accepted an empty resource list")
	}
	if _, err := client.IssueTunnelManagementToken(ctx, "tunnel", []TunnelManagementResource{"Unknown"}); err == nil {
		t.Error("IssueTunnelManagementToken() accepted an unsupported resource")
	}
	if requests != 0 {
		t.Fatalf("invalid inputs made %d HTTP requests", requests)
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
	if !DNSHostnamesEqual("BÜCHER.Example.", "xn--bcher-kva.example") {
		t.Fatal("Unicode and Punycode DNS hostnames did not compare equally")
	}
	if DNSHostnamesEqual("bücher.example", "foreign.example") {
		t.Fatal("distinct DNS hostnames compared equally")
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
