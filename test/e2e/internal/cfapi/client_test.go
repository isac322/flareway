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

package cfapi

import (
	"context"
	"github.com/isac322/flareway/test/cfstub"
	"reflect"
	"testing"
	"time"
)

func TestClientListsAndDeletesE2EResources(t *testing.T) {
	server := cfstub.New(t)
	now := time.Now().UTC().Truncate(time.Second)
	server.State.AddZone(cfstub.Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
	server.State.AddTunnel(cfstub.Tunnel{
		ID: "00000000-0000-0000-0000-000000000001", AccountID: "account-1", AccountTag: "account-1",
		Name: "flareway-e2e-deadbeef-public", Status: "inactive", ConfigSrc: "cloudflare", CreatedAt: now,
	})
	server.State.AddDNSRecord(cfstub.DNSRecord{
		ID: "dns-1", ZoneID: "zone-1", ZoneName: "example.com", Type: "CNAME",
		Name: "e2e-deadbeef-1.example.com", Content: "00000000-0000-0000-0000-000000000001.cfargotunnel.com",
		Proxied: true, Comment: "flareway flareway-e2e-deadbeef", CreatedOn: now, ModifiedOn: now,
	})
	server.State.AddAccessApplication("account-1", cfstub.AccessResource{
		"id": "app-1", "name": "flareway-e2e-deadbeef/access", "domain": "e2e-deadbeef-2.example.com",
		"tags": []string{"managed-by=flareway"}, "created_at": now,
	})
	server.State.AddAccessPolicy("account-1", cfstub.AccessResource{
		"id": "policy-1", "name": "flareway-e2e-deadbeef/service-auth", "decision": "non_identity",
		"include": []any{}, "created_at": now,
	})
	server.State.AddAccessServiceToken("account-1", cfstub.AccessServiceToken{
		ID: "token-1", ClientID: "client-id", Name: "flareway-e2e-deadbeef/service",
		Duration: "24h", Enabled: true, ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}, "client-secret")
	server.State.AddVirtualNetwork(cfstub.VirtualNetwork{
		ID: "00000000-0000-0000-0000-000000000002", AccountID: "account-1",
		Name: "flareway-e2e-deadbeef/private", Comment: "flareway-e2e-deadbeef", CreatedAt: now,
	})
	server.State.AddNetworkRoute(cfstub.NetworkRoute{
		ID: "00000000-0000-0000-0000-000000000003", AccountID: "account-1",
		Network: "10.96.0.0/12", TunnelID: "00000000-0000-0000-0000-000000000001",
		Comment: "flareway-e2e-deadbeef", CreatedAt: now,
	})
	server.State.AddHostnameRoute(cfstub.HostnameRoute{
		ID: "00000000-0000-0000-0000-000000000004", AccountID: "account-1",
		Hostname: "private-deadbeef.flareway.internal",
		TunnelID: "00000000-0000-0000-0000-000000000001",
		Comment:  "flareway-e2e-deadbeef", CreatedAt: now,
	})

	client := New("test-token", "account-1", server.URL)
	ctx := context.Background()
	if err := client.ResolveZone(ctx, "example.com"); err != nil {
		t.Fatalf("ResolveZone returned error: %v", err)
	}
	tunnels, err := client.ListTunnels(ctx)
	if err != nil || len(tunnels) != 1 {
		t.Fatalf("ListTunnels = %#v, %v", tunnels, err)
	}
	records, err := client.ListDNSRecords(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("ListDNSRecords = %#v, %v", records, err)
	}
	applications, err := client.ListAccessApplications(ctx)
	if err != nil || len(applications) != 1 {
		t.Fatalf("ListAccessApplications = %#v, %v", applications, err)
	}
	policies, err := client.ListAccessPolicies(ctx)
	if err != nil || len(policies) != 1 {
		t.Fatalf("ListAccessPolicies = %#v, %v", policies, err)
	}
	tokens, err := client.ListServiceTokens(ctx)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListServiceTokens returned count=%d err=%v", len(tokens), err)
	}
	virtualNetworks, err := client.ListVirtualNetworks(ctx)
	if err != nil || len(virtualNetworks) != 1 {
		t.Fatalf("ListVirtualNetworks = %#v, %v", virtualNetworks, err)
	}
	networkRoutes, err := client.ListNetworkRoutes(ctx)
	if err != nil || len(networkRoutes) != 1 {
		t.Fatalf("ListNetworkRoutes = %#v, %v", networkRoutes, err)
	}
	hostnameRoutes, err := client.ListHostnameRoutes(ctx)
	if err != nil || len(hostnameRoutes) != 1 {
		t.Fatalf("ListHostnameRoutes = %#v, %v", hostnameRoutes, err)
	}
	if err := client.DeleteAccessApplication(ctx, applications[0].ID); err != nil {
		t.Fatalf("DeleteAccessApplication returned error: %v", err)
	}
	if err := client.DeleteAccessPolicy(ctx, policies[0].ID); err != nil {
		t.Fatalf("DeleteAccessPolicy returned error: %v", err)
	}
	if err := client.DeleteServiceToken(ctx, tokens[0].ID); err != nil {
		t.Fatalf("DeleteServiceToken returned error: %v", err)
	}
	if err := client.DeleteHostnameRoute(ctx, hostnameRoutes[0].ID); err != nil {
		t.Fatalf("DeleteHostnameRoute returned error: %v", err)
	}
	if err := client.DeleteNetworkRoute(ctx, networkRoutes[0].ID); err != nil {
		t.Fatalf("DeleteNetworkRoute returned error: %v", err)
	}
	if err := client.DeleteVirtualNetwork(ctx, virtualNetworks[0].ID); err != nil {
		t.Fatalf("DeleteVirtualNetwork returned error: %v", err)
	}
	if err := client.DeleteDNSRecord(ctx, records[0].ID); err != nil {
		t.Fatalf("DeleteDNSRecord returned error: %v", err)
	}
	if err := client.DeleteTunnel(ctx, tunnels[0].ID); err != nil {
		t.Fatalf("DeleteTunnel returned error: %v", err)
	}
	if got := server.State.DNSRecords("zone-1"); len(got) != 0 {
		t.Fatalf("DNS records remain: %#v", got)
	}
	if got := server.State.Tunnels("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("tunnel was not deleted: %#v", got)
	}
	if got := server.State.AccessApplications("accounts/account-1"); len(got) != 0 {
		t.Fatalf("Access applications remain: %#v", got)
	}
	if got := server.State.AccessPolicies("account-1"); len(got) != 0 {
		t.Fatalf("Access policies remain: %#v", got)
	}
	if got := server.State.AccessServiceTokens("accounts/account-1"); len(got) != 0 {
		t.Fatalf("Access service tokens remain: %#v", got)
	}
	if got := server.State.VirtualNetworks("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("virtual network was not deleted: %#v", got)
	}
	if got := server.State.NetworkRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("network route was not deleted: %#v", got)
	}
	if got := server.State.HostnameRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("hostname route was not deleted: %#v", got)
	}
}

func TestClientReadsRestoresAndDeletesDeviceProfiles(t *testing.T) {
	server := cfstub.New(t)
	server.State.AddCustomDevicePolicy("account-1", cfstub.DevicePolicy{
		"policy_id": "profile-1",
		"name":      "flareway-e2e-deadbeef-device",
		"match":     "identity.email == \"nobody@example.invalid\"",
		"include": []any{
			map[string]any{"address": "10.96.0.0/12", "description": "k8s"},
		},
		"fallback_domains": []any{
			map[string]any{"suffix": "corp.example", "dns_server": []string{"10.0.0.53"}},
		},
	})
	client := New("test-token", "account-1", server.URL)
	ctx := context.Background()

	profile, err := client.GetDeviceProfile(ctx, "profile-1", false)
	if err != nil || profile.PolicyID != "profile-1" || profile.Default {
		t.Fatalf("GetDeviceProfile = %#v, %v", profile, err)
	}
	includes, err := client.GetDeviceProfileIncludes(ctx, "profile-1", false)
	if err != nil || len(includes) != 1 || includes[0].Address != "10.96.0.0/12" {
		t.Fatalf("GetDeviceProfileIncludes = %#v, %v", includes, err)
	}
	fallback, err := client.GetDeviceProfileFallbackDomains(ctx, "profile-1", false)
	if err != nil || len(fallback) != 1 || fallback[0].Suffix != "corp.example" {
		t.Fatalf("GetDeviceProfileFallbackDomains = %#v, %v", fallback, err)
	}
	replacement := []SplitTunnelEntry{{Host: "private.example.internal", Description: "private"}}
	if err := client.ReplaceDeviceProfileIncludes(ctx, "profile-1", false, replacement); err != nil {
		t.Fatalf("ReplaceDeviceProfileIncludes returned error: %v", err)
	}
	includes, err = client.GetDeviceProfileIncludes(ctx, "profile-1", false)
	if err != nil || len(includes) != 1 || includes[0] != replacement[0] {
		t.Fatalf("replaced includes = %#v, %v", includes, err)
	}
	if err := client.DeleteDeviceProfile(ctx, "profile-1"); err != nil {
		t.Fatalf("DeleteDeviceProfile returned error: %v", err)
	}
	if got := server.State.CustomDevicePolicies("account-1"); len(got) != 0 {
		t.Fatalf("custom device profiles remain: %#v", got)
	}
}

func TestDefaultDeviceProfileSnapshotRestoresEveryMutableFieldAndList(t *testing.T) {
	server := cfstub.New(t)
	original := cfstub.DevicePolicy{
		"name": "Default", "switch_locked": true, "captive_portal": float64(30),
		"allow_mode_switch": false, "allow_updates": true, "allowed_to_leave": false,
		"auto_connect": float64(60), "disable_auto_fallback": true, "exclude_office_ips": true,
		"service_mode_v2": map[string]any{"mode": "warp", "port": float64(0)},
		"support_url":     "https://support.example", "lan_allow_minutes": float64(15),
		"lan_allow_subnet_size": float64(24), "register_interface_ip_with_dns": true,
		"sccm_vpn_boundary_support": true, "tunnel_protocol": "masque",
		"virtual_networks":    map[string]any{"default": "vnet-a", "allowed": []any{"vnet-a", "vnet-b"}},
		"dns_search_suffixes": []any{map[string]any{"suffix": "corp.example", "description": "corp"}},
		"include":             []any{map[string]any{"address": "10.0.0.0/8", "description": "private"}},
		"exclude":             []any{map[string]any{"host": "public.example", "description": "public"}},
		"fallback_domains":    []any{map[string]any{"suffix": "legacy.example", "dns_server": []any{"10.0.0.53"}}},
	}
	server.State.SetDefaultDevicePolicy("account-1", original)
	client := New("test-token", "account-1", server.URL)
	ctx := context.Background()
	snapshot, err := client.SnapshotDefaultDeviceProfile(ctx)
	if err != nil {
		t.Fatalf("SnapshotDefaultDeviceProfile returned error: %v", err)
	}

	server.State.SetDefaultDevicePolicy("account-1", cfstub.DevicePolicy{
		"name": "Default", "switch_locked": false, "tunnel_protocol": "wireguard",
		"dns_search_suffixes": []any{}, "include": []any{}, "exclude": []any{},
		"fallback_domains": []any{},
	})
	if err := client.RestoreDefaultDeviceProfile(ctx, snapshot); err != nil {
		t.Fatalf("RestoreDefaultDeviceProfile returned error: %v", err)
	}
	restored, err := client.SnapshotDefaultDeviceProfile(ctx)
	if err != nil {
		t.Fatalf("snapshot restored profile: %v", err)
	}
	if !reflect.DeepEqual(restored, snapshot) {
		t.Fatalf("restored profile = %#v, want %#v", restored, snapshot)
	}
}
