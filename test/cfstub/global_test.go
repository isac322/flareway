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
	"net/http"
	"testing"
)

func TestGlobalSettingsOrganizationRulesAndLists(t *testing.T) {
	server := New(t)
	server.State.SetOrganization("account-1", Organization{ID: "org-1", Name: "team", AuthDomain: "team.cloudflareaccess.com"})

	var settings DeviceSettings
	requestResult(t, server, http.MethodPatch, "/accounts/account-1/devices/settings", map[string]any{
		"gateway_proxy_enabled": true, "gateway_udp_proxy_enabled": true,
		"root_certificate_installation_enabled": true, "use_zt_virtual_ip": true, "disable_for_time": 900,
	}, &settings)
	if !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled || !settings.RootCertificateInstallationEnabled || !settings.UseZTVirtualIP || settings.DisableForTime != 900 {
		t.Fatalf("edited device settings = %#v", settings)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/settings", nil, &settings)
	if settings.DisableForTime != 900 {
		t.Fatalf("read-back device settings = %#v", settings)
	}

	var organization Organization
	requestResult(t, server, http.MethodPut, "/accounts/account-1/access/organizations", map[string]any{
		"session_duration": "24h", "warp_auth_session_duration": "720h", "allow_authenticate_via_warp": true,
		"is_ui_read_only": true, "deny_unmatched_requests": true, "warp_auth_non_browser_401": true,
	}, &organization)
	if organization.Name != "team" || organization.AuthDomain != "team.cloudflareaccess.com" || organization.WARPAuthSessionDuration != "720h" || !organization.DenyUnmatchedRequests {
		t.Fatalf("updated organization = %#v", organization)
	}

	var list GatewayList
	requestResult(t, server, http.MethodPost, "/accounts/account-1/gateway/lists", map[string]any{
		"name": "trusted-egress", "description": "platform", "type": "IP",
		"items": []any{map[string]any{"value": "203.0.113.0/24", "description": "test net"}},
	}, &list)
	if list.ID == "" || list.Count != 1 || list.Items[0].Value != "203.0.113.0/24" {
		t.Fatalf("created Gateway list = %#v", list)
	}
	requestResult(t, server, http.MethodPut, "/accounts/account-1/gateway/lists/"+list.ID, map[string]any{
		"name": "trusted-egress", "description": "updated",
		"items": []any{map[string]any{"value": "198.51.100.0/24"}},
	}, &list)
	if list.Count != 1 || list.Items[0].Value != "198.51.100.0/24" || list.Description != "updated" {
		t.Fatalf("updated Gateway list = %#v", list)
	}
	var listItems []GatewayListItem
	requestResult(t, server, http.MethodGet, "/accounts/account-1/gateway/lists/"+list.ID+"/items", nil, &listItems)
	if len(listItems) != 1 || listItems[0].Value != "198.51.100.0/24" {
		t.Fatalf("Gateway list items = %#v", listItems)
	}

	var rule GatewayRule
	requestResult(t, server, http.MethodPost, "/accounts/account-1/gateway/rules", map[string]any{
		"name": "private-egress", "enabled": true, "precedence": 100, "filters": []string{"l4"},
		"action": "allow", "traffic": "net.dst.ip in {$" + list.ID + "}", "identity": "identity.email == \"ops@example.com\"",
	}, &rule)
	if rule.ID == "" || rule.Filters[0] != "l4" || rule.Traffic != "net.dst.ip in {$"+list.ID+"}" {
		t.Fatalf("created Gateway rule = %#v", rule)
	}
	requestResult(t, server, http.MethodPut, "/accounts/account-1/gateway/rules/"+rule.ID, map[string]any{
		"name": "private-egress", "enabled": false, "precedence": 101, "filters": []string{"dns"},
		"action": "override", "traffic": "dns.fqdn == \"private.example\"", "rule_settings": map[string]any{"override_ips": []string{"100.80.0.1"}},
	}, &rule)
	if rule.Enabled || rule.Filters[0] != "dns" || rule.Action != "override" {
		t.Fatalf("updated Gateway rule = %#v", rule)
	}

	requestResult[any](t, server, http.MethodDelete, "/accounts/account-1/gateway/rules/"+rule.ID, nil, nil)
	requestResult[any](t, server, http.MethodDelete, "/accounts/account-1/gateway/lists/"+list.ID, nil, nil)
	var rules []GatewayRule
	requestResult(t, server, http.MethodGet, "/accounts/account-1/gateway/rules", nil, &rules)
	if len(rules) != 0 {
		t.Fatalf("active Gateway rules after deletion = %#v", rules)
	}
	var lists []GatewayList
	requestResult(t, server, http.MethodGet, "/accounts/account-1/gateway/lists", nil, &lists)
	if len(lists) != 0 {
		t.Fatalf("Gateway lists after deletion = %#v", lists)
	}
}

func TestDevicePolicyWholeListsAndCustomProfileLifecycle(t *testing.T) {
	server := New(t)
	var profile DevicePolicy
	requestResult(t, server, http.MethodPost, "/accounts/account-1/devices/policy", map[string]any{
		"name": "flareway-e2e-deadbeef", "match": "identity.email == \"nobody@example.invalid\"", "precedence": 999,
	}, &profile)
	profileID := stringField(profile, "policy_id")
	if profileID == "" || profile["default"] != false {
		t.Fatalf("created custom device profile = %#v", profile)
	}

	include := []any{map[string]any{"address": "10.96.0.0/12", "description": "k8s"}, map[string]any{"host": "private.example.internal"}}
	fallback := []any{map[string]any{"suffix": "corp.example", "dns_server": []string{"10.0.0.53"}}}
	requestResult(t, server, http.MethodPut, "/accounts/account-1/devices/policy/"+profileID+"/include", include, &include)
	requestResult(t, server, http.MethodPut, "/accounts/account-1/devices/policy/"+profileID+"/fallback_domains", fallback, &fallback)
	var gotInclude, gotFallback []map[string]any
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/policy/"+profileID+"/include", nil, &gotInclude)
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/policy/"+profileID+"/fallback_domains", nil, &gotFallback)
	if len(gotInclude) != 2 || gotInclude[0]["address"] != "10.96.0.0/12" || len(gotFallback) != 1 || gotFallback[0]["suffix"] != "corp.example" {
		t.Fatalf("custom profile lists include=%#v fallback=%#v", gotInclude, gotFallback)
	}

	requestResult[any](t, server, http.MethodDelete, "/accounts/account-1/devices/policy/"+profileID, nil, nil)
	var profiles []DevicePolicy
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/policies", nil, &profiles)
	if len(profiles) != 0 {
		t.Fatalf("custom profiles after delete = %#v", profiles)
	}

	defaultInclude := []any{map[string]any{"address": "100.80.0.0/16"}}
	requestResult(t, server, http.MethodPut, "/accounts/account-1/devices/policy/include", defaultInclude, &defaultInclude)
	var gotDefault []map[string]any
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/policy/include", nil, &gotDefault)
	if len(gotDefault) != 1 || gotDefault[0]["address"] != "100.80.0.0/16" {
		t.Fatalf("default include = %#v", gotDefault)
	}
}
