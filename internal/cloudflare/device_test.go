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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
)

type deviceAdapterCall struct {
	method string
	path   string
	body   any
}

func TestDeviceAdaptersPreserveOptionalAndWholeListSemantics(t *testing.T) {
	var mu sync.Mutex
	var calls []deviceAdapterCall
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body any
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&body)
		}
		mu.Lock()
		calls = append(calls, deviceAdapterCall{method: request.Method, path: request.URL.Path, body: body})
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPatch && request.URL.Path == "/accounts/account/devices/settings":
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"disable_for_time":0,"gateway_proxy_enabled":false,"gateway_udp_proxy_enabled":true,"root_certificate_installation_enabled":true,"use_zt_virtual_ip":false}}`); err != nil {
				t.Fatal(err)
			}
		case request.Method == http.MethodPatch && request.URL.Path == "/accounts/account/devices/policy/custom-id":
			if _, err := fmt.Fprint(response, deviceProfileEnvelope); err != nil {
				t.Fatal(err)
			}
		case request.Method == http.MethodPut && request.URL.Path == "/accounts/account/devices/policy/custom-id/include":
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[{"host":"*.example.com","description":"apps"}],"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}}`); err != nil {
				t.Fatal(err)
			}
		case request.Method == http.MethodPut && request.URL.Path == "/accounts/account/devices/policy/exclude":
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[{"address":"10.0.0.0/8","description":"private"}],"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}}`); err != nil {
				t.Fatal(err)
			}
		case request.Method == http.MethodPut && request.URL.Path == "/accounts/account/devices/policy/custom-id/fallback_domains":
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`); err != nil {
				t.Fatal(err)
			}
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()
	falseValue := false
	zero := int64(0)
	settings, err := client.UpdateDeviceSettings(ctx, DeviceSettingsInput{GatewayProxyEnabled: &falseValue, DisableForTime: &zero})
	if err != nil || settings.GatewayProxyEnabled || settings.DisableForTime != 0 || !settings.GatewayUDPProxyEnabled {
		t.Fatalf("UpdateDeviceSettings() = %#v, %v", settings, err)
	}

	emptySuffixes := []DNSSearchSuffix{}
	profile, err := client.UpdateCustomDeviceProfile(ctx, "custom-id", DeviceProfileInput{Enabled: &falseValue, DNSSearchSuffixes: &emptySuffixes})
	if err != nil || profile.PolicyID != "custom-id" {
		t.Fatalf("UpdateCustomDeviceProfile() = %#v, %v", profile, err)
	}
	include, err := client.ReplaceDeviceProfileInclude(ctx, DeviceProfileRef{Kind: DeviceProfileKindCustom, ID: "custom-id"}, []SplitTunnelEntry{{Host: "*.example.com", Description: "apps"}})
	if err != nil || len(include) != 1 || include[0].Host != "*.example.com" {
		t.Fatalf("ReplaceDeviceProfileInclude() = %#v, %v", include, err)
	}
	exclude, err := client.ReplaceDeviceProfileExclude(ctx, DeviceProfileRef{Kind: DeviceProfileKindDefault}, []SplitTunnelEntry{{Address: "10.0.0.0/8", Description: "private"}})
	if err != nil || len(exclude) != 1 || exclude[0].Address != "10.0.0.0/8" {
		t.Fatalf("ReplaceDeviceProfileExclude() = %#v, %v", exclude, err)
	}
	fallback, err := client.ReplaceDeviceProfileFallbackDomains(ctx, DeviceProfileRef{Kind: DeviceProfileKindCustom, ID: "custom-id"}, []FallbackDomain{})
	if err != nil || len(fallback) != 0 {
		t.Fatalf("ReplaceDeviceProfileFallbackDomains() = %#v, %v", fallback, err)
	}

	settingsBody := findDeviceCall(t, calls, http.MethodPatch, "/accounts/account/devices/settings")
	assertJSONKeys(t, settingsBody, map[string]any{"gateway_proxy_enabled": false, "disable_for_time": float64(0)}, []string{"gateway_udp_proxy_enabled", "root_certificate_installation_enabled", "use_zt_virtual_ip"})
	profileBody := findDeviceCall(t, calls, http.MethodPatch, "/accounts/account/devices/policy/custom-id")
	assertJSONKeys(t, profileBody, map[string]any{"enabled": false, "dns_search_suffixes": []any{}}, []string{"switch_locked", "name", "match"})
	fallbackBody := findDeviceCall(t, calls, http.MethodPut, "/accounts/account/devices/policy/custom-id/fallback_domains")
	if values, ok := fallbackBody.([]any); !ok || len(values) != 0 {
		t.Fatalf("fallback replacement body = %#v, want empty array", fallbackBody)
	}
}

func TestDeviceAdapterRejectsAmbiguousWholeListEntry(t *testing.T) {
	client := New("token", "account", logr.Discard(), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	_, err := client.ReplaceDeviceProfileInclude(context.Background(), DeviceProfileRef{Kind: DeviceProfileKindDefault}, []SplitTunnelEntry{{Address: "10.0.0.0/8", Host: "example.com"}})
	if err == nil {
		t.Fatal("ReplaceDeviceProfileInclude() accepted an entry with both address and host")
	}
	lanMinutes := int64(10)
	_, err = client.UpdateDefaultDeviceProfile(context.Background(), DeviceProfileInput{LANAllowMinutes: &lanMinutes})
	if err == nil {
		t.Fatal("UpdateDefaultDeviceProfile() accepted custom-only LAN settings")
	}
}

func findDeviceCall(t *testing.T, calls []deviceAdapterCall, method, path string) any {
	t.Helper()
	for _, call := range calls {
		if call.method == method && call.path == path {
			return call.body
		}
	}
	t.Fatalf("missing %s %s call; calls = %#v", method, path, calls)
	return nil
}

func assertJSONKeys(t *testing.T, body any, present map[string]any, absent []string) {
	t.Helper()
	object, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("body = %#v, want object", body)
	}
	for key, want := range present {
		if got, exists := object[key]; !exists || !reflect.DeepEqual(got, want) {
			t.Fatalf("body[%q] = %#v, exists=%v, want %#v", key, got, exists, want)
		}
	}
	for _, key := range absent {
		if _, exists := object[key]; exists {
			t.Fatalf("body unexpectedly contains %q: %#v", key, body)
		}
	}
}

const deviceProfileEnvelope = `{"success":true,"errors":[],"messages":[],"result":{"policy_id":"custom-id","default":false,"name":"custom","description":"","enabled":false,"match":"identity.email matches \".*@example.com\"","precedence":100,"switch_locked":false,"captive_portal":0,"allow_mode_switch":false,"allow_updates":false,"allowed_to_leave":false,"auto_connect":0,"disable_auto_fallback":false,"exclude_office_ips":false,"service_mode_v2":{"mode":"warp","port":0},"support_url":"","lan_allow_minutes":0,"lan_allow_subnet_size":0,"register_interface_ip_with_dns":false,"sccm_vpn_boundary_support":false,"tunnel_protocol":"masque","virtual_networks":{"default":"vnet","allowed":["vnet"]},"dns_search_suffixes":[],"include":[],"exclude":[],"fallback_domains":[]}}`
