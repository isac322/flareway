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
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
)

type networkAdapterCall struct {
	method string
	path   string
	body   map[string]any
}

func TestNetworkAdaptersUseTypedCloudflareEndpoints(t *testing.T) {
	var mu sync.Mutex
	calls := make([]networkAdapterCall, 0)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&body)
		}
		mu.Lock()
		calls = append(calls, networkAdapterCall{method: request.Method, path: request.URL.Path, body: body})
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/accounts/account/devices/settings":
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"gateway_proxy_enabled":true,"gateway_udp_proxy_enabled":true}}`); err != nil {
				t.Fatal(err)
			}
		case strings.Contains(request.URL.Path, "/teamnet/virtual_networks"):
			writeNetworkEnvelope(response, request.Method, request.URL.Path == "/accounts/account/teamnet/virtual_networks", request.URL.Query().Get("page"), virtualNetworkJSON)
		case strings.Contains(request.URL.Path, "/teamnet/routes"):
			writeNetworkEnvelope(response, request.Method, request.URL.Path == "/accounts/account/teamnet/routes", request.URL.Query().Get("page"), networkRouteJSON)
		case strings.Contains(request.URL.Path, "/zerotrust/routes/hostname"):
			writeNetworkEnvelope(response, request.Method, request.URL.Path == "/accounts/account/zerotrust/routes/hostname", request.URL.Query().Get("page"), hostnameRouteJSON)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()
	vnetInput := VirtualNetworkInput{Name: "prod", IsDefault: true, Comment: "owner"}
	vnet, err := client.CreateVirtualNetwork(ctx, vnetInput)
	if err != nil || vnet.ID != "vnet-id" || !vnet.IsDefault {
		t.Fatalf("CreateVirtualNetwork() = %#v, %v", vnet, err)
	}
	if _, err = client.UpdateVirtualNetwork(ctx, vnet.ID, vnetInput); err != nil {
		t.Fatal(err)
	}
	if _, err = client.GetVirtualNetwork(ctx, vnet.ID); err != nil {
		t.Fatal(err)
	}
	if list, listErr := client.ListVirtualNetworks(ctx); listErr != nil || len(list) != 1 || list[0].ID != vnet.ID {
		t.Fatalf("ListVirtualNetworks() = %#v, %v", list, listErr)
	}
	if err = client.DeleteVirtualNetwork(ctx, vnet.ID); err != nil {
		t.Fatal(err)
	}

	networkInput := NetworkRouteInput{Network: "10.96.0.0/12", TunnelID: "tunnel-id", VirtualNetworkID: "vnet-id", Comment: "owner"}
	networkRoute, err := client.CreateNetworkRoute(ctx, networkInput)
	if err != nil || networkRoute.ID != "network-route-id" {
		t.Fatalf("CreateNetworkRoute() = %#v, %v", networkRoute, err)
	}
	if _, err = client.UpdateNetworkRoute(ctx, networkRoute.ID, networkInput); err != nil {
		t.Fatal(err)
	}
	if _, err = client.GetNetworkRoute(ctx, networkRoute.ID); err != nil {
		t.Fatal(err)
	}
	if list, listErr := client.ListNetworkRoutes(ctx); listErr != nil || len(list) != 1 || list[0].VirtualNetworkID != "vnet-id" {
		t.Fatalf("ListNetworkRoutes() = %#v, %v", list, listErr)
	}
	if err = client.DeleteNetworkRoute(ctx, networkRoute.ID); err != nil {
		t.Fatal(err)
	}

	hostnameInput := HostnameRouteInput{Hostname: "example.internal", TunnelID: "tunnel-id", Comment: "owner"}
	hostnameRoute, err := client.CreateHostnameRoute(ctx, hostnameInput)
	if err != nil || hostnameRoute.ID != "hostname-route-id" {
		t.Fatalf("CreateHostnameRoute() = %#v, %v", hostnameRoute, err)
	}
	if _, err = client.UpdateHostnameRoute(ctx, hostnameRoute.ID, hostnameInput); err != nil {
		t.Fatal(err)
	}
	if _, err = client.GetHostnameRoute(ctx, hostnameRoute.ID); err != nil {
		t.Fatal(err)
	}
	if list, listErr := client.ListHostnameRoutes(ctx); listErr != nil || len(list) != 1 || list[0].Hostname != "example.internal" {
		t.Fatalf("ListHostnameRoutes() = %#v, %v", list, listErr)
	}
	if err = client.DeleteHostnameRoute(ctx, hostnameRoute.ID); err != nil {
		t.Fatal(err)
	}
	settings, err := client.GetDeviceSettings(ctx)
	if err != nil || !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled {
		t.Fatalf("GetDeviceSettings() = %#v, %v", settings, err)
	}

	assertNetworkAdapterCall(t, calls, http.MethodPost, "/accounts/account/teamnet/virtual_networks", "name", "prod")
	assertNetworkAdapterCall(t, calls, http.MethodPost, "/accounts/account/teamnet/routes", "network", "10.96.0.0/12")
	assertNetworkAdapterCall(t, calls, http.MethodPost, "/accounts/account/zerotrust/routes/hostname", "hostname", "example.internal")
	assertNetworkAdapterCall(t, calls, http.MethodGet, "/accounts/account/devices/settings", "", "")
}

func assertNetworkAdapterCall(t *testing.T, calls []networkAdapterCall, method, path, key, value string) {
	t.Helper()
	for _, call := range calls {
		if call.method != method || call.path != path {
			continue
		}
		if key != "" && call.body[key] != value {
			t.Fatalf("%s %s body[%q] = %#v, want %q", method, path, key, call.body[key], value)
		}
		return
	}
	t.Fatalf("missing %s %s call; calls = %#v", method, path, calls)
}

func writeNetworkEnvelope(response http.ResponseWriter, method string, collection bool, page, result string) {
	if method == http.MethodGet && collection {
		if page != "" && page != "1" {
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":2,"per_page":100,"count":0,"total_count":1,"total_pages":1}}`); err != nil {
				return
			}
			return
		}
		_, _ = fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":[%s],"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}}`, result)
		return
	}
	_, _ = fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":%s}`, result)
}

const virtualNetworkJSON = `{"id":"vnet-id","name":"prod","comment":"owner","created_at":"2026-09-13T00:00:00Z","is_default_network":true}`
const networkRouteJSON = `{"id":"network-route-id","network":"10.96.0.0/12","tunnel_id":"tunnel-id","virtual_network_id":"vnet-id","comment":"owner","created_at":"2026-09-13T00:00:00Z"}`
const hostnameRouteJSON = `{"id":"hostname-route-id","hostname":"example.internal","tunnel_id":"tunnel-id","tunnel_name":"tunnel","tun_type":"cfd_tunnel","comment":"owner","created_at":"2026-09-13T00:00:00Z"}`
