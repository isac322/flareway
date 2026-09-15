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

func TestPrivateNetworkEndpointsPreserveStatePaginationAndDeletion(t *testing.T) {
	server := New(t)
	server.State.SetDeviceSettings("account-1", DeviceSettings{
		GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true,
	})

	var settings DeviceSettings
	requestResult(t, server, http.MethodGet, "/accounts/account-1/devices/settings", nil, &settings)
	if !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled {
		t.Fatalf("device settings = %#v, want both Gateway proxies enabled", settings)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-2/devices/settings", nil, &settings)
	if settings.GatewayProxyEnabled || settings.GatewayUDPProxyEnabled {
		t.Fatalf("default device settings = %#v, want both Gateway proxies disabled", settings)
	}

	var firstNetwork, secondNetwork VirtualNetwork
	requestResult(t, server, http.MethodPost, "/accounts/account-1/teamnet/virtual_networks", map[string]any{
		"name": "private-a", "comment": "first", "is_default_network": true,
	}, &firstNetwork)
	requestResult(t, server, http.MethodPost, "/accounts/account-1/teamnet/virtual_networks", map[string]any{
		"name": "private-b", "comment": "second", "is_default": true,
	}, &secondNetwork)
	if firstNetwork.ID == "" || secondNetwork.ID == "" || firstNetwork.ID == secondNetwork.ID {
		t.Fatalf("virtual network IDs = %q, %q", firstNetwork.ID, secondNetwork.ID)
	}

	var networks []VirtualNetwork
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/virtual_networks?per_page=1&page=2", nil, &networks)
	if len(networks) != 1 || networks[0].ID != secondNetwork.ID {
		t.Fatalf("second virtual-network page = %#v", networks)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/virtual_networks?is_default=true", nil, &networks)
	if len(networks) != 1 || networks[0].ID != secondNetwork.ID {
		t.Fatalf("default virtual networks = %#v", networks)
	}

	requestResult(t, server, http.MethodPatch, "/accounts/account-1/teamnet/virtual_networks/"+firstNetwork.ID, map[string]any{
		"comment": "updated",
	}, &firstNetwork)
	if firstNetwork.Comment != "updated" {
		t.Fatalf("edited virtual network = %#v", firstNetwork)
	}

	var networkRoute NetworkRoute
	requestResult(t, server, http.MethodPost, "/accounts/account-1/teamnet/routes", map[string]any{
		"network": "10.96.0.0/12", "tunnel_id": "tunnel-1",
		"virtual_network_id": secondNetwork.ID, "comment": "services",
	}, &networkRoute)
	requestResult(t, server, http.MethodPatch, "/accounts/account-1/teamnet/routes/"+networkRoute.ID, map[string]any{
		"network": "10.100.0.0/16", "comment": "narrowed",
	}, &networkRoute)
	if networkRoute.Network != "10.100.0.0/16" || networkRoute.Comment != "narrowed" {
		t.Fatalf("edited network route = %#v", networkRoute)
	}
	var networkRoutes []NetworkRoute
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/routes?network_subset=10.0.0.0/8&tunnel_id=tunnel-1", nil, &networkRoutes)
	if len(networkRoutes) != 1 || networkRoutes[0].ID != networkRoute.ID {
		t.Fatalf("filtered network routes = %#v", networkRoutes)
	}

	var hostnameRoute HostnameRoute
	requestResult(t, server, http.MethodPost, "/accounts/account-1/zerotrust/routes/hostname", map[string]any{
		"hostname": "Private.Example.Internal.", "tunnel_id": "tunnel-1", "comment": "admin",
	}, &hostnameRoute)
	if hostnameRoute.Hostname != "private.example.internal" {
		t.Fatalf("normalized hostname route = %#v", hostnameRoute)
	}
	requestResult(t, server, http.MethodPatch, "/accounts/account-1/zerotrust/routes/hostname/"+hostnameRoute.ID, map[string]any{
		"comment": "updated-admin",
	}, &hostnameRoute)
	var hostnameRoutes []HostnameRoute
	requestResult(t, server, http.MethodGet, "/accounts/account-1/zerotrust/routes/hostname?hostname=EXAMPLE&tunnel_id=tunnel-1", nil, &hostnameRoutes)
	if len(hostnameRoutes) != 1 || hostnameRoutes[0].Comment != "updated-admin" {
		t.Fatalf("filtered hostname routes = %#v", hostnameRoutes)
	}

	requestResult[NetworkRoute](t, server, http.MethodDelete, "/accounts/account-1/teamnet/routes/"+networkRoute.ID, nil, nil)
	requestResult[HostnameRoute](t, server, http.MethodDelete, "/accounts/account-1/zerotrust/routes/hostname/"+hostnameRoute.ID, nil, nil)
	requestResult[VirtualNetwork](t, server, http.MethodDelete, "/accounts/account-1/teamnet/virtual_networks/"+firstNetwork.ID, nil, nil)

	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/routes", nil, &networkRoutes)
	if len(networkRoutes) != 0 {
		t.Fatalf("active network routes after delete = %#v", networkRoutes)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/routes?is_deleted=true", nil, &networkRoutes)
	if len(networkRoutes) != 1 || networkRoutes[0].DeletedAt == nil {
		t.Fatalf("deleted network routes = %#v", networkRoutes)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/zerotrust/routes/hostname?is_deleted=true", nil, &hostnameRoutes)
	if len(hostnameRoutes) != 1 || hostnameRoutes[0].DeletedAt == nil {
		t.Fatalf("deleted hostname routes = %#v", hostnameRoutes)
	}

	if got := server.State.VirtualNetworks("account-1"); len(got) != 2 || got[0].DeletedAt == nil {
		t.Fatalf("stored virtual networks = %#v", got)
	}
	if got := server.State.NetworkRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("stored network routes = %#v", got)
	}
	if got := server.State.HostnameRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("stored hostname routes = %#v", got)
	}
}

func TestPrivateNetworkListsPaginateEveryResource(t *testing.T) {
	server := New(t)
	for _, id := range []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"} {
		server.State.AddVirtualNetwork(VirtualNetwork{ID: id, AccountID: "account-1", Name: "vnet-" + id})
		server.State.AddNetworkRoute(NetworkRoute{ID: id, AccountID: "account-1", Network: "10.0.0.0/8", TunnelID: "tunnel-1"})
		server.State.AddHostnameRoute(HostnameRoute{ID: id, AccountID: "account-1", Hostname: "private.example.internal", TunnelID: "tunnel-1"})
	}

	var virtualNetworks []VirtualNetwork
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/virtual_networks?page=2&per_page=1", nil, &virtualNetworks)
	if len(virtualNetworks) != 1 || virtualNetworks[0].ID != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("virtual network page = %#v", virtualNetworks)
	}
	var networkRoutes []NetworkRoute
	requestResult(t, server, http.MethodGet, "/accounts/account-1/teamnet/routes?page=2&per_page=1", nil, &networkRoutes)
	if len(networkRoutes) != 1 || networkRoutes[0].ID != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("network route page = %#v", networkRoutes)
	}
	var hostnameRoutes []HostnameRoute
	requestResult(t, server, http.MethodGet, "/accounts/account-1/zerotrust/routes/hostname?page=2&per_page=1", nil, &hostnameRoutes)
	if len(hostnameRoutes) != 1 || hostnameRoutes[0].ID != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("hostname route page = %#v", hostnameRoutes)
	}
}

func TestPrivateNetworkEndpointsUseSharedFaultInjection(t *testing.T) {
	server := New(t)
	server.Fault(http.MethodGet, `^/accounts/account-1/teamnet/virtual_networks$`, Fault{
		Status: http.StatusTooManyRequests, RetryAfter: "7", Times: 1,
	})

	response := request(t, server, http.MethodGet, "/client/v4/accounts/account-1/teamnet/virtual_networks", nil)
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "7" {
		t.Fatalf("fault response status=%d retry-after=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}

	var networks []VirtualNetwork
	requestResult(t, server, http.MethodGet, "/client/v4/accounts/account-1/teamnet/virtual_networks", nil, &networks)
	if len(networks) != 0 {
		t.Fatalf("virtual networks after one-shot fault = %#v", networks)
	}
}
