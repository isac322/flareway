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
	"context"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestPrivateNetworkEndpointsDecodeThroughCloudflareSDKAdapter(t *testing.T) {
	server := New(t)
	server.State.SetDeviceSettings("account-1", DeviceSettings{
		GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true,
	})
	api := flarecloudflare.New(
		"api-token", "account-1", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	ctx := context.Background()

	settings, err := api.GetDeviceSettings(ctx)
	if err != nil || !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled {
		t.Fatalf("GetDeviceSettings = %#v, %v", settings, err)
	}

	virtualNetwork, err := api.CreateVirtualNetwork(ctx, flarecloudflare.VirtualNetworkInput{
		Name: "private", IsDefault: true, Comment: "created by flareway",
	})
	if err != nil || virtualNetwork.ID == "" || !virtualNetwork.IsDefault {
		t.Fatalf("CreateVirtualNetwork = %#v, %v", virtualNetwork, err)
	}
	virtualNetwork, err = api.UpdateVirtualNetwork(ctx, virtualNetwork.ID, flarecloudflare.VirtualNetworkInput{
		Name: "private-updated", Comment: "updated",
	})
	if err != nil || virtualNetwork.Name != "private-updated" || virtualNetwork.Comment != "updated" {
		t.Fatalf("UpdateVirtualNetwork = %#v, %v", virtualNetwork, err)
	}
	virtualNetworks, err := api.ListVirtualNetworks(ctx)
	if err != nil || len(virtualNetworks) != 1 || virtualNetworks[0].ID != virtualNetwork.ID {
		t.Fatalf("ListVirtualNetworks = %#v, %v", virtualNetworks, err)
	}

	networkRoute, err := api.CreateNetworkRoute(ctx, flarecloudflare.NetworkRouteInput{
		Network: "10.96.0.0/12", TunnelID: "00000000-0000-0000-0000-000000000100",
		VirtualNetworkID: virtualNetwork.ID, Comment: "service CIDR",
	})
	if err != nil || networkRoute.ID == "" || networkRoute.VirtualNetworkID != virtualNetwork.ID {
		t.Fatalf("CreateNetworkRoute = %#v, %v", networkRoute, err)
	}
	networkRoute, err = api.GetNetworkRoute(ctx, networkRoute.ID)
	if err != nil || networkRoute.Network != "10.96.0.0/12" {
		t.Fatalf("GetNetworkRoute = %#v, %v", networkRoute, err)
	}
	networkRoutes, err := api.ListNetworkRoutes(ctx)
	if err != nil || len(networkRoutes) != 1 || networkRoutes[0].ID != networkRoute.ID {
		t.Fatalf("ListNetworkRoutes = %#v, %v", networkRoutes, err)
	}

	hostnameRoute, err := api.CreateHostnameRoute(ctx, flarecloudflare.HostnameRouteInput{
		Hostname: "private.example.internal", TunnelID: networkRoute.TunnelID, Comment: "private admin",
	})
	if err != nil || hostnameRoute.ID == "" || hostnameRoute.Hostname != "private.example.internal" {
		t.Fatalf("CreateHostnameRoute = %#v, %v", hostnameRoute, err)
	}
	hostnameRoutes, err := api.ListHostnameRoutes(ctx)
	if err != nil || len(hostnameRoutes) != 1 || hostnameRoutes[0].ID != hostnameRoute.ID {
		t.Fatalf("ListHostnameRoutes = %#v, %v", hostnameRoutes, err)
	}

	if err := api.DeleteHostnameRoute(ctx, hostnameRoute.ID); err != nil {
		t.Fatalf("DeleteHostnameRoute: %v", err)
	}
	if err := api.DeleteNetworkRoute(ctx, networkRoute.ID); err != nil {
		t.Fatalf("DeleteNetworkRoute: %v", err)
	}
	if err := api.DeleteVirtualNetwork(ctx, virtualNetwork.ID); err != nil {
		t.Fatalf("DeleteVirtualNetwork: %v", err)
	}
	if got := server.State.HostnameRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("stored hostname routes after adapter delete = %#v", got)
	}
	if got := server.State.NetworkRoutes("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("stored network routes after adapter delete = %#v", got)
	}
	if got := server.State.VirtualNetworks("account-1"); len(got) != 1 || got[0].DeletedAt == nil {
		t.Fatalf("stored virtual networks after adapter delete = %#v", got)
	}

	server.Fault(http.MethodGet, `^/accounts/account-1/devices/settings$`, Fault{Status: http.StatusForbidden})
	if _, err := api.GetDeviceSettings(ctx); err == nil {
		t.Fatal("GetDeviceSettings succeeded through an injected forbidden response")
	}
}
