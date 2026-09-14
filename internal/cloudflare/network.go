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
	"fmt"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// NetworkAPI is the complete M4 private-network Cloudflare surface.
type NetworkAPI interface {
	VirtualNetworkAPI
	NetworkRouteAPI
	HostnameRouteAPI
	DeviceSettingsAPI
}

// VirtualNetworkAPI manages Cloudflare virtual networks.
type VirtualNetworkAPI interface {
	CreateVirtualNetwork(context.Context, VirtualNetworkInput) (VirtualNetwork, error)
	UpdateVirtualNetwork(context.Context, string, VirtualNetworkInput) (VirtualNetwork, error)
	GetVirtualNetwork(context.Context, string) (VirtualNetwork, error)
	ListVirtualNetworks(context.Context) ([]VirtualNetwork, error)
	DeleteVirtualNetwork(context.Context, string) error
}

// NetworkRouteAPI manages CIDR routes through Cloudflare Tunnels.
type NetworkRouteAPI interface {
	CreateNetworkRoute(context.Context, NetworkRouteInput) (NetworkRoute, error)
	UpdateNetworkRoute(context.Context, string, NetworkRouteInput) (NetworkRoute, error)
	GetNetworkRoute(context.Context, string) (NetworkRoute, error)
	ListNetworkRoutes(context.Context) ([]NetworkRoute, error)
	DeleteNetworkRoute(context.Context, string) error
}

// HostnameRouteAPI manages private hostname routes through Cloudflare Tunnels.
type HostnameRouteAPI interface {
	CreateHostnameRoute(context.Context, HostnameRouteInput) (HostnameRoute, error)
	UpdateHostnameRoute(context.Context, string, HostnameRouteInput) (HostnameRoute, error)
	GetHostnameRoute(context.Context, string) (HostnameRoute, error)
	ListHostnameRoutes(context.Context) ([]HostnameRoute, error)
	DeleteHostnameRoute(context.Context, string) error
}

// VirtualNetworkInput is part of the Cloudflare adapter API.
type VirtualNetworkInput struct {
	Name      string
	IsDefault bool
	Comment   string
}

// VirtualNetwork is part of the Cloudflare adapter API.
type VirtualNetwork struct {
	ID        string
	Name      string
	IsDefault bool
	Comment   string
	Deleted   bool
}

// NetworkRouteInput is part of the Cloudflare adapter API.
type NetworkRouteInput struct {
	Network          string
	TunnelID         string
	VirtualNetworkID string
	Comment          string
}

// NetworkRoute is part of the Cloudflare adapter API.
type NetworkRoute struct {
	ID               string
	Network          string
	TunnelID         string
	VirtualNetworkID string
	Comment          string
	Deleted          bool
}

// HostnameRouteInput is part of the Cloudflare adapter API.
type HostnameRouteInput struct {
	Hostname string
	TunnelID string
	Comment  string
}

// HostnameRoute is part of the Cloudflare adapter API.
type HostnameRoute struct {
	ID       string
	Hostname string
	TunnelID string
	Comment  string
	Deleted  bool
}

// CreateVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) CreateVirtualNetwork(ctx context.Context, input VirtualNetworkInput) (VirtualNetwork, error) {
	remote, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.New(ctx, zero_trust.NetworkVirtualNetworkNewParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		Name:             cloudflaresdk.F(input.Name),
		Comment:          cloudflaresdk.F(input.Comment),
		IsDefaultNetwork: cloudflaresdk.F(input.IsDefault),
	})
	if err != nil {
		return VirtualNetwork{}, fmt.Errorf("create Cloudflare virtual network: %w", err)
	}
	return virtualNetworkFromSDK(remote), nil
}

// UpdateVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) UpdateVirtualNetwork(ctx context.Context, id string, input VirtualNetworkInput) (VirtualNetwork, error) {
	remote, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.Edit(ctx, id, zero_trust.NetworkVirtualNetworkEditParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		Name:             cloudflaresdk.F(input.Name),
		Comment:          cloudflaresdk.F(input.Comment),
		IsDefaultNetwork: cloudflaresdk.F(input.IsDefault),
	})
	if err != nil {
		return VirtualNetwork{}, fmt.Errorf("update Cloudflare virtual network: %w", err)
	}
	return virtualNetworkFromSDK(remote), nil
}

// GetVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) GetVirtualNetwork(ctx context.Context, id string) (VirtualNetwork, error) {
	remote, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.Get(ctx, id, zero_trust.NetworkVirtualNetworkGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return VirtualNetwork{}, fmt.Errorf("get Cloudflare virtual network: %w", err)
	}
	return virtualNetworkFromSDK(remote), nil
}

// ListVirtualNetworks is part of the Cloudflare adapter API.
func (client *Client) ListVirtualNetworks(ctx context.Context) ([]VirtualNetwork, error) {
	pager := client.sdk.ZeroTrust.Networks.VirtualNetworks.ListAutoPaging(ctx, zero_trust.NetworkVirtualNetworkListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
	})
	result := make([]VirtualNetwork, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, virtualNetworkFromSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare virtual networks: %w", err)
	}
	return result, nil
}

// DeleteVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) DeleteVirtualNetwork(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.Delete(ctx, id, zero_trust.NetworkVirtualNetworkDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Cloudflare virtual network: %w", err)
	}
	return nil
}

// CreateNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) CreateNetworkRoute(ctx context.Context, input NetworkRouteInput) (NetworkRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.Routes.New(ctx, zero_trust.NetworkRouteNewParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		Network:          cloudflaresdk.F(input.Network),
		TunnelID:         cloudflaresdk.F(input.TunnelID),
		VirtualNetworkID: cloudflaresdk.F(input.VirtualNetworkID),
		Comment:          cloudflaresdk.F(input.Comment),
	})
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("create Cloudflare network route: %w", err)
	}
	return networkRouteFromSDK(remote), nil
}

// UpdateNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) UpdateNetworkRoute(ctx context.Context, id string, input NetworkRouteInput) (NetworkRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.Routes.Edit(ctx, id, zero_trust.NetworkRouteEditParams{
		AccountID:        cloudflaresdk.F(client.accountID),
		Network:          cloudflaresdk.F(input.Network),
		TunnelID:         cloudflaresdk.F(input.TunnelID),
		VirtualNetworkID: cloudflaresdk.F(input.VirtualNetworkID),
		Comment:          cloudflaresdk.F(input.Comment),
	})
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("update Cloudflare network route: %w", err)
	}
	return networkRouteFromSDK(remote), nil
}

// GetNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) GetNetworkRoute(ctx context.Context, id string) (NetworkRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.Routes.Get(ctx, id, zero_trust.NetworkRouteGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("get Cloudflare network route: %w", err)
	}
	return networkRouteFromSDK(remote), nil
}

// ListNetworkRoutes is part of the Cloudflare adapter API.
func (client *Client) ListNetworkRoutes(ctx context.Context) ([]NetworkRoute, error) {
	pager := client.sdk.ZeroTrust.Networks.Routes.ListAutoPaging(ctx, zero_trust.NetworkRouteListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
	})
	result := make([]NetworkRoute, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, NetworkRoute{
			ID: remote.ID, Network: remote.Network, TunnelID: remote.TunnelID,
			VirtualNetworkID: remote.VirtualNetworkID, Comment: remote.Comment,
			Deleted: !remote.DeletedAt.IsZero(),
		})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare network routes: %w", err)
	}
	return result, nil
}

// DeleteNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) DeleteNetworkRoute(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Networks.Routes.Delete(ctx, id, zero_trust.NetworkRouteDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Cloudflare network route: %w", err)
	}
	return nil
}

// CreateHostnameRoute is part of the Cloudflare adapter API.
func (client *Client) CreateHostnameRoute(ctx context.Context, input HostnameRouteInput) (HostnameRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.New(ctx, zero_trust.NetworkHostnameRouteNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Hostname:  cloudflaresdk.F(input.Hostname),
		TunnelID:  cloudflaresdk.F(input.TunnelID),
		Comment:   cloudflaresdk.F(input.Comment),
	})
	if err != nil {
		return HostnameRoute{}, fmt.Errorf("create Cloudflare hostname route: %w", err)
	}
	return hostnameRouteFromSDK(remote), nil
}

// UpdateHostnameRoute is part of the Cloudflare adapter API.
func (client *Client) UpdateHostnameRoute(ctx context.Context, id string, input HostnameRouteInput) (HostnameRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.Edit(ctx, id, zero_trust.NetworkHostnameRouteEditParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Hostname:  cloudflaresdk.F(input.Hostname),
		TunnelID:  cloudflaresdk.F(input.TunnelID),
		Comment:   cloudflaresdk.F(input.Comment),
	})
	if err != nil {
		return HostnameRoute{}, fmt.Errorf("update Cloudflare hostname route: %w", err)
	}
	return hostnameRouteFromSDK(remote), nil
}

// GetHostnameRoute is part of the Cloudflare adapter API.
func (client *Client) GetHostnameRoute(ctx context.Context, id string) (HostnameRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.Get(ctx, id, zero_trust.NetworkHostnameRouteGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return HostnameRoute{}, fmt.Errorf("get Cloudflare hostname route: %w", err)
	}
	return hostnameRouteFromSDK(remote), nil
}

// ListHostnameRoutes is part of the Cloudflare adapter API.
func (client *Client) ListHostnameRoutes(ctx context.Context) ([]HostnameRoute, error) {
	pager := client.sdk.ZeroTrust.Networks.HostnameRoutes.ListAutoPaging(ctx, zero_trust.NetworkHostnameRouteListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
	})
	result := make([]HostnameRoute, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, hostnameRouteFromSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare hostname routes: %w", err)
	}
	return result, nil
}

// DeleteHostnameRoute is part of the Cloudflare adapter API.
func (client *Client) DeleteHostnameRoute(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.Delete(ctx, id, zero_trust.NetworkHostnameRouteDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Cloudflare hostname route: %w", err)
	}
	return nil
}

func virtualNetworkFromSDK(remote *zero_trust.VirtualNetwork) VirtualNetwork {
	return VirtualNetwork{ID: remote.ID, Name: remote.Name, IsDefault: remote.IsDefaultNetwork, Comment: remote.Comment, Deleted: !remote.DeletedAt.IsZero()}
}

func networkRouteFromSDK(remote *zero_trust.Route) NetworkRoute {
	return NetworkRoute{ID: remote.ID, Network: remote.Network, TunnelID: remote.TunnelID, VirtualNetworkID: remote.VirtualNetworkID, Comment: remote.Comment, Deleted: !remote.DeletedAt.IsZero()}
}

func hostnameRouteFromSDK(remote *zero_trust.HostnameRoute) HostnameRoute {
	return HostnameRoute{ID: remote.ID, Hostname: remote.Hostname, TunnelID: remote.TunnelID, Comment: remote.Comment, Deleted: !remote.DeletedAt.IsZero()}
}
