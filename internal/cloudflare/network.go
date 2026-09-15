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
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// NetworkAPI is the private-network surface shared by reconcilers.
type NetworkAPI interface {
	VirtualNetworkAPI
	NetworkRouteAPI
	NetworkRouteIPAPI
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

// NetworkRouteAPI manages CIDR routes through Cloudflare private-network connectors.
type NetworkRouteAPI interface {
	CreateNetworkRoute(context.Context, NetworkRouteInput) (NetworkRoute, error)
	UpdateNetworkRoute(context.Context, string, NetworkRouteInput) (NetworkRoute, error)
	GetNetworkRoute(context.Context, string) (NetworkRoute, error)
	ListNetworkRoutes(context.Context) ([]NetworkRoute, error)
	DeleteNetworkRoute(context.Context, string) error
}

// NetworkRouteIPAPI looks up the route containing an IP address.
type NetworkRouteIPAPI interface {
	LookupNetworkRoute(context.Context, NetworkRouteLookupInput) (NetworkRoute, error)
}

// HostnameRouteAPI manages private hostname routes through Cloudflare private-network connectors.
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
	CreatedAt time.Time
	DeletedAt *time.Time
	Deleted   bool
}

// NetworkTunnelType identifies the connector family serving a private route.
type NetworkTunnelType string

const (
	// NetworkTunnelTypeCloudflareTunnel identifies a Cloudflare Tunnel connector.
	NetworkTunnelTypeCloudflareTunnel NetworkTunnelType = "CloudflareTunnel"
	// NetworkTunnelTypeWARPConnector identifies a WARP Connector tunnel.
	NetworkTunnelTypeWARPConnector NetworkTunnelType = "WARPConnector"
	// NetworkTunnelTypeWARP identifies a WARP device route.
	NetworkTunnelTypeWARP NetworkTunnelType = "WARP"
	// NetworkTunnelTypeMagic identifies a Magic WAN tunnel.
	NetworkTunnelTypeMagic NetworkTunnelType = "Magic"
	// NetworkTunnelTypeIPSec identifies an IPsec tunnel.
	NetworkTunnelTypeIPSec NetworkTunnelType = "IPSec"
	// NetworkTunnelTypeGRE identifies a GRE tunnel.
	NetworkTunnelTypeGRE NetworkTunnelType = "GRE"
	// NetworkTunnelTypeCNI identifies a Cloudflare Network Interconnect route.
	NetworkTunnelTypeCNI NetworkTunnelType = "CNI"
	// NetworkTunnelTypeUnknown records an unrecognized connector family.
	NetworkTunnelTypeUnknown NetworkTunnelType = "Unknown"
)

// NetworkRouteInput is part of the Cloudflare adapter API.
type NetworkRouteInput struct {
	Network          string
	TunnelID         string
	TunnelType       NetworkTunnelType
	VirtualNetworkID string
	Comment          string
}

// NetworkRouteLookupInput selects the route containing one IP address.
type NetworkRouteLookupInput struct {
	IP                            string
	VirtualNetworkID              string
	DefaultVirtualNetworkFallback *bool
}

// NetworkRoute is part of the Cloudflare adapter API.
type NetworkRoute struct {
	ID                 string
	Network            string
	TunnelID           string
	TunnelType         NetworkTunnelType
	TunnelName         string
	VirtualNetworkID   string
	VirtualNetworkName string
	Comment            string
	CreatedAt          time.Time
	DeletedAt          *time.Time
	Deleted            bool
}

// HostnameRouteInput is part of the Cloudflare adapter API.
type HostnameRouteInput struct {
	Hostname   string
	TunnelID   string
	TunnelType NetworkTunnelType
	Comment    string
}

// HostnameRoute is part of the Cloudflare adapter API.
type HostnameRoute struct {
	ID         string
	Hostname   string
	TunnelID   string
	TunnelType NetworkTunnelType
	TunnelName string
	Comment    string
	CreatedAt  time.Time
	DeletedAt  *time.Time
	Deleted    bool
}

// CreateVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) CreateVirtualNetwork(ctx context.Context, input VirtualNetworkInput) (VirtualNetwork, error) {
	params := zero_trust.NetworkVirtualNetworkNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(input.Name),
	}
	if input.Comment != "" {
		params.Comment = cloudflaresdk.F(input.Comment)
	}
	if input.IsDefault {
		params.IsDefaultNetwork = cloudflaresdk.F(true)
	}
	remote, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.New(ctx, params)
	if err != nil {
		return VirtualNetwork{}, fmt.Errorf("create Cloudflare virtual network: %w", err)
	}
	if remote == nil || remote.ID == "" {
		return VirtualNetwork{}, fmt.Errorf("create Cloudflare virtual network: response has no virtual network ID")
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
	if remote == nil || remote.ID == "" {
		return VirtualNetwork{}, fmt.Errorf("update Cloudflare virtual network: response has no virtual network ID")
	}
	return virtualNetworkFromSDK(remote), nil
}

// GetVirtualNetwork is part of the Cloudflare adapter API.
func (client *Client) GetVirtualNetwork(ctx context.Context, id string) (VirtualNetwork, error) {
	remote, err := client.sdk.ZeroTrust.Networks.VirtualNetworks.Get(ctx, id, zero_trust.NetworkVirtualNetworkGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return VirtualNetwork{}, fmt.Errorf("get Cloudflare virtual network: %w", err)
	}
	if remote == nil || remote.ID == "" {
		return VirtualNetwork{}, fmt.Errorf("get Cloudflare virtual network: response has no virtual network ID")
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
	params := zero_trust.NetworkRouteNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Network:   cloudflaresdk.F(input.Network),
		TunnelID:  cloudflaresdk.F(input.TunnelID),
	}
	if input.VirtualNetworkID != "" {
		params.VirtualNetworkID = cloudflaresdk.F(input.VirtualNetworkID)
	}
	if input.Comment != "" {
		params.Comment = cloudflaresdk.F(input.Comment)
	}
	remote, err := client.sdk.ZeroTrust.Networks.Routes.New(ctx, params)
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("create Cloudflare network route: %w", err)
	}
	if remote == nil || remote.ID == "" {
		return NetworkRoute{}, fmt.Errorf("create Cloudflare network route: response has no route ID")
	}
	return client.GetNetworkRoute(ctx, remote.ID)
}

// UpdateNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) UpdateNetworkRoute(ctx context.Context, id string, input NetworkRouteInput) (NetworkRoute, error) {
	params := zero_trust.NetworkRouteEditParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Network:   cloudflaresdk.F(input.Network),
		TunnelID:  cloudflaresdk.F(input.TunnelID),
		Comment:   cloudflaresdk.F(input.Comment),
	}
	if input.VirtualNetworkID != "" {
		params.VirtualNetworkID = cloudflaresdk.F(input.VirtualNetworkID)
	}
	remote, err := client.sdk.ZeroTrust.Networks.Routes.Edit(ctx, id, params)
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("update Cloudflare network route: %w", err)
	}
	if remote != nil && remote.ID != "" {
		id = remote.ID
	}
	return client.GetNetworkRoute(ctx, id)
}

// GetNetworkRoute is part of the Cloudflare adapter API.
func (client *Client) GetNetworkRoute(ctx context.Context, id string) (NetworkRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.Routes.Get(ctx, id, zero_trust.NetworkRouteGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("get Cloudflare network route: %w", err)
	}
	if remote == nil {
		return NetworkRoute{}, fmt.Errorf("get Cloudflare network route: response has no route")
	}
	result := networkRouteFromSDK(remote)
	if result.Deleted {
		return result, nil
	}
	params := zero_trust.NetworkRouteListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
		RouteID:   cloudflaresdk.F(id),
	}
	remotes, listErr := client.listNetworkRoutes(ctx, params)
	if listErr != nil {
		return NetworkRoute{}, fmt.Errorf("get Cloudflare network route metadata: %w", listErr)
	}
	if len(remotes) != 1 {
		return NetworkRoute{}, fmt.Errorf("get Cloudflare network route metadata: route %q matched %d active routes", id, len(remotes))
	}
	return remotes[0], nil
}

// ListNetworkRoutes returns all active CIDR routes.
func (client *Client) ListNetworkRoutes(ctx context.Context) ([]NetworkRoute, error) {
	return client.listNetworkRoutes(ctx, zero_trust.NetworkRouteListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
	})
}

func (client *Client) listNetworkRoutes(ctx context.Context, params zero_trust.NetworkRouteListParams) ([]NetworkRoute, error) {
	pager := client.sdk.ZeroTrust.Networks.Routes.ListAutoPaging(ctx, params)
	result := make([]NetworkRoute, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, networkRouteFromTeamnetSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare network routes: %w", err)
	}
	return result, nil
}

// LookupNetworkRoute returns the route containing the requested IP address.
func (client *Client) LookupNetworkRoute(ctx context.Context, input NetworkRouteLookupInput) (NetworkRoute, error) {
	params := zero_trust.NetworkRouteIPGetParams{AccountID: cloudflaresdk.F(client.accountID)}
	if input.VirtualNetworkID != "" {
		params.VirtualNetworkID = cloudflaresdk.F(input.VirtualNetworkID)
	}
	if input.DefaultVirtualNetworkFallback != nil {
		params.DefaultVirtualNetworkFallback = cloudflaresdk.F(*input.DefaultVirtualNetworkFallback)
	}
	remote, err := client.sdk.ZeroTrust.Networks.Routes.IPs.Get(ctx, input.IP, params)
	if err != nil {
		return NetworkRoute{}, fmt.Errorf("look up Cloudflare network route for IP %q: %w", input.IP, err)
	}
	if remote == nil {
		return NetworkRoute{}, fmt.Errorf("look up Cloudflare network route for IP %q: response has no route", input.IP)
	}
	return networkRouteFromTeamnetSDK(remote), nil
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
	params := zero_trust.NetworkHostnameRouteNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Hostname:  cloudflaresdk.F(input.Hostname),
		TunnelID:  cloudflaresdk.F(input.TunnelID),
	}
	if input.Comment != "" {
		params.Comment = cloudflaresdk.F(input.Comment)
	}
	remote, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.New(ctx, params)
	if err != nil {
		return HostnameRoute{}, fmt.Errorf("create Cloudflare hostname route: %w", err)
	}
	if remote == nil || remote.ID == "" {
		return HostnameRoute{}, fmt.Errorf("create Cloudflare hostname route: response has no route ID")
	}
	return client.GetHostnameRoute(ctx, remote.ID)
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
	if remote != nil && remote.ID != "" {
		id = remote.ID
	}
	return client.GetHostnameRoute(ctx, id)
}

// GetHostnameRoute is part of the Cloudflare adapter API.
func (client *Client) GetHostnameRoute(ctx context.Context, id string) (HostnameRoute, error) {
	remote, err := client.sdk.ZeroTrust.Networks.HostnameRoutes.Get(ctx, id, zero_trust.NetworkHostnameRouteGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return HostnameRoute{}, fmt.Errorf("get Cloudflare hostname route: %w", err)
	}
	if remote == nil || remote.ID == "" {
		return HostnameRoute{}, fmt.Errorf("get Cloudflare hostname route: response has no route ID")
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
	if remote == nil {
		return VirtualNetwork{}
	}
	result := VirtualNetwork{
		ID: remote.ID, Name: remote.Name, IsDefault: remote.IsDefaultNetwork,
		Comment: remote.Comment, CreatedAt: remote.CreatedAt, Deleted: !remote.DeletedAt.IsZero(),
	}
	result.DeletedAt = networkTimePointer(remote.DeletedAt)
	return result
}

func networkRouteFromSDK(remote *zero_trust.Route) NetworkRoute {
	if remote == nil {
		return NetworkRoute{}
	}
	result := NetworkRoute{
		ID: remote.ID, Network: remote.Network, TunnelID: remote.TunnelID,
		VirtualNetworkID: remote.VirtualNetworkID, Comment: remote.Comment,
		CreatedAt: remote.CreatedAt, Deleted: !remote.DeletedAt.IsZero(),
	}
	result.DeletedAt = networkTimePointer(remote.DeletedAt)
	return result
}

func networkRouteFromTeamnetSDK(remote *zero_trust.Teamnet) NetworkRoute {
	if remote == nil {
		return NetworkRoute{}
	}
	result := NetworkRoute{
		ID: remote.ID, Network: remote.Network, TunnelID: remote.TunnelID,
		TunnelType: networkTunnelTypeFromWire(string(remote.TunType)), TunnelName: remote.TunnelName,
		VirtualNetworkID: remote.VirtualNetworkID, VirtualNetworkName: remote.VirtualNetworkName,
		Comment: remote.Comment, CreatedAt: remote.CreatedAt, Deleted: !remote.DeletedAt.IsZero(),
	}
	result.DeletedAt = networkTimePointer(remote.DeletedAt)
	return result
}

func hostnameRouteFromSDK(remote *zero_trust.HostnameRoute) HostnameRoute {
	if remote == nil {
		return HostnameRoute{}
	}
	result := HostnameRoute{
		ID: remote.ID, Hostname: remote.Hostname, TunnelID: remote.TunnelID,
		TunnelType: networkTunnelTypeFromWire(string(remote.TunType)), TunnelName: remote.TunnelName,
		Comment: remote.Comment, CreatedAt: remote.CreatedAt, Deleted: !remote.DeletedAt.IsZero(),
	}
	result.DeletedAt = networkTimePointer(remote.DeletedAt)
	return result
}

func networkTunnelTypeFromWire(value string) NetworkTunnelType {
	switch value {
	case "":
		return ""
	case "cfd_tunnel":
		return NetworkTunnelTypeCloudflareTunnel
	case "warp_connector":
		return NetworkTunnelTypeWARPConnector
	case "warp":
		return NetworkTunnelTypeWARP
	case "magic":
		return NetworkTunnelTypeMagic
	case "ip_sec":
		return NetworkTunnelTypeIPSec
	case "gre":
		return NetworkTunnelTypeGRE
	case "cni":
		return NetworkTunnelTypeCNI
	default:
		return NetworkTunnelTypeUnknown
	}
}

func networkTimePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}
