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
	"slices"
	"strings"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// WARPConnectorAPI is the complete Cloudflare WARP Connector surface. It covers
// the eleven official lifecycle, configuration, token, connection, connector,
// and failover endpoints in cloudflare-go v7.10.0.
// The SDK consumes response envelopes and page metadata; callers receive only
// typed results. Opaque metadata remains transport/read-only.
type WARPConnectorAPI interface {
	CreateWARPConnector(context.Context, WARPConnectorCreateInput) (WARPConnector, error)
	ListWARPConnectors(context.Context, WARPConnectorListFilter) ([]WARPConnector, error)
	DeleteWARPConnector(context.Context, string) (WARPConnector, error)
	UpdateWARPConnector(context.Context, string, WARPConnectorUpdateInput) (WARPConnector, error)
	GetWARPConnector(context.Context, string) (WARPConnector, error)
	UpdateWARPConnectorConfiguration(context.Context, string, WARPConnectorConfigurationInput) (WARPConnectorConfiguration, error)
	GetWARPConnectorConfiguration(context.Context, string) (WARPConnectorConfiguration, error)
	ListWARPConnectorClients(context.Context, string) ([]WARPConnectorClient, error)
	GetWARPConnectorClient(context.Context, string, string) (WARPConnectorClient, error)
	FailoverWARPConnector(context.Context, string, string) error
	GetWARPConnectorToken(context.Context, string) (string, error)
}

// WARPConnectorCreateInput contains mutable create-time fields. HighlyAvailable
// is create-only in Cloudflare and therefore intentionally absent from update.
type WARPConnectorCreateInput struct {
	Name            string
	HighlyAvailable *bool
}

// WARPConnectorUpdateInput exposes the official PATCH body. TunnelSecret is
// transport-only secret material and must never be copied into status, logs, or events.
type WARPConnectorUpdateInput struct {
	Name         *string
	TunnelSecret *string
}

// WARPConnectorListFilter exposes all optional filters accepted by the official list endpoint.
type WARPConnectorListFilter struct {
	ExcludePrefix *string
	ExistedAt     *time.Time
	IncludePrefix *string
	IsDeleted     *bool
	Name          *string
	Page          *int64
	PerPage       *int64
	Status        *TunnelStatus
	UUID          *string
	WasActiveAt   *time.Time
	WasInactiveAt *time.Time
}

// WARPConnector is non-secret tunnel state returned by lifecycle endpoints.
// Connections is empty because only the dedicated connection endpoints report it.
// Metadata is transport-only and is never persisted by a reconciler.
type WARPConnector struct {
	ID              string
	AccountTag      string
	Connections     []WARPConnectorConnection
	ConnsActiveAt   *time.Time
	ConnsInactiveAt *time.Time
	CreatedAt       *time.Time
	DeletedAt       *time.Time
	Metadata        any
	Name            string
	Status          TunnelStatus
	TunnelType      TunnelType
}

// Deleted reports whether Cloudflare has soft-deleted the connector tunnel.
func (connector WARPConnector) Deleted() bool {
	return connector.DeletedAt != nil
}

// WARPConnectorConnection is a single edge connection observation.
type WARPConnectorConnection struct {
	ID                 string
	ClientID           string
	ClientVersion      string
	ColoName           string
	IsPendingReconnect bool
	OpenedAt           *time.Time
	OriginIP           string
	UUID               string
}

// WARPConnectorHAMode is the public HA configuration mode.
type WARPConnectorHAMode string

const (
	// WARPConnectorHAModeNone disables high availability.
	WARPConnectorHAModeNone WARPConnectorHAMode = "None"
	// WARPConnectorHAModeDisabled marks high availability as disabled.
	WARPConnectorHAModeDisabled WARPConnectorHAMode = "Disabled"
	// WARPConnectorHAModeAWS selects AWS ENI failover.
	WARPConnectorHAModeAWS WARPConnectorHAMode = "AWS"
	// WARPConnectorHAModeLocal selects local-interface VIP failover.
	WARPConnectorHAModeLocal WARPConnectorHAMode = "Local"
)

// WARPConnectorConfigurationInput is the complete PUT configuration body.
type WARPConnectorConfigurationInput struct {
	Mode  WARPConnectorHAMode
	AWS   *WARPConnectorAWSConfiguration
	Local *WARPConnectorLocalConfiguration
}

// WARPConnectorAWSConfiguration configures AWS ENI failover.
type WARPConnectorAWSConfiguration struct {
	FloatingNetworkResourceID string
}

// WARPConnectorLocalConfiguration configures local-interface VIP failover.
type WARPConnectorLocalConfiguration struct {
	VIPs         []string
	VIPsPrevious []string
}

// WARPConnectorConfiguration is the non-secret result of the configuration endpoints.
type WARPConnectorConfiguration struct {
	Version   int64
	CreatedAt *time.Time
	Mode      WARPConnectorHAMode
	TunnelID  string
	AWS       *WARPConnectorAWSConfiguration
	Local     *WARPConnectorLocalConfiguration
	UpdatedAt *time.Time
}

// WARPConnectorClientHAStatus is the public HA role of a connector client.
type WARPConnectorClientHAStatus string

const (
	// WARPConnectorClientHAStatusOffline indicates an offline connector client.
	WARPConnectorClientHAStatusOffline WARPConnectorClientHAStatus = "Offline"
	// WARPConnectorClientHAStatusPassive indicates a passive connector client.
	WARPConnectorClientHAStatusPassive WARPConnectorClientHAStatus = "Passive"
	// WARPConnectorClientHAStatusActive indicates the active connector client.
	WARPConnectorClientHAStatusActive WARPConnectorClientHAStatus = "Active"
)

// WARPConnectorClient is one connector client and its current connections.
type WARPConnectorClient struct {
	ID          string
	Arch        string
	Connections []WARPConnectorConnection
	Features    []string
	HAStatus    WARPConnectorClientHAStatus
	RunAt       *time.Time
	Version     string
}

// CreateWARPConnector calls POST /accounts/{account_id}/warp_connector.
func (client *Client) CreateWARPConnector(ctx context.Context, input WARPConnectorCreateInput) (WARPConnector, error) {
	params := zero_trust.TunnelWARPConnectorNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(input.Name),
	}
	if input.HighlyAvailable != nil {
		params.Ha = cloudflaresdk.F(*input.HighlyAvailable)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.New(ctx, params)
	if err != nil {
		return WARPConnector{}, fmt.Errorf("create WARP Connector: %w", err)
	}
	return warpConnectorFromNew(result)
}

// ListWARPConnectors calls GET /accounts/{account_id}/warp_connector and consumes every page.
func (client *Client) ListWARPConnectors(ctx context.Context, filter WARPConnectorListFilter) ([]WARPConnector, error) {
	params := zero_trust.TunnelWARPConnectorListParams{AccountID: cloudflaresdk.F(client.accountID)}
	if filter.ExcludePrefix != nil {
		params.ExcludePrefix = cloudflaresdk.F(*filter.ExcludePrefix)
	}
	if filter.ExistedAt != nil {
		params.ExistedAt = cloudflaresdk.F(filter.ExistedAt.Format(time.RFC3339Nano))
	}
	if filter.IncludePrefix != nil {
		params.IncludePrefix = cloudflaresdk.F(*filter.IncludePrefix)
	}
	if filter.IsDeleted != nil {
		params.IsDeleted = cloudflaresdk.F(*filter.IsDeleted)
	}
	if filter.Name != nil {
		params.Name = cloudflaresdk.F(*filter.Name)
	}
	if filter.Page != nil {
		if *filter.Page <= 0 {
			return nil, fmt.Errorf("list WARP Connectors: page must be positive")
		}
		params.Page = cloudflaresdk.F(float64(*filter.Page))
	}
	if filter.PerPage != nil {
		if *filter.PerPage <= 0 {
			return nil, fmt.Errorf("list WARP Connectors: per-page limit must be positive")
		}
		params.PerPage = cloudflaresdk.F(float64(*filter.PerPage))
	}
	if filter.Status != nil {
		status, err := warpConnectorStatusToSDK(*filter.Status)
		if err != nil {
			return nil, fmt.Errorf("list WARP Connectors: %w", err)
		}
		params.Status = cloudflaresdk.F(status)
	}
	if filter.UUID != nil {
		if *filter.UUID == "" {
			return nil, fmt.Errorf("list WARP Connectors: UUID must not be empty")
		}
		params.UUID = cloudflaresdk.F(*filter.UUID)
	}
	if filter.WasActiveAt != nil {
		params.WasActiveAt = cloudflaresdk.F(*filter.WasActiveAt)
	}
	if filter.WasInactiveAt != nil {
		params.WasInactiveAt = cloudflaresdk.F(*filter.WasInactiveAt)
	}

	pager := client.sdk.ZeroTrust.Tunnels.WARPConnector.ListAutoPaging(ctx, params)
	result := make([]WARPConnector, 0)
	for pager.Next() {
		item := pager.Current()
		if item.ID == "" || item.Name == "" {
			continue
		}
		converted, err := warpConnectorFromList(&item)
		if err != nil {
			return nil, fmt.Errorf("list WARP Connectors: %w", err)
		}
		result = append(result, converted)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list WARP Connectors: %w", err)
	}
	slices.SortFunc(result, func(left, right WARPConnector) int {
		if compared := strings.Compare(left.Name, right.Name); compared != 0 {
			return compared
		}
		return strings.Compare(left.ID, right.ID)
	})
	return result, nil
}

// DeleteWARPConnector calls DELETE /accounts/{account_id}/warp_connector/{tunnel_id}.
func (client *Client) DeleteWARPConnector(ctx context.Context, tunnelID string) (WARPConnector, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Delete(ctx, tunnelID, zero_trust.TunnelWARPConnectorDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return WARPConnector{}, fmt.Errorf("delete WARP Connector: %w", err)
	}
	return warpConnectorFromDelete(result)
}

// UpdateWARPConnector calls PATCH /accounts/{account_id}/warp_connector/{tunnel_id}.
func (client *Client) UpdateWARPConnector(ctx context.Context, tunnelID string, input WARPConnectorUpdateInput) (WARPConnector, error) {
	params := zero_trust.TunnelWARPConnectorEditParams{AccountID: cloudflaresdk.F(client.accountID)}
	if input.Name != nil {
		params.Name = cloudflaresdk.F(*input.Name)
	}
	if input.TunnelSecret != nil {
		params.TunnelSecret = cloudflaresdk.F(*input.TunnelSecret)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Edit(ctx, tunnelID, params)
	if err != nil {
		return WARPConnector{}, fmt.Errorf("update WARP Connector: %w", err)
	}
	return warpConnectorFromEdit(result)
}

// GetWARPConnector calls GET /accounts/{account_id}/warp_connector/{tunnel_id}.
func (client *Client) GetWARPConnector(ctx context.Context, tunnelID string) (WARPConnector, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Get(ctx, tunnelID, zero_trust.TunnelWARPConnectorGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return WARPConnector{}, fmt.Errorf("get WARP Connector: %w", err)
	}
	return warpConnectorFromGet(result)
}

// UpdateWARPConnectorConfiguration calls PUT on the official HA configuration endpoint.
func (client *Client) UpdateWARPConnectorConfiguration(ctx context.Context, tunnelID string, input WARPConnectorConfigurationInput) (WARPConnectorConfiguration, error) {
	wireMode, err := warpConnectorHAModeToSDK(input.Mode)
	if err != nil {
		return WARPConnectorConfiguration{}, err
	}
	params := zero_trust.TunnelWARPConnectorConfigurationUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID),
		HaMode:    cloudflaresdk.F(wireMode),
	}
	switch input.Mode {
	case WARPConnectorHAModeAWS:
		if input.AWS == nil || input.AWS.FloatingNetworkResourceID == "" {
			return WARPConnectorConfiguration{}, fmt.Errorf("warp connector AWS HA mode requires floating network resource ID")
		}
		if input.Local != nil {
			return WARPConnectorConfiguration{}, fmt.Errorf("warp connector AWS HA mode does not accept local configuration")
		}
		params.Config = cloudflaresdk.F[zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigUnion](zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigTunnelMeshAwsConfig{
			FnrID: cloudflaresdk.F(input.AWS.FloatingNetworkResourceID),
		})
	case WARPConnectorHAModeLocal:
		if input.Local == nil || len(input.Local.VIPs) == 0 {
			return WARPConnectorConfiguration{}, fmt.Errorf("local WARP connector HA mode requires at least one virtual IP")
		}
		if input.AWS != nil {
			return WARPConnectorConfiguration{}, fmt.Errorf("local WARP connector HA mode does not accept AWS configuration")
		}
		vips := make([]zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigTunnelMeshLocalConfigVip, len(input.Local.VIPs))
		for index, address := range input.Local.VIPs {
			vips[index].Address = cloudflaresdk.F(address)
		}
		local := zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigTunnelMeshLocalConfig{Vips: cloudflaresdk.F(vips)}
		if len(input.Local.VIPsPrevious) > 0 {
			previous := make([]zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigTunnelMeshLocalConfigVipsPrevious, len(input.Local.VIPsPrevious))
			for index, address := range input.Local.VIPsPrevious {
				previous[index].Address = cloudflaresdk.F(address)
			}
			local.VipsPrevious = cloudflaresdk.F(previous)
		}
		params.Config = cloudflaresdk.F[zero_trust.TunnelWARPConnectorConfigurationUpdateParamsConfigUnion](local)
	case WARPConnectorHAModeNone, WARPConnectorHAModeDisabled:
		if input.AWS != nil || input.Local != nil {
			return WARPConnectorConfiguration{}, fmt.Errorf("%s WARP Connector HA mode does not accept provider configuration", input.Mode)
		}
		// Config must be omitted for these modes.
	default:
		return WARPConnectorConfiguration{}, fmt.Errorf("unsupported WARP Connector HA mode %q", input.Mode)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Configurations.Update(ctx, tunnelID, params)
	if err != nil {
		return WARPConnectorConfiguration{}, fmt.Errorf("update WARP Connector configuration: %w", err)
	}
	return warpConnectorConfigurationFromUpdate(result)
}

// GetWARPConnectorConfiguration calls GET on the official HA configuration endpoint.
func (client *Client) GetWARPConnectorConfiguration(ctx context.Context, tunnelID string) (WARPConnectorConfiguration, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Configurations.Get(ctx, tunnelID, zero_trust.TunnelWARPConnectorConfigurationGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return WARPConnectorConfiguration{}, fmt.Errorf("get WARP Connector configuration: %w", err)
	}
	return warpConnectorConfigurationFromGet(result)
}

// ListWARPConnectorClients calls the connections endpoint and consumes its single page.
func (client *Client) ListWARPConnectorClients(ctx context.Context, tunnelID string) ([]WARPConnectorClient, error) {
	pager := client.sdk.ZeroTrust.Tunnels.WARPConnector.Connections.GetAutoPaging(ctx, tunnelID, zero_trust.TunnelWARPConnectorConnectionGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	result := make([]WARPConnectorClient, 0)
	for pager.Next() {
		item := pager.Current()
		converted, err := warpConnectorClientFromConnection(&item)
		if err != nil {
			return nil, fmt.Errorf("list WARP Connector clients: %w", err)
		}
		result = append(result, converted)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list WARP Connector clients: %w", err)
	}
	slices.SortFunc(result, func(left, right WARPConnectorClient) int {
		return strings.Compare(left.ID, right.ID)
	})
	return result, nil
}

// GetWARPConnectorClient calls the connector detail endpoint.
func (client *Client) GetWARPConnectorClient(ctx context.Context, tunnelID, connectorID string) (WARPConnectorClient, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Connectors.Get(ctx, tunnelID, connectorID, zero_trust.TunnelWARPConnectorConnectorGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return WARPConnectorClient{}, fmt.Errorf("get WARP Connector client: %w", err)
	}
	return warpConnectorClientFromConnector(result)
}

// FailoverWARPConnector sets one linked client as active.
func (client *Client) FailoverWARPConnector(ctx context.Context, tunnelID, clientID string) error {
	_, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Failover.Update(ctx, tunnelID, zero_trust.TunnelWARPConnectorFailoverUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID), ClientID: cloudflaresdk.F(clientID),
	})
	if err != nil {
		return fmt.Errorf("fail over WARP Connector: %w", err)
	}
	return nil
}

// GetWARPConnectorToken returns secret connector bootstrap material.
func (client *Client) GetWARPConnectorToken(ctx context.Context, tunnelID string) (string, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.WARPConnector.Token.Get(ctx, tunnelID, zero_trust.TunnelWARPConnectorTokenGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return "", fmt.Errorf("get WARP Connector token: %w", err)
	}
	if result == nil {
		return "", fmt.Errorf("get WARP Connector token: Cloudflare returned no token")
	}
	return *result, nil
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return new(value)
}

func warpConnectorFromNew(remote *zero_trust.TunnelWARPConnectorNewResponse) (WARPConnector, error) {
	return warpConnectorFromLifecycle(remote.ID, remote.AccountTag, remote.ConnsActiveAt, remote.ConnsInactiveAt, remote.CreatedAt, remote.DeletedAt, remote.Metadata, remote.Name, string(remote.Status), string(remote.TunType))
}

func warpConnectorFromList(remote *zero_trust.TunnelWARPConnectorListResponse) (WARPConnector, error) {
	return warpConnectorFromLifecycle(remote.ID, remote.AccountTag, remote.ConnsActiveAt, remote.ConnsInactiveAt, remote.CreatedAt, remote.DeletedAt, remote.Metadata, remote.Name, string(remote.Status), string(remote.TunType))
}

func warpConnectorFromEdit(remote *zero_trust.TunnelWARPConnectorEditResponse) (WARPConnector, error) {
	return warpConnectorFromLifecycle(remote.ID, remote.AccountTag, remote.ConnsActiveAt, remote.ConnsInactiveAt, remote.CreatedAt, remote.DeletedAt, remote.Metadata, remote.Name, string(remote.Status), string(remote.TunType))
}

func warpConnectorFromGet(remote *zero_trust.TunnelWARPConnectorGetResponse) (WARPConnector, error) {
	return warpConnectorFromLifecycle(remote.ID, remote.AccountTag, remote.ConnsActiveAt, remote.ConnsInactiveAt, remote.CreatedAt, remote.DeletedAt, remote.Metadata, remote.Name, string(remote.Status), string(remote.TunType))
}

func warpConnectorFromDelete(remote *zero_trust.TunnelWARPConnectorDeleteResponse) (WARPConnector, error) {
	return warpConnectorFromLifecycle(remote.ID, remote.AccountTag, remote.ConnsActiveAt, remote.ConnsInactiveAt, remote.CreatedAt, remote.DeletedAt, remote.Metadata, remote.Name, string(remote.Status), string(remote.TunType))
}

func warpConnectorFromLifecycle(id, accountTag string, activeAt, inactiveAt, createdAt, deletedAt time.Time, metadata any, name, statusWire, tunnelTypeWire string) (WARPConnector, error) {
	status, err := warpConnectorStatusFromWire(statusWire)
	if err != nil {
		return WARPConnector{}, err
	}
	tunnelType, err := warpConnectorTunnelTypeFromWire(tunnelTypeWire)
	if err != nil {
		return WARPConnector{}, err
	}
	return WARPConnector{
		ID: id, AccountTag: accountTag,
		ConnsActiveAt: optionalTime(activeAt), ConnsInactiveAt: optionalTime(inactiveAt),
		CreatedAt: optionalTime(createdAt), DeletedAt: optionalTime(deletedAt),
		Metadata: metadata, Name: name, Status: status, TunnelType: tunnelType,
	}, nil
}

func warpConnectorConfigurationFromUpdate(remote *zero_trust.TunnelWARPConnectorConfigurationUpdateResponse) (WARPConnectorConfiguration, error) {
	mode, err := warpConnectorHAModeFromWire(string(remote.HaMode))
	if err != nil {
		return WARPConnectorConfiguration{}, err
	}
	result := WARPConnectorConfiguration{Version: remote.ConfigurationVersion, CreatedAt: optionalTime(remote.CreatedAt), Mode: mode, TunnelID: remote.TunnelID, UpdatedAt: optionalTime(remote.UpdatedAt)}
	switch config := remote.Config.AsUnion().(type) {
	case zero_trust.TunnelWARPConnectorConfigurationUpdateResponseConfigTunnelMeshAwsConfig:
		result.AWS = &WARPConnectorAWSConfiguration{FloatingNetworkResourceID: config.FnrID}
	case zero_trust.TunnelWARPConnectorConfigurationUpdateResponseConfigTunnelMeshLocalConfig:
		result.Local = localConfigurationFromUpdate(config)
	}
	return result, nil
}

func warpConnectorConfigurationFromGet(remote *zero_trust.TunnelWARPConnectorConfigurationGetResponse) (WARPConnectorConfiguration, error) {
	mode, err := warpConnectorHAModeFromWire(string(remote.HaMode))
	if err != nil {
		return WARPConnectorConfiguration{}, err
	}
	result := WARPConnectorConfiguration{Version: remote.ConfigurationVersion, CreatedAt: optionalTime(remote.CreatedAt), Mode: mode, TunnelID: remote.TunnelID, UpdatedAt: optionalTime(remote.UpdatedAt)}
	switch config := remote.Config.AsUnion().(type) {
	case zero_trust.TunnelWARPConnectorConfigurationGetResponseConfigTunnelMeshAwsConfig:
		result.AWS = &WARPConnectorAWSConfiguration{FloatingNetworkResourceID: config.FnrID}
	case zero_trust.TunnelWARPConnectorConfigurationGetResponseConfigTunnelMeshLocalConfig:
		result.Local = localConfigurationFromGet(config)
	}
	return result, nil
}

func localConfigurationFromUpdate(config zero_trust.TunnelWARPConnectorConfigurationUpdateResponseConfigTunnelMeshLocalConfig) *WARPConnectorLocalConfiguration {
	result := &WARPConnectorLocalConfiguration{VIPs: make([]string, len(config.Vips)), VIPsPrevious: make([]string, len(config.VipsPrevious))}
	for index := range config.Vips {
		result.VIPs[index] = config.Vips[index].Address
	}
	for index := range config.VipsPrevious {
		result.VIPsPrevious[index] = config.VipsPrevious[index].Address
	}
	return result
}

func localConfigurationFromGet(config zero_trust.TunnelWARPConnectorConfigurationGetResponseConfigTunnelMeshLocalConfig) *WARPConnectorLocalConfiguration {
	result := &WARPConnectorLocalConfiguration{VIPs: make([]string, len(config.Vips)), VIPsPrevious: make([]string, len(config.VipsPrevious))}
	for index := range config.Vips {
		result.VIPs[index] = config.Vips[index].Address
	}
	for index := range config.VipsPrevious {
		result.VIPsPrevious[index] = config.VipsPrevious[index].Address
	}
	return result
}

func warpConnectorClientFromConnection(remote *zero_trust.TunnelWARPConnectorConnectionGetResponse) (WARPConnectorClient, error) {
	haStatus, err := warpConnectorClientHAStatusFromWire(string(remote.HaStatus))
	if err != nil {
		return WARPConnectorClient{}, err
	}
	connections := make([]WARPConnectorConnection, len(remote.Conns))
	for index := range remote.Conns {
		value := remote.Conns[index]
		connections[index] = WARPConnectorConnection{ID: value.ID, ClientID: value.ClientID, ClientVersion: value.ClientVersion, ColoName: value.ColoName, OpenedAt: optionalTime(value.OpenedAt), OriginIP: value.OriginIP}
	}
	return WARPConnectorClient{ID: remote.ID, Arch: remote.Arch, Connections: connections, Features: append([]string(nil), remote.Features...), HAStatus: haStatus, RunAt: optionalTime(remote.RunAt), Version: remote.Version}, nil
}

func warpConnectorClientFromConnector(remote *zero_trust.TunnelWARPConnectorConnectorGetResponse) (WARPConnectorClient, error) {
	haStatus, err := warpConnectorClientHAStatusFromWire(string(remote.HaStatus))
	if err != nil {
		return WARPConnectorClient{}, err
	}
	connections := make([]WARPConnectorConnection, len(remote.Conns))
	for index := range remote.Conns {
		value := remote.Conns[index]
		connections[index] = WARPConnectorConnection{ID: value.ID, ClientID: value.ClientID, ClientVersion: value.ClientVersion, ColoName: value.ColoName, OpenedAt: optionalTime(value.OpenedAt), OriginIP: value.OriginIP}
	}
	return WARPConnectorClient{ID: remote.ID, Arch: remote.Arch, Connections: connections, Features: append([]string(nil), remote.Features...), HAStatus: haStatus, RunAt: optionalTime(remote.RunAt), Version: remote.Version}, nil
}

func warpConnectorStatusFromWire(value string) (TunnelStatus, error) {
	switch value {
	case "inactive":
		return TunnelStatusInactive, nil
	case "degraded":
		return TunnelStatusDegraded, nil
	case "healthy":
		return TunnelStatusHealthy, nil
	case "down":
		return TunnelStatusDown, nil
	default:
		return "", fmt.Errorf("unsupported WARP Connector status %q", value)
	}
}

func warpConnectorStatusToSDK(value TunnelStatus) (zero_trust.TunnelWARPConnectorListParamsStatus, error) {
	switch value {
	case TunnelStatusInactive:
		return zero_trust.TunnelWARPConnectorListParamsStatusInactive, nil
	case TunnelStatusDegraded:
		return zero_trust.TunnelWARPConnectorListParamsStatusDegraded, nil
	case TunnelStatusHealthy:
		return zero_trust.TunnelWARPConnectorListParamsStatusHealthy, nil
	case TunnelStatusDown:
		return zero_trust.TunnelWARPConnectorListParamsStatusDown, nil
	default:
		return "", fmt.Errorf("unsupported WARP Connector status %q", value)
	}
}

func warpConnectorTunnelTypeFromWire(value string) (TunnelType, error) {
	switch value {
	case "cfd_tunnel":
		return TunnelTypeCloudflared, nil
	case "warp_connector":
		return TunnelTypeWARPConnector, nil
	case "warp":
		return TunnelTypeWARP, nil
	case "magic":
		return TunnelTypeMagic, nil
	case "ip_sec":
		return TunnelTypeIPSec, nil
	case "gre":
		return TunnelTypeGRE, nil
	case "cni":
		return TunnelTypeCNI, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare tunnel type %q", value)
	}
}

func warpConnectorHAModeToSDK(value WARPConnectorHAMode) (zero_trust.TunnelWARPConnectorConfigurationUpdateParamsHaMode, error) {
	switch value {
	case WARPConnectorHAModeNone:
		return zero_trust.TunnelWARPConnectorConfigurationUpdateParamsHaModeNone, nil
	case WARPConnectorHAModeDisabled:
		return zero_trust.TunnelWARPConnectorConfigurationUpdateParamsHaModeDisabled, nil
	case WARPConnectorHAModeAWS:
		return zero_trust.TunnelWARPConnectorConfigurationUpdateParamsHaModeAws, nil
	case WARPConnectorHAModeLocal:
		return zero_trust.TunnelWARPConnectorConfigurationUpdateParamsHaModeLocal, nil
	default:
		return "", fmt.Errorf("unsupported WARP Connector HA mode %q", value)
	}
}

func warpConnectorHAModeFromWire(value string) (WARPConnectorHAMode, error) {
	switch value {
	case "none":
		return WARPConnectorHAModeNone, nil
	case "disabled":
		return WARPConnectorHAModeDisabled, nil
	case "aws":
		return WARPConnectorHAModeAWS, nil
	case "local":
		return WARPConnectorHAModeLocal, nil
	default:
		return "", fmt.Errorf("unsupported WARP Connector HA mode %q", value)
	}
}

func warpConnectorClientHAStatusFromWire(value string) (WARPConnectorClientHAStatus, error) {
	switch value {
	case "offline":
		return WARPConnectorClientHAStatusOffline, nil
	case "passive":
		return WARPConnectorClientHAStatusPassive, nil
	case "active":
		return WARPConnectorClientHAStatusActive, nil
	default:
		return "", fmt.Errorf("unsupported WARP Connector client HA status %q", value)
	}
}
