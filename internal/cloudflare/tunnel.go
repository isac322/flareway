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
	"sort"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

const maxTunnelObservations int64 = 50

// TunnelAPI is the remotely managed Cloudflare Tunnel surface used by controllers.
type TunnelAPI interface {
	CreateTunnel(ctx context.Context, name string) (Tunnel, error)
	GetTunnel(ctx context.Context, tunnelID string) (Tunnel, error)
	UpdateTunnelName(ctx context.Context, tunnelID, name string) (Tunnel, error)
	DeleteTunnel(ctx context.Context, tunnelID string, cascade bool) error
	GetTunnelToken(ctx context.Context, tunnelID string) (string, error)
	GetTunnelConfiguration(ctx context.Context, tunnelID string) (TunnelConfiguration, error)
	UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (TunnelConfiguration, error)
	IssueTunnelManagementToken(ctx context.Context, tunnelID string, resources []TunnelManagementResource) (string, error)
	GetTunnelConnector(ctx context.Context, tunnelID, connectorID string, limit int64) (TunnelConnector, error)
	ListTunnelConnections(ctx context.Context, tunnelID string, limit int64) ([]TunnelConnector, bool, error)
	EvictTunnelConnections(ctx context.Context, tunnelID string, connectorID *string) error
	WithTunnelLock(ctx context.Context, tunnelID string, fn func() error) error
}

// TunnelAdministrationAPI exposes account-wide lifecycle operations.
type TunnelAdministrationAPI interface {
	ListTunnels(ctx context.Context, options TunnelListOptions) ([]Tunnel, error)
}

// TunnelStatus is the observed Cloudflare Tunnel health.
type TunnelStatus string

const (
	// TunnelStatusInactive indicates that the tunnel has never connected.
	TunnelStatusInactive TunnelStatus = "Inactive"
	// TunnelStatusDegraded indicates that the tunnel is connected but unhealthy.
	TunnelStatusDegraded TunnelStatus = "Degraded"
	// TunnelStatusHealthy indicates that the tunnel is connected and serving traffic.
	TunnelStatusHealthy TunnelStatus = "Healthy"
	// TunnelStatusDown indicates that the tunnel has no active edge connections.
	TunnelStatusDown TunnelStatus = "Down"
)

// TunnelType identifies the Cloudflare tunnel implementation.
type TunnelType string

const (
	// TunnelTypeCloudflared identifies a cloudflared tunnel.
	TunnelTypeCloudflared TunnelType = "Cloudflared"
	// TunnelTypeWARPConnector identifies a WARP Connector tunnel.
	TunnelTypeWARPConnector TunnelType = "WARPConnector"
	// TunnelTypeWARP identifies a WARP tunnel.
	TunnelTypeWARP TunnelType = "WARP"
	// TunnelTypeMagic identifies a Magic WAN tunnel.
	TunnelTypeMagic TunnelType = "Magic"
	// TunnelTypeIPSec identifies an IPsec tunnel.
	TunnelTypeIPSec TunnelType = "IPSec"
	// TunnelTypeGRE identifies a GRE tunnel.
	TunnelTypeGRE TunnelType = "GRE"
	// TunnelTypeCNI identifies a Cloudflare Network Interconnect tunnel.
	TunnelTypeCNI TunnelType = "CNI"
)

// TunnelConfigSource identifies where a Cloudflare Tunnel is configured.
type TunnelConfigSource string

const (
	// TunnelConfigSourceLocal indicates configuration managed by the connector.
	TunnelConfigSourceLocal TunnelConfigSource = "Local"
	// TunnelConfigSourceCloudflare indicates configuration managed by Cloudflare.
	TunnelConfigSourceCloudflare TunnelConfigSource = "Cloudflare"
)

// TunnelManagementResource identifies a capability granted to a management token.
type TunnelManagementResource string

const (
	// TunnelManagementResourceLogs grants access to tunnel logs.
	TunnelManagementResourceLogs TunnelManagementResource = "Logs"
)

// TunnelListOptions contains optional Cloudflare Tunnel list filters.
type TunnelListOptions struct {
	ExcludePrefix *string
	ExistedAt     *time.Time
	IncludePrefix *string
	Deleted       *bool
	Name          *string
	Page          *int64
	PerPage       *int64
	Status        *TunnelStatus
	UUID          *string
	WasActiveAt   *time.Time
	WasInactiveAt *time.Time
}

// Tunnel is the non-secret remote tunnel state needed by reconcilers.
type Tunnel struct {
	ID                    string
	AccountTag            string
	Name                  string
	Status                TunnelStatus
	Type                  TunnelType
	ConfigSource          TunnelConfigSource
	CreatedAt             time.Time
	DeletedAt             *time.Time
	ConnectionsActiveAt   *time.Time
	ConnectionsInactiveAt *time.Time
}

// Deleted reports whether Cloudflare has soft-deleted the tunnel.
func (tunnel Tunnel) Deleted() bool {
	return tunnel.DeletedAt != nil
}

// TunnelConfiguration is a complete, versioned Cloudflare Tunnel configuration.
type TunnelConfiguration struct {
	AccountID string
	TunnelID  string
	Version   int64
	Source    TunnelConfigSource
	CreatedAt time.Time
	Config    json.RawMessage
}

// TunnelConnector is a bounded, non-secret cloudflared connector observation.
type TunnelConnector struct {
	ID                   string
	Architecture         string
	ConfigVersion        int64
	Connections          []TunnelConnection
	ConnectionsTruncated bool
	Features             []string
	FeaturesTruncated    bool
	RunAt                time.Time
	Version              string
}

// TunnelConnection is one observed connection between cloudflared and Cloudflare.
type TunnelConnection struct {
	ID               string
	ClientID         string
	ClientVersion    string
	ColoName         string
	PendingReconnect bool
	OpenedAt         time.Time
	OriginIP         string
	UUID             string
}

// CreateTunnel creates a remotely managed tunnel.
func (client *Client) CreateTunnel(ctx context.Context, name string) (Tunnel, error) {
	if name == "" {
		return Tunnel{}, fmt.Errorf("create Cloudflare tunnel: name must not be empty")
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.New(ctx, zero_trust.TunnelCloudflaredNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
		ConfigSrc: cloudflaresdk.F(zero_trust.TunnelCloudflaredNewParamsConfigSrcCloudflare),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("create Cloudflare tunnel: %w", err)
	}
	tunnel, err := tunnelFromSDK(result)
	if err != nil {
		return Tunnel{}, fmt.Errorf("create Cloudflare tunnel: %w", err)
	}
	if tunnel.Type != TunnelTypeCloudflared || tunnel.ConfigSource != TunnelConfigSourceCloudflare {
		return Tunnel{}, fmt.Errorf(
			"create Cloudflare tunnel: Cloudflare returned type %q with configuration source %q",
			tunnel.Type,
			tunnel.ConfigSource,
		)
	}
	return tunnel, nil
}

// GetTunnel fetches a tunnel by ID.
func (client *Client) GetTunnel(ctx context.Context, tunnelID string) (Tunnel, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return Tunnel{}, fmt.Errorf("get Cloudflare tunnel: %w", err)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("get Cloudflare tunnel: %w", err)
	}
	tunnel, err := tunnelFromSDK(result)
	if err != nil {
		return Tunnel{}, fmt.Errorf("get Cloudflare tunnel: %w", err)
	}
	return tunnel, nil
}

// ListTunnels returns tunnels matching the requested account-scoped filters.
func (client *Client) ListTunnels(ctx context.Context, options TunnelListOptions) ([]Tunnel, error) {
	params := zero_trust.TunnelCloudflaredListParams{AccountID: cloudflaresdk.F(client.accountID)}
	if options.ExcludePrefix != nil {
		params.ExcludePrefix = cloudflaresdk.F(*options.ExcludePrefix)
	}
	if options.ExistedAt != nil {
		params.ExistedAt = cloudflaresdk.F(options.ExistedAt.Format(time.RFC3339Nano))
	}
	if options.IncludePrefix != nil {
		params.IncludePrefix = cloudflaresdk.F(*options.IncludePrefix)
	}
	if options.Deleted != nil {
		params.IsDeleted = cloudflaresdk.F(*options.Deleted)
	}
	if options.Name != nil {
		params.Name = cloudflaresdk.F(*options.Name)
	}
	if options.Page != nil {
		if *options.Page <= 0 {
			return nil, fmt.Errorf("list Cloudflare tunnels: page must be positive")
		}
		params.Page = cloudflaresdk.F(float64(*options.Page))
	}
	if options.PerPage != nil {
		if *options.PerPage <= 0 {
			return nil, fmt.Errorf("list Cloudflare tunnels: per-page limit must be positive")
		}
		params.PerPage = cloudflaresdk.F(float64(*options.PerPage))
	}
	if options.Status != nil {
		status, err := tunnelStatusToSDK(*options.Status)
		if err != nil {
			return nil, fmt.Errorf("list Cloudflare tunnels: %w", err)
		}
		params.Status = cloudflaresdk.F(status)
	}
	if options.UUID != nil {
		if *options.UUID == "" {
			return nil, fmt.Errorf("list Cloudflare tunnels: UUID must not be empty")
		}
		params.UUID = cloudflaresdk.F(*options.UUID)
	}
	if options.WasActiveAt != nil {
		params.WasActiveAt = cloudflaresdk.F(*options.WasActiveAt)
	}
	if options.WasInactiveAt != nil {
		params.WasInactiveAt = cloudflaresdk.F(*options.WasInactiveAt)
	}

	pager := client.sdk.ZeroTrust.Tunnels.Cloudflared.ListAutoPaging(ctx, params)
	result := make([]Tunnel, 0)
	for pager.Next() {
		remote := pager.Current()
		tunnel, err := tunnelFromSDK(&remote)
		if err != nil {
			return nil, fmt.Errorf("list Cloudflare tunnels: %w", err)
		}
		result = append(result, tunnel)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare tunnels: %w", err)
	}
	return result, nil
}

// UpdateTunnelName updates the mutable name of an existing tunnel.
func (client *Client) UpdateTunnelName(ctx context.Context, tunnelID, name string) (Tunnel, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return Tunnel{}, fmt.Errorf("update Cloudflare tunnel name: %w", err)
	}
	if name == "" {
		return Tunnel{}, fmt.Errorf("update Cloudflare tunnel name: name must not be empty")
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Edit(ctx, tunnelID, zero_trust.TunnelCloudflaredEditParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("update Cloudflare tunnel name: %w", err)
	}
	tunnel, err := tunnelFromSDK(result)
	if err != nil {
		return Tunnel{}, fmt.Errorf("update Cloudflare tunnel name: %w", err)
	}
	return tunnel, nil
}

// DeleteTunnel deletes a tunnel. cascade=true remains an explicit query parameter
// because the generated SDK does not model it.
func (client *Client) DeleteTunnel(ctx context.Context, tunnelID string, cascade bool) error {
	if err := validateTunnelID(tunnelID); err != nil {
		return fmt.Errorf("delete Cloudflare tunnel: %w", err)
	}
	var requestOptions []option.RequestOption
	if cascade {
		requestOptions = append(requestOptions, option.WithQuery("cascade", "true"))
	}
	_, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Delete(ctx, tunnelID, zero_trust.TunnelCloudflaredDeleteParams{
		AccountID: cloudflaresdk.F(client.accountID),
	}, requestOptions...)
	if err != nil {
		return fmt.Errorf("delete Cloudflare tunnel: %w", err)
	}
	return nil
}

// GetTunnelToken returns the connector token. Callers must store it only in a Secret.
func (client *Client) GetTunnelToken(ctx context.Context, tunnelID string) (string, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return "", fmt.Errorf("get Cloudflare tunnel token: %w", err)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Token.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredTokenGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return "", fmt.Errorf("get Cloudflare tunnel token: %w", err)
	}
	if result == nil || *result == "" {
		return "", fmt.Errorf("get Cloudflare tunnel token: Cloudflare returned an empty token")
	}
	return *result, nil
}

// GetTunnelConfiguration returns the current whole-object configuration and metadata.
func (client *Client) GetTunnelConfiguration(ctx context.Context, tunnelID string) (TunnelConfiguration, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return TunnelConfiguration{}, fmt.Errorf("get Cloudflare tunnel configuration: %w", err)
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Configurations.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredConfigurationGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return TunnelConfiguration{}, fmt.Errorf("get Cloudflare tunnel configuration: %w", err)
	}
	if result == nil {
		return TunnelConfiguration{}, fmt.Errorf("get Cloudflare tunnel configuration: Cloudflare returned an empty configuration")
	}
	configuration, err := tunnelConfigurationFromSDK(
		client.accountID,
		tunnelID,
		result.AccountID,
		result.TunnelID,
		result.Version,
		string(result.Source),
		result.CreatedAt,
		result.JSON.Config.Raw(),
	)
	if err != nil {
		return TunnelConfiguration{}, fmt.Errorf("get Cloudflare tunnel configuration: %w", err)
	}
	return configuration, nil
}

// UpdateTunnelConfiguration replaces the remote tunnel's complete configuration.
func (client *Client) UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (TunnelConfiguration, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return TunnelConfiguration{}, fmt.Errorf("update Cloudflare tunnel configuration: %w", err)
	}
	params.AccountID = cloudflaresdk.F(client.accountID)
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Configurations.Update(ctx, tunnelID, params)
	if err != nil {
		return TunnelConfiguration{}, fmt.Errorf("update Cloudflare tunnel configuration: %w", err)
	}
	if result == nil {
		return TunnelConfiguration{}, fmt.Errorf("update Cloudflare tunnel configuration: Cloudflare returned an empty configuration")
	}
	configuration, err := tunnelConfigurationFromSDK(
		client.accountID,
		tunnelID,
		result.AccountID,
		result.TunnelID,
		result.Version,
		string(result.Source),
		result.CreatedAt,
		result.JSON.Config.Raw(),
	)
	if err != nil {
		return TunnelConfiguration{}, fmt.Errorf("update Cloudflare tunnel configuration: %w", err)
	}
	return configuration, nil
}

// IssueTunnelManagementToken returns a short-lived management token. Callers must
// store it only in an owned Secret.
func (client *Client) IssueTunnelManagementToken(ctx context.Context, tunnelID string, resources []TunnelManagementResource) (string, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return "", fmt.Errorf("issue Cloudflare tunnel management token: %w", err)
	}
	if len(resources) == 0 {
		return "", fmt.Errorf("issue Cloudflare tunnel management token: at least one resource is required")
	}
	wireResources := make([]zero_trust.TunnelCloudflaredManagementNewParamsResource, len(resources))
	for i, resource := range resources {
		switch resource {
		case TunnelManagementResourceLogs:
			wireResources[i] = zero_trust.TunnelCloudflaredManagementNewParamsResourceLogs
		default:
			return "", fmt.Errorf("issue Cloudflare tunnel management token: unsupported resource %q", resource)
		}
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Management.New(ctx, tunnelID, zero_trust.TunnelCloudflaredManagementNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Resources: cloudflaresdk.F(wireResources),
	})
	if err != nil {
		return "", fmt.Errorf("issue Cloudflare tunnel management token: %w", err)
	}
	if result == nil || *result == "" {
		return "", fmt.Errorf("issue Cloudflare tunnel management token: Cloudflare returned an empty token")
	}
	return *result, nil
}

// GetTunnelConnector returns one connector with bounded connection and feature observations.
func (client *Client) GetTunnelConnector(ctx context.Context, tunnelID, connectorID string, limit int64) (TunnelConnector, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return TunnelConnector{}, fmt.Errorf("get Cloudflare tunnel connector: %w", err)
	}
	if connectorID == "" {
		return TunnelConnector{}, fmt.Errorf("get Cloudflare tunnel connector: connector ID must not be empty")
	}
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Connectors.Get(ctx, tunnelID, connectorID, zero_trust.TunnelCloudflaredConnectorGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return TunnelConnector{}, fmt.Errorf("get Cloudflare tunnel connector: %w", err)
	}
	connector, err := tunnelConnectorFromSDK(result, observationLimit(limit))
	if err != nil {
		return TunnelConnector{}, fmt.Errorf("get Cloudflare tunnel connector: %w", err)
	}
	return connector, nil
}

// ListTunnelConnections returns one bounded page of connectors and their connections.
func (client *Client) ListTunnelConnections(ctx context.Context, tunnelID string, limit int64) ([]TunnelConnector, bool, error) {
	if err := validateTunnelID(tunnelID); err != nil {
		return nil, false, fmt.Errorf("list Cloudflare tunnel connections: %w", err)
	}
	page, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Connections.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredConnectionGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list Cloudflare tunnel connections: %w", err)
	}
	if page == nil {
		return nil, false, fmt.Errorf("list Cloudflare tunnel connections: Cloudflare returned an empty page")
	}
	bound := observationLimit(limit)
	values := page.Result
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	truncated := int64(len(values)) > bound
	if truncated {
		values = values[:bound]
	}
	result := make([]TunnelConnector, 0, len(values))
	for i := range values {
		connector, err := tunnelConnectorFromSDK(&values[i], bound)
		if err != nil {
			return nil, false, fmt.Errorf("list Cloudflare tunnel connections: %w", err)
		}
		result = append(result, connector)
	}
	return result, truncated, nil
}

// EvictTunnelConnections removes all connections, or only one connector's
// connections when connectorID is provided.
func (client *Client) EvictTunnelConnections(ctx context.Context, tunnelID string, connectorID *string) error {
	if err := validateTunnelID(tunnelID); err != nil {
		return fmt.Errorf("evict Cloudflare tunnel connections: %w", err)
	}
	params := zero_trust.TunnelCloudflaredConnectionDeleteParams{AccountID: cloudflaresdk.F(client.accountID)}
	if connectorID != nil {
		if *connectorID == "" {
			return fmt.Errorf("evict Cloudflare tunnel connections: connector ID must not be empty")
		}
		params.ClientID = cloudflaresdk.F(*connectorID)
	}
	if _, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Connections.Delete(ctx, tunnelID, params); err != nil {
		return fmt.Errorf("evict Cloudflare tunnel connections: %w", err)
	}
	return nil
}

func tunnelFromSDK(remote *shared.CloudflareTunnel) (Tunnel, error) {
	if remote == nil {
		return Tunnel{}, fmt.Errorf("cloudflare returned an empty tunnel")
	}
	if remote.ID == "" {
		return Tunnel{}, fmt.Errorf("cloudflare returned a tunnel without an ID")
	}
	if remote.AccountTag == "" {
		return Tunnel{}, fmt.Errorf("cloudflare returned tunnel %q without an account ID", remote.ID)
	}
	status, err := tunnelStatusFromSDK(remote.Status)
	if err != nil {
		return Tunnel{}, err
	}
	tunnelType, err := tunnelTypeFromSDK(remote.TunType)
	if err != nil {
		return Tunnel{}, err
	}
	wireConfigSource := string(remote.ConfigSrc)
	if wireConfigSource == "" {
		var remoteConfig bool
		if raw := remote.JSON.RemoteConfig.Raw(); raw != "" && json.Unmarshal([]byte(raw), &remoteConfig) == nil {
			wireConfigSource = string(shared.CloudflareTunnelConfigSrcLocal)
			if remoteConfig {
				wireConfigSource = string(shared.CloudflareTunnelConfigSrcCloudflare)
			}
		}
	}
	configSource, err := tunnelConfigSourceFromWire(wireConfigSource)
	if err != nil {
		return Tunnel{}, err
	}
	return Tunnel{
		ID:                    remote.ID,
		AccountTag:            remote.AccountTag,
		Name:                  remote.Name,
		Status:                status,
		Type:                  tunnelType,
		ConfigSource:          configSource,
		CreatedAt:             remote.CreatedAt,
		DeletedAt:             nonZeroTime(remote.DeletedAt),
		ConnectionsActiveAt:   nonZeroTime(remote.ConnsActiveAt),
		ConnectionsInactiveAt: nonZeroTime(remote.ConnsInactiveAt),
	}, nil
}

func tunnelConfigurationFromSDK(expectedAccountID, expectedTunnelID, accountID, tunnelID string, version int64, source string, createdAt time.Time, rawConfig string) (TunnelConfiguration, error) {
	if expectedAccountID == "" {
		return TunnelConfiguration{}, fmt.Errorf("tunnel configuration request has no account ID")
	}
	if expectedTunnelID == "" {
		return TunnelConfiguration{}, fmt.Errorf("tunnel configuration request has no tunnel ID")
	}
	if accountID != "" && accountID != expectedAccountID {
		return TunnelConfiguration{}, fmt.Errorf("cloudflare returned tunnel configuration account ID %q; expected %q", accountID, expectedAccountID)
	}
	if tunnelID != "" && tunnelID != expectedTunnelID {
		return TunnelConfiguration{}, fmt.Errorf("cloudflare returned tunnel configuration tunnel ID %q; expected %q", tunnelID, expectedTunnelID)
	}
	configSource, err := tunnelConfigSourceFromWire(source)
	if err != nil {
		return TunnelConfiguration{}, err
	}
	config := json.RawMessage(rawConfig)
	if len(config) == 0 || !json.Valid(config) {
		return TunnelConfiguration{}, fmt.Errorf("cloudflare returned invalid tunnel configuration JSON")
	}
	return TunnelConfiguration{
		AccountID: expectedAccountID,
		TunnelID:  expectedTunnelID,
		Version:   version,
		Source:    configSource,
		CreatedAt: createdAt,
		Config:    config,
	}, nil
}

func tunnelConnectorFromSDK(remote *zero_trust.Client, limit int64) (TunnelConnector, error) {
	if remote == nil {
		return TunnelConnector{}, fmt.Errorf("cloudflare returned an empty tunnel connector")
	}
	if remote.ID == "" {
		return TunnelConnector{}, fmt.Errorf("cloudflare returned a tunnel connector without an ID")
	}
	connections := append([]zero_trust.ClientConn(nil), remote.Conns...)
	sort.Slice(connections, func(i, j int) bool { return connections[i].ID < connections[j].ID })
	connectionsTruncated := int64(len(connections)) > limit
	if connectionsTruncated {
		connections = connections[:limit]
	}
	observedConnections := make([]TunnelConnection, 0, len(connections))
	for _, connection := range connections {
		if connection.ID == "" {
			return TunnelConnector{}, fmt.Errorf("cloudflare returned connector %q with a connection without an ID", remote.ID)
		}
		if connection.ClientID == "" {
			return TunnelConnector{}, fmt.Errorf("cloudflare returned connection %q without a connector ID", connection.ID)
		}
		if connection.UUID == "" {
			return TunnelConnector{}, fmt.Errorf("cloudflare returned connection %q without a UUID", connection.ID)
		}
		observedConnections = append(observedConnections, TunnelConnection{
			ID:            connection.ID,
			ClientID:      connection.ClientID,
			ClientVersion: connection.ClientVersion,
			ColoName:      connection.ColoName,
			OpenedAt:      connection.OpenedAt,
			OriginIP:      connection.OriginIP,
			UUID:          connection.UUID,
		})
	}
	features := append([]string(nil), remote.Features...)
	sort.Strings(features)
	featuresTruncated := int64(len(features)) > limit
	if featuresTruncated {
		features = features[:limit]
	}
	return TunnelConnector{
		ID:                   remote.ID,
		Architecture:         remote.Arch,
		ConfigVersion:        remote.ConfigVersion,
		Connections:          observedConnections,
		ConnectionsTruncated: connectionsTruncated,
		Features:             features,
		FeaturesTruncated:    featuresTruncated,
		RunAt:                remote.RunAt,
		Version:              remote.Version,
	}, nil
}

func validateTunnelID(tunnelID string) error {
	if tunnelID == "" {
		return fmt.Errorf("tunnel ID must not be empty")
	}
	return nil
}

func observationLimit(limit int64) int64 {
	if limit <= 0 || limit > maxTunnelObservations {
		return maxTunnelObservations
	}
	return limit
}

func tunnelStatusFromSDK(status shared.CloudflareTunnelStatus) (TunnelStatus, error) {
	switch status {
	case shared.CloudflareTunnelStatusInactive:
		return TunnelStatusInactive, nil
	case shared.CloudflareTunnelStatusDegraded:
		return TunnelStatusDegraded, nil
	case shared.CloudflareTunnelStatusHealthy:
		return TunnelStatusHealthy, nil
	case shared.CloudflareTunnelStatusDown:
		return TunnelStatusDown, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare tunnel status %q", status)
	}
}

func tunnelStatusToSDK(status TunnelStatus) (zero_trust.TunnelCloudflaredListParamsStatus, error) {
	switch status {
	case TunnelStatusInactive:
		return zero_trust.TunnelCloudflaredListParamsStatusInactive, nil
	case TunnelStatusDegraded:
		return zero_trust.TunnelCloudflaredListParamsStatusDegraded, nil
	case TunnelStatusHealthy:
		return zero_trust.TunnelCloudflaredListParamsStatusHealthy, nil
	case TunnelStatusDown:
		return zero_trust.TunnelCloudflaredListParamsStatusDown, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare tunnel status %q", status)
	}
}

func tunnelTypeFromSDK(tunnelType shared.CloudflareTunnelTunType) (TunnelType, error) {
	switch tunnelType {
	case shared.CloudflareTunnelTunTypeCfdTunnel:
		return TunnelTypeCloudflared, nil
	case shared.CloudflareTunnelTunTypeWARPConnector:
		return TunnelTypeWARPConnector, nil
	case shared.CloudflareTunnelTunTypeWARP:
		return TunnelTypeWARP, nil
	case shared.CloudflareTunnelTunTypeMagic:
		return TunnelTypeMagic, nil
	case shared.CloudflareTunnelTunTypeIPSec:
		return TunnelTypeIPSec, nil
	case shared.CloudflareTunnelTunTypeGRE:
		return TunnelTypeGRE, nil
	case shared.CloudflareTunnelTunTypeCNI:
		return TunnelTypeCNI, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare tunnel type %q", tunnelType)
	}
}

func tunnelConfigSourceFromWire(source string) (TunnelConfigSource, error) {
	switch source {
	case string(shared.CloudflareTunnelConfigSrcLocal):
		return TunnelConfigSourceLocal, nil
	case string(shared.CloudflareTunnelConfigSrcCloudflare):
		return TunnelConfigSourceCloudflare, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare tunnel configuration source %q", source)
	}
}

func nonZeroTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	result := value
	return &result
}
