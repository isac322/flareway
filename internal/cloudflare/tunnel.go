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
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// TunnelAPI is the remotely managed Cloudflare Tunnel surface used by M2 controllers.
type TunnelAPI interface {
	CreateTunnel(ctx context.Context, name string) (Tunnel, error)
	GetTunnel(ctx context.Context, tunnelID string) (Tunnel, error)
	DeleteTunnel(ctx context.Context, tunnelID string, cascade bool) error
	GetTunnelToken(ctx context.Context, tunnelID string) (string, error)
	GetTunnelConfigurationVersion(ctx context.Context, tunnelID string) (int64, error)
	UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (int64, error)
	WithTunnelLock(ctx context.Context, tunnelID string, fn func() error) error
}

// TunnelAdministrationAPI exposes lifecycle operations not needed by the
// CloudflareTunnel reconciler's narrow contract.
type TunnelAdministrationAPI interface {
	ListTunnels(ctx context.Context) ([]Tunnel, error)
	UpdateTunnelName(ctx context.Context, tunnelID, name string) (Tunnel, error)
}

// Tunnel is the non-secret remote tunnel state needed by reconcilers.
type Tunnel struct {
	ID        string
	Name      string
	Status    string
	DeletedAt *time.Time
}

// Deleted reports whether Cloudflare has soft-deleted the tunnel.
func (tunnel Tunnel) Deleted() bool {
	return tunnel.DeletedAt != nil
}

// CreateTunnel creates a remotely managed tunnel.
func (client *Client) CreateTunnel(ctx context.Context, name string) (Tunnel, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.New(ctx, zero_trust.TunnelCloudflaredNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
		ConfigSrc: cloudflaresdk.F(zero_trust.TunnelCloudflaredNewParamsConfigSrcCloudflare),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("create Cloudflare tunnel: %w", err)
	}
	return tunnelFromSDK(result), nil
}

// GetTunnel fetches a tunnel by ID.
func (client *Client) GetTunnel(ctx context.Context, tunnelID string) (Tunnel, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("get Cloudflare tunnel: %w", err)
	}
	return tunnelFromSDK(result), nil
}

// ListTunnels returns all non-deleted tunnels in the configured account.
func (client *Client) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	pager := client.sdk.ZeroTrust.Tunnels.Cloudflared.ListAutoPaging(ctx, zero_trust.TunnelCloudflaredListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		IsDeleted: cloudflaresdk.F(false),
		PerPage:   cloudflaresdk.F(100.0),
	})
	result := make([]Tunnel, 0)
	for pager.Next() {
		tunnel := pager.Current()
		result = append(result, tunnelFromSDK(&tunnel))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare tunnels: %w", err)
	}
	return result, nil
}

// UpdateTunnelName updates the mutable name of an existing tunnel.
func (client *Client) UpdateTunnelName(ctx context.Context, tunnelID, name string) (Tunnel, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Edit(ctx, tunnelID, zero_trust.TunnelCloudflaredEditParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
	})
	if err != nil {
		return Tunnel{}, fmt.Errorf("update Cloudflare tunnel name: %w", err)
	}
	return tunnelFromSDK(result), nil
}

// DeleteTunnel deletes a tunnel. cascade=true is sent explicitly because the
// generated SDK does not yet model Cloudflare's cascade query parameter.
func (client *Client) DeleteTunnel(ctx context.Context, tunnelID string, cascade bool) error {
	requestOptions := make([]option.RequestOption, 0, 1)
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
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Token.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredTokenGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return "", fmt.Errorf("get Cloudflare tunnel token: %w", err)
	}
	return *result, nil
}

// GetTunnelConfigurationVersion returns the current whole-object configuration version.
func (client *Client) GetTunnelConfigurationVersion(ctx context.Context, tunnelID string) (int64, error) {
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Configurations.Get(ctx, tunnelID, zero_trust.TunnelCloudflaredConfigurationGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return 0, fmt.Errorf("get Cloudflare tunnel configuration: %w", err)
	}
	return result.Version, nil
}

// UpdateTunnelConfiguration replaces the remote tunnel's complete configuration.
func (client *Client) UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (int64, error) {
	params.AccountID = cloudflaresdk.F(client.accountID)
	result, err := client.sdk.ZeroTrust.Tunnels.Cloudflared.Configurations.Update(ctx, tunnelID, params)
	if err != nil {
		return 0, fmt.Errorf("update Cloudflare tunnel configuration: %w", err)
	}
	return result.Version, nil
}

func tunnelFromSDK(remote *shared.CloudflareTunnel) Tunnel {
	tunnel := Tunnel{ID: remote.ID, Name: remote.Name, Status: string(remote.Status)}
	if !remote.DeletedAt.IsZero() {
		deletedAt := remote.DeletedAt
		tunnel.DeletedAt = &deletedAt
	}
	return tunnel
}
