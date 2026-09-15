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

// DeviceAPI is the complete account device and profile surface.
type DeviceAPI interface {
	DeviceProfileAPI
	DeviceSettingsAPI
}

// DeviceProfileAPI manages profile fields and their whole-list child resources.
type DeviceProfileAPI interface {
	GetDefaultDeviceProfile(context.Context) (DeviceProfile, error)
	UpdateDefaultDeviceProfile(context.Context, DeviceProfileInput) (DeviceProfile, error)
	CreateCustomDeviceProfile(context.Context, DeviceProfileInput) (DeviceProfile, error)
	ListCustomDeviceProfiles(context.Context) ([]DeviceProfile, error)
	GetCustomDeviceProfile(context.Context, string) (DeviceProfile, error)
	UpdateCustomDeviceProfile(context.Context, string, DeviceProfileInput) (DeviceProfile, error)
	DeleteCustomDeviceProfile(context.Context, string) error
	GetDeviceProfileInclude(context.Context, DeviceProfileRef) ([]SplitTunnelEntry, error)
	ReplaceDeviceProfileInclude(context.Context, DeviceProfileRef, []SplitTunnelEntry) ([]SplitTunnelEntry, error)
	GetDeviceProfileExclude(context.Context, DeviceProfileRef) ([]SplitTunnelEntry, error)
	ReplaceDeviceProfileExclude(context.Context, DeviceProfileRef, []SplitTunnelEntry) ([]SplitTunnelEntry, error)
	GetDeviceProfileFallbackDomains(context.Context, DeviceProfileRef) ([]FallbackDomain, error)
	ReplaceDeviceProfileFallbackDomains(context.Context, DeviceProfileRef, []FallbackDomain) ([]FallbackDomain, error)
}

// DeviceSettingsAPI reads and updates account-wide WARP settings.
type DeviceSettingsAPI interface {
	GetDeviceSettings(context.Context) (DeviceSettings, error)
	UpdateDeviceSettings(context.Context, DeviceSettingsInput) (DeviceSettings, error)
}

// DeviceProfileKind selects the default or a custom profile endpoint.
type DeviceProfileKind string

const (
	// DeviceProfileKindDefault is part of the Flareway API.
	DeviceProfileKindDefault DeviceProfileKind = "Default"
	// DeviceProfileKindCustom is part of the Flareway API.
	DeviceProfileKindCustom DeviceProfileKind = "Custom"
)

// DeviceProfileRef identifies a profile for whole-list operations. ID is required
// for Custom and ignored for Default.
type DeviceProfileRef struct {
	Kind DeviceProfileKind
	ID   string
}

// DeviceProfileServiceModeV2 configures the WARP client mode.
type DeviceProfileServiceModeV2 struct {
	Mode string
	Port *int32
}

// DeviceProfileVirtualNetworks contains resolved Cloudflare virtual-network IDs.
type DeviceProfileVirtualNetworks struct {
	Default string
	Allowed []string
}

// DNSSearchSuffix is one search suffix pushed to clients.
type DNSSearchSuffix struct {
	Suffix      string
	Description string
}

// DeviceProfileInput uses pointers so callers can distinguish omission from
// explicit false, zero, empty string, and empty-list updates.
type DeviceProfileInput struct {
	Name                       *string
	Description                *string
	Enabled                    *bool
	Match                      *string
	Precedence                 *int64
	SwitchLocked               *bool
	CaptivePortal              *int64
	AllowModeSwitch            *bool
	AllowUpdates               *bool
	AllowedToLeave             *bool
	AutoConnect                *int64
	DisableAutoFallback        *bool
	ExcludeOfficeIPs           *bool
	ServiceModeV2              *DeviceProfileServiceModeV2
	SupportURL                 *string
	LANAllowMinutes            *int64
	LANAllowSubnetSize         *int32
	RegisterInterfaceIPWithDNS *bool
	SCCMVPNBoundarySupport     *bool
	TunnelProtocol             *string
	VirtualNetworks            *DeviceProfileVirtualNetworks
	DNSSearchSuffixes          *[]DNSSearchSuffix
}

// DeviceProfile is the non-secret remote profile representation.
type DeviceProfile struct {
	PolicyID                   string
	Default                    bool
	Name                       string
	Description                string
	Enabled                    bool
	Match                      string
	Precedence                 int64
	SwitchLocked               bool
	CaptivePortal              int64
	AllowModeSwitch            bool
	AllowUpdates               bool
	AllowedToLeave             bool
	AutoConnect                int64
	DisableAutoFallback        bool
	ExcludeOfficeIPs           bool
	ServiceModeV2              DeviceProfileServiceModeV2
	SupportURL                 string
	LANAllowMinutes            int64
	LANAllowSubnetSize         int32
	RegisterInterfaceIPWithDNS bool
	SCCMVPNBoundarySupport     bool
	TunnelProtocol             string
	VirtualNetworks            DeviceProfileVirtualNetworks
	DNSSearchSuffixes          []DNSSearchSuffix
	Include                    []SplitTunnelEntry
	Exclude                    []SplitTunnelEntry
	FallbackDomains            []FallbackDomain
}

// SplitTunnelEntry is one address or hostname in a whole-list replacement.
type SplitTunnelEntry struct {
	Address     string
	Host        string
	Description string
}

// FallbackDomain is one local-domain fallback entry.
type FallbackDomain struct {
	Suffix      string
	Description string
	DNSServer   []string
}

// DeviceSettingsInput preserves optional update semantics for account settings.
type DeviceSettingsInput struct {
	GatewayProxyEnabled                *bool
	GatewayUDPProxyEnabled             *bool
	RootCertificateInstallationEnabled *bool
	UseZTVirtualIP                     *bool
	DisableForTime                     *int64
}

// DeviceSettings is the observed account-wide WARP settings state.
type DeviceSettings struct {
	GatewayProxyEnabled                bool
	GatewayUDPProxyEnabled             bool
	RootCertificateInstallationEnabled bool
	UseZTVirtualIP                     bool
	DisableForTime                     int64
}

// GetDefaultDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) GetDefaultDeviceProfile(ctx context.Context) (DeviceProfile, error) {
	remote, err := client.sdk.ZeroTrust.Devices.Policies.Default.Get(ctx, zero_trust.DevicePolicyDefaultGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("get Cloudflare default device profile: %w", err)
	}
	return defaultDeviceProfileFromGet(remote), nil
}

// UpdateDefaultDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) UpdateDefaultDeviceProfile(ctx context.Context, input DeviceProfileInput) (DeviceProfile, error) {
	if input.Name != nil || input.Description != nil || input.Enabled != nil || input.Match != nil || input.Precedence != nil || input.LANAllowMinutes != nil || input.LANAllowSubnetSize != nil {
		return DeviceProfile{}, fmt.Errorf("update Cloudflare default device profile: name, description, enabled, match, precedence, lanAllowMinutes, and lanAllowSubnetSize are custom-profile fields")
	}
	params := zero_trust.DevicePolicyDefaultEditParams{AccountID: cloudflaresdk.F(client.accountID)}
	setDefaultDeviceProfileParams(&params, input)
	remote, err := client.sdk.ZeroTrust.Devices.Policies.Default.Edit(ctx, params)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("update Cloudflare default device profile: %w", err)
	}
	return defaultDeviceProfileFromEdit(remote), nil
}

// CreateCustomDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) CreateCustomDeviceProfile(ctx context.Context, input DeviceProfileInput) (DeviceProfile, error) {
	if input.Name == nil || *input.Name == "" || input.Match == nil || *input.Match == "" || input.Precedence == nil {
		return DeviceProfile{}, fmt.Errorf("create Cloudflare custom device profile: name, match, and precedence are required")
	}
	params := zero_trust.DevicePolicyCustomNewParams{
		AccountID:  cloudflaresdk.F(client.accountID),
		Name:       cloudflaresdk.F(*input.Name),
		Match:      cloudflaresdk.F(*input.Match),
		Precedence: cloudflaresdk.F(float64(*input.Precedence)),
	}
	setCustomDeviceProfileNewParams(&params, input)
	remote, err := client.sdk.ZeroTrust.Devices.Policies.Custom.New(ctx, params)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("create Cloudflare custom device profile: %w", err)
	}
	return customDeviceProfileFromSDK(remote), nil
}

// ListCustomDeviceProfiles is part of the Cloudflare adapter API.
func (client *Client) ListCustomDeviceProfiles(ctx context.Context) ([]DeviceProfile, error) {
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.ListAutoPaging(ctx, zero_trust.DevicePolicyCustomListParams{AccountID: cloudflaresdk.F(client.accountID)})
	profiles := make([]DeviceProfile, 0)
	for pager.Next() {
		remote := pager.Current()
		profiles = append(profiles, customDeviceProfileFromSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare custom device profiles: %w", err)
	}
	return profiles, nil
}

// GetCustomDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) GetCustomDeviceProfile(ctx context.Context, profileID string) (DeviceProfile, error) {
	remote, err := client.sdk.ZeroTrust.Devices.Policies.Custom.Get(ctx, profileID, zero_trust.DevicePolicyCustomGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("get Cloudflare custom device profile: %w", err)
	}
	return customDeviceProfileFromSDK(remote), nil
}

// UpdateCustomDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) UpdateCustomDeviceProfile(ctx context.Context, profileID string, input DeviceProfileInput) (DeviceProfile, error) {
	params := zero_trust.DevicePolicyCustomEditParams{AccountID: cloudflaresdk.F(client.accountID)}
	setCustomDeviceProfileEditParams(&params, input)
	remote, err := client.sdk.ZeroTrust.Devices.Policies.Custom.Edit(ctx, profileID, params)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("update Cloudflare custom device profile: %w", err)
	}
	return customDeviceProfileFromSDK(remote), nil
}

// DeleteCustomDeviceProfile is part of the Cloudflare adapter API.
func (client *Client) DeleteCustomDeviceProfile(ctx context.Context, profileID string) error {
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.DeleteAutoPaging(ctx, profileID, zero_trust.DevicePolicyCustomDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	for pager.Next() {
	}
	if err := pager.Err(); err != nil {
		return fmt.Errorf("delete Cloudflare custom device profile: %w", err)
	}
	return nil
}

// GetDeviceProfileInclude is part of the Cloudflare adapter API.
func (client *Client) GetDeviceProfileInclude(ctx context.Context, ref DeviceProfileRef) ([]SplitTunnelEntry, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	var result []SplitTunnelEntry
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.Includes.GetAutoPaging(ctx, zero_trust.DevicePolicyDefaultIncludeGetParams{AccountID: cloudflaresdk.F(client.accountID)})
		for pager.Next() {
			result = append(result, splitTunnelIncludeFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("get Cloudflare default device profile include list: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.Includes.GetAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomIncludeGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	for pager.Next() {
		result = append(result, splitTunnelIncludeFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("get Cloudflare custom device profile include list: %w", err)
	}
	return result, nil
}

// ReplaceDeviceProfileInclude is part of the Cloudflare adapter API.
func (client *Client) ReplaceDeviceProfileInclude(ctx context.Context, ref DeviceProfileRef, entries []SplitTunnelEntry) ([]SplitTunnelEntry, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	body, err := splitTunnelIncludeParams(entries)
	if err != nil {
		return nil, err
	}
	result := make([]SplitTunnelEntry, 0, len(entries))
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.Includes.UpdateAutoPaging(ctx, zero_trust.DevicePolicyDefaultIncludeUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Body: body})
		for pager.Next() {
			result = append(result, splitTunnelIncludeFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("replace Cloudflare default device profile include list: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.Includes.UpdateAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomIncludeUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Body: body})
	for pager.Next() {
		result = append(result, splitTunnelIncludeFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("replace Cloudflare custom device profile include list: %w", err)
	}
	return result, nil
}

// GetDeviceProfileExclude is part of the Cloudflare adapter API.
func (client *Client) GetDeviceProfileExclude(ctx context.Context, ref DeviceProfileRef) ([]SplitTunnelEntry, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	var result []SplitTunnelEntry
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.Excludes.GetAutoPaging(ctx, zero_trust.DevicePolicyDefaultExcludeGetParams{AccountID: cloudflaresdk.F(client.accountID)})
		for pager.Next() {
			result = append(result, splitTunnelExcludeFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("get Cloudflare default device profile exclude list: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.Excludes.GetAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomExcludeGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	for pager.Next() {
		result = append(result, splitTunnelExcludeFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("get Cloudflare custom device profile exclude list: %w", err)
	}
	return result, nil
}

// ReplaceDeviceProfileExclude is part of the Cloudflare adapter API.
func (client *Client) ReplaceDeviceProfileExclude(ctx context.Context, ref DeviceProfileRef, entries []SplitTunnelEntry) ([]SplitTunnelEntry, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	body, err := splitTunnelExcludeParams(entries)
	if err != nil {
		return nil, err
	}
	result := make([]SplitTunnelEntry, 0, len(entries))
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.Excludes.UpdateAutoPaging(ctx, zero_trust.DevicePolicyDefaultExcludeUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Body: body})
		for pager.Next() {
			result = append(result, splitTunnelExcludeFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("replace Cloudflare default device profile exclude list: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.Excludes.UpdateAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomExcludeUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Body: body})
	for pager.Next() {
		result = append(result, splitTunnelExcludeFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("replace Cloudflare custom device profile exclude list: %w", err)
	}
	return result, nil
}

// GetDeviceProfileFallbackDomains is part of the Cloudflare adapter API.
func (client *Client) GetDeviceProfileFallbackDomains(ctx context.Context, ref DeviceProfileRef) ([]FallbackDomain, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	var result []FallbackDomain
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.FallbackDomains.GetAutoPaging(ctx, zero_trust.DevicePolicyDefaultFallbackDomainGetParams{AccountID: cloudflaresdk.F(client.accountID)})
		for pager.Next() {
			result = append(result, fallbackDomainFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("get Cloudflare default device profile fallback domains: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.FallbackDomains.GetAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomFallbackDomainGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	for pager.Next() {
		result = append(result, fallbackDomainFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("get Cloudflare custom device profile fallback domains: %w", err)
	}
	return result, nil
}

// ReplaceDeviceProfileFallbackDomains is part of the Cloudflare adapter API.
func (client *Client) ReplaceDeviceProfileFallbackDomains(ctx context.Context, ref DeviceProfileRef, domains []FallbackDomain) ([]FallbackDomain, error) {
	if err := validateDeviceProfileRef(ref); err != nil {
		return nil, err
	}
	body, err := fallbackDomainParams(domains)
	if err != nil {
		return nil, err
	}
	result := make([]FallbackDomain, 0, len(domains))
	if ref.Kind == DeviceProfileKindDefault {
		pager := client.sdk.ZeroTrust.Devices.Policies.Default.FallbackDomains.UpdateAutoPaging(ctx, zero_trust.DevicePolicyDefaultFallbackDomainUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Domains: body})
		for pager.Next() {
			result = append(result, fallbackDomainFromSDK(pager.Current()))
		}
		if err := pager.Err(); err != nil {
			return nil, fmt.Errorf("replace Cloudflare default device profile fallback domains: %w", err)
		}
		return result, nil
	}
	pager := client.sdk.ZeroTrust.Devices.Policies.Custom.FallbackDomains.UpdateAutoPaging(ctx, ref.ID, zero_trust.DevicePolicyCustomFallbackDomainUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Domains: body})
	for pager.Next() {
		result = append(result, fallbackDomainFromSDK(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("replace Cloudflare custom device profile fallback domains: %w", err)
	}
	return result, nil
}

// GetDeviceSettings is part of the Cloudflare adapter API.
func (client *Client) GetDeviceSettings(ctx context.Context) (DeviceSettings, error) {
	remote, err := client.sdk.ZeroTrust.Devices.Settings.Get(ctx, zero_trust.DeviceSettingGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return DeviceSettings{}, fmt.Errorf("get Cloudflare device settings: %w", err)
	}
	return deviceSettingsFromSDK(remote), nil
}

// UpdateDeviceSettings is part of the Cloudflare adapter API.
func (client *Client) UpdateDeviceSettings(ctx context.Context, input DeviceSettingsInput) (DeviceSettings, error) {
	params := zero_trust.DeviceSettingEditParams{AccountID: cloudflaresdk.F(client.accountID)}
	if input.GatewayProxyEnabled != nil {
		params.DeviceSettings.GatewayProxyEnabled = cloudflaresdk.F(*input.GatewayProxyEnabled)
	}
	if input.GatewayUDPProxyEnabled != nil {
		params.DeviceSettings.GatewayUdpProxyEnabled = cloudflaresdk.F(*input.GatewayUDPProxyEnabled)
	}
	if input.RootCertificateInstallationEnabled != nil {
		params.DeviceSettings.RootCertificateInstallationEnabled = cloudflaresdk.F(*input.RootCertificateInstallationEnabled)
	}
	if input.UseZTVirtualIP != nil {
		params.DeviceSettings.UseZtVirtualIP = cloudflaresdk.F(*input.UseZTVirtualIP)
	}
	if input.DisableForTime != nil {
		params.DeviceSettings.DisableForTime = cloudflaresdk.F(float64(*input.DisableForTime))
	}
	remote, err := client.sdk.ZeroTrust.Devices.Settings.Edit(ctx, params)
	if err != nil {
		return DeviceSettings{}, fmt.Errorf("update Cloudflare device settings: %w", err)
	}
	return deviceSettingsFromSDK(remote), nil
}

func validateDeviceProfileRef(ref DeviceProfileRef) error {
	switch ref.Kind {
	case DeviceProfileKindDefault:
		return nil
	case DeviceProfileKindCustom:
		if ref.ID == "" {
			return fmt.Errorf("cloudflare custom device profile ID is required")
		}
		return nil
	default:
		return fmt.Errorf("unsupported Cloudflare device profile kind %q", ref.Kind)
	}
}

func setDefaultDeviceProfileParams(params *zero_trust.DevicePolicyDefaultEditParams, input DeviceProfileInput) {
	if input.AllowModeSwitch != nil {
		params.AllowModeSwitch = cloudflaresdk.F(*input.AllowModeSwitch)
	}
	if input.AllowUpdates != nil {
		params.AllowUpdates = cloudflaresdk.F(*input.AllowUpdates)
	}
	if input.AllowedToLeave != nil {
		params.AllowedToLeave = cloudflaresdk.F(*input.AllowedToLeave)
	}
	if input.AutoConnect != nil {
		params.AutoConnect = cloudflaresdk.F(float64(*input.AutoConnect))
	}
	if input.CaptivePortal != nil {
		params.CaptivePortal = cloudflaresdk.F(float64(*input.CaptivePortal))
	}
	if input.DisableAutoFallback != nil {
		params.DisableAutoFallback = cloudflaresdk.F(*input.DisableAutoFallback)
	}
	if input.ExcludeOfficeIPs != nil {
		params.ExcludeOfficeIPs = cloudflaresdk.F(*input.ExcludeOfficeIPs)
	}
	if input.LANAllowMinutes != nil {
		params.LANAllowMinutes = cloudflaresdk.F(float64(*input.LANAllowMinutes))
	}
	if input.LANAllowSubnetSize != nil {
		params.LANAllowSubnetSize = cloudflaresdk.F(float64(*input.LANAllowSubnetSize))
	}
	if input.RegisterInterfaceIPWithDNS != nil {
		params.RegisterInterfaceIPWithDNS = cloudflaresdk.F(*input.RegisterInterfaceIPWithDNS)
	}
	if input.SCCMVPNBoundarySupport != nil {
		params.SccmVpnBoundarySupport = cloudflaresdk.F(*input.SCCMVPNBoundarySupport)
	}
	if input.ServiceModeV2 != nil {
		params.ServiceModeV2 = cloudflaresdk.F(defaultServiceModeParam(input.ServiceModeV2))
	}
	if input.SupportURL != nil {
		params.SupportURL = cloudflaresdk.F(*input.SupportURL)
	}
	if input.SwitchLocked != nil {
		params.SwitchLocked = cloudflaresdk.F(*input.SwitchLocked)
	}
	if input.TunnelProtocol != nil {
		params.TunnelProtocol = cloudflaresdk.F(*input.TunnelProtocol)
	}
	if input.VirtualNetworks != nil {
		params.VirtualNetworks = cloudflaresdk.F(defaultVirtualNetworksParam(input.VirtualNetworks))
	}
	if input.DNSSearchSuffixes != nil {
		params.DNSSearchSuffixes = cloudflaresdk.F(defaultDNSSearchSuffixParams(*input.DNSSearchSuffixes))
	}
}

func setCustomDeviceProfileNewParams(params *zero_trust.DevicePolicyCustomNewParams, input DeviceProfileInput) {
	if input.Description != nil {
		params.Description = cloudflaresdk.F(*input.Description)
	}
	if input.Enabled != nil {
		params.Enabled = cloudflaresdk.F(*input.Enabled)
	}
	if input.AllowModeSwitch != nil {
		params.AllowModeSwitch = cloudflaresdk.F(*input.AllowModeSwitch)
	}
	if input.AllowUpdates != nil {
		params.AllowUpdates = cloudflaresdk.F(*input.AllowUpdates)
	}
	if input.AllowedToLeave != nil {
		params.AllowedToLeave = cloudflaresdk.F(*input.AllowedToLeave)
	}
	if input.AutoConnect != nil {
		params.AutoConnect = cloudflaresdk.F(float64(*input.AutoConnect))
	}
	if input.CaptivePortal != nil {
		params.CaptivePortal = cloudflaresdk.F(float64(*input.CaptivePortal))
	}
	if input.DisableAutoFallback != nil {
		params.DisableAutoFallback = cloudflaresdk.F(*input.DisableAutoFallback)
	}
	if input.ExcludeOfficeIPs != nil {
		params.ExcludeOfficeIPs = cloudflaresdk.F(*input.ExcludeOfficeIPs)
	}
	if input.LANAllowMinutes != nil {
		params.LANAllowMinutes = cloudflaresdk.F(float64(*input.LANAllowMinutes))
	}
	if input.LANAllowSubnetSize != nil {
		params.LANAllowSubnetSize = cloudflaresdk.F(float64(*input.LANAllowSubnetSize))
	}
	if input.RegisterInterfaceIPWithDNS != nil {
		params.RegisterInterfaceIPWithDNS = cloudflaresdk.F(*input.RegisterInterfaceIPWithDNS)
	}
	if input.SCCMVPNBoundarySupport != nil {
		params.SccmVpnBoundarySupport = cloudflaresdk.F(*input.SCCMVPNBoundarySupport)
	}
	if input.ServiceModeV2 != nil {
		params.ServiceModeV2 = cloudflaresdk.F(customNewServiceModeParam(input.ServiceModeV2))
	}
	if input.SupportURL != nil {
		params.SupportURL = cloudflaresdk.F(*input.SupportURL)
	}
	if input.SwitchLocked != nil {
		params.SwitchLocked = cloudflaresdk.F(*input.SwitchLocked)
	}
	if input.TunnelProtocol != nil {
		params.TunnelProtocol = cloudflaresdk.F(*input.TunnelProtocol)
	}
	if input.VirtualNetworks != nil {
		params.VirtualNetworks = cloudflaresdk.F(customNewVirtualNetworksParam(input.VirtualNetworks))
	}
	if input.DNSSearchSuffixes != nil {
		params.DNSSearchSuffixes = cloudflaresdk.F(customNewDNSSearchSuffixParams(*input.DNSSearchSuffixes))
	}
}

func setCustomDeviceProfileEditParams(params *zero_trust.DevicePolicyCustomEditParams, input DeviceProfileInput) {
	if input.Name != nil {
		params.Name = cloudflaresdk.F(*input.Name)
	}
	if input.Description != nil {
		params.Description = cloudflaresdk.F(*input.Description)
	}
	if input.Enabled != nil {
		params.Enabled = cloudflaresdk.F(*input.Enabled)
	}
	if input.Match != nil {
		params.Match = cloudflaresdk.F(*input.Match)
	}
	if input.Precedence != nil {
		params.Precedence = cloudflaresdk.F(float64(*input.Precedence))
	}
	if input.AllowModeSwitch != nil {
		params.AllowModeSwitch = cloudflaresdk.F(*input.AllowModeSwitch)
	}
	if input.AllowUpdates != nil {
		params.AllowUpdates = cloudflaresdk.F(*input.AllowUpdates)
	}
	if input.AllowedToLeave != nil {
		params.AllowedToLeave = cloudflaresdk.F(*input.AllowedToLeave)
	}
	if input.AutoConnect != nil {
		params.AutoConnect = cloudflaresdk.F(float64(*input.AutoConnect))
	}
	if input.CaptivePortal != nil {
		params.CaptivePortal = cloudflaresdk.F(float64(*input.CaptivePortal))
	}
	if input.DisableAutoFallback != nil {
		params.DisableAutoFallback = cloudflaresdk.F(*input.DisableAutoFallback)
	}
	if input.ExcludeOfficeIPs != nil {
		params.ExcludeOfficeIPs = cloudflaresdk.F(*input.ExcludeOfficeIPs)
	}
	if input.LANAllowMinutes != nil {
		params.LANAllowMinutes = cloudflaresdk.F(float64(*input.LANAllowMinutes))
	}
	if input.LANAllowSubnetSize != nil {
		params.LANAllowSubnetSize = cloudflaresdk.F(float64(*input.LANAllowSubnetSize))
	}
	if input.RegisterInterfaceIPWithDNS != nil {
		params.RegisterInterfaceIPWithDNS = cloudflaresdk.F(*input.RegisterInterfaceIPWithDNS)
	}
	if input.SCCMVPNBoundarySupport != nil {
		params.SccmVpnBoundarySupport = cloudflaresdk.F(*input.SCCMVPNBoundarySupport)
	}
	if input.ServiceModeV2 != nil {
		params.ServiceModeV2 = cloudflaresdk.F(customEditServiceModeParam(input.ServiceModeV2))
	}
	if input.SupportURL != nil {
		params.SupportURL = cloudflaresdk.F(*input.SupportURL)
	}
	if input.SwitchLocked != nil {
		params.SwitchLocked = cloudflaresdk.F(*input.SwitchLocked)
	}
	if input.TunnelProtocol != nil {
		params.TunnelProtocol = cloudflaresdk.F(*input.TunnelProtocol)
	}
	if input.VirtualNetworks != nil {
		params.VirtualNetworks = cloudflaresdk.F(customEditVirtualNetworksParam(input.VirtualNetworks))
	}
	if input.DNSSearchSuffixes != nil {
		params.DNSSearchSuffixes = cloudflaresdk.F(customEditDNSSearchSuffixParams(*input.DNSSearchSuffixes))
	}
}

func defaultServiceModeParam(input *DeviceProfileServiceModeV2) zero_trust.DevicePolicyDefaultEditParamsServiceModeV2 {
	result := zero_trust.DevicePolicyDefaultEditParamsServiceModeV2{Mode: cloudflaresdk.F(input.Mode)}
	if input.Port != nil {
		result.Port = cloudflaresdk.F(float64(*input.Port))
	}
	return result
}
func customNewServiceModeParam(input *DeviceProfileServiceModeV2) zero_trust.DevicePolicyCustomNewParamsServiceModeV2 {
	result := zero_trust.DevicePolicyCustomNewParamsServiceModeV2{Mode: cloudflaresdk.F(input.Mode)}
	if input.Port != nil {
		result.Port = cloudflaresdk.F(float64(*input.Port))
	}
	return result
}
func customEditServiceModeParam(input *DeviceProfileServiceModeV2) zero_trust.DevicePolicyCustomEditParamsServiceModeV2 {
	result := zero_trust.DevicePolicyCustomEditParamsServiceModeV2{Mode: cloudflaresdk.F(input.Mode)}
	if input.Port != nil {
		result.Port = cloudflaresdk.F(float64(*input.Port))
	}
	return result
}
func defaultVirtualNetworksParam(input *DeviceProfileVirtualNetworks) zero_trust.DevicePolicyDefaultEditParamsVirtualNetworks {
	return zero_trust.DevicePolicyDefaultEditParamsVirtualNetworks{Default: cloudflaresdk.F(input.Default), Allowed: cloudflaresdk.F(append([]string(nil), input.Allowed...))}
}
func customNewVirtualNetworksParam(input *DeviceProfileVirtualNetworks) zero_trust.DevicePolicyCustomNewParamsVirtualNetworks {
	return zero_trust.DevicePolicyCustomNewParamsVirtualNetworks{Default: cloudflaresdk.F(input.Default), Allowed: cloudflaresdk.F(append([]string(nil), input.Allowed...))}
}
func customEditVirtualNetworksParam(input *DeviceProfileVirtualNetworks) zero_trust.DevicePolicyCustomEditParamsVirtualNetworks {
	return zero_trust.DevicePolicyCustomEditParamsVirtualNetworks{Default: cloudflaresdk.F(input.Default), Allowed: cloudflaresdk.F(append([]string(nil), input.Allowed...))}
}
func defaultDNSSearchSuffixParams(input []DNSSearchSuffix) []zero_trust.DevicePolicyDefaultEditParamsDNSSearchSuffix {
	result := make([]zero_trust.DevicePolicyDefaultEditParamsDNSSearchSuffix, len(input))
	for i := range input {
		result[i] = zero_trust.DevicePolicyDefaultEditParamsDNSSearchSuffix{Suffix: cloudflaresdk.F(input[i].Suffix), Description: cloudflaresdk.F(input[i].Description)}
	}
	return result
}
func customNewDNSSearchSuffixParams(input []DNSSearchSuffix) []zero_trust.DevicePolicyCustomNewParamsDNSSearchSuffix {
	result := make([]zero_trust.DevicePolicyCustomNewParamsDNSSearchSuffix, len(input))
	for i := range input {
		result[i] = zero_trust.DevicePolicyCustomNewParamsDNSSearchSuffix{Suffix: cloudflaresdk.F(input[i].Suffix), Description: cloudflaresdk.F(input[i].Description)}
	}
	return result
}
func customEditDNSSearchSuffixParams(input []DNSSearchSuffix) []zero_trust.DevicePolicyCustomEditParamsDNSSearchSuffix {
	result := make([]zero_trust.DevicePolicyCustomEditParamsDNSSearchSuffix, len(input))
	for i := range input {
		result[i] = zero_trust.DevicePolicyCustomEditParamsDNSSearchSuffix{Suffix: cloudflaresdk.F(input[i].Suffix), Description: cloudflaresdk.F(input[i].Description)}
	}
	return result
}

func splitTunnelIncludeParams(entries []SplitTunnelEntry) ([]zero_trust.SplitTunnelIncludeUnionParam, error) {
	result := make([]zero_trust.SplitTunnelIncludeUnionParam, len(entries))
	for i, entry := range entries {
		switch {
		case entry.Address != "" && entry.Host == "":
			result[i] = zero_trust.SplitTunnelIncludeTeamsDevicesIncludeSplitTunnelWithAddressParam{Address: cloudflaresdk.F(entry.Address), Description: cloudflaresdk.F(entry.Description)}
		case entry.Host != "" && entry.Address == "":
			result[i] = zero_trust.SplitTunnelIncludeTeamsDevicesIncludeSplitTunnelWithHostParam{Host: cloudflaresdk.F(entry.Host), Description: cloudflaresdk.F(entry.Description)}
		default:
			return nil, fmt.Errorf("include entry %d must set exactly one of address or host", i)
		}
	}
	return result, nil
}
func splitTunnelExcludeParams(entries []SplitTunnelEntry) ([]zero_trust.SplitTunnelExcludeUnionParam, error) {
	result := make([]zero_trust.SplitTunnelExcludeUnionParam, len(entries))
	for i, entry := range entries {
		switch {
		case entry.Address != "" && entry.Host == "":
			result[i] = zero_trust.SplitTunnelExcludeTeamsDevicesExcludeSplitTunnelWithAddressParam{Address: cloudflaresdk.F(entry.Address), Description: cloudflaresdk.F(entry.Description)}
		case entry.Host != "" && entry.Address == "":
			result[i] = zero_trust.SplitTunnelExcludeTeamsDevicesExcludeSplitTunnelWithHostParam{Host: cloudflaresdk.F(entry.Host), Description: cloudflaresdk.F(entry.Description)}
		default:
			return nil, fmt.Errorf("exclude entry %d must set exactly one of address or host", i)
		}
	}
	return result, nil
}
func fallbackDomainParams(domains []FallbackDomain) ([]zero_trust.FallbackDomainParam, error) {
	result := make([]zero_trust.FallbackDomainParam, len(domains))
	for i, domain := range domains {
		if domain.Suffix == "" {
			return nil, fmt.Errorf("fallback domain %d must set suffix", i)
		}
		result[i] = zero_trust.FallbackDomainParam{Suffix: cloudflaresdk.F(domain.Suffix), Description: cloudflaresdk.F(domain.Description), DNSServer: cloudflaresdk.F(append([]string(nil), domain.DNSServer...))}
	}
	return result, nil
}

func splitTunnelIncludeFromSDK(entry zero_trust.SplitTunnelInclude) SplitTunnelEntry {
	return SplitTunnelEntry{Address: entry.Address, Host: entry.Host, Description: entry.Description}
}
func splitTunnelExcludeFromSDK(entry zero_trust.SplitTunnelExclude) SplitTunnelEntry {
	return SplitTunnelEntry{Address: entry.Address, Host: entry.Host, Description: entry.Description}
}
func fallbackDomainFromSDK(domain zero_trust.FallbackDomain) FallbackDomain {
	return FallbackDomain{Suffix: domain.Suffix, Description: domain.Description, DNSServer: append([]string(nil), domain.DNSServer...)}
}

func customDeviceProfileFromSDK(remote *zero_trust.SettingsPolicy) DeviceProfile {
	result := DeviceProfile{PolicyID: remote.PolicyID, Default: remote.Default, Name: remote.Name, Description: remote.Description, Enabled: remote.Enabled, Match: remote.Match, Precedence: int64(remote.Precedence), SwitchLocked: remote.SwitchLocked, CaptivePortal: int64(remote.CaptivePortal), AllowModeSwitch: remote.AllowModeSwitch, AllowUpdates: remote.AllowUpdates, AllowedToLeave: remote.AllowedToLeave, AutoConnect: int64(remote.AutoConnect), DisableAutoFallback: remote.DisableAutoFallback, ExcludeOfficeIPs: remote.ExcludeOfficeIPs, ServiceModeV2: DeviceProfileServiceModeV2{Mode: remote.ServiceModeV2.Mode}, SupportURL: remote.SupportURL, LANAllowMinutes: int64(remote.LANAllowMinutes), LANAllowSubnetSize: int32(remote.LANAllowSubnetSize), RegisterInterfaceIPWithDNS: remote.RegisterInterfaceIPWithDNS, SCCMVPNBoundarySupport: remote.SccmVpnBoundarySupport, TunnelProtocol: remote.TunnelProtocol, VirtualNetworks: DeviceProfileVirtualNetworks{Default: remote.VirtualNetworks.Default, Allowed: append([]string(nil), remote.VirtualNetworks.Allowed...)}}
	if remote.ServiceModeV2.Port != 0 {
		port := int32(remote.ServiceModeV2.Port)
		result.ServiceModeV2.Port = &port
	}
	for _, suffix := range remote.DNSSearchSuffixes {
		result.DNSSearchSuffixes = append(result.DNSSearchSuffixes, DNSSearchSuffix{Suffix: suffix.Suffix, Description: suffix.Description})
	}
	for _, entry := range remote.Include {
		result.Include = append(result.Include, splitTunnelIncludeFromSDK(entry))
	}
	for _, entry := range remote.Exclude {
		result.Exclude = append(result.Exclude, splitTunnelExcludeFromSDK(entry))
	}
	for _, domain := range remote.FallbackDomains {
		result.FallbackDomains = append(result.FallbackDomains, fallbackDomainFromSDK(domain))
	}
	return result
}

func defaultDeviceProfileFromGet(remote *zero_trust.DevicePolicyDefaultGetResponse) DeviceProfile {
	result := DeviceProfile{PolicyID: remote.PolicyID, Default: remote.Default, Enabled: remote.Enabled, SwitchLocked: remote.SwitchLocked, CaptivePortal: int64(remote.CaptivePortal), AllowModeSwitch: remote.AllowModeSwitch, AllowUpdates: remote.AllowUpdates, AllowedToLeave: remote.AllowedToLeave, AutoConnect: int64(remote.AutoConnect), DisableAutoFallback: remote.DisableAutoFallback, ExcludeOfficeIPs: remote.ExcludeOfficeIPs, ServiceModeV2: DeviceProfileServiceModeV2{Mode: remote.ServiceModeV2.Mode}, SupportURL: remote.SupportURL, RegisterInterfaceIPWithDNS: remote.RegisterInterfaceIPWithDNS, SCCMVPNBoundarySupport: remote.SccmVpnBoundarySupport, TunnelProtocol: remote.TunnelProtocol, VirtualNetworks: DeviceProfileVirtualNetworks{Default: remote.VirtualNetworks.Default, Allowed: append([]string(nil), remote.VirtualNetworks.Allowed...)}}
	if remote.ServiceModeV2.Port != 0 {
		port := int32(remote.ServiceModeV2.Port)
		result.ServiceModeV2.Port = &port
	}
	for _, suffix := range remote.DNSSearchSuffixes {
		result.DNSSearchSuffixes = append(result.DNSSearchSuffixes, DNSSearchSuffix{Suffix: suffix.Suffix, Description: suffix.Description})
	}
	for _, entry := range remote.Include {
		result.Include = append(result.Include, splitTunnelIncludeFromSDK(entry))
	}
	for _, entry := range remote.Exclude {
		result.Exclude = append(result.Exclude, splitTunnelExcludeFromSDK(entry))
	}
	for _, domain := range remote.FallbackDomains {
		result.FallbackDomains = append(result.FallbackDomains, fallbackDomainFromSDK(domain))
	}
	return result
}

func defaultDeviceProfileFromEdit(remote *zero_trust.DevicePolicyDefaultEditResponse) DeviceProfile {
	result := DeviceProfile{PolicyID: remote.PolicyID, Default: remote.Default, Enabled: remote.Enabled, SwitchLocked: remote.SwitchLocked, CaptivePortal: int64(remote.CaptivePortal), AllowModeSwitch: remote.AllowModeSwitch, AllowUpdates: remote.AllowUpdates, AllowedToLeave: remote.AllowedToLeave, AutoConnect: int64(remote.AutoConnect), DisableAutoFallback: remote.DisableAutoFallback, ExcludeOfficeIPs: remote.ExcludeOfficeIPs, ServiceModeV2: DeviceProfileServiceModeV2{Mode: remote.ServiceModeV2.Mode}, SupportURL: remote.SupportURL, RegisterInterfaceIPWithDNS: remote.RegisterInterfaceIPWithDNS, SCCMVPNBoundarySupport: remote.SccmVpnBoundarySupport, TunnelProtocol: remote.TunnelProtocol, VirtualNetworks: DeviceProfileVirtualNetworks{Default: remote.VirtualNetworks.Default, Allowed: append([]string(nil), remote.VirtualNetworks.Allowed...)}}
	if remote.ServiceModeV2.Port != 0 {
		port := int32(remote.ServiceModeV2.Port)
		result.ServiceModeV2.Port = &port
	}
	for _, suffix := range remote.DNSSearchSuffixes {
		result.DNSSearchSuffixes = append(result.DNSSearchSuffixes, DNSSearchSuffix{Suffix: suffix.Suffix, Description: suffix.Description})
	}
	for _, entry := range remote.Include {
		result.Include = append(result.Include, splitTunnelIncludeFromSDK(entry))
	}
	for _, entry := range remote.Exclude {
		result.Exclude = append(result.Exclude, splitTunnelExcludeFromSDK(entry))
	}
	for _, domain := range remote.FallbackDomains {
		result.FallbackDomains = append(result.FallbackDomains, fallbackDomainFromSDK(domain))
	}
	return result
}

func deviceSettingsFromSDK(remote *zero_trust.DeviceSettings) DeviceSettings {
	return DeviceSettings{GatewayProxyEnabled: remote.GatewayProxyEnabled, GatewayUDPProxyEnabled: remote.GatewayUdpProxyEnabled, RootCertificateInstallationEnabled: remote.RootCertificateInstallationEnabled, UseZTVirtualIP: remote.UseZtVirtualIP, DisableForTime: int64(remote.DisableForTime)}
}
