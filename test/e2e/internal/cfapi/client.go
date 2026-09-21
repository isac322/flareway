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

// Package cfapi contains the small read/delete Cloudflare client used by e2e cleanup.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

// Client performs the Cloudflare operations needed by e2e verification and cleanup.
type Client struct {
	baseURL   string
	token     string
	accountID string
	zoneID    string
	http      *http.Client
}

// Tunnel is a cleanup view of a Cloudflare Tunnel.
type Tunnel struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Status      string           `json:"status"`
	CreatedAt   time.Time        `json:"created_at"`
	DeletedAt   *time.Time       `json:"deleted_at"`
	Connections []map[string]any `json:"connections"`
}

// DNSRecord is a cleanup view of a DNS record.
type DNSRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Comment    string    `json:"comment"`
	Tags       []string  `json:"tags"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

// AccessApplication is the cleanup view of a self-hosted Access application.
type AccessApplication struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Domain    string    `json:"domain"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

// AccessPolicy is the cleanup view of a reusable Access policy.
type AccessPolicy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ServiceToken is the cleanup view of an Access service token.
type ServiceToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// DeviceRegistration is the cleanup view of one WARP device registration.
// Registrations carry no name; ownership is proven through the profile ID,
// which is only populated when the list request passes include=policy.
type DeviceRegistration struct {
	ID        string                    `json:"id"`
	Policy    *DeviceRegistrationPolicy `json:"policy"`
	CreatedAt time.Time                 `json:"created_at"`
	DeletedAt *time.Time                `json:"deleted_at"`
}

// DeviceRegistrationPolicy is the nested profile reference on a registration.
type DeviceRegistrationPolicy struct {
	ID string `json:"id"`
}

// VirtualNetwork is a cleanup view of a Cloudflare virtual network.
type VirtualNetwork struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// NetworkRoute is a cleanup view of a Cloudflare CIDR route.
type NetworkRoute struct {
	ID        string    `json:"id"`
	Network   string    `json:"network"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// HostnameRoute is a cleanup view of a Cloudflare hostname route.
type HostnameRoute struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// DeviceProfile is the e2e verification view of every mutable WARP profile field.
type DeviceProfile struct {
	PolicyID                   string                       `json:"policy_id"`
	Name                       string                       `json:"name"`
	Default                    bool                         `json:"default"`
	Description                string                       `json:"description"`
	Enabled                    bool                         `json:"enabled"`
	Match                      string                       `json:"match"`
	Precedence                 int64                        `json:"precedence"`
	SwitchLocked               bool                         `json:"switch_locked"`
	CaptivePortal              int64                        `json:"captive_portal"`
	AllowModeSwitch            bool                         `json:"allow_mode_switch"`
	AllowUpdates               bool                         `json:"allow_updates"`
	AllowedToLeave             bool                         `json:"allowed_to_leave"`
	AutoConnect                int64                        `json:"auto_connect"`
	DisableAutoFallback        bool                         `json:"disable_auto_fallback"`
	ExcludeOfficeIPs           bool                         `json:"exclude_office_ips"`
	ServiceModeV2              DeviceProfileServiceModeV2   `json:"service_mode_v2"`
	SupportURL                 string                       `json:"support_url"`
	LANAllowMinutes            int64                        `json:"lan_allow_minutes"`
	LANAllowSubnetSize         int32                        `json:"lan_allow_subnet_size"`
	RegisterInterfaceIPWithDNS bool                         `json:"register_interface_ip_with_dns"`
	SCCMVPNBoundarySupport     bool                         `json:"sccm_vpn_boundary_support"`
	TunnelProtocol             string                       `json:"tunnel_protocol"`
	VirtualNetworks            DeviceProfileVirtualNetworks `json:"virtual_networks"`
	DNSSearchSuffixes          []DNSSearchSuffix            `json:"dns_search_suffixes"`
	CreatedAt                  time.Time                    `json:"created_at"`
	UpdatedAt                  time.Time                    `json:"updated_at"`
}

// DeviceProfileServiceModeV2 records the WARP client mode and optional proxy port.
type DeviceProfileServiceModeV2 struct {
	Mode string `json:"mode"`
	Port int32  `json:"port,omitempty"`
}

// DeviceProfileVirtualNetworks records resolved virtual-network IDs.
type DeviceProfileVirtualNetworks struct {
	Default string   `json:"default"`
	Allowed []string `json:"allowed"`
}

// DNSSearchSuffix is one WARP DNS search suffix.
type DNSSearchSuffix struct {
	Suffix      string `json:"suffix"`
	Description string `json:"description,omitempty"`
}

// DefaultDeviceProfileSnapshot contains every surface that a Managed default
// DeviceProfile can mutate and therefore must restore after a manual e2e run.
type DefaultDeviceProfileSnapshot struct {
	Profile         DeviceProfile
	Include         []SplitTunnelEntry
	Exclude         []SplitTunnelEntry
	FallbackDomains []FallbackDomain
}

// SplitTunnelEntry is one whole-list include or exclude entry.
type SplitTunnelEntry struct {
	Address     string `json:"address,omitempty"`
	Host        string `json:"host,omitempty"`
	Description string `json:"description,omitempty"`
}

// FallbackDomain is one device-profile local DNS suffix.
type FallbackDomain struct {
	Suffix      string   `json:"suffix"`
	Description string   `json:"description,omitempty"`
	DNSServer   []string `json:"dns_server,omitempty"`
}

// ZeroTrustOrganization carries the account-wide Zero Trust settings that the
// private WARP prerequisites depend on.
type ZeroTrustOrganization struct {
	AuthDomain              string `json:"auth_domain"`
	WARPAuthSessionDuration string `json:"warp_auth_session_duration"`
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type responseEnvelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     T `json:"result"`
	ResultInfo struct {
		Cursor string `json:"cursor"`
	} `json:"result_info"`
}

// New returns a client. Empty baseURL selects Cloudflare API v4.
func New(token, accountID, baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     token,
		accountID: accountID,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// ResolveZone selects the exact zone used by DNS list and delete operations.
func (c *Client) ResolveZone(ctx context.Context, name string) error {
	query := url.Values{"name": {strings.Trim(name, ".")}, "account.id": {c.accountID}, "per_page": {"50"}}
	var zones []zone
	if err := c.getAll(ctx, "/zones", query, &zones); err != nil {
		return fmt.Errorf("list zones: %w", err)
	}
	for _, candidate := range zones {
		if strings.EqualFold(candidate.Name, strings.Trim(name, ".")) {
			c.zoneID = candidate.ID
			return nil
		}
	}
	return fmt.Errorf("cloudflare zone %q was not found in account %q", name, c.accountID)
}

// GetZeroTrustOrganization reads the account-wide Zero Trust settings.
func (c *Client) GetZeroTrustOrganization(ctx context.Context) (ZeroTrustOrganization, error) {
	var organization ZeroTrustOrganization
	if err := c.get(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/access/organizations", &organization); err != nil {
		return ZeroTrustOrganization{}, err
	}
	return organization, nil
}

// ListTunnels returns all non-deleted tunnels in the configured account.
func (c *Client) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	var tunnels []Tunnel
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/cfd_tunnel", url.Values{"is_deleted": {"false"}, "per_page": {"100"}}, &tunnels); err != nil {
		return nil, err
	}
	return tunnels, nil
}

// CreateTunnel creates a remotely managed tunnel for adoption tests.
func (c *Client) CreateTunnel(ctx context.Context, name string) (Tunnel, error) {
	content, err := json.Marshal(map[string]string{"name": name, "config_src": "cloudflare"})
	if err != nil {
		return Tunnel{}, fmt.Errorf("encode tunnel request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/accounts/"+url.PathEscape(c.accountID)+"/cfd_tunnel",
		bytes.NewReader(content),
	)
	if err != nil {
		return Tunnel{}, fmt.Errorf("create Cloudflare request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return Tunnel{}, fmt.Errorf("send Cloudflare request: %w", err)
	}
	defer func() { _ = response.Body.Close() }() // response result is authoritative
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return Tunnel{}, fmt.Errorf("read Cloudflare response: %w", err)
	}
	var envelope responseEnvelope[Tunnel]
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return Tunnel{}, fmt.Errorf("decode Cloudflare response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		return Tunnel{}, cloudflareError(response.StatusCode, envelope.Errors)
	}
	return envelope.Result, nil
}

// DeleteTunnel removes a tunnel and its connections.
func (c *Client) DeleteTunnel(ctx context.Context, tunnelID string) error {
	path := "/accounts/" + url.PathEscape(c.accountID) + "/cfd_tunnel/" + url.PathEscape(tunnelID) + "?cascade=true"
	return c.do(ctx, http.MethodDelete, path, nil)
}

// ListDNSRecords returns all records in the resolved zone.
func (c *Client) ListDNSRecords(ctx context.Context) ([]DNSRecord, error) {
	if c.zoneID == "" {
		return nil, fmt.Errorf("zone must be resolved before listing DNS records")
	}
	var records []DNSRecord
	if err := c.getAll(ctx, "/zones/"+url.PathEscape(c.zoneID)+"/dns_records", url.Values{"per_page": {"100"}}, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// DeleteDNSRecord removes one record from the resolved zone.
func (c *Client) DeleteDNSRecord(ctx context.Context, recordID string) error {
	if c.zoneID == "" {
		return fmt.Errorf("zone must be resolved before deleting DNS records")
	}
	return c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(c.zoneID)+"/dns_records/"+url.PathEscape(recordID), nil)
}

// ListAccessApplications returns all Access applications in the configured account.
func (c *Client) ListAccessApplications(ctx context.Context) ([]AccessApplication, error) {
	var applications []AccessApplication
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/access/apps", url.Values{"per_page": {"100"}}, &applications); err != nil {
		return nil, err
	}
	return applications, nil
}

// DeleteAccessApplication removes an Access application.
func (c *Client) DeleteAccessApplication(ctx context.Context, applicationID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/access/apps/"+url.PathEscape(applicationID), nil)
}

// ListAccessPolicies returns all reusable Access policies in the configured account.
func (c *Client) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	var policies []AccessPolicy
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/access/policies", url.Values{"per_page": {"100"}}, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// DeleteAccessPolicy removes a reusable Access policy.
func (c *Client) DeleteAccessPolicy(ctx context.Context, policyID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/access/policies/"+url.PathEscape(policyID), nil)
}

// ListServiceTokens returns all Access service tokens in the configured account.
func (c *Client) ListServiceTokens(ctx context.Context) ([]ServiceToken, error) {
	var tokens []ServiceToken
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/access/service_tokens", url.Values{"per_page": {"100"}}, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// ListAccessApplicationPolicies returns the policies attached to one Access
// application, used to find app-scoped enrollment policies on the WARP app.
func (c *Client) ListAccessApplicationPolicies(ctx context.Context, applicationID string) ([]AccessPolicy, error) {
	var policies []AccessPolicy
	path := "/accounts/" + url.PathEscape(c.accountID) + "/access/apps/" + url.PathEscape(applicationID) + "/policies"
	if err := c.getAll(ctx, path, url.Values{"per_page": {"100"}}, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// DeleteAccessApplicationPolicy removes one app-scoped Access policy.
func (c *Client) DeleteAccessApplicationPolicy(ctx context.Context, applicationID, policyID string) error {
	path := "/accounts/" + url.PathEscape(c.accountID) + "/access/apps/" + url.PathEscape(applicationID) + "/policies/" + url.PathEscape(policyID)
	return c.do(ctx, http.MethodDelete, path, nil)
}

// ListDeviceRegistrations returns every WARP device registration in the
// account, including soft-deleted ones because status=all is required to see
// registrations whose profile was already removed. include=policy populates
// the profile binding used for ownership. The endpoint paginates with a
// cursor instead of page numbers.
func (c *Client) ListDeviceRegistrations(ctx context.Context) ([]DeviceRegistration, error) {
	path := "/accounts/" + url.PathEscape(c.accountID) + "/devices/registrations"
	query := url.Values{"status": {"all"}, "include": {"policy"}, "per_page": {"100"}}
	var registrations []DeviceRegistration
	for {
		var page []DeviceRegistration
		cursor, err := c.getPage(ctx, path, query, &page)
		if err != nil {
			return nil, err
		}
		registrations = append(registrations, page...)
		if cursor == "" || len(page) == 0 {
			return registrations, nil
		}
		query.Set("cursor", cursor)
	}
}

// DeleteDeviceRegistration removes one WARP device registration.
func (c *Client) DeleteDeviceRegistration(ctx context.Context, registrationID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/devices/registrations/"+url.PathEscape(registrationID), nil)
}

// DeleteServiceToken removes an Access service token.
func (c *Client) DeleteServiceToken(ctx context.Context, tokenID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/access/service_tokens/"+url.PathEscape(tokenID), nil)
}

// ListVirtualNetworks returns all active virtual networks in the configured account.
func (c *Client) ListVirtualNetworks(ctx context.Context) ([]VirtualNetwork, error) {
	var networks []VirtualNetwork
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/teamnet/virtual_networks", url.Values{"is_deleted": {"false"}, "per_page": {"100"}}, &networks); err != nil {
		return nil, err
	}
	return networks, nil
}

// DeleteVirtualNetwork removes one virtual network.
func (c *Client) DeleteVirtualNetwork(ctx context.Context, networkID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/teamnet/virtual_networks/"+url.PathEscape(networkID), nil)
}

// ListNetworkRoutes returns all active CIDR routes in the configured account.
func (c *Client) ListNetworkRoutes(ctx context.Context) ([]NetworkRoute, error) {
	var routes []NetworkRoute
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/teamnet/routes", url.Values{"is_deleted": {"false"}, "per_page": {"100"}}, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// DeleteNetworkRoute removes one private CIDR route.
func (c *Client) DeleteNetworkRoute(ctx context.Context, routeID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/teamnet/routes/"+url.PathEscape(routeID), nil)
}

// ListHostnameRoutes returns all active hostname routes in the configured account.
func (c *Client) ListHostnameRoutes(ctx context.Context) ([]HostnameRoute, error) {
	var routes []HostnameRoute
	if err := c.getAll(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/zerotrust/routes/hostname", url.Values{"is_deleted": {"false"}, "per_page": {"100"}}, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// DeleteHostnameRoute removes one private hostname route.
func (c *Client) DeleteHostnameRoute(ctx context.Context, routeID string) error {
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/zerotrust/routes/hostname/"+url.PathEscape(routeID), nil)
}

// ListDeviceProfiles returns every device profile in the account, including
// the default profile; callers must check DeviceProfile.Default. The endpoint
// is a single unpaginated response, not a page-numbered list.
func (c *Client) ListDeviceProfiles(ctx context.Context) ([]DeviceProfile, error) {
	var profiles []DeviceProfile
	if err := c.get(ctx, "/accounts/"+url.PathEscape(c.accountID)+"/devices/policies", &profiles); err != nil {
		return nil, err
	}
	return profiles, nil
}

// GetDeviceProfile reads the exact custom or default device profile.
func (c *Client) GetDeviceProfile(ctx context.Context, policyID string, isDefault bool) (DeviceProfile, error) {
	path := "/accounts/" + url.PathEscape(c.accountID) + "/devices/policy"
	if !isDefault {
		if policyID == "" {
			return DeviceProfile{}, fmt.Errorf("custom device profile ID is required")
		}
		path += "/" + url.PathEscape(policyID)
	}
	var profile DeviceProfile
	if err := c.get(ctx, path, &profile); err != nil {
		return DeviceProfile{}, err
	}
	return profile, nil
}

// GetDeviceProfileIncludes reads the complete include list for one profile.
func (c *Client) GetDeviceProfileIncludes(ctx context.Context, policyID string, isDefault bool) ([]SplitTunnelEntry, error) {
	path := c.deviceProfileListPath(policyID, isDefault, "include")
	var entries []SplitTunnelEntry
	if err := c.get(ctx, path, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetDeviceProfileExcludes reads the complete exclude list for one profile.
func (c *Client) GetDeviceProfileExcludes(ctx context.Context, policyID string, isDefault bool) ([]SplitTunnelEntry, error) {
	path := c.deviceProfileListPath(policyID, isDefault, "exclude")
	var entries []SplitTunnelEntry
	if err := c.get(ctx, path, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetDeviceProfileFallbackDomains reads the complete fallback-domain list.
func (c *Client) GetDeviceProfileFallbackDomains(ctx context.Context, policyID string, isDefault bool) ([]FallbackDomain, error) {
	path := c.deviceProfileListPath(policyID, isDefault, "fallback_domains")
	var entries []FallbackDomain
	if err := c.get(ctx, path, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// ReplaceDeviceProfileIncludes replaces the whole include list, used only to
// restore an explicitly requested manual default-profile e2e run.
func (c *Client) ReplaceDeviceProfileIncludes(ctx context.Context, policyID string, isDefault bool, entries []SplitTunnelEntry) error {
	return c.doJSON(ctx, http.MethodPut, c.deviceProfileListPath(policyID, isDefault, "include"), entries, nil)
}

// ReplaceDeviceProfileExcludes replaces the whole exclude list.
func (c *Client) ReplaceDeviceProfileExcludes(ctx context.Context, policyID string, isDefault bool, entries []SplitTunnelEntry) error {
	return c.doJSON(ctx, http.MethodPut, c.deviceProfileListPath(policyID, isDefault, "exclude"), entries, nil)
}

// ReplaceDeviceProfileFallbackDomains replaces the whole fallback-domain list.
func (c *Client) ReplaceDeviceProfileFallbackDomains(ctx context.Context, policyID string, isDefault bool, entries []FallbackDomain) error {
	return c.doJSON(ctx, http.MethodPut, c.deviceProfileListPath(policyID, isDefault, "fallback_domains"), entries, nil)
}

// SnapshotDefaultDeviceProfile captures every field and child list mutated by
// the default-profile controller path.
func (c *Client) SnapshotDefaultDeviceProfile(ctx context.Context) (DefaultDeviceProfileSnapshot, error) {
	profile, err := c.GetDeviceProfile(ctx, "", true)
	if err != nil {
		return DefaultDeviceProfileSnapshot{}, err
	}
	include, err := c.GetDeviceProfileIncludes(ctx, "", true)
	if err != nil {
		return DefaultDeviceProfileSnapshot{}, err
	}
	exclude, err := c.GetDeviceProfileExcludes(ctx, "", true)
	if err != nil {
		return DefaultDeviceProfileSnapshot{}, err
	}
	fallback, err := c.GetDeviceProfileFallbackDomains(ctx, "", true)
	if err != nil {
		return DefaultDeviceProfileSnapshot{}, err
	}
	return DefaultDeviceProfileSnapshot{Profile: profile, Include: include, Exclude: exclude, FallbackDomains: fallback}, nil
}

// RestoreDefaultDeviceProfile restores every mutable profile field and all
// whole-list child resources after a manual default-profile e2e run.
func (c *Client) RestoreDefaultDeviceProfile(ctx context.Context, snapshot DefaultDeviceProfileSnapshot) error {
	body := struct {
		SwitchLocked               bool                         `json:"switch_locked"`
		CaptivePortal              int64                        `json:"captive_portal"`
		AllowModeSwitch            bool                         `json:"allow_mode_switch"`
		AllowUpdates               bool                         `json:"allow_updates"`
		AllowedToLeave             bool                         `json:"allowed_to_leave"`
		AutoConnect                int64                        `json:"auto_connect"`
		DisableAutoFallback        bool                         `json:"disable_auto_fallback"`
		ExcludeOfficeIPs           bool                         `json:"exclude_office_ips"`
		ServiceModeV2              DeviceProfileServiceModeV2   `json:"service_mode_v2"`
		SupportURL                 string                       `json:"support_url"`
		LANAllowMinutes            int64                        `json:"lan_allow_minutes"`
		LANAllowSubnetSize         int32                        `json:"lan_allow_subnet_size"`
		RegisterInterfaceIPWithDNS bool                         `json:"register_interface_ip_with_dns"`
		SCCMVPNBoundarySupport     bool                         `json:"sccm_vpn_boundary_support"`
		TunnelProtocol             string                       `json:"tunnel_protocol"`
		VirtualNetworks            DeviceProfileVirtualNetworks `json:"virtual_networks"`
		DNSSearchSuffixes          []DNSSearchSuffix            `json:"dns_search_suffixes"`
	}{
		SwitchLocked: snapshot.Profile.SwitchLocked, CaptivePortal: snapshot.Profile.CaptivePortal,
		AllowModeSwitch: snapshot.Profile.AllowModeSwitch, AllowUpdates: snapshot.Profile.AllowUpdates,
		AllowedToLeave: snapshot.Profile.AllowedToLeave, AutoConnect: snapshot.Profile.AutoConnect,
		DisableAutoFallback: snapshot.Profile.DisableAutoFallback, ExcludeOfficeIPs: snapshot.Profile.ExcludeOfficeIPs,
		ServiceModeV2: snapshot.Profile.ServiceModeV2, SupportURL: snapshot.Profile.SupportURL,
		LANAllowMinutes: snapshot.Profile.LANAllowMinutes, LANAllowSubnetSize: snapshot.Profile.LANAllowSubnetSize,
		RegisterInterfaceIPWithDNS: snapshot.Profile.RegisterInterfaceIPWithDNS,
		SCCMVPNBoundarySupport:     snapshot.Profile.SCCMVPNBoundarySupport, TunnelProtocol: snapshot.Profile.TunnelProtocol,
		VirtualNetworks:   snapshot.Profile.VirtualNetworks,
		DNSSearchSuffixes: append([]DNSSearchSuffix(nil), snapshot.Profile.DNSSearchSuffixes...),
	}
	if err := c.doJSON(ctx, http.MethodPatch, "/accounts/"+url.PathEscape(c.accountID)+"/devices/policy", body, nil); err != nil {
		return fmt.Errorf("restore default device profile fields: %w", err)
	}
	if err := c.ReplaceDeviceProfileIncludes(ctx, "", true, snapshot.Include); err != nil {
		return fmt.Errorf("restore default device profile include list: %w", err)
	}
	if err := c.ReplaceDeviceProfileExcludes(ctx, "", true, snapshot.Exclude); err != nil {
		return fmt.Errorf("restore default device profile exclude list: %w", err)
	}
	if err := c.ReplaceDeviceProfileFallbackDomains(ctx, "", true, snapshot.FallbackDomains); err != nil {
		return fmt.Errorf("restore default device profile fallback domains: %w", err)
	}
	return nil
}

// DeleteDeviceProfile removes a custom profile after Orphan behavior is proven.
func (c *Client) DeleteDeviceProfile(ctx context.Context, policyID string) error {
	if policyID == "" {
		return fmt.Errorf("custom device profile ID is required")
	}
	return c.do(ctx, http.MethodDelete, "/accounts/"+url.PathEscape(c.accountID)+"/devices/policy/"+url.PathEscape(policyID), nil)
}

func (c *Client) deviceProfileListPath(policyID string, isDefault bool, kind string) string {
	path := "/accounts/" + url.PathEscape(c.accountID) + "/devices/policy"
	if !isDefault {
		path += "/" + url.PathEscape(policyID)
	}
	return path + "/" + kind
}

func (c *Client) getAll(ctx context.Context, path string, query url.Values, target any) error {
	page := 1
	rawItems := make([]json.RawMessage, 0)
	for {
		values := cloneValues(query)
		values.Set("page", strconv.Itoa(page))
		var items []json.RawMessage
		if err := c.get(ctx, path+"?"+values.Encode(), &items); err != nil {
			return err
		}
		if len(items) == 0 {
			break
		}
		rawItems = append(rawItems, items...)
		page++
	}
	content, err := json.Marshal(rawItems)
	if err != nil {
		return fmt.Errorf("marshal paginated response: %w", err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode paginated response: %w", err)
	}
	return nil
}

func (c *Client) get(ctx context.Context, path string, target any) error {
	_, err := c.getPage(ctx, path, nil, target)
	return err
}

// getPage fetches one page and returns the result_info cursor, which is empty
// for endpoints that do not cursor-paginate.
func (c *Client) getPage(ctx context.Context, path string, query url.Values, target any) (string, error) {
	if query != nil {
		path += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", fmt.Errorf("create Cloudflare request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("send Cloudflare request: %w", err)
	}
	defer func() { _ = response.Body.Close() }() // response result is authoritative
	content, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("read Cloudflare response: %w", err)
	}
	var envelope responseEnvelope[json.RawMessage]
	if err := json.Unmarshal(content, &envelope); err != nil {
		return "", fmt.Errorf("decode Cloudflare response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		return "", cloudflareError(response.StatusCode, envelope.Errors)
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		return "", fmt.Errorf("decode Cloudflare result: %w", err)
	}
	return envelope.ResultInfo.Cursor, nil
}

func (c *Client) do(ctx context.Context, method, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create Cloudflare request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send Cloudflare request: %w", err)
	}
	defer func() { _ = response.Body.Close() }() // response result is authoritative
	content, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read Cloudflare response: %w", err)
	}
	var envelope responseEnvelope[json.RawMessage]
	if err := json.Unmarshal(content, &envelope); err != nil {
		return fmt.Errorf("decode Cloudflare response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		return cloudflareError(response.StatusCode, envelope.Errors)
	}
	if target != nil {
		if err := json.Unmarshal(envelope.Result, target); err != nil {
			return fmt.Errorf("decode Cloudflare result: %w", err)
		}
	}
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, target any) error {
	content, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode Cloudflare request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("create Cloudflare request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send Cloudflare request: %w", err)
	}
	defer func() { _ = response.Body.Close() }() // response result is authoritative
	responseContent, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read Cloudflare response: %w", err)
	}
	var envelope responseEnvelope[json.RawMessage]
	if err := json.Unmarshal(responseContent, &envelope); err != nil {
		return fmt.Errorf("decode Cloudflare response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		return cloudflareError(response.StatusCode, envelope.Errors)
	}
	if target != nil {
		if err := json.Unmarshal(envelope.Result, target); err != nil {
			return fmt.Errorf("decode Cloudflare result: %w", err)
		}
	}
	return nil
}

func cloudflareError(status int, errors []struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}) error {
	if len(errors) == 0 {
		return fmt.Errorf("cloudflare API returned HTTP %d", status)
	}
	return fmt.Errorf("cloudflare API returned HTTP %d, code %d: %s", status, errors[0].Code, errors[0].Message)
}

func cloneValues(source url.Values) url.Values {
	cloned := make(url.Values, len(source))
	for key, values := range source {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}
