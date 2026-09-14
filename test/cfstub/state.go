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
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// TokenVerification is returned by the user token verification endpoint.
type TokenVerification struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// ZoneAccount is the account object nested in Cloudflare zone responses.
type ZoneAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Zone is the subset of a Cloudflare zone used by the controllers.
type Zone struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Account     ZoneAccount `json:"account"`
	AccountID   string      `json:"-"`
	AccountName string      `json:"-"`
}

// Organization is the subset of a Zero Trust organization used by the controllers.
type Organization struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	AuthDomain               string `json:"auth_domain"`
	SessionDuration          string `json:"session_duration,omitempty"`
	WARPAuthSessionDuration  string `json:"warp_auth_session_duration,omitempty"`
	AllowAuthenticateViaWARP bool   `json:"allow_authenticate_via_warp"`
	IsUIReadOnly             bool   `json:"is_ui_read_only"`
	DenyUnmatchedRequests    bool   `json:"deny_unmatched_requests"`
	WARPAuthNonBrowser401    bool   `json:"warp_auth_non_browser_401"`
}

// Tunnel is a stateful Cloudflare Tunnel resource.
type Tunnel struct {
	ID          string           `json:"id"`
	AccountID   string           `json:"-"`
	AccountTag  string           `json:"account_tag"`
	Name        string           `json:"name"`
	Status      string           `json:"status"`
	ConfigSrc   string           `json:"config_src,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	DeletedAt   *time.Time       `json:"deleted_at,omitempty"`
	Connections []map[string]any `json:"connections,omitempty"`
}

// TunnelConfiguration records the last whole-object configuration and version.
type TunnelConfiguration struct {
	AccountID string          `json:"account_id"`
	TunnelID  string          `json:"tunnel_id"`
	Version   int64           `json:"version"`
	Source    string          `json:"source"`
	CreatedAt time.Time       `json:"created_at"`
	Config    json.RawMessage `json:"config"`
}

// DNSRecord is the subset of a DNS record needed by M2 controllers and cleanup.
type DNSRecord struct {
	ID         string    `json:"id"`
	ZoneID     string    `json:"zone_id,omitempty"`
	ZoneName   string    `json:"zone_name,omitempty"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Content    string    `json:"content"`
	Proxied    bool      `json:"proxied"`
	Comment    string    `json:"comment,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

// AccessServiceToken is the persisted, secret-free representation returned by
// service-token get and list endpoints.
type AccessServiceToken struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Duration  string    `json:"duration"`
	Enabled   bool      `json:"enabled"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	Name      string    `json:"name"`

	clientSecret                  string
	previousClientSecret          string
	previousClientSecretExpiresAt *time.Time
	secretVersion                 float64
}

// AccessResource is a JSON-shaped Access object. The stub preserves every
// request field so SDK adapters are exercised against their real wire format.
type AccessResource map[string]any

// AccessTag is the account-scoped, secret-free Access application tag.
type AccessTag struct {
	Name string `json:"name"`
}

// State stores synchronized Cloudflare resources. Generic Set/Get remain useful
// for milestone-specific endpoint extensions.
type State struct {
	mu sync.RWMutex

	values                map[string]any
	token                 TokenVerification
	zones                 map[string]Zone
	organizations         map[string]Organization
	tunnels               map[string]map[string]Tunnel
	configs               map[string]TunnelConfiguration
	tunnelTokens          map[string]string
	dnsRecords            map[string]map[string]DNSRecord
	accessApps            map[string]map[string]AccessResource
	accessTags            map[string]map[string]AccessTag
	accessPolicies        map[string]map[string]AccessResource
	accessGroups          map[string]map[string]AccessResource
	identityProviders     map[string]map[string]AccessResource
	postureRules          map[string]map[string]AccessResource
	serviceTokens         map[string]map[string]AccessServiceToken
	virtualNetworks       map[string]map[string]VirtualNetwork
	networkRoutes         map[string]map[string]NetworkRoute
	hostnameRoutes        map[string]map[string]HostnameRoute
	deviceSettings        map[string]DeviceSettings
	defaultDevicePolicies map[string]DevicePolicy
	customDevicePolicies  map[string]map[string]DevicePolicy
	gatewayRules          map[string]map[string]GatewayRule
	gatewayLists          map[string]map[string]GatewayList
	nextID                uint64
}

// NewState returns empty synchronized state with a valid active API token.
func NewState() *State {
	return &State{
		values:                make(map[string]any),
		token:                 TokenVerification{ID: "stub-token", Status: "active"},
		zones:                 make(map[string]Zone),
		organizations:         make(map[string]Organization),
		tunnels:               make(map[string]map[string]Tunnel),
		configs:               make(map[string]TunnelConfiguration),
		tunnelTokens:          make(map[string]string),
		dnsRecords:            make(map[string]map[string]DNSRecord),
		accessApps:            make(map[string]map[string]AccessResource),
		accessTags:            make(map[string]map[string]AccessTag),
		accessPolicies:        make(map[string]map[string]AccessResource),
		accessGroups:          make(map[string]map[string]AccessResource),
		identityProviders:     make(map[string]map[string]AccessResource),
		postureRules:          make(map[string]map[string]AccessResource),
		serviceTokens:         make(map[string]map[string]AccessServiceToken),
		virtualNetworks:       make(map[string]map[string]VirtualNetwork),
		networkRoutes:         make(map[string]map[string]NetworkRoute),
		hostnameRoutes:        make(map[string]map[string]HostnameRoute),
		deviceSettings:        make(map[string]DeviceSettings),
		defaultDevicePolicies: make(map[string]DevicePolicy),
		customDevicePolicies:  make(map[string]map[string]DevicePolicy),
		gatewayRules:          make(map[string]map[string]GatewayRule),
		gatewayLists:          make(map[string]map[string]GatewayList),
	}
}

// Set stores a value under key.
func (s *State) Set(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
}

// Get returns the value stored under key.
func (s *State) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[key]
	return value, ok
}

// Delete removes key.
func (s *State) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
}

// SetTokenVerification changes the response returned by token verification.
func (s *State) SetTokenVerification(result TokenVerification) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = result
}

// AddZone seeds or replaces a zone.
func (s *State) AddZone(zone Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if zone.Account.ID == "" {
		zone.Account.ID = zone.AccountID
	}
	if zone.Account.Name == "" {
		zone.Account.Name = zone.AccountName
	}
	if zone.AccountID == "" {
		zone.AccountID = zone.Account.ID
	}
	if zone.AccountName == "" {
		zone.AccountName = zone.Account.Name
	}
	s.zones[zone.ID] = zone
}

// SetOrganization seeds the Zero Trust organization for an account.
func (s *State) SetOrganization(accountID string, organization Organization) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.organizations[accountID] = organization
}

// AddTunnel seeds or replaces a tunnel.
func (s *State) AddTunnel(tunnel Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putTunnelLocked(tunnel)
}

// SetTunnelToken replaces the connector token returned for tunnelID.
func (s *State) SetTunnelToken(tunnelID, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnelTokens[tunnelID] = token
}

// SetTunnelConfiguration seeds a tunnel configuration at an explicit version.
func (s *State) SetTunnelConfiguration(configuration TunnelConfiguration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	configuration.Config = cloneRaw(configuration.Config)
	s.configs[configuration.TunnelID] = configuration
}

// TunnelConfiguration returns a copy of a tunnel's configuration.
func (s *State) TunnelConfiguration(tunnelID string) (TunnelConfiguration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	configuration, ok := s.configs[tunnelID]
	configuration.Config = cloneRaw(configuration.Config)
	return configuration, ok
}

// Tunnels returns an account's tunnels sorted by ID.
func (s *State) Tunnels(accountID string) []Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Tunnel, 0, len(s.tunnels[accountID]))
	for _, tunnel := range s.tunnels[accountID] {
		tunnel.Connections = cloneConnections(tunnel.Connections)
		items = append(items, tunnel)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// AddDNSRecord seeds or replaces a DNS record.
func (s *State) AddDNSRecord(record DNSRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putDNSRecordLocked(record)
}

// DNSRecords returns a zone's records sorted by ID.
func (s *State) DNSRecords(zoneID string) []DNSRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]DNSRecord, 0, len(s.dnsRecords[zoneID]))
	for _, record := range s.dnsRecords[zoneID] {
		record.Tags = append([]string(nil), record.Tags...)
		items = append(items, record)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// AddAccessApplication seeds an account-scoped application.
func (s *State) AddAccessApplication(accountID string, application AccessResource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := "accounts/" + accountID
	if s.accessApps[scope] == nil {
		s.accessApps[scope] = make(map[string]AccessResource)
	}
	id, _ := application["id"].(string)
	if id == "" {
		id = s.nextIdentifierLocked("access-app")
		application["id"] = id
	}
	s.accessApps[scope][id] = cloneAccessResource(application)
}

// AddAccessTag seeds or replaces an account-scoped Access tag.
func (s *State) AddAccessTag(accountID string, tag AccessTag) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessTags[accountID] == nil {
		s.accessTags[accountID] = make(map[string]AccessTag)
	}
	s.accessTags[accountID][tag.Name] = tag
}

// AddAccessPolicy seeds an account-scoped reusable policy.
func (s *State) AddAccessPolicy(accountID string, policy AccessResource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessPolicies[accountID] == nil {
		s.accessPolicies[accountID] = make(map[string]AccessResource)
	}
	id, _ := policy["id"].(string)
	if id == "" {
		id = s.nextIdentifierLocked("access-policy")
		policy["id"] = id
	}
	s.accessPolicies[accountID][id] = cloneAccessResource(policy)
}

// AddAccessServiceToken seeds an account-scoped service token without exposing
// its client secret through list or get responses.
func (s *State) AddAccessServiceToken(accountID string, token AccessServiceToken, clientSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := "accounts/" + accountID
	if s.serviceTokens[scope] == nil {
		s.serviceTokens[scope] = make(map[string]AccessServiceToken)
	}
	if token.ID == "" {
		token.ID = s.nextIdentifierLocked("service-token")
	}
	token.clientSecret = clientSecret
	if token.secretVersion == 0 {
		token.secretVersion = 1
	}
	s.serviceTokens[scope][token.ID] = token
}

// AccessApplications returns an account or zone's applications sorted by ID.
// scope is "accounts/<id>" or "zones/<id>".
func (s *State) AccessApplications(scope string) []AccessResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedAccessResources(s.accessApps[scope])
}

// AccessTags returns an account's Access tags sorted by name.
func (s *State) AccessTags(accountID string) []AccessTag {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AccessTag, 0, len(s.accessTags[accountID]))
	for _, tag := range s.accessTags[accountID] {
		items = append(items, tag)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

// AccessPolicies returns an account's reusable policies sorted by ID.
func (s *State) AccessPolicies(accountID string) []AccessResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedAccessResources(s.accessPolicies[accountID])
}

// AccessGroups returns an account or zone's groups sorted by ID.
func (s *State) AccessGroups(scope string) []AccessResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedAccessResources(s.accessGroups[scope])
}

// IdentityProviders returns an account or zone's identity providers sorted by ID.
func (s *State) IdentityProviders(scope string) []AccessResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedAccessResources(s.identityProviders[scope])
}

// DevicePostureRules returns an account's posture rules sorted by ID.
func (s *State) DevicePostureRules(accountID string) []AccessResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedAccessResources(s.postureRules[accountID])
}

// AccessServiceTokens returns secret-free service tokens sorted by ID.
func (s *State) AccessServiceTokens(scope string) []AccessServiceToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AccessServiceToken, 0, len(s.serviceTokens[scope]))
	for _, token := range s.serviceTokens[scope] {
		items = append(items, publicServiceToken(token))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (s *State) nextIdentifierLocked(kind string) string {
	s.nextID++
	if kind == "tunnel" {
		return formatTunnelID(s.nextID)
	}
	return kind + "-" + formatSequence(s.nextID)
}

func (s *State) putTunnelLocked(tunnel Tunnel) {
	if s.tunnels[tunnel.AccountID] == nil {
		s.tunnels[tunnel.AccountID] = make(map[string]Tunnel)
	}
	tunnel.Connections = cloneConnections(tunnel.Connections)
	s.tunnels[tunnel.AccountID][tunnel.ID] = tunnel
}

func (s *State) putDNSRecordLocked(record DNSRecord) {
	if s.dnsRecords[record.ZoneID] == nil {
		s.dnsRecords[record.ZoneID] = make(map[string]DNSRecord)
	}
	record.Tags = append([]string(nil), record.Tags...)
	s.dnsRecords[record.ZoneID][record.ID] = record
}

func sortedAccessResources(resources map[string]AccessResource) []AccessResource {
	items := make([]AccessResource, 0, len(resources))
	for _, resource := range resources {
		items = append(items, cloneAccessResource(resource))
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := items[i]["id"].(string)
		right, _ := items[j]["id"].(string)
		return left < right
	})
	return items
}

func cloneAccessResource(resource AccessResource) AccessResource {
	if resource == nil {
		return nil
	}
	encoded, _ := json.Marshal(resource)
	var cloned AccessResource
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}

func publicServiceToken(token AccessServiceToken) AccessServiceToken {
	token.clientSecret = ""
	token.previousClientSecret = ""
	token.previousClientSecretExpiresAt = nil
	token.secretVersion = 0
	return token
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

func cloneConnections(value []map[string]any) []map[string]any {
	if value == nil {
		return nil
	}
	encoded, _ := json.Marshal(value)
	var cloned []map[string]any
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}
