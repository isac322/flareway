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
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VirtualNetwork is a stateful Cloudflare Zero Trust virtual network.
type VirtualNetwork struct {
	ID               string     `json:"id"`
	AccountID        string     `json:"-"`
	Comment          string     `json:"comment"`
	CreatedAt        time.Time  `json:"created_at"`
	IsDefaultNetwork bool       `json:"is_default_network"`
	Name             string     `json:"name"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

// NetworkRoute is a stateful Cloudflare private CIDR route.
type NetworkRoute struct {
	ID                 string     `json:"id"`
	AccountID          string     `json:"-"`
	Comment            string     `json:"comment"`
	CreatedAt          time.Time  `json:"created_at"`
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`
	Network            string     `json:"network"`
	TunType            string     `json:"tun_type"`
	TunnelID           string     `json:"tunnel_id"`
	TunnelName         string     `json:"tunnel_name,omitempty"`
	VirtualNetworkID   string     `json:"virtual_network_id,omitempty"`
	VirtualNetworkName string     `json:"virtual_network_name,omitempty"`
}

// HostnameRoute is a stateful Cloudflare private hostname route.
type HostnameRoute struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"-"`
	Comment    string     `json:"comment"`
	CreatedAt  time.Time  `json:"created_at"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
	Hostname   string     `json:"hostname"`
	TunType    string     `json:"tun_type"`
	TunnelID   string     `json:"tunnel_id"`
	TunnelName string     `json:"tunnel_name,omitempty"`
}

// DeviceSettings contains the account-wide WARP and Gateway proxy settings.
type DeviceSettings struct {
	GatewayProxyEnabled                bool    `json:"gateway_proxy_enabled"`
	GatewayUDPProxyEnabled             bool    `json:"gateway_udp_proxy_enabled"`
	RootCertificateInstallationEnabled bool    `json:"root_certificate_installation_enabled"`
	UseZTVirtualIP                     bool    `json:"use_zt_virtual_ip"`
	DisableForTime                     float64 `json:"disable_for_time"`
}

// AddVirtualNetwork seeds or replaces an account-scoped virtual network.
func (s *State) AddVirtualNetwork(network VirtualNetwork) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putVirtualNetworkLocked(network)
}

// VirtualNetworks returns an account's virtual networks sorted by ID.
func (s *State) VirtualNetworks(accountID string) []VirtualNetwork {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]VirtualNetwork, 0, len(s.virtualNetworks[accountID]))
	for _, network := range s.virtualNetworks[accountID] {
		items = append(items, network)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// AddNetworkRoute seeds or replaces an account-scoped CIDR route.
func (s *State) AddNetworkRoute(route NetworkRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putNetworkRouteLocked(route)
}

// NetworkRoutes returns an account's CIDR routes sorted by ID.
func (s *State) NetworkRoutes(accountID string) []NetworkRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]NetworkRoute, 0, len(s.networkRoutes[accountID]))
	for _, route := range s.networkRoutes[accountID] {
		items = append(items, route)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// AddHostnameRoute seeds or replaces an account-scoped hostname route.
func (s *State) AddHostnameRoute(route HostnameRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putHostnameRouteLocked(route)
}

// HostnameRoutes returns an account's hostname routes sorted by ID.
func (s *State) HostnameRoutes(accountID string) []HostnameRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]HostnameRoute, 0, len(s.hostnameRoutes[accountID]))
	for _, route := range s.hostnameRoutes[accountID] {
		items = append(items, route)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// SetDeviceSettings sets the device settings returned for an account.
func (s *State) SetDeviceSettings(accountID string, settings DeviceSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceSettings[accountID] = settings
}

func (s *State) putVirtualNetworkLocked(network VirtualNetwork) {
	if s.virtualNetworks[network.AccountID] == nil {
		s.virtualNetworks[network.AccountID] = make(map[string]VirtualNetwork)
	}
	s.virtualNetworks[network.AccountID][network.ID] = network
}

func (s *State) putNetworkRouteLocked(route NetworkRoute) {
	if s.networkRoutes[route.AccountID] == nil {
		s.networkRoutes[route.AccountID] = make(map[string]NetworkRoute)
	}
	s.networkRoutes[route.AccountID][route.ID] = route
}

func (s *State) putHostnameRouteLocked(route HostnameRoute) {
	if s.hostnameRoutes[route.AccountID] == nil {
		s.hostnameRoutes[route.AccountID] = make(map[string]HostnameRoute)
	}
	s.hostnameRoutes[route.AccountID][route.ID] = route
}

func (s *Server) registerPrivateNetworkRoutes() {
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/settings$`, s.getDeviceSettings)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/teamnet/virtual_networks/[^/]+$`, s.getVirtualNetwork)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/teamnet/virtual_networks/[^/]+$`, s.editVirtualNetwork)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/teamnet/virtual_networks/[^/]+$`, s.deleteVirtualNetwork)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/teamnet/virtual_networks$`, s.listVirtualNetworks)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/teamnet/virtual_networks$`, s.createVirtualNetwork)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/teamnet/routes/[^/]+$`, s.getNetworkRoute)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/teamnet/routes/[^/]+$`, s.editNetworkRoute)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/teamnet/routes/[^/]+$`, s.deleteNetworkRoute)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/teamnet/routes$`, s.listNetworkRoutes)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/teamnet/routes$`, s.createNetworkRoute)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/zerotrust/routes/hostname/[^/]+$`, s.getHostnameRoute)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/zerotrust/routes/hostname/[^/]+$`, s.editHostnameRoute)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/zerotrust/routes/hostname/[^/]+$`, s.deleteHostnameRoute)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/zerotrust/routes/hostname$`, s.listHostnameRoutes)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/zerotrust/routes/hostname$`, s.createHostnameRoute)
}

func (s *Server) getDeviceSettings(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	settings := s.State.deviceSettings[accountID]
	s.State.mu.RUnlock()
	writeResult(w, http.StatusOK, settings)
}

func (s *Server) createVirtualNetwork(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		Name             string `json:"name"`
		Comment          string `json:"comment"`
		IsDefault        bool   `json:"is_default"`
		IsDefaultNetwork bool   `json:"is_default_network"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Name == "" {
		WriteError(w, http.StatusBadRequest, 1004, "name is required")
		return
	}
	now := time.Now().UTC()
	s.State.mu.Lock()
	for _, existing := range s.State.virtualNetworks[accountID] {
		if existing.DeletedAt == nil && existing.Name == input.Name {
			s.State.mu.Unlock()
			WriteError(w, http.StatusConflict, 1005, "virtual network name already exists")
			return
		}
	}
	network := VirtualNetwork{
		ID: formatTunnelID(s.State.nextSequenceLocked()), AccountID: accountID,
		Name: input.Name, Comment: input.Comment, CreatedAt: now,
		IsDefaultNetwork: input.IsDefault || input.IsDefaultNetwork,
	}
	if network.IsDefaultNetwork {
		s.State.clearDefaultVirtualNetworkLocked(accountID)
	}
	s.State.putVirtualNetworkLocked(network)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, network)
}

func (s *Server) listVirtualNetworks(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	query := r.URL.Query()
	s.State.mu.RLock()
	items := make([]VirtualNetwork, 0, len(s.State.virtualNetworks[accountID]))
	for _, network := range s.State.virtualNetworks[accountID] {
		if !matchesDeleted(network.DeletedAt, query.Get("is_deleted")) ||
			query.Get("id") != "" && query.Get("id") != network.ID ||
			query.Get("name") != "" && query.Get("name") != network.Name ||
			!matchesOptionalBool(network.IsDefaultNetwork, firstQuery(query.Get("is_default_network"), query.Get("is_default"))) {
			continue
		}
		items = append(items, network)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getVirtualNetwork(w http.ResponseWriter, r *http.Request) {
	accountID, networkID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	network, ok := s.State.virtualNetworks[accountID][networkID]
	s.State.mu.RUnlock()
	if !ok || network.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "virtual network not found")
		return
	}
	writeResult(w, http.StatusOK, network)
}

func (s *Server) editVirtualNetwork(w http.ResponseWriter, r *http.Request) {
	accountID, networkID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input struct {
		Name             *string `json:"name"`
		Comment          *string `json:"comment"`
		IsDefaultNetwork *bool   `json:"is_default_network"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	network, ok := s.State.virtualNetworks[accountID][networkID]
	if !ok || network.DeletedAt != nil {
		s.State.mu.Unlock()
		WriteError(w, http.StatusNotFound, 1001, "virtual network not found")
		return
	}
	if input.Name != nil {
		network.Name = *input.Name
	}
	if input.Comment != nil {
		network.Comment = *input.Comment
	}
	if input.IsDefaultNetwork != nil {
		network.IsDefaultNetwork = *input.IsDefaultNetwork
		if network.IsDefaultNetwork {
			s.State.clearDefaultVirtualNetworkLocked(accountID)
		}
	}
	s.State.putVirtualNetworkLocked(network)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, network)
}

func (s *Server) deleteVirtualNetwork(w http.ResponseWriter, r *http.Request) {
	accountID, networkID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	network, ok := s.State.virtualNetworks[accountID][networkID]
	if ok && network.DeletedAt == nil {
		now := time.Now().UTC()
		network.DeletedAt = &now
		network.IsDefaultNetwork = false
		s.State.putVirtualNetworkLocked(network)
	} else {
		ok = false
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "virtual network not found")
		return
	}
	writeResult(w, http.StatusOK, network)
}

func (s *Server) createNetworkRoute(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		Network          string `json:"network"`
		TunnelID         string `json:"tunnel_id"`
		Comment          string `json:"comment"`
		VirtualNetworkID string `json:"virtual_network_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Network == "" || input.TunnelID == "" {
		WriteError(w, http.StatusBadRequest, 1004, "network and tunnel_id are required")
		return
	}
	if _, err := netip.ParsePrefix(input.Network); err != nil {
		WriteError(w, http.StatusBadRequest, 1004, "network must be a valid CIDR")
		return
	}
	s.State.mu.Lock()
	route := NetworkRoute{
		ID: formatTunnelID(s.State.nextSequenceLocked()), AccountID: accountID,
		Network: input.Network, TunnelID: input.TunnelID, Comment: input.Comment,
		VirtualNetworkID: input.VirtualNetworkID, TunType: "cfd_tunnel", CreatedAt: time.Now().UTC(),
	}
	s.State.putNetworkRouteLocked(route)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, route)
}

func (s *Server) listNetworkRoutes(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	query := r.URL.Query()
	s.State.mu.RLock()
	items := make([]NetworkRoute, 0, len(s.State.networkRoutes[accountID]))
	for _, route := range s.State.networkRoutes[accountID] {
		if !matchesDeleted(route.DeletedAt, query.Get("is_deleted")) ||
			query.Get("route_id") != "" && query.Get("route_id") != route.ID ||
			query.Get("comment") != "" && query.Get("comment") != route.Comment ||
			query.Get("tunnel_id") != "" && query.Get("tunnel_id") != route.TunnelID ||
			query.Get("virtual_network_id") != "" && query.Get("virtual_network_id") != route.VirtualNetworkID ||
			!matchesPrefixFilter(route.Network, query.Get("network_subset"), query.Get("network_superset")) {
			continue
		}
		items = append(items, route)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getNetworkRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	route, ok := s.State.networkRoutes[accountID][routeID]
	s.State.mu.RUnlock()
	if !ok || route.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "network route not found")
		return
	}
	writeResult(w, http.StatusOK, route)
}

func (s *Server) editNetworkRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input struct {
		Network          *string `json:"network"`
		TunnelID         *string `json:"tunnel_id"`
		Comment          *string `json:"comment"`
		VirtualNetworkID *string `json:"virtual_network_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	route, ok := s.State.networkRoutes[accountID][routeID]
	if !ok || route.DeletedAt != nil {
		s.State.mu.Unlock()
		WriteError(w, http.StatusNotFound, 1001, "network route not found")
		return
	}
	if input.Network != nil {
		if _, err := netip.ParsePrefix(*input.Network); err != nil {
			s.State.mu.Unlock()
			WriteError(w, http.StatusBadRequest, 1004, "network must be a valid CIDR")
			return
		}
		route.Network = *input.Network
	}
	if input.TunnelID != nil {
		route.TunnelID = *input.TunnelID
	}
	if input.Comment != nil {
		route.Comment = *input.Comment
	}
	if input.VirtualNetworkID != nil {
		route.VirtualNetworkID = *input.VirtualNetworkID
	}
	s.State.putNetworkRouteLocked(route)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, route)
}

func (s *Server) deleteNetworkRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	route, ok := s.State.networkRoutes[accountID][routeID]
	if ok && route.DeletedAt == nil {
		now := time.Now().UTC()
		route.DeletedAt = &now
		s.State.putNetworkRouteLocked(route)
	} else {
		ok = false
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "network route not found")
		return
	}
	writeResult(w, http.StatusOK, route)
}

func (s *Server) createHostnameRoute(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		Hostname string `json:"hostname"`
		TunnelID string `json:"tunnel_id"`
		Comment  string `json:"comment"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Hostname == "" || input.TunnelID == "" {
		WriteError(w, http.StatusBadRequest, 1004, "hostname and tunnel_id are required")
		return
	}
	s.State.mu.Lock()
	route := HostnameRoute{
		ID: formatTunnelID(s.State.nextSequenceLocked()), AccountID: accountID,
		Hostname: strings.ToLower(strings.TrimSuffix(input.Hostname, ".")), TunnelID: input.TunnelID,
		Comment: input.Comment, TunType: "cfd_tunnel", CreatedAt: time.Now().UTC(),
	}
	s.State.putHostnameRouteLocked(route)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, route)
}

func (s *Server) listHostnameRoutes(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	query := r.URL.Query()
	s.State.mu.RLock()
	items := make([]HostnameRoute, 0, len(s.State.hostnameRoutes[accountID]))
	for _, route := range s.State.hostnameRoutes[accountID] {
		if !matchesDeleted(route.DeletedAt, query.Get("is_deleted")) ||
			query.Get("id") != "" && query.Get("id") != route.ID ||
			query.Get("comment") != "" && query.Get("comment") != route.Comment ||
			query.Get("tunnel_id") != "" && query.Get("tunnel_id") != route.TunnelID ||
			query.Get("hostname") != "" && !strings.Contains(strings.ToLower(route.Hostname), strings.ToLower(query.Get("hostname"))) {
			continue
		}
		items = append(items, route)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getHostnameRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 5)
	s.State.mu.RLock()
	route, ok := s.State.hostnameRoutes[accountID][routeID]
	s.State.mu.RUnlock()
	if !ok || route.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "hostname route not found")
		return
	}
	writeResult(w, http.StatusOK, route)
}

func (s *Server) editHostnameRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 5)
	var input struct {
		Hostname *string `json:"hostname"`
		TunnelID *string `json:"tunnel_id"`
		Comment  *string `json:"comment"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	route, ok := s.State.hostnameRoutes[accountID][routeID]
	if !ok || route.DeletedAt != nil {
		s.State.mu.Unlock()
		WriteError(w, http.StatusNotFound, 1001, "hostname route not found")
		return
	}
	if input.Hostname != nil {
		route.Hostname = strings.ToLower(strings.TrimSuffix(*input.Hostname, "."))
	}
	if input.TunnelID != nil {
		route.TunnelID = *input.TunnelID
	}
	if input.Comment != nil {
		route.Comment = *input.Comment
	}
	s.State.putHostnameRouteLocked(route)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, route)
}

func (s *Server) deleteHostnameRoute(w http.ResponseWriter, r *http.Request) {
	accountID, routeID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 5)
	s.State.mu.Lock()
	route, ok := s.State.hostnameRoutes[accountID][routeID]
	if ok && route.DeletedAt == nil {
		now := time.Now().UTC()
		route.DeletedAt = &now
		s.State.putHostnameRouteLocked(route)
	} else {
		ok = false
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "hostname route not found")
		return
	}
	writeResult(w, http.StatusOK, route)
}

func (s *State) nextSequenceLocked() uint64 {
	s.nextID++
	return s.nextID
}

func (s *State) clearDefaultVirtualNetworkLocked(accountID string) {
	for id, existing := range s.virtualNetworks[accountID] {
		if existing.IsDefaultNetwork {
			existing.IsDefaultNetwork = false
			s.virtualNetworks[accountID][id] = existing
		}
	}
}

func matchesDeleted(deletedAt *time.Time, raw string) bool {
	if raw == "" {
		return deletedAt == nil
	}
	wantDeleted, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}
	return wantDeleted == (deletedAt != nil)
}

func matchesOptionalBool(actual bool, raw string) bool {
	if raw == "" {
		return true
	}
	want, err := strconv.ParseBool(raw)
	return err == nil && want == actual
}

func matchesPrefixFilter(network, subset, superset string) bool {
	route, err := netip.ParsePrefix(network)
	if err != nil {
		return false
	}
	route = route.Masked()
	if subset != "" {
		outer, parseErr := netip.ParsePrefix(subset)
		if parseErr != nil || !prefixContains(outer.Masked(), route) {
			return false
		}
	}
	if superset != "" {
		inner, parseErr := netip.ParsePrefix(superset)
		if parseErr != nil || !prefixContains(route, inner.Masked()) {
			return false
		}
	}
	return true
}

func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Addr().BitLen() == inner.Addr().BitLen() && outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
