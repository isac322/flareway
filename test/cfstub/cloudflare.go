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
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type envelope struct {
	Success    bool        `json:"success"`
	Errors     []any       `json:"errors"`
	Messages   []any       `json:"messages"`
	Result     any         `json:"result"`
	ResultInfo *resultInfo `json:"result_info,omitempty"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func (s *Server) registerCloudflareRoutes() {
	s.Handle(http.MethodGet, `^/user/tokens/verify$`, s.verifyToken)
	s.Handle(http.MethodGet, `^/zones$`, s.listZones)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/access/organizations$`, s.getOrganization)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/cfd_tunnel/[^/]+/token$`, s.getTunnelToken)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/cfd_tunnel/[^/]+/configurations$`, s.getTunnelConfiguration)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/cfd_tunnel/[^/]+/configurations$`, s.updateTunnelConfiguration)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/cfd_tunnel/[^/]+$`, s.getTunnel)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/cfd_tunnel/[^/]+$`, s.editTunnel)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/cfd_tunnel/[^/]+$`, s.deleteTunnel)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/cfd_tunnel$`, s.listTunnels)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/cfd_tunnel$`, s.createTunnel)

	s.Handle(http.MethodGet, `^/zones/[^/]+/dns_records/[^/]+$`, s.getDNSRecord)
	s.Handle(http.MethodPut, `^/zones/[^/]+/dns_records/[^/]+$`, s.updateDNSRecord)
	s.Handle(http.MethodPatch, `^/zones/[^/]+/dns_records/[^/]+$`, s.updateDNSRecord)
	s.Handle(http.MethodDelete, `^/zones/[^/]+/dns_records/[^/]+$`, s.deleteDNSRecord)
	s.Handle(http.MethodGet, `^/zones/[^/]+/dns_records$`, s.listDNSRecords)
	s.Handle(http.MethodPost, `^/zones/[^/]+/dns_records$`, s.createDNSRecord)
}

func (s *Server) verifyToken(w http.ResponseWriter, _ *http.Request) {
	s.State.mu.RLock()
	result := s.State.token
	s.State.mu.RUnlock()
	writeResult(w, http.StatusOK, result)
}

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account.id")
	name := r.URL.Query().Get("name")
	s.State.mu.RLock()
	items := make([]Zone, 0, len(s.State.zones))
	for _, zone := range s.State.zones {
		if accountID != "" && zone.AccountID != accountID {
			continue
		}
		if name != "" && !strings.EqualFold(zone.Name, name) {
			continue
		}
		items = append(items, zone)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	organization, ok := s.State.organizations[accountID]
	s.State.mu.RUnlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Zero Trust organization not found")
		return
	}
	writeResult(w, http.StatusOK, organization)
}

func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	name := r.URL.Query().Get("name")
	includeDeleted := strings.EqualFold(r.URL.Query().Get("is_deleted"), "true")
	s.State.mu.RLock()
	items := make([]Tunnel, 0, len(s.State.tunnels[accountID]))
	for _, tunnel := range s.State.tunnels[accountID] {
		if tunnel.DeletedAt != nil && !includeDeleted {
			continue
		}
		if name != "" && tunnel.Name != name {
			continue
		}
		tunnel.Connections = cloneConnections(tunnel.Connections)
		items = append(items, tunnel)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) createTunnel(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		Name      string `json:"name"`
		ConfigSrc string `json:"config_src"`
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
	for _, existing := range s.State.tunnels[accountID] {
		if existing.DeletedAt == nil && existing.Name == input.Name {
			s.State.mu.Unlock()
			WriteError(w, http.StatusConflict, 1005, "tunnel name already exists")
			return
		}
	}
	tunnel := Tunnel{
		ID:         s.State.nextIdentifierLocked("tunnel"),
		AccountID:  accountID,
		AccountTag: accountID,
		Name:       input.Name,
		Status:     "inactive",
		ConfigSrc:  input.ConfigSrc,
		CreatedAt:  now,
	}
	s.State.putTunnelLocked(tunnel)
	s.State.tunnelTokens[tunnel.ID] = "stub-token-" + tunnel.ID
	s.State.configs[tunnel.ID] = TunnelConfiguration{
		AccountID: accountID,
		TunnelID:  tunnel.ID,
		Version:   0,
		Source:    "cloudflare",
		CreatedAt: now,
		Config:    json.RawMessage(`{}`),
	}
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, tunnel)
}

func (s *Server) getTunnel(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	s.State.mu.RLock()
	tunnel, ok := s.State.tunnels[accountID][tunnelID]
	s.State.mu.RUnlock()
	if !ok || tunnel.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "tunnel not found")
		return
	}
	tunnel.Connections = cloneConnections(tunnel.Connections)
	writeResult(w, http.StatusOK, tunnel)
}
func (s *Server) editTunnel(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	var input struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	tunnel, ok := s.State.tunnels[accountID][tunnelID]
	if ok && tunnel.DeletedAt == nil && input.Name != "" {
		tunnel.Name = input.Name
		s.State.tunnels[accountID][tunnelID] = tunnel
	}
	s.State.mu.Unlock()
	if !ok || tunnel.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "tunnel not found")
		return
	}
	writeResult(w, http.StatusOK, tunnel)
}

func (s *Server) deleteTunnel(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	now := time.Now().UTC()
	s.State.mu.Lock()
	tunnel, ok := s.State.tunnels[accountID][tunnelID]
	if ok && tunnel.DeletedAt == nil {
		tunnel.DeletedAt = &now
		s.State.tunnels[accountID][tunnelID] = tunnel
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "tunnel not found")
		return
	}
	writeResult(w, http.StatusOK, tunnel)
}

func (s *Server) getTunnelToken(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	s.State.mu.RLock()
	tunnel, ok := s.State.tunnels[accountID][tunnelID]
	token := s.State.tunnelTokens[tunnelID]
	s.State.mu.RUnlock()
	if !ok || tunnel.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "tunnel not found")
		return
	}
	writeResult(w, http.StatusOK, token)
}

func (s *Server) getTunnelConfiguration(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	s.State.mu.RLock()
	tunnel, tunnelOK := s.State.tunnels[accountID][tunnelID]
	configuration, configOK := s.State.configs[tunnelID]
	configuration.Config = cloneRaw(configuration.Config)
	s.State.mu.RUnlock()
	if !tunnelOK || tunnel.DeletedAt != nil || !configOK {
		WriteError(w, http.StatusNotFound, 1001, "tunnel configuration not found")
		return
	}
	writeResult(w, http.StatusOK, configuration)
}

func (s *Server) updateTunnelConfiguration(w http.ResponseWriter, r *http.Request) {
	accountID, tunnelID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	var input struct {
		Config json.RawMessage `json:"config"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Config) == 0 || string(input.Config) == "null" {
		WriteError(w, http.StatusBadRequest, 1004, "config is required")
		return
	}

	s.State.mu.Lock()
	tunnel, ok := s.State.tunnels[accountID][tunnelID]
	if !ok || tunnel.DeletedAt != nil {
		s.State.mu.Unlock()
		WriteError(w, http.StatusNotFound, 1001, "tunnel not found")
		return
	}
	configuration := s.State.configs[tunnelID]
	configuration.AccountID = accountID
	configuration.TunnelID = tunnelID
	configuration.Source = "cloudflare"
	configuration.Version++
	configuration.CreatedAt = time.Now().UTC()
	configuration.Config = cloneRaw(input.Config)
	s.State.configs[tunnelID] = configuration
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, configuration)
}

func (s *Server) listDNSRecords(w http.ResponseWriter, r *http.Request) {
	zoneID := pathPart(r.URL.Path, 1)
	query := r.URL.Query()
	s.State.mu.RLock()
	items := make([]DNSRecord, 0, len(s.State.dnsRecords[zoneID]))
	for _, record := range s.State.dnsRecords[zoneID] {
		if value := firstQuery(query.Get("name.exact"), query.Get("name")); value != "" && !strings.EqualFold(record.Name, value) {
			continue
		}
		if value := query.Get("type"); value != "" && !strings.EqualFold(record.Type, value) {
			continue
		}
		if value := firstQuery(query.Get("content.exact"), query.Get("content")); value != "" && record.Content != value {
			continue
		}
		if value := firstQuery(query.Get("comment.exact"), query.Get("comment")); value != "" && record.Comment != value {
			continue
		}
		if tags := query["tag"]; len(tags) > 0 && !recordHasTags(record, tags, query.Get("tag-match")) {
			continue
		}
		record.Tags = append([]string(nil), record.Tags...)
		items = append(items, record)
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) createDNSRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := pathPart(r.URL.Path, 1)
	var input DNSRecord
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Type == "" || input.Name == "" || input.Content == "" {
		WriteError(w, http.StatusBadRequest, 1004, "type, name, and content are required")
		return
	}

	now := time.Now().UTC()
	s.State.mu.Lock()
	for _, existing := range s.State.dnsRecords[zoneID] {
		if strings.EqualFold(existing.Type, input.Type) && strings.EqualFold(existing.Name, input.Name) {
			s.State.mu.Unlock()
			WriteError(w, http.StatusConflict, 81053, "record already exists")
			return
		}
	}
	input.ID = s.State.nextIdentifierLocked("dns")
	input.ZoneID = zoneID
	if zone, ok := s.State.zones[zoneID]; ok {
		input.ZoneName = zone.Name
	}
	input.CreatedOn = now
	input.ModifiedOn = now
	s.State.putDNSRecordLocked(input)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, input)
}

func (s *Server) getDNSRecord(w http.ResponseWriter, r *http.Request) {
	zoneID, recordID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	s.State.mu.RLock()
	record, ok := s.State.dnsRecords[zoneID][recordID]
	record.Tags = append([]string(nil), record.Tags...)
	s.State.mu.RUnlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 81044, "record not found")
		return
	}
	writeResult(w, http.StatusOK, record)
}

func (s *Server) updateDNSRecord(w http.ResponseWriter, r *http.Request) {
	zoneID, recordID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	var input DNSRecord
	if !decodeJSON(w, r, &input) {
		return
	}

	s.State.mu.Lock()
	existing, ok := s.State.dnsRecords[zoneID][recordID]
	if !ok {
		s.State.mu.Unlock()
		WriteError(w, http.StatusNotFound, 81044, "record not found")
		return
	}
	if input.Type != "" {
		existing.Type = input.Type
	}
	if input.Name != "" {
		existing.Name = input.Name
	}
	if input.Content != "" {
		existing.Content = input.Content
	}
	if r.Method == http.MethodPut || input.Proxied {
		existing.Proxied = input.Proxied
	}
	if r.Method == http.MethodPut || input.Comment != "" {
		existing.Comment = input.Comment
	}
	if r.Method == http.MethodPut || input.Tags != nil {
		existing.Tags = append([]string(nil), input.Tags...)
	}
	existing.ModifiedOn = time.Now().UTC()
	s.State.putDNSRecordLocked(existing)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, existing)
}

func (s *Server) deleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	zoneID, recordID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 3)
	s.State.mu.Lock()
	_, ok := s.State.dnsRecords[zoneID][recordID]
	if ok {
		delete(s.State.dnsRecords[zoneID], recordID)
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 81044, "record not found")
		return
	}
	writeResult(w, http.StatusOK, map[string]string{"id": recordID})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		WriteError(w, http.StatusBadRequest, 1004, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, status int, result any) {
	writeEnvelope(w, status, envelope{Success: true, Errors: []any{}, Messages: []any{}, Result: result})
}

func writePage(w http.ResponseWriter, result any, info resultInfo) {
	writeEnvelope(w, http.StatusOK, envelope{
		Success:    true,
		Errors:     []any{},
		Messages:   []any{},
		Result:     result,
		ResultInfo: &info,
	})
}

func writeEnvelope(w http.ResponseWriter, status int, response envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func paginate[T any](items []T, r *http.Request) ([]T, resultInfo) {
	page := positiveInt(r.URL.Query().Get("page"), 1)
	perPage := positiveInt(r.URL.Query().Get("per_page"), 20)
	total := len(items)
	totalPages := 0
	if total > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	result := append([]T(nil), items[start:end]...)
	return result, resultInfo{
		Page:       page,
		PerPage:    perPage,
		Count:      len(result),
		TotalCount: total,
		TotalPages: totalPages,
	}
}

func positiveInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}

func pathPart(path string, index int) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if index < 0 || index >= len(parts) {
		return ""
	}
	return parts[index]
}

func recordHasTags(record DNSRecord, wanted []string, match string) bool {
	matched := 0
	for _, want := range wanted {
		for _, actual := range record.Tags {
			if actual == want {
				matched++
				break
			}
		}
	}
	if strings.EqualFold(match, "any") {
		return matched > 0
	}
	return matched == len(wanted)
}

func formatTunnelID(sequence uint64) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", sequence)
}

func formatSequence(sequence uint64) string {
	return fmt.Sprintf("%08d", sequence)
}

func firstQuery(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
