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
	"net/http"
	"sort"
	"strings"
	"time"
)

// DevicePolicy is the JSON-shaped device profile stored by the strict stub.
type DevicePolicy map[string]any

// GatewayRule is the stateful subset of a Zero Trust Gateway rule.
type GatewayRule struct {
	ID            string         `json:"id"`
	AccountID     string         `json:"-"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Enabled       bool           `json:"enabled"`
	Precedence    int64          `json:"precedence"`
	Filters       []string       `json:"filters"`
	Action        string         `json:"action"`
	Traffic       string         `json:"traffic"`
	Identity      string         `json:"identity,omitempty"`
	DevicePosture string         `json:"device_posture,omitempty"`
	RuleSettings  map[string]any `json:"rule_settings,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
}

// GatewayListItem is one Zero Trust list value.
type GatewayListItem struct {
	Value       string    `json:"value"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// GatewayList is a stateful Zero Trust Gateway list.
type GatewayList struct {
	ID          string            `json:"id"`
	AccountID   string            `json:"-"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"`
	Items       []GatewayListItem `json:"items"`
	Count       int               `json:"count"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// SetDefaultDevicePolicy seeds the account default profile and all embedded fields.
func (s *State) SetDefaultDevicePolicy(accountID string, policy DevicePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy["policy_id"] = "default"
	policy["default"] = true
	for _, key := range []string{"include", "exclude", "fallback_domains", "dns_search_suffixes"} {
		if _, ok := policy[key]; !ok {
			policy[key] = []any{}
		}
	}
	s.defaultDevicePolicies[accountID] = cloneDevicePolicy(policy)
}

// AddCustomDevicePolicy seeds or replaces a custom account-scoped profile.
func (s *State) AddCustomDevicePolicy(accountID string, policy DevicePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.customDevicePolicies[accountID] == nil {
		s.customDevicePolicies[accountID] = make(map[string]DevicePolicy)
	}
	id := stringField(policy, "policy_id")
	if id == "" {
		id = s.nextIdentifierLocked("device-policy")
		policy["policy_id"] = id
	}
	policy["default"] = false
	s.customDevicePolicies[accountID][id] = cloneDevicePolicy(policy)
}

// CustomDevicePolicies returns account profiles sorted by policy ID.
func (s *State) CustomDevicePolicies(accountID string) []DevicePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]DevicePolicy, 0, len(s.customDevicePolicies[accountID]))
	for _, policy := range s.customDevicePolicies[accountID] {
		items = append(items, cloneDevicePolicy(policy))
	}
	sort.Slice(items, func(i, j int) bool { return stringField(items[i], "policy_id") < stringField(items[j], "policy_id") })
	return items
}

// GatewayRules returns active and soft-deleted rules sorted by ID.
func (s *State) GatewayRules(accountID string) []GatewayRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]GatewayRule, 0, len(s.gatewayRules[accountID]))
	for _, rule := range s.gatewayRules[accountID] {
		items = append(items, cloneGatewayRule(rule))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// GatewayLists returns lists sorted by ID.
func (s *State) GatewayLists(accountID string) []GatewayList {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]GatewayList, 0, len(s.gatewayLists[accountID]))
	for _, list := range s.gatewayLists[accountID] {
		items = append(items, cloneGatewayList(list))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (s *Server) registerGlobalRoutes() {
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/policy$`, s.getDefaultDevicePolicy)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/devices/policy$`, s.editDefaultDevicePolicy)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/devices/policy$`, s.createCustomDevicePolicy)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/policies$`, s.listCustomDevicePolicies)
	for _, listKind := range []string{"include", "exclude", "fallback_domains"} {
		s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/policy/`+listKind+`$`, s.getDefaultDevicePolicyList(listKind))
		s.Handle(http.MethodPut, `^/accounts/[^/]+/devices/policy/`+listKind+`$`, s.updateDefaultDevicePolicyList(listKind))
		s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/policy/[^/]+/`+listKind+`$`, s.getCustomDevicePolicyList(listKind))
		s.Handle(http.MethodPut, `^/accounts/[^/]+/devices/policy/[^/]+/`+listKind+`$`, s.updateCustomDevicePolicyList(listKind))
	}
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/policy/[^/]+$`, s.getCustomDevicePolicy)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/devices/policy/[^/]+$`, s.editCustomDevicePolicy)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/devices/policy/[^/]+$`, s.deleteCustomDevicePolicy)

	s.Handle(http.MethodPatch, `^/accounts/[^/]+/devices/settings$`, s.editDeviceSettings)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/devices/settings$`, s.editDeviceSettings)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/access/organizations$`, s.updateOrganization)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/gateway/rules/[^/]+$`, s.getGatewayRule)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/gateway/rules/[^/]+$`, s.updateGatewayRule)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/gateway/rules/[^/]+$`, s.deleteGatewayRule)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/gateway/rules$`, s.listGatewayRules)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/gateway/rules$`, s.createGatewayRule)

	s.Handle(http.MethodGet, `^/accounts/[^/]+/gateway/lists/[^/]+/items$`, s.listGatewayListItems)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/gateway/lists/[^/]+$`, s.getGatewayList)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/gateway/lists/[^/]+$`, s.updateGatewayList)
	s.Handle(http.MethodPatch, `^/accounts/[^/]+/gateway/lists/[^/]+$`, s.editGatewayList)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/gateway/lists/[^/]+$`, s.deleteGatewayList)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/gateway/lists$`, s.listGatewayLists)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/gateway/lists$`, s.createGatewayList)
}

func cloneDevicePolicy(policy DevicePolicy) DevicePolicy {
	if policy == nil {
		return nil
	}
	encoded, _ := json.Marshal(policy)
	var result DevicePolicy
	_ = json.Unmarshal(encoded, &result)
	return result
}

func (s *Server) ensureDefaultDevicePolicyLocked(accountID string) DevicePolicy {
	policy := s.State.defaultDevicePolicies[accountID]
	if policy == nil {
		policy = DevicePolicy{"policy_id": "default", "default": true, "name": "Default", "include": []any{}, "exclude": []any{}, "fallback_domains": []any{}, "dns_search_suffixes": []any{}}
		s.State.defaultDevicePolicies[accountID] = policy
	}
	return policy
}

func (s *Server) getDefaultDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.Lock()
	policy := cloneDevicePolicy(s.ensureDefaultDevicePolicyLocked(accountID))
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, policy)
}

func (s *Server) editDefaultDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input DevicePolicy
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	policy := s.ensureDefaultDevicePolicyLocked(accountID)
	mergeJSONMap(policy, input)
	policy["policy_id"] = "default"
	policy["default"] = true
	result := cloneDevicePolicy(policy)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, result)
}

func (s *Server) createCustomDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input DevicePolicy
	if !decodeJSON(w, r, &input) {
		return
	}
	name, _ := input["name"].(string)
	match, _ := input["match"].(string)
	if name == "" || match == "" {
		WriteError(w, http.StatusBadRequest, 1004, "name and match are required")
		return
	}
	s.State.mu.Lock()
	if s.State.customDevicePolicies[accountID] == nil {
		s.State.customDevicePolicies[accountID] = make(map[string]DevicePolicy)
	}
	for _, existing := range s.State.customDevicePolicies[accountID] {
		if existing["name"] == name {
			s.State.mu.Unlock()
			WriteError(w, http.StatusConflict, 1005, "device policy name already exists")
			return
		}
	}
	id := s.State.nextIdentifierLocked("device-policy")
	input["policy_id"] = id
	input["default"] = false
	for _, key := range []string{"include", "exclude", "fallback_domains", "dns_search_suffixes"} {
		if _, ok := input[key]; !ok {
			input[key] = []any{}
		}
	}
	s.State.customDevicePolicies[accountID][id] = cloneDevicePolicy(input)
	result := cloneDevicePolicy(input)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, result)
}

func (s *Server) listCustomDevicePolicies(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	items := make([]DevicePolicy, 0, len(s.State.customDevicePolicies[accountID]))
	for _, policy := range s.State.customDevicePolicies[accountID] {
		items = append(items, cloneDevicePolicy(policy))
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return stringField(items[i], "policy_id") < stringField(items[j], "policy_id") })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getCustomDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID, policyID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	policy, ok := s.State.customDevicePolicies[accountID][policyID]
	result := cloneDevicePolicy(policy)
	s.State.mu.RUnlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "device policy not found")
		return
	}
	writeResult(w, http.StatusOK, result)
}

func (s *Server) editCustomDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID, policyID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input DevicePolicy
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	policy, ok := s.State.customDevicePolicies[accountID][policyID]
	if ok {
		mergeJSONMap(policy, input)
		policy["policy_id"] = policyID
		policy["default"] = false
		s.State.customDevicePolicies[accountID][policyID] = policy
	}
	result := cloneDevicePolicy(policy)
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "device policy not found")
		return
	}
	writeResult(w, http.StatusOK, result)
}

func (s *Server) deleteCustomDevicePolicy(w http.ResponseWriter, r *http.Request) {
	accountID, policyID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	_, ok := s.State.customDevicePolicies[accountID][policyID]
	if ok {
		delete(s.State.customDevicePolicies[accountID], policyID)
	}
	items := make([]DevicePolicy, 0, len(s.State.customDevicePolicies[accountID]))
	for _, policy := range s.State.customDevicePolicies[accountID] {
		items = append(items, cloneDevicePolicy(policy))
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "device policy not found")
		return
	}
	writeResult(w, http.StatusOK, items)
}

func (s *Server) getDefaultDevicePolicyList(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID := pathPart(r.URL.Path, 1)
		s.State.mu.Lock()
		policy := s.ensureDefaultDevicePolicyLocked(accountID)
		result := cloneJSONSlice(policy[kind])
		s.State.mu.Unlock()
		writePage(w, result, resultInfo{Page: 1, PerPage: len(result), Count: len(result), TotalCount: len(result), TotalPages: 1})
	}
}

func (s *Server) updateDefaultDevicePolicyList(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID := pathPart(r.URL.Path, 1)
		var input []any
		if !decodeJSON(w, r, &input) {
			return
		}
		s.State.mu.Lock()
		policy := s.ensureDefaultDevicePolicyLocked(accountID)
		policy[kind] = cloneJSONSlice(input)
		s.State.mu.Unlock()
		writePage(w, input, resultInfo{Page: 1, PerPage: len(input), Count: len(input), TotalCount: len(input), TotalPages: 1})
	}
}

func (s *Server) getCustomDevicePolicyList(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, policyID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
		s.State.mu.RLock()
		policy, ok := s.State.customDevicePolicies[accountID][policyID]
		result := cloneJSONSlice(policy[kind])
		s.State.mu.RUnlock()
		if !ok {
			WriteError(w, http.StatusNotFound, 1001, "device policy not found")
			return
		}
		writePage(w, result, resultInfo{Page: 1, PerPage: len(result), Count: len(result), TotalCount: len(result), TotalPages: 1})
	}
}

func (s *Server) updateCustomDevicePolicyList(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, policyID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
		var input []any
		if !decodeJSON(w, r, &input) {
			return
		}
		s.State.mu.Lock()
		policy, ok := s.State.customDevicePolicies[accountID][policyID]
		if ok {
			policy[kind] = cloneJSONSlice(input)
		}
		s.State.mu.Unlock()
		if !ok {
			WriteError(w, http.StatusNotFound, 1001, "device policy not found")
			return
		}
		writePage(w, input, resultInfo{Page: 1, PerPage: len(input), Count: len(input), TotalCount: len(input), TotalPages: 1})
	}
}

func mergeJSONMap(target, input map[string]any) {
	for key, value := range input {
		target[key] = value
	}
}

func cloneJSONSlice(value any) []any {
	items, _ := value.([]any)
	encoded, _ := json.Marshal(items)
	var result []any
	_ = json.Unmarshal(encoded, &result)
	if result == nil {
		return []any{}
	}
	return result
}

func stringField(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func (s *Server) editDeviceSettings(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		GatewayProxyEnabled                *bool    `json:"gateway_proxy_enabled"`
		GatewayUDPProxyEnabled             *bool    `json:"gateway_udp_proxy_enabled"`
		RootCertificateInstallationEnabled *bool    `json:"root_certificate_installation_enabled"`
		UseZTVirtualIP                     *bool    `json:"use_zt_virtual_ip"`
		DisableForTime                     *float64 `json:"disable_for_time"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	current := s.State.deviceSettings[accountID]
	if input.GatewayProxyEnabled != nil {
		current.GatewayProxyEnabled = *input.GatewayProxyEnabled
	}
	if input.GatewayUDPProxyEnabled != nil {
		current.GatewayUDPProxyEnabled = *input.GatewayUDPProxyEnabled
	}
	if input.RootCertificateInstallationEnabled != nil {
		current.RootCertificateInstallationEnabled = *input.RootCertificateInstallationEnabled
	}
	if input.UseZTVirtualIP != nil {
		current.UseZTVirtualIP = *input.UseZTVirtualIP
	}
	if input.DisableForTime != nil {
		current.DisableForTime = *input.DisableForTime
	}
	s.State.deviceSettings[accountID] = current
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, current)
}

func (s *Server) updateOrganization(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input struct {
		SessionDuration          *string `json:"session_duration"`
		WARPAuthSessionDuration  *string `json:"warp_auth_session_duration"`
		AllowAuthenticateViaWARP *bool   `json:"allow_authenticate_via_warp"`
		IsUIReadOnly             *bool   `json:"is_ui_read_only"`
		DenyUnmatchedRequests    *bool   `json:"deny_unmatched_requests"`
		WARPAuthNonBrowser401    *bool   `json:"warp_auth_non_browser_401"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	current := s.State.organizations[accountID]
	if input.SessionDuration != nil {
		current.SessionDuration = *input.SessionDuration
	}
	if input.WARPAuthSessionDuration != nil {
		current.WARPAuthSessionDuration = *input.WARPAuthSessionDuration
	}
	if input.AllowAuthenticateViaWARP != nil {
		current.AllowAuthenticateViaWARP = *input.AllowAuthenticateViaWARP
	}
	if input.IsUIReadOnly != nil {
		current.IsUIReadOnly = *input.IsUIReadOnly
	}
	if input.DenyUnmatchedRequests != nil {
		current.DenyUnmatchedRequests = *input.DenyUnmatchedRequests
	}
	if input.WARPAuthNonBrowser401 != nil {
		current.WARPAuthNonBrowser401 = *input.WARPAuthNonBrowser401
	}
	s.State.organizations[accountID] = current
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, current)
}

func (s *Server) createGatewayRule(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input GatewayRule
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Name == "" || input.Action == "" || input.Traffic == "" || len(input.Filters) != 1 || input.Filters[0] != "l4" && input.Filters[0] != "dns" {
		WriteError(w, http.StatusBadRequest, 1004, "name, action, traffic, and exactly one l4 or dns filter are required")
		return
	}
	now := time.Now().UTC()
	s.State.mu.Lock()
	if s.State.gatewayRules[accountID] == nil {
		s.State.gatewayRules[accountID] = make(map[string]GatewayRule)
	}
	input.ID = s.State.nextIdentifierLocked("gateway-rule")
	input.AccountID = accountID
	input.CreatedAt, input.UpdatedAt = now, now
	s.State.gatewayRules[accountID][input.ID] = cloneGatewayRule(input)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, input)
}

func (s *Server) listGatewayRules(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	items := make([]GatewayRule, 0, len(s.State.gatewayRules[accountID]))
	for _, rule := range s.State.gatewayRules[accountID] {
		if rule.DeletedAt == nil {
			items = append(items, cloneGatewayRule(rule))
		}
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getGatewayRule(w http.ResponseWriter, r *http.Request) {
	accountID, ruleID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	rule, ok := s.State.gatewayRules[accountID][ruleID]
	s.State.mu.RUnlock()
	if !ok || rule.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "Gateway rule not found")
		return
	}
	writeResult(w, http.StatusOK, cloneGatewayRule(rule))
}

func (s *Server) updateGatewayRule(w http.ResponseWriter, r *http.Request) {
	accountID, ruleID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input GatewayRule
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	current, ok := s.State.gatewayRules[accountID][ruleID]
	if ok && current.DeletedAt == nil {
		input.ID, input.AccountID, input.CreatedAt, input.UpdatedAt = ruleID, accountID, current.CreatedAt, time.Now().UTC()
		s.State.gatewayRules[accountID][ruleID] = cloneGatewayRule(input)
	}
	s.State.mu.Unlock()
	if !ok || current.DeletedAt != nil {
		WriteError(w, http.StatusNotFound, 1001, "Gateway rule not found")
		return
	}
	writeResult(w, http.StatusOK, input)
}

func (s *Server) deleteGatewayRule(w http.ResponseWriter, r *http.Request) {
	accountID, ruleID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	rule, ok := s.State.gatewayRules[accountID][ruleID]
	if ok && rule.DeletedAt == nil {
		now := time.Now().UTC()
		rule.DeletedAt, rule.UpdatedAt = &now, now
		s.State.gatewayRules[accountID][ruleID] = rule
	} else {
		ok = false
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway rule not found")
		return
	}
	writeResult(w, http.StatusOK, nil)
}

func cloneGatewayRule(rule GatewayRule) GatewayRule {
	rule.Filters = append([]string(nil), rule.Filters...)
	encoded, _ := json.Marshal(rule.RuleSettings)
	_ = json.Unmarshal(encoded, &rule.RuleSettings)
	return rule
}

func (s *Server) createGatewayList(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	var input GatewayList
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Type = strings.ToUpper(input.Type)
	if input.Name == "" || !validGatewayListType(input.Type) {
		WriteError(w, http.StatusBadRequest, 1004, "name and supported list type are required")
		return
	}
	now := time.Now().UTC()
	s.State.mu.Lock()
	if s.State.gatewayLists[accountID] == nil {
		s.State.gatewayLists[accountID] = make(map[string]GatewayList)
	}
	input.ID = s.State.nextIdentifierLocked("gateway-list")
	input.AccountID = accountID
	input.CreatedAt, input.UpdatedAt = now, now
	input.Items = normalizeGatewayListItems(input.Items, now)
	input.Count = len(input.Items)
	s.State.gatewayLists[accountID][input.ID] = cloneGatewayList(input)
	s.State.mu.Unlock()
	writeResult(w, http.StatusOK, input)
}

func (s *Server) listGatewayLists(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	filterType := strings.ToUpper(r.URL.Query().Get("type"))
	s.State.mu.RLock()
	items := make([]GatewayList, 0, len(s.State.gatewayLists[accountID]))
	for _, list := range s.State.gatewayLists[accountID] {
		if filterType == "" || list.Type == filterType {
			items = append(items, cloneGatewayList(list))
		}
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	writeResult(w, http.StatusOK, items)
}

func (s *Server) getGatewayList(w http.ResponseWriter, r *http.Request) {
	accountID, listID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	list, ok := s.State.gatewayLists[accountID][listID]
	s.State.mu.RUnlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway list not found")
		return
	}
	writeResult(w, http.StatusOK, cloneGatewayList(list))
}

func (s *Server) updateGatewayList(w http.ResponseWriter, r *http.Request) {
	accountID, listID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input GatewayList
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	current, ok := s.State.gatewayLists[accountID][listID]
	if ok {
		current.Name, current.Description = input.Name, input.Description
		if input.Items != nil {
			current.Items = normalizeGatewayListItems(input.Items, time.Now().UTC())
		}
		current.Count, current.UpdatedAt = len(current.Items), time.Now().UTC()
		s.State.gatewayLists[accountID][listID] = current
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway list not found")
		return
	}
	writeResult(w, http.StatusOK, cloneGatewayList(current))
}

func (s *Server) editGatewayList(w http.ResponseWriter, r *http.Request) {
	accountID, listID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	var input struct {
		Append []GatewayListItem `json:"append"`
		Remove []string          `json:"remove"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	s.State.mu.Lock()
	current, ok := s.State.gatewayLists[accountID][listID]
	if ok {
		remove := make(map[string]struct{}, len(input.Remove))
		for _, value := range input.Remove {
			remove[value] = struct{}{}
		}
		kept := current.Items[:0]
		for _, item := range current.Items {
			if _, drop := remove[item.Value]; !drop {
				kept = append(kept, item)
			}
		}
		current.Items = append([]GatewayListItem(nil), append(kept, normalizeGatewayListItems(input.Append, time.Now().UTC())...)...)
		current.Count, current.UpdatedAt = len(current.Items), time.Now().UTC()
		s.State.gatewayLists[accountID][listID] = current
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway list not found")
		return
	}
	writeResult(w, http.StatusOK, cloneGatewayList(current))
}

func (s *Server) deleteGatewayList(w http.ResponseWriter, r *http.Request) {
	accountID, listID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	_, ok := s.State.gatewayLists[accountID][listID]
	if ok {
		delete(s.State.gatewayLists[accountID], listID)
	}
	s.State.mu.Unlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway list not found")
		return
	}
	writeResult(w, http.StatusOK, nil)
}

func (s *Server) listGatewayListItems(w http.ResponseWriter, r *http.Request) {
	accountID, listID := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	list, ok := s.State.gatewayLists[accountID][listID]
	items := cloneGatewayList(list).Items
	s.State.mu.RUnlock()
	if !ok {
		WriteError(w, http.StatusNotFound, 1001, "Gateway list not found")
		return
	}
	writeResult(w, http.StatusOK, items)
}

func validGatewayListType(value string) bool {
	switch value {
	case "SERIAL", "URL", "DOMAIN", "EMAIL", "IP":
		return true
	default:
		return false
	}
}

func normalizeGatewayListItems(items []GatewayListItem, now time.Time) []GatewayListItem {
	result := append([]GatewayListItem(nil), items...)
	for i := range result {
		if result[i].CreatedAt.IsZero() {
			result[i].CreatedAt = now
		}
	}
	return result
}

func cloneGatewayList(list GatewayList) GatewayList {
	list.Items = append([]GatewayListItem(nil), list.Items...)
	return list
}
