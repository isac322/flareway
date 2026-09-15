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
	"slices"
	"sort"
	"strings"
	"time"
)

const accessTagNameMaxLength = 35

func (s *Server) registerAccessRoutes() {
	for _, prefix := range []string{"accounts", "zones"} {
		s.Handle(http.MethodPost, `^/`+prefix+`/[^/]+/access/apps$`, s.createAccessApplication)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/apps$`, s.listAccessApplications)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/apps/[^/]+$`, s.getAccessApplication)
		s.Handle(http.MethodPut, `^/`+prefix+`/[^/]+/access/apps/[^/]+$`, s.updateAccessApplication)
		s.Handle(http.MethodDelete, `^/`+prefix+`/[^/]+/access/apps/[^/]+$`, s.deleteAccessApplication)
		s.Handle(http.MethodPost, `^/`+prefix+`/[^/]+/access/apps/[^/]+/revoke_tokens$`, s.revokeAccessApplicationTokens)

		s.Handle(http.MethodPost, `^/`+prefix+`/[^/]+/access/groups$`, s.createAccessGroup)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/groups$`, s.listAccessGroups)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/groups/[^/]+$`, s.getAccessGroup)
		s.Handle(http.MethodPut, `^/`+prefix+`/[^/]+/access/groups/[^/]+$`, s.updateAccessGroup)
		s.Handle(http.MethodDelete, `^/`+prefix+`/[^/]+/access/groups/[^/]+$`, s.deleteAccessGroup)

		s.Handle(http.MethodPost, `^/`+prefix+`/[^/]+/access/identity_providers$`, s.createIdentityProvider)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/identity_providers$`, s.listIdentityProviders)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/identity_providers/[^/]+$`, s.getIdentityProvider)
		s.Handle(http.MethodPut, `^/`+prefix+`/[^/]+/access/identity_providers/[^/]+$`, s.updateIdentityProvider)
		s.Handle(http.MethodDelete, `^/`+prefix+`/[^/]+/access/identity_providers/[^/]+$`, s.deleteIdentityProvider)

		s.Handle(http.MethodPost, `^/`+prefix+`/[^/]+/access/service_tokens$`, s.createAccessServiceToken)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/service_tokens$`, s.listAccessServiceTokens)
		s.Handle(http.MethodGet, `^/`+prefix+`/[^/]+/access/service_tokens/[^/]+$`, s.getAccessServiceToken)
		s.Handle(http.MethodPut, `^/`+prefix+`/[^/]+/access/service_tokens/[^/]+$`, s.updateAccessServiceToken)
		s.Handle(http.MethodDelete, `^/`+prefix+`/[^/]+/access/service_tokens/[^/]+$`, s.deleteAccessServiceToken)
	}

	s.Handle(http.MethodPost, `^/accounts/[^/]+/access/policies$`, s.createAccessPolicy)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/access/policies$`, s.listAccessPolicies)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/access/policies/[^/]+$`, s.getAccessPolicy)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/access/policies/[^/]+$`, s.updateAccessPolicy)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/access/policies/[^/]+$`, s.deleteAccessPolicy)

	s.Handle(http.MethodPost, `^/accounts/[^/]+/devices/posture$`, s.createDevicePostureRule)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/posture$`, s.listDevicePostureRules)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/devices/posture/[^/]+$`, s.getDevicePostureRule)
	s.Handle(http.MethodPut, `^/accounts/[^/]+/devices/posture/[^/]+$`, s.updateDevicePostureRule)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/devices/posture/[^/]+$`, s.deleteDevicePostureRule)

	s.Handle(http.MethodPost, `^/accounts/[^/]+/access/service_tokens/[^/]+/rotate$`, s.rotateAccessServiceToken)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/access/service_tokens/[^/]+/refresh$`, s.refreshAccessServiceToken)
	s.Handle(http.MethodPost, `^/accounts/[^/]+/access/tags$`, s.createAccessTag)
	s.Handle(http.MethodGet, `^/accounts/[^/]+/access/tags/[^/]+$`, s.getAccessTag)
	s.Handle(http.MethodDelete, `^/accounts/[^/]+/access/tags/[^/]+$`, s.deleteAccessTag)
}

func (s *Server) createAccessApplication(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "body")
	if !ok || !requireStrings(w, resource, "type") || !validateApplicationPolicies(w, resource) {
		return
	}
	scope := accessScope(r.URL.Path)
	now := time.Now().UTC()
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if !validateApplicationTagsLocked(w, s.State, r.URL.Path, resource) {
		return
	}
	if name := resourceString(resource, "name"); name != "" && duplicateResourceName(s.State.accessApps[scope], name, "") {
		WriteError(w, http.StatusConflict, 1005, "Access application name already exists")
		return
	}
	ensureResourceMap(s.State.accessApps, scope)
	id := s.State.nextIdentifierLocked("access-app")
	resource["id"] = id
	resource["aud"] = "aud-" + id
	resource["created_at"] = now
	resource["updated_at"] = now
	response := accessApplicationCreateResponse(resource, id)
	stripAccessApplicationSecrets(resource)
	s.State.accessApps[scope][id] = cloneAccessResource(resource)
	s.State.adjustPolicyAppCountsLocked(scope, nil, resource)
	writeResult(w, http.StatusOK, response)
}

func (s *Server) listAccessApplications(w http.ResponseWriter, r *http.Request) {
	scope := accessScope(r.URL.Path)
	s.State.mu.RLock()
	items := sortedAccessResources(s.State.accessApps[scope])
	s.State.mu.RUnlock()
	query := r.URL.Query()
	exact := strings.EqualFold(query.Get("exact"), "true")
	items = filterAccessResources(items, func(resource AccessResource) bool {
		return matchQuery(resourceString(resource, "name"), query.Get("name"), exact) &&
			matchQuery(resourceString(resource, "domain"), query.Get("domain"), exact) &&
			matchQuery(resourceString(resource, "aud"), query.Get("aud"), true) &&
			matchSearch(resource, query.Get("search"))
	})
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getAccessApplication(w http.ResponseWriter, r *http.Request) {
	writeAccessResourceByID(w, s.State, s.State.accessApps, accessScope(r.URL.Path), pathPart(r.URL.Path, 4), "Access application")
}

func (s *Server) updateAccessApplication(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "body")
	if !ok || !requireStrings(w, resource, "type") || !validateApplicationPolicies(w, resource) {
		return
	}
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if !validateApplicationTagsLocked(w, s.State, r.URL.Path, resource) {
		return
	}
	existing, found := s.State.accessApps[scope][id]
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Access application not found")
		return
	}
	if name := resourceString(resource, "name"); name != "" && duplicateResourceName(s.State.accessApps[scope], name, id) {
		WriteError(w, http.StatusConflict, 1005, "Access application name already exists")
		return
	}
	resource["id"] = id
	resource["aud"] = existing["aud"]
	resource["created_at"] = existing["created_at"]
	resource["updated_at"] = time.Now().UTC()
	stripAccessApplicationSecrets(resource)
	s.State.accessApps[scope][id] = cloneAccessResource(resource)
	s.State.adjustPolicyAppCountsLocked(scope, existing, resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) deleteAccessApplication(w http.ResponseWriter, r *http.Request) {
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	resource, found := s.State.accessApps[scope][id]
	if found {
		s.State.adjustPolicyAppCountsLocked(scope, resource, nil)
		delete(s.State.accessApps[scope], id)
	}
	s.State.mu.Unlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Access application not found")
		return
	}
	writeResult(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Server) revokeAccessApplicationTokens(w http.ResponseWriter, r *http.Request) {
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	_, found := s.State.accessApps[scope][id]
	s.State.mu.RUnlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Access application not found")
		return
	}
	writeResult(w, http.StatusOK, map[string]string{"id": id})
}

func accessApplicationCreateResponse(resource AccessResource, id string) AccessResource {
	response := cloneAccessResource(resource)
	stripAccessApplicationSecrets(response)
	if resourceString(response, "type") != "saas" {
		return response
	}
	saas, ok := response["saas_app"].(map[string]any)
	if !ok {
		saas = make(map[string]any)
		response["saas_app"] = saas
	}
	saas["client_secret"] = "saas-secret-" + id
	return response
}

func stripAccessApplicationSecrets(resource AccessResource) {
	if saas, ok := resource["saas_app"].(map[string]any); ok {
		delete(saas, "client_secret")
	}
	scim, ok := resource["scim_config"].(map[string]any)
	if !ok {
		return
	}
	switch authentication := scim["authentication"].(type) {
	case map[string]any:
		stripAccessAuthenticationSecrets(authentication)
	case []any:
		for _, item := range authentication {
			if object, ok := item.(map[string]any); ok {
				stripAccessAuthenticationSecrets(object)
			}
		}
	}
}

func stripAccessAuthenticationSecrets(authentication map[string]any) {
	delete(authentication, "password")
	delete(authentication, "token")
	delete(authentication, "client_secret")
}

func (s *Server) createAccessTag(w http.ResponseWriter, r *http.Request) {
	var tag AccessTag
	if !decodeJSON(w, r, &tag) {
		return
	}
	if !validAccessTagName(tag.Name) {
		WriteError(w, http.StatusBadRequest, 1004, "Access tag name must be 1-35 ASCII letters, digits, hyphens, or underscores")
		return
	}
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if _, found := s.State.accessTags[accountID][tag.Name]; found {
		WriteError(w, http.StatusConflict, 1005, "Access tag already exists")
		return
	}
	if s.State.accessTags[accountID] == nil {
		s.State.accessTags[accountID] = make(map[string]AccessTag)
	}
	s.State.accessTags[accountID][tag.Name] = tag
	writeResult(w, http.StatusOK, tag)
}

func (s *Server) getAccessTag(w http.ResponseWriter, r *http.Request) {
	accountID, name := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	tag, found := s.State.accessTags[accountID][name]
	s.State.mu.RUnlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Access tag not found")
		return
	}
	writeResult(w, http.StatusOK, tag)
}

func (s *Server) deleteAccessTag(w http.ResponseWriter, r *http.Request) {
	accountID, name := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if _, found := s.State.accessTags[accountID][name]; !found {
		WriteError(w, http.StatusNotFound, 1001, "Access tag not found")
		return
	}
	if accessApplicationUsesTagLocked(s.State.accessApps["accounts/"+accountID], name) {
		WriteError(w, http.StatusConflict, 1005, "Access tag is still assigned to an application")
		return
	}
	delete(s.State.accessTags[accountID], name)
	writeResult(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Server) createAccessPolicy(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok || !requireStrings(w, resource, "name", "decision") || !requireArray(w, resource, "include") {
		return
	}
	accountID := pathPart(r.URL.Path, 1)
	now := time.Now().UTC()
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if duplicateResourceName(s.State.accessPolicies[accountID], resourceString(resource, "name"), "") {
		WriteError(w, http.StatusConflict, 1005, "Access policy name already exists")
		return
	}
	ensureResourceMap(s.State.accessPolicies, accountID)
	id := s.State.nextIdentifierLocked("access-policy")
	resource["id"] = id
	resource["account_id"] = accountID
	resource["reusable"] = true
	resource["app_count"] = float64(0)
	resource["created_at"] = now
	resource["updated_at"] = now
	s.State.accessPolicies[accountID][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) listAccessPolicies(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	items := sortedAccessResources(s.State.accessPolicies[accountID])
	s.State.mu.RUnlock()
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getAccessPolicy(w http.ResponseWriter, r *http.Request) {
	writeAccessResourceByID(w, s.State, s.State.accessPolicies, pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4), "Access policy")
}

func (s *Server) updateAccessPolicy(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok || !requireStrings(w, resource, "name", "decision") || !requireArray(w, resource, "include") {
		return
	}
	accountID, id := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	existing, found := s.State.accessPolicies[accountID][id]
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Access policy not found")
		return
	}
	if duplicateResourceName(s.State.accessPolicies[accountID], resourceString(resource, "name"), id) {
		WriteError(w, http.StatusConflict, 1005, "Access policy name already exists")
		return
	}
	resource["id"] = id
	resource["account_id"] = accountID
	resource["reusable"] = true
	resource["app_count"] = existing["app_count"]
	resource["created_at"] = existing["created_at"]
	resource["updated_at"] = time.Now().UTC()
	s.State.accessPolicies[accountID][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) deleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	deleteAccessResource(w, s.State, s.State.accessPolicies, pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4), "Access policy")
}

func (s *Server) createAccessGroup(w http.ResponseWriter, r *http.Request) {
	s.createNamedAccessResource(w, r, "Access group", "access-group", s.State.accessGroups, "", []string{"name"}, []string{"include"})
}

func (s *Server) listAccessGroups(w http.ResponseWriter, r *http.Request) {
	s.listNamedAccessResources(w, r, s.State.accessGroups)
}

func (s *Server) getAccessGroup(w http.ResponseWriter, r *http.Request) {
	writeAccessResourceByID(w, s.State, s.State.accessGroups, accessScope(r.URL.Path), pathPart(r.URL.Path, 4), "Access group")
}

func (s *Server) updateAccessGroup(w http.ResponseWriter, r *http.Request) {
	s.updateNamedAccessResource(w, r, "Access group", s.State.accessGroups, "", []string{"name"}, []string{"include"})
}

func (s *Server) deleteAccessGroup(w http.ResponseWriter, r *http.Request) {
	deleteAccessResource(w, s.State, s.State.accessGroups, accessScope(r.URL.Path), pathPart(r.URL.Path, 4), "Access group")
}

func (s *Server) createIdentityProvider(w http.ResponseWriter, r *http.Request) {
	s.createNamedAccessResource(w, r, "Identity provider", "identity-provider", s.State.identityProviders, "identity_provider", []string{"name", "type"}, nil)
}

func (s *Server) listIdentityProviders(w http.ResponseWriter, r *http.Request) {
	s.listNamedAccessResources(w, r, s.State.identityProviders)
}

func (s *Server) getIdentityProvider(w http.ResponseWriter, r *http.Request) {
	writeAccessResourceByID(w, s.State, s.State.identityProviders, accessScope(r.URL.Path), pathPart(r.URL.Path, 4), "Identity provider")
}

func (s *Server) updateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	s.updateNamedAccessResource(w, r, "Identity provider", s.State.identityProviders, "identity_provider", []string{"name", "type"}, nil)
}

func (s *Server) deleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	deleteAccessResource(w, s.State, s.State.identityProviders, accessScope(r.URL.Path), pathPart(r.URL.Path, 4), "Identity provider")
}

func (s *Server) createDevicePostureRule(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok || !requireStrings(w, resource, "name", "type") {
		return
	}
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if duplicateResourceName(s.State.postureRules[accountID], resourceString(resource, "name"), "") {
		WriteError(w, http.StatusConflict, 1005, "Device posture rule name already exists")
		return
	}
	ensureResourceMap(s.State.postureRules, accountID)
	id := s.State.nextIdentifierLocked("posture-rule")
	resource["id"] = id
	resource["enabled"] = true
	s.State.postureRules[accountID][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) listDevicePostureRules(w http.ResponseWriter, r *http.Request) {
	accountID := pathPart(r.URL.Path, 1)
	s.State.mu.RLock()
	items := sortedAccessResources(s.State.postureRules[accountID])
	s.State.mu.RUnlock()
	writeResult(w, http.StatusOK, items)
}

func (s *Server) getDevicePostureRule(w http.ResponseWriter, r *http.Request) {
	writeAccessResourceByID(w, s.State, s.State.postureRules, pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4), "Device posture rule")
}

func (s *Server) updateDevicePostureRule(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok || !requireStrings(w, resource, "name", "type") {
		return
	}
	accountID, id := pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if _, found := s.State.postureRules[accountID][id]; !found {
		WriteError(w, http.StatusNotFound, 1001, "Device posture rule not found")
		return
	}
	if duplicateResourceName(s.State.postureRules[accountID], resourceString(resource, "name"), id) {
		WriteError(w, http.StatusConflict, 1005, "Device posture rule name already exists")
		return
	}
	resource["id"] = id
	resource["enabled"] = true
	s.State.postureRules[accountID][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) deleteDevicePostureRule(w http.ResponseWriter, r *http.Request) {
	deleteAccessResource(w, s.State, s.State.postureRules, pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4), "Device posture rule")
}

func (s *Server) createAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok || !requireStrings(w, resource, "name") {
		return
	}
	scope := accessScope(r.URL.Path)
	duration := resourceString(resource, "duration")
	if duration == "" {
		duration = "8760h"
	}
	now := time.Now().UTC()
	expiresAt, ok := serviceTokenExpiry(w, duration, now)
	if !ok {
		return
	}
	enabled := true
	if value, present := resource["enabled"].(bool); present {
		enabled = value
	}
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if duplicateServiceTokenName(s.State.serviceTokens[scope], resourceString(resource, "name"), "") {
		WriteError(w, http.StatusConflict, 1005, "Service token name already exists")
		return
	}
	ensureServiceTokenMap(s.State.serviceTokens, scope)
	id := s.State.nextIdentifierLocked("service-token")
	token := AccessServiceToken{
		ID: id, ClientID: id + ".access.stub", Duration: duration, Enabled: enabled,
		ExpiresAt: expiresAt, CreatedAt: now, Name: resourceString(resource, "name"),
		clientSecret: "secret-" + id + "-v1", secretVersion: 1,
	}
	s.State.serviceTokens[scope][id] = token
	writeResult(w, http.StatusOK, serviceTokenSecretResponse(token))
}

func (s *Server) listAccessServiceTokens(w http.ResponseWriter, r *http.Request) {
	scope := accessScope(r.URL.Path)
	s.State.mu.RLock()
	items := make([]AccessServiceToken, 0, len(s.State.serviceTokens[scope]))
	for _, token := range s.State.serviceTokens[scope] {
		if query := r.URL.Query().Get("name"); query != "" && token.Name != query {
			continue
		}
		if query := strings.ToLower(r.URL.Query().Get("search")); query != "" && !strings.Contains(strings.ToLower(token.Name), query) {
			continue
		}
		items = append(items, publicServiceToken(token))
	}
	s.State.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) getAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.RLock()
	token, found := s.State.serviceTokens[scope][id]
	s.State.mu.RUnlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Service token not found")
		return
	}
	writeResult(w, http.StatusOK, publicServiceToken(token))
}

func (s *Server) updateAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok {
		return
	}
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	token, found := s.State.serviceTokens[scope][id]
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Service token not found")
		return
	}
	if name := resourceString(resource, "name"); name != "" {
		if duplicateServiceTokenName(s.State.serviceTokens[scope], name, id) {
			WriteError(w, http.StatusConflict, 1005, "Service token name already exists")
			return
		}
		token.Name = name
	}
	if duration := resourceString(resource, "duration"); duration != "" {
		expiresAt, valid := serviceTokenExpiry(w, duration, time.Now().UTC())
		if !valid {
			return
		}
		token.Duration, token.ExpiresAt = duration, expiresAt
	}
	if enabled, present := resource["enabled"].(bool); present {
		token.Enabled = enabled
	}
	if version, present := resourceNumber(resource, "client_secret_version"); present && version > token.secretVersion {
		rotateServiceToken(&token, version, optionalTime(resource["previous_client_secret_expires_at"]))
	}
	if expires := optionalTime(resource["previous_client_secret_expires_at"]); expires != nil {
		token.previousClientSecretExpiresAt = expires
	}
	s.State.serviceTokens[scope][id] = token
	writeResult(w, http.StatusOK, publicServiceToken(token))
}

func (s *Server) deleteAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	_, found := s.State.serviceTokens[scope][id]
	if found {
		delete(s.State.serviceTokens[scope], id)
	}
	s.State.mu.Unlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Service token not found")
		return
	}
	writeResult(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Server) rotateAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	resource, ok := decodeAccessResource(w, r, "")
	if !ok {
		return
	}
	scope, id := "accounts/"+pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	token, found := s.State.serviceTokens[scope][id]
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Service token not found")
		return
	}
	rotateServiceToken(&token, token.secretVersion+1, optionalTime(resource["previous_client_secret_expires_at"]))
	s.State.serviceTokens[scope][id] = token
	writeResult(w, http.StatusOK, serviceTokenSecretResponse(token))
}

func (s *Server) refreshAccessServiceToken(w http.ResponseWriter, r *http.Request) {
	scope, id := "accounts/"+pathPart(r.URL.Path, 1), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	token, found := s.State.serviceTokens[scope][id]
	if !found {
		WriteError(w, http.StatusNotFound, 1001, "Service token not found")
		return
	}
	expiresAt, valid := serviceTokenExpiry(w, token.Duration, time.Now().UTC())
	if !valid {
		return
	}
	token.ExpiresAt = expiresAt
	s.State.serviceTokens[scope][id] = token
	writeResult(w, http.StatusOK, publicServiceToken(token))
}

func (s *Server) createNamedAccessResource(w http.ResponseWriter, r *http.Request, label, idKind string, resources map[string]map[string]AccessResource, unwrap string, requiredStrings, requiredArrays []string) {
	resource, ok := decodeAccessResource(w, r, unwrap)
	if !ok || !requireStrings(w, resource, requiredStrings...) {
		return
	}
	for _, field := range requiredArrays {
		if !requireArray(w, resource, field) {
			return
		}
	}
	scope := accessScope(r.URL.Path)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if duplicateResourceName(resources[scope], resourceString(resource, "name"), "") {
		WriteError(w, http.StatusConflict, 1005, label+" name already exists")
		return
	}
	ensureResourceMap(resources, scope)
	id := s.State.nextIdentifierLocked(idKind)
	resource["id"] = id
	resources[scope][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func (s *Server) listNamedAccessResources(w http.ResponseWriter, r *http.Request, resources map[string]map[string]AccessResource) {
	scope := accessScope(r.URL.Path)
	s.State.mu.RLock()
	items := sortedAccessResources(resources[scope])
	s.State.mu.RUnlock()
	name, search := r.URL.Query().Get("name"), strings.ToLower(r.URL.Query().Get("search"))
	items = filterAccessResources(items, func(resource AccessResource) bool {
		if name != "" && resourceString(resource, "name") != name {
			return false
		}
		return search == "" || strings.Contains(strings.ToLower(resourceString(resource, "name")), search)
	})
	page, info := paginate(items, r)
	writePage(w, page, info)
}

func (s *Server) updateNamedAccessResource(w http.ResponseWriter, r *http.Request, label string, resources map[string]map[string]AccessResource, unwrap string, requiredStrings, requiredArrays []string) {
	resource, ok := decodeAccessResource(w, r, unwrap)
	if !ok || !requireStrings(w, resource, requiredStrings...) {
		return
	}
	for _, field := range requiredArrays {
		if !requireArray(w, resource, field) {
			return
		}
	}
	scope, id := accessScope(r.URL.Path), pathPart(r.URL.Path, 4)
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	if _, found := resources[scope][id]; !found {
		WriteError(w, http.StatusNotFound, 1001, label+" not found")
		return
	}
	if duplicateResourceName(resources[scope], resourceString(resource, "name"), id) {
		WriteError(w, http.StatusConflict, 1005, label+" name already exists")
		return
	}
	resource["id"] = id
	resources[scope][id] = cloneAccessResource(resource)
	writeResult(w, http.StatusOK, resource)
}

func writeAccessResourceByID(w http.ResponseWriter, state *State, resources map[string]map[string]AccessResource, scope, id, label string) {
	state.mu.RLock()
	resource, found := resources[scope][id]
	resource = cloneAccessResource(resource)
	state.mu.RUnlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, label+" not found")
		return
	}
	writeResult(w, http.StatusOK, resource)
}

func deleteAccessResource(w http.ResponseWriter, state *State, resources map[string]map[string]AccessResource, scope, id, label string) {
	state.mu.Lock()
	_, found := resources[scope][id]
	if found {
		delete(resources[scope], id)
	}
	state.mu.Unlock()
	if !found {
		WriteError(w, http.StatusNotFound, 1001, label+" not found")
		return
	}
	writeResult(w, http.StatusOK, map[string]string{"id": id})
}

func decodeAccessResource(w http.ResponseWriter, r *http.Request, unwrap string) (AccessResource, bool) {
	var resource AccessResource
	if !decodeJSON(w, r, &resource) {
		return nil, false
	}
	if unwrap != "" {
		if nested, found := resource[unwrap].(map[string]any); found {
			resource = nested
		}
	}
	return resource, true
}

func validateApplicationPolicies(w http.ResponseWriter, resource AccessResource) bool {
	value, found := resource["policies"]
	if !found || value == nil {
		return true
	}
	policies, ok := value.([]any)
	if !ok {
		WriteError(w, http.StatusBadRequest, 1004, "policies must be an array")
		return false
	}
	seen := make(map[float64]struct{}, len(policies))
	for _, value := range policies {
		policy, ok := value.(map[string]any)
		if !ok {
			WriteError(w, http.StatusBadRequest, 1004, "each policy must be an object")
			return false
		}
		precedence, ok := resourceNumber(policy, "precedence")
		if !ok || precedence < 1 {
			WriteError(w, http.StatusBadRequest, 1004, "each policy requires a positive precedence")
			return false
		}
		if _, duplicate := seen[precedence]; duplicate {
			WriteError(w, http.StatusBadRequest, 1004, "policy precedence must be unique within an application")
			return false
		}
		seen[precedence] = struct{}{}
	}
	return true
}

func validateApplicationTagsLocked(w http.ResponseWriter, state *State, path string, resource AccessResource) bool {
	if pathPart(path, 0) != "accounts" {
		return true
	}
	value, found := resource["tags"]
	if !found || value == nil {
		return true
	}
	tags, ok := accessResourceTags(value)
	if !ok {
		WriteError(w, http.StatusBadRequest, 1004, "tags must be an array of strings")
		return false
	}
	accountID := pathPart(path, 1)
	for _, name := range tags {
		if _, found := state.accessTags[accountID][name]; !found {
			WriteError(w, http.StatusBadRequest, 1004, "Access application tag "+name+" does not exist")
			return false
		}
	}
	return true
}

func accessApplicationUsesTagLocked(applications map[string]AccessResource, name string) bool {
	for _, application := range applications {
		tags, _ := accessResourceTags(application["tags"])
		if slices.Contains(tags, name) {
			return true
		}
	}
	return false
}

func accessResourceTags(value any) ([]string, bool) {
	switch tags := value.(type) {
	case nil:
		return nil, true
	case []string:
		return append([]string(nil), tags...), true
	case []any:
		result := make([]string, 0, len(tags))
		for _, value := range tags {
			tag, ok := value.(string)
			if !ok {
				return nil, false
			}
			result = append(result, tag)
		}
		return result, true
	default:
		return nil, false
	}
}

func validAccessTagName(name string) bool {
	if len(name) == 0 || len(name) > accessTagNameMaxLength {
		return false
	}
	for index := range name {
		value := name[index]
		if value >= 'a' && value <= 'z' ||
			value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' ||
			value == '-' || value == '_' {
			continue
		}
		return false
	}
	return true
}

func requireStrings(w http.ResponseWriter, resource AccessResource, fields ...string) bool {
	for _, field := range fields {
		if resourceString(resource, field) == "" {
			WriteError(w, http.StatusBadRequest, 1004, field+" is required")
			return false
		}
	}
	return true
}

func requireArray(w http.ResponseWriter, resource AccessResource, field string) bool {
	value, found := resource[field]
	if !found {
		WriteError(w, http.StatusBadRequest, 1004, field+" is required")
		return false
	}
	if _, ok := value.([]any); !ok {
		WriteError(w, http.StatusBadRequest, 1004, field+" must be an array")
		return false
	}
	return true
}

func accessScope(path string) string {
	return pathPart(path, 0) + "/" + pathPart(path, 1)
}

func ensureResourceMap(resources map[string]map[string]AccessResource, scope string) {
	if resources[scope] == nil {
		resources[scope] = make(map[string]AccessResource)
	}
}

func ensureServiceTokenMap(resources map[string]map[string]AccessServiceToken, scope string) {
	if resources[scope] == nil {
		resources[scope] = make(map[string]AccessServiceToken)
	}
}

func duplicateResourceName(resources map[string]AccessResource, name, exceptID string) bool {
	for id, resource := range resources {
		if id != exceptID && resourceString(resource, "name") == name {
			return true
		}
	}
	return false
}

func duplicateServiceTokenName(tokens map[string]AccessServiceToken, name, exceptID string) bool {
	for id, token := range tokens {
		if id != exceptID && token.Name == name {
			return true
		}
	}
	return false
}

func resourceString(resource AccessResource, key string) string {
	value, _ := resource[key].(string)
	return value
}

func resourceNumber(resource AccessResource, key string) (float64, bool) {
	switch value := resource[key].(type) {
	case json.Number:
		number, err := value.Float64()
		return number, err == nil
	case float64:
		return value, true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}

func filterAccessResources(items []AccessResource, keep func(AccessResource) bool) []AccessResource {
	filtered := items[:0]
	for _, item := range items {
		if keep(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func matchQuery(actual, wanted string, exact bool) bool {
	if wanted == "" {
		return true
	}
	if exact {
		return actual == wanted
	}
	return strings.Contains(strings.ToLower(actual), strings.ToLower(wanted))
}

func matchSearch(resource AccessResource, search string) bool {
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	return strings.Contains(strings.ToLower(resourceString(resource, "name")), search) ||
		strings.Contains(strings.ToLower(resourceString(resource, "domain")), search)
}

func serviceTokenExpiry(w http.ResponseWriter, duration string, now time.Time) (time.Time, bool) {
	if duration == "forever" {
		return time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC), true
	}
	parsed, err := time.ParseDuration(duration)
	if err != nil || parsed <= 0 {
		WriteError(w, http.StatusBadRequest, 1004, fmt.Sprintf("invalid service token duration %q", duration))
		return time.Time{}, false
	}
	return now.Add(parsed), true
}

func rotateServiceToken(token *AccessServiceToken, version float64, previousExpiresAt *time.Time) {
	token.previousClientSecret = token.clientSecret
	token.previousClientSecretExpiresAt = previousExpiresAt
	token.secretVersion = version
	token.clientSecret = fmt.Sprintf("secret-%s-v%g", token.ID, version)
}

func serviceTokenSecretResponse(token AccessServiceToken) AccessResource {
	return AccessResource{
		"id": token.ID, "client_id": token.ClientID, "client_secret": token.clientSecret,
		"duration": token.Duration, "enabled": token.Enabled, "name": token.Name,
	}
}

func optionalTime(value any) *time.Time {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil
	}
	// cloudflare-go v7 encodes date-time request fields with time.RFC3339.
	// Reject fractional seconds instead of silently accepting a different wire contract.
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil || parsed.Format(time.RFC3339) != text {
		return nil
	}
	return &parsed
}

func (s *State) adjustPolicyAppCountsLocked(scope string, previous, next AccessResource) {
	if !strings.HasPrefix(scope, "accounts/") {
		return
	}
	accountID := strings.TrimPrefix(scope, "accounts/")
	delta := make(map[string]int)
	for id := range applicationPolicyIDs(previous) {
		delta[id]--
	}
	for id := range applicationPolicyIDs(next) {
		delta[id]++
	}
	for id, change := range delta {
		policy, found := s.accessPolicies[accountID][id]
		if !found || change == 0 {
			continue
		}
		count, _ := resourceNumber(policy, "app_count")
		count += float64(change)
		if count < 0 {
			count = 0
		}
		policy["app_count"] = count
		s.accessPolicies[accountID][id] = policy
	}
}

func applicationPolicyIDs(application AccessResource) map[string]struct{} {
	ids := make(map[string]struct{})
	if application == nil {
		return ids
	}
	policies, _ := application["policies"].([]any)
	for _, value := range policies {
		policy, _ := value.(map[string]any)
		if id, _ := policy["id"].(string); id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}
