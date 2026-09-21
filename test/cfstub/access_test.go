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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAccessApplicationsPreserveAUDPrecedenceAndPagination(t *testing.T) {
	server := New(t)
	createPolicy := func(name string) AccessResource {
		var policy AccessResource
		requestResult(t, server, http.MethodPost, "/accounts/account-1/access/policies", AccessResource{
			"name": name, "decision": "allow", "include": []any{map[string]any{"everyone": map[string]any{}}},
		}, &policy)
		return policy
	}
	policyOne := createPolicy("allow-one")
	policyTwo := createPolicy("allow-two")

	createApp := func(name, domain string) AccessResource {
		var app AccessResource
		requestResult(t, server, http.MethodPost, "/accounts/account-1/access/apps", AccessResource{
			"name": name, "type": "self_hosted", "domain": domain,
			"destinations": []any{map[string]any{"type": "public", "uri": domain}},
			"policies": []any{
				map[string]any{"id": policyOne["id"], "precedence": 10},
				map[string]any{"id": policyTwo["id"], "precedence": 20},
			},
		}, &app)
		return app
	}
	first := createApp("flareway/first", "first.example.com")
	second := createApp("flareway/second", "second.example.com")
	if first["aud"] == "" || first["aud"] == second["aud"] {
		t.Fatalf("application AUDs = %#v and %#v, want non-empty unique values", first["aud"], second["aud"])
	}
	policies := server.State.AccessPolicies("account-1")
	if len(policies) != 2 || policies[0]["app_count"] != float64(2) || policies[1]["app_count"] != float64(2) {
		t.Fatalf("policy application counts = %#v, want two applications on each policy", policies)
	}

	var page []AccessResource
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/apps?page=1&per_page=1", nil, &page)
	if len(page) != 1 || page[0]["id"] != first["id"] {
		t.Fatalf("first application page = %#v", page)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/apps?page=2&per_page=1", nil, &page)
	if len(page) != 1 || page[0]["id"] != second["id"] {
		t.Fatalf("second application page = %#v", page)
	}
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/apps?name=second&exact=false", nil, &page)
	if len(page) != 1 || page[0]["id"] != second["id"] {
		t.Fatalf("filtered applications = %#v", page)
	}

	var updated AccessResource
	requestResult(t, server, http.MethodPut, "/accounts/account-1/access/apps/"+first["id"].(string), AccessResource{
		"name": "flareway/first-updated", "type": "self_hosted", "domain": "first.example.com",
		"policies": []any{map[string]any{"id": policyOne["id"], "precedence": 50}},
	}, &updated)
	if updated["aud"] != first["aud"] {
		t.Fatalf("application AUD changed on update: before=%#v after=%#v", first["aud"], updated["aud"])
	}

	response := request(t, server, http.MethodPost, "/accounts/account-1/access/apps", AccessResource{
		"name": "invalid", "type": "self_hosted", "domain": "invalid.example.com",
		"policies": []any{
			map[string]any{"id": policyOne["id"], "precedence": 1},
			map[string]any{"id": policyTwo["id"], "precedence": 1},
		},
	})
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	if response.StatusCode != http.StatusBadRequest {
		content, _ := io.ReadAll(response.Body)
		t.Fatalf("duplicate precedence returned %d: %s", response.StatusCode, content)
	}

	apps := server.State.AccessApplications("accounts/account-1")
	if len(apps) != 2 || apps[0]["aud"] == "" {
		t.Fatalf("persisted applications = %#v", apps)
	}
}

func TestAccessTagsGateApplicationWrites(t *testing.T) {
	server := New(t)
	invalid := request(t, server, http.MethodPost, "/accounts/account-1/access/tags", AccessTag{Name: "managed-by=flareway"})
	defer func() {
		if err := invalid.Body.Close(); err != nil {
			t.Errorf("close invalid tag response: %v", err)
		}
	}()
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid Access tag returned %d", invalid.StatusCode)
	}

	overlong := request(t, server, http.MethodPost, "/accounts/account-1/access/tags", AccessTag{Name: strings.Repeat("a", accessTagNameMaxLength+1)})
	if overlong.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong Access tag returned %d", overlong.StatusCode)
	}
	if err := overlong.Body.Close(); err != nil {
		t.Errorf("close overlong tag response: %v", err)
	}

	var managed AccessTag
	requestResult(t, server, http.MethodPost, "/accounts/account-1/access/tags", AccessTag{Name: "flareway-managed"}, &managed)
	if managed.Name != "flareway-managed" {
		t.Fatalf("created Access tag = %#v", managed)
	}
	var fetched AccessTag
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/tags/flareway-managed", nil, &fetched)
	if fetched != managed {
		t.Fatalf("fetched Access tag = %#v, want %#v", fetched, managed)
	}

	missing := request(t, server, http.MethodPost, "/accounts/account-1/access/apps", AccessResource{
		"name": "missing-tag", "type": "self_hosted", "domain": "missing.example.com",
		"tags": []string{"flareway-managed", "customer-existing"},
	})
	defer func() {
		if err := missing.Body.Close(); err != nil {
			t.Errorf("close missing tag response: %v", err)
		}
	}()
	if missing.StatusCode != http.StatusBadRequest {
		t.Fatalf("application with unregistered tag returned %d", missing.StatusCode)
	}

	requestResult[AccessTag](t, server, http.MethodPost, "/accounts/account-1/access/tags", AccessTag{Name: "customer-existing"}, nil)
	var application AccessResource
	requestResult(t, server, http.MethodPost, "/accounts/account-1/access/apps", AccessResource{
		"name": "registered-tags", "type": "self_hosted", "domain": "registered.example.com",
		"tags": []string{"flareway-managed", "customer-existing"},
	}, &application)

	inUse := request(t, server, http.MethodDelete, "/accounts/account-1/access/tags/flareway-managed", nil)
	defer func() {
		if err := inUse.Body.Close(); err != nil {
			t.Errorf("close in-use tag response: %v", err)
		}
	}()
	if inUse.StatusCode != http.StatusConflict {
		t.Fatalf("deleting assigned Access tag returned %d", inUse.StatusCode)
	}

	requestResult[map[string]string](t, server, http.MethodDelete, "/accounts/account-1/access/apps/"+application["id"].(string), nil, nil)
	requestResult[map[string]string](t, server, http.MethodDelete, "/accounts/account-1/access/tags/flareway-managed", nil, nil)
	if got := server.State.AccessTags("account-1"); len(got) != 1 || got[0].Name != "customer-existing" {
		t.Fatalf("remaining Access tags = %#v", got)
	}
}

func TestAccessTagsListIsAccountScopedAndPaginated(t *testing.T) {
	server := New(t)
	for _, name := range []string{"beta-tag", "alpha-tag", "gamma-tag"} {
		requestResult[AccessTag](t, server, http.MethodPost, "/accounts/account-1/access/tags", AccessTag{Name: name}, nil)
	}
	requestResult[AccessTag](t, server, http.MethodPost, "/accounts/account-2/access/tags", AccessTag{Name: "other-account"}, nil)

	var all []AccessTag
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/tags", nil, &all)
	if len(all) != 3 || all[0].Name != "alpha-tag" || all[1].Name != "beta-tag" || all[2].Name != "gamma-tag" {
		t.Fatalf("listed Access tags = %#v", all)
	}

	var page []AccessTag
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/tags?page=2&per_page=2", nil, &page)
	if len(page) != 1 || page[0].Name != "gamma-tag" {
		t.Fatalf("second Access tag page = %#v", page)
	}
}

func TestAccessResourcesCRUDAndFaults(t *testing.T) {
	server := New(t)

	resources := []struct {
		label      string
		collection string
		body       AccessResource
		state      func() []AccessResource
	}{
		{
			label: "group", collection: "/accounts/account-1/access/groups",
			body:  AccessResource{"name": "developers", "include": []any{map[string]any{"email_domain": map[string]any{"domain": "example.com"}}}},
			state: func() []AccessResource { return server.State.AccessGroups("accounts/account-1") },
		},
		{
			label: "identity provider", collection: "/accounts/account-1/access/identity_providers",
			body:  AccessResource{"identity_provider": map[string]any{"name": "Google", "type": "google", "config": map[string]any{"client_id": "id"}}},
			state: func() []AccessResource { return server.State.IdentityProviders("accounts/account-1") },
		},
		{
			label: "posture rule", collection: "/accounts/account-1/devices/posture",
			body:  AccessResource{"name": "WARP", "type": "warp", "input": map[string]any{}, "match": []any{}},
			state: func() []AccessResource { return server.State.DevicePostureRules("account-1") },
		},
	}

	for _, test := range resources {
		t.Run(test.label, func(t *testing.T) {
			var created AccessResource
			requestResult(t, server, http.MethodPost, test.collection, test.body, &created)
			id, _ := created["id"].(string)
			if id == "" {
				t.Fatalf("created resource has no ID: %#v", created)
			}
			var fetched AccessResource
			requestResult(t, server, http.MethodGet, test.collection+"/"+id, nil, &fetched)
			if fetched["id"] != id {
				t.Fatalf("fetched resource = %#v", fetched)
			}
			if got := test.state(); len(got) != 1 || got[0]["id"] != id {
				t.Fatalf("persisted resources = %#v", got)
			}
			requestResult[map[string]string](t, server, http.MethodDelete, test.collection+"/"+id, nil, nil)
			if got := test.state(); len(got) != 0 {
				t.Fatalf("resources after delete = %#v", got)
			}
		})
	}

	server.Fault(http.MethodGet, `^/accounts/account-1/access/groups$`, Fault{Status: http.StatusTooManyRequests, Times: 1})
	response := request(t, server, http.MethodGet, "/accounts/account-1/access/groups", nil)
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "1" {
		t.Fatalf("fault response status=%d retry-after=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}
}

func TestAccessServiceTokenSecretsAreOneTimeAndRotationIsStateful(t *testing.T) {
	server := New(t)
	var created AccessResource
	requestResult(t, server, http.MethodPost, "/accounts/account-1/access/service_tokens", AccessResource{
		"name": "e2e", "duration": "24h",
	}, &created)
	id := created["id"].(string)
	firstSecret := created["client_secret"].(string)
	if firstSecret == "" {
		t.Fatal("service-token create did not return its one-time secret")
	}

	var fetched map[string]any
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/service_tokens/"+id, nil, &fetched)
	if _, leaked := fetched["client_secret"]; leaked {
		t.Fatalf("service-token get leaked client_secret: %#v", fetched)
	}
	var listed []map[string]any
	requestResult(t, server, http.MethodGet, "/accounts/account-1/access/service_tokens?page=1&per_page=1", nil, &listed)
	if len(listed) != 1 {
		t.Fatalf("listed service tokens = %#v", listed)
	}
	if _, leaked := listed[0]["client_secret"]; leaked {
		t.Fatalf("service-token list leaked client_secret: %#v", listed)
	}

	previousExpiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var rotated AccessResource
	requestResult(t, server, http.MethodPost, "/accounts/account-1/access/service_tokens/"+id+"/rotate", AccessResource{
		"previous_client_secret_expires_at": previousExpiresAt.Format(time.RFC3339),
	}, &rotated)
	secondSecret := rotated["client_secret"].(string)
	if secondSecret == "" || secondSecret == firstSecret {
		t.Fatalf("rotated service-token secret present=%t changed=%t", secondSecret != "", secondSecret != firstSecret)
	}

	beforeRefresh := parsedTime(t, fetched["expires_at"])
	var refreshed map[string]any
	time.Sleep(time.Millisecond)
	requestResult(t, server, http.MethodPost, "/accounts/account-1/access/service_tokens/"+id+"/refresh", AccessResource{}, &refreshed)
	if _, leaked := refreshed["client_secret"]; leaked {
		t.Fatalf("service-token refresh leaked client_secret: %#v", refreshed)
	}
	if !parsedTime(t, refreshed["expires_at"]).After(beforeRefresh) {
		t.Fatalf("refresh did not extend expiry: before=%s after=%v", beforeRefresh, refreshed["expires_at"])
	}

	persisted := server.State.AccessServiceTokens("accounts/account-1")
	if len(persisted) != 1 || persisted[0].ID != id {
		t.Fatalf("persisted service tokens = %#v", persisted)
	}
	encoded, err := json.Marshal(persisted[0])
	if err != nil {
		t.Fatalf("marshal persisted service token: %v", err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("public service-token state exposed a secret: %s", encoded)
	}
}

func parsedTime(t *testing.T, value any) time.Time {
	t.Helper()
	text, ok := value.(string)
	if !ok {
		t.Fatalf("timestamp has type %T, want string", value)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatalf("parse timestamp %q: %v", text, err)
	}
	return parsed
}
