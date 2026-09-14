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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
)

func TestOrganizationAdapterPreservesOptionalFields(t *testing.T) {
	var updateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPut {
			_ = json.NewDecoder(request.Body).Decode(&updateBody)
		}
		if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"auth_domain":"team.cloudflareaccess.com","name":"team","session_duration":"24h","warp_auth_session_duration":"720h","allow_authenticate_via_warp":false,"is_ui_read_only":true,"deny_unmatched_requests":false,"warp_auth_non_browser_401":true}}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	observed, err := client.GetOrganization(context.Background())
	if err != nil || observed.AuthDomain != "team.cloudflareaccess.com" || observed.WARPAuthSessionDuration != "720h" {
		t.Fatalf("GetOrganization() = %#v, %v", observed, err)
	}
	falseValue := false
	updated, err := client.UpdateOrganization(context.Background(), OrganizationInput{AllowAuthenticateViaWARP: &falseValue})
	if err != nil || updated.AllowAuthenticateViaWARP {
		t.Fatalf("UpdateOrganization() = %#v, %v", updated, err)
	}
	assertJSONKeys(t, updateBody, map[string]any{"allow_authenticate_via_warp": false}, []string{"session_duration", "warp_auth_session_duration", "is_ui_read_only", "deny_unmatched_requests", "warp_auth_non_browser_401"})
}
