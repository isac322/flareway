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

const organizationResponseJSON = `{"success":true,"errors":[],"messages":[],"result":{"auth_domain":"team.cloudflareaccess.com","name":"team","session_duration":"24h","warp_auth_session_duration":"720h","allow_authenticate_via_warp":false,"auto_redirect_to_identity":true,"is_ui_read_only":true,"ui_read_only_toggle_reason":"managed by flareway","deny_unmatched_requests":true,"deny_unmatched_requests_exempted_zone_names":["b.example","a.example"],"warp_auth_non_browser_401":true,"user_seat_expiration_inactive_time":"730h","custom_pages":{"forbidden":"page-forbidden","identity_denied":"page-identity"},"login_design":{"background_color":"#000000","footer_text":"footer","header_text":"header","logo_path":"https://example.com/logo.svg","text_color":"#ffffff"},"mfa_config":{"allowed_authenticators":["totp","security_key"],"amr_matching_session_duration":"12h","required_aaguids":"00000000-0000-0000-0000-000000000001","session_duration":"24h"},"mfa_piv_key_requirements":{"pin_policy":"once","require_fips_device":true,"ssh_key_size":[256,2048],"ssh_key_type":["ecdsa","rsa"],"touch_policy":"cached"},"mfa_required_for_all_apps":true}}`

func TestOrganizationAdapterRoundTripsAllMutableFieldsAtZoneScope(t *testing.T) {
	var updateBody map[string]any
	var updatePath string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		updatePath = request.URL.Path
		if request.Method == http.MethodPut {
			_ = json.NewDecoder(request.Body).Decode(&updateBody)
		}
		if _, err := fmt.Fprint(response, organizationResponseJSON); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	observed, err := client.GetAccessOrganization(context.Background(), AccessScope{ZoneID: "zone-1"})
	if err != nil || observed.AuthDomain != "team.cloudflareaccess.com" || observed.Name != "team" ||
		observed.SessionDuration != "24h" || observed.WARPAuthSessionDuration != "720h" ||
		observed.AllowAuthenticateViaWARP || !observed.AutoRedirectToIdentity || !observed.IsUIReadOnly ||
		observed.UIReadOnlyToggleReason != "managed by flareway" || !observed.DenyUnmatchedRequests ||
		fmt.Sprint(observed.DenyUnmatchedRequestsExemptedZoneNames) != "[b.example a.example]" ||
		!observed.WARPAuthNonBrowser401 || observed.UserSeatExpirationInactiveTime != "730h" ||
		observed.CustomPages.Forbidden != "page-forbidden" || observed.CustomPages.IdentityDenied != "page-identity" ||
		observed.LoginDesign.BackgroundColor != "#000000" || observed.LoginDesign.FooterText != "footer" ||
		observed.LoginDesign.HeaderText != "header" || observed.LoginDesign.LogoPath != "https://example.com/logo.svg" ||
		observed.LoginDesign.TextColor != "#ffffff" ||
		fmt.Sprint(observed.MFAConfig.AllowedAuthenticators) != "[Totp SecurityKey]" ||
		observed.MFAConfig.AMRMatchingSessionDuration != "12h" ||
		observed.MFAConfig.RequiredAAGUIDs != "00000000-0000-0000-0000-000000000001" ||
		observed.MFAConfig.SessionDuration != "24h" ||
		observed.MFAPIVKeyRequirements.PinPolicy != OrganizationPIVPinPolicyOnce ||
		!observed.MFAPIVKeyRequirements.RequireFIPSDevice ||
		fmt.Sprint(observed.MFAPIVKeyRequirements.SSHKeySizes) != "[256 2048]" ||
		fmt.Sprint(observed.MFAPIVKeyRequirements.SSHKeyTypes) != "[Ecdsa Rsa]" ||
		observed.MFAPIVKeyRequirements.TouchPolicy != OrganizationPIVTouchPolicyCached ||
		!observed.MFARequiredForAllApps {
		t.Fatalf("GetAccessOrganization() = %#v, %v", observed, err)
	}

	name, session, warp := "team", "24h", "720h"
	empty, inactive := "", "730h"
	truth, falseValue := true, false
	exempted := []string{}
	forbidden, identityDenied := "page-forbidden", ""
	background, footer, header, logo, textColor := "#000000", "footer", "header", "https://example.com/logo.svg", "#ffffff"
	authenticators := []OrganizationMFAAuthenticator{OrganizationMFAAuthenticatorTOTP, OrganizationMFAAuthenticatorSecurityKey}
	amr, aaguids, mfaSession := "12h", "00000000-0000-0000-0000-000000000001", "24h"
	pin, touch := OrganizationPIVPinPolicyOnce, OrganizationPIVTouchPolicyCached
	keySizes := []int64{256, 2048}
	keyTypes := []OrganizationPIVSSHKeyType{OrganizationPIVSSHKeyTypeECDSA, OrganizationPIVSSHKeyTypeRSA}
	updated, err := client.UpdateAccessOrganization(context.Background(), AccessScope{ZoneID: "zone-1"}, OrganizationInput{
		Name: &name, SessionDuration: &session, WARPAuthSessionDuration: &warp,
		AllowAuthenticateViaWARP: &falseValue, AutoRedirectToIdentity: &truth, IsUIReadOnly: &truth,
		UIReadOnlyToggleReason: &empty, DenyUnmatchedRequests: &truth, DenyUnmatchedRequestsExemptedZoneNames: &exempted,
		WARPAuthNonBrowser401: &truth, UserSeatExpirationInactiveTime: &inactive, MFARequiredForAllApps: &truth,
		CustomPages:           &OrganizationCustomPagesInput{Forbidden: &forbidden, IdentityDenied: &identityDenied},
		LoginDesign:           &OrganizationLoginDesignInput{BackgroundColor: &background, FooterText: &footer, HeaderText: &header, LogoPath: &logo, TextColor: &textColor},
		MFAConfig:             &OrganizationMFAConfigInput{AllowedAuthenticators: &authenticators, AMRMatchingSessionDuration: &amr, RequiredAAGUIDs: &aaguids, SessionDuration: &mfaSession},
		MFAPIVKeyRequirements: &OrganizationMFAPIVKeyRequirementsInput{PinPolicy: &pin, RequireFIPSDevice: &truth, SSHKeySizes: &keySizes, SSHKeyTypes: &keyTypes, TouchPolicy: &touch},
	})
	if err != nil || updated.Name != "team" {
		t.Fatalf("UpdateAccessOrganization() = %#v, %v", updated, err)
	}
	if updatePath != "/zones/zone-1/access/organizations" {
		t.Fatalf("update path = %q", updatePath)
	}
	assertJSONKeys(t, updateBody, map[string]any{
		"name": "team", "session_duration": "24h", "warp_auth_session_duration": "720h",
		"allow_authenticate_via_warp": false, "auto_redirect_to_identity": true,
		"is_ui_read_only": true, "ui_read_only_toggle_reason": nil,
		"deny_unmatched_requests": true, "deny_unmatched_requests_exempted_zone_names": []any{},
		"warp_auth_non_browser_401": true, "user_seat_expiration_inactive_time": "730h",
		"mfa_required_for_all_apps": true,
	}, []string{"auth_domain"})
	customPages := updateBody["custom_pages"].(map[string]any)
	if customPages["forbidden"] != "page-forbidden" || customPages["identity_denied"] != nil {
		t.Fatalf("custom_pages = %#v", customPages)
	}
	loginDesign := updateBody["login_design"].(map[string]any)
	if loginDesign["background_color"] != "#000000" || loginDesign["footer_text"] != "footer" ||
		loginDesign["header_text"] != "header" || loginDesign["logo_path"] != "https://example.com/logo.svg" ||
		loginDesign["text_color"] != "#ffffff" {
		t.Fatalf("login_design = %#v", loginDesign)
	}
	mfa := updateBody["mfa_config"].(map[string]any)
	if got := mfa["allowed_authenticators"]; fmt.Sprint(got) != "[totp security_key]" ||
		mfa["amr_matching_session_duration"] != "12h" ||
		mfa["required_aaguids"] != "00000000-0000-0000-0000-000000000001" ||
		mfa["session_duration"] != "24h" {
		t.Fatalf("mfa_config = %#v", mfa)
	}
	piv := updateBody["mfa_piv_key_requirements"].(map[string]any)
	if piv["pin_policy"] != "once" || piv["require_fips_device"] != true ||
		fmt.Sprint(piv["ssh_key_size"]) != "[256 2048]" ||
		fmt.Sprint(piv["ssh_key_type"]) != "[ecdsa rsa]" || piv["touch_policy"] != "cached" {
		t.Fatalf("mfa_piv_key_requirements = %#v", piv)
	}
}

func TestOrganizationAdapterCreatesWithoutUpdatingAuthDomain(t *testing.T) {
	var createBody, updateBody map[string]any
	var createPath, updatePath string
	var requestOrder []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		requestOrder = append(requestOrder, request.Method+" "+request.URL.Path)
		switch request.Method {
		case http.MethodPost:
			createPath = request.URL.Path
			_ = json.NewDecoder(request.Body).Decode(&createBody)
		case http.MethodPut:
			updatePath = request.URL.Path
			_ = json.NewDecoder(request.Body).Decode(&updateBody)
		}
		if _, err := fmt.Fprint(response, organizationResponseJSON); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	name, session, forbidden := "team", "24h", "page-forbidden"
	if _, err := client.CreateAccessOrganization(context.Background(), AccessScope{}, OrganizationCreateInput{
		AuthDomain: "team.cloudflareaccess.com",
		OrganizationInput: OrganizationInput{
			Name: &name, SessionDuration: &session,
			CustomPages: &OrganizationCustomPagesInput{Forbidden: &forbidden},
		},
	}); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, createBody, map[string]any{"auth_domain": "team.cloudflareaccess.com", "name": "team", "session_duration": "24h"}, []string{"custom_pages"})
	if createPath != "/accounts/account/access/organizations" || updatePath != "/accounts/account/access/organizations" {
		t.Fatalf("create/update paths = %q, %q", createPath, updatePath)
	}
	if len(requestOrder) != 2 ||
		requestOrder[0] != "POST /accounts/account/access/organizations" ||
		requestOrder[1] != "PUT /accounts/account/access/organizations" {
		t.Fatalf("create/update request order = %#v", requestOrder)
	}
	if _, exists := updateBody["auth_domain"]; exists {
		t.Fatalf("post-create update unexpectedly contained auth_domain: %#v", updateBody)
	}
	customPages := updateBody["custom_pages"].(map[string]any)
	if customPages["forbidden"] != forbidden || customPages["identity_denied"] != nil {
		t.Fatalf("post-create custom_pages = %#v", customPages)
	}
}

func TestOrganizationAdapterRevocationAndDOHAreAccountSafe(t *testing.T) {
	var zoneRevokeBody, accountRevokeBody, dohBody map[string]any
	var zoneRevokeQuery, accountRevokeQuery string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/zones/zone-1/access/organizations/revoke_user":
			zoneRevokeQuery = request.URL.RawQuery
			_ = json.NewDecoder(request.Body).Decode(&zoneRevokeBody)
			_, _ = fmt.Fprint(response, `{"success":true,"result":true}`)
		case "/accounts/account/access/organizations/revoke_user":
			accountRevokeQuery = request.URL.RawQuery
			_ = json.NewDecoder(request.Body).Decode(&accountRevokeBody)
			_, _ = fmt.Fprint(response, `{"success":true,"result":true}`)
		case "/accounts/account/access/organizations/doh":
			if request.Method == http.MethodPut {
				_ = json.NewDecoder(request.Body).Decode(&dohBody)
			}
			_, _ = fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"service-token-id","client_id":"non-secret-client-id","doh_jwt_duration":"12h","duration":"8760h","enabled":true,"expires_at":"2030-01-01T00:00:00Z","name":"doh"}}`)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
	}))
	t.Cleanup(server.Close)
	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	uid := "user-id"
	truth := true
	revoked, err := client.RevokeAccessOrganizationUser(context.Background(), AccessScope{ZoneID: "zone-1"}, OrganizationUserRevocationInput{Email: "user@example.com", UserUID: &uid, Devices: &truth, WARPSessionReauth: &truth})
	if err != nil || !revoked {
		t.Fatalf("zone RevokeAccessOrganizationUser() = %v, %v", revoked, err)
	}
	if zoneRevokeQuery != "devices=true" || zoneRevokeBody["email"] != "user@example.com" || zoneRevokeBody["devices"] != true || zoneRevokeBody["user_uid"] != "user-id" || zoneRevokeBody["warp_session_reauth"] != true {
		t.Fatalf("zone revoke request query=%q body=%#v", zoneRevokeQuery, zoneRevokeBody)
	}
	revoked, err = client.RevokeAccessOrganizationUser(context.Background(), AccessScope{}, OrganizationUserRevocationInput{Email: "account-user@example.com"})
	if err != nil || !revoked {
		t.Fatalf("account RevokeAccessOrganizationUser() = %v, %v", revoked, err)
	}
	if accountRevokeQuery != "" || accountRevokeBody["email"] != "account-user@example.com" {
		t.Fatalf("account revoke request query=%q body=%#v", accountRevokeQuery, accountRevokeBody)
	}
	jwtDuration := "12h"
	updated, err := client.UpdateAccessOrganizationDOH(context.Background(), OrganizationDOHInput{ServiceTokenID: "service-token-id", JWTDuration: &jwtDuration})
	if err != nil || updated.ServiceTokenID != "service-token-id" || updated.JWTDuration != "12h" {
		t.Fatalf("UpdateAccessOrganizationDOH() = %#v, %v", updated, err)
	}
	assertJSONKeys(t, dohBody, map[string]any{"service_token_id": "service-token-id", "doh_jwt_duration": "12h"}, nil)
	observed, err := client.GetAccessOrganizationDOH(context.Background())
	if err != nil || observed.ServiceTokenID != "service-token-id" || observed.JWTDuration != "12h" {
		t.Fatalf("GetAccessOrganizationDOH() = %#v, %v", observed, err)
	}
}
