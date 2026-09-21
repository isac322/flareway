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
	"reflect"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/api/resource"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/test/cfstub"
)

func TestAccessRulesToSDKMapsEveryTypedRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, key string
		rule      ResolvedAccessRule
	}{
		{"email", "email", ResolvedAccessRule{Kind: "email", Value: "user@example.com"}},
		{"email domain", "email_domain", ResolvedAccessRule{Kind: "emailDomain", Value: "example.com"}},
		{"email list", "email_list", ResolvedAccessRule{Kind: "emailList", ID: "list"}},
		{"everyone", "everyone", ResolvedAccessRule{Kind: "everyone"}},
		{"ip", "ip", ResolvedAccessRule{Kind: "ip", Value: "192.0.2.0/24"}},
		{"ip list", "ip_list", ResolvedAccessRule{Kind: "ipList", ID: "list"}},
		{"certificate", "certificate", ResolvedAccessRule{Kind: "certificate"}},
		{"common name", "common_name", ResolvedAccessRule{Kind: "commonName", Value: "device.example"}},
		{"group", "group", ResolvedAccessRule{Kind: "group", ID: "group"}},
		{"azure ad", "azureAD", ResolvedAccessRule{Kind: "azureAD", ID: "group", IdentityProviderID: "idp"}},
		{"github organization", "github-organization", ResolvedAccessRule{Kind: "githubOrganization", Value: "org", Value2: "team", IdentityProviderID: "idp"}},
		{"gsuite", "gsuite", ResolvedAccessRule{Kind: "gsuite", Value: "group@example.com", IdentityProviderID: "idp"}},
		{"okta", "okta", ResolvedAccessRule{Kind: "okta", Value: "group", IdentityProviderID: "idp"}},
		{"saml", "saml", ResolvedAccessRule{Kind: "saml", Value: "role", Value2: "admin", IdentityProviderID: "idp"}},
		{"oidc", "oidc", ResolvedAccessRule{Kind: "oidc", Value: "groups", Value2: "admin", IdentityProviderID: "idp"}},
		{"service token", "service_token", ResolvedAccessRule{Kind: "serviceToken", ID: "token"}},
		{"any service token", "any_valid_service_token", ResolvedAccessRule{Kind: "anyValidServiceToken"}},
		{"external evaluation", "external_evaluation", ResolvedAccessRule{Kind: "externalEvaluation", Value: "https://example.com/eval", Value2: "https://example.com/keys"}},
		{"geo", "geo", ResolvedAccessRule{Kind: "geo", Value: "US"}},
		{"auth method", "auth_method", ResolvedAccessRule{Kind: "authMethod", Value: "hwk"}},
		{"device posture", "device_posture", ResolvedAccessRule{Kind: "devicePosture", ID: "posture", AccountID: "account"}},
		{"login method", "login_method", ResolvedAccessRule{Kind: "loginMethod", IdentityProviderID: "idp"}},
		{"auth context", "auth_context", ResolvedAccessRule{Kind: "authContext", Value: "ctx", Value2: "acid", IdentityProviderID: "idp"}},
		{"linked app", "linked_app_token", ResolvedAccessRule{Kind: "linkedAppToken", ID: "app"}},
		{"risk score", "user_risk_score", ResolvedAccessRule{Kind: "userRiskScore", Values: []string{"low", "medium"}}},
		{"account member", "cloudflare_account_member", ResolvedAccessRule{Kind: "cloudflareAccountMember", AccountID: "account"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules, err := AccessRulesToSDK([]ResolvedAccessRule{test.rule})
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(rules[0])
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatal(err)
			}
			if len(object) != 1 {
				t.Fatalf("got keys %v, want exactly one", reflect.ValueOf(object).MapKeys())
			}
			if _, ok := object[test.key]; !ok {
				t.Fatalf("got %s, want top-level key %q", data, test.key)
			}
		})
	}
}

func TestIdentityProviderBodyUsesTypedSDKUnions(t *testing.T) {
	t.Parallel()
	types := []v1alpha1.IdentityProviderType{
		v1alpha1.IdentityProviderTypeOneTimePIN,
		v1alpha1.IdentityProviderTypeAzureAD,
		v1alpha1.IdentityProviderTypeSAML,
		v1alpha1.IdentityProviderTypeCentrify,
		v1alpha1.IdentityProviderTypeFacebook,
		v1alpha1.IdentityProviderTypeGitHub,
		v1alpha1.IdentityProviderTypeGoogleApps,
		v1alpha1.IdentityProviderTypeGoogle,
		v1alpha1.IdentityProviderTypeLinkedIn,
		v1alpha1.IdentityProviderTypeOIDC,
		v1alpha1.IdentityProviderTypeOkta,
		v1alpha1.IdentityProviderTypeOneLogin,
		v1alpha1.IdentityProviderTypePingOne,
		v1alpha1.IdentityProviderTypeYandex,
		v1alpha1.IdentityProviderTypeCloudflare,
	}
	for _, providerType := range types {
		body, err := identityProviderBody(IdentityProviderInput{Name: "provider", Type: providerType, ClientSecret: "secret"})
		if err != nil {
			t.Fatalf("%s: %v", providerType, err)
		}
		if reflect.TypeOf(body).Name() == "IdentityProviderParam" {
			t.Fatalf("%s used untyped SDK fallback", providerType)
		}
	}
}

func TestDevicePostureInputUsesQuantityStringJSON(t *testing.T) {
	t.Parallel()
	score := resource.MustParse("42.5")
	apiData, err := json.Marshal(v1alpha1.DevicePostureInput{Score: &score})
	if err != nil {
		t.Fatal(err)
	}
	var apiObject map[string]any
	if err := json.Unmarshal(apiData, &apiObject); err != nil {
		t.Fatal(err)
	}
	apiScore, ok := apiObject["score"].(string)
	if !ok {
		t.Fatalf("API score = %#v, want Kubernetes quantity JSON string", apiObject["score"])
	}
	storedScore, err := resource.ParseQuantity(apiScore)
	if err != nil {
		t.Fatalf("parse API score %q as Kubernetes quantity: %v", apiScore, err)
	}
	if storedScore.Cmp(score) != 0 {
		t.Fatalf("API score = %q, want quantity equivalent to %s", apiScore, score.String())
	}
}

func TestDeviceInputUsesTypedNumericScoreAndWARPEnum(t *testing.T) {
	t.Parallel()
	score := resource.MustParse("42.5")
	body, present, err := deviceInput(
		v1alpha1.DevicePostureRuleTypeCustomS2S,
		v1alpha1.DevicePostureInput{Score: &score, Operator: v1alpha1.DevicePostureOperatorEqual},
		"integration-id",
	)
	if err != nil || !present {
		t.Fatalf("deviceInput() present = %v, err = %v", present, err)
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if object["score"] != 42.5 {
		t.Fatalf("Cloudflare wire score = %#v, want numeric JSON value 42.5", object["score"])
	}
	if _, present, err := deviceInput(v1alpha1.DevicePostureRuleTypeWARP, v1alpha1.DevicePostureInput{}, ""); err != nil || present {
		t.Fatalf("WARP deviceInput() present = %v, err = %v", present, err)
	}
}

func TestDeviceInputConvertsPostureQuantitiesAtWireBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ruleType v1alpha1.DevicePostureRuleType
		input    v1alpha1.DevicePostureInput
		wireKey  string
		want     float64
	}{
		{name: "total score", ruleType: v1alpha1.DevicePostureRuleTypeTanium, input: v1alpha1.DevicePostureInput{TotalScore: devicePostureTestQuantity("90.25")}, wireKey: "total_score", want: 90.25},
		{name: "active threats", ruleType: v1alpha1.DevicePostureRuleTypeSentinelOneS2S, input: v1alpha1.DevicePostureInput{ActiveThreats: devicePostureTestQuantity("1.5")}, wireKey: "active_threats", want: 1.5},
		{name: "update window", ruleType: v1alpha1.DevicePostureRuleTypeAntivirus, input: v1alpha1.DevicePostureInput{UpdateWindowDays: devicePostureTestQuantity("7.25")}, wireKey: "update_window_days", want: 7.25},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, present, err := deviceInput(test.ruleType, test.input, "integration-id")
			if err != nil || !present {
				t.Fatalf("deviceInput() present = %v, err = %v", present, err)
			}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]any
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatal(err)
			}
			if object[test.wireKey] != test.want {
				t.Fatalf("%s = %#v, want %v", test.wireKey, object[test.wireKey], test.want)
			}
		})
	}
}

func devicePostureTestQuantity(value string) *resource.Quantity {
	quantity := resource.MustParse(value)
	return &quantity
}

func TestDevicePostureQuantityCloudflareRoundTrip(t *testing.T) {
	t.Parallel()
	for _, decimal := range []string{"0.1", "42.125", "99.999999"} {
		t.Run(decimal, func(t *testing.T) {
			quantity := resource.MustParse(decimal)
			wire, err := devicePostureQuantityToFloat64("score", &quantity)
			if err != nil {
				t.Fatalf("to Cloudflare number: %v", err)
			}
			roundTripped := devicePostureQuantityFromFloat64(&wire)
			if roundTripped == nil || roundTripped.Cmp(quantity) != 0 {
				t.Fatalf("round trip = %v, want %s", roundTripped, decimal)
			}
		})
	}
}

func TestAccessApplicationBodiesUseEverySDKUnion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		applicationType AccessApplicationType
		bodyName        string
	}{
		{AccessApplicationTypeSelfHosted, "SelfHostedApplication"},
		{AccessApplicationTypeSaaS, "SaaSApplication"},
		{AccessApplicationTypeSSH, "BrowserSSHApplication"},
		{AccessApplicationTypeVNC, "BrowserVNCApplication"},
		{AccessApplicationTypeRDP, "BrowserRDPApplication"},
		{AccessApplicationTypeMCP, "McpServerApplication"},
		{AccessApplicationTypeProxyEndpoint, "GatewayIdentityProxyEndpointApplication"},
		{AccessApplicationTypeBookmark, "BookmarkApplication"},
		{AccessApplicationTypeInfrastructure, "InfrastructureApplication"},
		{AccessApplicationTypeAppLauncher, "AppLauncherApplication"},
		{AccessApplicationTypeWARP, "DeviceEnrollmentPermissionsApplication"},
		{AccessApplicationTypeBISO, "BrowserIsolationPermissionsApplication"},
		{AccessApplicationTypeDashSSO, "GatewayIdentityProxyEndpointApplication"},
		{AccessApplicationTypeMCPPortal, "McpServerPortalApplication"},
	}
	for _, test := range tests {
		t.Run(string(test.applicationType), func(t *testing.T) {
			input := AccessApplicationInput{
				Type:   test.applicationType,
				Domain: "ExactCase.Example.COM/Path",
				TargetCriteria: []AccessApplicationTargetCriterion{{
					Port: 22, Protocol: AccessApplicationTargetProtocolSSH,
					TargetAttributes: map[string][]string{"hostname": {"host"}},
				}},
			}
			newBody, err := accessApplicationNewBody(input)
			if err != nil {
				t.Fatal(err)
			}
			if got := reflect.TypeOf(newBody).Name(); got != "AccessApplicationNewParamsBody"+test.bodyName {
				t.Fatalf("new body type = %s", got)
			}
			updateBody, err := accessApplicationUpdateBody(input)
			if err != nil {
				t.Fatal(err)
			}
			if got := reflect.TypeOf(updateBody).Name(); got != "AccessApplicationUpdateParamsBody"+test.bodyName {
				t.Fatalf("update body type = %s", got)
			}
		})
	}
}

func TestAccessApplicationRequestValuesOmitEmptyAndTranslateEnums(t *testing.T) {
	t.Parallel()
	disabled := false
	values, err := accessApplicationRequestValues(AccessApplicationInput{
		AllowIframe:             &disabled,
		Type:                    AccessApplicationTypeSelfHosted,
		SameSiteCookieAttribute: v1alpha1.AccessSameSiteCookieStrict,
		Destinations: []AccessApplicationDestination{{
			Type: AccessApplicationDestinationTypePrivate, Hostname: "ExactCase.Example.COM",
			L4Protocol: AccessApplicationL4ProtocolUDP,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if values["allow_iframe"] != false {
		t.Fatalf("allow_iframe = %#v", values["allow_iframe"])
	}
	if values["same_site_cookie_attribute"] != "strict" {
		t.Fatalf("same_site_cookie_attribute = %#v", values["same_site_cookie_attribute"])
	}
	destinations := values["destinations"].([]map[string]any)
	if destinations[0]["type"] != "private" || destinations[0]["l4_protocol"] != "udp" || destinations[0]["hostname"] != "ExactCase.Example.COM" {
		t.Fatalf("destination = %#v", destinations[0])
	}
	for _, key := range []string{"name", "session_duration", "allowed_idps", "custom_pages", "tags", "logo_url"} {
		if _, found := values[key]; found {
			t.Fatalf("optional empty field %q was serialized", key)
		}
	}
}

func TestWARPApplicationRequestAndDriftIgnoreName(t *testing.T) {
	t.Parallel()
	input := AccessApplicationInput{
		Type:            AccessApplicationTypeWARP,
		Name:            "controller-only-name",
		SessionDuration: "24h",
		CustomDenyURL:   "https://deny.example.test",
	}
	values, err := accessApplicationRequestValues(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := values["name"]; found {
		t.Fatalf("WARP request serialized unsupported name: %#v", values["name"])
	}
	if values["session_duration"] != "24h" || values["custom_deny_url"] != "https://deny.example.test" {
		t.Fatalf("WARP request lost official fields: %#v", values)
	}
	observed := AccessApplication{
		Type:            AccessApplicationTypeWARP,
		Name:            "cloudflare-observed-name",
		SessionDuration: "24h",
		CustomDenyURL:   "https://deny.example.test",
	}
	if !AccessApplicationMatchesInput(observed, input) {
		t.Fatal("WARP response name reported false drift")
	}
}

func TestAccessApplicationClientRoutesScopesCapturesSaaSSecretAndRevokes(t *testing.T) {
	server := cfstub.New(t)
	client := New("top-secret", "account-1", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()

	accountResult, err := client.CreateAccessApplication(ctx, AccessScope{}, AccessApplicationInput{
		Type: AccessApplicationTypeSelfHosted, Name: "account-app", Domain: "ExactCase.Example.COM/Path",
	})
	if err != nil {
		t.Fatal(err)
	}
	storedAccount := server.State.AccessApplications("accounts/account-1")
	if len(storedAccount) != 1 || storedAccount[0]["type"] != "self_hosted" || storedAccount[0]["domain"] != "ExactCase.Example.COM/Path" {
		t.Fatalf("stored account request = %#v", storedAccount)
	}
	for _, key := range []string{"allowed_idps", "session_duration", "custom_pages", "tags", "logo_url"} {
		if _, found := storedAccount[0][key]; found {
			t.Fatalf("wire request included optional empty field %q", key)
		}
	}
	if accountResult.Application.Domain != "ExactCase.Example.COM/Path" {
		t.Fatalf("domain = %q", accountResult.Application.Domain)
	}

	zoneResult, err := client.CreateAccessApplication(ctx, AccessScope{ZoneID: "zone-1"}, AccessApplicationInput{
		Type: AccessApplicationTypeSaaS, Name: "zone-app",
		SaaSApp: &AccessSaaSApplicationInput{AuthType: AccessSaaSAuthenticationTypeOIDC, ClientID: "client-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if zoneResult.SaaSClientSecret == "" {
		t.Fatal("SaaS client secret was not returned from create")
	}
	if zoneResult.Application.SaaSApp == nil || zoneResult.Application.SaaSApp.ClientID != "client-id" {
		t.Fatalf("created SaaS application = %#v", zoneResult.Application)
	}
	storedZone := server.State.AccessApplications("zones/zone-1")
	if len(storedZone) != 1 || storedZone[0]["type"] != "saas" {
		t.Fatalf("stored zone request = %#v", storedZone)
	}
	storedSaaS, _ := storedZone[0]["saas_app"].(map[string]any)
	if storedSaaS["auth_type"] != "oidc" {
		t.Fatalf("stored SaaS request = %#v", storedSaaS)
	}
	if _, found := storedSaaS["client_secret"]; found {
		t.Fatal("stub persisted a one-time SaaS client secret")
	}

	accountApplications, err := client.ListAccessApplications(ctx, AccessScope{})
	if err != nil || len(accountApplications) != 1 || accountApplications[0].ID != accountResult.Application.ID {
		t.Fatalf("account list = %#v, %v", accountApplications, err)
	}
	zoneApplications, err := client.ListAccessApplications(ctx, AccessScope{ZoneID: "zone-1"})
	if err != nil || len(zoneApplications) != 1 || zoneApplications[0].ID != zoneResult.Application.ID {
		t.Fatalf("zone list = %#v, %v", zoneApplications, err)
	}
	observed, err := client.GetAccessApplication(ctx, AccessScope{ZoneID: "zone-1"}, zoneResult.Application.ID)
	if err != nil || observed.Name != "zone-app" {
		t.Fatalf("zone get = %#v, %v", observed, err)
	}
	updated, err := client.UpdateAccessApplication(ctx, AccessScope{ZoneID: "zone-1"}, observed.ID, AccessApplicationInput{
		Type: AccessApplicationTypeSaaS, Name: "zone-app-updated",
		SaaSApp: &AccessSaaSApplicationInput{AuthType: AccessSaaSAuthenticationTypeOIDC, ClientID: "client-id"},
	})
	if err != nil || updated.Name != "zone-app-updated" {
		t.Fatalf("zone update = %#v, %v", updated, err)
	}
	if err := client.RevokeAccessApplicationTokens(ctx, AccessScope{ZoneID: "zone-1"}, observed.ID); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteAccessApplication(ctx, AccessScope{ZoneID: "zone-1"}, observed.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAccessApplicationPrivateOnlyOmitsDomainOnTheWire(t *testing.T) {
	server := cfstub.New(t)
	client := New("top-secret", "account-1", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()

	privateDestinations := []AccessApplicationDestination{{
		Type: AccessApplicationDestinationTypePrivate, Hostname: "db.internal.example",
		PortRange: "5432", L4Protocol: AccessApplicationL4ProtocolTCP, VNetID: "vnet-1",
	}}
	created, err := client.CreateAccessApplication(ctx, AccessScope{}, AccessApplicationInput{
		Type: AccessApplicationTypeSelfHosted, Name: "private-app", Destinations: privateDestinations,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := server.State.AccessApplications("accounts/account-1")
	if len(stored) != 1 {
		t.Fatalf("stored applications = %#v", stored)
	}
	if domain, found := stored[0]["domain"]; found {
		t.Fatalf("private-only create sent domain %#v", domain)
	}
	destinations, _ := stored[0]["destinations"].([]any)
	if len(destinations) != 1 {
		t.Fatalf("private-only create stored destinations = %#v", stored[0]["destinations"])
	}

	if _, err := client.UpdateAccessApplication(ctx, AccessScope{}, created.Application.ID, AccessApplicationInput{
		Type: AccessApplicationTypeSelfHosted, Name: "private-app", Destinations: privateDestinations,
	}); err != nil {
		t.Fatal(err)
	}
	stored = server.State.AccessApplications("accounts/account-1")
	if domain, found := stored[0]["domain"]; found {
		t.Fatalf("private-only update sent domain %#v", domain)
	}

	mixed, err := client.CreateAccessApplication(ctx, AccessScope{}, AccessApplicationInput{
		Type: AccessApplicationTypeSelfHosted, Name: "mixed-app", Domain: "app.example.test",
		Destinations: append(slices.Clone(privateDestinations), AccessApplicationDestination{
			Type: AccessApplicationDestinationTypePublic, URI: "app.example.test",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	stored = server.State.AccessApplications("accounts/account-1")
	if len(stored) != 2 || stored[1]["id"] != mixed.Application.ID {
		t.Fatalf("stored applications = %#v", stored)
	}
	if stored[1]["domain"] != "app.example.test" {
		t.Fatalf("mixed create lost domain: %#v", stored[1])
	}
}

func TestAccessApplicationMatchesInputIgnoresSecretsAndResponseMetadata(t *testing.T) {
	t.Parallel()
	input := AccessApplicationInput{
		Type:        AccessApplicationTypeSaaS,
		Name:        "saas",
		AllowedIDPs: []string{"idp-b", "idp-a"},
		Tags:        []string{"tag-z", "tag-a"},
		SaaSApp: &AccessSaaSApplicationInput{
			AuthType: AccessSaaSAuthenticationTypeOIDC, ClientID: "client-id", ClientSecret: "write-only",
			GrantTypes:   []AccessSaaSOIDCGrantType{AccessSaaSOIDCGrantTypeHybrid, AccessSaaSOIDCGrantTypeAuthorizationCode},
			RedirectURIs: []string{"https://b.example/callback", "https://a.example/callback"},
			Scopes:       []AccessSaaSOIDCScope{AccessSaaSOIDCScopeProfile, AccessSaaSOIDCScopeOpenID},
		},
	}
	observed := AccessApplication{
		ID: "app-id", AUD: "audience", Type: AccessApplicationTypeSaaS, Name: "saas",
		AllowedIDPs: []string{"idp-a", "idp-b"},
		Tags:        []string{"tag-a", "tag-z"},
		SaaSApp: &AccessSaaSApplication{
			AuthType: AccessSaaSAuthenticationTypeOIDC, ClientID: "client-id",
			GrantTypes:   []AccessSaaSOIDCGrantType{AccessSaaSOIDCGrantTypeAuthorizationCode, AccessSaaSOIDCGrantTypeHybrid},
			RedirectURIs: []string{"https://a.example/callback", "https://b.example/callback"},
			Scopes:       []AccessSaaSOIDCScope{AccessSaaSOIDCScopeOpenID, AccessSaaSOIDCScopeProfile},
		},
	}
	if !AccessApplicationMatchesInput(observed, input) {
		t.Fatal("matching application reported drift")
	}
	mfaInput := AccessApplicationInput{
		Type: AccessApplicationTypeSelfHosted, Domain: "app.example.com",
		MFAConfig: &AccessApplicationMFAConfig{AllowedAuthenticators: []AccessApplicationMFAAuthenticator{
			AccessApplicationMFAAuthenticatorSecurityKey, AccessApplicationMFAAuthenticatorTOTP,
		}},
	}
	mfaObserved := AccessApplication{
		Type: AccessApplicationTypeSelfHosted, Domain: "app.example.com",
		MFAConfig: &AccessApplicationMFAConfig{AllowedAuthenticators: []AccessApplicationMFAAuthenticator{
			AccessApplicationMFAAuthenticatorTOTP, AccessApplicationMFAAuthenticatorSecurityKey,
		}},
	}
	if !AccessApplicationMatchesInput(mfaObserved, mfaInput) {
		t.Fatal("reordered MFA authenticator set reported drift")
	}
	observed.Name = "different"
	if AccessApplicationMatchesInput(observed, input) {
		t.Fatal("different mutable field did not report drift")
	}
}
