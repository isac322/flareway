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
	"encoding/json"
	"reflect"
	"testing"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
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
	types := []v1alpha1.IdentityProviderType{"onetimepin", "azureAD", "saml", "centrify", "facebook", "github", "google-apps", "google", "linkedin", "oidc", "okta", "onelogin", "pingone", "yandex", "cloudflare"}
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

func TestDeviceInputRejectsInvalidNumericValue(t *testing.T) {
	t.Parallel()
	if _, err := deviceInput(v1alpha1.DevicePostureInput{Score: "not-a-number"}); err == nil {
		t.Fatal("expected invalid score to fail")
	}
}
