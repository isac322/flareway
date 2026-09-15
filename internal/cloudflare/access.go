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
	"fmt"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// AccessAPI is the complete M3 Cloudflare Access surface.
type AccessAPI interface {
	AccessApplicationAPI
	AccessInfrastructureTargetAPI
	AccessCustomPageAPI
	AccessTagAPI
	AccessPolicyAPI
	AccessGroupAPI
	IdentityProviderAPI
	DevicePostureRuleAPI
	DevicePostureIntegrationAPI
	ServiceTokenAPI
}

// AccessScope selects the account endpoint by default or a zone endpoint when ZoneID is set.
type AccessScope struct {
	ZoneID string
}

func applyAccessScope(accountID string, scope AccessScope, setAccountID, setZoneID func(string)) {
	if scope.ZoneID != "" {
		setZoneID(scope.ZoneID)
		return
	}
	setAccountID(accountID)
}

func setAccessString(values map[string]any, key, value string) {
	if value != "" {
		values[key] = value
	}
}

func setAccessOptionalBool(values map[string]any, key string, value *bool) {
	if value != nil {
		values[key] = *value
	}
}

func setAccessSlice[T any](values map[string]any, key string, value []T) {
	if len(value) != 0 {
		values[key] = value
	}
}

// ResolvedAccessRule is part of the Flareway API.
type ResolvedAccessRule struct {
	Kind               string
	Value              string
	Value2             string
	Value3             string
	Values             []string
	ID                 string
	IdentityProviderID string
	AccountID          string
}

// AccessRulesToSDK converts every typed Flareway Access rule to cloudflare-go's typed union.
func AccessRulesToSDK(values []ResolvedAccessRule) ([]zero_trust.AccessRuleUnionParam, error) {
	out := make([]zero_trust.AccessRuleUnionParam, 0, len(values))
	for _, v := range values {
		var rule zero_trust.AccessRuleUnionParam
		switch v.Kind {
		case "email":
			rule = zero_trust.EmailRuleParam{Email: cloudflaresdk.F(zero_trust.EmailRuleEmailParam{Email: cloudflaresdk.F(v.Value)})}
		case "emailDomain":
			rule = zero_trust.DomainRuleParam{EmailDomain: cloudflaresdk.F(zero_trust.DomainRuleEmailDomainParam{Domain: cloudflaresdk.F(v.Value)})}
		case "emailList":
			rule = zero_trust.EmailListRuleParam{EmailList: cloudflaresdk.F(zero_trust.EmailListRuleEmailListParam{ID: cloudflaresdk.F(v.ID)})}
		case "everyone":
			rule = zero_trust.EveryoneRuleParam{Everyone: cloudflaresdk.F(zero_trust.EveryoneRuleEveryoneParam{})}
		case "ip":
			rule = zero_trust.IPRuleParam{IP: cloudflaresdk.F(zero_trust.IPRuleIPParam{IP: cloudflaresdk.F(v.Value)})}
		case "ipList":
			rule = zero_trust.IPListRuleParam{IPList: cloudflaresdk.F(zero_trust.IPListRuleIPListParam{ID: cloudflaresdk.F(v.ID)})}
		case "certificate":
			rule = zero_trust.CertificateRuleParam{Certificate: cloudflaresdk.F(zero_trust.CertificateRuleCertificateParam{})}
		case "commonName":
			rule = zero_trust.AccessRuleAccessCommonNameRuleParam{CommonName: cloudflaresdk.F(zero_trust.AccessRuleAccessCommonNameRuleCommonNameParam{CommonName: cloudflaresdk.F(v.Value)})}
		case "group":
			rule = zero_trust.GroupRuleParam{Group: cloudflaresdk.F(zero_trust.GroupRuleGroupParam{ID: cloudflaresdk.F(v.ID)})}
		case "azureAD":
			rule = zero_trust.AzureGroupRuleParam{AzureAD: cloudflaresdk.F(zero_trust.AzureGroupRuleAzureADParam{ID: cloudflaresdk.F(v.ID), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "githubOrganization":
			rule = zero_trust.GitHubOrganizationRuleParam{GitHubOrganization: cloudflaresdk.F(zero_trust.GitHubOrganizationRuleGitHubOrganizationParam{Name: cloudflaresdk.F(v.Value), Team: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "gsuite":
			rule = zero_trust.GSuiteGroupRuleParam{GSuite: cloudflaresdk.F(zero_trust.GSuiteGroupRuleGSuiteParam{Email: cloudflaresdk.F(v.Value), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "okta":
			rule = zero_trust.OktaGroupRuleParam{Okta: cloudflaresdk.F(zero_trust.OktaGroupRuleOktaParam{Name: cloudflaresdk.F(v.Value), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "saml":
			rule = zero_trust.SAMLGroupRuleParam{SAML: cloudflaresdk.F(zero_trust.SAMLGroupRuleSAMLParam{AttributeName: cloudflaresdk.F(v.Value), AttributeValue: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "oidc":
			rule = zero_trust.AccessRuleAccessOIDCClaimRuleParam{OIDC: cloudflaresdk.F(zero_trust.AccessRuleAccessOIDCClaimRuleOIDCParam{ClaimName: cloudflaresdk.F(v.Value), ClaimValue: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "serviceToken":
			rule = zero_trust.ServiceTokenRuleParam{ServiceToken: cloudflaresdk.F(zero_trust.ServiceTokenRuleServiceTokenParam{TokenID: cloudflaresdk.F(v.ID)})}
		case "anyValidServiceToken":
			rule = zero_trust.AnyValidServiceTokenRuleParam{AnyValidServiceToken: cloudflaresdk.F(zero_trust.AnyValidServiceTokenRuleAnyValidServiceTokenParam{})}
		case "externalEvaluation":
			rule = zero_trust.ExternalEvaluationRuleParam{ExternalEvaluation: cloudflaresdk.F(zero_trust.ExternalEvaluationRuleExternalEvaluationParam{EvaluateURL: cloudflaresdk.F(v.Value), KeysURL: cloudflaresdk.F(v.Value2)})}
		case "geo":
			rule = zero_trust.CountryRuleParam{Geo: cloudflaresdk.F(zero_trust.CountryRuleGeoParam{CountryCode: cloudflaresdk.F(v.Value)})}
		case "authMethod":
			rule = zero_trust.AuthenticationMethodRuleParam{AuthMethod: cloudflaresdk.F(zero_trust.AuthenticationMethodRuleAuthMethodParam{AuthMethod: cloudflaresdk.F(v.Value)})}
		case "devicePosture":
			rule = zero_trust.AccessDevicePostureRuleParam{DevicePosture: cloudflaresdk.F(zero_trust.AccessDevicePostureRuleDevicePostureParam{IntegrationUID: cloudflaresdk.F(v.ID), AccountID: cloudflaresdk.F(v.AccountID)})}
		case "loginMethod":
			rule = zero_trust.AccessRuleAccessLoginMethodRuleParam{LoginMethod: cloudflaresdk.F(zero_trust.AccessRuleAccessLoginMethodRuleLoginMethodParam{ID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "authContext":
			rule = zero_trust.AccessRuleAccessAuthContextRuleParam{AuthContext: cloudflaresdk.F(zero_trust.AccessRuleAccessAuthContextRuleAuthContextParam{ID: cloudflaresdk.F(v.Value), AcID: cloudflaresdk.F(v.Value2), IdentityProviderID: cloudflaresdk.F(v.IdentityProviderID)})}
		case "linkedAppToken":
			rule = zero_trust.AccessRuleAccessLinkedAppTokenRuleParam{LinkedAppToken: cloudflaresdk.F(zero_trust.AccessRuleAccessLinkedAppTokenRuleLinkedAppTokenParam{AppUID: cloudflaresdk.F(v.ID)})}
		case "userRiskScore":
			levels := make([]zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScore, len(v.Values))
			for i := range v.Values {
				levels[i] = zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScore(v.Values[i])
			}
			rule = zero_trust.AccessRuleAccessUserRiskScoreRuleParam{UserRiskScore: cloudflaresdk.F(zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreParam{UserRiskScore: cloudflaresdk.F(levels)})}
		case "cloudflareAccountMember":
			rule = zero_trust.AccessRuleAccessCloudflareAccountMemberRuleParam{CloudflareAccountMember: cloudflaresdk.F(zero_trust.AccessRuleAccessCloudflareAccountMemberRuleCloudflareAccountMemberParam{AccountID: cloudflaresdk.F(v.AccountID)})}
		default:
			return nil, fmt.Errorf("unsupported Access rule kind %q", v.Kind)
		}
		out = append(out, rule)
	}
	return out, nil
}
