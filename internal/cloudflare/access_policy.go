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
	"fmt"
	"slices"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// AccessPolicyAPI is part of the Flareway API.
type AccessPolicyAPI interface {
	CreateAccessPolicy(context.Context, AccessPolicyInput) (AccessPolicy, error)
	UpdateAccessPolicy(context.Context, string, AccessPolicyInput) (AccessPolicy, error)
	GetAccessPolicy(context.Context, string) (AccessPolicy, error)
	ListAccessPolicies(context.Context) ([]AccessPolicy, error)
	DeleteAccessPolicy(context.Context, string) error
}

// AccessPolicyInput contains mutable reusable-policy fields.
type AccessPolicyInput struct {
	Name                         string
	Decision                     string
	Include                      []ResolvedAccessRule
	Require                      []ResolvedAccessRule
	Exclude                      []ResolvedAccessRule
	SessionDuration              string
	PurposeJustificationRequired *bool
	PurposeJustificationPrompt   string
	ApprovalRequired             *bool
	ApprovalGroups               []AccessApprovalGroup
	IsolationRequired            *bool
	ConnectionRules              *AccessPolicyConnectionRules
	MFAConfig                    *AccessPolicyMFAConfig
}

// AccessApprovalGroup configures one approval group.
type AccessApprovalGroup struct {
	ApprovalsNeeded int32
	EmailAddresses  []string
	EmailListID     string
}

// AccessPolicyConnectionRules configures protocol-specific connection behavior.
type AccessPolicyConnectionRules struct {
	RDP *AccessPolicyRDPConnectionRules
}

// AccessPolicyRDPConnectionRules configures RDP clipboard behavior.
type AccessPolicyRDPConnectionRules struct {
	AllowedClipboardLocalToRemoteFormats []string
	AllowedClipboardRemoteToLocalFormats []string
}

// AccessPolicyMFAConfig configures policy-level multi-factor authentication.
type AccessPolicyMFAConfig struct {
	AllowedAuthenticators []string
	MFADisabled           *bool
	SessionDuration       string
}

// AccessPolicy retains every mutable reusable-policy field returned by Cloudflare.
type AccessPolicy struct {
	ID                           string
	Name                         string
	Decision                     string
	Include                      []ResolvedAccessRule
	Require                      []ResolvedAccessRule
	Exclude                      []ResolvedAccessRule
	SessionDuration              string
	PurposeJustificationRequired bool
	PurposeJustificationPrompt   string
	ApprovalRequired             bool
	ApprovalGroups               []AccessApprovalGroup
	IsolationRequired            bool
	ConnectionRules              AccessPolicyConnectionRules
	MFAConfig                    AccessPolicyMFAConfig
}

// UnsupportedAccessPolicyFieldError identifies remote or desired policy data
// that cannot be represented by the reusable-policy contract.
type UnsupportedAccessPolicyFieldError struct {
	Field string
	Value string
}

func (e *UnsupportedAccessPolicyFieldError) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("unsupported Access policy field %q", e.Field)
	}
	return fmt.Sprintf("unsupported Access policy %s %q", e.Field, e.Value)
}

// CreateAccessPolicy creates an account-level reusable policy.
func (client *Client) CreateAccessPolicy(ctx context.Context, input AccessPolicyInput) (AccessPolicy, error) {
	params, err := accessPolicyNewParams(client.accountID, input)
	if err != nil {
		return AccessPolicy{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Policies.New(ctx, params)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("create Access policy: %w", err)
	}
	policy, err := accessPolicyFromNewResponse(result)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("parse created Access policy: %w", err)
	}
	return policy, nil
}

// UpdateAccessPolicy updates an account-level reusable policy.
func (client *Client) UpdateAccessPolicy(ctx context.Context, id string, input AccessPolicyInput) (AccessPolicy, error) {
	params, err := accessPolicyUpdateParams(client.accountID, input)
	if err != nil {
		return AccessPolicy{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Policies.Update(ctx, id, params)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("update Access policy: %w", err)
	}
	policy, err := accessPolicyFromUpdateResponse(result)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("parse updated Access policy: %w", err)
	}
	return policy, nil
}

// GetAccessPolicy fetches an account-level reusable policy.
func (client *Client) GetAccessPolicy(ctx context.Context, id string) (AccessPolicy, error) {
	result, err := client.sdk.ZeroTrust.Access.Policies.Get(ctx, id, zero_trust.AccessPolicyGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("get Access policy: %w", err)
	}
	policy, err := accessPolicyFromGetResponse(result)
	if err != nil {
		return AccessPolicy{}, fmt.Errorf("parse Access policy: %w", err)
	}
	return policy, nil
}

// ListAccessPolicies lists account-level reusable policies.
func (client *Client) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	pager := client.sdk.ZeroTrust.Access.Policies.ListAutoPaging(ctx, zero_trust.AccessPolicyListParams{AccountID: cloudflaresdk.F(client.accountID), PerPage: cloudflaresdk.F(int64(100))})
	var out []AccessPolicy
	for pager.Next() {
		policy, err := accessPolicyFromListResponse(pager.Current())
		if err != nil {
			return nil, fmt.Errorf("parse listed Access policy: %w", err)
		}
		out = append(out, policy)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access policies: %w", err)
	}
	return out, nil
}

// DeleteAccessPolicy deletes an account-level reusable policy.
func (client *Client) DeleteAccessPolicy(ctx context.Context, id string) error {
	_, err := client.sdk.ZeroTrust.Access.Policies.Delete(ctx, id, zero_trust.AccessPolicyDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access policy: %w", err)
	}
	return nil
}

// AccessRulesForSDK translates public enum values and builds SDK rule unions.
func AccessRulesForSDK(values []ResolvedAccessRule) ([]zero_trust.AccessRuleUnionParam, error) {
	out := make([]zero_trust.AccessRuleUnionParam, 0, len(values))
	for _, value := range values {
		value.Values = slices.Clone(value.Values)
		if value.Kind == "userRiskScore" {
			for i := range value.Values {
				switch value.Values[i] {
				case "Low":
					value.Values[i] = "low"
				case "Medium":
					value.Values[i] = "medium"
				case "High":
					value.Values[i] = "high"
				case "Unscored":
					value.Values[i] = "unscored"
				default:
					return nil, &UnsupportedAccessPolicyFieldError{Field: "user risk level", Value: value.Values[i]}
				}
			}
		}
		if value.Kind == "githubOrganization" && value.Value2 == "" {
			out = append(out, zero_trust.GitHubOrganizationRuleParam{GitHubOrganization: cloudflaresdk.F(zero_trust.GitHubOrganizationRuleGitHubOrganizationParam{
				Name:               cloudflaresdk.F(value.Value),
				IdentityProviderID: cloudflaresdk.F(value.IdentityProviderID),
			})})
			continue
		}
		converted, err := AccessRulesToSDK([]ResolvedAccessRule{value})
		if err != nil {
			return nil, err
		}
		out = append(out, converted[0])
	}
	return out, nil
}

// AccessRulesFromSDK parses every official Access rule response variant.
func AccessRulesFromSDK(values []zero_trust.AccessRule) ([]ResolvedAccessRule, error) {
	out := make([]ResolvedAccessRule, len(values))
	for i := range values {
		switch rule := values[i].AsUnion().(type) {
		case zero_trust.GroupRule:
			out[i] = ResolvedAccessRule{Kind: "group", ID: rule.Group.ID}
		case zero_trust.AnyValidServiceTokenRule:
			out[i] = ResolvedAccessRule{Kind: "anyValidServiceToken"}
		case zero_trust.AccessRuleAccessAuthContextRule:
			out[i] = ResolvedAccessRule{Kind: "authContext", Value: rule.AuthContext.ID, Value2: rule.AuthContext.AcID, IdentityProviderID: rule.AuthContext.IdentityProviderID}
		case zero_trust.AuthenticationMethodRule:
			out[i] = ResolvedAccessRule{Kind: "authMethod", Value: rule.AuthMethod.AuthMethod}
		case zero_trust.AzureGroupRule:
			out[i] = ResolvedAccessRule{Kind: "azureAD", ID: rule.AzureAD.ID, IdentityProviderID: rule.AzureAD.IdentityProviderID}
		case zero_trust.CertificateRule:
			out[i] = ResolvedAccessRule{Kind: "certificate"}
		case zero_trust.AccessRuleAccessCommonNameRule:
			out[i] = ResolvedAccessRule{Kind: "commonName", Value: rule.CommonName.CommonName}
		case zero_trust.CountryRule:
			out[i] = ResolvedAccessRule{Kind: "geo", Value: rule.Geo.CountryCode}
		case zero_trust.AccessDevicePostureRule:
			out[i] = ResolvedAccessRule{Kind: "devicePosture", ID: rule.DevicePosture.IntegrationUID, AccountID: rule.DevicePosture.AccountID}
		case zero_trust.DomainRule:
			out[i] = ResolvedAccessRule{Kind: "emailDomain", Value: rule.EmailDomain.Domain}
		case zero_trust.EmailListRule:
			out[i] = ResolvedAccessRule{Kind: "emailList", ID: rule.EmailList.ID}
		case zero_trust.EmailRule:
			out[i] = ResolvedAccessRule{Kind: "email", Value: rule.Email.Email}
		case zero_trust.EveryoneRule:
			out[i] = ResolvedAccessRule{Kind: "everyone"}
		case zero_trust.ExternalEvaluationRule:
			out[i] = ResolvedAccessRule{Kind: "externalEvaluation", Value: rule.ExternalEvaluation.EvaluateURL, Value2: rule.ExternalEvaluation.KeysURL}
		case zero_trust.GitHubOrganizationRule:
			out[i] = ResolvedAccessRule{Kind: "githubOrganization", Value: rule.GitHubOrganization.Name, Value2: rule.GitHubOrganization.Team, IdentityProviderID: rule.GitHubOrganization.IdentityProviderID}
		case zero_trust.GSuiteGroupRule:
			out[i] = ResolvedAccessRule{Kind: "gsuite", Value: rule.GSuite.Email, IdentityProviderID: rule.GSuite.IdentityProviderID}
		case zero_trust.AccessRuleAccessLoginMethodRule:
			out[i] = ResolvedAccessRule{Kind: "loginMethod", IdentityProviderID: rule.LoginMethod.ID}
		case zero_trust.IPListRule:
			out[i] = ResolvedAccessRule{Kind: "ipList", ID: rule.IPList.ID}
		case zero_trust.IPRule:
			out[i] = ResolvedAccessRule{Kind: "ip", Value: rule.IP.IP}
		case zero_trust.OktaGroupRule:
			out[i] = ResolvedAccessRule{Kind: "okta", Value: rule.Okta.Name, IdentityProviderID: rule.Okta.IdentityProviderID}
		case zero_trust.SAMLGroupRule:
			out[i] = ResolvedAccessRule{Kind: "saml", Value: rule.SAML.AttributeName, Value2: rule.SAML.AttributeValue, IdentityProviderID: rule.SAML.IdentityProviderID}
		case zero_trust.AccessRuleAccessOIDCClaimRule:
			out[i] = ResolvedAccessRule{Kind: "oidc", Value: rule.OIDC.ClaimName, Value2: rule.OIDC.ClaimValue, IdentityProviderID: rule.OIDC.IdentityProviderID}
		case zero_trust.ServiceTokenRule:
			out[i] = ResolvedAccessRule{Kind: "serviceToken", ID: rule.ServiceToken.TokenID}
		case zero_trust.AccessRuleAccessLinkedAppTokenRule:
			out[i] = ResolvedAccessRule{Kind: "linkedAppToken", ID: rule.LinkedAppToken.AppUID}
		case zero_trust.AccessRuleAccessUserRiskScoreRule:
			levels := make([]string, len(rule.UserRiskScore.UserRiskScore))
			for j := range rule.UserRiskScore.UserRiskScore {
				switch rule.UserRiskScore.UserRiskScore[j] {
				case zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScoreLow:
					levels[j] = "Low"
				case zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScoreMedium:
					levels[j] = "Medium"
				case zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScoreHigh:
					levels[j] = "High"
				case zero_trust.AccessRuleAccessUserRiskScoreRuleUserRiskScoreUserRiskScoreUnscored:
					levels[j] = "Unscored"
				default:
					return nil, &UnsupportedAccessPolicyFieldError{Field: "user risk level", Value: string(rule.UserRiskScore.UserRiskScore[j])}
				}
			}
			out[i] = ResolvedAccessRule{Kind: "userRiskScore", Values: levels}
		case zero_trust.AccessRuleAccessCloudflareAccountMemberRule:
			out[i] = ResolvedAccessRule{Kind: "cloudflareAccountMember", AccountID: rule.CloudflareAccountMember.AccountID}
		default:
			return nil, &UnsupportedAccessPolicyFieldError{Field: "rule variant", Value: fmt.Sprintf("%T", values[i].AsUnion())}
		}
	}
	return out, nil
}

// AccessPolicyMatchesInput reports whether every explicitly managed field matches.
func AccessPolicyMatchesInput(remote AccessPolicy, input AccessPolicyInput) bool {
	if remote.Name != input.Name || remote.Decision != input.Decision ||
		!equalAccessRules(remote.Include, input.Include) {
		return false
	}
	if input.Require != nil && !equalAccessRules(remote.Require, input.Require) {
		return false
	}
	if input.Exclude != nil && !equalAccessRules(remote.Exclude, input.Exclude) {
		return false
	}
	if input.SessionDuration != "" && remote.SessionDuration != input.SessionDuration {
		return false
	}
	if input.PurposeJustificationRequired != nil &&
		remote.PurposeJustificationRequired != *input.PurposeJustificationRequired {
		return false
	}
	if input.PurposeJustificationPrompt != "" &&
		remote.PurposeJustificationPrompt != input.PurposeJustificationPrompt {
		return false
	}
	if input.ApprovalRequired != nil &&
		(remote.ApprovalRequired != *input.ApprovalRequired ||
			!equalApprovalGroups(remote.ApprovalGroups, input.ApprovalGroups)) {
		return false
	}
	if input.IsolationRequired != nil && remote.IsolationRequired != *input.IsolationRequired {
		return false
	}
	if input.ConnectionRules != nil && !equalConnectionRules(remote.ConnectionRules, *input.ConnectionRules) {
		return false
	}
	if input.MFAConfig != nil && !equalMFAConfig(remote.MFAConfig, *input.MFAConfig) {
		return false
	}
	return true
}

func accessPolicyNewParams(accountID string, input AccessPolicyInput) (zero_trust.AccessPolicyNewParams, error) {
	include, err := AccessRulesForSDK(input.Include)
	if err != nil {
		return zero_trust.AccessPolicyNewParams{}, err
	}
	decision, err := accessReusablePolicyDecisionToWire(input.Decision)
	if err != nil {
		return zero_trust.AccessPolicyNewParams{}, err
	}
	params := zero_trust.AccessPolicyNewParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Decision:  cloudflaresdk.F(decision),
		Include:   cloudflaresdk.F(include),
	}
	if input.Require != nil {
		require, convertErr := AccessRulesForSDK(input.Require)
		if convertErr != nil {
			return zero_trust.AccessPolicyNewParams{}, convertErr
		}
		params.Require = cloudflaresdk.F(require)
	}
	if input.Exclude != nil {
		exclude, convertErr := AccessRulesForSDK(input.Exclude)
		if convertErr != nil {
			return zero_trust.AccessPolicyNewParams{}, convertErr
		}
		params.Exclude = cloudflaresdk.F(exclude)
	}
	if input.SessionDuration != "" {
		params.SessionDuration = cloudflaresdk.F(input.SessionDuration)
	}
	if input.PurposeJustificationRequired != nil {
		params.PurposeJustificationRequired = cloudflaresdk.F(*input.PurposeJustificationRequired)
	}
	if input.PurposeJustificationPrompt != "" {
		params.PurposeJustificationPrompt = cloudflaresdk.F(input.PurposeJustificationPrompt)
	}
	if input.ApprovalRequired != nil {
		params.ApprovalRequired = cloudflaresdk.F(*input.ApprovalRequired)
		params.ApprovalGroups = cloudflaresdk.F(approvalGroups(input.ApprovalGroups))
	}
	if input.IsolationRequired != nil {
		params.IsolationRequired = cloudflaresdk.F(*input.IsolationRequired)
	}
	if input.ConnectionRules != nil {
		connectionRules, convertErr := accessPolicyNewConnectionRules(*input.ConnectionRules)
		if convertErr != nil {
			return zero_trust.AccessPolicyNewParams{}, convertErr
		}
		params.ConnectionRules = cloudflaresdk.F(connectionRules)
	}
	if input.MFAConfig != nil {
		mfaConfig, convertErr := accessPolicyNewMFAConfig(*input.MFAConfig)
		if convertErr != nil {
			return zero_trust.AccessPolicyNewParams{}, convertErr
		}
		params.MfaConfig = cloudflaresdk.F(mfaConfig)
	}
	return params, nil
}

func accessPolicyUpdateParams(accountID string, input AccessPolicyInput) (zero_trust.AccessPolicyUpdateParams, error) {
	include, err := AccessRulesForSDK(input.Include)
	if err != nil {
		return zero_trust.AccessPolicyUpdateParams{}, err
	}
	decision, err := accessReusablePolicyDecisionToWire(input.Decision)
	if err != nil {
		return zero_trust.AccessPolicyUpdateParams{}, err
	}
	params := zero_trust.AccessPolicyUpdateParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Decision:  cloudflaresdk.F(decision),
		Include:   cloudflaresdk.F(include),
	}
	if input.Require != nil {
		require, convertErr := AccessRulesForSDK(input.Require)
		if convertErr != nil {
			return zero_trust.AccessPolicyUpdateParams{}, convertErr
		}
		params.Require = cloudflaresdk.F(require)
	}
	if input.Exclude != nil {
		exclude, convertErr := AccessRulesForSDK(input.Exclude)
		if convertErr != nil {
			return zero_trust.AccessPolicyUpdateParams{}, convertErr
		}
		params.Exclude = cloudflaresdk.F(exclude)
	}
	if input.SessionDuration != "" {
		params.SessionDuration = cloudflaresdk.F(input.SessionDuration)
	}
	if input.PurposeJustificationRequired != nil {
		params.PurposeJustificationRequired = cloudflaresdk.F(*input.PurposeJustificationRequired)
	}
	if input.PurposeJustificationPrompt != "" {
		params.PurposeJustificationPrompt = cloudflaresdk.F(input.PurposeJustificationPrompt)
	}
	if input.ApprovalRequired != nil {
		params.ApprovalRequired = cloudflaresdk.F(*input.ApprovalRequired)
		params.ApprovalGroups = cloudflaresdk.F(approvalGroups(input.ApprovalGroups))
	}
	if input.IsolationRequired != nil {
		params.IsolationRequired = cloudflaresdk.F(*input.IsolationRequired)
	}
	if input.ConnectionRules != nil {
		connectionRules, convertErr := accessPolicyUpdateConnectionRules(*input.ConnectionRules)
		if convertErr != nil {
			return zero_trust.AccessPolicyUpdateParams{}, convertErr
		}
		params.ConnectionRules = cloudflaresdk.F(connectionRules)
	}
	if input.MFAConfig != nil {
		mfaConfig, convertErr := accessPolicyUpdateMFAConfig(*input.MFAConfig)
		if convertErr != nil {
			return zero_trust.AccessPolicyUpdateParams{}, convertErr
		}
		params.MfaConfig = cloudflaresdk.F(mfaConfig)
	}
	return params, nil
}

func accessReusablePolicyDecisionToWire(value string) (zero_trust.Decision, error) {
	switch value {
	case "Allow":
		return zero_trust.DecisionAllow, nil
	case "Deny":
		return zero_trust.DecisionDeny, nil
	case "NonIdentity":
		return zero_trust.DecisionNonIdentity, nil
	case "Bypass":
		return zero_trust.DecisionBypass, nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "decision", Value: value}
	}
}

func accessReusablePolicyDecisionFromWire(value zero_trust.Decision) (string, error) {
	switch value {
	case zero_trust.DecisionAllow:
		return "Allow", nil
	case zero_trust.DecisionDeny:
		return "Deny", nil
	case zero_trust.DecisionNonIdentity:
		return "NonIdentity", nil
	case zero_trust.DecisionBypass:
		return "Bypass", nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "decision", Value: string(value)}
	}
}

func approvalGroups(values []AccessApprovalGroup) []zero_trust.ApprovalGroupParam {
	out := make([]zero_trust.ApprovalGroupParam, len(values))
	for i, value := range values {
		out[i].ApprovalsNeeded = cloudflaresdk.F(float64(value.ApprovalsNeeded))
		if value.EmailAddresses != nil {
			out[i].EmailAddresses = cloudflaresdk.F(slices.Clone(value.EmailAddresses))
		}
		if value.EmailListID != "" {
			out[i].EmailListUUID = cloudflaresdk.F(value.EmailListID)
		}
	}
	return out
}

func approvalGroupsFromSDK(values []zero_trust.ApprovalGroup) []AccessApprovalGroup {
	out := make([]AccessApprovalGroup, len(values))
	for i := range values {
		out[i] = AccessApprovalGroup{
			ApprovalsNeeded: int32(values[i].ApprovalsNeeded),
			EmailAddresses:  slices.Clone(values[i].EmailAddresses),
			EmailListID:     values[i].EmailListUUID,
		}
	}
	return out
}

func accessPolicyNewConnectionRules(value AccessPolicyConnectionRules) (zero_trust.AccessPolicyNewParamsConnectionRules, error) {
	var out zero_trust.AccessPolicyNewParamsConnectionRules
	if value.RDP == nil {
		return out, nil
	}
	rdp := zero_trust.AccessPolicyNewParamsConnectionRulesRDP{}
	if value.RDP.AllowedClipboardLocalToRemoteFormats != nil {
		formats, err := newLocalClipboardFormats(value.RDP.AllowedClipboardLocalToRemoteFormats)
		if err != nil {
			return out, err
		}
		rdp.AllowedClipboardLocalToRemoteFormats = cloudflaresdk.F(formats)
	}
	if value.RDP.AllowedClipboardRemoteToLocalFormats != nil {
		formats, err := newRemoteClipboardFormats(value.RDP.AllowedClipboardRemoteToLocalFormats)
		if err != nil {
			return out, err
		}
		rdp.AllowedClipboardRemoteToLocalFormats = cloudflaresdk.F(formats)
	}
	out.RDP = cloudflaresdk.F(rdp)
	return out, nil
}

func accessPolicyUpdateConnectionRules(value AccessPolicyConnectionRules) (zero_trust.AccessPolicyUpdateParamsConnectionRules, error) {
	var out zero_trust.AccessPolicyUpdateParamsConnectionRules
	if value.RDP == nil {
		return out, nil
	}
	rdp := zero_trust.AccessPolicyUpdateParamsConnectionRulesRDP{}
	if value.RDP.AllowedClipboardLocalToRemoteFormats != nil {
		formats := make([]zero_trust.AccessPolicyUpdateParamsConnectionRulesRDPAllowedClipboardLocalToRemoteFormat, len(value.RDP.AllowedClipboardLocalToRemoteFormats))
		for i := range value.RDP.AllowedClipboardLocalToRemoteFormats {
			wire, err := clipboardFormatToWire(value.RDP.AllowedClipboardLocalToRemoteFormats[i])
			if err != nil {
				return out, err
			}
			formats[i] = zero_trust.AccessPolicyUpdateParamsConnectionRulesRDPAllowedClipboardLocalToRemoteFormat(wire)
		}
		rdp.AllowedClipboardLocalToRemoteFormats = cloudflaresdk.F(formats)
	}
	if value.RDP.AllowedClipboardRemoteToLocalFormats != nil {
		formats := make([]zero_trust.AccessPolicyUpdateParamsConnectionRulesRDPAllowedClipboardRemoteToLocalFormat, len(value.RDP.AllowedClipboardRemoteToLocalFormats))
		for i := range value.RDP.AllowedClipboardRemoteToLocalFormats {
			wire, err := clipboardFormatToWire(value.RDP.AllowedClipboardRemoteToLocalFormats[i])
			if err != nil {
				return out, err
			}
			formats[i] = zero_trust.AccessPolicyUpdateParamsConnectionRulesRDPAllowedClipboardRemoteToLocalFormat(wire)
		}
		rdp.AllowedClipboardRemoteToLocalFormats = cloudflaresdk.F(formats)
	}
	out.RDP = cloudflaresdk.F(rdp)
	return out, nil
}

func newLocalClipboardFormats(values []string) ([]zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardLocalToRemoteFormat, error) {
	out := make([]zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardLocalToRemoteFormat, len(values))
	for i := range values {
		wire, err := clipboardFormatToWire(values[i])
		if err != nil {
			return nil, err
		}
		out[i] = zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardLocalToRemoteFormat(wire)
	}
	return out, nil
}

func newRemoteClipboardFormats(values []string) ([]zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardRemoteToLocalFormat, error) {
	out := make([]zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardRemoteToLocalFormat, len(values))
	for i := range values {
		wire, err := clipboardFormatToWire(values[i])
		if err != nil {
			return nil, err
		}
		out[i] = zero_trust.AccessPolicyNewParamsConnectionRulesRDPAllowedClipboardRemoteToLocalFormat(wire)
	}
	return out, nil
}

func clipboardFormatToWire(value string) (string, error) {
	switch value {
	case "Text":
		return "text", nil
	case "File":
		return "file", nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "RDP clipboard format", Value: value}
	}
}

func clipboardFormatFromWire(value string) (string, error) {
	switch value {
	case "text":
		return "Text", nil
	case "file":
		return "File", nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "RDP clipboard format", Value: value}
	}
}

func accessPolicyNewMFAConfig(value AccessPolicyMFAConfig) (zero_trust.AccessPolicyNewParamsMfaConfig, error) {
	var out zero_trust.AccessPolicyNewParamsMfaConfig
	if value.AllowedAuthenticators != nil {
		authenticators := make([]zero_trust.AccessPolicyNewParamsMfaConfigAllowedAuthenticator, len(value.AllowedAuthenticators))
		for i := range value.AllowedAuthenticators {
			wire, err := mfaAuthenticatorToWire(value.AllowedAuthenticators[i])
			if err != nil {
				return out, err
			}
			authenticators[i] = zero_trust.AccessPolicyNewParamsMfaConfigAllowedAuthenticator(wire)
		}
		out.AllowedAuthenticators = cloudflaresdk.F(authenticators)
	}
	if value.MFADisabled != nil {
		out.MfaDisabled = cloudflaresdk.F(*value.MFADisabled)
	}
	if value.SessionDuration != "" {
		out.SessionDuration = cloudflaresdk.F(value.SessionDuration)
	}
	return out, nil
}

func accessPolicyUpdateMFAConfig(value AccessPolicyMFAConfig) (zero_trust.AccessPolicyUpdateParamsMfaConfig, error) {
	var out zero_trust.AccessPolicyUpdateParamsMfaConfig
	if value.AllowedAuthenticators != nil {
		authenticators := make([]zero_trust.AccessPolicyUpdateParamsMfaConfigAllowedAuthenticator, len(value.AllowedAuthenticators))
		for i := range value.AllowedAuthenticators {
			wire, err := mfaAuthenticatorToWire(value.AllowedAuthenticators[i])
			if err != nil {
				return out, err
			}
			authenticators[i] = zero_trust.AccessPolicyUpdateParamsMfaConfigAllowedAuthenticator(wire)
		}
		out.AllowedAuthenticators = cloudflaresdk.F(authenticators)
	}
	if value.MFADisabled != nil {
		out.MfaDisabled = cloudflaresdk.F(*value.MFADisabled)
	}
	if value.SessionDuration != "" {
		out.SessionDuration = cloudflaresdk.F(value.SessionDuration)
	}
	return out, nil
}

func mfaAuthenticatorToWire(value string) (string, error) {
	switch value {
	case "TOTP":
		return "totp", nil
	case "Biometrics":
		return "biometrics", nil
	case "SecurityKey":
		return "security_key", nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "MFA authenticator", Value: value}
	}
}

func mfaAuthenticatorFromWire(value string) (string, error) {
	switch value {
	case "totp":
		return "TOTP", nil
	case "biometrics":
		return "Biometrics", nil
	case "security_key":
		return "SecurityKey", nil
	default:
		return "", &UnsupportedAccessPolicyFieldError{Field: "MFA authenticator", Value: value}
	}
}

func accessPolicyFromNewResponse(value *zero_trust.AccessPolicyNewResponse) (AccessPolicy, error) {
	include, require, exclude, decision, err := accessPolicyCoreFromSDK(value.Include, value.Require, value.Exclude, value.Decision)
	if err != nil {
		return AccessPolicy{}, err
	}
	connectionRules, err := accessPolicyConnectionRulesFromSDK(
		newLocalFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats),
		newRemoteFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats),
	)
	if err != nil {
		return AccessPolicy{}, err
	}
	mfaConfig, err := accessPolicyMFAFromSDK(newMFAAuthenticatorsFromSDK(value.MfaConfig.AllowedAuthenticators), value.MfaConfig.MfaDisabled, value.MfaConfig.SessionDuration)
	if err != nil {
		return AccessPolicy{}, err
	}
	return accessPolicyResult(value.ID, value.Name, decision, include, require, exclude, value.SessionDuration, value.PurposeJustificationRequired, value.PurposeJustificationPrompt, value.ApprovalRequired, value.ApprovalGroups, value.IsolationRequired, connectionRules, mfaConfig), nil
}

func accessPolicyFromUpdateResponse(value *zero_trust.AccessPolicyUpdateResponse) (AccessPolicy, error) {
	include, require, exclude, decision, err := accessPolicyCoreFromSDK(value.Include, value.Require, value.Exclude, value.Decision)
	if err != nil {
		return AccessPolicy{}, err
	}
	connectionRules, err := accessPolicyConnectionRulesFromSDK(
		updateLocalFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats),
		updateRemoteFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats),
	)
	if err != nil {
		return AccessPolicy{}, err
	}
	mfaConfig, err := accessPolicyMFAFromSDK(updateMFAAuthenticatorsFromSDK(value.MfaConfig.AllowedAuthenticators), value.MfaConfig.MfaDisabled, value.MfaConfig.SessionDuration)
	if err != nil {
		return AccessPolicy{}, err
	}
	return accessPolicyResult(value.ID, value.Name, decision, include, require, exclude, value.SessionDuration, value.PurposeJustificationRequired, value.PurposeJustificationPrompt, value.ApprovalRequired, value.ApprovalGroups, value.IsolationRequired, connectionRules, mfaConfig), nil
}

func accessPolicyFromGetResponse(value *zero_trust.AccessPolicyGetResponse) (AccessPolicy, error) {
	include, require, exclude, decision, err := accessPolicyCoreFromSDK(value.Include, value.Require, value.Exclude, value.Decision)
	if err != nil {
		return AccessPolicy{}, err
	}
	connectionRules, err := accessPolicyConnectionRulesFromSDK(
		getLocalFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats),
		getRemoteFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats),
	)
	if err != nil {
		return AccessPolicy{}, err
	}
	mfaConfig, err := accessPolicyMFAFromSDK(getMFAAuthenticatorsFromSDK(value.MfaConfig.AllowedAuthenticators), value.MfaConfig.MfaDisabled, value.MfaConfig.SessionDuration)
	if err != nil {
		return AccessPolicy{}, err
	}
	return accessPolicyResult(value.ID, value.Name, decision, include, require, exclude, value.SessionDuration, value.PurposeJustificationRequired, value.PurposeJustificationPrompt, value.ApprovalRequired, value.ApprovalGroups, value.IsolationRequired, connectionRules, mfaConfig), nil
}

func accessPolicyFromListResponse(value zero_trust.AccessPolicyListResponse) (AccessPolicy, error) {
	include, require, exclude, decision, err := accessPolicyCoreFromSDK(value.Include, value.Require, value.Exclude, value.Decision)
	if err != nil {
		return AccessPolicy{}, err
	}
	connectionRules, err := accessPolicyConnectionRulesFromSDK(
		listLocalFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats),
		listRemoteFormatsFromSDK(value.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats),
	)
	if err != nil {
		return AccessPolicy{}, err
	}
	mfaConfig, err := accessPolicyMFAFromSDK(listMFAAuthenticatorsFromSDK(value.MfaConfig.AllowedAuthenticators), value.MfaConfig.MfaDisabled, value.MfaConfig.SessionDuration)
	if err != nil {
		return AccessPolicy{}, err
	}
	return accessPolicyResult(value.ID, value.Name, decision, include, require, exclude, value.SessionDuration, value.PurposeJustificationRequired, value.PurposeJustificationPrompt, value.ApprovalRequired, value.ApprovalGroups, value.IsolationRequired, connectionRules, mfaConfig), nil
}

func accessPolicyCoreFromSDK(includeValue, requireValue, excludeValue []zero_trust.AccessRule, decisionValue zero_trust.Decision) ([]ResolvedAccessRule, []ResolvedAccessRule, []ResolvedAccessRule, string, error) {
	include, err := AccessRulesFromSDK(includeValue)
	if err != nil {
		return nil, nil, nil, "", err
	}
	require, err := AccessRulesFromSDK(requireValue)
	if err != nil {
		return nil, nil, nil, "", err
	}
	exclude, err := AccessRulesFromSDK(excludeValue)
	if err != nil {
		return nil, nil, nil, "", err
	}
	decision, err := accessReusablePolicyDecisionFromWire(decisionValue)
	return include, require, exclude, decision, err
}

func accessPolicyResult(id, name, decision string, include, require, exclude []ResolvedAccessRule, sessionDuration string, purposeRequired bool, purposePrompt string, approvalRequired bool, groups []zero_trust.ApprovalGroup, isolationRequired bool, connectionRules AccessPolicyConnectionRules, mfaConfig AccessPolicyMFAConfig) AccessPolicy {
	return AccessPolicy{
		ID:                           id,
		Name:                         name,
		Decision:                     decision,
		Include:                      include,
		Require:                      require,
		Exclude:                      exclude,
		SessionDuration:              sessionDuration,
		PurposeJustificationRequired: purposeRequired,
		PurposeJustificationPrompt:   purposePrompt,
		ApprovalRequired:             approvalRequired,
		ApprovalGroups:               approvalGroupsFromSDK(groups),
		IsolationRequired:            isolationRequired,
		ConnectionRules:              connectionRules,
		MFAConfig:                    mfaConfig,
	}
}

func accessPolicyConnectionRulesFromSDK(local, remote []string) (AccessPolicyConnectionRules, error) {
	rdp := &AccessPolicyRDPConnectionRules{
		AllowedClipboardLocalToRemoteFormats: make([]string, len(local)),
		AllowedClipboardRemoteToLocalFormats: make([]string, len(remote)),
	}
	for i := range local {
		value, err := clipboardFormatFromWire(local[i])
		if err != nil {
			return AccessPolicyConnectionRules{}, err
		}
		rdp.AllowedClipboardLocalToRemoteFormats[i] = value
	}
	for i := range remote {
		value, err := clipboardFormatFromWire(remote[i])
		if err != nil {
			return AccessPolicyConnectionRules{}, err
		}
		rdp.AllowedClipboardRemoteToLocalFormats[i] = value
	}
	return AccessPolicyConnectionRules{RDP: rdp}, nil
}

func accessPolicyMFAFromSDK(authenticators []string, disabled bool, duration string) (AccessPolicyMFAConfig, error) {
	out := AccessPolicyMFAConfig{AllowedAuthenticators: make([]string, len(authenticators)), MFADisabled: new(disabled), SessionDuration: duration}
	for i := range authenticators {
		value, err := mfaAuthenticatorFromWire(authenticators[i])
		if err != nil {
			return AccessPolicyMFAConfig{}, err
		}
		out.AllowedAuthenticators[i] = value
	}
	return out, nil
}

func newLocalFormatsFromSDK(values []zero_trust.AccessPolicyNewResponseConnectionRulesRDPAllowedClipboardLocalToRemoteFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func newRemoteFormatsFromSDK(values []zero_trust.AccessPolicyNewResponseConnectionRulesRDPAllowedClipboardRemoteToLocalFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func updateLocalFormatsFromSDK(values []zero_trust.AccessPolicyUpdateResponseConnectionRulesRDPAllowedClipboardLocalToRemoteFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func updateRemoteFormatsFromSDK(values []zero_trust.AccessPolicyUpdateResponseConnectionRulesRDPAllowedClipboardRemoteToLocalFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func getLocalFormatsFromSDK(values []zero_trust.AccessPolicyGetResponseConnectionRulesRDPAllowedClipboardLocalToRemoteFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func getRemoteFormatsFromSDK(values []zero_trust.AccessPolicyGetResponseConnectionRulesRDPAllowedClipboardRemoteToLocalFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func listLocalFormatsFromSDK(values []zero_trust.AccessPolicyListResponseConnectionRulesRDPAllowedClipboardLocalToRemoteFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func listRemoteFormatsFromSDK(values []zero_trust.AccessPolicyListResponseConnectionRulesRDPAllowedClipboardRemoteToLocalFormat) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func newMFAAuthenticatorsFromSDK(values []zero_trust.AccessPolicyNewResponseMfaConfigAllowedAuthenticator) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func updateMFAAuthenticatorsFromSDK(values []zero_trust.AccessPolicyUpdateResponseMfaConfigAllowedAuthenticator) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func getMFAAuthenticatorsFromSDK(values []zero_trust.AccessPolicyGetResponseMfaConfigAllowedAuthenticator) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func listMFAAuthenticatorsFromSDK(values []zero_trust.AccessPolicyListResponseMfaConfigAllowedAuthenticator) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func equalAccessRules(left, right []ResolvedAccessRule) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Kind != right[i].Kind ||
			left[i].Value != right[i].Value ||
			left[i].Value2 != right[i].Value2 ||
			left[i].Value3 != right[i].Value3 ||
			left[i].ID != right[i].ID ||
			left[i].IdentityProviderID != right[i].IdentityProviderID ||
			left[i].AccountID != right[i].AccountID ||
			!equalStringSet(left[i].Values, right[i].Values) {
			return false
		}
	}
	return true
}

func equalApprovalGroups(left, right []AccessApprovalGroup) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].ApprovalsNeeded != right[i].ApprovalsNeeded ||
			left[i].EmailListID != right[i].EmailListID ||
			!equalStringSet(left[i].EmailAddresses, right[i].EmailAddresses) {
			return false
		}
	}
	return true
}

func equalConnectionRules(left, right AccessPolicyConnectionRules) bool {
	if right.RDP == nil {
		return true
	}
	if left.RDP == nil {
		return false
	}
	return equalStringSet(left.RDP.AllowedClipboardLocalToRemoteFormats, right.RDP.AllowedClipboardLocalToRemoteFormats) &&
		equalStringSet(left.RDP.AllowedClipboardRemoteToLocalFormats, right.RDP.AllowedClipboardRemoteToLocalFormats)
}

func equalMFAConfig(left, right AccessPolicyMFAConfig) bool {
	if right.MFADisabled != nil && (left.MFADisabled == nil || *left.MFADisabled != *right.MFADisabled) {
		return false
	}
	if right.SessionDuration != "" && left.SessionDuration != right.SessionDuration {
		return false
	}
	return right.AllowedAuthenticators == nil || equalStringSet(left.AllowedAuthenticators, right.AllowedAuthenticators)
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// EnsureBypassPolicy finds or creates the operator's shared bypass policy.
func (client *Client) EnsureBypassPolicy(ctx context.Context, name string) (AccessPolicy, error) {
	policies, err := client.ListAccessPolicies(ctx)
	if err != nil {
		return AccessPolicy{}, err
	}
	for _, policy := range policies {
		if policy.Name == name {
			if policy.Decision != "Bypass" {
				return AccessPolicy{}, fmt.Errorf("access policy %q exists with decision %q", name, policy.Decision)
			}
			return policy, nil
		}
	}
	return client.CreateAccessPolicy(ctx, AccessPolicyInput{Name: name, Decision: "Bypass", Include: []ResolvedAccessRule{{Kind: "everyone"}}})
}
