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
	"errors"
	"fmt"
	"slices"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// OrganizationAPI manages account- and zone-scoped Access organizations.
type OrganizationAPI interface {
	GetAccessOrganization(context.Context, AccessScope) (Organization, error)
	CreateAccessOrganization(context.Context, AccessScope, OrganizationCreateInput) (Organization, error)
	UpdateAccessOrganization(context.Context, AccessScope, OrganizationInput) (Organization, error)
	RevokeAccessOrganizationUser(context.Context, AccessScope, OrganizationUserRevocationInput) (bool, error)
	GetAccessOrganizationDOH(context.Context) (OrganizationDOHSettings, error)
	UpdateAccessOrganizationDOH(context.Context, OrganizationDOHInput) (OrganizationDOHSettings, error)
	GetAccessCustomPage(context.Context, string) (AccessCustomPage, error)
	GetServiceToken(context.Context, AccessScope, string) (ServiceToken, error)
}

// OrganizationCreateInput contains required create-only identity and mutable settings.
type OrganizationCreateInput struct {
	AuthDomain string
	OrganizationInput
}

// OrganizationInput preserves optional update and explicit-null semantics.
type OrganizationInput struct {
	Name                                   *string
	SessionDuration                        *string
	WARPAuthSessionDuration                *string
	AllowAuthenticateViaWARP               *bool
	AutoRedirectToIdentity                 *bool
	IsUIReadOnly                           *bool
	UIReadOnlyToggleReason                 *string
	DenyUnmatchedRequests                  *bool
	DenyUnmatchedRequestsExemptedZoneNames *[]string
	WARPAuthNonBrowser401                  *bool
	UserSeatExpirationInactiveTime         *string
	CustomPages                            *OrganizationCustomPagesInput
	LoginDesign                            *OrganizationLoginDesignInput
	MFAConfig                              *OrganizationMFAConfigInput
	MFAPIVKeyRequirements                  *OrganizationMFAPIVKeyRequirementsInput
	MFARequiredForAllApps                  *bool
}

// OrganizationCustomPages contains observed custom-page IDs.
type OrganizationCustomPages struct {
	Forbidden      string
	IdentityDenied string
}

// OrganizationCustomPagesInput contains desired custom-page IDs.
type OrganizationCustomPagesInput struct {
	Forbidden      *string
	IdentityDenied *string
}

// OrganizationLoginDesign contains observed login-page design fields.
type OrganizationLoginDesign struct {
	BackgroundColor string
	FooterText      string
	HeaderText      string
	LogoPath        string
	TextColor       string
}

// OrganizationLoginDesignInput contains desired login-page design fields.
type OrganizationLoginDesignInput struct {
	BackgroundColor *string
	FooterText      *string
	HeaderText      *string
	LogoPath        *string
	TextColor       *string
}

// OrganizationMFAAuthenticator is an organization MFA method.
type OrganizationMFAAuthenticator string

const (
	// OrganizationMFAAuthenticatorTOTP selects time-based one-time password authentication.
	OrganizationMFAAuthenticatorTOTP OrganizationMFAAuthenticator = "Totp"
	// OrganizationMFAAuthenticatorBiometrics selects platform biometric authentication.
	OrganizationMFAAuthenticatorBiometrics OrganizationMFAAuthenticator = "Biometrics"
	// OrganizationMFAAuthenticatorSecurityKey selects WebAuthn security-key authentication.
	OrganizationMFAAuthenticatorSecurityKey OrganizationMFAAuthenticator = "SecurityKey"
	// OrganizationMFAAuthenticatorPIVKey selects PIV-backed SSH key authentication.
	OrganizationMFAAuthenticatorPIVKey OrganizationMFAAuthenticator = "PivKey"
	// OrganizationMFAAuthenticatorSSHFIDO2Key selects FIDO2-backed SSH key authentication.
	OrganizationMFAAuthenticatorSSHFIDO2Key OrganizationMFAAuthenticator = "SshFido2Key"
)

// OrganizationMFAConfig contains observed MFA settings.
type OrganizationMFAConfig struct {
	AllowedAuthenticators      []OrganizationMFAAuthenticator
	AMRMatchingSessionDuration string
	RequiredAAGUIDs            string
	SessionDuration            string
}

// OrganizationMFAConfigInput contains desired MFA settings.
type OrganizationMFAConfigInput struct {
	AllowedAuthenticators      *[]OrganizationMFAAuthenticator
	AMRMatchingSessionDuration *string
	RequiredAAGUIDs            *string
	SessionDuration            *string
}

// OrganizationPIVPinPolicy controls PIN prompting.
type OrganizationPIVPinPolicy string

const (
	// OrganizationPIVPinPolicyNever disables PIN prompts.
	OrganizationPIVPinPolicyNever OrganizationPIVPinPolicy = "Never"
	// OrganizationPIVPinPolicyOnce requires one PIN prompt per session.
	OrganizationPIVPinPolicyOnce OrganizationPIVPinPolicy = "Once"
	// OrganizationPIVPinPolicyAlways requires a PIN prompt for every operation.
	OrganizationPIVPinPolicyAlways OrganizationPIVPinPolicy = "Always"
)

// OrganizationPIVSSHKeyType is an allowed SSH key algorithm.
type OrganizationPIVSSHKeyType string

const (
	// OrganizationPIVSSHKeyTypeECDSA selects ECDSA SSH keys.
	OrganizationPIVSSHKeyTypeECDSA OrganizationPIVSSHKeyType = "Ecdsa"
	// OrganizationPIVSSHKeyTypeEd25519 selects Ed25519 SSH keys.
	OrganizationPIVSSHKeyTypeEd25519 OrganizationPIVSSHKeyType = "Ed25519"
	// OrganizationPIVSSHKeyTypeRSA selects RSA SSH keys.
	OrganizationPIVSSHKeyTypeRSA OrganizationPIVSSHKeyType = "Rsa"
)

// OrganizationPIVTouchPolicy controls hardware-key touch prompting.
type OrganizationPIVTouchPolicy string

const (
	// OrganizationPIVTouchPolicyNever disables hardware-key touch prompts.
	OrganizationPIVTouchPolicyNever OrganizationPIVTouchPolicy = "Never"
	// OrganizationPIVTouchPolicyAlways requires touch for every operation.
	OrganizationPIVTouchPolicyAlways OrganizationPIVTouchPolicy = "Always"
	// OrganizationPIVTouchPolicyCached allows cached hardware-key touch confirmation.
	OrganizationPIVTouchPolicyCached OrganizationPIVTouchPolicy = "Cached"
)

// OrganizationMFAPIVKeyRequirements contains observed hardware SSH-key settings.
type OrganizationMFAPIVKeyRequirements struct {
	PinPolicy         OrganizationPIVPinPolicy
	RequireFIPSDevice bool
	SSHKeySizes       []int64
	SSHKeyTypes       []OrganizationPIVSSHKeyType
	TouchPolicy       OrganizationPIVTouchPolicy
}

// OrganizationMFAPIVKeyRequirementsInput contains desired hardware SSH-key settings.
type OrganizationMFAPIVKeyRequirementsInput struct {
	PinPolicy         *OrganizationPIVPinPolicy
	RequireFIPSDevice *bool
	SSHKeySizes       *[]int64
	SSHKeyTypes       *[]OrganizationPIVSSHKeyType
	TouchPolicy       *OrganizationPIVTouchPolicy
}

// OrganizationUserRevocationInput requests one user revocation.
type OrganizationUserRevocationInput struct {
	Email             string
	UserUID           *string
	Devices           *bool
	WARPSessionReauth *bool
}

// OrganizationDOHInput contains account-only DoH settings.
type OrganizationDOHInput struct {
	ServiceTokenID string
	JWTDuration    *string
}

// OrganizationDOHSettings contains non-secret observed DoH settings.
type OrganizationDOHSettings struct {
	ServiceTokenID string
	JWTDuration    string
}

// GetAccessOrganization returns an account- or zone-scoped organization.
func (client *Client) GetAccessOrganization(ctx context.Context, scope AccessScope) (Organization, error) {
	params := zero_trust.OrganizationListParams{}
	applyOrganizationListScope(&params, client.accountID, scope)
	remote, err := client.sdk.ZeroTrust.Organizations.List(ctx, params)
	if err != nil {
		return Organization{}, fmt.Errorf("get Cloudflare Zero Trust organization: %w", err)
	}
	return organizationFromSDK(remote), nil
}

// CreateAccessOrganization creates an absent account- or zone-scoped organization.
func (client *Client) CreateAccessOrganization(ctx context.Context, scope AccessScope, input OrganizationCreateInput) (Organization, error) {
	if input.AuthDomain == "" {
		return Organization{}, errors.New("create Cloudflare Zero Trust organization: auth domain is required")
	}
	if input.Name == nil || *input.Name == "" {
		return Organization{}, errors.New("create Cloudflare Zero Trust organization: name is required")
	}
	params := zero_trust.OrganizationNewParams{
		AuthDomain: cloudflaresdk.F(input.AuthDomain),
		Name:       cloudflaresdk.F(*input.Name),
	}
	applyOrganizationNewScope(&params, client.accountID, scope)
	applyOrganizationNewInput(&params, input.OrganizationInput)
	remote, err := client.sdk.ZeroTrust.Organizations.New(ctx, params)
	if err != nil {
		return Organization{}, fmt.Errorf("create Cloudflare Zero Trust organization: %w", err)
	}
	if input.CustomPages != nil {
		created, updateErr := client.UpdateAccessOrganization(ctx, scope, OrganizationInput{CustomPages: input.CustomPages})
		if updateErr != nil {
			return Organization{}, fmt.Errorf("set custom pages after creating Cloudflare Zero Trust organization: %w", updateErr)
		}
		return created, nil
	}
	return organizationFromSDK(remote), nil
}

// UpdateAccessOrganization updates mutable account- or zone-scoped settings.
func (client *Client) UpdateAccessOrganization(ctx context.Context, scope AccessScope, input OrganizationInput) (Organization, error) {
	params := zero_trust.OrganizationUpdateParams{}
	applyOrganizationUpdateScope(&params, client.accountID, scope)
	applyOrganizationUpdateInput(&params, input)
	remote, err := client.sdk.ZeroTrust.Organizations.Update(ctx, params)
	if err != nil {
		return Organization{}, fmt.Errorf("update Cloudflare Zero Trust organization: %w", err)
	}
	return organizationFromSDK(remote), nil
}

// RevokeAccessOrganizationUser revokes one user's Access sessions.
func (client *Client) RevokeAccessOrganizationUser(ctx context.Context, scope AccessScope, input OrganizationUserRevocationInput) (bool, error) {
	if input.Email == "" {
		return false, errors.New("revoke Cloudflare Zero Trust organization user: email is required")
	}
	params := zero_trust.OrganizationRevokeUsersParams{Email: cloudflaresdk.F(input.Email)}
	applyOrganizationRevokeScope(&params, client.accountID, scope)
	if input.UserUID != nil && *input.UserUID != "" {
		params.UserUID = cloudflaresdk.F(*input.UserUID)
	}
	if input.Devices != nil {
		params.QueryDevices = cloudflaresdk.F(*input.Devices)
		params.BodyDevices = cloudflaresdk.F(*input.Devices)
	}
	if input.WARPSessionReauth != nil {
		params.WARPSessionReauth = cloudflaresdk.F(*input.WARPSessionReauth)
	}
	result, err := client.sdk.ZeroTrust.Organizations.RevokeUsers(ctx, params)
	if err != nil {
		return false, fmt.Errorf("revoke Cloudflare Zero Trust organization user: %w", err)
	}
	return bool(*result), nil
}

// GetAccessOrganizationDOH returns account-scoped non-secret DoH settings.
func (client *Client) GetAccessOrganizationDOH(ctx context.Context) (OrganizationDOHSettings, error) {
	remote, err := client.sdk.ZeroTrust.Organizations.DOH.Get(ctx, zero_trust.OrganizationDOHGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return OrganizationDOHSettings{}, fmt.Errorf("get Cloudflare Zero Trust organization DoH settings: %w", err)
	}
	return OrganizationDOHSettings{ServiceTokenID: remote.ID, JWTDuration: remote.DOHJWTDuration}, nil
}

// UpdateAccessOrganizationDOH updates account-scoped DoH settings.
func (client *Client) UpdateAccessOrganizationDOH(ctx context.Context, input OrganizationDOHInput) (OrganizationDOHSettings, error) {
	if input.ServiceTokenID == "" {
		return OrganizationDOHSettings{}, errors.New("update Cloudflare Zero Trust organization DoH settings: service token ID is required")
	}
	params := zero_trust.OrganizationDOHUpdateParams{
		AccountID:      cloudflaresdk.F(client.accountID),
		ServiceTokenID: cloudflaresdk.F(input.ServiceTokenID),
	}
	if input.JWTDuration != nil {
		if *input.JWTDuration == "" {
			params.DOHJWTDuration = cloudflaresdk.Null[string]()
		} else {
			params.DOHJWTDuration = cloudflaresdk.F(*input.JWTDuration)
		}
	}
	remote, err := client.sdk.ZeroTrust.Organizations.DOH.Update(ctx, params)
	if err != nil {
		return OrganizationDOHSettings{}, fmt.Errorf("update Cloudflare Zero Trust organization DoH settings: %w", err)
	}
	return OrganizationDOHSettings{ServiceTokenID: remote.ID, JWTDuration: remote.DOHJWTDuration}, nil
}

func applyOrganizationListScope(params *zero_trust.OrganizationListParams, accountID string, scope AccessScope) {
	if scope.ZoneID != "" {
		params.ZoneID = cloudflaresdk.F(scope.ZoneID)
	} else {
		params.AccountID = cloudflaresdk.F(accountID)
	}
}

func applyOrganizationNewScope(params *zero_trust.OrganizationNewParams, accountID string, scope AccessScope) {
	if scope.ZoneID != "" {
		params.ZoneID = cloudflaresdk.F(scope.ZoneID)
	} else {
		params.AccountID = cloudflaresdk.F(accountID)
	}
}

func applyOrganizationUpdateScope(params *zero_trust.OrganizationUpdateParams, accountID string, scope AccessScope) {
	if scope.ZoneID != "" {
		params.ZoneID = cloudflaresdk.F(scope.ZoneID)
	} else {
		params.AccountID = cloudflaresdk.F(accountID)
	}
}

func applyOrganizationRevokeScope(params *zero_trust.OrganizationRevokeUsersParams, accountID string, scope AccessScope) {
	if scope.ZoneID != "" {
		params.ZoneID = cloudflaresdk.F(scope.ZoneID)
	} else {
		params.AccountID = cloudflaresdk.F(accountID)
	}
}

func applyOrganizationUpdateInput(params *zero_trust.OrganizationUpdateParams, input OrganizationInput) {
	if input.Name != nil {
		if *input.Name == "" {
			params.Name = cloudflaresdk.Null[string]()
		} else {
			params.Name = cloudflaresdk.F(*input.Name)
		}
	}
	if input.SessionDuration != nil {
		if *input.SessionDuration == "" {
			params.SessionDuration = cloudflaresdk.Null[string]()
		} else {
			params.SessionDuration = cloudflaresdk.F(*input.SessionDuration)
		}
	}
	if input.WARPAuthSessionDuration != nil {
		if *input.WARPAuthSessionDuration == "" {
			params.WARPAuthSessionDuration = cloudflaresdk.Null[string]()
		} else {
			params.WARPAuthSessionDuration = cloudflaresdk.F(*input.WARPAuthSessionDuration)
		}
	}
	if input.UIReadOnlyToggleReason != nil {
		if *input.UIReadOnlyToggleReason == "" {
			params.UIReadOnlyToggleReason = cloudflaresdk.Null[string]()
		} else {
			params.UIReadOnlyToggleReason = cloudflaresdk.F(*input.UIReadOnlyToggleReason)
		}
	}
	if input.UserSeatExpirationInactiveTime != nil {
		if *input.UserSeatExpirationInactiveTime == "" {
			params.UserSeatExpirationInactiveTime = cloudflaresdk.Null[string]()
		} else {
			params.UserSeatExpirationInactiveTime = cloudflaresdk.F(*input.UserSeatExpirationInactiveTime)
		}
	}
	if input.AllowAuthenticateViaWARP != nil {
		params.AllowAuthenticateViaWARP = cloudflaresdk.F(*input.AllowAuthenticateViaWARP)
	}
	if input.AutoRedirectToIdentity != nil {
		params.AutoRedirectToIdentity = cloudflaresdk.F(*input.AutoRedirectToIdentity)
	}
	if input.IsUIReadOnly != nil {
		params.IsUIReadOnly = cloudflaresdk.F(*input.IsUIReadOnly)
	}
	if input.DenyUnmatchedRequests != nil {
		params.DenyUnmatchedRequests = cloudflaresdk.F(*input.DenyUnmatchedRequests)
	}
	if input.DenyUnmatchedRequestsExemptedZoneNames != nil {
		params.DenyUnmatchedRequestsExemptedZoneNames = cloudflaresdk.F(slices.Clone(*input.DenyUnmatchedRequestsExemptedZoneNames))
	}
	if input.WARPAuthNonBrowser401 != nil {
		params.WARPAuthNonBrowser401 = cloudflaresdk.F(*input.WARPAuthNonBrowser401)
	}
	if input.MFARequiredForAllApps != nil {
		params.MfaRequiredForAllApps = cloudflaresdk.F(*input.MFARequiredForAllApps)
	}
	if input.CustomPages != nil {
		value := zero_trust.OrganizationUpdateParamsCustomPages{}
		if input.CustomPages.Forbidden == nil || *input.CustomPages.Forbidden == "" {
			value.Forbidden = cloudflaresdk.Null[string]()
		} else {
			value.Forbidden = cloudflaresdk.F(*input.CustomPages.Forbidden)
		}
		if input.CustomPages.IdentityDenied == nil || *input.CustomPages.IdentityDenied == "" {
			value.IdentityDenied = cloudflaresdk.Null[string]()
		} else {
			value.IdentityDenied = cloudflaresdk.F(*input.CustomPages.IdentityDenied)
		}
		params.CustomPages = cloudflaresdk.F(value)
	}
	if input.LoginDesign != nil {
		value := zero_trust.LoginDesignParam{}
		if input.LoginDesign.BackgroundColor != nil {
			if *input.LoginDesign.BackgroundColor == "" {
				value.BackgroundColor = cloudflaresdk.Null[string]()
			} else {
				value.BackgroundColor = cloudflaresdk.F(*input.LoginDesign.BackgroundColor)
			}
		}
		if input.LoginDesign.FooterText != nil {
			if *input.LoginDesign.FooterText == "" {
				value.FooterText = cloudflaresdk.Null[string]()
			} else {
				value.FooterText = cloudflaresdk.F(*input.LoginDesign.FooterText)
			}
		}
		if input.LoginDesign.HeaderText != nil {
			if *input.LoginDesign.HeaderText == "" {
				value.HeaderText = cloudflaresdk.Null[string]()
			} else {
				value.HeaderText = cloudflaresdk.F(*input.LoginDesign.HeaderText)
			}
		}
		if input.LoginDesign.LogoPath != nil {
			if *input.LoginDesign.LogoPath == "" {
				value.LogoPath = cloudflaresdk.Null[string]()
			} else {
				value.LogoPath = cloudflaresdk.F(*input.LoginDesign.LogoPath)
			}
		}
		if input.LoginDesign.TextColor != nil {
			if *input.LoginDesign.TextColor == "" {
				value.TextColor = cloudflaresdk.Null[string]()
			} else {
				value.TextColor = cloudflaresdk.F(*input.LoginDesign.TextColor)
			}
		}
		params.LoginDesign = cloudflaresdk.F(value)
	}
	if input.MFAConfig != nil {
		value := zero_trust.OrganizationUpdateParamsMfaConfig{}
		if input.MFAConfig.AllowedAuthenticators != nil {
			items := make([]zero_trust.OrganizationUpdateParamsMfaConfigAllowedAuthenticator, len(*input.MFAConfig.AllowedAuthenticators))
			for i, item := range *input.MFAConfig.AllowedAuthenticators {
				items[i] = updateMFAAuthenticatorToSDK(item)
			}
			value.AllowedAuthenticators = cloudflaresdk.F(items)
		}
		if input.MFAConfig.AMRMatchingSessionDuration != nil {
			if *input.MFAConfig.AMRMatchingSessionDuration == "" {
				value.AmrMatchingSessionDuration = cloudflaresdk.Null[string]()
			} else {
				value.AmrMatchingSessionDuration = cloudflaresdk.F(*input.MFAConfig.AMRMatchingSessionDuration)
			}
		}
		if input.MFAConfig.RequiredAAGUIDs != nil {
			if *input.MFAConfig.RequiredAAGUIDs == "" {
				value.RequiredAaguids = cloudflaresdk.Null[string]()
			} else {
				value.RequiredAaguids = cloudflaresdk.F(*input.MFAConfig.RequiredAAGUIDs)
			}
		}
		if input.MFAConfig.SessionDuration != nil {
			if *input.MFAConfig.SessionDuration == "" {
				value.SessionDuration = cloudflaresdk.Null[string]()
			} else {
				value.SessionDuration = cloudflaresdk.F(*input.MFAConfig.SessionDuration)
			}
		}
		params.MfaConfig = cloudflaresdk.F(value)
	}
	if input.MFAPIVKeyRequirements != nil {
		value := zero_trust.OrganizationUpdateParamsMfaPivKeyRequirements{}
		if item := input.MFAPIVKeyRequirements.PinPolicy; item != nil {
			if *item == "" {
				value.PinPolicy = cloudflaresdk.Null[zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsPinPolicy]()
			} else {
				value.PinPolicy = cloudflaresdk.F(updatePIVPinPolicyToSDK(*item))
			}
		}
		if input.MFAPIVKeyRequirements.RequireFIPSDevice != nil {
			value.RequireFipsDevice = cloudflaresdk.F(*input.MFAPIVKeyRequirements.RequireFIPSDevice)
		}
		if input.MFAPIVKeyRequirements.SSHKeySizes != nil {
			items := make([]zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsSSHKeySize, len(*input.MFAPIVKeyRequirements.SSHKeySizes))
			for i, item := range *input.MFAPIVKeyRequirements.SSHKeySizes {
				items[i] = zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsSSHKeySize(item)
			}
			value.SSHKeySize = cloudflaresdk.F(items)
		}
		if input.MFAPIVKeyRequirements.SSHKeyTypes != nil {
			items := make([]zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsSSHKeyType, len(*input.MFAPIVKeyRequirements.SSHKeyTypes))
			for i, item := range *input.MFAPIVKeyRequirements.SSHKeyTypes {
				items[i] = updatePIVSSHKeyTypeToSDK(item)
			}
			value.SSHKeyType = cloudflaresdk.F(items)
		}
		if item := input.MFAPIVKeyRequirements.TouchPolicy; item != nil {
			if *item == "" {
				value.TouchPolicy = cloudflaresdk.Null[zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsTouchPolicy]()
			} else {
				value.TouchPolicy = cloudflaresdk.F(updatePIVTouchPolicyToSDK(*item))
			}
		}
		params.MfaPivKeyRequirements = cloudflaresdk.F(value)
	}
}

func applyOrganizationNewInput(params *zero_trust.OrganizationNewParams, input OrganizationInput) {
	if input.SessionDuration != nil {
		if *input.SessionDuration == "" {
			params.SessionDuration = cloudflaresdk.Null[string]()
		} else {
			params.SessionDuration = cloudflaresdk.F(*input.SessionDuration)
		}
	}
	if input.WARPAuthSessionDuration != nil {
		if *input.WARPAuthSessionDuration == "" {
			params.WARPAuthSessionDuration = cloudflaresdk.Null[string]()
		} else {
			params.WARPAuthSessionDuration = cloudflaresdk.F(*input.WARPAuthSessionDuration)
		}
	}
	if input.UIReadOnlyToggleReason != nil {
		if *input.UIReadOnlyToggleReason == "" {
			params.UIReadOnlyToggleReason = cloudflaresdk.Null[string]()
		} else {
			params.UIReadOnlyToggleReason = cloudflaresdk.F(*input.UIReadOnlyToggleReason)
		}
	}
	if input.UserSeatExpirationInactiveTime != nil {
		if *input.UserSeatExpirationInactiveTime == "" {
			params.UserSeatExpirationInactiveTime = cloudflaresdk.Null[string]()
		} else {
			params.UserSeatExpirationInactiveTime = cloudflaresdk.F(*input.UserSeatExpirationInactiveTime)
		}
	}
	if input.AllowAuthenticateViaWARP != nil {
		params.AllowAuthenticateViaWARP = cloudflaresdk.F(*input.AllowAuthenticateViaWARP)
	}
	if input.AutoRedirectToIdentity != nil {
		params.AutoRedirectToIdentity = cloudflaresdk.F(*input.AutoRedirectToIdentity)
	}
	if input.IsUIReadOnly != nil {
		params.IsUIReadOnly = cloudflaresdk.F(*input.IsUIReadOnly)
	}
	if input.DenyUnmatchedRequests != nil {
		params.DenyUnmatchedRequests = cloudflaresdk.F(*input.DenyUnmatchedRequests)
	}
	if input.DenyUnmatchedRequestsExemptedZoneNames != nil {
		params.DenyUnmatchedRequestsExemptedZoneNames = cloudflaresdk.F(slices.Clone(*input.DenyUnmatchedRequestsExemptedZoneNames))
	}
	if input.WARPAuthNonBrowser401 != nil {
		params.WARPAuthNonBrowser401 = cloudflaresdk.F(*input.WARPAuthNonBrowser401)
	}
	if input.MFARequiredForAllApps != nil {
		params.MfaRequiredForAllApps = cloudflaresdk.F(*input.MFARequiredForAllApps)
	}
	if input.LoginDesign != nil {
		value := zero_trust.LoginDesignParam{}
		if input.LoginDesign.BackgroundColor != nil {
			if *input.LoginDesign.BackgroundColor == "" {
				value.BackgroundColor = cloudflaresdk.Null[string]()
			} else {
				value.BackgroundColor = cloudflaresdk.F(*input.LoginDesign.BackgroundColor)
			}
		}
		if input.LoginDesign.FooterText != nil {
			if *input.LoginDesign.FooterText == "" {
				value.FooterText = cloudflaresdk.Null[string]()
			} else {
				value.FooterText = cloudflaresdk.F(*input.LoginDesign.FooterText)
			}
		}
		if input.LoginDesign.HeaderText != nil {
			if *input.LoginDesign.HeaderText == "" {
				value.HeaderText = cloudflaresdk.Null[string]()
			} else {
				value.HeaderText = cloudflaresdk.F(*input.LoginDesign.HeaderText)
			}
		}
		if input.LoginDesign.LogoPath != nil {
			if *input.LoginDesign.LogoPath == "" {
				value.LogoPath = cloudflaresdk.Null[string]()
			} else {
				value.LogoPath = cloudflaresdk.F(*input.LoginDesign.LogoPath)
			}
		}
		if input.LoginDesign.TextColor != nil {
			if *input.LoginDesign.TextColor == "" {
				value.TextColor = cloudflaresdk.Null[string]()
			} else {
				value.TextColor = cloudflaresdk.F(*input.LoginDesign.TextColor)
			}
		}
		params.LoginDesign = cloudflaresdk.F(value)
	}
	if input.MFAConfig != nil {
		value := zero_trust.OrganizationNewParamsMfaConfig{}
		if input.MFAConfig.AllowedAuthenticators != nil {
			items := make([]zero_trust.OrganizationNewParamsMfaConfigAllowedAuthenticator, len(*input.MFAConfig.AllowedAuthenticators))
			for i, item := range *input.MFAConfig.AllowedAuthenticators {
				items[i] = newMFAAuthenticatorToSDK(item)
			}
			value.AllowedAuthenticators = cloudflaresdk.F(items)
		}
		if input.MFAConfig.AMRMatchingSessionDuration != nil {
			if *input.MFAConfig.AMRMatchingSessionDuration == "" {
				value.AmrMatchingSessionDuration = cloudflaresdk.Null[string]()
			} else {
				value.AmrMatchingSessionDuration = cloudflaresdk.F(*input.MFAConfig.AMRMatchingSessionDuration)
			}
		}
		if input.MFAConfig.RequiredAAGUIDs != nil {
			if *input.MFAConfig.RequiredAAGUIDs == "" {
				value.RequiredAaguids = cloudflaresdk.Null[string]()
			} else {
				value.RequiredAaguids = cloudflaresdk.F(*input.MFAConfig.RequiredAAGUIDs)
			}
		}
		if input.MFAConfig.SessionDuration != nil {
			if *input.MFAConfig.SessionDuration == "" {
				value.SessionDuration = cloudflaresdk.Null[string]()
			} else {
				value.SessionDuration = cloudflaresdk.F(*input.MFAConfig.SessionDuration)
			}
		}
		params.MfaConfig = cloudflaresdk.F(value)
	}
	if input.MFAPIVKeyRequirements != nil {
		value := zero_trust.OrganizationNewParamsMfaPivKeyRequirements{}
		if item := input.MFAPIVKeyRequirements.PinPolicy; item != nil {
			if *item == "" {
				value.PinPolicy = cloudflaresdk.Null[zero_trust.OrganizationNewParamsMfaPivKeyRequirementsPinPolicy]()
			} else {
				value.PinPolicy = cloudflaresdk.F(newPIVPinPolicyToSDK(*item))
			}
		}
		if input.MFAPIVKeyRequirements.RequireFIPSDevice != nil {
			value.RequireFipsDevice = cloudflaresdk.F(*input.MFAPIVKeyRequirements.RequireFIPSDevice)
		}
		if input.MFAPIVKeyRequirements.SSHKeySizes != nil {
			items := make([]zero_trust.OrganizationNewParamsMfaPivKeyRequirementsSSHKeySize, len(*input.MFAPIVKeyRequirements.SSHKeySizes))
			for i, item := range *input.MFAPIVKeyRequirements.SSHKeySizes {
				items[i] = zero_trust.OrganizationNewParamsMfaPivKeyRequirementsSSHKeySize(item)
			}
			value.SSHKeySize = cloudflaresdk.F(items)
		}
		if input.MFAPIVKeyRequirements.SSHKeyTypes != nil {
			items := make([]zero_trust.OrganizationNewParamsMfaPivKeyRequirementsSSHKeyType, len(*input.MFAPIVKeyRequirements.SSHKeyTypes))
			for i, item := range *input.MFAPIVKeyRequirements.SSHKeyTypes {
				items[i] = newPIVSSHKeyTypeToSDK(item)
			}
			value.SSHKeyType = cloudflaresdk.F(items)
		}
		if item := input.MFAPIVKeyRequirements.TouchPolicy; item != nil {
			if *item == "" {
				value.TouchPolicy = cloudflaresdk.Null[zero_trust.OrganizationNewParamsMfaPivKeyRequirementsTouchPolicy]()
			} else {
				value.TouchPolicy = cloudflaresdk.F(newPIVTouchPolicyToSDK(*item))
			}
		}
		params.MfaPivKeyRequirements = cloudflaresdk.F(value)
	}
}

func organizationFromSDK(remote *zero_trust.Organization) Organization {
	if remote == nil {
		return Organization{}
	}
	authenticators := make([]OrganizationMFAAuthenticator, len(remote.MfaConfig.AllowedAuthenticators))
	for i, item := range remote.MfaConfig.AllowedAuthenticators {
		authenticators[i] = mfaAuthenticatorFromSDK(item)
	}
	keySizes := make([]int64, len(remote.MfaPivKeyRequirements.SSHKeySize))
	for i, item := range remote.MfaPivKeyRequirements.SSHKeySize {
		keySizes[i] = int64(item)
	}
	keyTypes := make([]OrganizationPIVSSHKeyType, len(remote.MfaPivKeyRequirements.SSHKeyType))
	for i, item := range remote.MfaPivKeyRequirements.SSHKeyType {
		keyTypes[i] = pivSSHKeyTypeFromSDK(item)
	}
	return Organization{
		AuthDomain:                             remote.AuthDomain,
		Name:                                   remote.Name,
		SessionDuration:                        remote.SessionDuration,
		WARPAuthSessionDuration:                remote.WARPAuthSessionDuration,
		AllowAuthenticateViaWARP:               remote.AllowAuthenticateViaWARP,
		AutoRedirectToIdentity:                 remote.AutoRedirectToIdentity,
		IsUIReadOnly:                           remote.IsUIReadOnly,
		UIReadOnlyToggleReason:                 remote.UIReadOnlyToggleReason,
		DenyUnmatchedRequests:                  remote.DenyUnmatchedRequests,
		DenyUnmatchedRequestsExemptedZoneNames: slices.Clone(remote.DenyUnmatchedRequestsExemptedZoneNames),
		WARPAuthNonBrowser401:                  remote.WARPAuthNonBrowser401,
		UserSeatExpirationInactiveTime:         remote.UserSeatExpirationInactiveTime,
		CustomPages: OrganizationCustomPages{
			Forbidden: remote.CustomPages.Forbidden, IdentityDenied: remote.CustomPages.IdentityDenied,
		},
		LoginDesign: OrganizationLoginDesign{
			BackgroundColor: remote.LoginDesign.BackgroundColor, FooterText: remote.LoginDesign.FooterText,
			HeaderText: remote.LoginDesign.HeaderText, LogoPath: remote.LoginDesign.LogoPath, TextColor: remote.LoginDesign.TextColor,
		},
		MFAConfig: OrganizationMFAConfig{
			AllowedAuthenticators: authenticators, AMRMatchingSessionDuration: remote.MfaConfig.AmrMatchingSessionDuration,
			RequiredAAGUIDs: remote.MfaConfig.RequiredAaguids, SessionDuration: remote.MfaConfig.SessionDuration,
		},
		MFAPIVKeyRequirements: OrganizationMFAPIVKeyRequirements{
			PinPolicy: pivPinPolicyFromSDK(remote.MfaPivKeyRequirements.PinPolicy), RequireFIPSDevice: remote.MfaPivKeyRequirements.RequireFipsDevice,
			SSHKeySizes: keySizes, SSHKeyTypes: keyTypes, TouchPolicy: pivTouchPolicyFromSDK(remote.MfaPivKeyRequirements.TouchPolicy),
		},
		MFARequiredForAllApps: remote.MfaRequiredForAllApps,
	}
}

func updateMFAAuthenticatorToSDK(value OrganizationMFAAuthenticator) zero_trust.OrganizationUpdateParamsMfaConfigAllowedAuthenticator {
	return zero_trust.OrganizationUpdateParamsMfaConfigAllowedAuthenticator(mfaAuthenticatorWireValue(value))
}
func newMFAAuthenticatorToSDK(value OrganizationMFAAuthenticator) zero_trust.OrganizationNewParamsMfaConfigAllowedAuthenticator {
	return zero_trust.OrganizationNewParamsMfaConfigAllowedAuthenticator(mfaAuthenticatorWireValue(value))
}
func mfaAuthenticatorWireValue(value OrganizationMFAAuthenticator) string {
	switch value {
	case OrganizationMFAAuthenticatorTOTP:
		return "totp"
	case OrganizationMFAAuthenticatorBiometrics:
		return "biometrics"
	case OrganizationMFAAuthenticatorSecurityKey:
		return "security_key"
	case OrganizationMFAAuthenticatorPIVKey:
		return "piv_key"
	case OrganizationMFAAuthenticatorSSHFIDO2Key:
		return "ssh_fido2_key"
	default:
		return string(value)
	}
}
func mfaAuthenticatorFromSDK(value zero_trust.OrganizationMfaConfigAllowedAuthenticator) OrganizationMFAAuthenticator {
	switch value {
	case zero_trust.OrganizationMfaConfigAllowedAuthenticatorTotp:
		return OrganizationMFAAuthenticatorTOTP
	case zero_trust.OrganizationMfaConfigAllowedAuthenticatorBiometrics:
		return OrganizationMFAAuthenticatorBiometrics
	case zero_trust.OrganizationMfaConfigAllowedAuthenticatorSecurityKey:
		return OrganizationMFAAuthenticatorSecurityKey
	case zero_trust.OrganizationMfaConfigAllowedAuthenticatorPivKey:
		return OrganizationMFAAuthenticatorPIVKey
	case zero_trust.OrganizationMfaConfigAllowedAuthenticatorSSHFido2Key:
		return OrganizationMFAAuthenticatorSSHFIDO2Key
	default:
		return OrganizationMFAAuthenticator(value)
	}
}

func updatePIVPinPolicyToSDK(value OrganizationPIVPinPolicy) zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsPinPolicy {
	return zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsPinPolicy(pivPinPolicyWireValue(value))
}
func newPIVPinPolicyToSDK(value OrganizationPIVPinPolicy) zero_trust.OrganizationNewParamsMfaPivKeyRequirementsPinPolicy {
	return zero_trust.OrganizationNewParamsMfaPivKeyRequirementsPinPolicy(pivPinPolicyWireValue(value))
}
func pivPinPolicyWireValue(value OrganizationPIVPinPolicy) string {
	switch value {
	case OrganizationPIVPinPolicyNever:
		return "never"
	case OrganizationPIVPinPolicyOnce:
		return "once"
	case OrganizationPIVPinPolicyAlways:
		return "always"
	default:
		return string(value)
	}
}
func pivPinPolicyFromSDK(value zero_trust.OrganizationMfaPivKeyRequirementsPinPolicy) OrganizationPIVPinPolicy {
	switch value {
	case zero_trust.OrganizationMfaPivKeyRequirementsPinPolicyNever:
		return OrganizationPIVPinPolicyNever
	case zero_trust.OrganizationMfaPivKeyRequirementsPinPolicyOnce:
		return OrganizationPIVPinPolicyOnce
	case zero_trust.OrganizationMfaPivKeyRequirementsPinPolicyAlways:
		return OrganizationPIVPinPolicyAlways
	default:
		return OrganizationPIVPinPolicy(value)
	}
}

func updatePIVSSHKeyTypeToSDK(value OrganizationPIVSSHKeyType) zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsSSHKeyType {
	return zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsSSHKeyType(pivSSHKeyTypeWireValue(value))
}
func newPIVSSHKeyTypeToSDK(value OrganizationPIVSSHKeyType) zero_trust.OrganizationNewParamsMfaPivKeyRequirementsSSHKeyType {
	return zero_trust.OrganizationNewParamsMfaPivKeyRequirementsSSHKeyType(pivSSHKeyTypeWireValue(value))
}
func pivSSHKeyTypeWireValue(value OrganizationPIVSSHKeyType) string {
	switch value {
	case OrganizationPIVSSHKeyTypeECDSA:
		return "ecdsa"
	case OrganizationPIVSSHKeyTypeEd25519:
		return "ed25519"
	case OrganizationPIVSSHKeyTypeRSA:
		return "rsa"
	default:
		return string(value)
	}
}
func pivSSHKeyTypeFromSDK(value zero_trust.OrganizationMfaPivKeyRequirementsSSHKeyType) OrganizationPIVSSHKeyType {
	switch value {
	case zero_trust.OrganizationMfaPivKeyRequirementsSSHKeyTypeEcdsa:
		return OrganizationPIVSSHKeyTypeECDSA
	case zero_trust.OrganizationMfaPivKeyRequirementsSSHKeyTypeEd25519:
		return OrganizationPIVSSHKeyTypeEd25519
	case zero_trust.OrganizationMfaPivKeyRequirementsSSHKeyTypeRSA:
		return OrganizationPIVSSHKeyTypeRSA
	default:
		return OrganizationPIVSSHKeyType(value)
	}
}

func updatePIVTouchPolicyToSDK(value OrganizationPIVTouchPolicy) zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsTouchPolicy {
	return zero_trust.OrganizationUpdateParamsMfaPivKeyRequirementsTouchPolicy(pivTouchPolicyWireValue(value))
}
func newPIVTouchPolicyToSDK(value OrganizationPIVTouchPolicy) zero_trust.OrganizationNewParamsMfaPivKeyRequirementsTouchPolicy {
	return zero_trust.OrganizationNewParamsMfaPivKeyRequirementsTouchPolicy(pivTouchPolicyWireValue(value))
}
func pivTouchPolicyWireValue(value OrganizationPIVTouchPolicy) string {
	switch value {
	case OrganizationPIVTouchPolicyNever:
		return "never"
	case OrganizationPIVTouchPolicyAlways:
		return "always"
	case OrganizationPIVTouchPolicyCached:
		return "cached"
	default:
		return string(value)
	}
}
func pivTouchPolicyFromSDK(value zero_trust.OrganizationMfaPivKeyRequirementsTouchPolicy) OrganizationPIVTouchPolicy {
	switch value {
	case zero_trust.OrganizationMfaPivKeyRequirementsTouchPolicyNever:
		return OrganizationPIVTouchPolicyNever
	case zero_trust.OrganizationMfaPivKeyRequirementsTouchPolicyAlways:
		return OrganizationPIVTouchPolicyAlways
	case zero_trust.OrganizationMfaPivKeyRequirementsTouchPolicyCached:
		return OrganizationPIVTouchPolicyCached
	default:
		return OrganizationPIVTouchPolicy(value)
	}
}
