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
	"reflect"
	"sort"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// AccessApplicationAPI is part of the Flareway API.
type AccessApplicationAPI interface {
	CreateAccessApplication(context.Context, AccessScope, AccessApplicationInput) (AccessApplicationCreateResult, error)
	UpdateAccessApplication(context.Context, AccessScope, string, AccessApplicationInput) (AccessApplication, error)
	GetAccessApplication(context.Context, AccessScope, string) (AccessApplication, error)
	ListAccessApplications(context.Context, AccessScope) ([]AccessApplication, error)
	DeleteAccessApplication(context.Context, AccessScope, string) error
	RevokeAccessApplicationTokens(context.Context, AccessScope, string) error
	EnsureBypassPolicy(context.Context, string) (AccessPolicy, error)
}

// AccessApplicationType is a Cloudflare Access application discriminator.
type AccessApplicationType string

const (
	// AccessApplicationTypeSelfHosted selects the self-hosted application variant.
	AccessApplicationTypeSelfHosted AccessApplicationType = "SelfHosted"
	// AccessApplicationTypeSaaS selects the SaaS application variant.
	AccessApplicationTypeSaaS AccessApplicationType = "SaaS"
	// AccessApplicationTypeSSH selects the browser-rendered SSH application variant.
	AccessApplicationTypeSSH AccessApplicationType = "SSH"
	// AccessApplicationTypeVNC selects the browser-rendered VNC application variant.
	AccessApplicationTypeVNC AccessApplicationType = "VNC"
	// AccessApplicationTypeRDP selects the browser-rendered RDP application variant.
	AccessApplicationTypeRDP AccessApplicationType = "RDP"
	// AccessApplicationTypeMCP selects the MCP server application variant.
	AccessApplicationTypeMCP AccessApplicationType = "MCP"
	// AccessApplicationTypeProxyEndpoint selects the proxy endpoint application variant.
	AccessApplicationTypeProxyEndpoint AccessApplicationType = "ProxyEndpoint"
	// AccessApplicationTypeBookmark selects the App Launcher bookmark variant.
	AccessApplicationTypeBookmark AccessApplicationType = "Bookmark"
	// AccessApplicationTypeInfrastructure selects the infrastructure application variant.
	AccessApplicationTypeInfrastructure AccessApplicationType = "Infrastructure"
	// AccessApplicationTypeAppLauncher selects the Access App Launcher variant.
	AccessApplicationTypeAppLauncher AccessApplicationType = "AppLauncher"
	// AccessApplicationTypeWARP selects the WARP application variant.
	AccessApplicationTypeWARP AccessApplicationType = "WARP"
	// AccessApplicationTypeBISO selects the browser isolation application variant.
	AccessApplicationTypeBISO AccessApplicationType = "BISO"
	// AccessApplicationTypeDashSSO selects the Cloudflare dashboard SSO variant.
	AccessApplicationTypeDashSSO AccessApplicationType = "DashSSO"
	// AccessApplicationTypeMCPPortal selects the MCP server portal variant.
	AccessApplicationTypeMCPPortal AccessApplicationType = "MCPPortal"
)

// AccessApplicationDestinationType identifies a destination union member.
type AccessApplicationDestinationType string

const (
	// AccessApplicationDestinationTypePublic selects a public hostname destination.
	AccessApplicationDestinationTypePublic AccessApplicationDestinationType = "Public"
	// AccessApplicationDestinationTypePrivate selects a private hostname or IP destination.
	AccessApplicationDestinationTypePrivate AccessApplicationDestinationType = "Private"
	// AccessApplicationDestinationTypeViaMCPServerPortal routes through an MCP server portal.
	AccessApplicationDestinationTypeViaMCPServerPortal AccessApplicationDestinationType = "ViaMCPServerPortal"
	// AccessApplicationDestinationTypeWorker selects a deployed Worker destination.
	AccessApplicationDestinationTypeWorker AccessApplicationDestinationType = "Worker"
	// AccessApplicationDestinationTypePreviewWorker selects a preview Worker destination.
	AccessApplicationDestinationTypePreviewWorker AccessApplicationDestinationType = "PreviewWorker"
	// AccessApplicationDestinationTypeAllWorkers selects all deployed Workers.
	AccessApplicationDestinationTypeAllWorkers AccessApplicationDestinationType = "AllWorkers"
	// AccessApplicationDestinationTypeAllPreviewWorkers selects all preview Workers.
	AccessApplicationDestinationTypeAllPreviewWorkers AccessApplicationDestinationType = "AllPreviewWorkers"
)

// AccessApplicationL4Protocol is a private destination transport protocol.
type AccessApplicationL4Protocol string

const (
	// AccessApplicationL4ProtocolTCP selects TCP transport.
	AccessApplicationL4ProtocolTCP AccessApplicationL4Protocol = "TCP"
	// AccessApplicationL4ProtocolUDP selects UDP transport.
	AccessApplicationL4ProtocolUDP AccessApplicationL4Protocol = "UDP"
)

// AccessApplicationDestination is part of the Flareway API.
type AccessApplicationDestination struct {
	Type        AccessApplicationDestinationType `json:"type"`
	URI         string                           `json:"uri,omitempty"`
	Hostname    string                           `json:"hostname,omitempty"`
	CIDR        string                           `json:"cidr,omitempty"`
	PortRange   string                           `json:"port_range,omitempty"`
	L4Protocol  AccessApplicationL4Protocol      `json:"l4_protocol,omitempty"`
	VNetID      string                           `json:"vnet_id,omitempty"`
	MCPServerID string                           `json:"mcp_server_id,omitempty"`
	WorkerID    string                           `json:"worker_id,omitempty"`
}

// AccessApplicationPolicyAttachment identifies an attached reusable policy.
type AccessApplicationPolicyAttachment struct {
	ID         string `json:"id"`
	Precedence int64  `json:"precedence,omitempty"`
}

// AccessApplicationMFAAuthenticator is an application MFA method.
type AccessApplicationMFAAuthenticator string

const (
	// AccessApplicationMFAAuthenticatorTOTP requires a time-based one-time password.
	AccessApplicationMFAAuthenticatorTOTP AccessApplicationMFAAuthenticator = "TOTP"
	// AccessApplicationMFAAuthenticatorBiometrics requires platform biometrics.
	AccessApplicationMFAAuthenticatorBiometrics AccessApplicationMFAAuthenticator = "Biometrics"
	// AccessApplicationMFAAuthenticatorSecurityKey requires a WebAuthn security key.
	AccessApplicationMFAAuthenticatorSecurityKey AccessApplicationMFAAuthenticator = "SecurityKey"
	// AccessApplicationMFAAuthenticatorPIVKey requires a PIV-backed SSH key.
	AccessApplicationMFAAuthenticatorPIVKey AccessApplicationMFAAuthenticator = "PIVKey"
	// AccessApplicationMFAAuthenticatorSSHFIDO2Key requires a FIDO2-backed SSH key.
	AccessApplicationMFAAuthenticatorSSHFIDO2Key AccessApplicationMFAAuthenticator = "SSHFIDO2Key"
)

// AccessApplicationMFAConfig configures application MFA.
type AccessApplicationMFAConfig struct {
	AllowedAuthenticators []AccessApplicationMFAAuthenticator `json:"allowed_authenticators,omitempty"`
	Disabled              *bool                               `json:"mfa_disabled,omitempty"`
	SessionDuration       string                              `json:"session_duration,omitempty"`
}

// AccessApplicationCORSHeaders is observable wire-compatible CORS state.
type AccessApplicationCORSHeaders struct {
	AllowAllHeaders  *bool                       `json:"allow_all_headers,omitempty"`
	AllowAllMethods  *bool                       `json:"allow_all_methods,omitempty"`
	AllowAllOrigins  *bool                       `json:"allow_all_origins,omitempty"`
	AllowCredentials *bool                       `json:"allow_credentials,omitempty"`
	AllowedHeaders   []string                    `json:"allowed_headers,omitempty"`
	AllowedMethods   []v1alpha1.AccessCORSMethod `json:"allowed_methods,omitempty"`
	AllowedOrigins   []string                    `json:"allowed_origins,omitempty"`
	MaxAge           *int64                      `json:"max_age,omitempty"`
}

// AccessApplicationOAuthConfiguration configures OAuth authorization-server behavior.
type AccessApplicationOAuthConfiguration struct {
	DynamicClientRegistration *AccessApplicationOAuthDynamicClientRegistration `json:"dynamic_client_registration,omitempty"`
	Enabled                   *bool                                            `json:"enabled,omitempty"`
	Grant                     *AccessApplicationOAuthGrant                     `json:"grant,omitempty"`
}

// AccessApplicationOAuthDynamicClientRegistration configures OAuth dynamic registration.
type AccessApplicationOAuthDynamicClientRegistration struct {
	AllowAnyOnLocalhost *bool    `json:"allow_any_on_localhost,omitempty"`
	AllowAnyOnLoopback  *bool    `json:"allow_any_on_loopback,omitempty"`
	AllowedURIs         []string `json:"allowed_uris,omitempty"`
	Enabled             *bool    `json:"enabled,omitempty"`
}

// AccessApplicationOAuthGrant configures issued OAuth tokens.
type AccessApplicationOAuthGrant struct {
	AccessTokenLifetime string `json:"access_token_lifetime,omitempty"`
	SessionDuration     string `json:"session_duration,omitempty"`
}

// AccessSCIMAuthenticationScheme is a SCIM authentication discriminator.
type AccessSCIMAuthenticationScheme string

const (
	// AccessSCIMAuthenticationSchemeHTTPBasic uses HTTP Basic credentials.
	AccessSCIMAuthenticationSchemeHTTPBasic AccessSCIMAuthenticationScheme = "HTTPBasic"
	// AccessSCIMAuthenticationSchemeOAuthBearerToken uses a static OAuth bearer token.
	AccessSCIMAuthenticationSchemeOAuthBearerToken AccessSCIMAuthenticationScheme = "OAuthBearerToken"
	// AccessSCIMAuthenticationSchemeOAuth2 uses OAuth 2 client credentials.
	AccessSCIMAuthenticationSchemeOAuth2 AccessSCIMAuthenticationScheme = "OAuth2"
	// AccessSCIMAuthenticationSchemeAccessServiceToken uses a Cloudflare Access service token.
	AccessSCIMAuthenticationSchemeAccessServiceToken AccessSCIMAuthenticationScheme = "AccessServiceToken"
)

// AccessSCIMAuthenticationInput contains SCIM credentials used only in requests.
type AccessSCIMAuthenticationInput struct {
	Scheme           AccessSCIMAuthenticationScheme
	User             string
	Password         string
	Token            string
	AuthorizationURL string
	ClientID         string
	ClientSecret     string
	TokenURL         string
	Scopes           []string
}

// AccessSCIMAuthentication is the non-secret observable SCIM authentication state.
type AccessSCIMAuthentication struct {
	Scheme           AccessSCIMAuthenticationScheme `json:"scheme"`
	User             string                         `json:"user,omitempty"`
	AuthorizationURL string                         `json:"authorization_url,omitempty"`
	ClientID         string                         `json:"client_id,omitempty"`
	TokenURL         string                         `json:"token_url,omitempty"`
	Scopes           []string                       `json:"scopes,omitempty"`
}

// AccessSCIMMappingStrictness controls handling of unknown SCIM attributes.
type AccessSCIMMappingStrictness string

const (
	// AccessSCIMMappingStrictnessStrict rejects attributes absent from the mapping.
	AccessSCIMMappingStrictnessStrict AccessSCIMMappingStrictness = "Strict"
	// AccessSCIMMappingStrictnessPassthrough preserves attributes absent from the mapping.
	AccessSCIMMappingStrictnessPassthrough AccessSCIMMappingStrictness = "Passthrough"
)

// AccessSCIMMapping configures a SCIM resource mapping.
type AccessSCIMMapping struct {
	Schema           string                       `json:"schema"`
	Enabled          *bool                        `json:"enabled,omitempty"`
	Filter           string                       `json:"filter,omitempty"`
	Operations       *AccessSCIMMappingOperations `json:"operations,omitempty"`
	Strictness       AccessSCIMMappingStrictness  `json:"strictness,omitempty"`
	TransformJSONata string                       `json:"transform_jsonata,omitempty"`
}

// AccessSCIMMappingOperations selects SCIM operations for a mapping.
type AccessSCIMMappingOperations struct {
	Create *bool `json:"create,omitempty"`
	Delete *bool `json:"delete,omitempty"`
	Update *bool `json:"update,omitempty"`
}

// AccessSCIMConfigInput configures SCIM provisioning, including request-only credentials.
type AccessSCIMConfigInput struct {
	IdentityProviderUID string
	RemoteURI           string
	Authentication      []AccessSCIMAuthenticationInput
	DeactivateOnDelete  *bool
	Enabled             *bool
	Mappings            []AccessSCIMMapping
}

// AccessSCIMConfig is the non-secret observable SCIM configuration.
type AccessSCIMConfig struct {
	IdentityProviderUID string                     `json:"idp_uid,omitempty"`
	Authentication      []AccessSCIMAuthentication `json:"authentication,omitempty"`
	DeactivateOnDelete  *bool                      `json:"deactivate_on_delete,omitempty"`
	Enabled             *bool                      `json:"enabled,omitempty"`
	Mappings            []AccessSCIMMapping        `json:"mappings,omitempty"`
}

// AccessSaaSAuthenticationType identifies a SaaS protocol.
type AccessSaaSAuthenticationType string

const (
	// AccessSaaSAuthenticationTypeSAML selects SAML authentication.
	AccessSaaSAuthenticationTypeSAML AccessSaaSAuthenticationType = "SAML"
	// AccessSaaSAuthenticationTypeOIDC selects OpenID Connect authentication.
	AccessSaaSAuthenticationTypeOIDC AccessSaaSAuthenticationType = "OIDC"
)

// AccessSaaSOIDCGrantType is an OIDC grant.
type AccessSaaSOIDCGrantType string

const (
	// AccessSaaSOIDCGrantTypeAuthorizationCode enables the authorization code flow.
	AccessSaaSOIDCGrantTypeAuthorizationCode AccessSaaSOIDCGrantType = "AuthorizationCode"
	// AccessSaaSOIDCGrantTypeAuthorizationCodeWithPKCE enables authorization code with PKCE.
	AccessSaaSOIDCGrantTypeAuthorizationCodeWithPKCE AccessSaaSOIDCGrantType = "AuthorizationCodeWithPKCE"
	// AccessSaaSOIDCGrantTypeRefreshTokens enables refresh token grants.
	AccessSaaSOIDCGrantTypeRefreshTokens AccessSaaSOIDCGrantType = "RefreshTokens"
	// AccessSaaSOIDCGrantTypeHybrid enables the OIDC hybrid flow.
	AccessSaaSOIDCGrantTypeHybrid AccessSaaSOIDCGrantType = "Hybrid"
	// AccessSaaSOIDCGrantTypeImplicit enables the OIDC implicit flow.
	AccessSaaSOIDCGrantTypeImplicit AccessSaaSOIDCGrantType = "Implicit"
)

// AccessSaaSOIDCScope is an OIDC scope.
type AccessSaaSOIDCScope string

const (
	// AccessSaaSOIDCScopeOpenID requests the OpenID Connect identity scope.
	AccessSaaSOIDCScopeOpenID AccessSaaSOIDCScope = "OpenID"
	// AccessSaaSOIDCScopeGroups requests group membership claims.
	AccessSaaSOIDCScopeGroups AccessSaaSOIDCScope = "Groups"
	// AccessSaaSOIDCScopeEmail requests email claims.
	AccessSaaSOIDCScopeEmail AccessSaaSOIDCScope = "Email"
	// AccessSaaSOIDCScopeProfile requests profile claims.
	AccessSaaSOIDCScopeProfile AccessSaaSOIDCScope = "Profile"
)

// AccessSaaSNameIDFormat is a SAML NameID format.
type AccessSaaSNameIDFormat string

const (
	// AccessSaaSNameIDFormatID emits an identifier as the SAML NameID.
	AccessSaaSNameIDFormatID AccessSaaSNameIDFormat = "ID"
	// AccessSaaSNameIDFormatEmail emits an email address as the SAML NameID.
	AccessSaaSNameIDFormatEmail AccessSaaSNameIDFormat = "Email"
)

// AccessSaaSAttributeNameFormat is a SAML attribute name format.
type AccessSaaSAttributeNameFormat string

const (
	// AccessSaaSAttributeNameFormatUnspecified uses the SAML unspecified name format.
	AccessSaaSAttributeNameFormatUnspecified AccessSaaSAttributeNameFormat = "Unspecified"
	// AccessSaaSAttributeNameFormatBasic uses the SAML basic name format.
	AccessSaaSAttributeNameFormatBasic AccessSaaSAttributeNameFormat = "Basic"
	// AccessSaaSAttributeNameFormatURI uses the SAML URI name format.
	AccessSaaSAttributeNameFormatURI AccessSaaSAttributeNameFormat = "URI"
)

// AccessSaaSApplicationInput contains all OIDC and SAML SaaS settings.
type AccessSaaSApplicationInput struct {
	AuthType                      AccessSaaSAuthenticationType
	AccessTokenLifetime           string
	AllowPKCEWithoutClientSecret  *bool
	AppLauncherURL                string
	ClientID                      string
	ClientSecret                  string
	CustomClaims                  []AccessSaaSOIDCCustomClaim
	GrantTypes                    []AccessSaaSOIDCGrantType
	GroupFilterRegex              string
	HybridAndImplicitOptions      *AccessSaaSOIDCHybridAndImplicitOptions
	PublicKey                     string
	RedirectURIs                  []string
	RefreshTokenOptions           *AccessSaaSOIDCRefreshTokenOptions
	Scopes                        []AccessSaaSOIDCScope
	ConsumerServiceURL            string
	CustomAttributes              []AccessSaaSSAMLCustomAttribute
	DefaultRelayState             string
	IdentityProviderEntityID      string
	NameIDFormat                  AccessSaaSNameIDFormat
	NameIDTransformJSONata        string
	SAMLAttributeTransformJSONata string
	ServiceProviderEntityID       string
	SSOEndpoint                   string
}

// AccessSaaSApplication is the non-secret observable SaaS configuration.
type AccessSaaSApplication struct {
	AuthType                      AccessSaaSAuthenticationType            `json:"auth_type,omitempty"`
	AccessTokenLifetime           string                                  `json:"access_token_lifetime,omitempty"`
	AllowPKCEWithoutClientSecret  *bool                                   `json:"allow_pkce_without_client_secret,omitempty"`
	AppLauncherURL                string                                  `json:"app_launcher_url,omitempty"`
	ClientID                      string                                  `json:"client_id,omitempty"`
	CustomClaims                  []AccessSaaSOIDCCustomClaim             `json:"custom_claims,omitempty"`
	GrantTypes                    []AccessSaaSOIDCGrantType               `json:"grant_types,omitempty"`
	GroupFilterRegex              string                                  `json:"group_filter_regex,omitempty"`
	HybridAndImplicitOptions      *AccessSaaSOIDCHybridAndImplicitOptions `json:"hybrid_and_implicit_options,omitempty"`
	PublicKey                     string                                  `json:"public_key,omitempty"`
	RedirectURIs                  []string                                `json:"redirect_uris,omitempty"`
	RefreshTokenOptions           *AccessSaaSOIDCRefreshTokenOptions      `json:"refresh_token_options,omitempty"`
	Scopes                        []AccessSaaSOIDCScope                   `json:"scopes,omitempty"`
	ConsumerServiceURL            string                                  `json:"consumer_service_url,omitempty"`
	CustomAttributes              []AccessSaaSSAMLCustomAttribute         `json:"custom_attributes,omitempty"`
	DefaultRelayState             string                                  `json:"default_relay_state,omitempty"`
	IdentityProviderEntityID      string                                  `json:"idp_entity_id,omitempty"`
	NameIDFormat                  AccessSaaSNameIDFormat                  `json:"name_id_format,omitempty"`
	NameIDTransformJSONata        string                                  `json:"name_id_transform_jsonata,omitempty"`
	SAMLAttributeTransformJSONata string                                  `json:"saml_attribute_transform_jsonata,omitempty"`
	ServiceProviderEntityID       string                                  `json:"sp_entity_id,omitempty"`
	SSOEndpoint                   string                                  `json:"sso_endpoint,omitempty"`
}

// AccessSaaSOIDCCustomClaim configures an OIDC custom claim.
type AccessSaaSOIDCCustomClaim struct {
	Name     string                      `json:"name,omitempty"`
	Required *bool                       `json:"required,omitempty"`
	Scope    AccessSaaSOIDCScope         `json:"scope,omitempty"`
	Source   *AccessSaaSOIDCCustomSource `json:"source,omitempty"`
}

// AccessSaaSOIDCCustomSource identifies the source IdP claim.
type AccessSaaSOIDCCustomSource struct {
	Name      string            `json:"name,omitempty"`
	NameByIDP map[string]string `json:"name_by_idp,omitempty"`
}

// AccessSaaSOIDCHybridAndImplicitOptions configures OIDC hybrid/implicit responses.
type AccessSaaSOIDCHybridAndImplicitOptions struct {
	ReturnAccessTokenFromAuthorizationEndpoint *bool `json:"return_access_token_from_authorization_endpoint,omitempty"`
	ReturnIDTokenFromAuthorizationEndpoint     *bool `json:"return_id_token_from_authorization_endpoint,omitempty"`
}

// AccessSaaSOIDCRefreshTokenOptions configures OIDC refresh tokens.
type AccessSaaSOIDCRefreshTokenOptions struct {
	Lifetime string `json:"lifetime,omitempty"`
}

// AccessSaaSSAMLCustomAttribute configures a SAML assertion attribute.
type AccessSaaSSAMLCustomAttribute struct {
	FriendlyName string                        `json:"friendly_name,omitempty"`
	Name         string                        `json:"name,omitempty"`
	NameFormat   AccessSaaSAttributeNameFormat `json:"name_format,omitempty"`
	Required     *bool                         `json:"required,omitempty"`
	Source       *AccessSaaSSAMLCustomSource   `json:"source,omitempty"`
}

// AccessSaaSSAMLCustomSource identifies source IdP attributes.
type AccessSaaSSAMLCustomSource struct {
	Name      string                              `json:"name,omitempty"`
	NameByIDP []AccessSaaSSAMLCustomSourceMapping `json:"name_by_idp,omitempty"`
}

// AccessSaaSSAMLCustomSourceMapping maps one IdP UID to a source attribute.
type AccessSaaSSAMLCustomSourceMapping struct {
	IdentityProviderID string `json:"idp_id,omitempty"`
	SourceName         string `json:"source_name,omitempty"`
}

// AccessApplicationFooterLink is an App Launcher footer link.
type AccessApplicationFooterLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// AccessApplicationLandingPageDesign configures the App Launcher landing page.
type AccessApplicationLandingPageDesign struct {
	ButtonColor     string `json:"button_color,omitempty"`
	ButtonTextColor string `json:"button_text_color,omitempty"`
	ImageURL        string `json:"image_url,omitempty"`
	Message         string `json:"message,omitempty"`
	Title           string `json:"title,omitempty"`
}

// AccessApplicationTargetProtocol identifies an infrastructure target protocol.
type AccessApplicationTargetProtocol string

const (
	// AccessApplicationTargetProtocolSSH selects SSH infrastructure targets.
	AccessApplicationTargetProtocolSSH AccessApplicationTargetProtocol = "SSH"
	// AccessApplicationTargetProtocolRDP selects RDP infrastructure targets.
	AccessApplicationTargetProtocolRDP AccessApplicationTargetProtocol = "RDP"
	// AccessApplicationTargetProtocolTCP selects raw TCP infrastructure targets.
	AccessApplicationTargetProtocolTCP AccessApplicationTargetProtocol = "TCP"
)

// AccessApplicationPolicyDecision is an Access policy action.
type AccessApplicationPolicyDecision string

const (
	// AccessApplicationPolicyDecisionAllow grants access when the policy matches.
	AccessApplicationPolicyDecisionAllow AccessApplicationPolicyDecision = "Allow"
	// AccessApplicationPolicyDecisionBlock denies access when the policy matches.
	AccessApplicationPolicyDecisionBlock AccessApplicationPolicyDecision = "Block"
	// AccessApplicationPolicyDecisionBypass skips Access enforcement when the policy matches.
	AccessApplicationPolicyDecisionBypass AccessApplicationPolicyDecision = "Bypass"
	// AccessApplicationPolicyDecisionServiceAuth requires service-token authentication.
	AccessApplicationPolicyDecisionServiceAuth AccessApplicationPolicyDecision = "ServiceAuth"
	// AccessApplicationPolicyDecisionNonIdentity grants access without an identity provider login.
	AccessApplicationPolicyDecisionNonIdentity AccessApplicationPolicyDecision = "NonIdentity"
)

// AccessApplicationTargetCriterion selects infrastructure targets.
type AccessApplicationTargetCriterion struct {
	Port             int64                           `json:"port"`
	Protocol         AccessApplicationTargetProtocol `json:"protocol"`
	TargetAttributes map[string][]string             `json:"target_attributes"`
}

// AccessInfrastructurePolicyInput defines an inline infrastructure policy.
type AccessInfrastructurePolicyInput struct {
	Name            string
	Decision        AccessApplicationPolicyDecision
	Include         []ResolvedAccessRule
	Require         []ResolvedAccessRule
	Exclude         []ResolvedAccessRule
	ConnectionRules *AccessInfrastructureConnectionRules
	MFAConfig       *AccessApplicationMFAConfig
}

// AccessInfrastructureConnectionRules contains protocol-specific connection rules.
type AccessInfrastructureConnectionRules struct {
	SSH *AccessInfrastructureSSHConnectionRules `json:"ssh,omitempty"`
	RDP *AccessInfrastructureRDPConnectionRules `json:"rdp,omitempty"`
}

// AccessInfrastructureSSHConnectionRules controls SSH user names.
type AccessInfrastructureSSHConnectionRules struct {
	Usernames       []string `json:"usernames,omitempty"`
	AllowEmailAlias *bool    `json:"allow_email_alias,omitempty"`
}

// AccessRDPClipboardFormat is a transferable RDP clipboard format.
type AccessRDPClipboardFormat string

const (
	// AccessRDPClipboardFormatText permits text clipboard transfers.
	AccessRDPClipboardFormatText AccessRDPClipboardFormat = "Text"
	// AccessRDPClipboardFormatFile permits file clipboard transfers.
	AccessRDPClipboardFormatFile AccessRDPClipboardFormat = "File"
)

// AccessInfrastructureRDPConnectionRules controls RDP clipboard formats.
type AccessInfrastructureRDPConnectionRules struct {
	AllowedClipboardLocalToRemoteFormats []AccessRDPClipboardFormat `json:"allowed_clipboard_local_to_remote_formats,omitempty"`
	AllowedClipboardRemoteToLocalFormats []AccessRDPClipboardFormat `json:"allowed_clipboard_remote_to_local_formats,omitempty"`
}

// AccessApplicationApprovalGroup is an observed temporary-access approver group.
type AccessApplicationApprovalGroup struct {
	ApprovalsNeeded int32    `json:"approvals_needed,omitempty"`
	EmailAddresses  []string `json:"email_addresses,omitempty"`
	EmailListID     string   `json:"email_list_uuid,omitempty"`
}

// AccessApplicationPolicy is mutable policy state returned with an application.
type AccessApplicationPolicy struct {
	ID                           string                               `json:"id,omitempty"`
	Name                         string                               `json:"name,omitempty"`
	Decision                     AccessApplicationPolicyDecision      `json:"decision,omitempty"`
	Precedence                   int64                                `json:"precedence,omitempty"`
	Include                      []map[string]any                     `json:"include,omitempty"`
	Require                      []map[string]any                     `json:"require,omitempty"`
	Exclude                      []map[string]any                     `json:"exclude,omitempty"`
	ConnectionRules              *AccessInfrastructureConnectionRules `json:"connection_rules,omitempty"`
	MFAConfig                    *AccessApplicationMFAConfig          `json:"mfa_config,omitempty"`
	ApprovalRequired             *bool                                `json:"approval_required,omitempty"`
	ApprovalGroups               []AccessApplicationApprovalGroup     `json:"approval_groups,omitempty"`
	IsolationRequired            *bool                                `json:"isolation_required,omitempty"`
	PurposeJustificationPrompt   string                               `json:"purpose_justification_prompt,omitempty"`
	PurposeJustificationRequired *bool                                `json:"purpose_justification_required,omitempty"`
	SessionDuration              string                               `json:"session_duration,omitempty"`
}

// AccessApplicationInput contains every mutable application field supported by cloudflare-go v7.10.0.
type AccessApplicationInput struct {
	Type                                 AccessApplicationType
	Domain                               string
	Name                                 string
	Destinations                         []AccessApplicationDestination
	Policies                             []AccessApplicationPolicyAttachment
	InfrastructurePolicies               []AccessInfrastructurePolicyInput
	AllowedIDPs                          []string
	SessionDuration                      string
	AllowAuthenticateViaWARP             *bool
	AllowIframe                          *bool
	SkipInterstitial                     *bool
	AutoRedirectToIdentity               *bool
	AppLauncherVisible                   *bool
	ServiceAuth401Redirect               *bool
	EnableBindingCookie                  *bool
	SameSiteCookieAttribute              v1alpha1.AccessSameSiteCookieAttribute
	EagerRedirectCookieSetting           *bool
	HTTPOnlyCookieAttribute              *bool
	PathCookieAttribute                  *bool
	OptionsPreflightBypass               *bool
	CORSHeaders                          *v1alpha1.AccessCORSHeaders
	ReadServiceTokensFromHeader          string
	CustomDenyMessage                    string
	CustomDenyURL                        string
	CustomNonIdentityDenyURL             string
	CustomPages                          []string
	Tags                                 []string
	LogoURL                              string
	SelfHostedDomains                    []string
	UseClientlessIsolationAppLauncherURL *bool
	MFAConfig                            *AccessApplicationMFAConfig
	OAuthConfiguration                   *AccessApplicationOAuthConfiguration
	SCIMConfig                           *AccessSCIMConfigInput
	SaaSApp                              *AccessSaaSApplicationInput
	TargetCriteria                       []AccessApplicationTargetCriterion
	AppLauncherLogoURL                   string
	BackgroundColor                      string
	FooterLinks                          []AccessApplicationFooterLink
	HeaderBackgroundColor                string
	LandingPageDesign                    *AccessApplicationLandingPageDesign
	SkipAppLauncherLoginPage             *bool
}

// AccessApplication is complete non-secret mutable application state.
type AccessApplication struct {
	ID                                   string                                 `json:"id,omitempty"`
	AUD                                  string                                 `json:"aud,omitempty"`
	Type                                 AccessApplicationType                  `json:"type,omitempty"`
	Domain                               string                                 `json:"domain,omitempty"`
	Name                                 string                                 `json:"name,omitempty"`
	Destinations                         []AccessApplicationDestination         `json:"destinations,omitempty"`
	Policies                             []AccessApplicationPolicy              `json:"policies,omitempty"`
	AllowedIDPs                          []string                               `json:"allowed_idps,omitempty"`
	SessionDuration                      string                                 `json:"session_duration,omitempty"`
	AllowAuthenticateViaWARP             *bool                                  `json:"allow_authenticate_via_warp,omitempty"`
	AllowIframe                          *bool                                  `json:"allow_iframe,omitempty"`
	SkipInterstitial                     *bool                                  `json:"skip_interstitial,omitempty"`
	AutoRedirectToIdentity               *bool                                  `json:"auto_redirect_to_identity,omitempty"`
	AppLauncherVisible                   *bool                                  `json:"app_launcher_visible,omitempty"`
	ServiceAuth401Redirect               *bool                                  `json:"service_auth_401_redirect,omitempty"`
	EnableBindingCookie                  *bool                                  `json:"enable_binding_cookie,omitempty"`
	EagerRedirectCookieSetting           *bool                                  `json:"eager_redirect_cookie_setting,omitempty"`
	HTTPOnlyCookieAttribute              *bool                                  `json:"http_only_cookie_attribute,omitempty"`
	SameSiteCookieAttribute              v1alpha1.AccessSameSiteCookieAttribute `json:"same_site_cookie_attribute,omitempty"`
	PathCookieAttribute                  *bool                                  `json:"path_cookie_attribute,omitempty"`
	OptionsPreflightBypass               *bool                                  `json:"options_preflight_bypass,omitempty"`
	CORSHeaders                          *AccessApplicationCORSHeaders          `json:"cors_headers,omitempty"`
	ReadServiceTokensFromHeader          string                                 `json:"read_service_tokens_from_header,omitempty"`
	CustomDenyMessage                    string                                 `json:"custom_deny_message,omitempty"`
	CustomDenyURL                        string                                 `json:"custom_deny_url,omitempty"`
	CustomNonIdentityDenyURL             string                                 `json:"custom_non_identity_deny_url,omitempty"`
	CustomPages                          []string                               `json:"custom_pages,omitempty"`
	Tags                                 []string                               `json:"tags,omitempty"`
	LogoURL                              string                                 `json:"logo_url,omitempty"`
	SelfHostedDomains                    []string                               `json:"self_hosted_domains,omitempty"`
	UseClientlessIsolationAppLauncherURL *bool                                  `json:"use_clientless_isolation_app_launcher_url,omitempty"`
	MFAConfig                            *AccessApplicationMFAConfig            `json:"mfa_config,omitempty"`
	OAuthConfiguration                   *AccessApplicationOAuthConfiguration   `json:"oauth_configuration,omitempty"`
	SCIMConfig                           *AccessSCIMConfig                      `json:"scim_config,omitempty"`
	SaaSApp                              *AccessSaaSApplication                 `json:"saas_app,omitempty"`
	TargetCriteria                       []AccessApplicationTargetCriterion     `json:"target_criteria,omitempty"`
	AppLauncherLogoURL                   string                                 `json:"app_launcher_logo_url,omitempty"`
	BackgroundColor                      string                                 `json:"bg_color,omitempty"`
	FooterLinks                          []AccessApplicationFooterLink          `json:"footer_links,omitempty"`
	HeaderBackgroundColor                string                                 `json:"header_bg_color,omitempty"`
	LandingPageDesign                    *AccessApplicationLandingPageDesign    `json:"landing_page_design,omitempty"`
	SkipAppLauncherLoginPage             *bool                                  `json:"skip_app_launcher_login_page,omitempty"`
}

// AccessApplicationCreateResult separates one-time credentials from observable state.
type AccessApplicationCreateResult struct {
	Application      AccessApplication
	SaaSClientSecret string
}

// AccessApplicationListing is one Access application as a drift sweep pass
// saw it, together with the other listings of the same pass that its
// references resolve against. Every map is built from a complete listing; a
// nil map means that listing was not taken in this pass.
type AccessApplicationListing struct {
	Application AccessApplication
	// Applications holds every application listed in the pass, by ID, so
	// bypass children can be checked alongside their parent.
	Applications map[string]AccessApplication
	// IdentityProviders holds the account's identity provider IDs.
	IdentityProviders map[string]struct{}
	// CustomPages holds the account's custom pages by ID.
	CustomPages map[string]AccessCustomPageSummary
}

// CreateAccessApplication is part of the Flareway API.
func (client *Client) CreateAccessApplication(ctx context.Context, scope AccessScope, input AccessApplicationInput) (AccessApplicationCreateResult, error) {
	body, err := accessApplicationNewBody(input)
	if err != nil {
		return AccessApplicationCreateResult{}, err
	}
	values, err := accessApplicationRequestValues(input)
	if err != nil {
		return AccessApplicationCreateResult{}, err
	}
	params := zero_trust.AccessApplicationNewParams{Body: body}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	result, err := client.sdk.ZeroTrust.Access.Applications.New(ctx, params, accessApplicationRequestOptions(values)...)
	if err != nil {
		return AccessApplicationCreateResult{}, fmt.Errorf("create Access application: %w", err)
	}
	raw := result.JSON.RawJSON()
	application := AccessApplication{}
	if raw != "" {
		application, err = decodeAccessApplication(raw)
		if err != nil {
			return AccessApplicationCreateResult{}, fmt.Errorf("decode created Access application: %w", err)
		}
	}
	// The generated SDK exposes create responses through a scope-dependent union.
	// Preserve its structured common fields when the raw projection is incomplete.
	if application.ID == "" {
		application.ID = result.ID
	}
	if application.Type == "" {
		application.Type = accessApplicationTypeFromWire(string(result.Type))
	}
	if application.Name == "" {
		application.Name = result.Name
	}
	if application.ID == "" {
		return AccessApplicationCreateResult{}, fmt.Errorf("create Access application returned an empty application ID")
	}
	secret := accessApplicationSaaSClientSecret(raw)
	if secret == "" {
		switch saas := result.SaaSApp.(type) {
		case zero_trust.AccessApplicationNewResponseSaaSApplicationSaaSApp:
			secret = saas.ClientSecret
		case *zero_trust.AccessApplicationNewResponseSaaSApplicationSaaSApp:
			secret = saas.ClientSecret
		}
	}
	return AccessApplicationCreateResult{Application: application, SaaSClientSecret: secret}, nil
}

// UpdateAccessApplication is part of the Flareway API.
func (client *Client) UpdateAccessApplication(ctx context.Context, scope AccessScope, id string, input AccessApplicationInput) (AccessApplication, error) {
	body, err := accessApplicationUpdateBody(input)
	if err != nil {
		return AccessApplication{}, err
	}
	values, err := accessApplicationRequestValues(input)
	if err != nil {
		return AccessApplication{}, err
	}
	params := zero_trust.AccessApplicationUpdateParams{Body: body}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	result, err := client.sdk.ZeroTrust.Access.Applications.Update(ctx, id, params, accessApplicationRequestOptions(values)...)
	if err != nil {
		return AccessApplication{}, fmt.Errorf("update Access application: %w", err)
	}
	application, err := decodeAccessApplication(result.JSON.RawJSON())
	if err != nil {
		return AccessApplication{}, fmt.Errorf("decode updated Access application: %w", err)
	}
	return application, nil
}

// GetAccessApplication is part of the Flareway API.
func (client *Client) GetAccessApplication(ctx context.Context, scope AccessScope, id string) (AccessApplication, error) {
	params := zero_trust.AccessApplicationGetParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	result, err := client.sdk.ZeroTrust.Access.Applications.Get(ctx, id, params)
	if err != nil {
		return AccessApplication{}, fmt.Errorf("get Access application: %w", err)
	}
	application, err := decodeAccessApplication(result.JSON.RawJSON())
	if err != nil {
		return AccessApplication{}, fmt.Errorf("decode Access application: %w", err)
	}
	return application, nil
}

// ListAccessApplications is part of the Flareway API.
func (client *Client) ListAccessApplications(ctx context.Context, scope AccessScope) ([]AccessApplication, error) {
	params := zero_trust.AccessApplicationListParams{PerPage: cloudflaresdk.F(int64(accessListPerPage))}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	pager := client.sdk.ZeroTrust.Access.Applications.ListAutoPaging(ctx, params)
	applications := make([]AccessApplication, 0)
	for pager.Next() {
		current := pager.Current()
		application, err := decodeAccessApplication(current.JSON.RawJSON())
		if err != nil {
			return nil, fmt.Errorf("decode listed Access application: %w", err)
		}
		applications = append(applications, application)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access applications: %w", err)
	}
	return applications, nil
}

// DeleteAccessApplication is part of the Flareway API.
func (client *Client) DeleteAccessApplication(ctx context.Context, scope AccessScope, id string) error {
	params := zero_trust.AccessApplicationDeleteParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	if _, err := client.sdk.ZeroTrust.Access.Applications.Delete(ctx, id, params); err != nil {
		return fmt.Errorf("delete Access application: %w", err)
	}
	return nil
}

// RevokeAccessApplicationTokens revokes every token issued for an application.
func (client *Client) RevokeAccessApplicationTokens(ctx context.Context, scope AccessScope, id string) error {
	params := zero_trust.AccessApplicationRevokeTokensParams{}
	applyAccessScope(client.accountID, scope, func(value string) { params.AccountID = cloudflaresdk.F(value) }, func(value string) { params.ZoneID = cloudflaresdk.F(value) })
	if _, err := client.sdk.ZeroTrust.Access.Applications.RevokeTokens(ctx, id, params); err != nil {
		return fmt.Errorf("revoke Access application tokens: %w", err)
	}
	return nil
}

func accessApplicationNewBody(input AccessApplicationInput) (zero_trust.AccessApplicationNewParamsBodyUnion, error) {
	wireType, err := accessApplicationTypeToWire(input.Type)
	if err != nil {
		return nil, err
	}
	switch input.Type {
	case AccessApplicationTypeSelfHosted:
		return zero_trust.AccessApplicationNewParamsBodySelfHostedApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeSaaS:
		return zero_trust.AccessApplicationNewParamsBodySaaSApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeSSH:
		return zero_trust.AccessApplicationNewParamsBodyBrowserSSHApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodyBrowserSSHApplicationType(wireType))}, nil
	case AccessApplicationTypeVNC:
		return zero_trust.AccessApplicationNewParamsBodyBrowserVNCApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodyBrowserVNCApplicationType(wireType))}, nil
	case AccessApplicationTypeRDP:
		return zero_trust.AccessApplicationNewParamsBodyBrowserRDPApplication{Domain: cloudflaresdk.F(input.Domain), TargetCriteria: cloudflaresdk.F(newRDPTargetCriteria(input.TargetCriteria)), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeMCP:
		return zero_trust.AccessApplicationNewParamsBodyMcpServerApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeMCPPortal:
		return zero_trust.AccessApplicationNewParamsBodyMcpServerPortalApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeProxyEndpoint, AccessApplicationTypeDashSSO:
		return zero_trust.AccessApplicationNewParamsBodyGatewayIdentityProxyEndpointApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeBookmark:
		return zero_trust.AccessApplicationNewParamsBodyBookmarkApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeInfrastructure:
		return zero_trust.AccessApplicationNewParamsBodyInfrastructureApplication{TargetCriteria: cloudflaresdk.F(newInfrastructureTargetCriteria(input.TargetCriteria)), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeAppLauncher:
		return zero_trust.AccessApplicationNewParamsBodyAppLauncherApplication{Type: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodyAppLauncherApplicationType(wireType))}, nil
	case AccessApplicationTypeWARP:
		return zero_trust.AccessApplicationNewParamsBodyDeviceEnrollmentPermissionsApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeBISO:
		return zero_trust.AccessApplicationNewParamsBodyBrowserIsolationPermissionsApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	default:
		return nil, fmt.Errorf("unsupported Access application type %q", input.Type)
	}
}

func accessApplicationUpdateBody(input AccessApplicationInput) (zero_trust.AccessApplicationUpdateParamsBodyUnion, error) {
	wireType, err := accessApplicationTypeToWire(input.Type)
	if err != nil {
		return nil, err
	}
	switch input.Type {
	case AccessApplicationTypeSelfHosted:
		return zero_trust.AccessApplicationUpdateParamsBodySelfHostedApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeSaaS:
		return zero_trust.AccessApplicationUpdateParamsBodySaaSApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeSSH:
		return zero_trust.AccessApplicationUpdateParamsBodyBrowserSSHApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodyBrowserSSHApplicationType(wireType))}, nil
	case AccessApplicationTypeVNC:
		return zero_trust.AccessApplicationUpdateParamsBodyBrowserVNCApplication{Domain: cloudflaresdk.F(input.Domain), Type: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodyBrowserVNCApplicationType(wireType))}, nil
	case AccessApplicationTypeRDP:
		return zero_trust.AccessApplicationUpdateParamsBodyBrowserRDPApplication{Domain: cloudflaresdk.F(input.Domain), TargetCriteria: cloudflaresdk.F(updateRDPTargetCriteria(input.TargetCriteria)), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeMCP:
		return zero_trust.AccessApplicationUpdateParamsBodyMcpServerApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeMCPPortal:
		return zero_trust.AccessApplicationUpdateParamsBodyMcpServerPortalApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeProxyEndpoint, AccessApplicationTypeDashSSO:
		return zero_trust.AccessApplicationUpdateParamsBodyGatewayIdentityProxyEndpointApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeBookmark:
		return zero_trust.AccessApplicationUpdateParamsBodyBookmarkApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeInfrastructure:
		return zero_trust.AccessApplicationUpdateParamsBodyInfrastructureApplication{TargetCriteria: cloudflaresdk.F(updateInfrastructureTargetCriteria(input.TargetCriteria)), Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeAppLauncher:
		return zero_trust.AccessApplicationUpdateParamsBodyAppLauncherApplication{Type: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodyAppLauncherApplicationType(wireType))}, nil
	case AccessApplicationTypeWARP:
		return zero_trust.AccessApplicationUpdateParamsBodyDeviceEnrollmentPermissionsApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	case AccessApplicationTypeBISO:
		return zero_trust.AccessApplicationUpdateParamsBodyBrowserIsolationPermissionsApplication{Type: cloudflaresdk.F(zero_trust.ApplicationType(wireType))}, nil
	default:
		return nil, fmt.Errorf("unsupported Access application type %q", input.Type)
	}
}

func newInfrastructureTargetCriteria(values []AccessApplicationTargetCriterion) []zero_trust.AccessApplicationNewParamsBodyInfrastructureApplicationTargetCriterion {
	result := make([]zero_trust.AccessApplicationNewParamsBodyInfrastructureApplicationTargetCriterion, len(values))
	for i, value := range values {
		result[i] = zero_trust.AccessApplicationNewParamsBodyInfrastructureApplicationTargetCriterion{Port: cloudflaresdk.F(value.Port), Protocol: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodyInfrastructureApplicationTargetCriteriaProtocol(accessTargetProtocolToWire(value.Protocol))), TargetAttributes: cloudflaresdk.F(value.TargetAttributes)}
	}
	return result
}

func updateInfrastructureTargetCriteria(values []AccessApplicationTargetCriterion) []zero_trust.AccessApplicationUpdateParamsBodyInfrastructureApplicationTargetCriterion {
	result := make([]zero_trust.AccessApplicationUpdateParamsBodyInfrastructureApplicationTargetCriterion, len(values))
	for i, value := range values {
		result[i] = zero_trust.AccessApplicationUpdateParamsBodyInfrastructureApplicationTargetCriterion{Port: cloudflaresdk.F(value.Port), Protocol: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodyInfrastructureApplicationTargetCriteriaProtocol(accessTargetProtocolToWire(value.Protocol))), TargetAttributes: cloudflaresdk.F(value.TargetAttributes)}
	}
	return result
}

func newRDPTargetCriteria(values []AccessApplicationTargetCriterion) []zero_trust.AccessApplicationNewParamsBodyBrowserRDPApplicationTargetCriterion {
	result := make([]zero_trust.AccessApplicationNewParamsBodyBrowserRDPApplicationTargetCriterion, len(values))
	for i, value := range values {
		result[i] = zero_trust.AccessApplicationNewParamsBodyBrowserRDPApplicationTargetCriterion{Port: cloudflaresdk.F(value.Port), Protocol: cloudflaresdk.F(zero_trust.AccessApplicationNewParamsBodyBrowserRDPApplicationTargetCriteriaProtocol(accessTargetProtocolToWire(value.Protocol))), TargetAttributes: cloudflaresdk.F(value.TargetAttributes)}
	}
	return result
}

func updateRDPTargetCriteria(values []AccessApplicationTargetCriterion) []zero_trust.AccessApplicationUpdateParamsBodyBrowserRDPApplicationTargetCriterion {
	result := make([]zero_trust.AccessApplicationUpdateParamsBodyBrowserRDPApplicationTargetCriterion, len(values))
	for i, value := range values {
		result[i] = zero_trust.AccessApplicationUpdateParamsBodyBrowserRDPApplicationTargetCriterion{Port: cloudflaresdk.F(value.Port), Protocol: cloudflaresdk.F(zero_trust.AccessApplicationUpdateParamsBodyBrowserRDPApplicationTargetCriteriaProtocol(accessTargetProtocolToWire(value.Protocol))), TargetAttributes: cloudflaresdk.F(value.TargetAttributes)}
	}
	return result
}

func accessApplicationRequestValues(input AccessApplicationInput) (map[string]any, error) {
	values := make(map[string]any)
	if input.Type != AccessApplicationTypeWARP {
		setAccessString(values, "name", input.Name)
	}
	setAccessSlice(values, "allowed_idps", input.AllowedIDPs)
	setAccessString(values, "session_duration", input.SessionDuration)
	setAccessOptionalBool(values, "allow_authenticate_via_warp", input.AllowAuthenticateViaWARP)
	setAccessOptionalBool(values, "allow_iframe", input.AllowIframe)
	setAccessOptionalBool(values, "skip_interstitial", input.SkipInterstitial)
	setAccessOptionalBool(values, "auto_redirect_to_identity", input.AutoRedirectToIdentity)
	setAccessOptionalBool(values, "app_launcher_visible", input.AppLauncherVisible)
	setAccessOptionalBool(values, "service_auth_401_redirect", input.ServiceAuth401Redirect)
	setAccessOptionalBool(values, "enable_binding_cookie", input.EnableBindingCookie)
	setAccessOptionalBool(values, "eager_redirect_cookie_setting", input.EagerRedirectCookieSetting)
	setAccessOptionalBool(values, "http_only_cookie_attribute", input.HTTPOnlyCookieAttribute)
	if input.SameSiteCookieAttribute != "" {
		values["same_site_cookie_attribute"] = accessSameSiteCookieToWire(input.SameSiteCookieAttribute)
	}
	setAccessOptionalBool(values, "path_cookie_attribute", input.PathCookieAttribute)
	setAccessOptionalBool(values, "options_preflight_bypass", input.OptionsPreflightBypass)
	setAccessString(values, "read_service_tokens_from_header", input.ReadServiceTokensFromHeader)
	setAccessString(values, "custom_deny_message", input.CustomDenyMessage)
	setAccessString(values, "custom_deny_url", input.CustomDenyURL)
	setAccessString(values, "custom_non_identity_deny_url", input.CustomNonIdentityDenyURL)
	setAccessSlice(values, "custom_pages", input.CustomPages)
	setAccessSlice(values, "tags", input.Tags)
	setAccessString(values, "logo_url", input.LogoURL)
	setAccessSlice(values, "self_hosted_domains", input.SelfHostedDomains)
	setAccessOptionalBool(values, "use_clientless_isolation_app_launcher_url", input.UseClientlessIsolationAppLauncherURL)
	if input.CORSHeaders != nil {
		values["cors_headers"] = accessCORSHeadersValue(input.CORSHeaders)
	}
	if len(input.Destinations) > 0 {
		values["destinations"] = accessDestinationValues(input.Destinations)
	}
	if len(input.Policies) > 0 {
		values["policies"] = input.Policies
	}
	if input.MFAConfig != nil {
		values["mfa_config"] = accessMFAConfigValue(input.MFAConfig)
	}
	if input.OAuthConfiguration != nil {
		values["oauth_configuration"] = accessOAuthConfigurationValue(input.OAuthConfiguration)
	}
	if input.SCIMConfig != nil {
		values["scim_config"] = accessSCIMConfigValue(input.SCIMConfig)
	}
	if input.SaaSApp != nil {
		values["saas_app"] = accessSaaSApplicationValue(input.SaaSApp)
	}
	if len(input.InfrastructurePolicies) > 0 {
		policies, err := accessInfrastructurePolicyValues(input.InfrastructurePolicies)
		if err != nil {
			return nil, err
		}
		values["policies"] = policies
	}
	if len(input.TargetCriteria) > 0 {
		values["target_criteria"] = accessTargetCriteriaValues(input.TargetCriteria)
	}
	setAccessString(values, "domain", input.Domain)
	setAccessString(values, "app_launcher_logo_url", input.AppLauncherLogoURL)
	setAccessString(values, "bg_color", input.BackgroundColor)
	setAccessSlice(values, "footer_links", input.FooterLinks)
	setAccessString(values, "header_bg_color", input.HeaderBackgroundColor)
	if input.LandingPageDesign != nil {
		values["landing_page_design"] = input.LandingPageDesign
	}
	setAccessOptionalBool(values, "skip_app_launcher_login_page", input.SkipAppLauncherLoginPage)
	return filterAccessApplicationRequestValues(input.Type, values), nil
}

func filterAccessApplicationRequestValues(applicationType AccessApplicationType, values map[string]any) map[string]any {
	common := []string{
		"name", "allowed_idps", "session_duration", "allow_authenticate_via_warp",
		"allow_iframe", "skip_interstitial", "auto_redirect_to_identity",
		"app_launcher_visible", "service_auth_401_redirect", "enable_binding_cookie",
		"eager_redirect_cookie_setting", "http_only_cookie_attribute",
		"same_site_cookie_attribute", "path_cookie_attribute", "options_preflight_bypass",
		"read_service_tokens_from_header", "custom_deny_message", "custom_deny_url",
		"custom_non_identity_deny_url", "custom_pages", "tags", "logo_url",
		"self_hosted_domains", "use_clientless_isolation_app_launcher_url",
		"cors_headers", "destinations", "policies", "mfa_config",
		"oauth_configuration", "scim_config", "domain",
	}
	allowed := make(map[string]struct{})
	add := func(keys ...string) {
		for _, key := range keys {
			allowed[key] = struct{}{}
		}
	}
	switch applicationType {
	case AccessApplicationTypeSelfHosted, AccessApplicationTypeSSH, AccessApplicationTypeVNC, AccessApplicationTypeRDP:
		add(common...)
		if applicationType == AccessApplicationTypeRDP {
			add("target_criteria")
		}
	case AccessApplicationTypeMCP:
		add("name", "allowed_idps", "session_duration", "allow_authenticate_via_warp",
			"auto_redirect_to_identity", "http_only_cookie_attribute",
			"same_site_cookie_attribute", "options_preflight_bypass",
			"custom_deny_message", "custom_deny_url", "custom_non_identity_deny_url",
			"custom_pages", "tags", "logo_url", "destinations", "policies",
			"oauth_configuration", "scim_config")
	case AccessApplicationTypeMCPPortal:
		add("name", "domain", "allowed_idps", "session_duration", "allow_authenticate_via_warp",
			"auto_redirect_to_identity", "http_only_cookie_attribute",
			"same_site_cookie_attribute", "options_preflight_bypass",
			"custom_deny_message", "custom_deny_url", "custom_non_identity_deny_url",
			"custom_pages", "tags", "logo_url", "destinations", "policies",
			"oauth_configuration", "scim_config")
	case AccessApplicationTypeSaaS:
		add("name", "allowed_idps", "app_launcher_visible", "auto_redirect_to_identity",
			"custom_pages", "logo_url", "policies", "saas_app", "scim_config", "tags")
	case AccessApplicationTypeBookmark:
		add("name", "domain", "app_launcher_visible", "logo_url", "policies", "tags")
	case AccessApplicationTypeInfrastructure:
		add("name", "target_criteria", "mfa_config", "policies")
	case AccessApplicationTypeAppLauncher:
		add("allowed_idps", "session_duration", "auto_redirect_to_identity",
			"custom_deny_url", "custom_non_identity_deny_url", "custom_pages", "policies",
			"app_launcher_logo_url", "bg_color", "footer_links", "header_bg_color",
			"landing_page_design", "skip_app_launcher_login_page")
	case AccessApplicationTypeWARP:
		add("allowed_idps", "session_duration", "auto_redirect_to_identity",
			"custom_deny_url", "custom_non_identity_deny_url", "custom_pages", "policies")
	case AccessApplicationTypeBISO:
		add("allowed_idps", "session_duration", "auto_redirect_to_identity",
			"custom_deny_url", "custom_non_identity_deny_url", "custom_pages", "policies")
	case AccessApplicationTypeDashSSO, AccessApplicationTypeProxyEndpoint:
		add("name", "domain", "allowed_idps", "session_duration", "auto_redirect_to_identity",
			"custom_deny_url", "custom_non_identity_deny_url", "custom_pages", "policies")
	}
	for key := range values {
		if _, ok := allowed[key]; !ok {
			delete(values, key)
		}
	}
	return values
}

func accessApplicationRequestOptions(values map[string]any) []option.RequestOption {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	options := make([]option.RequestOption, 0, len(keys)+1)
	for _, key := range keys {
		options = append(options, option.WithJSONSet(key, values[key]))
	}
	// The typed SDK bodies mark domain as required and would serialize an empty
	// string; the API rejects a domain that is not a public destination, so the
	// key must be absent from the wire payload when no domain was requested.
	if _, found := values["domain"]; !found {
		options = append(options, option.WithJSONDel("domain"))
	}
	return options
}

func accessDestinationValues(values []AccessApplicationDestination) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		destination := map[string]any{"type": accessDestinationTypeToWire(value.Type)}
		setAccessString(destination, "uri", value.URI)
		setAccessString(destination, "hostname", value.Hostname)
		setAccessString(destination, "cidr", value.CIDR)
		setAccessString(destination, "port_range", value.PortRange)
		if value.L4Protocol != "" {
			destination["l4_protocol"] = accessL4ProtocolToWire(value.L4Protocol)
		}
		setAccessString(destination, "vnet_id", value.VNetID)
		setAccessString(destination, "mcp_server_id", value.MCPServerID)
		setAccessString(destination, "worker_id", value.WorkerID)
		result = append(result, destination)
	}
	return result
}

func accessTargetCriteriaValues(values []AccessApplicationTargetCriterion) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"port":              value.Port,
			"protocol":          accessTargetProtocolToWire(value.Protocol),
			"target_attributes": value.TargetAttributes,
		})
	}
	return result
}

func accessCORSHeadersValue(value *v1alpha1.AccessCORSHeaders) map[string]any {
	result := make(map[string]any)
	setAccessOptionalBool(result, "allow_all_headers", value.AllowAllHeaders)
	setAccessOptionalBool(result, "allow_all_methods", value.AllowAllMethods)
	setAccessOptionalBool(result, "allow_all_origins", value.AllowAllOrigins)
	setAccessOptionalBool(result, "allow_credentials", value.AllowCredentials)
	setAccessSlice(result, "allowed_headers", value.AllowedHeaders)
	setAccessSlice(result, "allowed_methods", value.AllowedMethods)
	setAccessSlice(result, "allowed_origins", value.AllowedOrigins)
	if value.MaxAge != nil {
		result["max_age"] = *value.MaxAge
	}
	return result
}

func accessMFAConfigValue(value *AccessApplicationMFAConfig) map[string]any {
	result := make(map[string]any)
	if len(value.AllowedAuthenticators) > 0 {
		authenticators := make([]string, len(value.AllowedAuthenticators))
		for i := range value.AllowedAuthenticators {
			authenticators[i] = accessMFAAuthenticatorToWire(value.AllowedAuthenticators[i])
		}
		result["allowed_authenticators"] = authenticators
	}
	setAccessOptionalBool(result, "mfa_disabled", value.Disabled)
	setAccessString(result, "session_duration", value.SessionDuration)
	return result
}

func accessOAuthConfigurationValue(value *AccessApplicationOAuthConfiguration) map[string]any {
	result := make(map[string]any)
	setAccessOptionalBool(result, "enabled", value.Enabled)
	if value.DynamicClientRegistration != nil {
		dynamic := make(map[string]any)
		setAccessOptionalBool(dynamic, "allow_any_on_localhost", value.DynamicClientRegistration.AllowAnyOnLocalhost)
		setAccessOptionalBool(dynamic, "allow_any_on_loopback", value.DynamicClientRegistration.AllowAnyOnLoopback)
		setAccessSlice(dynamic, "allowed_uris", value.DynamicClientRegistration.AllowedURIs)
		setAccessOptionalBool(dynamic, "enabled", value.DynamicClientRegistration.Enabled)
		result["dynamic_client_registration"] = dynamic
	}
	if value.Grant != nil {
		grant := make(map[string]any)
		setAccessString(grant, "access_token_lifetime", value.Grant.AccessTokenLifetime)
		setAccessString(grant, "session_duration", value.Grant.SessionDuration)
		result["grant"] = grant
	}
	return result
}

func accessSCIMConfigValue(value *AccessSCIMConfigInput) map[string]any {
	result := make(map[string]any)
	setAccessString(result, "idp_uid", value.IdentityProviderUID)
	setAccessString(result, "remote_uri", value.RemoteURI)
	setAccessOptionalBool(result, "deactivate_on_delete", value.DeactivateOnDelete)
	setAccessOptionalBool(result, "enabled", value.Enabled)
	if len(value.Mappings) > 0 {
		mappings := make([]map[string]any, 0, len(value.Mappings))
		for _, value := range value.Mappings {
			mapping := make(map[string]any)
			setAccessString(mapping, "schema", value.Schema)
			setAccessOptionalBool(mapping, "enabled", value.Enabled)
			setAccessString(mapping, "filter", value.Filter)
			if value.Operations != nil {
				operations := make(map[string]any)
				setAccessOptionalBool(operations, "create", value.Operations.Create)
				setAccessOptionalBool(operations, "delete", value.Operations.Delete)
				setAccessOptionalBool(operations, "update", value.Operations.Update)
				mapping["operations"] = operations
			}
			if value.Strictness != "" {
				mapping["strictness"] = accessSCIMStrictnessToWire(value.Strictness)
			}
			setAccessString(mapping, "transform_jsonata", value.TransformJSONata)
			mappings = append(mappings, mapping)
		}
		result["mappings"] = mappings
	}
	if len(value.Authentication) == 1 {
		result["authentication"] = accessSCIMAuthenticationValue(value.Authentication[0])
	} else if len(value.Authentication) > 1 {
		authentication := make([]map[string]any, 0, len(value.Authentication))
		for _, item := range value.Authentication {
			authentication = append(authentication, accessSCIMAuthenticationValue(item))
		}
		result["authentication"] = authentication
	}
	return result
}

func accessSCIMAuthenticationValue(value AccessSCIMAuthenticationInput) map[string]any {
	result := map[string]any{"scheme": accessSCIMAuthenticationSchemeToWire(value.Scheme)}
	setAccessString(result, "user", value.User)
	setAccessString(result, "password", value.Password)
	setAccessString(result, "token", value.Token)
	setAccessString(result, "authorization_url", value.AuthorizationURL)
	setAccessString(result, "client_id", value.ClientID)
	setAccessString(result, "client_secret", value.ClientSecret)
	setAccessString(result, "token_url", value.TokenURL)
	setAccessSlice(result, "scopes", value.Scopes)
	return result
}

func accessSaaSApplicationValue(value *AccessSaaSApplicationInput) map[string]any {
	result := make(map[string]any)
	if value.AuthType != "" {
		result["auth_type"] = accessSaaSAuthenticationTypeToWire(value.AuthType)
	}
	setAccessString(result, "access_token_lifetime", value.AccessTokenLifetime)
	setAccessOptionalBool(result, "allow_pkce_without_client_secret", value.AllowPKCEWithoutClientSecret)
	setAccessString(result, "app_launcher_url", value.AppLauncherURL)
	setAccessString(result, "client_id", value.ClientID)
	setAccessString(result, "client_secret", value.ClientSecret)
	if len(value.CustomClaims) > 0 {
		claims := make([]map[string]any, 0, len(value.CustomClaims))
		for _, value := range value.CustomClaims {
			claim := make(map[string]any)
			setAccessString(claim, "name", value.Name)
			setAccessOptionalBool(claim, "required", value.Required)
			if value.Scope != "" {
				claim["scope"] = accessSaaSOIDCScopeToWire(value.Scope)
			}
			if value.Source != nil {
				claim["source"] = value.Source
			}
			claims = append(claims, claim)
		}
		result["custom_claims"] = claims
	}
	if len(value.GrantTypes) > 0 {
		grants := make([]string, len(value.GrantTypes))
		for i := range value.GrantTypes {
			grants[i] = accessSaaSOIDCGrantTypeToWire(value.GrantTypes[i])
		}
		result["grant_types"] = grants
	}
	setAccessString(result, "group_filter_regex", value.GroupFilterRegex)
	if value.HybridAndImplicitOptions != nil {
		result["hybrid_and_implicit_options"] = value.HybridAndImplicitOptions
	}
	setAccessString(result, "public_key", value.PublicKey)
	setAccessSlice(result, "redirect_uris", value.RedirectURIs)
	if value.RefreshTokenOptions != nil {
		result["refresh_token_options"] = value.RefreshTokenOptions
	}
	if len(value.Scopes) > 0 {
		scopes := make([]string, len(value.Scopes))
		for i := range value.Scopes {
			scopes[i] = accessSaaSOIDCScopeToWire(value.Scopes[i])
		}
		result["scopes"] = scopes
	}
	setAccessString(result, "consumer_service_url", value.ConsumerServiceURL)
	if len(value.CustomAttributes) > 0 {
		attributes := make([]map[string]any, 0, len(value.CustomAttributes))
		for _, value := range value.CustomAttributes {
			attribute := make(map[string]any)
			setAccessString(attribute, "friendly_name", value.FriendlyName)
			setAccessString(attribute, "name", value.Name)
			if value.NameFormat != "" {
				attribute["name_format"] = accessSaaSAttributeNameFormatToWire(value.NameFormat)
			}
			setAccessOptionalBool(attribute, "required", value.Required)
			if value.Source != nil {
				attribute["source"] = value.Source
			}
			attributes = append(attributes, attribute)
		}
		result["custom_attributes"] = attributes
	}
	setAccessString(result, "default_relay_state", value.DefaultRelayState)
	setAccessString(result, "idp_entity_id", value.IdentityProviderEntityID)
	if value.NameIDFormat != "" {
		result["name_id_format"] = accessSaaSNameIDFormatToWire(value.NameIDFormat)
	}
	setAccessString(result, "name_id_transform_jsonata", value.NameIDTransformJSONata)
	setAccessString(result, "saml_attribute_transform_jsonata", value.SAMLAttributeTransformJSONata)
	setAccessString(result, "sp_entity_id", value.ServiceProviderEntityID)
	setAccessString(result, "sso_endpoint", value.SSOEndpoint)
	return result
}

func accessInfrastructurePolicyValues(values []AccessInfrastructurePolicyInput) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		include, err := AccessRulesToSDK(value.Include)
		if err != nil {
			return nil, fmt.Errorf("convert infrastructure policy %q include rules: %w", value.Name, err)
		}
		require, err := AccessRulesToSDK(value.Require)
		if err != nil {
			return nil, fmt.Errorf("convert infrastructure policy %q require rules: %w", value.Name, err)
		}
		exclude, err := AccessRulesToSDK(value.Exclude)
		if err != nil {
			return nil, fmt.Errorf("convert infrastructure policy %q exclude rules: %w", value.Name, err)
		}
		policy := make(map[string]any)
		setAccessString(policy, "name", value.Name)
		if value.Decision != "" {
			policy["decision"] = accessPolicyDecisionToWire(value.Decision)
		}
		setAccessSlice(policy, "include", include)
		setAccessSlice(policy, "require", require)
		setAccessSlice(policy, "exclude", exclude)
		if value.ConnectionRules != nil {
			policy["connection_rules"] = accessInfrastructureConnectionRulesValue(value.ConnectionRules)
		}
		if value.MFAConfig != nil {
			policy["mfa_config"] = accessMFAConfigValue(value.MFAConfig)
		}
		result = append(result, policy)
	}
	return result, nil
}

func accessInfrastructureConnectionRulesValue(value *AccessInfrastructureConnectionRules) map[string]any {
	result := make(map[string]any)
	if value.SSH != nil {
		ssh := make(map[string]any)
		setAccessSlice(ssh, "usernames", value.SSH.Usernames)
		setAccessOptionalBool(ssh, "allow_email_alias", value.SSH.AllowEmailAlias)
		result["ssh"] = ssh
	}
	if value.RDP != nil {
		rdp := make(map[string]any)
		if len(value.RDP.AllowedClipboardLocalToRemoteFormats) > 0 {
			formats := make([]string, len(value.RDP.AllowedClipboardLocalToRemoteFormats))
			for i := range value.RDP.AllowedClipboardLocalToRemoteFormats {
				formats[i] = accessRDPClipboardFormatToWire(value.RDP.AllowedClipboardLocalToRemoteFormats[i])
			}
			rdp["allowed_clipboard_local_to_remote_formats"] = formats
		}
		if len(value.RDP.AllowedClipboardRemoteToLocalFormats) > 0 {
			formats := make([]string, len(value.RDP.AllowedClipboardRemoteToLocalFormats))
			for i := range value.RDP.AllowedClipboardRemoteToLocalFormats {
				formats[i] = accessRDPClipboardFormatToWire(value.RDP.AllowedClipboardRemoteToLocalFormats[i])
			}
			rdp["allowed_clipboard_remote_to_local_formats"] = formats
		}
		result["rdp"] = rdp
	}
	return result
}

func normalizeAccessRDPClipboardFormats(value *AccessInfrastructureRDPConnectionRules) {
	for i := range value.AllowedClipboardLocalToRemoteFormats {
		value.AllowedClipboardLocalToRemoteFormats[i] = accessRDPClipboardFormatFromWire(string(value.AllowedClipboardLocalToRemoteFormats[i]))
	}
	for i := range value.AllowedClipboardRemoteToLocalFormats {
		value.AllowedClipboardRemoteToLocalFormats[i] = accessRDPClipboardFormatFromWire(string(value.AllowedClipboardRemoteToLocalFormats[i]))
	}
}

func decodeAccessApplication(raw string) (AccessApplication, error) {
	var result AccessApplication
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return AccessApplication{}, err
	}
	result.Type = accessApplicationTypeFromWire(string(result.Type))
	result.SameSiteCookieAttribute = accessSameSiteCookieFromWire(string(result.SameSiteCookieAttribute))
	for i := range result.Destinations {
		result.Destinations[i].Type = accessDestinationTypeFromWire(string(result.Destinations[i].Type))
		result.Destinations[i].L4Protocol = accessL4ProtocolFromWire(string(result.Destinations[i].L4Protocol))
	}
	normalizeAccessMFA(result.MFAConfig)
	if result.SaaSApp != nil {
		result.SaaSApp.AuthType = accessSaaSAuthenticationTypeFromWire(string(result.SaaSApp.AuthType))
		result.SaaSApp.NameIDFormat = accessSaaSNameIDFormatFromWire(string(result.SaaSApp.NameIDFormat))
		for i := range result.SaaSApp.GrantTypes {
			result.SaaSApp.GrantTypes[i] = accessSaaSOIDCGrantTypeFromWire(string(result.SaaSApp.GrantTypes[i]))
		}
		for i := range result.SaaSApp.Scopes {
			result.SaaSApp.Scopes[i] = accessSaaSOIDCScopeFromWire(string(result.SaaSApp.Scopes[i]))
		}
		for i := range result.SaaSApp.CustomClaims {
			result.SaaSApp.CustomClaims[i].Scope = accessSaaSOIDCScopeFromWire(string(result.SaaSApp.CustomClaims[i].Scope))
		}
		for i := range result.SaaSApp.CustomAttributes {
			result.SaaSApp.CustomAttributes[i].NameFormat = accessSaaSAttributeNameFormatFromWire(string(result.SaaSApp.CustomAttributes[i].NameFormat))
		}
	}
	if result.SCIMConfig != nil {
		for i := range result.SCIMConfig.Authentication {
			result.SCIMConfig.Authentication[i].Scheme = accessSCIMAuthenticationSchemeFromWire(string(result.SCIMConfig.Authentication[i].Scheme))
		}
		for i := range result.SCIMConfig.Mappings {
			result.SCIMConfig.Mappings[i].Strictness = accessSCIMStrictnessFromWire(string(result.SCIMConfig.Mappings[i].Strictness))
		}
	}
	for i := range result.TargetCriteria {
		result.TargetCriteria[i].Protocol = accessTargetProtocolFromWire(string(result.TargetCriteria[i].Protocol))
	}
	for i := range result.Policies {
		normalizeAccessMFA(result.Policies[i].MFAConfig)
		result.Policies[i].Decision = accessPolicyDecisionFromWire(string(result.Policies[i].Decision))
		if result.Policies[i].ConnectionRules != nil && result.Policies[i].ConnectionRules.RDP != nil {
			normalizeAccessRDPClipboardFormats(result.Policies[i].ConnectionRules.RDP)
		}
	}
	return result, nil
}

// UnmarshalJSON accepts SCIM authentication as either a single object or an array.
func (config *AccessSCIMConfig) UnmarshalJSON(data []byte) error {
	type plain AccessSCIMConfig
	var value struct {
		plain
		Authentication json.RawMessage `json:"authentication"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*config = AccessSCIMConfig(value.plain)
	if len(value.Authentication) == 0 || string(value.Authentication) == "null" {
		return nil
	}
	if value.Authentication[0] == '[' {
		return json.Unmarshal(value.Authentication, &config.Authentication)
	}
	var authentication AccessSCIMAuthentication
	if err := json.Unmarshal(value.Authentication, &authentication); err != nil {
		return err
	}
	config.Authentication = []AccessSCIMAuthentication{authentication}
	return nil
}

func accessApplicationSaaSClientSecret(raw string) string {
	var value struct {
		SaaSApp struct {
			ClientSecret string `json:"client_secret"`
		} `json:"saas_app"`
	}
	_ = json.Unmarshal([]byte(raw), &value)
	return value.SaaSApp.ClientSecret
}

func normalizeAccessMFA(value *AccessApplicationMFAConfig) {
	if value == nil {
		return
	}
	for i := range value.AllowedAuthenticators {
		value.AllowedAuthenticators[i] = accessMFAAuthenticatorFromWire(string(value.AllowedAuthenticators[i]))
	}
}

// AccessApplicationMatchesInput compares every desired mutable field while ignoring
// response-only metadata and write-only credentials.
func AccessApplicationMatchesInput(observed AccessApplication, input AccessApplicationInput) bool {
	expected, err := accessApplicationRequestValues(input)
	if err != nil {
		return false
	}
	wireType, err := accessApplicationTypeToWire(input.Type)
	if err != nil {
		return false
	}
	expected["type"] = wireType
	stripAccessApplicationSecrets(expected)
	expectedValues, ok := accessJSONValue(expected).(map[string]any)
	if !ok {
		return false
	}

	data, err := json.Marshal(observed)
	if err != nil {
		return false
	}
	var actual map[string]any
	if err := json.Unmarshal(data, &actual); err != nil {
		return false
	}
	normalizeAccessApplicationWireMap(actual)
	normalizeAccessApplicationSetValues(expectedValues)
	normalizeAccessApplicationSetValues(actual)
	return accessSubsetEqual(expectedValues, actual)
}

func stripAccessApplicationSecrets(values map[string]any) {
	if saas, ok := values["saas_app"].(map[string]any); ok {
		delete(saas, "client_secret")
	}
	scim, ok := values["scim_config"].(map[string]any)
	if !ok {
		return
	}
	switch authentication := scim["authentication"].(type) {
	case map[string]any:
		stripAccessSCIMAuthenticationSecrets(authentication)
	case []map[string]any:
		for _, item := range authentication {
			stripAccessSCIMAuthenticationSecrets(item)
		}
	case []any:
		for _, item := range authentication {
			if object, ok := item.(map[string]any); ok {
				stripAccessSCIMAuthenticationSecrets(object)
			}
		}
	}
}

func stripAccessSCIMAuthenticationSecrets(value map[string]any) {
	delete(value, "password")
	delete(value, "token")
	delete(value, "client_secret")
}

func normalizeAccessApplicationWireMap(value map[string]any) {
	if applicationType, ok := value["type"].(string); ok {
		if wire, err := accessApplicationTypeToWire(AccessApplicationType(applicationType)); err == nil {
			value["type"] = wire
		}
	}
	if sameSite, ok := value["same_site_cookie_attribute"].(string); ok {
		value["same_site_cookie_attribute"] = accessSameSiteCookieToWire(v1alpha1.AccessSameSiteCookieAttribute(sameSite))
	}
	normalizeAccessDestinationMaps(value["destinations"])
	normalizeAccessMFAWireMap(value["mfa_config"])
	normalizeAccessSaaSWireMap(value["saas_app"])
	normalizeAccessSCIMWireMap(value["scim_config"])
	normalizeAccessTargetCriteriaMaps(value["target_criteria"])
	if policies, ok := value["policies"].([]any); ok {
		for _, item := range policies {
			policy, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if decision, ok := policy["decision"].(string); ok {
				policy["decision"] = accessPolicyDecisionToWire(AccessApplicationPolicyDecision(decision))
			}
			normalizeAccessMFAWireMap(policy["mfa_config"])
			normalizeAccessConnectionRulesWireMap(policy["connection_rules"])
		}
	}
}

func normalizeAccessApplicationSetValues(value map[string]any) {
	for _, key := range []string{"allowed_idps", "tags", "self_hosted_domains"} {
		normalizeAccessStringSet(value, key)
	}
	if cors, ok := value["cors_headers"].(map[string]any); ok {
		for _, key := range []string{"allowed_headers", "allowed_methods", "allowed_origins"} {
			normalizeAccessStringSet(cors, key)
		}
	}
	normalizeAccessMFASetValues(value["mfa_config"])
	if oauth, ok := value["oauth_configuration"].(map[string]any); ok {
		if dynamic, ok := oauth["dynamic_client_registration"].(map[string]any); ok {
			normalizeAccessStringSet(dynamic, "allowed_uris")
		}
	}
	if saas, ok := value["saas_app"].(map[string]any); ok {
		for _, key := range []string{"grant_types", "redirect_uris", "scopes"} {
			normalizeAccessStringSet(saas, key)
		}
	}
	if policies, ok := value["policies"].([]any); ok {
		for _, item := range policies {
			if policy, ok := item.(map[string]any); ok {
				normalizeAccessMFASetValues(policy["mfa_config"])
			}
		}
	}
}

func normalizeAccessMFASetValues(value any) {
	if config, ok := value.(map[string]any); ok {
		normalizeAccessStringSet(config, "allowed_authenticators")
	}
}

func normalizeAccessStringSet(value map[string]any, key string) {
	items, ok := value[key].([]any)
	if !ok {
		return
	}
	seen := make(map[string]struct{}, len(items))
	strings := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return
		}
		if _, duplicate := seen[text]; duplicate {
			continue
		}
		seen[text] = struct{}{}
		strings = append(strings, text)
	}
	sort.Strings(strings)
	value[key] = strings
}

func normalizeAccessDestinationMaps(value any) {
	destinations, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range destinations {
		destination, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if destinationType, ok := destination["type"].(string); ok {
			destination["type"] = accessDestinationTypeToWire(AccessApplicationDestinationType(destinationType))
		}
		if protocol, ok := destination["l4_protocol"].(string); ok {
			destination["l4_protocol"] = accessL4ProtocolToWire(AccessApplicationL4Protocol(protocol))
		}
	}
}

func normalizeAccessMFAWireMap(value any) {
	config, ok := value.(map[string]any)
	if !ok {
		return
	}
	authenticators, ok := config["allowed_authenticators"].([]any)
	if !ok {
		return
	}
	for i, item := range authenticators {
		if public, ok := item.(string); ok {
			authenticators[i] = accessMFAAuthenticatorToWire(AccessApplicationMFAAuthenticator(public))
		}
	}
}

func normalizeAccessConnectionRulesWireMap(value any) {
	rules, ok := value.(map[string]any)
	if !ok {
		return
	}
	rdp, ok := rules["rdp"].(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"allowed_clipboard_local_to_remote_formats", "allowed_clipboard_remote_to_local_formats"} {
		formats, ok := rdp[key].([]any)
		if !ok {
			continue
		}
		for i, item := range formats {
			if public, ok := item.(string); ok {
				formats[i] = accessRDPClipboardFormatToWire(AccessRDPClipboardFormat(public))
			}
		}
	}
}

func normalizeAccessSaaSWireMap(value any) {
	config, ok := value.(map[string]any)
	if !ok {
		return
	}
	if authType, ok := config["auth_type"].(string); ok {
		config["auth_type"] = accessSaaSAuthenticationTypeToWire(AccessSaaSAuthenticationType(authType))
	}
	if nameIDFormat, ok := config["name_id_format"].(string); ok {
		config["name_id_format"] = accessSaaSNameIDFormatToWire(AccessSaaSNameIDFormat(nameIDFormat))
	}
	if grants, ok := config["grant_types"].([]any); ok {
		for i, item := range grants {
			if public, ok := item.(string); ok {
				grants[i] = accessSaaSOIDCGrantTypeToWire(AccessSaaSOIDCGrantType(public))
			}
		}
	}
	if scopes, ok := config["scopes"].([]any); ok {
		for i, item := range scopes {
			if public, ok := item.(string); ok {
				scopes[i] = accessSaaSOIDCScopeToWire(AccessSaaSOIDCScope(public))
			}
		}
	}
	if claims, ok := config["custom_claims"].([]any); ok {
		for _, item := range claims {
			claim, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if scope, ok := claim["scope"].(string); ok {
				claim["scope"] = accessSaaSOIDCScopeToWire(AccessSaaSOIDCScope(scope))
			}
		}
	}
	if attributes, ok := config["custom_attributes"].([]any); ok {
		for _, item := range attributes {
			attribute, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if format, ok := attribute["name_format"].(string); ok {
				attribute["name_format"] = accessSaaSAttributeNameFormatToWire(AccessSaaSAttributeNameFormat(format))
			}
		}
	}
}

func normalizeAccessSCIMWireMap(value any) {
	config, ok := value.(map[string]any)
	if !ok {
		return
	}
	if authentication, ok := config["authentication"].([]any); ok {
		for _, item := range authentication {
			if object, ok := item.(map[string]any); ok {
				if scheme, ok := object["scheme"].(string); ok {
					object["scheme"] = accessSCIMAuthenticationSchemeToWire(AccessSCIMAuthenticationScheme(scheme))
				}
			}
		}
		if len(authentication) == 1 {
			config["authentication"] = authentication[0]
		}
	}
	if mappings, ok := config["mappings"].([]any); ok {
		for _, item := range mappings {
			mapping, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if strictness, ok := mapping["strictness"].(string); ok {
				mapping["strictness"] = accessSCIMStrictnessToWire(AccessSCIMMappingStrictness(strictness))
			}
		}
	}
}

func normalizeAccessTargetCriteriaMaps(value any) {
	criteria, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range criteria {
		criterion, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if protocol, ok := criterion["protocol"].(string); ok {
			criterion["protocol"] = accessTargetProtocolToWire(AccessApplicationTargetProtocol(protocol))
		}
	}
}

func accessSubsetEqual(expected, actual any) bool {
	expected = accessJSONValue(expected)
	actual = accessJSONValue(actual)
	switch expectedValue := expected.(type) {
	case map[string]any:
		actualValue, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for key, item := range expectedValue {
			if !accessSubsetEqual(item, actualValue[key]) {
				return false
			}
		}
		return true
	case []any:
		actualValue, ok := actual.([]any)
		if !ok || len(expectedValue) != len(actualValue) {
			return false
		}
		for i := range expectedValue {
			if !accessSubsetEqual(expectedValue[i], actualValue[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(expected, actual)
	}
}

func accessJSONValue(value any) any {
	data, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return value
	}
	return result
}

func accessApplicationTypeToWire(value AccessApplicationType) (string, error) {
	wire, ok := map[AccessApplicationType]string{
		AccessApplicationTypeSelfHosted: "self_hosted", AccessApplicationTypeSaaS: "saas", AccessApplicationTypeSSH: "ssh", AccessApplicationTypeVNC: "vnc", AccessApplicationTypeRDP: "rdp", AccessApplicationTypeMCP: "mcp", AccessApplicationTypeProxyEndpoint: "proxy_endpoint", AccessApplicationTypeBookmark: "bookmark", AccessApplicationTypeInfrastructure: "infrastructure", AccessApplicationTypeAppLauncher: "app_launcher", AccessApplicationTypeWARP: "warp", AccessApplicationTypeBISO: "biso", AccessApplicationTypeDashSSO: "dash_sso", AccessApplicationTypeMCPPortal: "mcp_portal",
	}[value]
	if !ok {
		return "", fmt.Errorf("unsupported Access application type %q", value)
	}
	return wire, nil
}

func accessApplicationTypeFromWire(value string) AccessApplicationType {
	for public := range map[AccessApplicationType]struct{}{AccessApplicationTypeSelfHosted: {}, AccessApplicationTypeSaaS: {}, AccessApplicationTypeSSH: {}, AccessApplicationTypeVNC: {}, AccessApplicationTypeRDP: {}, AccessApplicationTypeMCP: {}, AccessApplicationTypeProxyEndpoint: {}, AccessApplicationTypeBookmark: {}, AccessApplicationTypeInfrastructure: {}, AccessApplicationTypeAppLauncher: {}, AccessApplicationTypeWARP: {}, AccessApplicationTypeBISO: {}, AccessApplicationTypeDashSSO: {}, AccessApplicationTypeMCPPortal: {}} {
		wire, _ := accessApplicationTypeToWire(public)
		if wire == value {
			return public
		}
	}
	return AccessApplicationType(value)
}

func accessDestinationTypeToWire(value AccessApplicationDestinationType) string {
	if wire, ok := map[AccessApplicationDestinationType]string{AccessApplicationDestinationTypePublic: "public", AccessApplicationDestinationTypePrivate: "private", AccessApplicationDestinationTypeViaMCPServerPortal: "via_mcp_server_portal", AccessApplicationDestinationTypeWorker: "worker", AccessApplicationDestinationTypePreviewWorker: "preview_worker", AccessApplicationDestinationTypeAllWorkers: "all_workers", AccessApplicationDestinationTypeAllPreviewWorkers: "all_preview_workers"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessDestinationTypeFromWire(value string) AccessApplicationDestinationType {
	for public, wire := range map[AccessApplicationDestinationType]string{AccessApplicationDestinationTypePublic: "public", AccessApplicationDestinationTypePrivate: "private", AccessApplicationDestinationTypeViaMCPServerPortal: "via_mcp_server_portal", AccessApplicationDestinationTypeWorker: "worker", AccessApplicationDestinationTypePreviewWorker: "preview_worker", AccessApplicationDestinationTypeAllWorkers: "all_workers", AccessApplicationDestinationTypeAllPreviewWorkers: "all_preview_workers"} {
		if wire == value {
			return public
		}
	}
	return AccessApplicationDestinationType(value)
}
func accessL4ProtocolToWire(value AccessApplicationL4Protocol) string {
	switch value {
	case AccessApplicationL4ProtocolUDP:
		return "udp"
	case AccessApplicationL4ProtocolTCP:
		return "tcp"
	default:
		return string(value)
	}
}
func accessL4ProtocolFromWire(value string) AccessApplicationL4Protocol {
	if value == "udp" {
		return AccessApplicationL4ProtocolUDP
	}
	if value == "tcp" {
		return AccessApplicationL4ProtocolTCP
	}
	return AccessApplicationL4Protocol(value)
}
func accessMFAAuthenticatorToWire(value AccessApplicationMFAAuthenticator) string {
	if wire, ok := map[AccessApplicationMFAAuthenticator]string{AccessApplicationMFAAuthenticatorTOTP: "totp", AccessApplicationMFAAuthenticatorBiometrics: "biometrics", AccessApplicationMFAAuthenticatorSecurityKey: "security_key", AccessApplicationMFAAuthenticatorPIVKey: "piv_key", AccessApplicationMFAAuthenticatorSSHFIDO2Key: "ssh_fido2_key"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessMFAAuthenticatorFromWire(value string) AccessApplicationMFAAuthenticator {
	for public, wire := range map[AccessApplicationMFAAuthenticator]string{AccessApplicationMFAAuthenticatorTOTP: "totp", AccessApplicationMFAAuthenticatorBiometrics: "biometrics", AccessApplicationMFAAuthenticatorSecurityKey: "security_key", AccessApplicationMFAAuthenticatorPIVKey: "piv_key", AccessApplicationMFAAuthenticatorSSHFIDO2Key: "ssh_fido2_key"} {
		if wire == value {
			return public
		}
	}
	return AccessApplicationMFAAuthenticator(value)
}
func accessSCIMAuthenticationSchemeToWire(value AccessSCIMAuthenticationScheme) string {
	if wire, ok := map[AccessSCIMAuthenticationScheme]string{AccessSCIMAuthenticationSchemeHTTPBasic: "httpbasic", AccessSCIMAuthenticationSchemeOAuthBearerToken: "oauthbearertoken", AccessSCIMAuthenticationSchemeOAuth2: "oauth2", AccessSCIMAuthenticationSchemeAccessServiceToken: "access_service_token"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessSCIMAuthenticationSchemeFromWire(value string) AccessSCIMAuthenticationScheme {
	for public, wire := range map[AccessSCIMAuthenticationScheme]string{AccessSCIMAuthenticationSchemeHTTPBasic: "httpbasic", AccessSCIMAuthenticationSchemeOAuthBearerToken: "oauthbearertoken", AccessSCIMAuthenticationSchemeOAuth2: "oauth2", AccessSCIMAuthenticationSchemeAccessServiceToken: "access_service_token"} {
		if wire == value {
			return public
		}
	}
	return AccessSCIMAuthenticationScheme(value)
}
func accessSCIMStrictnessToWire(value AccessSCIMMappingStrictness) string {
	switch value {
	case AccessSCIMMappingStrictnessPassthrough:
		return "passthrough"
	case AccessSCIMMappingStrictnessStrict:
		return "strict"
	default:
		return string(value)
	}
}
func accessSameSiteCookieToWire(value v1alpha1.AccessSameSiteCookieAttribute) string {
	switch value {
	case v1alpha1.AccessSameSiteCookieLax:
		return "lax"
	case v1alpha1.AccessSameSiteCookieStrict:
		return "strict"
	case v1alpha1.AccessSameSiteCookieNone:
		return "none"
	default:
		return string(value)
	}
}
func accessSameSiteCookieFromWire(value string) v1alpha1.AccessSameSiteCookieAttribute {
	switch value {
	case "lax":
		return v1alpha1.AccessSameSiteCookieLax
	case "strict":
		return v1alpha1.AccessSameSiteCookieStrict
	case "none":
		return v1alpha1.AccessSameSiteCookieNone
	default:
		return v1alpha1.AccessSameSiteCookieAttribute(value)
	}
}
func accessSCIMStrictnessFromWire(value string) AccessSCIMMappingStrictness {
	if value == "passthrough" {
		return AccessSCIMMappingStrictnessPassthrough
	}
	if value == "strict" {
		return AccessSCIMMappingStrictnessStrict
	}
	return AccessSCIMMappingStrictness(value)
}
func accessSaaSAuthenticationTypeToWire(value AccessSaaSAuthenticationType) string {
	switch value {
	case AccessSaaSAuthenticationTypeOIDC:
		return "oidc"
	case AccessSaaSAuthenticationTypeSAML:
		return "saml"
	default:
		return string(value)
	}
}
func accessSaaSAuthenticationTypeFromWire(value string) AccessSaaSAuthenticationType {
	if value == "oidc" {
		return AccessSaaSAuthenticationTypeOIDC
	}
	if value == "saml" {
		return AccessSaaSAuthenticationTypeSAML
	}
	return AccessSaaSAuthenticationType(value)
}
func accessSaaSOIDCGrantTypeToWire(value AccessSaaSOIDCGrantType) string {
	if wire, ok := map[AccessSaaSOIDCGrantType]string{AccessSaaSOIDCGrantTypeAuthorizationCode: "authorization_code", AccessSaaSOIDCGrantTypeAuthorizationCodeWithPKCE: "authorization_code_with_pkce", AccessSaaSOIDCGrantTypeRefreshTokens: "refresh_tokens", AccessSaaSOIDCGrantTypeHybrid: "hybrid", AccessSaaSOIDCGrantTypeImplicit: "implicit"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessSaaSOIDCGrantTypeFromWire(value string) AccessSaaSOIDCGrantType {
	for public, wire := range map[AccessSaaSOIDCGrantType]string{AccessSaaSOIDCGrantTypeAuthorizationCode: "authorization_code", AccessSaaSOIDCGrantTypeAuthorizationCodeWithPKCE: "authorization_code_with_pkce", AccessSaaSOIDCGrantTypeRefreshTokens: "refresh_tokens", AccessSaaSOIDCGrantTypeHybrid: "hybrid", AccessSaaSOIDCGrantTypeImplicit: "implicit"} {
		if wire == value {
			return public
		}
	}
	return AccessSaaSOIDCGrantType(value)
}
func accessSaaSOIDCScopeToWire(value AccessSaaSOIDCScope) string {
	if wire, ok := map[AccessSaaSOIDCScope]string{AccessSaaSOIDCScopeOpenID: "openid", AccessSaaSOIDCScopeGroups: "groups", AccessSaaSOIDCScopeEmail: "email", AccessSaaSOIDCScopeProfile: "profile"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessSaaSOIDCScopeFromWire(value string) AccessSaaSOIDCScope {
	for public, wire := range map[AccessSaaSOIDCScope]string{AccessSaaSOIDCScopeOpenID: "openid", AccessSaaSOIDCScopeGroups: "groups", AccessSaaSOIDCScopeEmail: "email", AccessSaaSOIDCScopeProfile: "profile"} {
		if wire == value {
			return public
		}
	}
	return AccessSaaSOIDCScope(value)
}
func accessSaaSNameIDFormatToWire(value AccessSaaSNameIDFormat) string {
	switch value {
	case AccessSaaSNameIDFormatEmail:
		return "email"
	case AccessSaaSNameIDFormatID:
		return "id"
	default:
		return string(value)
	}
}
func accessSaaSNameIDFormatFromWire(value string) AccessSaaSNameIDFormat {
	if value == "email" {
		return AccessSaaSNameIDFormatEmail
	}
	if value == "id" {
		return AccessSaaSNameIDFormatID
	}
	return AccessSaaSNameIDFormat(value)
}
func accessSaaSAttributeNameFormatToWire(value AccessSaaSAttributeNameFormat) string {
	if wire, ok := map[AccessSaaSAttributeNameFormat]string{AccessSaaSAttributeNameFormatUnspecified: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified", AccessSaaSAttributeNameFormatBasic: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", AccessSaaSAttributeNameFormatURI: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}[value]; ok {
		return wire
	}
	return string(value)
}
func accessSaaSAttributeNameFormatFromWire(value string) AccessSaaSAttributeNameFormat {
	for public, wire := range map[AccessSaaSAttributeNameFormat]string{AccessSaaSAttributeNameFormatUnspecified: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified", AccessSaaSAttributeNameFormatBasic: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", AccessSaaSAttributeNameFormatURI: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"} {
		if wire == value {
			return public
		}
	}
	return AccessSaaSAttributeNameFormat(value)
}
func accessTargetProtocolToWire(value AccessApplicationTargetProtocol) string {
	switch value {
	case AccessApplicationTargetProtocolRDP:
		return "RDP"
	case AccessApplicationTargetProtocolTCP:
		return "TCP"
	case AccessApplicationTargetProtocolSSH:
		return "SSH"
	default:
		return string(value)
	}
}
func accessTargetProtocolFromWire(value string) AccessApplicationTargetProtocol {
	switch value {
	case "RDP":
		return AccessApplicationTargetProtocolRDP
	case "TCP":
		return AccessApplicationTargetProtocolTCP
	case "SSH":
		return AccessApplicationTargetProtocolSSH
	default:
		return AccessApplicationTargetProtocol(value)
	}
}
func accessRDPClipboardFormatToWire(value AccessRDPClipboardFormat) string {
	switch value {
	case AccessRDPClipboardFormatFile:
		return "file"
	case AccessRDPClipboardFormatText:
		return "text"
	default:
		return string(value)
	}
}
func accessRDPClipboardFormatFromWire(value string) AccessRDPClipboardFormat {
	if value == "file" {
		return AccessRDPClipboardFormatFile
	}
	if value == "text" {
		return AccessRDPClipboardFormatText
	}
	return AccessRDPClipboardFormat(value)
}
func accessPolicyDecisionToWire(value AccessApplicationPolicyDecision) string {
	switch value {
	case AccessApplicationPolicyDecisionNonIdentity:
		return "non_identity"
	case AccessApplicationPolicyDecisionBypass:
		return "bypass"
	case AccessApplicationPolicyDecisionAllow:
		return "allow"
	case AccessApplicationPolicyDecisionBlock:
		return "block"
	case AccessApplicationPolicyDecisionServiceAuth:
		return "service_auth"
	default:
		return string(value)
	}
}
func accessPolicyDecisionFromWire(value string) AccessApplicationPolicyDecision {
	switch value {
	case "non_identity":
		return AccessApplicationPolicyDecisionNonIdentity
	case "bypass":
		return AccessApplicationPolicyDecisionBypass
	case "allow":
		return AccessApplicationPolicyDecisionAllow
	case "block":
		return AccessApplicationPolicyDecisionBlock
	case "service_auth":
		return AccessApplicationPolicyDecisionServiceAuth
	default:
		return AccessApplicationPolicyDecision(value)
	}
}
