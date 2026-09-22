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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// AccessStandaloneApplicationFinalizer protects remote application cleanup.
	AccessStandaloneApplicationFinalizer = "flareway.bhyoo.com/accessstandaloneapplication"
	// AccessStandaloneApplicationClientSecretKey stores a create-only SaaS secret.
	AccessStandaloneApplicationClientSecretKey = "clientSecret"
)

// AccessStandaloneApplicationType selects a non-Gateway Access application variant.
// +kubebuilder:validation:Enum=SaaS;Bookmark;Infrastructure;AppLauncher;WARP;BISO;DashSSO;MCPPortal
type AccessStandaloneApplicationType string

const (
	// AccessStandaloneApplicationTypeSaaS selects a SaaS application.
	AccessStandaloneApplicationTypeSaaS AccessStandaloneApplicationType = "SaaS"
	// AccessStandaloneApplicationTypeBookmark selects a bookmark.
	AccessStandaloneApplicationTypeBookmark AccessStandaloneApplicationType = "Bookmark"
	// AccessStandaloneApplicationTypeInfrastructure selects an infrastructure application.
	AccessStandaloneApplicationTypeInfrastructure AccessStandaloneApplicationType = "Infrastructure"
	// AccessStandaloneApplicationTypeAppLauncher selects the account App Launcher.
	AccessStandaloneApplicationTypeAppLauncher AccessStandaloneApplicationType = "AppLauncher"
	// AccessStandaloneApplicationTypeWARP selects the WARP enrollment application.
	AccessStandaloneApplicationTypeWARP AccessStandaloneApplicationType = "WARP"
	// AccessStandaloneApplicationTypeBISO selects Browser Isolation permissions.
	AccessStandaloneApplicationTypeBISO AccessStandaloneApplicationType = "BISO"
	// AccessStandaloneApplicationTypeDashSSO selects dashboard single sign-on.
	AccessStandaloneApplicationTypeDashSSO AccessStandaloneApplicationType = "DashSSO"
	// AccessStandaloneApplicationTypeMCPPortal selects an MCP portal application.
	AccessStandaloneApplicationTypeMCPPortal AccessStandaloneApplicationType = "MCPPortal"
)

// AccessSaaSAuthenticationType selects the SaaS federation protocol.
// +kubebuilder:validation:Enum=OIDC;SAML
type AccessSaaSAuthenticationType string

const (
	// AccessSaaSAuthenticationTypeOIDC selects OpenID Connect.
	AccessSaaSAuthenticationTypeOIDC AccessSaaSAuthenticationType = "OIDC"
	// AccessSaaSAuthenticationTypeSAML selects SAML.
	AccessSaaSAuthenticationTypeSAML AccessSaaSAuthenticationType = "SAML"
)

// AccessSaaSOIDCGrantType selects an enabled OIDC flow.
// +kubebuilder:validation:Enum=AuthorizationCode;AuthorizationCodeWithPKCE;RefreshTokens;Hybrid;Implicit
type AccessSaaSOIDCGrantType string

const (
	// AccessSaaSOIDCGrantAuthorizationCode enables the authorization-code flow.
	AccessSaaSOIDCGrantAuthorizationCode AccessSaaSOIDCGrantType = "AuthorizationCode"
	// AccessSaaSOIDCGrantAuthorizationCodeWithPKCE enables authorization code with PKCE.
	AccessSaaSOIDCGrantAuthorizationCodeWithPKCE AccessSaaSOIDCGrantType = "AuthorizationCodeWithPKCE"
	// AccessSaaSOIDCGrantRefreshTokens enables refresh tokens.
	AccessSaaSOIDCGrantRefreshTokens AccessSaaSOIDCGrantType = "RefreshTokens"
	// AccessSaaSOIDCGrantHybrid enables hybrid flows.
	AccessSaaSOIDCGrantHybrid AccessSaaSOIDCGrantType = "Hybrid"
	// AccessSaaSOIDCGrantImplicit enables implicit flows.
	AccessSaaSOIDCGrantImplicit AccessSaaSOIDCGrantType = "Implicit"
)

// AccessSaaSOIDCScope is an OIDC scope emitted by Access.
// +kubebuilder:validation:Enum=OpenID;Groups;Email;Profile
type AccessSaaSOIDCScope string

const (
	// AccessSaaSOIDCScopeOpenID selects the openid scope.
	AccessSaaSOIDCScopeOpenID AccessSaaSOIDCScope = "OpenID"
	// AccessSaaSOIDCScopeGroups selects the groups scope.
	AccessSaaSOIDCScopeGroups AccessSaaSOIDCScope = "Groups"
	// AccessSaaSOIDCScopeEmail selects the email scope.
	AccessSaaSOIDCScopeEmail AccessSaaSOIDCScope = "Email"
	// AccessSaaSOIDCScopeProfile selects the profile scope.
	AccessSaaSOIDCScopeProfile AccessSaaSOIDCScope = "Profile"
)

// AccessSaaSAttributeSourceByIDP maps an IdP to one source attribute.
type AccessSaaSAttributeSourceByIDP struct {
	IDPRef AccessIdentityProviderReference `json:"idpRef"`
	// +kubebuilder:validation:MinLength=1
	SourceName string `json:"sourceName"`
}

// AccessSaaSAttributeSource selects a default source or per-IdP sources.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.nameByIdp)",message="exactly one of name or nameByIdp is required"
type AccessSaaSAttributeSource struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	NameByIDP []AccessSaaSAttributeSourceByIDP `json:"nameByIdp,omitempty"`
}

// AccessSaaSOIDCCustomClaim configures one custom OIDC claim.
type AccessSaaSOIDCCustomClaim struct {
	// +kubebuilder:validation:MinLength=1
	Name     string                    `json:"name"`
	Required *bool                     `json:"required,omitempty"`
	Scope    AccessSaaSOIDCScope       `json:"scope"`
	Source   AccessSaaSAttributeSource `json:"source"`
}

// AccessSaaSOIDCHybridAndImplicitOptions configures token return behavior.
type AccessSaaSOIDCHybridAndImplicitOptions struct {
	ReturnAccessTokenFromAuthorizationEndpoint *bool `json:"returnAccessTokenFromAuthorizationEndpoint,omitempty"`
	ReturnIDTokenFromAuthorizationEndpoint     *bool `json:"returnIdTokenFromAuthorizationEndpoint,omitempty"`
}

// AccessSaaSOIDCRefreshTokenOptions configures refresh token lifetime.
type AccessSaaSOIDCRefreshTokenOptions struct {
	// +kubebuilder:validation:Pattern=`^([0-9]+(m|h|d))+$`
	Lifetime string `json:"lifetime,omitempty"`
}

// AccessSaaSOIDCSpec configures an OIDC SaaS application.
type AccessSaaSOIDCSpec struct {
	// +kubebuilder:validation:Pattern=`^([0-9]+(m|h))+$`
	AccessTokenLifetime          string `json:"accessTokenLifetime,omitempty"`
	AllowPKCEWithoutClientSecret *bool  `json:"allowPkceWithoutClientSecret,omitempty"`
	AppLauncherURL               string `json:"appLauncherUrl,omitempty"`
	// +listType=atomic
	CustomClaims []AccessSaaSOIDCCustomClaim `json:"customClaims,omitempty"`
	// +listType=set
	GrantTypes               []AccessSaaSOIDCGrantType               `json:"grantTypes,omitempty"`
	GroupFilterRegex         string                                  `json:"groupFilterRegex,omitempty"`
	HybridAndImplicitOptions *AccessSaaSOIDCHybridAndImplicitOptions `json:"hybridAndImplicitOptions,omitempty"`
	PublicKey                string                                  `json:"publicKey,omitempty"`
	// +listType=set
	RedirectURIs        []string                           `json:"redirectUris,omitempty"`
	RefreshTokenOptions *AccessSaaSOIDCRefreshTokenOptions `json:"refreshTokenOptions,omitempty"`
	// +listType=set
	Scopes []AccessSaaSOIDCScope `json:"scopes,omitempty"`
}

// AccessSaaSNameIDFormat configures the SAML NameID format.
// +kubebuilder:validation:Enum=ID;Email
type AccessSaaSNameIDFormat string

const (
	// AccessSaaSNameIDFormatID uses the Access identity ID.
	AccessSaaSNameIDFormatID AccessSaaSNameIDFormat = "ID"
	// AccessSaaSNameIDFormatEmail uses the identity email.
	AccessSaaSNameIDFormatEmail AccessSaaSNameIDFormat = "Email"
)

// AccessSaaSSAMLAttributeNameFormat configures a custom attribute name format.
// +kubebuilder:validation:Enum=Unspecified;Basic;URI
type AccessSaaSSAMLAttributeNameFormat string

const (
	// AccessSaaSSAMLAttributeNameFormatUnspecified leaves the format unspecified.
	AccessSaaSSAMLAttributeNameFormatUnspecified AccessSaaSSAMLAttributeNameFormat = "Unspecified"
	// AccessSaaSSAMLAttributeNameFormatBasic uses the SAML Basic format.
	AccessSaaSSAMLAttributeNameFormatBasic AccessSaaSSAMLAttributeNameFormat = "Basic"
	// AccessSaaSSAMLAttributeNameFormatURI uses the SAML URI format.
	AccessSaaSSAMLAttributeNameFormatURI AccessSaaSSAMLAttributeNameFormat = "URI"
)

// AccessSaaSSAMLCustomAttribute configures one custom SAML attribute.
type AccessSaaSSAMLCustomAttribute struct {
	FriendlyName string `json:"friendlyName,omitempty"`
	// +kubebuilder:validation:MinLength=1
	Name       string                            `json:"name"`
	NameFormat AccessSaaSSAMLAttributeNameFormat `json:"nameFormat,omitempty"`
	Required   *bool                             `json:"required,omitempty"`
	Source     AccessSaaSAttributeSource         `json:"source"`
}

// AccessSaaSSAMLSpec configures a SAML SaaS application.
type AccessSaaSSAMLSpec struct {
	ConsumerServiceURL string `json:"consumerServiceUrl,omitempty"`
	// +listType=atomic
	CustomAttributes              []AccessSaaSSAMLCustomAttribute `json:"customAttributes,omitempty"`
	DefaultRelayState             string                          `json:"defaultRelayState,omitempty"`
	IDPEntityID                   string                          `json:"idpEntityId,omitempty"`
	NameIDFormat                  AccessSaaSNameIDFormat          `json:"nameIdFormat,omitempty"`
	NameIDTransformJSONata        string                          `json:"nameIdTransformJsonata,omitempty"`
	PublicKey                     string                          `json:"publicKey,omitempty"`
	SAMLAttributeTransformJSONata string                          `json:"samlAttributeTransformJsonata,omitempty"`
	SPEntityID                    string                          `json:"spEntityId,omitempty"`
	SSOEndpoint                   string                          `json:"ssoEndpoint,omitempty"`
}

// AccessSaaSApplicationSpec is a discriminated OIDC or SAML configuration.
// +kubebuilder:validation:XValidation:rule="(has(self.oidc)?1:0)+(has(self.saml)?1:0) == 1",message="exactly one SaaS protocol variant is required"
// +kubebuilder:validation:XValidation:rule="(self.authType == 'OIDC') == has(self.oidc)",message="oidc is required if and only if authType is OIDC"
// +kubebuilder:validation:XValidation:rule="(self.authType == 'SAML') == has(self.saml)",message="saml is required if and only if authType is SAML"
type AccessSaaSApplicationSpec struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="authType is immutable"
	AuthType AccessSaaSAuthenticationType `json:"authType"`
	OIDC     *AccessSaaSOIDCSpec          `json:"oidc,omitempty"`
	SAML     *AccessSaaSSAMLSpec          `json:"saml,omitempty"`
}

// AccessBookmarkApplicationSpec configures a bookmark tile.
type AccessBookmarkApplicationSpec struct {
	// +kubebuilder:validation:MinLength=1
	URL     string `json:"url"`
	LogoURL string `json:"logoUrl,omitempty"`
}

// AccessInfrastructureMFAAuthenticator is an infrastructure MFA method.
// +kubebuilder:validation:Enum=PIVKey;SSHFIDO2Key
type AccessInfrastructureMFAAuthenticator string

const (
	// AccessInfrastructureMFAAuthenticatorPIVKey selects PIV keys.
	AccessInfrastructureMFAAuthenticatorPIVKey AccessInfrastructureMFAAuthenticator = "PIVKey"
	// AccessInfrastructureMFAAuthenticatorSSHFIDO2Key selects SSH FIDO2 keys.
	AccessInfrastructureMFAAuthenticatorSSHFIDO2Key AccessInfrastructureMFAAuthenticator = "SSHFIDO2Key"
)

// AccessInfrastructureMFAConfig configures infrastructure MFA.
type AccessInfrastructureMFAConfig struct {
	// +listType=set
	AllowedAuthenticators []AccessInfrastructureMFAAuthenticator `json:"allowedAuthenticators,omitempty"`
	MFADisabled           *bool                                  `json:"mfaDisabled,omitempty"`
	// +kubebuilder:validation:Pattern=`^([0-9]+(m|h))+$`
	SessionDuration string `json:"sessionDuration,omitempty"`
}

// AccessInfrastructureSSHConnectionRules configures allowed SSH identities.
type AccessInfrastructureSSHConnectionRules struct {
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Usernames       []string `json:"usernames"`
	AllowEmailAlias *bool    `json:"allowEmailAlias,omitempty"`
}

// AccessInfrastructureConnectionRules configures protocol-specific connection rules.
type AccessInfrastructureConnectionRules struct {
	SSH *AccessInfrastructureSSHConnectionRules `json:"ssh,omitempty"`
}

// AccessInfrastructureApplicationPolicy is an inline infrastructure policy.
// +kubebuilder:validation:XValidation:rule="self.decision == 'Allow'",message="infrastructure application policies only support Allow"
type AccessInfrastructureApplicationPolicy struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:default=Allow
	Decision AccessPolicyDecision `json:"decision,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Include []AccessRule `json:"include"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Require []AccessRule `json:"require,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Exclude         []AccessRule                         `json:"exclude,omitempty"`
	ConnectionRules *AccessInfrastructureConnectionRules `json:"connectionRules,omitempty"`
	MFAConfig       *AccessInfrastructureMFAConfig       `json:"mfaConfig,omitempty"`
}

// AccessInfrastructureApplicationSpec selects infrastructure targets and policies.
// +kubebuilder:validation:XValidation:rule="self.targetCriteria.all(c, c.protocol == 'SSH')",message="infrastructure target criteria require SSH protocol"
type AccessInfrastructureApplicationSpec struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	TargetCriteria []AccessTargetCriterion        `json:"targetCriteria"`
	MFAConfig      *AccessInfrastructureMFAConfig `json:"mfaConfig,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Policies []AccessInfrastructureApplicationPolicy `json:"policies"`
}

// AccessAppLauncherFooterLink is one footer link.
type AccessAppLauncherFooterLink struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`
}

// AccessAppLauncherLandingPageDesign configures the launcher landing page.
type AccessAppLauncherLandingPageDesign struct {
	ButtonColor     string `json:"buttonColor,omitempty"`
	ButtonTextColor string `json:"buttonTextColor,omitempty"`
	ImageURL        string `json:"imageUrl,omitempty"`
	Message         string `json:"message,omitempty"`
	Title           string `json:"title,omitempty"`
}

// AccessAppLauncherApplicationSpec configures App Launcher presentation.
type AccessAppLauncherApplicationSpec struct {
	AppLauncherLogoURL    string                              `json:"appLauncherLogoUrl,omitempty"`
	BackgroundColor       string                              `json:"backgroundColor,omitempty"`
	HeaderBackgroundColor string                              `json:"headerBackgroundColor,omitempty"`
	LandingPageDesign     *AccessAppLauncherLandingPageDesign `json:"landingPageDesign,omitempty"`
	// +listType=atomic
	FooterLinks              []AccessAppLauncherFooterLink `json:"footerLinks,omitempty"`
	SkipAppLauncherLoginPage *bool                         `json:"skipAppLauncherLoginPage,omitempty"`
}

// AccessWARPApplicationSpec selects the WARP enrollment request shape.
type AccessWARPApplicationSpec struct{}

// AccessBISOApplicationSpec selects the Browser Isolation request shape.
type AccessBISOApplicationSpec struct{}

// AccessDashSSOApplicationSpec configures the Gateway identity proxy endpoint.
type AccessDashSSOApplicationSpec struct {
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
}

// AccessMCPPortalApplicationSpec configures an MCP server portal application.
type AccessMCPPortalApplicationSpec struct {
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Destinations []AccessApplicationDestinationSpec `json:"destinations"`
}

// AccessStandaloneApplicationSpec defines a non-Gateway Access application.
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="(has(self.saas)?1:0)+(has(self.bookmark)?1:0)+(has(self.infrastructure)?1:0)+(has(self.appLauncher)?1:0)+(has(self.warp)?1:0)+(has(self.biso)?1:0)+(has(self.dashSso)?1:0)+(has(self.mcpPortal)?1:0) == 1",message="exactly one standalone application variant is required"
// +kubebuilder:validation:XValidation:rule="(self.type == 'SaaS') == has(self.saas)",message="saas is required if and only if type is SaaS"
// +kubebuilder:validation:XValidation:rule="(self.type == 'Bookmark') == has(self.bookmark)",message="bookmark is required if and only if type is Bookmark"
// +kubebuilder:validation:XValidation:rule="(self.type == 'Infrastructure') == has(self.infrastructure)",message="infrastructure is required if and only if type is Infrastructure"
// +kubebuilder:validation:XValidation:rule="(self.type == 'AppLauncher') == has(self.appLauncher)",message="appLauncher is required if and only if type is AppLauncher"
// +kubebuilder:validation:XValidation:rule="(self.type == 'WARP') == has(self.warp)",message="warp is required if and only if type is WARP"
// +kubebuilder:validation:XValidation:rule="(self.type == 'BISO') == has(self.biso)",message="biso is required if and only if type is BISO"
// +kubebuilder:validation:XValidation:rule="(self.type == 'DashSSO') == has(self.dashSso)",message="dashSso is required if and only if type is DashSSO"
// +kubebuilder:validation:XValidation:rule="(self.type == 'MCPPortal') == has(self.mcpPortal)",message="mcpPortal is required if and only if type is MCPPortal"
// +kubebuilder:validation:XValidation:rule="self.type != 'Infrastructure' || !has(self.policies) || size(self.policies) == 0",message="Infrastructure policies must be declared in infrastructure.policies"
// +kubebuilder:validation:XValidation:rule="self.type in ['SaaS', 'Bookmark', 'MCPPortal'] || !has(self.application.tags) || size(self.application.tags) == 0",message="application.tags is unsupported for this standalone application type"
// +kubebuilder:validation:XValidation:rule="self.type != 'WARP' || !has(self.application.name)",message="WARP application.name is unsupported; use adoption.expect.name to identify an existing enrollment"
// +kubebuilder:validation:XValidation:rule="self.type != 'WARP' || (self.managementPolicy != 'ObserveOnly' && self.adoption.mode != 'AdoptById') || (has(self.adoption.expect) && has(self.adoption.expect.name) && size(self.adoption.expect.name) > 0)",message="WARP ObserveOnly and AdoptById require adoption.expect.name"
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessStandaloneApplicationSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Zone is an optional DNS zone name resolved through CloudflareAccount status.
	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone,omitempty"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type        AccessStandaloneApplicationType `json:"type"`
	Application AccessApplicationSettings       `json:"application"`
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Policies       []AccessApplicationPolicyReference   `json:"policies,omitempty"`
	SaaS           *AccessSaaSApplicationSpec           `json:"saas,omitempty"`
	Bookmark       *AccessBookmarkApplicationSpec       `json:"bookmark,omitempty"`
	Infrastructure *AccessInfrastructureApplicationSpec `json:"infrastructure,omitempty"`
	AppLauncher    *AccessAppLauncherApplicationSpec    `json:"appLauncher,omitempty"`
	WARP           *AccessWARPApplicationSpec           `json:"warp,omitempty"`
	BISO           *AccessBISOApplicationSpec           `json:"biso,omitempty"`
	DashSSO        *AccessDashSSOApplicationSpec        `json:"dashSso,omitempty"`
	MCPPortal      *AccessMCPPortalApplicationSpec      `json:"mcpPortal,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                    `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessApplicationExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessSaaSAttributeSourceStatus records resolved SaaS claim sources.
type AccessSaaSAttributeSourceStatus struct {
	Name      string            `json:"name,omitempty"`
	NameByIDP map[string]string `json:"nameByIdp,omitempty"`
}

// AccessSaaSOIDCCustomClaimStatus records an observed custom OIDC claim.
type AccessSaaSOIDCCustomClaimStatus struct {
	Name     string                          `json:"name,omitempty"`
	Required bool                            `json:"required,omitempty"`
	Scope    string                          `json:"scope,omitempty"`
	Source   AccessSaaSAttributeSourceStatus `json:"source,omitempty"`
}

// AccessSaaSOIDCStatus records observed non-secret OIDC settings.
type AccessSaaSOIDCStatus struct {
	AccessTokenLifetime                        string                            `json:"accessTokenLifetime,omitempty"`
	AllowPKCEWithoutClientSecret               bool                              `json:"allowPkceWithoutClientSecret,omitempty"`
	AppLauncherURL                             string                            `json:"appLauncherUrl,omitempty"`
	CustomClaims                               []AccessSaaSOIDCCustomClaimStatus `json:"customClaims,omitempty"`
	GrantTypes                                 []string                          `json:"grantTypes,omitempty"`
	GroupFilterRegex                           string                            `json:"groupFilterRegex,omitempty"`
	ReturnAccessTokenFromAuthorizationEndpoint bool                              `json:"returnAccessTokenFromAuthorizationEndpoint,omitempty"`
	ReturnIDTokenFromAuthorizationEndpoint     bool                              `json:"returnIdTokenFromAuthorizationEndpoint,omitempty"`
	PublicKey                                  string                            `json:"publicKey,omitempty"`
	RedirectURIs                               []string                          `json:"redirectUris,omitempty"`
	RefreshTokenLifetime                       string                            `json:"refreshTokenLifetime,omitempty"`
	Scopes                                     []string                          `json:"scopes,omitempty"`
}

// AccessSaaSSAMLCustomAttributeStatus records an observed custom SAML attribute.
type AccessSaaSSAMLCustomAttributeStatus struct {
	FriendlyName string                          `json:"friendlyName,omitempty"`
	Name         string                          `json:"name,omitempty"`
	NameFormat   string                          `json:"nameFormat,omitempty"`
	Required     bool                            `json:"required,omitempty"`
	Source       AccessSaaSAttributeSourceStatus `json:"source,omitempty"`
}

// AccessSaaSSAMLStatus records observed non-secret SAML settings.
type AccessSaaSSAMLStatus struct {
	ConsumerServiceURL            string                                `json:"consumerServiceUrl,omitempty"`
	CustomAttributes              []AccessSaaSSAMLCustomAttributeStatus `json:"customAttributes,omitempty"`
	DefaultRelayState             string                                `json:"defaultRelayState,omitempty"`
	IDPEntityID                   string                                `json:"idpEntityId,omitempty"`
	NameIDFormat                  string                                `json:"nameIdFormat,omitempty"`
	NameIDTransformJSONata        string                                `json:"nameIdTransformJsonata,omitempty"`
	PublicKey                     string                                `json:"publicKey,omitempty"`
	SAMLAttributeTransformJSONata string                                `json:"samlAttributeTransformJsonata,omitempty"`
	SPEntityID                    string                                `json:"spEntityId,omitempty"`
	SSOEndpoint                   string                                `json:"ssoEndpoint,omitempty"`
}

// AccessSaaSApplicationStatus records non-secret SaaS values.
type AccessSaaSApplicationStatus struct {
	AuthType string `json:"authType,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	// ClientSecretRef names the controller-owned Secret containing the create-only client secret.
	ClientSecretRef *corev1.LocalObjectReference `json:"clientSecretRef,omitempty"`
	OIDC            *AccessSaaSOIDCStatus        `json:"oidc,omitempty"`
	SAML            *AccessSaaSSAMLStatus        `json:"saml,omitempty"`
}

// AccessBookmarkApplicationStatus records observed bookmark values.
type AccessBookmarkApplicationStatus struct {
	URL     string `json:"url,omitempty"`
	LogoURL string `json:"logoUrl,omitempty"`
}

// AccessTargetCriterionStatus records one observed target criterion.
type AccessTargetCriterionStatus struct {
	Port             int32               `json:"port,omitempty"`
	Protocol         string              `json:"protocol,omitempty"`
	TargetAttributes map[string][]string `json:"targetAttributes,omitempty"`
}

// AccessInfrastructureMFAStatus records observed infrastructure MFA settings.
type AccessInfrastructureMFAStatus struct {
	AllowedAuthenticators []string `json:"allowedAuthenticators,omitempty"`
	MFADisabled           bool     `json:"mfaDisabled,omitempty"`
	SessionDuration       string   `json:"sessionDuration,omitempty"`
}

// AccessInfrastructureApplicationStatus records observed infrastructure settings.
type AccessInfrastructureApplicationStatus struct {
	TargetCriteria []AccessTargetCriterionStatus  `json:"targetCriteria,omitempty"`
	MFAConfig      *AccessInfrastructureMFAStatus `json:"mfaConfig,omitempty"`
}

// AccessAppLauncherFooterLinkStatus records one observed footer link.
type AccessAppLauncherFooterLinkStatus struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// AccessAppLauncherLandingPageDesignStatus records observed landing-page design.
type AccessAppLauncherLandingPageDesignStatus struct {
	ButtonColor     string `json:"buttonColor,omitempty"`
	ButtonTextColor string `json:"buttonTextColor,omitempty"`
	ImageURL        string `json:"imageUrl,omitempty"`
	Message         string `json:"message,omitempty"`
	Title           string `json:"title,omitempty"`
}

// AccessAppLauncherApplicationStatus records observed launcher presentation.
type AccessAppLauncherApplicationStatus struct {
	AppLauncherLogoURL       string                                    `json:"appLauncherLogoUrl,omitempty"`
	BackgroundColor          string                                    `json:"backgroundColor,omitempty"`
	HeaderBackgroundColor    string                                    `json:"headerBackgroundColor,omitempty"`
	LandingPageDesign        *AccessAppLauncherLandingPageDesignStatus `json:"landingPageDesign,omitempty"`
	FooterLinks              []AccessAppLauncherFooterLinkStatus       `json:"footerLinks,omitempty"`
	SkipAppLauncherLoginPage bool                                      `json:"skipAppLauncherLoginPage,omitempty"`
}

// AccessDashSSOApplicationStatus records the observed identity proxy domain.
type AccessDashSSOApplicationStatus struct {
	Domain string `json:"domain,omitempty"`
}

// AccessMCPPortalApplicationStatus records observed MCP portal routing.
type AccessMCPPortalApplicationStatus struct {
	Domain       string                               `json:"domain,omitempty"`
	Destinations []AccessApplicationDestinationStatus `json:"destinations,omitempty"`
}

// AccessStandaloneApplicationStatus defines the observed non-secret state.
type AccessStandaloneApplicationStatus struct {
	ApplicationID     string                                 `json:"applicationId,omitempty"`
	Type              AccessStandaloneApplicationType        `json:"type,omitempty"`
	Name              string                                 `json:"name,omitempty"`
	Domain            string                                 `json:"domain,omitempty"`
	ZoneID            string                                 `json:"zoneId,omitempty"`
	OwnershipVerified bool                                   `json:"ownershipVerified,omitempty"`
	Tags              []string                               `json:"tags,omitempty"`
	SaaS              *AccessSaaSApplicationStatus           `json:"saas,omitempty"`
	Bookmark          *AccessBookmarkApplicationStatus       `json:"bookmark,omitempty"`
	Infrastructure    *AccessInfrastructureApplicationStatus `json:"infrastructure,omitempty"`
	AppLauncher       *AccessAppLauncherApplicationStatus    `json:"appLauncher,omitempty"`
	DashSSO           *AccessDashSSOApplicationStatus        `json:"dashSso,omitempty"`
	MCPPortal         *AccessMCPPortalApplicationStatus      `json:"mcpPortal,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	// AppliedHash is the desired-state hash recorded after the last successful remote convergence.
	// +optional
	AppliedHash string `json:"appliedHash,omitempty"`
	// AppliedAt is when AppliedHash was last recorded; nil means never applied.
	// +optional
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfasa,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Application",type=string,JSONPath=`.status.applicationId`

// AccessStandaloneApplication is a non-Gateway Cloudflare Access application.
type AccessStandaloneApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessStandaloneApplicationSpec   `json:"spec,omitempty"`
	Status            AccessStandaloneApplicationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessStandaloneApplicationList contains standalone applications.
type AccessStandaloneApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessStandaloneApplication `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AccessStandaloneApplication{}, &AccessStandaloneApplicationList{})
		return nil
	})
}
