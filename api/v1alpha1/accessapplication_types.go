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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// AccessApplicationFinalizer protects remote application cleanup.
	AccessApplicationFinalizer = "flareway.bhyoo.com/accessapplication"
	// AccessApplicationConditionOriginJWTEnforced reports origin JWT enforcement.
	AccessApplicationConditionOriginJWTEnforced = "OriginJWTEnforced"
	// AccessApplicationAUDSecretLabel identifies the exact AccessApplication bound to an AUD Secret.
	AccessApplicationAUDSecretLabel = "flareway.bhyoo.com/access-application"
	// AccessApplicationGatewayAUDLabel identifies the exact Gateway bound to an AUD Secret.
	AccessApplicationGatewayAUDLabel = "flareway.bhyoo.com/aud-for-gateway"
	// AccessApplicationAUDSecretKey stores an application audience.
	AccessApplicationAUDSecretKey = "aud"
	// AccessApplicationIDSecretKey stores the bound Cloudflare application identifier.
	AccessApplicationIDSecretKey = "applicationId"
	// AccessApplicationNamespacedNameSecretKey stores the bound AccessApplication namespace and name.
	AccessApplicationNamespacedNameSecretKey = "applicationNamespacedName"
	// AccessApplicationUIDSecretKey stores the bound AccessApplication UID.
	AccessApplicationUIDSecretKey = "applicationUID"
	// AccessApplicationGatewayNamespacedNameSecretKey stores the bound Gateway namespace and name.
	AccessApplicationGatewayNamespacedNameSecretKey = "gatewayNamespacedName"
	// AccessApplicationGatewayUIDSecretKey stores the bound Gateway UID.
	AccessApplicationGatewayUIDSecretKey = "gatewayUID"
)

// AccessApplicationType selects a Gateway-attached Access application variant.
// +kubebuilder:validation:Enum=SelfHosted;SSH;VNC;RDP;MCP;ProxyEndpoint
type AccessApplicationType string

const (
	// AccessApplicationTypeSelfHosted selects a self-hosted application.
	AccessApplicationTypeSelfHosted AccessApplicationType = "SelfHosted"
	// AccessApplicationTypeSSH selects a browser SSH application.
	AccessApplicationTypeSSH AccessApplicationType = "SSH"
	// AccessApplicationTypeVNC selects a browser VNC application.
	AccessApplicationTypeVNC AccessApplicationType = "VNC"
	// AccessApplicationTypeRDP selects a browser RDP application.
	AccessApplicationTypeRDP AccessApplicationType = "RDP"
	// AccessApplicationTypeMCP selects an MCP server application.
	AccessApplicationTypeMCP AccessApplicationType = "MCP"
	// AccessApplicationTypeProxyEndpoint selects a Gateway identity proxy endpoint.
	AccessApplicationTypeProxyEndpoint AccessApplicationType = "ProxyEndpoint"
)

// AccessApplicationExternalReference identifies an existing Access application.
type AccessApplicationExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	ApplicationID string `json:"applicationId"`
}

// NamespacedLocalObjectReference identifies a namespaced Flareway resource.
type NamespacedLocalObjectReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Namespace defaults to the referencing object's namespace.
	Namespace string `json:"namespace,omitempty"`
}

// AccessIdentityProviderReference selects a managed IdP or an external IdP ID.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.externalId)",message="exactly one of name or externalId is required"
type AccessIdentityProviderReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MinLength=1
	ExternalID string `json:"externalId,omitempty"`
}

// AccessCustomPageReference selects a managed AccessCustomPage or an external page ID.
// +kubebuilder:validation:XValidation:rule="has(self.objectRef) != has(self.externalId)",message="exactly one of objectRef or externalId is required"
type AccessCustomPageReference struct {
	ObjectRef *NamespacedLocalObjectReference `json:"objectRef,omitempty"`
	// +kubebuilder:validation:MinLength=1
	ExternalID string `json:"externalId,omitempty"`
}

// DevicePostureIntegrationReference selects a managed integration or an external integration ID.
// +kubebuilder:validation:XValidation:rule="has(self.objectRef) != has(self.externalId)",message="exactly one of objectRef or externalId is required"
type DevicePostureIntegrationReference struct {
	ObjectRef *NamespacedLocalObjectReference `json:"objectRef,omitempty"`
	// +kubebuilder:validation:MinLength=1
	ExternalID string `json:"externalId,omitempty"`
}

// AccessApplicationSecretKeyReference identifies one key in a Secret in the same namespace.
type AccessApplicationSecretKeyReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// AccessApplicationPolicyExternalReference identifies a reusable Access policy.
type AccessApplicationPolicyExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	PolicyID string `json:"policyId"`
}

// AccessApplicationPolicyReference selects a managed policy or an external policy ID.
// Slice order defines remote policy precedence.
// +kubebuilder:validation:XValidation:rule="has(self.policyRef) != has(self.externalRef)",message="exactly one of policyRef or externalRef is required"
type AccessApplicationPolicyReference struct {
	PolicyRef   *NamespacedLocalObjectReference           `json:"policyRef,omitempty"`
	ExternalRef *AccessApplicationPolicyExternalReference `json:"externalRef,omitempty"`
}

// AccessCORSMethod is an HTTP method accepted by Cloudflare Access CORS settings.
// +kubebuilder:validation:Enum=GET;POST;HEAD;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
type AccessCORSMethod string

// AccessCORSHeaders configures Access edge CORS handling.
type AccessCORSHeaders struct {
	AllowAllHeaders  *bool `json:"allowAllHeaders,omitempty"`
	AllowAllMethods  *bool `json:"allowAllMethods,omitempty"`
	AllowAllOrigins  *bool `json:"allowAllOrigins,omitempty"`
	AllowCredentials *bool `json:"allowCredentials,omitempty"`
	// +listType=set
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
	// +listType=set
	AllowedMethods []AccessCORSMethod `json:"allowedMethods,omitempty"`
	// +listType=set
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	MaxAge         *int64   `json:"maxAge,omitempty"`
}

// AccessSameSiteCookieAttribute configures the SameSite cookie attribute.
// +kubebuilder:validation:Enum=Lax;Strict;None
type AccessSameSiteCookieAttribute string

const (
	// AccessSameSiteCookieLax selects SameSite=Lax.
	AccessSameSiteCookieLax AccessSameSiteCookieAttribute = "Lax"
	// AccessSameSiteCookieStrict selects SameSite=Strict.
	AccessSameSiteCookieStrict AccessSameSiteCookieAttribute = "Strict"
	// AccessSameSiteCookieNone selects SameSite=None.
	AccessSameSiteCookieNone AccessSameSiteCookieAttribute = "None"
)

// AccessApplicationMFAAuthenticator is an application-level MFA method.
// +kubebuilder:validation:Enum=TOTP;Biometrics;SecurityKey
type AccessApplicationMFAAuthenticator string

const (
	// AccessApplicationMFAAuthenticatorTOTP allows time-based one-time passwords.
	AccessApplicationMFAAuthenticatorTOTP AccessApplicationMFAAuthenticator = "TOTP"
	// AccessApplicationMFAAuthenticatorBiometrics allows biometric authentication.
	AccessApplicationMFAAuthenticatorBiometrics AccessApplicationMFAAuthenticator = "Biometrics"
	// AccessApplicationMFAAuthenticatorSecurityKey allows security keys.
	AccessApplicationMFAAuthenticatorSecurityKey AccessApplicationMFAAuthenticator = "SecurityKey"
)

// AccessApplicationMFAConfig configures application-level MFA.
type AccessApplicationMFAConfig struct {
	// +listType=set
	AllowedAuthenticators []AccessApplicationMFAAuthenticator `json:"allowedAuthenticators,omitempty"`
	MFADisabled           *bool                               `json:"mfaDisabled,omitempty"`
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|ms|s|m|h))+$`
	SessionDuration string `json:"sessionDuration,omitempty"`
}

// AccessOAuthDynamicClientRegistration configures OAuth dynamic clients.
type AccessOAuthDynamicClientRegistration struct {
	Enabled             *bool `json:"enabled,omitempty"`
	AllowAnyOnLocalhost *bool `json:"allowAnyOnLocalhost,omitempty"`
	AllowAnyOnLoopback  *bool `json:"allowAnyOnLoopback,omitempty"`
	// +listType=set
	AllowedURIs []string `json:"allowedUris,omitempty"`
}

// AccessOAuthGrant configures OAuth token and session lifetimes.
type AccessOAuthGrant struct {
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|ms|s|m|h))+$`
	AccessTokenLifetime string `json:"accessTokenLifetime,omitempty"`
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|ms|s|m|h))+$`
	SessionDuration string `json:"sessionDuration,omitempty"`
}

// AccessApplicationOAuthConfiguration makes Access an OAuth authorization server.
type AccessApplicationOAuthConfiguration struct {
	Enabled                   *bool                                 `json:"enabled,omitempty"`
	DynamicClientRegistration *AccessOAuthDynamicClientRegistration `json:"dynamicClientRegistration,omitempty"`
	Grant                     *AccessOAuthGrant                     `json:"grant,omitempty"`
}

// AccessSCIMAuthenticationScheme selects a SCIM authentication mechanism.
// +kubebuilder:validation:Enum=HTTPBasic;OAuthBearerToken;OAuth2;AccessServiceToken
type AccessSCIMAuthenticationScheme string

const (
	// AccessSCIMAuthenticationHTTPBasic selects HTTP Basic authentication.
	AccessSCIMAuthenticationHTTPBasic AccessSCIMAuthenticationScheme = "HTTPBasic"
	// AccessSCIMAuthenticationOAuthBearerToken selects a static bearer token.
	AccessSCIMAuthenticationOAuthBearerToken AccessSCIMAuthenticationScheme = "OAuthBearerToken"
	// AccessSCIMAuthenticationOAuth2 selects OAuth 2 authentication.
	AccessSCIMAuthenticationOAuth2 AccessSCIMAuthenticationScheme = "OAuth2"
	// AccessSCIMAuthenticationAccessServiceToken selects an Access service token.
	AccessSCIMAuthenticationAccessServiceToken AccessSCIMAuthenticationScheme = "AccessServiceToken"
)

// AccessSCIMHTTPBasicAuthentication configures SCIM HTTP Basic authentication.
type AccessSCIMHTTPBasicAuthentication struct {
	// +kubebuilder:validation:MinLength=1
	User              string                              `json:"user"`
	PasswordSecretRef AccessApplicationSecretKeyReference `json:"passwordSecretRef"`
}

// AccessSCIMOAuthBearerTokenAuthentication configures a static bearer token.
type AccessSCIMOAuthBearerTokenAuthentication struct {
	TokenSecretRef AccessApplicationSecretKeyReference `json:"tokenSecretRef"`
}

// AccessSCIMOAuth2Authentication configures OAuth 2 client credentials for SCIM.
type AccessSCIMOAuth2Authentication struct {
	// +kubebuilder:validation:MinLength=1
	AuthorizationURL string `json:"authorizationUrl"`
	// +kubebuilder:validation:MinLength=1
	ClientID        string                              `json:"clientId"`
	ClientSecretRef AccessApplicationSecretKeyReference `json:"clientSecretRef"`
	// +kubebuilder:validation:MinLength=1
	TokenURL string `json:"tokenUrl"`
	// +listType=set
	Scopes []string `json:"scopes,omitempty"`
}

// AccessSCIMAccessServiceTokenAuthentication selects a managed ServiceToken.
type AccessSCIMAccessServiceTokenAuthentication struct {
	ServiceTokenRef NamespacedLocalObjectReference `json:"serviceTokenRef"`
}

// AccessSCIMAuthenticationMethod is one member of a multi-authentication list.
// +kubebuilder:validation:XValidation:rule="(has(self.httpBasic)?1:0)+(has(self.oauthBearerToken)?1:0)+(has(self.oauth2)?1:0)+(has(self.accessServiceToken)?1:0) == 1",message="exactly one SCIM authentication method is required"
type AccessSCIMAuthenticationMethod struct {
	HTTPBasic          *AccessSCIMHTTPBasicAuthentication          `json:"httpBasic,omitempty"`
	OAuthBearerToken   *AccessSCIMOAuthBearerTokenAuthentication   `json:"oauthBearerToken,omitempty"`
	OAuth2             *AccessSCIMOAuth2Authentication             `json:"oauth2,omitempty"`
	AccessServiceToken *AccessSCIMAccessServiceTokenAuthentication `json:"accessServiceToken,omitempty"`
}

// AccessSCIMAuthentication selects one authentication method or an ordered set.
// +kubebuilder:validation:XValidation:rule="(has(self.httpBasic)?1:0)+(has(self.oauthBearerToken)?1:0)+(has(self.oauth2)?1:0)+(has(self.accessServiceToken)?1:0)+(has(self.multiple)?1:0) == 1",message="exactly one SCIM authentication variant is required"
type AccessSCIMAuthentication struct {
	HTTPBasic          *AccessSCIMHTTPBasicAuthentication          `json:"httpBasic,omitempty"`
	OAuthBearerToken   *AccessSCIMOAuthBearerTokenAuthentication   `json:"oauthBearerToken,omitempty"`
	OAuth2             *AccessSCIMOAuth2Authentication             `json:"oauth2,omitempty"`
	AccessServiceToken *AccessSCIMAccessServiceTokenAuthentication `json:"accessServiceToken,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	// +listType=atomic
	Multiple []AccessSCIMAuthenticationMethod `json:"multiple,omitempty"`
}

// AccessSCIMMappingStrictness controls handling of unknown SCIM values.
// +kubebuilder:validation:Enum=Strict;Passthrough
type AccessSCIMMappingStrictness string

const (
	// AccessSCIMMappingStrict drops unknown SCIM values.
	AccessSCIMMappingStrict AccessSCIMMappingStrictness = "Strict"
	// AccessSCIMMappingPassthrough retains unknown SCIM values.
	AccessSCIMMappingPassthrough AccessSCIMMappingStrictness = "Passthrough"
)

// AccessSCIMMappingOperations selects SCIM operations for one mapping.
type AccessSCIMMappingOperations struct {
	Create *bool `json:"create,omitempty"`
	Update *bool `json:"update,omitempty"`
	Delete *bool `json:"delete,omitempty"`
}

// AccessSCIMMapping transforms or filters one SCIM resource type.
type AccessSCIMMapping struct {
	// +kubebuilder:validation:MinLength=1
	Schema           string                       `json:"schema"`
	Enabled          *bool                        `json:"enabled,omitempty"`
	Filter           string                       `json:"filter,omitempty"`
	Operations       *AccessSCIMMappingOperations `json:"operations,omitempty"`
	Strictness       AccessSCIMMappingStrictness  `json:"strictness,omitempty"`
	TransformJSONata string                       `json:"transformJsonata,omitempty"`
}

// AccessApplicationSCIMConfig configures outbound SCIM provisioning.
type AccessApplicationSCIMConfig struct {
	IDPRef AccessIdentityProviderReference `json:"idpRef"`
	// +kubebuilder:validation:MinLength=1
	RemoteURI          string                    `json:"remoteUri"`
	Authentication     *AccessSCIMAuthentication `json:"authentication,omitempty"`
	DeactivateOnDelete *bool                     `json:"deactivateOnDelete,omitempty"`
	Enabled            *bool                     `json:"enabled,omitempty"`
	// +listType=atomic
	Mappings []AccessSCIMMapping `json:"mappings,omitempty"`
}

// AccessApplicationSettings contains fields shared by Access application variants.
// +kubebuilder:validation:XValidation:rule="!has(self.optionsPreflightBypass) || !self.optionsPreflightBypass || !has(self.corsHeaders)",message="optionsPreflightBypass cannot be true when corsHeaders is set"
// +kubebuilder:validation:XValidation:rule="!has(self.autoRedirectToIdentity) || !self.autoRedirectToIdentity || (has(self.allowedIdpRefs) && size(self.allowedIdpRefs) == 1)",message="autoRedirectToIdentity requires exactly one allowedIdpRef"
type AccessApplicationSettings struct {
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|ms|s|m|h))+$`
	SessionDuration          string `json:"sessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool  `json:"allowAuthenticateViaWarp,omitempty"`
	AllowIframe              *bool  `json:"allowIframe,omitempty"`
	SkipInterstitial         *bool  `json:"skipInterstitial,omitempty"`
	AutoRedirectToIdentity   *bool  `json:"autoRedirectToIdentity,omitempty"`
	// +listType=atomic
	AllowedIDPRefs              []AccessIdentityProviderReference `json:"allowedIdpRefs,omitempty"`
	AppLauncherVisible          *bool                             `json:"appLauncherVisible,omitempty"`
	ServiceAuth401Redirect      *bool                             `json:"serviceAuth401Redirect,omitempty"`
	EnableBindingCookie         *bool                             `json:"enableBindingCookie,omitempty"`
	HTTPOnlyCookieAttribute     *bool                             `json:"httpOnlyCookieAttribute,omitempty"`
	SameSiteCookieAttribute     AccessSameSiteCookieAttribute     `json:"sameSiteCookieAttribute,omitempty"`
	PathCookieAttribute         *bool                             `json:"pathCookieAttribute,omitempty"`
	OptionsPreflightBypass      *bool                             `json:"optionsPreflightBypass,omitempty"`
	CORSHeaders                 *AccessCORSHeaders                `json:"corsHeaders,omitempty"`
	ReadServiceTokensFromHeader string                            `json:"readServiceTokensFromHeader,omitempty"`
	CustomDenyMessage           string                            `json:"customDenyMessage,omitempty"`
	CustomDenyURL               string                            `json:"customDenyUrl,omitempty"`
	CustomNonIdentityDenyURL    string                            `json:"customNonIdentityDenyUrl,omitempty"`
	// +kubebuilder:validation:MaxItems=25
	// +listType=atomic
	CustomPageRefs                       []AccessCustomPageReference          `json:"customPageRefs,omitempty"`
	EagerRedirectCookieSetting           *bool                                `json:"eagerRedirectCookieSetting,omitempty"`
	LogoURL                              string                               `json:"logoUrl,omitempty"`
	MFAConfig                            *AccessApplicationMFAConfig          `json:"mfaConfig,omitempty"`
	OAuthConfiguration                   *AccessApplicationOAuthConfiguration `json:"oauthConfiguration,omitempty"`
	SCIMConfig                           *AccessApplicationSCIMConfig         `json:"scimConfig,omitempty"`
	UseClientlessIsolationAppLauncherURL *bool                                `json:"useClientlessIsolationAppLauncherUrl,omitempty"`
	// +kubebuilder:validation:MaxItems=23
	// +kubebuilder:validation:items:MaxLength=35
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z0-9_-]+$`
	// +kubebuilder:validation:items:XValidation:rule="!self.startsWith('flareway-')",message="tag names starting with flareway- are reserved by the operator"
	// +listType=set
	Tags []string `json:"tags,omitempty"`
}

// AccessApplicationDestinationType selects a Cloudflare Access destination variant.
// +kubebuilder:validation:Enum=Public;Private;ViaMCPServerPortal;Worker;PreviewWorker;AllWorkers;AllPreviewWorkers
type AccessApplicationDestinationType string

const (
	// AccessApplicationDestinationPublic selects a public URI.
	AccessApplicationDestinationPublic AccessApplicationDestinationType = "Public"
	// AccessApplicationDestinationPrivate selects a private network destination.
	AccessApplicationDestinationPrivate AccessApplicationDestinationType = "Private"
	// AccessApplicationDestinationViaMCPServerPortal selects an MCP server portal.
	AccessApplicationDestinationViaMCPServerPortal AccessApplicationDestinationType = "ViaMCPServerPortal"
	// AccessApplicationDestinationWorker selects a production Worker.
	AccessApplicationDestinationWorker AccessApplicationDestinationType = "Worker"
	// AccessApplicationDestinationPreviewWorker selects Worker previews.
	AccessApplicationDestinationPreviewWorker AccessApplicationDestinationType = "PreviewWorker"
	// AccessApplicationDestinationAllWorkers selects every production Worker.
	AccessApplicationDestinationAllWorkers AccessApplicationDestinationType = "AllWorkers"
	// AccessApplicationDestinationAllPreviewWorkers selects every Worker preview.
	AccessApplicationDestinationAllPreviewWorkers AccessApplicationDestinationType = "AllPreviewWorkers"
)

// AccessPublicDestinationSpec directly identifies a public hostname or path.
type AccessPublicDestinationSpec struct {
	// +kubebuilder:validation:MinLength=1
	URI string `json:"uri"`
}

// AccessPrivateDestinationSpec selects one managed private route.
// +kubebuilder:validation:XValidation:rule="has(self.networkRouteRef) != has(self.hostnameRouteRef)",message="exactly one of networkRouteRef or hostnameRouteRef is required"
type AccessPrivateDestinationSpec struct {
	NetworkRouteRef  *corev1.LocalObjectReference `json:"networkRouteRef,omitempty"`
	HostnameRouteRef *corev1.LocalObjectReference `json:"hostnameRouteRef,omitempty"`
	CIDR             string                       `json:"cidr,omitempty"`
	// +kubebuilder:validation:Pattern=`^[0-9]+(-[0-9]+)?$`
	PortRange  string            `json:"portRange,omitempty"`
	L4Protocol *AccessL4Protocol `json:"l4Protocol,omitempty"`
}

// AccessMCPServerPortalDestinationSpec selects an AI Controls MCP server.
type AccessMCPServerPortalDestinationSpec struct {
	// +kubebuilder:validation:MinLength=1
	MCPServerID string `json:"mcpServerId"`
}

// AccessWorkerDestinationSpec selects a Cloudflare Worker.
type AccessWorkerDestinationSpec struct {
	// +kubebuilder:validation:MinLength=1
	WorkerID string `json:"workerId"`
}

// AccessAllWorkersDestinationSpec selects all production Workers.
type AccessAllWorkersDestinationSpec struct{}

// AccessAllPreviewWorkersDestinationSpec selects all Worker previews.
type AccessAllPreviewWorkersDestinationSpec struct{}

// AccessApplicationDestinationSpec is a discriminated destination union.
// +kubebuilder:validation:XValidation:rule="(has(self.public)?1:0)+(has(self.private)?1:0)+(has(self.viaMcpServerPortal)?1:0)+(has(self.worker)?1:0)+(has(self.previewWorker)?1:0)+(has(self.allWorkers)?1:0)+(has(self.allPreviewWorkers)?1:0) == 1",message="exactly one destination variant is required"
// +kubebuilder:validation:XValidation:rule="(self.type == 'Public') == has(self.public)",message="public is required if and only if type is Public"
// +kubebuilder:validation:XValidation:rule="(self.type == 'Private') == has(self.private)",message="private is required if and only if type is Private"
// +kubebuilder:validation:XValidation:rule="(self.type == 'ViaMCPServerPortal') == has(self.viaMcpServerPortal)",message="viaMcpServerPortal is required if and only if type is ViaMCPServerPortal"
// +kubebuilder:validation:XValidation:rule="(self.type == 'Worker') == has(self.worker)",message="worker is required if and only if type is Worker"
// +kubebuilder:validation:XValidation:rule="(self.type == 'PreviewWorker') == has(self.previewWorker)",message="previewWorker is required if and only if type is PreviewWorker"
// +kubebuilder:validation:XValidation:rule="(self.type == 'AllWorkers') == has(self.allWorkers)",message="allWorkers is required if and only if type is AllWorkers"
// +kubebuilder:validation:XValidation:rule="(self.type == 'AllPreviewWorkers') == has(self.allPreviewWorkers)",message="allPreviewWorkers is required if and only if type is AllPreviewWorkers"
type AccessApplicationDestinationSpec struct {
	Type               AccessApplicationDestinationType        `json:"type"`
	Public             *AccessPublicDestinationSpec            `json:"public,omitempty"`
	Private            *AccessPrivateDestinationSpec           `json:"private,omitempty"`
	ViaMCPServerPortal *AccessMCPServerPortalDestinationSpec   `json:"viaMcpServerPortal,omitempty"`
	Worker             *AccessWorkerDestinationSpec            `json:"worker,omitempty"`
	PreviewWorker      *AccessWorkerDestinationSpec            `json:"previewWorker,omitempty"`
	AllWorkers         *AccessAllWorkersDestinationSpec        `json:"allWorkers,omitempty"`
	AllPreviewWorkers  *AccessAllPreviewWorkersDestinationSpec `json:"allPreviewWorkers,omitempty"`
}

// AccessL4Protocol selects a private destination transport protocol. Omission matches both.
// +kubebuilder:validation:Enum=TCP;UDP
type AccessL4Protocol string

const (
	// AccessL4ProtocolTCP selects TCP traffic.
	AccessL4ProtocolTCP AccessL4Protocol = "TCP"
	// AccessL4ProtocolUDP selects UDP traffic.
	AccessL4ProtocolUDP AccessL4Protocol = "UDP"
)

// AccessTargetPath narrows a Gateway attachment to a protected path.
type AccessTargetPath struct {
	// +kubebuilder:validation:Enum=Exact;PathPrefix
	// +kubebuilder:default=PathPrefix
	Type gatewayv1.PathMatchType `json:"type,omitempty"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^/`
	Value string `json:"value"`
}

// AccessTargetProtocol is a target criterion protocol.
// +kubebuilder:validation:Enum=SSH;TCP;RDP
type AccessTargetProtocol string

const (
	// AccessTargetProtocolSSH selects SSH target traffic.
	AccessTargetProtocolSSH AccessTargetProtocol = "SSH"
	// AccessTargetProtocolTCP selects generic TCP target traffic.
	AccessTargetProtocolTCP AccessTargetProtocol = "TCP"
	// AccessTargetProtocolRDP selects RDP target traffic.
	AccessTargetProtocolRDP AccessTargetProtocol = "RDP"
)

// AccessTargetCriterion selects infrastructure targets by port, protocol and attributes.
type AccessTargetCriterion struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port     int32                `json:"port"`
	Protocol AccessTargetProtocol `json:"protocol"`
	// +kubebuilder:validation:MinProperties=1
	TargetAttributes map[string][]string `json:"targetAttributes"`
}

// AccessSelfHostedApplicationSpec selects the self-hosted request shape.
type AccessSelfHostedApplicationSpec struct{}

// AccessSSHApplicationSpec selects the browser SSH request shape.
type AccessSSHApplicationSpec struct{}

// AccessVNCApplicationSpec selects the browser VNC request shape.
type AccessVNCApplicationSpec struct{}

// AccessRDPApplicationSpec configures browser RDP target criteria.
// +kubebuilder:validation:XValidation:rule="self.targetCriteria.all(c, c.protocol == 'RDP')",message="RDP target criteria require RDP protocol"
type AccessRDPApplicationSpec struct {
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	TargetCriteria []AccessTargetCriterion `json:"targetCriteria"`
}

// AccessMCPApplicationSpec selects the MCP server request shape.
type AccessMCPApplicationSpec struct{}

// AccessProxyEndpointApplicationSpec selects the Gateway proxy endpoint request shape.
type AccessProxyEndpointApplicationSpec struct{}

// AccessOriginJWTMode controls origin JWT verification.
// +kubebuilder:validation:Enum=Required;Disabled
type AccessOriginJWTMode string

const (
	// AccessOriginJWTModeRequired requires origin JWT verification.
	AccessOriginJWTModeRequired AccessOriginJWTMode = "Required"
	// AccessOriginJWTModeDisabled disables origin JWT verification.
	AccessOriginJWTModeDisabled AccessOriginJWTMode = "Disabled"
)

// AccessOriginJWTAudienceScope selects which application audiences an origin accepts.
// +kubebuilder:validation:Enum=Application;Hostname
type AccessOriginJWTAudienceScope string

const (
	// AccessOriginJWTAudienceScopeApplication accepts only this application's AUD.
	AccessOriginJWTAudienceScopeApplication AccessOriginJWTAudienceScope = "Application"
	// AccessOriginJWTAudienceScopeHostname accepts every ready AUD on the hostname.
	AccessOriginJWTAudienceScopeHostname AccessOriginJWTAudienceScope = "Hostname"
)

// AccessOriginJWTSpec configures origin JWT enforcement.
// +kubebuilder:validation:XValidation:rule="!has(self.audienceScope) || self.audienceScope != 'Hostname' || !has(self.mode) || self.mode == 'Required'",message="Hostname audienceScope requires mode Required"
type AccessOriginJWTSpec struct {
	// +kubebuilder:default=Required
	Mode AccessOriginJWTMode `json:"mode,omitempty"`
	// +kubebuilder:default=Application
	AudienceScope              AccessOriginJWTAudienceScope `json:"audienceScope,omitempty"`
	AssumeGatewayTLSDecryption bool                         `json:"assumeGatewayTLSDecryption,omitempty"`
}

// AccessBypassChildSpec declares remote identity and adoption for one compiled carve-out.
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessBypassChildSpec struct {
	// +kubebuilder:validation:MinLength=1
	Hostname string `json:"hostname"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^/`
	Path        string                              `json:"path"`
	Name        string                              `json:"name,omitempty"`
	ExternalRef *AccessApplicationExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption  AdoptionSpec                      `json:"adoption,omitempty"`
	PolicyRef *AccessApplicationPolicyReference `json:"policyRef,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessBypassSpec declares adoptable identities for carve-outs compiled from routes.
type AccessBypassSpec struct {
	// +kubebuilder:validation:MaxItems=100
	// +listType=map
	// +listMapKey=hostname
	// +listMapKey=path
	Children []AccessBypassChildSpec `json:"children,omitempty"`
}

// AccessApplicationSpec defines one Gateway-attached Cloudflare Access application.
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="(has(self.selfHosted)?1:0)+(has(self.ssh)?1:0)+(has(self.vnc)?1:0)+(has(self.rdp)?1:0)+(has(self.mcp)?1:0)+(has(self.proxyEndpoint)?1:0) == 1",message="exactly one application variant is required"
// +kubebuilder:validation:XValidation:rule="(self.type == 'SelfHosted') == has(self.selfHosted)",message="selfHosted is required if and only if type is SelfHosted"
// +kubebuilder:validation:XValidation:rule="(self.type == 'SSH') == has(self.ssh)",message="ssh is required if and only if type is SSH"
// +kubebuilder:validation:XValidation:rule="(self.type == 'VNC') == has(self.vnc)",message="vnc is required if and only if type is VNC"
// +kubebuilder:validation:XValidation:rule="(self.type == 'RDP') == has(self.rdp)",message="rdp is required if and only if type is RDP"
// +kubebuilder:validation:XValidation:rule="(self.type == 'MCP') == has(self.mcp)",message="mcp is required if and only if type is MCP"
// +kubebuilder:validation:XValidation:rule="(self.type == 'ProxyEndpoint') == has(self.proxyEndpoint)",message="proxyEndpoint is required if and only if type is ProxyEndpoint"
// +kubebuilder:validation:XValidation:rule="self.type == 'ProxyEndpoint' ? (has(self.targetRefs) && size(self.targetRefs) > 0 && (!has(self.destinations) || size(self.destinations) == 0)) : ((has(self.targetRefs) && size(self.targetRefs) > 0) || (has(self.destinations) && size(self.destinations) > 0))",message="ProxyEndpoint requires targetRefs only; other types require targetRefs or destinations"
// +kubebuilder:validation:XValidation:rule="!has(self.targetRefs) || self.targetRefs.all(t, t.group == 'gateway.networking.k8s.io' && (t.kind == 'Gateway' || t.kind == 'HTTPRoute'))",message="targetRefs must reference gateway.networking.k8s.io Gateway or HTTPRoute objects"
// +kubebuilder:validation:XValidation:rule="!has(self.destinations) || self.destinations.all(d, d.type != 'Public')",message="public destinations must be compiled from targetRefs"
// +kubebuilder:validation:XValidation:rule="!has(self.pathScope) || (has(self.targetRefs) && size(self.targetRefs) > 0)",message="pathScope requires targetRefs"
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || !has(self.bypass) || !has(self.bypass.children) || self.bypass.children.all(c, has(c.externalRef))",message="ObserveOnly requires externalRef for every bypass child"
type AccessApplicationSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Zone is an optional DNS zone name resolved through CloudflareAccount status.
	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone,omitempty"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type          AccessApplicationType               `json:"type"`
	SelfHosted    *AccessSelfHostedApplicationSpec    `json:"selfHosted,omitempty"`
	SSH           *AccessSSHApplicationSpec           `json:"ssh,omitempty"`
	VNC           *AccessVNCApplicationSpec           `json:"vnc,omitempty"`
	RDP           *AccessRDPApplicationSpec           `json:"rdp,omitempty"`
	MCP           *AccessMCPApplicationSpec           `json:"mcp,omitempty"`
	ProxyEndpoint *AccessProxyEndpointApplicationSpec `json:"proxyEndpoint,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	TargetRefs []gatewayv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs,omitempty"`
	// Destinations adds Cloudflare-side private, MCP, and Worker destinations.
	// Public destinations are derived from TargetRefs. The deprecated
	// self_hosted_domains wire field is intentionally not exposed.
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Destinations []AccessApplicationDestinationSpec `json:"destinations,omitempty"`
	PathScope    *AccessTargetPath                  `json:"pathScope,omitempty"`
	Application  AccessApplicationSettings          `json:"application"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Policies []AccessApplicationPolicyReference `json:"policies"`
	// +kubebuilder:default={}
	OriginJWT AccessOriginJWTSpec `json:"originJWT,omitempty"`
	// +kubebuilder:default={}
	Bypass AccessBypassSpec `json:"bypass,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                    `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessApplicationExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessApplicationDestinationStatus records a compiled Access destination.
type AccessApplicationDestinationStatus struct {
	Type        AccessApplicationDestinationType `json:"type"`
	URI         string                           `json:"uri,omitempty"`
	Hostname    string                           `json:"hostname,omitempty"`
	CIDR        string                           `json:"cidr,omitempty"`
	PortRange   string                           `json:"portRange,omitempty"`
	L4Protocol  *AccessL4Protocol                `json:"l4Protocol,omitempty"`
	VNetID      string                           `json:"vnetId,omitempty"`
	MCPServerID string                           `json:"mcpServerId,omitempty"`
	WorkerID    string                           `json:"workerId,omitempty"`
}

// AccessApplicationDataPlaneStatus records the selected tunnel and Envoy domain.
type AccessApplicationDataPlaneStatus struct {
	Tunnel           string                `json:"tunnel,omitempty"`
	Listener         gatewayv1.SectionName `json:"listener,omitempty"`
	ProtectionDomain string                `json:"protectionDomain,omitempty"`
	EnvoyPort        int32                 `json:"envoyPort,omitempty"`
}

// AccessBypassApplicationOrigin records how a bypass child entered management.
// +kubebuilder:validation:Enum=Created;Recovered;Adopted
type AccessBypassApplicationOrigin string

const (
	// AccessBypassApplicationOriginCreated identifies a newly created child.
	AccessBypassApplicationOriginCreated AccessBypassApplicationOrigin = "Created"
	// AccessBypassApplicationOriginRecovered identifies an owned recovered child.
	AccessBypassApplicationOriginRecovered AccessBypassApplicationOrigin = "Recovered"
	// AccessBypassApplicationOriginAdopted identifies an explicitly adopted child after ownership
	// was established. Its application ID and last observed name form the durable adoption checkpoint.
	AccessBypassApplicationOriginAdopted AccessBypassApplicationOrigin = "Adopted"
)

// AccessBypassApplicationStatus records an operator-owned public carve-out application.
type AccessBypassApplicationStatus struct {
	Hostname       string                        `json:"hostname"`
	Path           string                        `json:"path"`
	ApplicationID  string                        `json:"applicationId"`
	Name           string                        `json:"name,omitempty"`
	PolicyID       string                        `json:"policyId,omitempty"`
	Origin         AccessBypassApplicationOrigin `json:"origin,omitempty"`
	DeletionPolicy DeletionPolicy                `json:"deletionPolicy,omitempty"`
}

// AccessApplicationStatus records the remote application without exposing its AUD.
type AccessApplicationStatus struct {
	ApplicationID     string                `json:"applicationId,omitempty"`
	Type              AccessApplicationType `json:"type,omitempty"`
	Domain            string                `json:"domain,omitempty"`
	ZoneID            string                `json:"zoneId,omitempty"`
	OwnershipVerified bool                  `json:"ownershipVerified,omitempty"`
	// +listType=set
	Tags []string `json:"tags,omitempty"`
	// +listType=atomic
	Destinations []AccessApplicationDestinationStatus `json:"destinations,omitempty"`
	// +listType=atomic
	DataPlanes []AccessApplicationDataPlaneStatus `json:"dataPlanes,omitempty"`
	// +listType=map
	// +listMapKey=hostname
	// +listMapKey=path
	BypassApplications []AccessBypassApplicationStatus `json:"bypassApplications,omitempty"`
	// +listType=atomic
	Ancestors []gatewayv1.PolicyAncestorStatus `json:"ancestors,omitempty"`
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
// +kubebuilder:resource:scope=Namespaced,shortName=cfaa,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=Direct"
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Application",type=string,JSONPath=`.status.applicationId`

// AccessApplication attaches Cloudflare Access to Gateway API targets.
type AccessApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessApplicationSpec   `json:"spec,omitempty"`
	Status            AccessApplicationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessApplicationList contains AccessApplication objects.
type AccessApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessApplication `json:"items"`
}
