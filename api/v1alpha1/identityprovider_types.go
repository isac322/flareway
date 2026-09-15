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
)

const (
	// IdentityProviderFinalizer identifies the IdP cleanup finalizer.
	IdentityProviderFinalizer = "flareway.bhyoo.com/identityprovider"
	// IdentityProviderSCIMSecretKey stores the one-time SCIM bearer token.
	IdentityProviderSCIMSecretKey = "secret"
	// IdentityProviderIDAnnotation records the IdP that issued an owned SCIM Secret.
	IdentityProviderIDAnnotation = "flareway.bhyoo.com/identity-provider-id"
)

// IdentityProviderType identifies a Cloudflare Access IdP integration.
// +kubebuilder:validation:Enum=OneTimePIN;AzureAD;SAML;Centrify;Facebook;GitHub;GoogleApps;Google;LinkedIn;OIDC;Okta;OneLogin;PingOne;Yandex;Cloudflare
type IdentityProviderType string

const (
	// IdentityProviderTypeOneTimePIN selects Cloudflare's one-time PIN provider.
	IdentityProviderTypeOneTimePIN IdentityProviderType = "OneTimePIN"
	// IdentityProviderTypeAzureAD selects the Microsoft Azure AD provider.
	IdentityProviderTypeAzureAD IdentityProviderType = "AzureAD"
	// IdentityProviderTypeSAML selects a SAML identity provider.
	IdentityProviderTypeSAML IdentityProviderType = "SAML"
	// IdentityProviderTypeCentrify selects the Centrify provider.
	IdentityProviderTypeCentrify IdentityProviderType = "Centrify"
	// IdentityProviderTypeFacebook selects the Facebook provider.
	IdentityProviderTypeFacebook IdentityProviderType = "Facebook"
	// IdentityProviderTypeGitHub selects the GitHub provider.
	IdentityProviderTypeGitHub IdentityProviderType = "GitHub"
	// IdentityProviderTypeGoogleApps selects the Google Workspace provider.
	IdentityProviderTypeGoogleApps IdentityProviderType = "GoogleApps"
	// IdentityProviderTypeGoogle selects the Google provider.
	IdentityProviderTypeGoogle IdentityProviderType = "Google"
	// IdentityProviderTypeLinkedIn selects the LinkedIn provider.
	IdentityProviderTypeLinkedIn IdentityProviderType = "LinkedIn"
	// IdentityProviderTypeOIDC selects a generic OpenID Connect provider.
	IdentityProviderTypeOIDC IdentityProviderType = "OIDC"
	// IdentityProviderTypeOkta selects the Okta provider.
	IdentityProviderTypeOkta IdentityProviderType = "Okta"
	// IdentityProviderTypeOneLogin selects the OneLogin provider.
	IdentityProviderTypeOneLogin IdentityProviderType = "OneLogin"
	// IdentityProviderTypePingOne selects the PingOne provider.
	IdentityProviderTypePingOne IdentityProviderType = "PingOne"
	// IdentityProviderTypeYandex selects the Yandex provider.
	IdentityProviderTypeYandex IdentityProviderType = "Yandex"
	// IdentityProviderTypeCloudflare selects the Cloudflare provider.
	IdentityProviderTypeCloudflare IdentityProviderType = "Cloudflare"
)

// IdentityProviderPrompt controls account selection in supported IdPs.
// +kubebuilder:validation:Enum=Login;SelectAccount;None
type IdentityProviderPrompt string

const (
	// IdentityProviderPromptLogin requests the provider's login prompt.
	IdentityProviderPromptLogin IdentityProviderPrompt = "Login"
	// IdentityProviderPromptSelectAccount requests the provider's account chooser.
	IdentityProviderPromptSelectAccount IdentityProviderPrompt = "SelectAccount"
	// IdentityProviderPromptNone suppresses an explicit provider prompt.
	IdentityProviderPromptNone IdentityProviderPrompt = "None"
)

// IdentityProviderSecretReference identifies a local Secret key.
type IdentityProviderSecretReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:default=clientSecret
	Key string `json:"key,omitempty"`
}

// IdentityProviderSAMLHeaderAttribute maps a SAML attribute to an Access header.
type IdentityProviderSAMLHeaderAttribute struct {
	Name          string `json:"name"`
	AttributeName string `json:"attributeName"`
}

// IdentityProviderConfig contains typed provider-specific settings. Type selects
// which fields are sent to Cloudflare.
type IdentityProviderConfig struct {
	ClientID        string                           `json:"clientId,omitempty"`
	ClientSecretRef *IdentityProviderSecretReference `json:"clientSecretRef,omitempty"`
	// +listType=set
	Claims                   []string               `json:"claims,omitempty"`
	EmailClaimName           string                 `json:"emailClaimName,omitempty"`
	DirectoryID              string                 `json:"directoryId,omitempty"`
	ConditionalAccessEnabled *bool                  `json:"conditionalAccessEnabled,omitempty"`
	SupportGroups            *bool                  `json:"supportGroups,omitempty"`
	Prompt                   IdentityProviderPrompt `json:"prompt,omitempty"`
	AppsDomain               string                 `json:"appsDomain,omitempty"`
	CentrifyAccount          string                 `json:"centrifyAccount,omitempty"`
	CentrifyAppID            string                 `json:"centrifyAppId,omitempty"`
	AuthorizationServerID    string                 `json:"authorizationServerId,omitempty"`
	OktaAccount              string                 `json:"oktaAccount,omitempty"`
	OneloginAccount          string                 `json:"oneloginAccount,omitempty"`
	PingEnvironmentID        string                 `json:"pingEnvironmentId,omitempty"`
	AuthURL                  string                 `json:"authUrl,omitempty"`
	CertsURL                 string                 `json:"certsUrl,omitempty"`
	TokenURL                 string                 `json:"tokenUrl,omitempty"`
	PKCEEnabled              *bool                  `json:"pkceEnabled,omitempty"`
	// +listType=set
	Scopes []string `json:"scopes,omitempty"`
	// +listType=set
	Attributes         []string `json:"attributes,omitempty"`
	EmailAttributeName string   `json:"emailAttributeName,omitempty"`
	EnableEncryption   *bool    `json:"enableEncryption,omitempty"`
	ForceAuthn         *bool    `json:"forceAuthn,omitempty"`
	// +listType=atomic
	HeaderAttributes []IdentityProviderSAMLHeaderAttribute `json:"headerAttributes,omitempty"`
	// +listType=set
	IDPPublicCerts           []string `json:"idpPublicCerts,omitempty"`
	IssuerURL                string   `json:"issuerUrl,omitempty"`
	MaxSSOURLLength          *int64   `json:"maxSsoUrlLength,omitempty"`
	SignRequest              *bool    `json:"signRequest,omitempty"`
	SSOTargetURL             string   `json:"ssoTargetUrl,omitempty"`
	RestrictToAccountMembers *bool    `json:"restrictToAccountMembers,omitempty"`
}

// IdentityProviderSCIMIdentityUpdateBehavior controls how SCIM changes affect identities.
// +kubebuilder:validation:Enum=Automatic;Reauth;NoAction
type IdentityProviderSCIMIdentityUpdateBehavior string

const (
	// IdentityProviderSCIMIdentityUpdateAutomatic applies SCIM identity changes automatically.
	IdentityProviderSCIMIdentityUpdateAutomatic IdentityProviderSCIMIdentityUpdateBehavior = "Automatic"
	// IdentityProviderSCIMIdentityUpdateReauth requires reauthentication after SCIM identity changes.
	IdentityProviderSCIMIdentityUpdateReauth IdentityProviderSCIMIdentityUpdateBehavior = "Reauth"
	// IdentityProviderSCIMIdentityUpdateNoAction leaves authentication unchanged after SCIM identity changes.
	IdentityProviderSCIMIdentityUpdateNoAction IdentityProviderSCIMIdentityUpdateBehavior = "NoAction"
)

// IdentityProviderSCIMConfig configures SCIM synchronization.
type IdentityProviderSCIMConfig struct {
	Enabled                *bool                                      `json:"enabled,omitempty"`
	IdentityUpdateBehavior IdentityProviderSCIMIdentityUpdateBehavior `json:"identityUpdateBehavior,omitempty"`
	SeatDeprovision        *bool                                      `json:"seatDeprovision,omitempty"`
	UserDeprovision        *bool                                      `json:"userDeprovision,omitempty"`
	SecretRef              *corev1.LocalObjectReference               `json:"secretRef,omitempty"`
}

// IdentityProviderSAMLCertificateStatus records one public SAML encryption certificate.
type IdentityProviderSAMLCertificateStatus struct {
	ID                string       `json:"id,omitempty"`
	Current           bool         `json:"current,omitempty"`
	NotAfter          *metav1.Time `json:"notAfter,omitempty"`
	PublicCertificate string       `json:"publicCertificate,omitempty"`
}

// IdentityProviderSAMLCertificateSetStatus records the assigned SAML encryption certificate set.
type IdentityProviderSAMLCertificateSetStatus struct {
	ID string `json:"id,omitempty"`
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`
	// +optional
	UpdatedAt *metav1.Time                           `json:"updatedAt,omitempty"`
	Current   *IdentityProviderSAMLCertificateStatus `json:"current,omitempty"`
	Previous  *IdentityProviderSAMLCertificateStatus `json:"previous,omitempty"`
}

// IdentityProviderSCIMUserStatus is a bounded, credential-free SCIM user observation.
type IdentityProviderSCIMUserStatus struct {
	// +kubebuilder:validation:MinLength=1
	ID          string `json:"id"`
	ExternalID  string `json:"externalId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Active      bool   `json:"active,omitempty"`
	// +kubebuilder:validation:MaxItems=10
	// +listType=set
	Emails []string `json:"emails,omitempty"`
}

// IdentityProviderSCIMGroupStatus is a bounded, credential-free SCIM group observation.
type IdentityProviderSCIMGroupStatus struct {
	// +kubebuilder:validation:MinLength=1
	ID          string `json:"id"`
	ExternalID  string `json:"externalId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// IdentityProviderSCIMDirectoryStatus records at most one API page of SCIM resources.
type IdentityProviderSCIMDirectoryStatus struct {
	BaseURL string `json:"baseUrl,omitempty"`
	// +kubebuilder:validation:MaxItems=50
	// +listType=map
	// +listMapKey=id
	Users []IdentityProviderSCIMUserStatus `json:"users,omitempty"`
	// +kubebuilder:validation:MaxItems=50
	// +listType=map
	// +listMapKey=id
	Groups          []IdentityProviderSCIMGroupStatus `json:"groups,omitempty"`
	UsersTruncated  bool                              `json:"usersTruncated,omitempty"`
	GroupsTruncated bool                              `json:"groupsTruncated,omitempty"`
}

// IdentityProviderExternalReference identifies an existing IdP.
type IdentityProviderExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	IDPID string `json:"idpId"`
}

// IdentityProviderSpec defines a shared Cloudflare Access identity provider.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.scimConfig) || !has(self.scimConfig.enabled) || !self.scimConfig.enabled || has(self.scimConfig.secretRef)",message="SCIM secretRef is required when SCIM is enabled"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.scimConfig) || !has(oldSelf.scimConfig.secretRef) || (has(self.scimConfig) && has(self.scimConfig.secretRef) && self.scimConfig.secretRef == oldSelf.scimConfig.secretRef)",message="SCIM secretRef is immutable once set"
type IdentityProviderSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	Type       IdentityProviderType        `json:"type"`
	// +kubebuilder:validation:MinLength=1
	Name       string                      `json:"name"`
	Config     IdentityProviderConfig      `json:"config,omitempty"`
	SCIMConfig *IdentityProviderSCIMConfig `json:"scimConfig,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy                   `json:"managementPolicy,omitempty"`
	ExternalRef      *IdentityProviderExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// IdentityProviderStatus records the remote IdP identity and conditions.
type IdentityProviderStatus struct {
	IDPID             string `json:"idpId,omitempty"`
	OwnershipVerified bool   `json:"ownershipVerified,omitempty"`
	ReadOnly          bool   `json:"readOnly,omitempty"`
	// RedirectURL is Cloudflare's read-only login URL for OneTimePIN and Cloudflare providers.
	// +kubebuilder:validation:MaxLength=2048
	RedirectURL        string                                    `json:"redirectUrl,omitempty"`
	SAMLCertificateSet *IdentityProviderSAMLCertificateSetStatus `json:"samlCertificateSet,omitempty"`
	SCIMDirectory      *IdentityProviderSCIMDirectoryStatus      `json:"scimDirectory,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfidp,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="IdP",type=string,JSONPath=`.status.idpId`

// IdentityProvider is a namespaced Cloudflare Access identity provider.
type IdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IdentityProviderSpec   `json:"spec,omitempty"`
	Status            IdentityProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IdentityProviderList contains IdentityProvider objects.
type IdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IdentityProvider `json:"items"`
}
