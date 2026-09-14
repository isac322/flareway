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

// IdentityProviderFinalizer identifies the IdP cleanup finalizer.
const IdentityProviderFinalizer = "flareway.bhyoo.com/identityprovider"

// IdentityProviderType identifies a Cloudflare Access IdP integration.
// +kubebuilder:validation:Enum=onetimepin;azureAD;saml;centrify;facebook;github;google-apps;google;linkedin;oidc;okta;onelogin;pingone;yandex;cloudflare
type IdentityProviderType string

// IdentityProviderPrompt controls account selection in supported IdPs.
// +kubebuilder:validation:Enum=login;select_account;none
type IdentityProviderPrompt string

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
	ConditionalAccessEnabled bool                   `json:"conditionalAccessEnabled,omitempty"`
	SupportGroups            bool                   `json:"supportGroups,omitempty"`
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
	PKCEEnabled              bool                   `json:"pkceEnabled,omitempty"`
	// +listType=set
	Scopes []string `json:"scopes,omitempty"`
	// +listType=set
	Attributes         []string `json:"attributes,omitempty"`
	EmailAttributeName string   `json:"emailAttributeName,omitempty"`
	EnableEncryption   bool     `json:"enableEncryption,omitempty"`
	ForceAuthn         bool     `json:"forceAuthn,omitempty"`
	// +listType=atomic
	HeaderAttributes []IdentityProviderSAMLHeaderAttribute `json:"headerAttributes,omitempty"`
	// +listType=set
	IDPPublicCerts           []string `json:"idpPublicCerts,omitempty"`
	IssuerURL                string   `json:"issuerUrl,omitempty"`
	MaxSSOURLLength          int64    `json:"maxSsoUrlLength,omitempty"`
	SignRequest              bool     `json:"signRequest,omitempty"`
	SSOTargetURL             string   `json:"ssoTargetUrl,omitempty"`
	RestrictToAccountMembers bool     `json:"restrictToAccountMembers,omitempty"`
}

// IdentityProviderSCIMIdentityUpdateBehavior controls how SCIM changes affect identities.
// +kubebuilder:validation:Enum=automatic;reauth;no_action
type IdentityProviderSCIMIdentityUpdateBehavior string

// IdentityProviderSCIMConfig configures SCIM synchronization.
type IdentityProviderSCIMConfig struct {
	Enabled                bool                                       `json:"enabled,omitempty"`
	IdentityUpdateBehavior IdentityProviderSCIMIdentityUpdateBehavior `json:"identityUpdateBehavior,omitempty"`
	SeatDeprovision        bool                                       `json:"seatDeprovision,omitempty"`
	UserDeprovision        bool                                       `json:"userDeprovision,omitempty"`
}

// IdentityProviderExternalReference identifies an existing IdP.
type IdentityProviderExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	IDPID string `json:"idpId"`
}

// IdentityProviderSpec defines a shared Cloudflare Access identity provider.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
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
