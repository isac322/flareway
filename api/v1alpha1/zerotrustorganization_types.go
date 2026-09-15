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
	// ZeroTrustOrganizationFinalizer identifies organization cleanup.
	ZeroTrustOrganizationFinalizer = "flareway.bhyoo.com/zerotrustorganization"
	// ZeroTrustOrganizationConditionAccepted is a supported API value.
	ZeroTrustOrganizationConditionAccepted = "Accepted"
	// ZeroTrustOrganizationConditionReady is a supported API value.
	ZeroTrustOrganizationConditionReady = "Ready"
)

// ZeroTrustOrganizationMFAAuthenticator is an Access MFA method.
// +kubebuilder:validation:Enum=Totp;Biometrics;SecurityKey;PivKey;SshFido2Key
type ZeroTrustOrganizationMFAAuthenticator string

const (
	// ZeroTrustOrganizationMFAAuthenticatorTOTP uses one-time passwords.
	ZeroTrustOrganizationMFAAuthenticatorTOTP ZeroTrustOrganizationMFAAuthenticator = "Totp"
	// ZeroTrustOrganizationMFAAuthenticatorBiometrics uses platform biometrics.
	ZeroTrustOrganizationMFAAuthenticatorBiometrics ZeroTrustOrganizationMFAAuthenticator = "Biometrics"
	// ZeroTrustOrganizationMFAAuthenticatorSecurityKey uses WebAuthn security keys.
	ZeroTrustOrganizationMFAAuthenticatorSecurityKey ZeroTrustOrganizationMFAAuthenticator = "SecurityKey"
	// ZeroTrustOrganizationMFAAuthenticatorPIVKey uses PIV-backed SSH keys.
	ZeroTrustOrganizationMFAAuthenticatorPIVKey ZeroTrustOrganizationMFAAuthenticator = "PivKey"
	// ZeroTrustOrganizationMFAAuthenticatorSSHFIDO2Key uses FIDO2-backed SSH keys.
	ZeroTrustOrganizationMFAAuthenticatorSSHFIDO2Key ZeroTrustOrganizationMFAAuthenticator = "SshFido2Key"
)

// ZeroTrustOrganizationPIVPinPolicy controls PIV PIN prompting.
// +kubebuilder:validation:Enum=Never;Once;Always
type ZeroTrustOrganizationPIVPinPolicy string

const (
	// ZeroTrustOrganizationPIVPinPolicyNever disables PIV PIN prompts.
	ZeroTrustOrganizationPIVPinPolicyNever ZeroTrustOrganizationPIVPinPolicy = "Never"
	// ZeroTrustOrganizationPIVPinPolicyOnce prompts for the PIV PIN once.
	ZeroTrustOrganizationPIVPinPolicyOnce ZeroTrustOrganizationPIVPinPolicy = "Once"
	// ZeroTrustOrganizationPIVPinPolicyAlways prompts for the PIV PIN on every use.
	ZeroTrustOrganizationPIVPinPolicyAlways ZeroTrustOrganizationPIVPinPolicy = "Always"
)

// ZeroTrustOrganizationPIVSSHKeyType is an allowed SSH key algorithm.
// +kubebuilder:validation:Enum=Ecdsa;Ed25519;Rsa
type ZeroTrustOrganizationPIVSSHKeyType string

const (
	// ZeroTrustOrganizationPIVSSHKeyTypeECDSA permits ECDSA SSH keys.
	ZeroTrustOrganizationPIVSSHKeyTypeECDSA ZeroTrustOrganizationPIVSSHKeyType = "Ecdsa"
	// ZeroTrustOrganizationPIVSSHKeyTypeEd25519 permits Ed25519 SSH keys.
	ZeroTrustOrganizationPIVSSHKeyTypeEd25519 ZeroTrustOrganizationPIVSSHKeyType = "Ed25519"
	// ZeroTrustOrganizationPIVSSHKeyTypeRSA permits RSA SSH keys.
	ZeroTrustOrganizationPIVSSHKeyTypeRSA ZeroTrustOrganizationPIVSSHKeyType = "Rsa"
)

// ZeroTrustOrganizationPIVTouchPolicy controls hardware-key touch prompting.
// +kubebuilder:validation:Enum=Never;Always;Cached
type ZeroTrustOrganizationPIVTouchPolicy string

const (
	// ZeroTrustOrganizationPIVTouchPolicyNever disables hardware-key touch prompts.
	ZeroTrustOrganizationPIVTouchPolicyNever ZeroTrustOrganizationPIVTouchPolicy = "Never"
	// ZeroTrustOrganizationPIVTouchPolicyAlways requires hardware-key touch on every use.
	ZeroTrustOrganizationPIVTouchPolicyAlways ZeroTrustOrganizationPIVTouchPolicy = "Always"
	// ZeroTrustOrganizationPIVTouchPolicyCached reuses a recent hardware-key touch.
	ZeroTrustOrganizationPIVTouchPolicyCached ZeroTrustOrganizationPIVTouchPolicy = "Cached"
)

// ZeroTrustOrganizationCustomPageReferences selects organization deny pages.
type ZeroTrustOrganizationCustomPageReferences struct {
	Forbidden      *AccessObjectReference `json:"forbidden,omitempty"`
	IdentityDenied *AccessObjectReference `json:"identityDenied,omitempty"`
}

// ZeroTrustOrganizationCustomPageValues contains observed custom-page IDs.
type ZeroTrustOrganizationCustomPageValues struct {
	Forbidden      *string `json:"forbidden,omitempty"`
	IdentityDenied *string `json:"identityDenied,omitempty"`
}

// ZeroTrustOrganizationLoginDesign configures the Access login page.
type ZeroTrustOrganizationLoginDesign struct {
	BackgroundColor *string `json:"backgroundColor,omitempty"`
	FooterText      *string `json:"footerText,omitempty"`
	HeaderText      *string `json:"headerText,omitempty"`
	LogoPath        *string `json:"logoPath,omitempty"`
	TextColor       *string `json:"textColor,omitempty"`
}

// ZeroTrustOrganizationMFAConfig configures organization-wide MFA.
type ZeroTrustOrganizationMFAConfig struct {
	// +listType=set
	// +kubebuilder:validation:MaxItems=5
	AllowedAuthenticators      *[]ZeroTrustOrganizationMFAAuthenticator `json:"allowedAuthenticators,omitempty"`
	AMRMatchingSessionDuration *string                                  `json:"amrMatchingSessionDuration,omitempty"`
	RequiredAAGUIDs            *string                                  `json:"requiredAaguids,omitempty"`
	SessionDuration            *string                                  `json:"sessionDuration,omitempty"`
}

// ZeroTrustOrganizationMFAPIVKeyRequirements configures hardware SSH keys.
type ZeroTrustOrganizationMFAPIVKeyRequirements struct {
	PinPolicy         *ZeroTrustOrganizationPIVPinPolicy `json:"pinPolicy,omitempty"`
	RequireFIPSDevice *bool                              `json:"requireFipsDevice,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=6
	SSHKeySizes *[]int64 `json:"sshKeySizes,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=3
	SSHKeyTypes *[]ZeroTrustOrganizationPIVSSHKeyType `json:"sshKeyTypes,omitempty"`
	TouchPolicy *ZeroTrustOrganizationPIVTouchPolicy  `json:"touchPolicy,omitempty"`
}

// ZeroTrustOrganizationUserRevocation requests one idempotent user revocation.
type ZeroTrustOrganizationUserRevocation struct {
	// +kubebuilder:validation:MinLength=1
	Email             string       `json:"email"`
	UserUID           *string      `json:"userUid,omitempty"`
	Devices           *bool        `json:"devices,omitempty"`
	WARPSessionReauth *bool        `json:"warpSessionReauth,omitempty"`
	RequestedAt       *metav1.Time `json:"requestedAt,omitempty"`
}

// ZeroTrustOrganizationDOH configures account-scoped Access DoH authentication.
type ZeroTrustOrganizationDOH struct {
	ServiceTokenRef AccessObjectReference `json:"serviceTokenRef"`
	JWTDuration     *string               `json:"jwtDuration,omitempty"`
}

// ZeroTrustOrganizationDOHValues contains non-secret observed DoH settings.
type ZeroTrustOrganizationDOHValues struct {
	ServiceTokenID *string `json:"serviceTokenId,omitempty"`
	JWTDuration    *string `json:"jwtDuration,omitempty"`
}

// ZeroTrustOrganizationValues contains mutable organization settings returned
// by Cloudflare. Pointers let WouldApply distinguish false, empty, and omitted.
type ZeroTrustOrganizationValues struct {
	Name                     *string `json:"name,omitempty"`
	SessionDuration          *string `json:"sessionDuration,omitempty"`
	WARPAuthSessionDuration  *string `json:"warpAuthSessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool   `json:"allowAuthenticateViaWarp,omitempty"`
	AutoRedirectToIdentity   *bool   `json:"autoRedirectToIdentity,omitempty"`
	IsUIReadOnly             *bool   `json:"isUiReadOnly,omitempty"`
	UIReadOnlyToggleReason   *string `json:"uiReadOnlyToggleReason,omitempty"`
	DenyUnmatchedRequests    *bool   `json:"denyUnmatchedRequests,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1000
	DenyUnmatchedRequestsExemptedZoneNames *[]string                                   `json:"denyUnmatchedRequestsExemptedZoneNames,omitempty"`
	WARPAuthNonBrowser401                  *bool                                       `json:"warpAuthNonBrowser401,omitempty"`
	UserSeatExpirationInactiveTime         *string                                     `json:"userSeatExpirationInactiveTime,omitempty"`
	CustomPages                            *ZeroTrustOrganizationCustomPageValues      `json:"customPages,omitempty"`
	LoginDesign                            *ZeroTrustOrganizationLoginDesign           `json:"loginDesign,omitempty"`
	MFAConfig                              *ZeroTrustOrganizationMFAConfig             `json:"mfaConfig,omitempty"`
	MFAPIVKeyRequirements                  *ZeroTrustOrganizationMFAPIVKeyRequirements `json:"mfaPivKeyRequirements,omitempty"`
	MFARequiredForAllApps                  *bool                                       `json:"mfaRequiredForAllApps,omitempty"`
	DOH                                    *ZeroTrustOrganizationDOHValues             `json:"doh,omitempty"`
}

// ZeroTrustOrganizationSpec defines one account- or zone-scoped Access organization.
// AuthDomain is create-only and is never sent by update operations.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.authDomain) || (has(self.authDomain) && self.authDomain == oldSelf.authDomain)",message="authDomain cannot change once set"
type ZeroTrustOrganizationSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Zone is an optional DNS zone name from CloudflareAccount.status.verified.zones.
	Zone string `json:"zone,omitempty"`
	// AuthDomain is required only when a Managed organization must be created.
	AuthDomain               *string `json:"authDomain,omitempty"`
	Name                     *string `json:"name,omitempty"`
	SessionDuration          *string `json:"sessionDuration,omitempty"`
	WARPAuthSessionDuration  *string `json:"warpAuthSessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool   `json:"allowAuthenticateViaWarp,omitempty"`
	AutoRedirectToIdentity   *bool   `json:"autoRedirectToIdentity,omitempty"`
	IsUIReadOnly             *bool   `json:"isUiReadOnly,omitempty"`
	UIReadOnlyToggleReason   *string `json:"uiReadOnlyToggleReason,omitempty"`
	DenyUnmatchedRequests    *bool   `json:"denyUnmatchedRequests,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1000
	DenyUnmatchedRequestsExemptedZoneNames *[]string                                   `json:"denyUnmatchedRequestsExemptedZoneNames,omitempty"`
	WARPAuthNonBrowser401                  *bool                                       `json:"warpAuthNonBrowser401,omitempty"`
	UserSeatExpirationInactiveTime         *string                                     `json:"userSeatExpirationInactiveTime,omitempty"`
	CustomPages                            *ZeroTrustOrganizationCustomPageReferences  `json:"customPages,omitempty"`
	LoginDesign                            *ZeroTrustOrganizationLoginDesign           `json:"loginDesign,omitempty"`
	MFAConfig                              *ZeroTrustOrganizationMFAConfig             `json:"mfaConfig,omitempty"`
	MFAPIVKeyRequirements                  *ZeroTrustOrganizationMFAPIVKeyRequirements `json:"mfaPivKeyRequirements,omitempty"`
	MFARequiredForAllApps                  *bool                                       `json:"mfaRequiredForAllApps,omitempty"`
	UserRevocation                         *ZeroTrustOrganizationUserRevocation        `json:"userRevocation,omitempty"`
	DOH                                    *ZeroTrustOrganizationDOH                   `json:"doh,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`
	// Organization deletion is always orphaning because Cloudflare exposes no delete endpoint.
	// +kubebuilder:validation:Enum=Orphan
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ZeroTrustOrganizationStatus records bounded, non-secret observed state.
type ZeroTrustOrganizationStatus struct {
	AuthDomain                    string                       `json:"authDomain,omitempty"`
	Observed                      ZeroTrustOrganizationValues  `json:"observed,omitempty"`
	WouldApply                    *ZeroTrustOrganizationValues `json:"wouldApply,omitempty"`
	ObservedUserRevocationRequest *metav1.Time                 `json:"observedUserRevocationRequest,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=ztorg,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="ZeroTrustOrganization must be named default"
// +kubebuilder:printcolumn:name="Auth Domain",type=string,JSONPath=`.status.authDomain`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// ZeroTrustOrganization manages the Cloudflare Zero Trust organization singleton.
type ZeroTrustOrganization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ZeroTrustOrganizationSpec   `json:"spec,omitempty"`
	Status            ZeroTrustOrganizationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZeroTrustOrganizationList contains ZeroTrustOrganization objects.
type ZeroTrustOrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZeroTrustOrganization `json:"items"`
}
