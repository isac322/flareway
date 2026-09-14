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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	// CloudflareAccountConditionAccepted is a supported API value.
	CloudflareAccountConditionAccepted = "Accepted"
	// CloudflareAccountConditionCredentialsValid is a supported API value.
	CloudflareAccountConditionCredentialsValid = "CredentialsValid"
)

// Exposure selects a Cloudflare public-edge or private-WARP exposure.
// +kubebuilder:validation:Enum=Public;Private
type Exposure string

const (
	// ExposurePublic is a supported API value.
	ExposurePublic Exposure = "Public"
	// ExposurePrivate is a supported API value.
	ExposurePrivate Exposure = "Private"
)

// GrantPermission is an explicit allow or deny gate in a CloudflareAccount grant.
// +kubebuilder:validation:Enum=Allowed;Denied
type GrantPermission string

const (
	// GrantPermissionAllowed is a supported API value.
	GrantPermissionAllowed GrantPermission = "Allowed"
	// GrantPermissionDenied is a supported API value.
	GrantPermissionDenied GrantPermission = "Denied"
)

// BackendNamespaceMode selects which backend namespaces a grant permits.
// +kubebuilder:validation:Enum=Same;Selector
type BackendNamespaceMode string

const (
	// BackendNamespaceSame is a supported API value.
	BackendNamespaceSame BackendNamespaceMode = "Same"
	// BackendNamespaceSelector is a supported API value.
	BackendNamespaceSelector BackendNamespaceMode = "Selector"
)

// BackendKind is a Kubernetes backend kind permitted by an account grant.
// +kubebuilder:validation:Enum=Service
type BackendKind string

// BackendKindService identifies a Service backend.
const BackendKindService BackendKind = "Service"

// NamespacedSecretKeyReference identifies one key in a namespaced Secret.
type NamespacedSecretKeyReference struct {
	// Name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the Secret namespace.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Key is the key containing the API token.
	// +kubebuilder:default=token
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`
}

// CloudflareAccountCredentials references credentials used for an account.
type CloudflareAccountCredentials struct {
	// APITokenSecretRef identifies the Cloudflare API token.
	APITokenSecretRef NamespacedSecretKeyReference `json:"apiTokenSecretRef"`
}

// CloudflarePrivateRouteGrant authorizes platform private-route objects selected by labels.
type CloudflarePrivateRouteGrant struct {
	// NetworkRouteSelector selects permitted NetworkRoute objects. An empty selector matches all.
	NetworkRouteSelector *metav1.LabelSelector `json:"networkRouteSelector,omitempty"`

	// HostnameRouteSelector selects permitted HostnameRoute objects. An empty selector matches all.
	HostnameRouteSelector *metav1.LabelSelector `json:"hostnameRouteSelector,omitempty"`
}

// CloudflareBackendGrant adds an account-level SSRF boundary on top of ReferenceGrant.
// +kubebuilder:validation:XValidation:rule="self.namespaces != 'Selector' || has(self.selector)",message="selector is required when namespaces is Selector"
type CloudflareBackendGrant struct {
	// Namespaces selects same-namespace backends or namespaces matching Selector.
	// +kubebuilder:default=Same
	Namespaces BackendNamespaceMode `json:"namespaces,omitempty"`

	// Selector selects backend namespaces when Namespaces is Selector.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Kinds lists permitted backend kinds.
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Kinds []BackendKind `json:"kinds"`
}

// CloudflareAccountGrant authorizes one set of tenant operations.
type CloudflareAccountGrant struct {
	// NamespaceSelector selects namespaces governed by this grant.
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`

	// Hostnames contains exact hostnames, single-label wildcard hostnames, or "*".
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Hostnames []string `json:"hostnames"`

	// Zones contains exact zone names or "*".
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Zones []string `json:"zones"`

	// Exposures lists permitted listener exposures.
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Exposures []Exposure `json:"exposures"`

	// UnprotectedHostnames lists hostnames allowed without Cloudflare Access.
	// +listType=set
	UnprotectedHostnames []string `json:"unprotectedHostnames,omitempty"`

	// AccessPolicyRefs permits references to platform Access policy objects.
	// +kubebuilder:default=Denied
	AccessPolicyRefs GrantPermission `json:"accessPolicyRefs,omitempty"`

	// PrivateRoutes selects platform private-route objects this namespace may reference.
	PrivateRoutes *CloudflarePrivateRouteGrant `json:"privateRoutes,omitempty"`

	// Backends configures the account-level backend SSRF boundary.
	Backends *CloudflareBackendGrant `json:"backends,omitempty"`

	// PlatformObjects permits creation or management of platform-scoped objects.
	// +kubebuilder:default=Denied
	PlatformObjects GrantPermission `json:"platformObjects,omitempty"`
}

// CloudflareAccountSpec defines credentials and tenant authorization for one account.
type CloudflareAccountSpec struct {
	// AccountID is the Cloudflare account identifier.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{32}$`
	AccountID string `json:"accountId"`

	// Credentials references the API token used for this account.
	Credentials CloudflareAccountCredentials `json:"credentials"`

	// Grants define tenant authorization. A namespace matching no grant is denied.
	// +listType=atomic
	Grants []CloudflareAccountGrant `json:"grants,omitempty"`
}

// CloudflareVerifiedZone is a zone observed while verifying account credentials.
type CloudflareVerifiedZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CloudflareAccountVerifiedStatus records non-secret account information returned by Cloudflare.
type CloudflareAccountVerifiedStatus struct {
	AccountName string `json:"accountName,omitempty"`
	AuthDomain  string `json:"authDomain,omitempty"`
	TeamName    string `json:"teamName,omitempty"`

	// +listType=map
	// +listMapKey=id
	Zones []CloudflareVerifiedZone `json:"zones,omitempty"`

	// TokenPermissions never contains token values or request bodies.
	// +listType=set
	TokenPermissions []string `json:"tokenPermissions,omitempty"`
}

// CloudflareAccountStatus defines observed account verification state.
type CloudflareAccountStatus struct {
	Verified CloudflareAccountVerifiedStatus `json:"verified,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=cfa,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Credentials",type=string,JSONPath=`.status.conditions[?(@.type=="CredentialsValid")].status`
// +kubebuilder:printcolumn:name="Account",type=string,JSONPath=`.status.verified.accountName`

// CloudflareAccount defines a Cloudflare account and tenant authorization boundary.
type CloudflareAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudflareAccountSpec   `json:"spec,omitempty"`
	Status CloudflareAccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CloudflareAccountList contains CloudflareAccount objects.
type CloudflareAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudflareAccount `json:"items"`
}
