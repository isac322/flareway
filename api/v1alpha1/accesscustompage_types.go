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
	// AccessCustomPageFinalizer identifies the finalizer used for remote cleanup.
	AccessCustomPageFinalizer = "flareway.bhyoo.com/accesscustompage"
	// AccessCustomPageConditionAccepted reports whether the desired page is valid and authorized.
	AccessCustomPageConditionAccepted = "Accepted"
	// AccessCustomPageConditionReady reports whether the remote page is available.
	AccessCustomPageConditionReady = "Ready"
	// AccessCustomPageConditionDegraded reports drift or advisory template warnings.
	AccessCustomPageConditionDegraded = "Degraded"
	// AccessCustomPageConditionCleanupBlocked reports references that prevent deletion.
	AccessCustomPageConditionCleanupBlocked = "CleanupBlocked"
)

// AccessCustomPageType identifies where Cloudflare displays a custom page.
// +kubebuilder:validation:Enum=IdentityDenied;Forbidden;Login;Interstitial
type AccessCustomPageType string

const (
	// AccessCustomPageTypeIdentityDenied is shown when identity cannot be verified.
	AccessCustomPageTypeIdentityDenied AccessCustomPageType = "IdentityDenied"
	// AccessCustomPageTypeForbidden is shown when a policy denies access.
	AccessCustomPageTypeForbidden AccessCustomPageType = "Forbidden"
	// AccessCustomPageTypeLogin replaces the Access login page.
	AccessCustomPageTypeLogin AccessCustomPageType = "Login"
	// AccessCustomPageTypeInterstitial replaces the Access interstitial page.
	AccessCustomPageTypeInterstitial AccessCustomPageType = "Interstitial"
)

// AccessCustomPageExternalReference identifies an existing Cloudflare Access custom page.
type AccessCustomPageExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	CustomPageID string `json:"customPageId"`
}

// AccessCustomPageSpec defines one account-level Cloudflare Access custom page.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
type AccessCustomPageSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string               `json:"name"`
	Type AccessCustomPageType `json:"type"`
	// HTML is the Access page's HTML and Liquid template.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=262144
	HTML string `json:"html"`
	// ContractVersion selects Cloudflare's sanitized Liquid template contract.
	// An omitted value uses legacy verbatim rendering.
	// +kubebuilder:validation:Minimum=1
	ContractVersion int64 `json:"contractVersion,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                   `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessCustomPageExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessCustomPageObservedStatus records mutable remote fields without duplicating HTML.
type AccessCustomPageObservedStatus struct {
	Name            string               `json:"name,omitempty"`
	Type            AccessCustomPageType `json:"type,omitempty"`
	ContractVersion int64                `json:"contractVersion,omitempty"`
}

// AccessCustomPageStatus defines the observed state of AccessCustomPage.
type AccessCustomPageStatus struct {
	CustomPageID      string                          `json:"customPageId,omitempty"`
	OwnershipVerified bool                            `json:"ownershipVerified,omitempty"`
	Observed          *AccessCustomPageObservedStatus `json:"observed,omitempty"`
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
// +kubebuilder:resource:scope=Namespaced,shortName=cfacp,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Page",type=string,JSONPath=`.status.customPageId`

// AccessCustomPage is a platform-scoped Cloudflare Access custom page.
type AccessCustomPage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessCustomPageSpec   `json:"spec,omitempty"`
	Status            AccessCustomPageStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessCustomPageList contains AccessCustomPage objects.
type AccessCustomPageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessCustomPage `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AccessCustomPage{}, &AccessCustomPageList{})
		return nil
	})
}
