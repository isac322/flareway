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

// ZeroTrustOrganizationValues contains mutable organization settings. Pointers
// preserve omission separately from explicit false and empty values.
type ZeroTrustOrganizationValues struct {
	SessionDuration          *string `json:"sessionDuration,omitempty"`
	WARPAuthSessionDuration  *string `json:"warpAuthSessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool   `json:"allowAuthenticateViaWarp,omitempty"`
	IsUIReadOnly             *bool   `json:"isUiReadOnly,omitempty"`
	DenyUnmatchedRequests    *bool   `json:"denyUnmatchedRequests,omitempty"`
	WARPAuthNonBrowser401    *bool   `json:"warpAuthNonBrowser401,omitempty"`
}

// ZeroTrustOrganizationSpec defines the account Access organization singleton.
type ZeroTrustOrganizationSpec struct {
	AccountRef               corev1.LocalObjectReference `json:"accountRef"`
	SessionDuration          *string                     `json:"sessionDuration,omitempty"`
	WARPAuthSessionDuration  *string                     `json:"warpAuthSessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool                       `json:"allowAuthenticateViaWarp,omitempty"`
	IsUIReadOnly             *bool                       `json:"isUiReadOnly,omitempty"`
	DenyUnmatchedRequests    *bool                       `json:"denyUnmatchedRequests,omitempty"`
	WARPAuthNonBrowser401    *bool                       `json:"warpAuthNonBrowser401,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ZeroTrustOrganizationStatus records the canonical team domain and observed settings.
type ZeroTrustOrganizationStatus struct {
	AuthDomain string                       `json:"authDomain,omitempty"`
	Name       string                       `json:"name,omitempty"`
	Observed   ZeroTrustOrganizationValues  `json:"observed,omitempty"`
	WouldApply *ZeroTrustOrganizationValues `json:"wouldApply,omitempty"`
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
