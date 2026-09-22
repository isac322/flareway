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

// AccessGroupFinalizer identifies the finalizer used for AccessGroup cleanup.
const AccessGroupFinalizer = "flareway.bhyoo.com/accessgroup"

// AccessGroupExternalReference identifies an existing Cloudflare Access group.
type AccessGroupExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	GroupID string `json:"groupId"`
}

// AccessGroupSpec defines a reusable group of Access rules.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessGroupSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Zone optionally scopes the group to the verified Cloudflare zone with this DNS name.
	// When omitted, the group is account scoped.
	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone,omitempty"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Include []AccessRule `json:"include"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Require []AccessRule `json:"require,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Exclude []AccessRule `json:"exclude,omitempty"`
	// IsDefault requests that Cloudflare make this the default Access group.
	IsDefault bool `json:"isDefault,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy              `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessGroupExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessGroupObservedState records the remote group state returned by Cloudflare.
//
// Cloudflare's Access group response schema exposes is_default inconsistently:
// some responses contain a boolean while others contain a rule array. IsDefault
// and Default preserve both forms without guessing.
type AccessGroupObservedState struct {
	Name string `json:"name"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Include []AccessRuleObservation `json:"include,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Require []AccessRuleObservation `json:"require,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Exclude   []AccessRuleObservation `json:"exclude,omitempty"`
	IsDefault *bool                   `json:"isDefault,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Default []AccessRuleObservation `json:"default,omitempty"`
}

// AccessGroupStatus records the remote group identity and conditions.
type AccessGroupStatus struct {
	GroupID           string                    `json:"groupId,omitempty"`
	ZoneID            string                    `json:"zoneId,omitempty"`
	OwnershipVerified bool                      `json:"ownershipVerified,omitempty"`
	Observed          *AccessGroupObservedState `json:"observed,omitempty"`
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
// +kubebuilder:resource:scope=Namespaced,shortName=cfag,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=`.status.groupId`

// AccessGroup is a namespaced Cloudflare Access group resource.
type AccessGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessGroupSpec   `json:"spec,omitempty"`
	Status            AccessGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessGroupList contains AccessGroup objects.
type AccessGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessGroup `json:"items"`
}
