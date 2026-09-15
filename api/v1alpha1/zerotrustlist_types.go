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
	// ZeroTrustListFinalizer identifies list cleanup.
	ZeroTrustListFinalizer = "flareway.bhyoo.com/zerotrustlist"
	// ZeroTrustListConditionAccepted is a supported API value.
	ZeroTrustListConditionAccepted = "Accepted"
	// ZeroTrustListConditionReady is a supported API value.
	ZeroTrustListConditionReady = "Ready"
)

// ZeroTrustListType selects the Cloudflare Gateway list item parser.
// +kubebuilder:validation:Enum=SERIAL;URL;DOMAIN;EMAIL;IP
type ZeroTrustListType string

const (
	// ZeroTrustListTypeSerial stores serial-number items.
	ZeroTrustListTypeSerial ZeroTrustListType = "SERIAL"
	// ZeroTrustListTypeURL is a supported API value.
	ZeroTrustListTypeURL ZeroTrustListType = "URL"
	// ZeroTrustListTypeDomain is a supported API value.
	ZeroTrustListTypeDomain ZeroTrustListType = "DOMAIN"
	// ZeroTrustListTypeEmail is a supported API value.
	ZeroTrustListTypeEmail ZeroTrustListType = "EMAIL"
	// ZeroTrustListTypeIP is a supported API value.
	ZeroTrustListTypeIP ZeroTrustListType = "IP"
)

// ZeroTrustListExternalReference identifies an existing Cloudflare Gateway list.
type ZeroTrustListExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	ListID string `json:"listId"`
}

// ZeroTrustListSpec defines a whole-object Cloudflare Gateway list.
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
type ZeroTrustListSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	Name string            `json:"name"`
	Type ZeroTrustListType `json:"type"`
	// +listType=set
	Items []string `json:"items,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy                `json:"managementPolicy,omitempty"`
	ExternalRef      *ZeroTrustListExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ZeroTrustListObservedState records non-secret remote list state.
type ZeroTrustListObservedState struct {
	Name string            `json:"name"`
	Type ZeroTrustListType `json:"type"`
	// +listType=set
	Items []string `json:"items,omitempty"`
}

// ZeroTrustListItemsDiff is the item-level ObserveOnly diff.
type ZeroTrustListItemsDiff struct {
	// +listType=set
	Add []string `json:"add,omitempty"`
	// +listType=set
	Remove []string `json:"remove,omitempty"`
}

// ZeroTrustListStatus records the remote identity and whole-list ownership state.
type ZeroTrustListStatus struct {
	ListID            string                      `json:"listId,omitempty"`
	OwnershipVerified bool                        `json:"ownershipVerified,omitempty"`
	Observed          *ZeroTrustListObservedState `json:"observed,omitempty"`
	WouldApply        *ZeroTrustListItemsDiff     `json:"wouldApply,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=ztlist,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="List",type=string,JSONPath=`.status.listId`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// ZeroTrustList manages one Cloudflare Gateway list and all of its items.
type ZeroTrustList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ZeroTrustListSpec   `json:"spec,omitempty"`
	Status            ZeroTrustListStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZeroTrustListList contains ZeroTrustList objects.
type ZeroTrustListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZeroTrustList `json:"items"`
}
