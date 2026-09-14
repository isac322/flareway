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
	// ServiceTokenFinalizer is a supported API value.
	ServiceTokenFinalizer = "flareway.bhyoo.com/servicetoken"
	// ServiceTokenClientIDKey is a supported API value.
	ServiceTokenClientIDKey = "CF-Access-Client-Id"
	// ServiceTokenClientSecretKey is a supported API value.
	ServiceTokenClientSecretKey = "CF-Access-Client-Secret"
	// ServiceTokenIDAnnotation is a supported API value.
	ServiceTokenIDAnnotation = "flareway.bhyoo.com/service-token-id"
)

// ServiceTokenRotationMode controls automatic service-token secret rotation.
// +kubebuilder:validation:Enum=Manual;OnExpiry
type ServiceTokenRotationMode string

const (
	// ServiceTokenRotationManual is a supported API value.
	ServiceTokenRotationManual ServiceTokenRotationMode = "Manual"
	// ServiceTokenRotationOnExpiry is a supported API value.
	ServiceTokenRotationOnExpiry ServiceTokenRotationMode = "OnExpiry"
)

// ServiceTokenRotationSpec is part of the servicetokenrotationspec configuration.
type ServiceTokenRotationSpec struct {
	// +kubebuilder:default=Manual
	Mode ServiceTokenRotationMode `json:"mode,omitempty"`
	// +kubebuilder:default="24h"
	GraceDuration string       `json:"graceDuration,omitempty"`
	RequestedAt   *metav1.Time `json:"requestedAt,omitempty"`
}

// ServiceTokenExternalReference is part of the servicetokenexternalreference configuration.
type ServiceTokenExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	TokenID string `json:"tokenId"`
}

// ServiceTokenSpec defines a Cloudflare Access service token and its Secret.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type ServiceTokenSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:default="8760h"
	Duration  string                      `json:"duration,omitempty"`
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
	// +kubebuilder:default={}
	Rotation ServiceTokenRotationSpec `json:"rotation,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy               `json:"managementPolicy,omitempty"`
	ExternalRef      *ServiceTokenExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ServiceTokenStatus is part of the servicetokenstatus configuration.
type ServiceTokenStatus struct {
	TokenID                 string       `json:"tokenId,omitempty"`
	ClientID                string       `json:"clientId,omitempty"`
	OwnershipVerified       bool         `json:"ownershipVerified,omitempty"`
	ExpiresAt               *metav1.Time `json:"expiresAt,omitempty"`
	RotatedAt               *metav1.Time `json:"rotatedAt,omitempty"`
	ObservedRotationRequest *metav1.Time `json:"observedRotationRequest,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfst,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Token",type=string,JSONPath=`.status.tokenId`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.expiresAt`

// ServiceToken is part of the servicetoken configuration.
type ServiceToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceTokenSpec   `json:"spec,omitempty"`
	Status            ServiceTokenStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceTokenList is part of the servicetokenlist configuration.
type ServiceTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceToken `json:"items"`
}
