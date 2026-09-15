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

// AccessInfrastructureTargetFinalizer protects remote target cleanup.
const AccessInfrastructureTargetFinalizer = "flareway.bhyoo.com/accessinfrastructuretarget"

// AccessInfrastructureTargetExternalReference identifies an existing target.
type AccessInfrastructureTargetExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	TargetID string `json:"targetId"`
}

// AccessInfrastructureTargetAdoptionExpect declares attributes checked before adoption.
type AccessInfrastructureTargetAdoptionExpect struct {
	Hostname string `json:"hostname,omitempty"`
}

// AccessInfrastructureTargetAdoptionSpec configures explicit target adoption.
type AccessInfrastructureTargetAdoptionSpec struct {
	// +kubebuilder:default=None
	Mode   AdoptionMode                             `json:"mode,omitempty"`
	Expect AccessInfrastructureTargetAdoptionExpect `json:"expect,omitempty"`
}

// AccessInfrastructureTargetIPv4Address is an IPv4 target address.
type AccessInfrastructureTargetIPv4Address struct {
	// +kubebuilder:validation:Format=ipv4
	IPAddr            string                          `json:"ipAddr"`
	VirtualNetworkRef *NamespacedLocalObjectReference `json:"virtualNetworkRef,omitempty"`
	// +kubebuilder:validation:MinLength=1
	VirtualNetworkID string `json:"virtualNetworkId,omitempty"`
}

// AccessInfrastructureTargetIPv6Address is an IPv6 target address.
type AccessInfrastructureTargetIPv6Address struct {
	// +kubebuilder:validation:Format=ipv6
	IPAddr            string                          `json:"ipAddr"`
	VirtualNetworkRef *NamespacedLocalObjectReference `json:"virtualNetworkRef,omitempty"`
	// +kubebuilder:validation:MinLength=1
	VirtualNetworkID string `json:"virtualNetworkId,omitempty"`
}

// AccessInfrastructureTargetIP contains one or both IP families.
// +kubebuilder:validation:XValidation:rule="has(self.ipv4) || has(self.ipv6)",message="at least one of ipv4 or ipv6 is required"
// +kubebuilder:validation:XValidation:rule="!has(self.ipv4) || !has(self.ipv4.virtualNetworkRef) || !has(self.ipv4.virtualNetworkId)",message="ipv4 virtualNetworkRef and virtualNetworkId are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!has(self.ipv6) || !has(self.ipv6.virtualNetworkRef) || !has(self.ipv6.virtualNetworkId)",message="ipv6 virtualNetworkRef and virtualNetworkId are mutually exclusive"
type AccessInfrastructureTargetIP struct {
	IPV4 *AccessInfrastructureTargetIPv4Address `json:"ipv4,omitempty"`
	IPV6 *AccessInfrastructureTargetIPv6Address `json:"ipv6,omitempty"`
}

// AccessInfrastructureTargetSpec defines an independently registered target.
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessInfrastructureTargetSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Hostname is case-insensitive and may contain letters, digits, periods, and dashes.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`
	Hostname string                       `json:"hostname"`
	IP       AccessInfrastructureTargetIP `json:"ip"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                             `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessInfrastructureTargetExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AccessInfrastructureTargetAdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessInfrastructureTargetIPAddressStatus records a resolved target address.
type AccessInfrastructureTargetIPAddressStatus struct {
	IPAddr           string `json:"ipAddr,omitempty"`
	VirtualNetworkID string `json:"virtualNetworkId,omitempty"`
}

// AccessInfrastructureTargetIPStatus records resolved target addresses.
type AccessInfrastructureTargetIPStatus struct {
	IPV4 *AccessInfrastructureTargetIPAddressStatus `json:"ipv4,omitempty"`
	IPV6 *AccessInfrastructureTargetIPAddressStatus `json:"ipv6,omitempty"`
}

// AccessInfrastructureTargetObservedState records mutable target state without transport metadata.
type AccessInfrastructureTargetObservedState struct {
	Hostname string                             `json:"hostname"`
	IP       AccessInfrastructureTargetIPStatus `json:"ip"`
}

// AccessInfrastructureTargetStatus defines the observed state without transport metadata.
type AccessInfrastructureTargetStatus struct {
	TargetID          string                             `json:"targetId,omitempty"`
	Hostname          string                             `json:"hostname,omitempty"`
	IP                AccessInfrastructureTargetIPStatus `json:"ip,omitempty"`
	OwnershipVerified bool                               `json:"ownershipVerified,omitempty"`
	// WouldApply is the state Managed mode would write when ObserveOnly detects drift.
	WouldApply *AccessInfrastructureTargetObservedState `json:"wouldApply,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfait,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.status.targetId`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`

// AccessInfrastructureTarget is a Cloudflare infrastructure access target.
type AccessInfrastructureTarget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessInfrastructureTargetSpec   `json:"spec,omitempty"`
	Status            AccessInfrastructureTargetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessInfrastructureTargetList contains infrastructure targets.
type AccessInfrastructureTargetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessInfrastructureTarget `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AccessInfrastructureTarget{}, &AccessInfrastructureTargetList{})
		return nil
	})
}
