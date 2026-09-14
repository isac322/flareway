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
	// VirtualNetworkFinalizer identifies virtual network cleanup.
	VirtualNetworkFinalizer = "flareway.bhyoo.com/virtualnetwork"
	// NetworkRouteFinalizer is a supported API value.
	NetworkRouteFinalizer = "flareway.bhyoo.com/networkroute"
	// HostnameRouteFinalizer is a supported API value.
	HostnameRouteFinalizer = "flareway.bhyoo.com/hostnameroute"

	// PrivateNetworkConditionAccepted is a supported API value.
	PrivateNetworkConditionAccepted = "Accepted"
	// PrivateNetworkConditionReady is a supported API value.
	PrivateNetworkConditionReady = "Ready"
)

// AllowedNamespaceFrom selects namespaces permitted to consume a private route.
// +kubebuilder:validation:Enum=Same;All;Selector
type AllowedNamespaceFrom string

const (
	// AllowedNamespaceFromSame permits same-namespace consumers.
	AllowedNamespaceFromSame AllowedNamespaceFrom = "Same"
	// AllowedNamespaceFromAll is a supported API value.
	AllowedNamespaceFromAll AllowedNamespaceFrom = "All"
	// AllowedNamespaceFromSelector is a supported API value.
	AllowedNamespaceFromSelector AllowedNamespaceFrom = "Selector"
)

// AllowedNamespaces limits which namespaces may reference a NetworkRoute or HostnameRoute.
// +kubebuilder:validation:XValidation:rule="!has(self.from) || self.from != 'Selector' || has(self.selector)",message="selector is required when from is Selector"
// +kubebuilder:validation:XValidation:rule="!has(self.selector) || (has(self.from) && self.from == 'Selector')",message="selector is only valid when from is Selector"
type AllowedNamespaces struct {
	// +kubebuilder:default=Same
	From AllowedNamespaceFrom `json:"from,omitempty"`

	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// NamespacedObjectReference identifies a namespaced Flareway resource.
type NamespacedObjectReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace defaults to the referencing object's namespace.
	Namespace string `json:"namespace,omitempty"`
}

// VirtualNetworkExternalReference identifies an existing Cloudflare virtual network.
type VirtualNetworkExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	VirtualNetworkID string `json:"virtualNetworkId"`
}

// VirtualNetworkSpec defines one Cloudflare Zero Trust virtual network.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && self.accountRef.name != \"\"",message="accountRef.name is required"
type VirtualNetworkSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`

	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	IsDefault bool `json:"isDefault,omitempty"`

	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`

	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`

	ExternalRef *VirtualNetworkExternalReference `json:"externalRef,omitempty"`

	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`

	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// VirtualNetworkStatus records the remote virtual network identity and observed state.
type VirtualNetworkStatus struct {
	VirtualNetworkID string `json:"virtualNetworkId,omitempty"`
	Name             string `json:"name,omitempty"`
	IsDefault        bool   `json:"isDefault,omitempty"`
	Comment          string `json:"comment,omitempty"`

	OwnershipVerified bool `json:"ownershipVerified,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=vnet,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Virtual Network",type=string,JSONPath=`.status.virtualNetworkId`

// VirtualNetwork manages a Cloudflare Zero Trust virtual network.
type VirtualNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VirtualNetworkSpec   `json:"spec,omitempty"`
	Status            VirtualNetworkStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VirtualNetworkList contains VirtualNetwork objects.
type VirtualNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualNetwork `json:"items"`
}

// NetworkRouteExternalReference identifies an existing Cloudflare CIDR route.
type NetworkRouteExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	RouteID string `json:"routeId"`
}

// NetworkRouteSpec defines a CIDR routed through a CloudflareTunnel in one virtual network.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="isCIDR(self.network)",message="network must be a valid IPv4 or IPv6 CIDR"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.network) || cidr(self.network) == cidr(self.network).masked()",message="network must be masked"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && self.accountRef.name != \"\"",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="has(self.virtualNetworkRef.name) && self.virtualNetworkRef.name != \"\"",message="virtualNetworkRef.name is required"
type NetworkRouteSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`

	// Network must be a masked IPv4 or IPv6 CIDR.
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=49
	Network string `json:"network"`

	TunnelRef NamespacedObjectReference `json:"tunnelRef"`

	VirtualNetworkRef corev1.LocalObjectReference `json:"virtualNetworkRef"`

	// +kubebuilder:default={}
	AllowedNamespaces AllowedNamespaces `json:"allowedNamespaces,omitempty"`

	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`

	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`

	ExternalRef *NetworkRouteExternalReference `json:"externalRef,omitempty"`

	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`

	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// NetworkRouteAppliedStatus is the exact CIDR and resolved remote target last applied.
type NetworkRouteAppliedStatus struct {
	Network            string `json:"network,omitempty"`
	TunnelID           string `json:"tunnelId,omitempty"`
	VirtualNetworkID   string `json:"virtualNetworkId,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
}

// NetworkRouteStatus records the remote route identity and applied claim.
type NetworkRouteStatus struct {
	RouteID string                    `json:"routeId,omitempty"`
	Applied NetworkRouteAppliedStatus `json:"applied,omitempty"`
	Comment string                    `json:"comment,omitempty"`

	OwnershipVerified bool `json:"ownershipVerified,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=nroute,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Network",type=string,JSONPath=`.spec.network`
// +kubebuilder:printcolumn:name="Route",type=string,JSONPath=`.status.routeId`

// NetworkRoute manages one Cloudflare Tunnel CIDR route.
type NetworkRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NetworkRouteSpec   `json:"spec,omitempty"`
	Status            NetworkRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkRouteList contains NetworkRoute objects.
type NetworkRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkRoute `json:"items"`
}

// HostnameRouteExternalReference identifies an existing Cloudflare hostname route.
type HostnameRouteExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	RouteID string `json:"routeId"`
}

// HostnameRouteSpec defines an exact or single-label wildcard hostname routed through a CloudflareTunnel.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && self.accountRef.name != \"\"",message="accountRef.name is required"
type HostnameRouteSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`

	// Hostname accepts an exact DNS name or a wildcard occupying exactly the first label.
	// +kubebuilder:validation:Pattern=`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname"`

	TunnelRef NamespacedObjectReference `json:"tunnelRef"`

	// +kubebuilder:default={}
	AllowedNamespaces AllowedNamespaces `json:"allowedNamespaces,omitempty"`

	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`

	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`

	ExternalRef *HostnameRouteExternalReference `json:"externalRef,omitempty"`

	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`

	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// HostnameRouteAppliedStatus is the exact hostname and resolved tunnel last applied.
type HostnameRouteAppliedStatus struct {
	Hostname           string `json:"hostname,omitempty"`
	TunnelID           string `json:"tunnelId,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
}

// HostnameRouteStatus records the remote route identity and applied claim.
type HostnameRouteStatus struct {
	RouteID string                     `json:"routeId,omitempty"`
	Applied HostnameRouteAppliedStatus `json:"applied,omitempty"`
	Comment string                     `json:"comment,omitempty"`

	OwnershipVerified bool `json:"ownershipVerified,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=hroute,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`
// +kubebuilder:printcolumn:name="Route",type=string,JSONPath=`.status.routeId`

// HostnameRoute manages one Cloudflare private hostname route.
type HostnameRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HostnameRouteSpec   `json:"spec,omitempty"`
	Status            HostnameRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HostnameRouteList contains HostnameRoute objects.
type HostnameRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HostnameRoute `json:"items"`
}
