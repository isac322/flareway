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
	// VirtualNetworkFinalizer identifies the virtual network cleanup finalizer.
	VirtualNetworkFinalizer = "flareway.bhyoo.com/virtualnetwork"
	// NetworkRouteFinalizer identifies the network route cleanup finalizer.
	NetworkRouteFinalizer = "flareway.bhyoo.com/networkroute"
	// HostnameRouteFinalizer identifies the hostname route cleanup finalizer.
	HostnameRouteFinalizer = "flareway.bhyoo.com/hostnameroute"
	// PrivateNetworkConditionAccepted reports whether a private network resource is valid.
	PrivateNetworkConditionAccepted = "Accepted"
	// PrivateNetworkConditionReady reports whether a private network resource is ready.
	PrivateNetworkConditionReady = "Ready"
)

// AllowedNamespaceFrom selects namespaces permitted to consume a private route.
// +kubebuilder:validation:Enum=Same;All;Selector
type AllowedNamespaceFrom string

const (
	// AllowedNamespaceFromSame permits references from the resource namespace.
	AllowedNamespaceFromSame AllowedNamespaceFrom = "Same"
	// AllowedNamespaceFromAll permits references from every namespace.
	AllowedNamespaceFromAll AllowedNamespaceFrom = "All"
	// AllowedNamespaceFromSelector permits references from selected namespaces.
	AllowedNamespaceFromSelector AllowedNamespaceFrom = "Selector"
)

// AllowedNamespaces limits which namespaces may reference a NetworkRoute or HostnameRoute.
// +kubebuilder:validation:XValidation:rule="!has(self.from) || self.from != 'Selector' || has(self.selector)",message="selector is required when from is Selector"
// +kubebuilder:validation:XValidation:rule="!has(self.selector) || (has(self.from) && self.from == 'Selector')",message="selector is only valid when from is Selector"
type AllowedNamespaces struct {
	// +kubebuilder:default=Same
	From     AllowedNamespaceFrom  `json:"from,omitempty"`
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// TunnelReferenceKind selects a supported private-route tunnel resource.
// +kubebuilder:validation:Enum=CloudflareTunnel;WARPConnector
type TunnelReferenceKind string

const (
	// TunnelReferenceKindCloudflareTunnel references a CloudflareTunnel.
	TunnelReferenceKindCloudflareTunnel TunnelReferenceKind = "CloudflareTunnel"
	// TunnelReferenceKindWARPConnector references a WARPConnector.
	TunnelReferenceKindWARPConnector TunnelReferenceKind = "WARPConnector"
)

// TunnelReference identifies a namespaced CloudflareTunnel or WARPConnector.
type TunnelReference struct {
	// +kubebuilder:default=CloudflareTunnel
	Kind TunnelReferenceKind `json:"kind,omitempty"`
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
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
type VirtualNetworkSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=100
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                 `json:"managementPolicy,omitempty"`
	ExternalRef      *VirtualNetworkExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// VirtualNetworkStatus records all actionable remote virtual-network fields.
type VirtualNetworkStatus struct {
	VirtualNetworkID   string       `json:"virtualNetworkId,omitempty"`
	Name               string       `json:"name,omitempty"`
	IsDefault          bool         `json:"isDefault,omitempty"`
	Comment            string       `json:"comment,omitempty"`
	CreatedAt          *metav1.Time `json:"createdAt,omitempty"`
	DeletedAt          *metav1.Time `json:"deletedAt,omitempty"`
	OwnershipVerified  bool         `json:"ownershipVerified,omitempty"`
	ObservedGeneration int64        `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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

// NetworkRouteIPLookupSpec requests the most-specific route containing one IP address.
// +kubebuilder:validation:XValidation:rule="!has(self.virtualNetworkRef) || !has(self.defaultVirtualNetworkFallback)",message="virtualNetworkRef and defaultVirtualNetworkFallback are mutually exclusive"
type NetworkRouteIPLookupSpec struct {
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="ip must be a valid IPv4 or IPv6 address"
	IP                            string                       `json:"ip"`
	VirtualNetworkRef             *corev1.LocalObjectReference `json:"virtualNetworkRef,omitempty"`
	DefaultVirtualNetworkFallback *bool                        `json:"defaultVirtualNetworkFallback,omitempty"`
}

// NetworkRouteIPLookupResultStatus records the Teamnet route returned by an IP lookup.
type NetworkRouteIPLookupResultStatus struct {
	RouteID            string           `json:"routeId,omitempty"`
	Network            string           `json:"network,omitempty"`
	TunnelID           string           `json:"tunnelId,omitempty"`
	TunnelName         string           `json:"tunnelName,omitempty"`
	TunnelType         TunnelRemoteType `json:"tunnelType,omitempty"`
	VirtualNetworkID   string           `json:"virtualNetworkId,omitempty"`
	VirtualNetworkName string           `json:"virtualNetworkName,omitempty"`
	Comment            string           `json:"comment,omitempty"`
	CreatedAt          *metav1.Time     `json:"createdAt,omitempty"`
	DeletedAt          *metav1.Time     `json:"deletedAt,omitempty"`
}

// NetworkRouteIPLookupStatus records the request that produced the current lookup result.
type NetworkRouteIPLookupStatus struct {
	IP                            string                            `json:"ip,omitempty"`
	VirtualNetworkID              string                            `json:"virtualNetworkId,omitempty"`
	DefaultVirtualNetworkFallback *bool                             `json:"defaultVirtualNetworkFallback,omitempty"`
	Result                        *NetworkRouteIPLookupResultStatus `json:"result,omitempty"`
	ObservedGeneration            int64                             `json:"observedGeneration,omitempty"`
}

// NetworkRouteSpec defines a CIDR routed through a typed tunnel reference.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="isCIDR(self.network)",message="network must be a valid IPv4 or IPv6 CIDR"
// +kubebuilder:validation:XValidation:rule="!isCIDR(self.network) || cidr(self.network) == cidr(self.network).masked()",message="network must be masked"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="has(self.tunnelRef.name) && size(self.tunnelRef.name) > 0",message="tunnelRef.name is required"
type NetworkRouteSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=49
	Network   string          `json:"network"`
	TunnelRef TunnelReference `json:"tunnelRef"`
	// VirtualNetworkRef is optional; omission selects the account default virtual network.
	VirtualNetworkRef *corev1.LocalObjectReference `json:"virtualNetworkRef,omitempty"`
	IPLookup          *NetworkRouteIPLookupSpec    `json:"ipLookup,omitempty"`
	// +kubebuilder:default={}
	AllowedNamespaces AllowedNamespaces `json:"allowedNamespaces,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy               `json:"managementPolicy,omitempty"`
	ExternalRef      *NetworkRouteExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// NetworkRouteAppliedStatus is the exact CIDR and resolved remote target last applied.
type NetworkRouteAppliedStatus struct {
	Network            string           `json:"network,omitempty"`
	TunnelID           string           `json:"tunnelId,omitempty"`
	TunnelType         TunnelRemoteType `json:"tunnelType,omitempty"`
	VirtualNetworkID   string           `json:"virtualNetworkId,omitempty"`
	ObservedGeneration int64            `json:"observedGeneration,omitempty"`
}

// NetworkRouteStatus records actionable route and lookup metadata.
type NetworkRouteStatus struct {
	RouteID            string                      `json:"routeId,omitempty"`
	Network            string                      `json:"network,omitempty"`
	TunnelID           string                      `json:"tunnelId,omitempty"`
	TunnelName         string                      `json:"tunnelName,omitempty"`
	TunnelType         TunnelRemoteType            `json:"tunnelType,omitempty"`
	VirtualNetworkID   string                      `json:"virtualNetworkId,omitempty"`
	VirtualNetworkName string                      `json:"virtualNetworkName,omitempty"`
	Comment            string                      `json:"comment,omitempty"`
	CreatedAt          *metav1.Time                `json:"createdAt,omitempty"`
	DeletedAt          *metav1.Time                `json:"deletedAt,omitempty"`
	Applied            NetworkRouteAppliedStatus   `json:"applied,omitempty"`
	IPLookup           *NetworkRouteIPLookupStatus `json:"ipLookup,omitempty"`
	OwnershipVerified  bool                        `json:"ownershipVerified,omitempty"`
	ObservedGeneration int64                       `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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

// HostnameRouteSpec defines a private hostname routed through a typed tunnel reference.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="has(self.tunnelRef.name) && size(self.tunnelRef.name) > 0",message="tunnelRef.name is required"
type HostnameRouteSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:Pattern=`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=253
	Hostname  string          `json:"hostname"`
	TunnelRef TunnelReference `json:"tunnelRef"`
	// +kubebuilder:default={}
	AllowedNamespaces AllowedNamespaces `json:"allowedNamespaces,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	Comment string `json:"comment,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                `json:"managementPolicy,omitempty"`
	ExternalRef      *HostnameRouteExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// HostnameRouteAppliedStatus is the exact hostname and resolved remote tunnel last applied.
type HostnameRouteAppliedStatus struct {
	Hostname           string           `json:"hostname,omitempty"`
	TunnelID           string           `json:"tunnelId,omitempty"`
	TunnelType         TunnelRemoteType `json:"tunnelType,omitempty"`
	ObservedGeneration int64            `json:"observedGeneration,omitempty"`
}

// HostnameRouteStatus records actionable hostname-route and lookup metadata.
type HostnameRouteStatus struct {
	RouteID            string                     `json:"routeId,omitempty"`
	Hostname           string                     `json:"hostname,omitempty"`
	TunnelID           string                     `json:"tunnelId,omitempty"`
	TunnelName         string                     `json:"tunnelName,omitempty"`
	TunnelType         TunnelRemoteType           `json:"tunnelType,omitempty"`
	Comment            string                     `json:"comment,omitempty"`
	CreatedAt          *metav1.Time               `json:"createdAt,omitempty"`
	DeletedAt          *metav1.Time               `json:"deletedAt,omitempty"`
	Applied            HostnameRouteAppliedStatus `json:"applied,omitempty"`
	OwnershipVerified  bool                       `json:"ownershipVerified,omitempty"`
	ObservedGeneration int64                      `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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
