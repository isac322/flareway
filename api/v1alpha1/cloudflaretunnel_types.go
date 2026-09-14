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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// CloudflareTunnelFinalizer identifies the tunnel cleanup finalizer.
	CloudflareTunnelFinalizer = "flareway.bhyoo.com/tunnel"
	// CloudflareTunnelTeardownAnnotation is a supported API value.
	CloudflareTunnelTeardownAnnotation = "flareway.bhyoo.com/teardown"

	// CloudflareTunnelConditionAccepted is a supported API value.
	CloudflareTunnelConditionAccepted = "Accepted"
	// CloudflareTunnelConditionTunnelReady is a supported API value.
	CloudflareTunnelConditionTunnelReady = "TunnelReady"
	// CloudflareTunnelConditionConfigApplied is a supported API value.
	CloudflareTunnelConditionConfigApplied = "ConfigApplied"
	// CloudflareTunnelConditionDNSReady is a supported API value.
	CloudflareTunnelConditionDNSReady = "DNSReady"
	// CloudflareTunnelConditionPrivateListenerDegraded is a supported API value.
	CloudflareTunnelConditionPrivateListenerDegraded = "PrivateListenerDegraded"
	// CloudflareTunnelConditionReady is a supported API value.
	CloudflareTunnelConditionReady = "Ready"
	// CloudflareTunnelConditionCleanupBlocked is a supported API value.
	CloudflareTunnelConditionCleanupBlocked = "CleanupBlocked"
	// CloudflareTunnelConditionConflict is a supported API value.
	CloudflareTunnelConditionConflict = "Conflict"
)

// ManagementPolicy controls whether Flareway mutates a remote resource.
// +kubebuilder:validation:Enum=Managed;ObserveOnly
type ManagementPolicy string

const (
	// ManagementPolicyManaged allows remote mutations.
	ManagementPolicyManaged ManagementPolicy = "Managed"
	// ManagementPolicyObserveOnly is a supported API value.
	ManagementPolicyObserveOnly ManagementPolicy = "ObserveOnly"
)

// AdoptionMode controls explicit adoption of a remote resource.
// +kubebuilder:validation:Enum=None;AdoptById
type AdoptionMode string

const (
	// AdoptionModeNone disables adoption.
	AdoptionModeNone AdoptionMode = "None"
	// AdoptionModeAdoptByID is a supported API value.
	AdoptionModeAdoptByID AdoptionMode = "AdoptById"
)

// DeletionPolicy controls whether a managed remote resource is deleted or orphaned.
// +kubebuilder:validation:Enum=Delete;Orphan
type DeletionPolicy string

const (
	// DeletionPolicyDelete deletes the remote resource.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyOrphan is a supported API value.
	DeletionPolicyOrphan DeletionPolicy = "Orphan"
)

// AdoptionExpect declares remote attributes that must match before adoption.
type AdoptionExpect struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// AdoptionSpec configures explicit adoption of an existing remote object.
type AdoptionSpec struct {
	// +kubebuilder:default=None
	Mode AdoptionMode `json:"mode,omitempty"`

	Expect AdoptionExpect `json:"expect,omitempty"`
}

// CloudflareTunnelExternalReference identifies an existing Cloudflare Tunnel.
type CloudflareTunnelExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	TunnelID string `json:"tunnelId"`
}

// CloudflareTunnelRemoteSpec configures the remote tunnel identity.
type CloudflareTunnelRemoteSpec struct {
	// Name defaults in the controller to "<cluster>-<namespace>-<name>".
	Name string `json:"name,omitempty"`

	ExternalRef *CloudflareTunnelExternalReference `json:"externalRef,omitempty"`
}

// CloudflareTunnelDNSConfig configures public DNS ownership.
type CloudflareTunnelDNSConfig struct {
	// +kubebuilder:default=Managed
	Mode DNSMode `json:"mode,omitempty"`

	// +kubebuilder:default="managed-by=flareway"
	RecordComment string `json:"recordComment,omitempty"`
}

// CloudflareTunnelHostnameRouteConfig configures automatic HostnameRoute creation.
type CloudflareTunnelHostnameRouteConfig struct {
	// +kubebuilder:default=true
	Create *bool `json:"create,omitempty"`
}

// CloudflareTunnelListener configures exposure for one Gateway listener.
type CloudflareTunnelListener struct {
	Name gatewayv1.SectionName `json:"name"`

	// +kubebuilder:default=Public
	Exposure Exposure `json:"exposure,omitempty"`

	VirtualNetworkRef *corev1.LocalObjectReference `json:"virtualNetworkRef,omitempty"`

	// +kubebuilder:default={}
	HostnameRoute CloudflareTunnelHostnameRouteConfig `json:"hostnameRoute,omitempty"`
}

// CloudflareTunnelSpec defines remote ownership and connector configuration.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.tunnel.externalRef)",message="ObserveOnly requires tunnel.externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.tunnel.externalRef)",message="AdoptById requires tunnel.externalRef"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && self.accountRef.name != ''",message="accountRef.name is required"

// CloudflareTunnelSpec defines remote ownership and connector configuration.
type CloudflareTunnelSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`

	// +kubebuilder:default={}
	Tunnel CloudflareTunnelRemoteSpec `json:"tunnel,omitempty"`

	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`

	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`

	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Connector overrides the GatewayClassConfig connector settings.
	Connector *ConnectorSpec `json:"connector,omitempty"`

	// Proxy overrides the GatewayClassConfig proxy settings.
	Proxy *ProxySpec `json:"proxy,omitempty"`

	// PrivateDNS overrides the GatewayClassConfig private DNS settings.
	PrivateDNS *PrivateDNSSpec `json:"privateDNS,omitempty"`

	// +kubebuilder:default={}
	DNS CloudflareTunnelDNSConfig `json:"dns,omitempty"`

	// Listeners configures per-listener exposure. Omitted listeners are Public.
	// +listType=map
	// +listMapKey=name
	Listeners []CloudflareTunnelListener `json:"listeners,omitempty"`
}

// ConnectorState is the observed health of the remote tunnel connectors.
// +kubebuilder:validation:Enum=healthy;degraded;down;inactive
type ConnectorState string

const (
	// ConnectorStateHealthy indicates healthy connectors.
	ConnectorStateHealthy ConnectorState = "healthy"
	// ConnectorStateDegraded is a supported API value.
	ConnectorStateDegraded ConnectorState = "degraded"
	// ConnectorStateDown is a supported API value.
	ConnectorStateDown ConnectorState = "down"
	// ConnectorStateInactive is a supported API value.
	ConnectorStateInactive ConnectorState = "inactive"
)

// CloudflareTunnelConfigVersion is split between the gateway field manager
// (Desired, DesiredHash, Applied) and the tunnel controller's Ready aggregation.
type CloudflareTunnelConfigVersion struct {
	Desired     int64  `json:"desired,omitempty"`
	DesiredHash string `json:"desiredHash,omitempty"`
	Applied     int64  `json:"applied,omitempty"`
}

// HostnameGuard records the fail-closed state applied to a public hostname.
// +kubebuilder:validation:Enum=Forwarding;Blocked;Unprotected
type HostnameGuard string

const (
	// HostnameGuardForwarding indicates traffic is forwarded.
	HostnameGuardForwarding HostnameGuard = "Forwarding"
	// HostnameGuardBlocked is a supported API value.
	HostnameGuardBlocked HostnameGuard = "Blocked"
	// HostnameGuardUnprotected is a supported API value.
	HostnameGuardUnprotected HostnameGuard = "Unprotected"
)

// CloudflareTunnelHostnameStatus is owned by the gateway field manager.
type CloudflareTunnelHostnameStatus struct {
	Hostname string `json:"hostname"`
	// +kubebuilder:default=""
	ProtectionDomain string `json:"protectionDomain"`
	// +kubebuilder:default=""
	AccessApplication string        `json:"accessApplication"`
	Guard             HostnameGuard `json:"guard"`
	AppliedVersion    int64         `json:"appliedVersion,omitempty"`
}

// CloudflareTunnelDNSRecordStatus records a managed DNS record.
type CloudflareTunnelDNSRecordStatus struct {
	Hostname string `json:"hostname"`
	RecordID string `json:"recordId"`
	ZoneID   string `json:"zoneId"`
	State    string `json:"state,omitempty"`
}

// ListenerBinding identifies the private Envoy listener binding strategy.
// +kubebuilder:validation:Enum=Loopback;PodIP
type ListenerBinding string

const (
	// ListenerBindingLoopback binds a private listener to loopback.
	ListenerBindingLoopback ListenerBinding = "Loopback"
	// ListenerBindingPodIP is a supported API value.
	ListenerBindingPodIP ListenerBinding = "PodIP"
)

// CloudflareProtectionDomainStatus records one Envoy protection domain.
type CloudflareProtectionDomainStatus struct {
	Name      string `json:"name"`
	EnvoyPort int32  `json:"envoyPort"`
	Protected bool   `json:"protected"`
}

// CloudflareTunnelListenerStatus is owned by the gateway field manager.
type CloudflareTunnelListenerStatus struct {
	Name     gatewayv1.SectionName `json:"name"`
	Exposure Exposure              `json:"exposure"`
	Binding  ListenerBinding       `json:"binding,omitempty"`

	// +listType=map
	// +listMapKey=name
	ProtectionDomains []CloudflareProtectionDomainStatus `json:"protectionDomains,omitempty"`
}

// CloudflareTunnelStatus contains disjoint tunnel-controller and gateway-controller fields.
type CloudflareTunnelStatus struct {
	// Tunnel-controller-owned fields.
	TunnelID         string         `json:"tunnelId,omitempty"`
	ConnectorState   ConnectorState `json:"connectorState,omitempty"`
	OrphanedTunnelID string         `json:"orphanedTunnelId,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Addresses []gatewayv1.GatewayStatusAddress `json:"addresses,omitempty"`

	// +listType=map
	// +listMapKey=hostname
	DNSRecords []CloudflareTunnelDNSRecordStatus `json:"dnsRecords,omitempty"`

	GatewayRef *corev1.LocalObjectReference `json:"gatewayRef,omitempty"`

	// Gateway-controller-owned fields.
	ConfigVersion CloudflareTunnelConfigVersion `json:"configVersion,omitempty"`
	// +listType=map
	// +listMapKey=hostname
	// +listMapKey=protectionDomain
	// +listMapKey=accessApplication
	Hostnames []CloudflareTunnelHostnameStatus `json:"hostnames,omitempty"`
	// +listType=map
	// +listMapKey=name
	Listeners []CloudflareTunnelListenerStatus `json:"listeners,omitempty"`

	// Conditions are merged by type. Accepted, TunnelReady, DNSReady, Ready,
	// CleanupBlocked and Conflict are tunnel-owned; ConfigApplied and
	// PrivateListenerDegraded are gateway-owned.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cft,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tunnel",type=string,JSONPath=`.status.tunnelId`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.status.gatewayRef.name`

// CloudflareTunnel represents one remotely managed Cloudflare Tunnel and its Gateway data plane.
type CloudflareTunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudflareTunnelSpec   `json:"spec,omitempty"`
	Status CloudflareTunnelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CloudflareTunnelList contains CloudflareTunnel objects.
type CloudflareTunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudflareTunnel `json:"items"`
}
