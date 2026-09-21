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
	// WARPConnectorFinalizer identifies the WARP Connector cleanup finalizer.
	WARPConnectorFinalizer = "flareway.bhyoo.com/warpconnector"
	// WARPConnectorTokenSecretKey stores the WARP Connector token.
	WARPConnectorTokenSecretKey = "token"
	// WARPConnectorConditionAccepted reports whether the resource configuration is accepted.
	WARPConnectorConditionAccepted = "Accepted"
	// WARPConnectorConditionTunnelReady reports whether the remote tunnel is ready.
	WARPConnectorConditionTunnelReady = "TunnelReady"
	// WARPConnectorConditionConfigurationReady reports whether the remote configuration is ready.
	WARPConnectorConditionConfigurationReady = "ConfigurationReady"
	// WARPConnectorConditionClientsReady reports whether connector clients are ready.
	WARPConnectorConditionClientsReady = "ClientsReady"
	// WARPConnectorConditionReady summarizes overall connector readiness.
	WARPConnectorConditionReady = "Ready"
	// WARPConnectorConditionCleanupBlocked reports that remote cleanup cannot proceed.
	WARPConnectorConditionCleanupBlocked = "CleanupBlocked"
	// WARPConnectorConditionConflict reports a conflicting remote connector.
	WARPConnectorConditionConflict = "Conflict"
)

// WARPConnectorExternalReference identifies an existing WARP Connector tunnel.
type WARPConnectorExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	TunnelID string `json:"tunnelId"`
}

// WARPConnectorHAMode selects the WARP Connector high-availability provider.
// +kubebuilder:validation:Enum=None;Disabled;AWS;Local
type WARPConnectorHAMode string

const (
	// WARPConnectorHAModeNone leaves high availability unconfigured.
	WARPConnectorHAModeNone WARPConnectorHAMode = "None"
	// WARPConnectorHAModeDisabled disables high availability.
	WARPConnectorHAModeDisabled WARPConnectorHAMode = "Disabled"
	// WARPConnectorHAModeAWS uses AWS ENI movement for high availability.
	WARPConnectorHAModeAWS WARPConnectorHAMode = "AWS"
	// WARPConnectorHAModeLocal uses local virtual IPs for high availability.
	WARPConnectorHAModeLocal WARPConnectorHAMode = "Local"
)

// WARPConnectorAWSHAConfig configures AWS ENI movement on failover.
type WARPConnectorAWSHAConfig struct {
	// FNRID is the Floating Network Resource ID for the secondary ENI.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	FNRID string `json:"fnrId"`
}

// WARPConnectorVirtualIP identifies one local HA virtual IP.
type WARPConnectorVirtualIP struct {
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be a valid IPv4 or IPv6 address"
	Address string `json:"address"`
}

// WARPConnectorLocalHAConfig configures virtual IPs on the local CloudflareWARP interface.
type WARPConnectorLocalHAConfig struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=address
	VIPs []WARPConnectorVirtualIP `json:"vips"`
	// VIPsPrevious are removed on demotion or configuration-version drift.
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=address
	VIPsPrevious []WARPConnectorVirtualIP `json:"vipsPrevious,omitempty"`
}

// WARPConnectorHighAvailability configures the create-only HA capability and its mutable provider.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'AWS' || (has(self.aws) && !has(self.local))",message="AWS mode requires only aws configuration"
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'Local' || (has(self.local) && !has(self.aws))",message="Local mode requires only local configuration"
// +kubebuilder:validation:XValidation:rule="!has(self.aws) || (has(self.mode) && self.mode == 'AWS')",message="aws configuration is only valid in AWS mode"
// +kubebuilder:validation:XValidation:rule="!has(self.local) || (has(self.mode) && self.mode == 'Local')",message="local configuration is only valid in Local mode"
// +kubebuilder:validation:XValidation:rule="!has(self.enabled) || self.enabled || !has(self.mode) || self.mode == 'Disabled'",message="HA provider modes require enabled=true"
type WARPConnectorHighAvailability struct {
	// Enabled is sent only when the remote tunnel is created.
	// +kubebuilder:default=false
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="enabled is immutable"
	Enabled *bool `json:"enabled,omitempty"`
	// +kubebuilder:default=Disabled
	Mode  WARPConnectorHAMode         `json:"mode,omitempty"`
	AWS   *WARPConnectorAWSHAConfig   `json:"aws,omitempty"`
	Local *WARPConnectorLocalHAConfig `json:"local,omitempty"`
}

// WARPConnectorFailoverRequest requests activation of one linked HA client.
type WARPConnectorFailoverRequest struct {
	// +kubebuilder:validation:MinLength=1
	ClientID string `json:"clientId"`
	// RequestID must change to request another failover, including to the same client.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	RequestID string `json:"requestId"`
}

// WARPConnectorSpec defines a distinct WARP Connector tunnel with no Gateway data plane.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || (has(self.adoption.expect) && has(self.adoption.expect.name) && size(self.adoption.expect.name) > 0)",message="AdoptById requires adoption.expect.name"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="!has(self.failover) || (has(self.highAvailability.enabled) && self.highAvailability.enabled && self.highAvailability.mode != 'Disabled')",message="failover requires enabled high availability"
type WARPConnectorSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// Name is trimmed of surrounding whitespace before remote operations.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name"`
	// +kubebuilder:default={}
	HighAvailability WARPConnectorHighAvailability `json:"highAvailability,omitempty"`
	Failover         *WARPConnectorFailoverRequest `json:"failover,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                `json:"managementPolicy,omitempty"`
	ExternalRef      *WARPConnectorExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// WARPConnectorClientHAStatus is the public representation of a client's HA role.
// +kubebuilder:validation:Enum=Offline;Passive;Active
type WARPConnectorClientHAStatus string

const (
	// WARPConnectorClientHAStatusOffline marks a client as disconnected.
	WARPConnectorClientHAStatusOffline WARPConnectorClientHAStatus = "Offline"
	// WARPConnectorClientHAStatusPassive marks a connected standby client.
	WARPConnectorClientHAStatusPassive WARPConnectorClientHAStatus = "Passive"
	// WARPConnectorClientHAStatusActive marks the client currently serving traffic.
	WARPConnectorClientHAStatusActive WARPConnectorClientHAStatus = "Active"
)

// WARPConnectorConnectionStatus records one edge connection for a WARP client.
type WARPConnectorConnectionStatus struct {
	// +kubebuilder:validation:MinLength=1
	ID            string       `json:"id"`
	ClientID      string       `json:"clientId,omitempty"`
	ClientVersion string       `json:"clientVersion,omitempty"`
	ColoName      string       `json:"coloName,omitempty"`
	OpenedAt      *metav1.Time `json:"openedAt,omitempty"`
	OriginIP      string       `json:"originIp,omitempty"`
}

// WARPConnectorClientStatus records one bounded connected client observation.
type WARPConnectorClientStatus struct {
	ID       string                      `json:"id"`
	Arch     string                      `json:"arch,omitempty"`
	HAStatus WARPConnectorClientHAStatus `json:"haStatus,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=128
	// +listType=set
	Features []string     `json:"features,omitempty"`
	RunAt    *metav1.Time `json:"runAt,omitempty"`
	Version  string       `json:"version,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=id
	Connections []WARPConnectorConnectionStatus `json:"connections,omitempty"`
}

// WARPConnectorHAConfigurationStatus records the applied remote HA configuration.
type WARPConnectorHAConfigurationStatus struct {
	TunnelID             string                      `json:"tunnelId,omitempty"`
	ConfigurationVersion int64                       `json:"configurationVersion,omitempty"`
	CreatedAt            *metav1.Time                `json:"createdAt,omitempty"`
	UpdatedAt            *metav1.Time                `json:"updatedAt,omitempty"`
	Mode                 WARPConnectorHAMode         `json:"mode,omitempty"`
	AWS                  *WARPConnectorAWSHAConfig   `json:"aws,omitempty"`
	Local                *WARPConnectorLocalHAConfig `json:"local,omitempty"`
}

// WARPConnectorFailoverStatus records the most recently completed manual failover request.
type WARPConnectorFailoverStatus struct {
	ClientID  string       `json:"clientId,omitempty"`
	RequestID string       `json:"requestId,omitempty"`
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`
}

// WARPConnectorStatus records bounded remote lifecycle, HA, token and client observations.
type WARPConnectorStatus struct {
	TunnelID              string           `json:"tunnelId,omitempty"`
	AccountID             string           `json:"accountId,omitempty"`
	Name                  string           `json:"name,omitempty"`
	TunnelType            TunnelRemoteType `json:"tunnelType,omitempty"`
	ConnectorState        ConnectorState   `json:"connectorState,omitempty"`
	CreatedAt             *metav1.Time     `json:"createdAt,omitempty"`
	DeletedAt             *metav1.Time     `json:"deletedAt,omitempty"`
	ConnectionsActiveAt   *metav1.Time     `json:"connectionsActiveAt,omitempty"`
	ConnectionsInactiveAt *metav1.Time     `json:"connectionsInactiveAt,omitempty"`
	OrphanedTunnelID      string           `json:"orphanedTunnelId,omitempty"`
	OwnershipVerified     bool             `json:"ownershipVerified,omitempty"`
	// CreateAttemptName and CreateAttemptGeneration form the controller-owned
	// checkpoint for recovering an ambiguous create request.
	CreateAttemptName       string                             `json:"createAttemptName,omitempty"`
	CreateAttemptGeneration int64                              `json:"createAttemptGeneration,omitempty"`
	ObservedGeneration      int64                              `json:"observedGeneration,omitempty"`
	TokenSecretRef          *corev1.LocalObjectReference       `json:"tokenSecretRef,omitempty"`
	Configuration           WARPConnectorHAConfigurationStatus `json:"configuration,omitempty"`
	Failover                *WARPConnectorFailoverStatus       `json:"failover,omitempty"`
	// +kubebuilder:validation:MaxItems=25
	// +listType=map
	// +listMapKey=id
	Clients []WARPConnectorClientStatus `json:"clients,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// AppliedHash is the desired-state hash recorded after the last successful remote convergence.
	// +optional
	AppliedHash string `json:"appliedHash,omitempty"`
	// AppliedAt is when AppliedHash was last recorded; nil means never applied.
	// +optional
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=warpc,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tunnel",type=string,JSONPath=`.status.tunnelId`
// +kubebuilder:printcolumn:name="HA",type=string,JSONPath=`.status.configuration.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// WARPConnector manages one Cloudflare WARP Connector tunnel.
type WARPConnector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              WARPConnectorSpec   `json:"spec,omitempty"`
	Status            WARPConnectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WARPConnectorList contains WARPConnector objects.
type WARPConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WARPConnector `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WARPConnector{}, &WARPConnectorList{})
		return nil
	})
}
