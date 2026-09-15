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
	// DeviceProfileFinalizer identifies the profile cleanup finalizer.
	DeviceProfileFinalizer = "flareway.bhyoo.com/deviceprofile"
	// DeviceProfileConditionAccepted is a supported API value.
	DeviceProfileConditionAccepted = "Accepted"
	// DeviceProfileConditionReady is a supported API value.
	DeviceProfileConditionReady = "Ready"
)

// DeviceProfileKind selects the account default profile or a custom profile.
// +kubebuilder:validation:Enum=Default;Custom
type DeviceProfileKind string

const (
	// DeviceProfileKindDefault selects the account default profile.
	DeviceProfileKindDefault DeviceProfileKind = "Default"
	// DeviceProfileKindCustom is a supported API value.
	DeviceProfileKindCustom DeviceProfileKind = "Custom"
)

// DeviceProfileSplitTunnelMode selects the one active whole-list split-tunnel policy.
// +kubebuilder:validation:Enum=Include;Exclude
type DeviceProfileSplitTunnelMode string

const (
	// DeviceProfileSplitTunnelModeInclude includes listed routes.
	DeviceProfileSplitTunnelModeInclude DeviceProfileSplitTunnelMode = "Include"
	// DeviceProfileSplitTunnelModeExclude is a supported API value.
	DeviceProfileSplitTunnelModeExclude DeviceProfileSplitTunnelMode = "Exclude"
)

// DeviceProfileServiceMode selects the operating mode used by the WARP client.
// +kubebuilder:validation:Enum=warp;1.1.1.1;proxy;posture_only
type DeviceProfileServiceMode string

// DeviceProfileTunnelProtocol selects the WARP tunnel transport.
// +kubebuilder:validation:Enum=wireguard;masque
type DeviceProfileTunnelProtocol string

// DeviceProfileServiceModeV2 configures the WARP client's service mode.
// +kubebuilder:validation:XValidation:rule="self.mode != 'proxy' || has(self.port)",message="port is required when mode is proxy"
// +kubebuilder:validation:XValidation:rule="self.mode == 'proxy' || !has(self.port)",message="port is only valid when mode is proxy"
type DeviceProfileServiceModeV2 struct {
	Mode DeviceProfileServiceMode `json:"mode"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`
}

// DeviceProfileVirtualNetworks configures virtual-network access by Kubernetes reference.
type DeviceProfileVirtualNetworks struct {
	DefaultRef corev1.LocalObjectReference `json:"defaultRef"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1000
	// +listType=map
	// +listMapKey=name
	AllowedRefs []corev1.LocalObjectReference `json:"allowedRefs"`
}

// DeviceProfileFields contains optional remote profile fields. Pointers preserve
// omission separately from explicit false, zero, and empty values.
type DeviceProfileFields struct {
	Name                       *string                       `json:"name,omitempty"`
	Description                *string                       `json:"description,omitempty"`
	Enabled                    *bool                         `json:"enabled,omitempty"`
	SwitchLocked               *bool                         `json:"switchLocked,omitempty"`
	CaptivePortal              *int64                        `json:"captivePortal,omitempty"`
	AllowModeSwitch            *bool                         `json:"allowModeSwitch,omitempty"`
	AllowUpdates               *bool                         `json:"allowUpdates,omitempty"`
	AllowedToLeave             *bool                         `json:"allowedToLeave,omitempty"`
	AutoConnect                *int64                        `json:"autoConnect,omitempty"`
	DisableAutoFallback        *bool                         `json:"disableAutoFallback,omitempty"`
	ExcludeOfficeIPs           *bool                         `json:"excludeOfficeIps,omitempty"`
	ServiceModeV2              *DeviceProfileServiceModeV2   `json:"serviceModeV2,omitempty"`
	SupportURL                 *string                       `json:"supportUrl,omitempty"`
	LANAllowMinutes            *int64                        `json:"lanAllowMinutes,omitempty"`
	LANAllowSubnetSize         *int32                        `json:"lanAllowSubnetSize,omitempty"`
	RegisterInterfaceIPWithDNS *bool                         `json:"registerInterfaceIpWithDns,omitempty"`
	SCCMVPNBoundarySupport     *bool                         `json:"sccmVpnBoundarySupport,omitempty"`
	TunnelProtocol             *DeviceProfileTunnelProtocol  `json:"tunnelProtocol,omitempty"`
	VirtualNetworks            *DeviceProfileVirtualNetworks `json:"virtualNetworks,omitempty"`
}

// DeviceProfileTarget selects and configures the remote profile.
// +kubebuilder:validation:XValidation:rule="self.kind != 'Custom' || (has(self.match) && self.match != \"\" && has(self.precedence) && has(self.fields) && has(self.fields.name) && self.fields.name != \"\")",message="Custom profiles require match, precedence, and fields.name"
// +kubebuilder:validation:XValidation:rule="self.kind == 'Custom' || (!has(self.match) && !has(self.precedence) && (!has(self.fields) || (!has(self.fields.name) && !has(self.fields.description) && !has(self.fields.enabled) && !has(self.fields.lanAllowMinutes) && !has(self.fields.lanAllowSubnetSize))))",message="match, precedence, name, description, enabled, lanAllowMinutes, and lanAllowSubnetSize are only valid for Custom profiles"
type DeviceProfileTarget struct {
	// +kubebuilder:default=Default
	Kind DeviceProfileKind `json:"kind,omitempty"`
	// +kubebuilder:validation:MaxLength=10000
	Match *string `json:"match,omitempty"`
	// +kubebuilder:validation:Minimum=0
	Precedence *int64               `json:"precedence,omitempty"`
	Fields     *DeviceProfileFields `json:"fields,omitempty"`
}

// DeviceProfileSplitTunnelEntry is one address or hostname in a whole-list update.
// +kubebuilder:validation:XValidation:rule="has(self.address) != has(self.host)",message="exactly one of address or host is required"
type DeviceProfileSplitTunnelEntry struct {
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=49
	Address *string `json:"address,omitempty"`
	// +kubebuilder:validation:Pattern=`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=253
	Host *string `json:"host,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
}

// DeviceProfileRouteSelector selects route resources whose accepted values are aggregated.
type DeviceProfileRouteSelector struct {
	Selector metav1.LabelSelector `json:"selector"`
}

// DeviceProfileAccessApplicationSource selects public Access applications by namespace.
type DeviceProfileAccessApplicationSource struct {
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`
}

// DeviceProfileRouteSources configures route-derived split-tunnel entries.
type DeviceProfileRouteSources struct {
	NetworkRoutes        *DeviceProfileRouteSelector           `json:"networkRoutes,omitempty"`
	HostnameRoutes       *DeviceProfileRouteSelector           `json:"hostnameRoutes,omitempty"`
	PrivateHostnameRange bool                                  `json:"privateHostnameRange,omitempty"`
	AccessApplications   *DeviceProfileAccessApplicationSource `json:"accessApplications,omitempty"`
}

// DeviceProfileSplitTunnel configures the active whole-list split-tunnel mode.
// +kubebuilder:validation:XValidation:rule="self.mode == 'Include' || !has(self.routeSources) || (!self.routeSources.privateHostnameRange && !has(self.routeSources.accessApplications))",message="privateHostnameRange and accessApplications are only valid in Include mode"
type DeviceProfileSplitTunnel struct {
	Mode DeviceProfileSplitTunnelMode `json:"mode"`
	// +kubebuilder:validation:MaxItems=1000
	// +listType=atomic
	Static       []DeviceProfileSplitTunnelEntry `json:"static,omitempty"`
	RouteSources DeviceProfileRouteSources       `json:"routeSources,omitempty"`
}

// DeviceProfileFallbackDomain bypasses Gateway DNS resolution for one suffix.
type DeviceProfileFallbackDomain struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Suffix string `json:"suffix"`
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	DNSServer []string `json:"dnsServer,omitempty"`
}

// DeviceProfileFallbackDomains contains statically owned fallback domains.
type DeviceProfileFallbackDomains struct {
	// +kubebuilder:validation:MaxItems=1000
	// +listType=atomic
	Static []DeviceProfileFallbackDomain `json:"static,omitempty"`
}

// DeviceProfileDNSSearchSuffix is one search suffix pushed to WARP clients.
type DeviceProfileDNSSearchSuffix struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Suffix string `json:"suffix"`
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
}

// DeviceProfileExternalReference identifies an existing custom device profile.
type DeviceProfileExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	ProfileID string `json:"profileId"`
}

// DeviceProfileSpec defines one aggregate writer for a remote device profile.
// +kubebuilder:validation:XValidation:rule="self.profile.kind != 'Default' || (!has(self.externalRef) && self.adoption.mode == 'None')",message="Default profiles cannot use externalRef or adoption"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
type DeviceProfileSpec struct {
	AccountRef      corev1.LocalObjectReference  `json:"accountRef"`
	Profile         DeviceProfileTarget          `json:"profile"`
	SplitTunnel     DeviceProfileSplitTunnel     `json:"splitTunnel"`
	FallbackDomains DeviceProfileFallbackDomains `json:"fallbackDomains,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	DNSSearchSuffixes []DeviceProfileDNSSearchSuffix `json:"dnsSearchSuffixes,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy                `json:"managementPolicy,omitempty"`
	ExternalRef      *DeviceProfileExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DeviceProfileStatusSplitTunnelEntry is an unvalidated status mirror of a split-tunnel entry.
type DeviceProfileStatusSplitTunnelEntry struct {
	Address     *string `json:"address,omitempty"`
	Host        *string `json:"host,omitempty"`
	Description string  `json:"description,omitempty"`
}

// DeviceProfileStatusFallbackDomain is an unvalidated status mirror of a fallback domain.
type DeviceProfileStatusFallbackDomain struct {
	Suffix      string   `json:"suffix"`
	Description string   `json:"description,omitempty"`
	DNSServer   []string `json:"dnsServer,omitempty"`
}

// DeviceProfileAppliedSplitTunnelEntry records an applied entry and every source that contributed it.
type DeviceProfileAppliedSplitTunnelEntry struct {
	Entry DeviceProfileStatusSplitTunnelEntry `json:"entry"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1000
	Provenance []string `json:"provenance"`
}

// DeviceProfileAppliedFallbackDomain records an applied fallback and its sources.
type DeviceProfileAppliedFallbackDomain struct {
	Entry DeviceProfileStatusFallbackDomain `json:"entry"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1000
	Provenance []string `json:"provenance"`
}

// DeviceProfileSplitTunnelDiff is the item-level diff reported in ObserveOnly mode.
type DeviceProfileSplitTunnelDiff struct {
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Add []DeviceProfileStatusSplitTunnelEntry `json:"add,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Remove []DeviceProfileStatusSplitTunnelEntry `json:"remove,omitempty"`
}

// DeviceProfileFallbackDomainDiff is the fallback-domain diff reported in ObserveOnly mode.
type DeviceProfileFallbackDomainDiff struct {
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Add []DeviceProfileStatusFallbackDomain `json:"add,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Remove []DeviceProfileStatusFallbackDomain `json:"remove,omitempty"`
}

// DeviceProfileDNSSearchSuffixDiff is the DNS search suffix diff reported in ObserveOnly mode.
type DeviceProfileDNSSearchSuffixDiff struct {
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Add []DeviceProfileDNSSearchSuffix `json:"add,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Remove []DeviceProfileDNSSearchSuffix `json:"remove,omitempty"`
}

// DeviceProfileWouldApplyStatus is the exact non-secret diff that Managed mode would write.
type DeviceProfileWouldApplyStatus struct {
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	ProfileFields     []string                         `json:"profileFields,omitempty"`
	Include           DeviceProfileSplitTunnelDiff     `json:"include,omitempty"`
	Exclude           DeviceProfileSplitTunnelDiff     `json:"exclude,omitempty"`
	FallbackDomains   DeviceProfileFallbackDomainDiff  `json:"fallbackDomains,omitempty"`
	DNSSearchSuffixes DeviceProfileDNSSearchSuffixDiff `json:"dnsSearchSuffixes,omitempty"`
}

// DeviceProfileStatus records the resolved remote profile and aggregate ownership.
type DeviceProfileStatus struct {
	ProfileID         string `json:"profileId,omitempty"`
	OwnershipVerified bool   `json:"ownershipVerified,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	AppliedInclude []DeviceProfileAppliedSplitTunnelEntry `json:"appliedInclude,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	AppliedExclude []DeviceProfileAppliedSplitTunnelEntry `json:"appliedExclude,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	AppliedFallback []DeviceProfileAppliedFallbackDomain `json:"appliedFallback,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=1000
	Conflicts  []string                       `json:"conflicts,omitempty"`
	WouldApply *DeviceProfileWouldApplyStatus `json:"wouldApply,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=dprofile,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.spec.profile.kind`
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.status.profileId`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// DeviceProfile owns all mutable fields and whole lists for one Cloudflare device profile.
type DeviceProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DeviceProfileSpec   `json:"spec,omitempty"`
	Status            DeviceProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DeviceProfileList contains DeviceProfile objects.
type DeviceProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DeviceProfile `json:"items"`
}
