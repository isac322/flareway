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
	// DeviceSettingsFinalizer identifies the settings cleanup finalizer.
	DeviceSettingsFinalizer = "flareway.bhyoo.com/devicesettings"
	// DeviceSettingsConditionAccepted is a supported API value.
	DeviceSettingsConditionAccepted = "Accepted"
	// DeviceSettingsConditionReady is a supported API value.
	DeviceSettingsConditionReady = "Ready"
)

// DeviceSettingsValues contains account-wide WARP settings. Pointers preserve
// omitted fields separately from explicit false and zero values.
type DeviceSettingsValues struct {
	GatewayProxyEnabled                *bool `json:"gatewayProxyEnabled,omitempty"`
	GatewayUDPProxyEnabled             *bool `json:"gatewayUdpProxyEnabled,omitempty"`
	RootCertificateInstallationEnabled *bool `json:"rootCertificateInstallationEnabled,omitempty"`
	UseZTVirtualIP                     *bool `json:"useZtVirtualIp,omitempty"`
	// +kubebuilder:validation:Minimum=0
	DisableForTime *int64 `json:"disableForTime,omitempty"`
}

// DeviceSettingsSpec defines the singleton account device settings.
type DeviceSettingsSpec struct {
	AccountRef                         corev1.LocalObjectReference `json:"accountRef"`
	GatewayProxyEnabled                *bool                       `json:"gatewayProxyEnabled,omitempty"`
	GatewayUDPProxyEnabled             *bool                       `json:"gatewayUdpProxyEnabled,omitempty"`
	RootCertificateInstallationEnabled *bool                       `json:"rootCertificateInstallationEnabled,omitempty"`
	UseZTVirtualIP                     *bool                       `json:"useZtVirtualIp,omitempty"`
	// +kubebuilder:validation:Minimum=0
	DisableForTime *int64 `json:"disableForTime,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DeviceSettingsStatus records observed values and the pending ObserveOnly diff.
type DeviceSettingsStatus struct {
	Observed   DeviceSettingsValues  `json:"observed,omitempty"`
	WouldApply *DeviceSettingsValues `json:"wouldApply,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=dsettings,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="DeviceSettings must be named default"
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// DeviceSettings manages the account-wide Cloudflare device settings singleton.
type DeviceSettings struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DeviceSettingsSpec   `json:"spec,omitempty"`
	Status            DeviceSettingsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DeviceSettingsList contains DeviceSettings objects.
type DeviceSettingsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DeviceSettings `json:"items"`
}
