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

// DevicePostureIntegrationFinalizer identifies the integration cleanup finalizer.
const DevicePostureIntegrationFinalizer = "flareway.bhyoo.com/devicepostureintegration"

// DevicePostureIntegrationType selects a third-party posture provider.
// +kubebuilder:validation:Enum=WorkspaceOne;CrowdstrikeS2S;Uptycs;Intune;Kolide;TaniumS2S;SentinelOneS2S;CustomS2S
type DevicePostureIntegrationType string

const (
	// DevicePostureIntegrationTypeWorkspaceOne selects Workspace ONE.
	DevicePostureIntegrationTypeWorkspaceOne DevicePostureIntegrationType = "WorkspaceOne"
	// DevicePostureIntegrationTypeCrowdstrikeS2S selects CrowdStrike S2S.
	DevicePostureIntegrationTypeCrowdstrikeS2S DevicePostureIntegrationType = "CrowdstrikeS2S"
	// DevicePostureIntegrationTypeUptycs selects Uptycs.
	DevicePostureIntegrationTypeUptycs DevicePostureIntegrationType = "Uptycs"
	// DevicePostureIntegrationTypeIntune selects Microsoft Intune.
	DevicePostureIntegrationTypeIntune DevicePostureIntegrationType = "Intune"
	// DevicePostureIntegrationTypeKolide selects Kolide.
	DevicePostureIntegrationTypeKolide DevicePostureIntegrationType = "Kolide"
	// DevicePostureIntegrationTypeTaniumS2S selects Tanium S2S.
	DevicePostureIntegrationTypeTaniumS2S DevicePostureIntegrationType = "TaniumS2S"
	// DevicePostureIntegrationTypeSentinelOneS2S selects SentinelOne S2S.
	DevicePostureIntegrationTypeSentinelOneS2S DevicePostureIntegrationType = "SentinelOneS2S"
	// DevicePostureIntegrationTypeCustomS2S selects a custom S2S provider.
	DevicePostureIntegrationTypeCustomS2S DevicePostureIntegrationType = "CustomS2S"
)

// DevicePostureIntegrationSecretReference identifies one local Secret key.
type DevicePostureIntegrationSecretReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// DevicePostureIntegrationConfig contains provider-specific settings.
// Secret values are always read from the referenced Kubernetes Secrets.
type DevicePostureIntegrationConfig struct {
	APIURL     string `json:"apiUrl,omitempty"`
	AuthURL    string `json:"authUrl,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	CustomerID string `json:"customerId,omitempty"`

	ClientSecretRef       *DevicePostureIntegrationSecretReference `json:"clientSecretRef,omitempty"`
	ClientKeyRef          *DevicePostureIntegrationSecretReference `json:"clientKeyRef,omitempty"`
	AccessClientIDRef     *DevicePostureIntegrationSecretReference `json:"accessClientIdRef,omitempty"`
	AccessClientSecretRef *DevicePostureIntegrationSecretReference `json:"accessClientSecretRef,omitempty"`
}

// DevicePostureIntegrationExternalReference identifies an existing integration.
type DevicePostureIntegrationExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	IntegrationID string `json:"integrationId"`
}

// DevicePostureIntegrationSpec defines a Cloudflare device posture integration.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'WorkspaceOne' || (size(self.config.apiUrl) > 0 && size(self.config.authUrl) > 0 && size(self.config.clientId) > 0 && has(self.config.clientSecretRef))",message="WorkspaceOne requires apiUrl, authUrl, clientId, and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'CrowdstrikeS2S' || (size(self.config.apiUrl) > 0 && size(self.config.clientId) > 0 && size(self.config.customerId) > 0 && has(self.config.clientSecretRef))",message="CrowdstrikeS2S requires apiUrl, clientId, customerId, and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'Uptycs' || (size(self.config.apiUrl) > 0 && size(self.config.customerId) > 0 && has(self.config.clientKeyRef) && has(self.config.clientSecretRef))",message="Uptycs requires apiUrl, customerId, clientKeyRef, and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'Intune' || (size(self.config.clientId) > 0 && size(self.config.customerId) > 0 && has(self.config.clientSecretRef))",message="Intune requires clientId, customerId, and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'Kolide' || (size(self.config.clientId) > 0 && has(self.config.clientSecretRef))",message="Kolide requires clientId and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'TaniumS2S' || (size(self.config.apiUrl) > 0 && has(self.config.clientSecretRef) && (has(self.config.accessClientIdRef) == has(self.config.accessClientSecretRef)))",message="TaniumS2S requires apiUrl and clientSecretRef; Access credentials must be supplied together"
// +kubebuilder:validation:XValidation:rule="self.type != 'SentinelOneS2S' || (size(self.config.apiUrl) > 0 && has(self.config.clientSecretRef))",message="SentinelOneS2S requires apiUrl and clientSecretRef"
// +kubebuilder:validation:XValidation:rule="self.type != 'CustomS2S' || (size(self.config.apiUrl) > 0 && has(self.config.accessClientIdRef) && has(self.config.accessClientSecretRef))",message="CustomS2S requires apiUrl and Access client credential references"
type DevicePostureIntegrationSpec struct {
	AccountRef corev1.LocalObjectReference  `json:"accountRef"`
	Type       DevicePostureIntegrationType `json:"type"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[1-9][0-9]*[mh]$`
	Interval string                         `json:"interval"`
	Config   DevicePostureIntegrationConfig `json:"config"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                           `json:"managementPolicy,omitempty"`
	ExternalRef      *DevicePostureIntegrationExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DevicePostureIntegrationObservedConfig contains only non-secret remote configuration.
type DevicePostureIntegrationObservedConfig struct {
	APIURL     string `json:"apiUrl,omitempty"`
	AuthURL    string `json:"authUrl,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	CustomerID string `json:"customerId,omitempty"`
}

// DevicePostureIntegrationObservedState retains mutable non-secret remote fields.
type DevicePostureIntegrationObservedState struct {
	Name     string                                 `json:"name,omitempty"`
	Type     DevicePostureIntegrationType           `json:"type,omitempty"`
	Interval string                                 `json:"interval,omitempty"`
	Config   DevicePostureIntegrationObservedConfig `json:"config,omitempty"`
}

// DevicePostureIntegrationStatus defines the observed state without credentials.
type DevicePostureIntegrationStatus struct {
	IntegrationID     string                                 `json:"integrationId,omitempty"`
	OwnershipVerified bool                                   `json:"ownershipVerified,omitempty"`
	Observed          *DevicePostureIntegrationObservedState `json:"observed,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfdpi,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Integration",type=string,JSONPath=`.status.integrationId`

// DevicePostureIntegration is a namespaced Cloudflare posture integration.
type DevicePostureIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DevicePostureIntegrationSpec   `json:"spec,omitempty"`
	Status            DevicePostureIntegrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DevicePostureIntegrationList contains DevicePostureIntegration objects.
type DevicePostureIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DevicePostureIntegration `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DevicePostureIntegration{}, &DevicePostureIntegrationList{})
		return nil
	})
}
