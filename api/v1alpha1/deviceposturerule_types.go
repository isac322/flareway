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

// DevicePostureRuleFinalizer identifies the posture rule cleanup finalizer.
const DevicePostureRuleFinalizer = "flareway.bhyoo.com/deviceposturerule"

// DevicePostureRuleType selects a Cloudflare posture check implementation.
// +kubebuilder:validation:Enum=file;application;serial_number;os_version;domain_joined;firewall;disk_encryption;client_certificate;warp;gateway;unique_client_id;antivirus;intune;crowdstrike_s2s;sentinelone_s2s;kolide;tanium_s2s;uptycs;workspace_one
type DevicePostureRuleType string

// DevicePosturePlatform selects operating systems on which a posture check runs.
// +kubebuilder:validation:Enum=windows;mac;linux;android;ios;chromeos
type DevicePosturePlatform string

// DevicePostureMatch selects a platform for posture evaluation.
type DevicePostureMatch struct {
	Platform DevicePosturePlatform `json:"platform"`
}

// DevicePostureInput is the typed superset accepted by Cloudflare posture rules.
// The rule Type determines which fields Cloudflare evaluates.
type DevicePostureInput struct {
	ID              string                `json:"id,omitempty"`
	ConnectionID    string                `json:"connectionId,omitempty"`
	OperatingSystem DevicePosturePlatform `json:"operatingSystem,omitempty"`
	Path            string                `json:"path,omitempty"`
	SHA256          string                `json:"sha256,omitempty"`
	Domain          string                `json:"domain,omitempty"`
	Version         string                `json:"version,omitempty"`
	// +kubebuilder:validation:Enum=<;<=;>;>=;==
	VersionOperator  string `json:"versionOperator,omitempty"`
	Operator         string `json:"operator,omitempty"`
	Enabled          *bool  `json:"enabled,omitempty"`
	Exists           *bool  `json:"exists,omitempty"`
	RequireAll       *bool  `json:"requireAll,omitempty"`
	Infected         *bool  `json:"infected,omitempty"`
	IsActive         *bool  `json:"isActive,omitempty"`
	ComplianceStatus string `json:"complianceStatus,omitempty"`
	NetworkStatus    string `json:"networkStatus,omitempty"`
	OperationalState string `json:"operationalState,omitempty"`
	State            string `json:"state,omitempty"`
	RiskLevel        string `json:"riskLevel,omitempty"`
	Score            string `json:"score,omitempty"`
	TotalScore       string `json:"totalScore,omitempty"`
	ActiveThreats    string `json:"activeThreats,omitempty"`
	UpdateWindowDays string `json:"updateWindowDays,omitempty"`
	LastSeen         string `json:"lastSeen,omitempty"`
	EIDLastSeen      string `json:"eidLastSeen,omitempty"`
	IssueCount       string `json:"issueCount,omitempty"`
	SensorConfig     string `json:"sensorConfig,omitempty"`
	CertificateID    string `json:"certificateId,omitempty"`
	CheckPrivateKey  *bool  `json:"checkPrivateKey,omitempty"`
	CommonName       string `json:"commonName,omitempty"`
	Thumbprint       string `json:"thumbprint,omitempty"`
	OS               string `json:"os,omitempty"`
	OSDistroName     string `json:"osDistroName,omitempty"`
	OSDistroRevision string `json:"osDistroRevision,omitempty"`
	OSVersionExtra   string `json:"osVersionExtra,omitempty"`
	Overall          string `json:"overall,omitempty"`
}

// DevicePostureRuleExternalReference identifies an existing posture rule.
type DevicePostureRuleExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	RuleID string `json:"ruleId"`
}

// DevicePostureRuleSpec defines a reusable Cloudflare device posture rule.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type DevicePostureRuleSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	Type       DevicePostureRuleType       `json:"type"`
	// +kubebuilder:validation:MinLength=1
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Schedule    string `json:"schedule,omitempty"`
	Expiration  string `json:"expiration,omitempty"`
	// +listType=atomic
	Match []DevicePostureMatch `json:"match,omitempty"`
	Input DevicePostureInput   `json:"input,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                    `json:"managementPolicy,omitempty"`
	ExternalRef      *DevicePostureRuleExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DevicePostureRuleStatus records the remote rule identity and conditions.
type DevicePostureRuleStatus struct {
	RuleID            string `json:"ruleId,omitempty"`
	OwnershipVerified bool   `json:"ownershipVerified,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfdpr,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Rule",type=string,JSONPath=`.status.ruleId`

// DevicePostureRule is a namespaced Cloudflare posture rule resource.
type DevicePostureRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DevicePostureRuleSpec   `json:"spec,omitempty"`
	Status            DevicePostureRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DevicePostureRuleList contains DevicePostureRule objects.
type DevicePostureRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DevicePostureRule `json:"items"`
}
