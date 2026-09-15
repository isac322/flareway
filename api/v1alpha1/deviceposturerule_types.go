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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DevicePostureRuleFinalizer identifies the posture rule cleanup finalizer.
const DevicePostureRuleFinalizer = "flareway.bhyoo.com/deviceposturerule"

// DevicePostureRuleType selects a Cloudflare posture check implementation.
// +kubebuilder:validation:Enum=File;Application;Tanium;Gateway;WARP;DiskEncryption;SerialNumber;SentinelOne;CarbonBlack;Firewall;OSVersion;DomainJoined;ClientCertificate;ClientCertificateV2;Antivirus;UniqueClientID;Kolide;TaniumS2S;CrowdstrikeS2S;Intune;WorkspaceOne;SentinelOneS2S;CustomS2S
type DevicePostureRuleType string

const (
	// DevicePostureRuleTypeFile checks for a file.
	DevicePostureRuleTypeFile DevicePostureRuleType = "File"
	// DevicePostureRuleTypeApplication checks for an application.
	DevicePostureRuleTypeApplication DevicePostureRuleType = "Application"
	// DevicePostureRuleTypeTanium checks Tanium posture data.
	DevicePostureRuleTypeTanium DevicePostureRuleType = "Tanium"
	// DevicePostureRuleTypeGateway checks Gateway posture data.
	DevicePostureRuleTypeGateway DevicePostureRuleType = "Gateway"
	// DevicePostureRuleTypeWARP checks the WARP client.
	DevicePostureRuleTypeWARP DevicePostureRuleType = "WARP"
	// DevicePostureRuleTypeDiskEncryption checks disk encryption.
	DevicePostureRuleTypeDiskEncryption DevicePostureRuleType = "DiskEncryption"
	// DevicePostureRuleTypeSerialNumber checks a device serial number.
	DevicePostureRuleTypeSerialNumber DevicePostureRuleType = "SerialNumber"
	// DevicePostureRuleTypeSentinelOne checks SentinelOne posture data.
	DevicePostureRuleTypeSentinelOne DevicePostureRuleType = "SentinelOne"
	// DevicePostureRuleTypeCarbonBlack checks Carbon Black posture data.
	DevicePostureRuleTypeCarbonBlack DevicePostureRuleType = "CarbonBlack"
	// DevicePostureRuleTypeFirewall checks firewall status.
	DevicePostureRuleTypeFirewall DevicePostureRuleType = "Firewall"
	// DevicePostureRuleTypeOSVersion checks the operating system version.
	DevicePostureRuleTypeOSVersion DevicePostureRuleType = "OSVersion"
	// DevicePostureRuleTypeDomainJoined checks domain membership.
	DevicePostureRuleTypeDomainJoined DevicePostureRuleType = "DomainJoined"
	// DevicePostureRuleTypeClientCertificate checks a client certificate.
	DevicePostureRuleTypeClientCertificate DevicePostureRuleType = "ClientCertificate"
	// DevicePostureRuleTypeClientCertificateV2 checks a version 2 client certificate.
	DevicePostureRuleTypeClientCertificateV2 DevicePostureRuleType = "ClientCertificateV2"
	// DevicePostureRuleTypeAntivirus checks antivirus status.
	DevicePostureRuleTypeAntivirus DevicePostureRuleType = "Antivirus"
	// DevicePostureRuleTypeUniqueClientID checks the unique client ID.
	DevicePostureRuleTypeUniqueClientID DevicePostureRuleType = "UniqueClientID"
	// DevicePostureRuleTypeKolide checks Kolide posture data.
	DevicePostureRuleTypeKolide DevicePostureRuleType = "Kolide"
	// DevicePostureRuleTypeTaniumS2S checks Tanium S2S posture data.
	DevicePostureRuleTypeTaniumS2S DevicePostureRuleType = "TaniumS2S"
	// DevicePostureRuleTypeCrowdstrikeS2S checks CrowdStrike S2S posture data.
	DevicePostureRuleTypeCrowdstrikeS2S DevicePostureRuleType = "CrowdstrikeS2S"
	// DevicePostureRuleTypeIntune checks Microsoft Intune posture data.
	DevicePostureRuleTypeIntune DevicePostureRuleType = "Intune"
	// DevicePostureRuleTypeWorkspaceOne checks Workspace ONE posture data.
	DevicePostureRuleTypeWorkspaceOne DevicePostureRuleType = "WorkspaceOne"
	// DevicePostureRuleTypeSentinelOneS2S checks SentinelOne S2S posture data.
	DevicePostureRuleTypeSentinelOneS2S DevicePostureRuleType = "SentinelOneS2S"
	// DevicePostureRuleTypeCustomS2S checks custom S2S posture data.
	DevicePostureRuleTypeCustomS2S DevicePostureRuleType = "CustomS2S"
)

// DevicePosturePlatform selects an operating system.
// +kubebuilder:validation:Enum=Windows;Mac;Linux;Android;IOS;ChromeOS
type DevicePosturePlatform string

const (
	// DevicePosturePlatformWindows selects Windows.
	DevicePosturePlatformWindows DevicePosturePlatform = "Windows"
	// DevicePosturePlatformMac selects macOS.
	DevicePosturePlatformMac DevicePosturePlatform = "Mac"
	// DevicePosturePlatformLinux selects Linux.
	DevicePosturePlatformLinux DevicePosturePlatform = "Linux"
	// DevicePosturePlatformAndroid selects Android.
	DevicePosturePlatformAndroid DevicePosturePlatform = "Android"
	// DevicePosturePlatformIOS selects iOS.
	DevicePosturePlatformIOS DevicePosturePlatform = "IOS"
	// DevicePosturePlatformChromeOS selects ChromeOS.
	DevicePosturePlatformChromeOS DevicePosturePlatform = "ChromeOS"
)

// DevicePostureOperator selects a numeric or version comparison.
// +kubebuilder:validation:Enum=LessThan;LessThanOrEqual;GreaterThan;GreaterThanOrEqual;Equal
type DevicePostureOperator string

const (
	// DevicePostureOperatorLessThan performs a less-than comparison.
	DevicePostureOperatorLessThan DevicePostureOperator = "LessThan"
	// DevicePostureOperatorLessThanOrEqual performs a less-than-or-equal comparison.
	DevicePostureOperatorLessThanOrEqual DevicePostureOperator = "LessThanOrEqual"
	// DevicePostureOperatorGreaterThan performs a greater-than comparison.
	DevicePostureOperatorGreaterThan DevicePostureOperator = "GreaterThan"
	// DevicePostureOperatorGreaterThanOrEqual performs a greater-than-or-equal comparison.
	DevicePostureOperatorGreaterThanOrEqual DevicePostureOperator = "GreaterThanOrEqual"
	// DevicePostureOperatorEqual performs an equality comparison.
	DevicePostureOperatorEqual DevicePostureOperator = "Equal"
)

// DevicePostureComplianceStatus selects a provider compliance state.
// +kubebuilder:validation:Enum=Compliant;NonCompliant;Unknown;NotApplicable;InGracePeriod;Error
type DevicePostureComplianceStatus string

// DevicePostureNetworkStatus selects a SentinelOne network state.
// +kubebuilder:validation:Enum=Connected;Disconnected;Disconnecting;Connecting
type DevicePostureNetworkStatus string

// DevicePostureOperationalState selects a SentinelOne agent state.
// +kubebuilder:validation:Enum=NotApplicable;PartiallyDisabled;AutomaticallyFullyDisabled;FullyDisabled;AutomaticallyPartiallyDisabled;DisabledError;DatabaseCorruption
type DevicePostureOperationalState string

// DevicePostureState selects a CrowdStrike device state.
// +kubebuilder:validation:Enum=Online;Offline;Unknown
type DevicePostureState string

// DevicePostureRiskLevel selects a Tanium risk level.
// +kubebuilder:validation:Enum=Low;Medium;High;Critical
type DevicePostureRiskLevel string

// DevicePostureKolideAuthState selects a Kolide authentication state.
// +kubebuilder:validation:Enum=Good;Notified;WillBlock;Blocked
type DevicePostureKolideAuthState string

// DevicePostureExtendedKeyUsage selects a certificate key purpose.
// +kubebuilder:validation:Enum=ClientAuth;EmailProtection
type DevicePostureExtendedKeyUsage string

// DevicePostureTrustStore selects a certificate trust store.
// +kubebuilder:validation:Enum=System;User
type DevicePostureTrustStore string

const (
	// DevicePostureComplianceCompliant selects compliant devices.
	DevicePostureComplianceCompliant DevicePostureComplianceStatus = "Compliant"
	// DevicePostureComplianceNonCompliant selects noncompliant devices.
	DevicePostureComplianceNonCompliant DevicePostureComplianceStatus = "NonCompliant"
	// DevicePostureComplianceUnknown selects devices with unknown compliance.
	DevicePostureComplianceUnknown DevicePostureComplianceStatus = "Unknown"
	// DevicePostureComplianceNotApplicable selects devices without an applicable compliance state.
	DevicePostureComplianceNotApplicable DevicePostureComplianceStatus = "NotApplicable"
	// DevicePostureComplianceInGracePeriod selects devices in a compliance grace period.
	DevicePostureComplianceInGracePeriod DevicePostureComplianceStatus = "InGracePeriod"
	// DevicePostureComplianceError selects devices whose compliance check failed.
	DevicePostureComplianceError DevicePostureComplianceStatus = "Error"

	// DevicePostureNetworkConnected selects connected devices.
	DevicePostureNetworkConnected DevicePostureNetworkStatus = "Connected"
	// DevicePostureNetworkDisconnected selects disconnected devices.
	DevicePostureNetworkDisconnected DevicePostureNetworkStatus = "Disconnected"
	// DevicePostureNetworkDisconnecting selects disconnecting devices.
	DevicePostureNetworkDisconnecting DevicePostureNetworkStatus = "Disconnecting"
	// DevicePostureNetworkConnecting selects connecting devices.
	DevicePostureNetworkConnecting DevicePostureNetworkStatus = "Connecting"

	// DevicePostureOperationalNotApplicable selects agents without an applicable operational state.
	DevicePostureOperationalNotApplicable DevicePostureOperationalState = "NotApplicable"
	// DevicePostureOperationalPartiallyDisabled selects partially disabled agents.
	DevicePostureOperationalPartiallyDisabled DevicePostureOperationalState = "PartiallyDisabled"
	// DevicePostureOperationalAutomaticallyFullyDisabled selects automatically fully disabled agents.
	DevicePostureOperationalAutomaticallyFullyDisabled DevicePostureOperationalState = "AutomaticallyFullyDisabled"
	// DevicePostureOperationalFullyDisabled selects fully disabled agents.
	DevicePostureOperationalFullyDisabled DevicePostureOperationalState = "FullyDisabled"
	// DevicePostureOperationalAutomaticallyPartiallyDisabled selects automatically partially disabled agents.
	DevicePostureOperationalAutomaticallyPartiallyDisabled DevicePostureOperationalState = "AutomaticallyPartiallyDisabled"
	// DevicePostureOperationalDisabledError selects agents disabled by an error.
	DevicePostureOperationalDisabledError DevicePostureOperationalState = "DisabledError"
	// DevicePostureOperationalDatabaseCorruption selects agents with database corruption.
	DevicePostureOperationalDatabaseCorruption DevicePostureOperationalState = "DatabaseCorruption"

	// DevicePostureStateOnline selects online devices.
	DevicePostureStateOnline DevicePostureState = "Online"
	// DevicePostureStateOffline selects offline devices.
	DevicePostureStateOffline DevicePostureState = "Offline"
	// DevicePostureStateUnknown selects devices with unknown state.
	DevicePostureStateUnknown DevicePostureState = "Unknown"

	// DevicePostureRiskLow selects low-risk devices.
	DevicePostureRiskLow DevicePostureRiskLevel = "Low"
	// DevicePostureRiskMedium selects medium-risk devices.
	DevicePostureRiskMedium DevicePostureRiskLevel = "Medium"
	// DevicePostureRiskHigh selects high-risk devices.
	DevicePostureRiskHigh DevicePostureRiskLevel = "High"
	// DevicePostureRiskCritical selects critical-risk devices.
	DevicePostureRiskCritical DevicePostureRiskLevel = "Critical"

	// DevicePostureKolideAuthGood selects devices with good Kolide authentication.
	DevicePostureKolideAuthGood DevicePostureKolideAuthState = "Good"
	// DevicePostureKolideAuthNotified selects devices notified by Kolide.
	DevicePostureKolideAuthNotified DevicePostureKolideAuthState = "Notified"
	// DevicePostureKolideAuthWillBlock selects devices that Kolide will block.
	DevicePostureKolideAuthWillBlock DevicePostureKolideAuthState = "WillBlock"
	// DevicePostureKolideAuthBlocked selects devices blocked by Kolide.
	DevicePostureKolideAuthBlocked DevicePostureKolideAuthState = "Blocked"

	// DevicePostureExtendedKeyUsageClientAuth selects client authentication certificates.
	DevicePostureExtendedKeyUsageClientAuth DevicePostureExtendedKeyUsage = "ClientAuth"
	// DevicePostureExtendedKeyUsageEmailProtection selects email protection certificates.
	DevicePostureExtendedKeyUsageEmailProtection DevicePostureExtendedKeyUsage = "EmailProtection"

	// DevicePostureTrustStoreSystem selects the system trust store.
	DevicePostureTrustStoreSystem DevicePostureTrustStore = "System"
	// DevicePostureTrustStoreUser selects the user trust store.
	DevicePostureTrustStoreUser DevicePostureTrustStore = "User"
)

// DevicePostureMatch selects a platform for posture evaluation.
type DevicePostureMatch struct {
	Platform DevicePosturePlatform `json:"platform"`
}

// DevicePostureCertificateLocations selects certificate paths and trust stores.
type DevicePostureCertificateLocations struct {
	// +listType=set
	Paths []string `json:"paths,omitempty"`
	// +listType=set
	TrustStores []DevicePostureTrustStore `json:"trustStores,omitempty"`
}

// DevicePostureInput is the typed superset accepted by Cloudflare posture rules.
// Type determines which fields are required and sent.
type DevicePostureInput struct {
	ID             string                             `json:"id,omitempty"`
	IntegrationRef *DevicePostureIntegrationReference `json:"integrationRef,omitempty"`

	OperatingSystem DevicePosturePlatform `json:"operatingSystem,omitempty"`
	Path            string                `json:"path,omitempty"`
	SHA256          string                `json:"sha256,omitempty"`
	Domain          string                `json:"domain,omitempty"`
	Version         string                `json:"version,omitempty"`
	VersionOperator DevicePostureOperator `json:"versionOperator,omitempty"`
	Operator        DevicePostureOperator `json:"operator,omitempty"`

	Enabled         *bool `json:"enabled,omitempty"`
	Exists          *bool `json:"exists,omitempty"`
	RequireAll      *bool `json:"requireAll,omitempty"`
	Infected        *bool `json:"infected,omitempty"`
	IsActive        *bool `json:"isActive,omitempty"`
	CheckPrivateKey *bool `json:"checkPrivateKey,omitempty"`

	ComplianceStatus DevicePostureComplianceStatus `json:"complianceStatus,omitempty"`
	NetworkStatus    DevicePostureNetworkStatus    `json:"networkStatus,omitempty"`
	OperationalState DevicePostureOperationalState `json:"operationalState,omitempty"`
	State            DevicePostureState            `json:"state,omitempty"`
	RiskLevel        DevicePostureRiskLevel        `json:"riskLevel,omitempty"`

	// +kubebuilder:validation:Type=string
	Score         *resource.Quantity    `json:"score,omitempty"`
	ScoreOperator DevicePostureOperator `json:"scoreOperator,omitempty"`
	// +kubebuilder:validation:Type=string
	TotalScore *resource.Quantity `json:"totalScore,omitempty"`
	// +kubebuilder:validation:Type=string
	ActiveThreats *resource.Quantity `json:"activeThreats,omitempty"`
	// +kubebuilder:validation:Type=string
	UpdateWindowDays *resource.Quantity    `json:"updateWindowDays,omitempty"`
	LastSeen         string                `json:"lastSeen,omitempty"`
	EIDLastSeen      string                `json:"eidLastSeen,omitempty"`
	IssueCount       string                `json:"issueCount,omitempty"`
	CountOperator    DevicePostureOperator `json:"countOperator,omitempty"`
	SensorConfig     string                `json:"sensorConfig,omitempty"`

	CertificateID    string `json:"certificateId,omitempty"`
	CommonName       string `json:"commonName,omitempty"`
	Thumbprint       string `json:"thumbprint,omitempty"`
	OS               string `json:"os,omitempty"`
	OSDistroName     string `json:"osDistroName,omitempty"`
	OSDistroRevision string `json:"osDistroRevision,omitempty"`
	OSVersionExtra   string `json:"osVersionExtra,omitempty"`
	Overall          string `json:"overall,omitempty"`

	// +listType=set
	AuthState []DevicePostureKolideAuthState `json:"authState,omitempty"`
	// +listType=set
	CheckDisks []string `json:"checkDisks,omitempty"`
	// +listType=set
	ExtendedKeyUsage []DevicePostureExtendedKeyUsage    `json:"extendedKeyUsage,omitempty"`
	Locations        *DevicePostureCertificateLocations `json:"locations,omitempty"`
	// +listType=set
	SubjectAlternativeNames []string `json:"subjectAlternativeNames,omitempty"`
}

// DevicePostureRuleExternalReference identifies an existing posture rule.
type DevicePostureRuleExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	RuleID string `json:"ruleId"`
}

// DevicePostureRuleSpec defines a reusable Cloudflare device posture rule.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!(self.type in ['Tanium','TaniumS2S','CrowdstrikeS2S','Intune','WorkspaceOne','Kolide','SentinelOneS2S','CustomS2S']) || (has(self.input) && has(self.input.integrationRef))",message="integration-backed posture rules require input.integrationRef"
// +kubebuilder:validation:XValidation:rule="(self.type in ['Tanium','TaniumS2S','CrowdstrikeS2S','Intune','WorkspaceOne','Kolide','SentinelOneS2S','CustomS2S']) || !has(self.input) || !has(self.input.integrationRef)",message="input.integrationRef is only valid for integration-backed posture rules"
// +kubebuilder:validation:XValidation:rule="self.type != 'Firewall' || (has(self.input) && has(self.input.enabled) && has(self.input.operatingSystem))",message="Firewall requires enabled and operatingSystem"
// +kubebuilder:validation:XValidation:rule="self.type != 'CustomS2S' || (has(self.input) && has(self.input.score) && has(self.input.operator))",message="CustomS2S requires score and operator"
// +kubebuilder:validation:XValidation:rule="self.type != 'ClientCertificateV2' || (has(self.input) && has(self.input.checkPrivateKey) && has(self.input.operatingSystem) && size(self.input.certificateId) > 0)",message="ClientCertificateV2 requires certificateId, checkPrivateKey, and operatingSystem"
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

// DevicePostureRuleObservedState retains mutable remote fields for drift comparison.
type DevicePostureRuleObservedState struct {
	Name        string                `json:"name,omitempty"`
	Type        DevicePostureRuleType `json:"type,omitempty"`
	Description string                `json:"description,omitempty"`
	Enabled     bool                  `json:"enabled,omitempty"`
	Schedule    string                `json:"schedule,omitempty"`
	Expiration  string                `json:"expiration,omitempty"`
	// +listType=atomic
	Match []DevicePostureMatch `json:"match,omitempty"`
	Input DevicePostureInput   `json:"input,omitempty"`
}

// DevicePostureRuleStatus records the remote rule identity and observed state.
type DevicePostureRuleStatus struct {
	RuleID            string                          `json:"ruleId,omitempty"`
	OwnershipVerified bool                            `json:"ownershipVerified,omitempty"`
	Observed          *DevicePostureRuleObservedState `json:"observed,omitempty"`
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
