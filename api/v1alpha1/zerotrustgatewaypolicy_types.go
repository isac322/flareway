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
	// ZeroTrustGatewayPolicyFinalizer is a supported API value.
	ZeroTrustGatewayPolicyFinalizer = "flareway.bhyoo.com/zerotrustgatewaypolicy"
	// ZeroTrustGatewayPolicyConditionAccepted is a supported API value.
	ZeroTrustGatewayPolicyConditionAccepted = "Accepted"
	// ZeroTrustGatewayPolicyConditionReady is a supported API value.
	ZeroTrustGatewayPolicyConditionReady = "Ready"
)

// ZeroTrustGatewayFilter selects the Gateway policy evaluation layer.
// +kubebuilder:validation:Enum=l4;dns
type ZeroTrustGatewayFilter string

const (
	// ZeroTrustGatewayFilterL4 is a supported API value.
	ZeroTrustGatewayFilterL4 ZeroTrustGatewayFilter = "l4"
	// ZeroTrustGatewayFilterDNS is a supported API value.
	ZeroTrustGatewayFilterDNS ZeroTrustGatewayFilter = "dns"
)

// ZeroTrustGatewayAction is an action accepted by Cloudflare Gateway rules.
// +kubebuilder:validation:Enum=on;off;allow;block;scan;noscan;safesearch;ytrestricted;isolate;noisolate;override;l4_override;audit_ssh;egress;resolve;quarantine;redirect
type ZeroTrustGatewayAction string

// ZeroTrustGatewayListReference identifies a ZeroTrustList in the same namespace.
type ZeroTrustGatewayListReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ZeroTrustGatewayCheckSession configures session freshness for an allow rule.
type ZeroTrustGatewayCheckSession struct {
	Enforce  *bool   `json:"enforce,omitempty"`
	Duration *string `json:"duration,omitempty"`
}

// ZeroTrustGatewayAuditSSH configures SSH command logging.
type ZeroTrustGatewayAuditSSH struct {
	CommandLogging *bool `json:"commandLogging,omitempty"`
}

// ZeroTrustGatewayL4Override redirects matching traffic to an address and port.
type ZeroTrustGatewayL4Override struct {
	// +kubebuilder:validation:MinLength=1
	IP string `json:"ip"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ZeroTrustGatewayNotification configures a client notification for blocked traffic.
type ZeroTrustGatewayNotification struct {
	Enabled        *bool   `json:"enabled,omitempty"`
	IncludeContext *bool   `json:"includeContext,omitempty"`
	Message        *string `json:"message,omitempty"`
	SupportURL     *string `json:"supportUrl,omitempty"`
}

// ZeroTrustGatewayRuleSettings contains settings supported by l4 and dns rules.
type ZeroTrustGatewayRuleSettings struct {
	AuditSSH                        *ZeroTrustGatewayAuditSSH     `json:"auditSsh,omitempty"`
	BlockPageEnabled                *bool                         `json:"blockPageEnabled,omitempty"`
	BlockReason                     *string                       `json:"blockReason,omitempty"`
	CheckSession                    *ZeroTrustGatewayCheckSession `json:"checkSession,omitempty"`
	IgnoreCNAMECategoryMatches      *bool                         `json:"ignoreCnameCategoryMatches,omitempty"`
	InsecureDisableDNSSECValidation *bool                         `json:"insecureDisableDnssecValidation,omitempty"`
	IPCategories                    *bool                         `json:"ipCategories,omitempty"`
	IPIndicatorFeeds                *bool                         `json:"ipIndicatorFeeds,omitempty"`
	L4Override                      *ZeroTrustGatewayL4Override   `json:"l4Override,omitempty"`
	Notification                    *ZeroTrustGatewayNotification `json:"notification,omitempty"`
	OverrideHost                    *string                       `json:"overrideHost,omitempty"`
	// +listType=set
	OverrideIPs []string `json:"overrideIps,omitempty"`
}

// ZeroTrustGatewayPolicyDesiredState is the non-secret state sent to Cloudflare.
type ZeroTrustGatewayPolicyDesiredState struct {
	Name          string                        `json:"name"`
	Description   *string                       `json:"description,omitempty"`
	Enabled       *bool                         `json:"enabled,omitempty"`
	Precedence    *int64                        `json:"precedence,omitempty"`
	Filters       []ZeroTrustGatewayFilter      `json:"filters"`
	Action        ZeroTrustGatewayAction        `json:"action"`
	Traffic       string                        `json:"traffic"`
	Identity      *string                       `json:"identity,omitempty"`
	DevicePosture *string                       `json:"devicePosture,omitempty"`
	RuleSettings  *ZeroTrustGatewayRuleSettings `json:"ruleSettings,omitempty"`
}

// ZeroTrustGatewayPolicyExternalReference identifies an existing Gateway rule.
type ZeroTrustGatewayPolicyExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	RuleID string `json:"ruleId"`
}

// ZeroTrustGatewayPolicySpec defines one l4 or dns Gateway rule.
// +kubebuilder:validation:XValidation:rule="self.filters[0] == 'dns' || self.action != 'override'",message="override action requires the dns filter"
// +kubebuilder:validation:XValidation:rule="self.filters[0] == 'l4' || !(self.action in ['l4_override', 'audit_ssh'])",message="l4_override and audit_ssh actions require the l4 filter"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
// +kubebuilder:validation:XValidation:rule="!has(self.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
type ZeroTrustGatewayPolicySpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	// +kubebuilder:validation:Minimum=0
	Precedence *int64 `json:"precedence,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	// +listType=set
	Filters []ZeroTrustGatewayFilter `json:"filters"`
	Action  ZeroTrustGatewayAction   `json:"action"`
	// +kubebuilder:validation:MinLength=1
	Traffic       string  `json:"traffic"`
	Identity      *string `json:"identity,omitempty"`
	DevicePosture *string `json:"devicePosture,omitempty"`
	// +listType=map
	// +listMapKey=name
	ListRefs     []ZeroTrustGatewayListReference `json:"listRefs,omitempty"`
	RuleSettings *ZeroTrustGatewayRuleSettings   `json:"ruleSettings,omitempty"`
	// +kubebuilder:default=ObserveOnly
	ManagementPolicy ManagementPolicy                         `json:"managementPolicy,omitempty"`
	ExternalRef      *ZeroTrustGatewayPolicyExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ZeroTrustGatewayPolicyStatus records the remote rule identity and normalized expressions.
type ZeroTrustGatewayPolicyStatus struct {
	RuleID            string                              `json:"ruleId,omitempty"`
	OwnershipVerified bool                                `json:"ownershipVerified,omitempty"`
	Observed          *ZeroTrustGatewayPolicyDesiredState `json:"observed,omitempty"`
	WouldApply        *ZeroTrustGatewayPolicyDesiredState `json:"wouldApply,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	// AppliedHash is the desired-state hash recorded after the last successful remote convergence.
	// +optional
	AppliedHash string `json:"appliedHash,omitempty"`
	// AppliedAt is when AppliedHash was last recorded; nil means never applied.
	// +optional
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=ztgp,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Filter",type=string,JSONPath=`.spec.filters[0]`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="Rule",type=string,JSONPath=`.status.ruleId`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// ZeroTrustGatewayPolicy manages one Cloudflare Gateway l4 or dns rule.
type ZeroTrustGatewayPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ZeroTrustGatewayPolicySpec   `json:"spec,omitempty"`
	Status            ZeroTrustGatewayPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZeroTrustGatewayPolicyList contains ZeroTrustGatewayPolicy objects.
type ZeroTrustGatewayPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZeroTrustGatewayPolicy `json:"items"`
}
