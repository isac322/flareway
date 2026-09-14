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

// AccessPolicyFinalizer identifies the finalizer used for AccessPolicy cleanup.
const AccessPolicyFinalizer = "flareway.bhyoo.com/accesspolicy"

// AccessPolicyDecision is the action taken for a matching Access policy.
// +kubebuilder:validation:Enum=allow;deny;nonIdentity;bypass
type AccessPolicyDecision string

const (
	// AccessPolicyDecisionAllow permits matching requests.
	AccessPolicyDecisionAllow AccessPolicyDecision = "allow"
	// AccessPolicyDecisionDeny is a supported API value.
	AccessPolicyDecisionDeny AccessPolicyDecision = "deny"
	// AccessPolicyDecisionNonIdentity is a supported API value.
	AccessPolicyDecisionNonIdentity AccessPolicyDecision = "nonIdentity"
	// AccessPolicyDecisionBypass is a supported API value.
	AccessPolicyDecisionBypass AccessPolicyDecision = "bypass"
)

// AccessPolicyExternalReference identifies an existing Cloudflare Access policy.
type AccessPolicyExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	PolicyID string `json:"policyId"`
}

// AccessPolicyPurposeJustification configures purpose justification prompts.
type AccessPolicyPurposeJustification struct {
	Required bool   `json:"required,omitempty"`
	Prompt   string `json:"prompt,omitempty"`
}

// AccessPolicyApprovalGroup configures an approval group.
type AccessPolicyApprovalGroup struct {
	// +kubebuilder:validation:Minimum=1
	ApprovalsNeeded int32 `json:"approvalsNeeded"`
	// +listType=set
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	EmailListID    string   `json:"emailListId,omitempty"`
}

// AccessPolicyApproval configures policy approval requirements.
type AccessPolicyApproval struct {
	Required bool `json:"required,omitempty"`
	// +listType=atomic
	Groups []AccessPolicyApprovalGroup `json:"groups,omitempty"`
}

// AccessPolicySpec defines a reusable account-level Access policy.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessPolicySpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:validation:MinLength=1
	Name     string               `json:"name"`
	Decision AccessPolicyDecision `json:"decision"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Include []AccessRule `json:"include"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Require []AccessRule `json:"require,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	Exclude              []AccessRule                      `json:"exclude,omitempty"`
	SessionDuration      string                            `json:"sessionDuration,omitempty"`
	PurposeJustification *AccessPolicyPurposeJustification `json:"purposeJustification,omitempty"`
	Approval             *AccessPolicyApproval             `json:"approval,omitempty"`
	IsolationRequired    bool                              `json:"isolationRequired,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy               `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessPolicyExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Orphan
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessPolicyReferenceStatus identifies a resource referencing this policy.
type AccessPolicyReferenceStatus struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// AccessPolicyStatus records the remote policy identity and references.
type AccessPolicyStatus struct {
	PolicyID          string `json:"policyId,omitempty"`
	OwnershipVerified bool   `json:"ownershipVerified,omitempty"`
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	ReferencedBy []AccessPolicyReferenceStatus `json:"referencedBy,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfap,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.policyId`

// AccessPolicy manages a reusable Cloudflare Access policy.
type AccessPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessPolicySpec   `json:"spec,omitempty"`
	Status            AccessPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessPolicyList contains AccessPolicy objects.
type AccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessPolicy `json:"items"`
}
