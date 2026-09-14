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
	// AccessApplicationFinalizer is a supported API value.
	AccessApplicationFinalizer = "flareway.bhyoo.com/accessapplication"
	// AccessApplicationConditionOriginJWTEnforced is a supported API value.
	AccessApplicationConditionOriginJWTEnforced = "OriginJWTEnforced"
	// AccessApplicationAUDSecretLabel is a supported API value.
	AccessApplicationAUDSecretLabel = "flareway.bhyoo.com/access-application"
	// AccessApplicationGatewayAUDLabel is a supported API value.
	AccessApplicationGatewayAUDLabel = "flareway.bhyoo.com/aud-for-gateway"
	// AccessApplicationAUDSecretKey is a supported API value.
	AccessApplicationAUDSecretKey = "aud"
	// AccessApplicationIDSecretKey is a supported API value.
	AccessApplicationIDSecretKey = "applicationId"
)

// AccessApplicationExternalReference identifies an existing Access application.
type AccessApplicationExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	ApplicationID string `json:"applicationId"`
}

// AccessPrivateDestinationSpec exposes a non-HTTP destination through Access.
// +kubebuilder:validation:XValidation:rule="has(self.networkRouteRef) != has(self.hostnameRouteRef)",message="exactly one of networkRouteRef or hostnameRouteRef is required"
type AccessPrivateDestinationSpec struct {
	NetworkRouteRef  *corev1.LocalObjectReference `json:"networkRouteRef,omitempty"`
	HostnameRouteRef *corev1.LocalObjectReference `json:"hostnameRouteRef,omitempty"`
	CIDR             string                       `json:"cidr,omitempty"`
	// +kubebuilder:validation:Pattern=`^[0-9]+(-[0-9]+)?$`
	PortRange string `json:"portRange,omitempty"`
	// +kubebuilder:default=tcp
	L4Protocol AccessL4Protocol `json:"l4Protocol,omitempty"`
}

// AccessL4Protocol is the transport protocol for a private Access destination.
// +kubebuilder:validation:Enum=tcp;udp
type AccessL4Protocol string

const (
	// AccessL4ProtocolTCP is a supported API value.
	AccessL4ProtocolTCP AccessL4Protocol = "tcp"
	// AccessL4ProtocolUDP is a supported API value.
	AccessL4ProtocolUDP AccessL4Protocol = "udp"
)

// AccessIdentityProviderReference selects a managed IdP or an external IdP ID.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.externalId)",message="exactly one of name or externalId is required"
type AccessIdentityProviderReference struct {
	Name       string `json:"name,omitempty"`
	ExternalID string `json:"externalId,omitempty"`
}

// AccessCORSHeaders configures Access edge CORS handling.
type AccessCORSHeaders struct {
	AllowAllHeaders  *bool `json:"allowAllHeaders,omitempty"`
	AllowAllMethods  *bool `json:"allowAllMethods,omitempty"`
	AllowAllOrigins  *bool `json:"allowAllOrigins,omitempty"`
	AllowCredentials *bool `json:"allowCredentials,omitempty"`
	// +listType=set
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
	// +listType=set
	AllowedMethods []string `json:"allowedMethods,omitempty"`
	// +listType=set
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	MaxAge         *int64   `json:"maxAge,omitempty"`
}

// AccessApplicationSettings configures a self-hosted Access application.
type AccessApplicationSettings struct {
	Name                     string `json:"name,omitempty"`
	SessionDuration          string `json:"sessionDuration,omitempty"`
	AllowAuthenticateViaWARP *bool  `json:"allowAuthenticateViaWarp,omitempty"`
	SkipInterstitial         *bool  `json:"skipInterstitial,omitempty"`
	AutoRedirectToIdentity   *bool  `json:"autoRedirectToIdentity,omitempty"`
	// +listType=atomic
	AllowedIDPRefs          []AccessIdentityProviderReference `json:"allowedIdpRefs,omitempty"`
	AppLauncherVisible      *bool                             `json:"appLauncherVisible,omitempty"`
	ServiceAuth401Redirect  *bool                             `json:"serviceAuth401Redirect,omitempty"`
	EnableBindingCookie     *bool                             `json:"enableBindingCookie,omitempty"`
	HTTPOnlyCookieAttribute *bool                             `json:"httpOnlyCookieAttribute,omitempty"`
	// +kubebuilder:validation:Enum=lax;strict;none
	SameSiteCookieAttribute     string             `json:"sameSiteCookieAttribute,omitempty"`
	PathCookieAttribute         *bool              `json:"pathCookieAttribute,omitempty"`
	OptionsPreflightBypass      *bool              `json:"optionsPreflightBypass,omitempty"`
	CORSHeaders                 *AccessCORSHeaders `json:"corsHeaders,omitempty"`
	ReadServiceTokensFromHeader string             `json:"readServiceTokensFromHeader,omitempty"`
	CustomDenyMessage           string             `json:"customDenyMessage,omitempty"`
	CustomDenyURL               string             `json:"customDenyUrl,omitempty"`
	CustomNonIdentityDenyURL    string             `json:"customNonIdentityDenyUrl,omitempty"`
	// +listType=set
	CustomPages []string `json:"customPages,omitempty"`
	// +listType=set
	Tags []string `json:"tags,omitempty"`
}

// AccessApplicationPolicyExternalReference identifies a reusable Access policy.
type AccessApplicationPolicyExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	PolicyID string `json:"policyId"`
}

// AccessApplicationPolicyReference selects a managed policy or an external policy ID.
// +kubebuilder:validation:XValidation:rule="has(self.policyRef) != has(self.externalRef)",message="exactly one of policyRef or externalRef is required"
type AccessApplicationPolicyReference struct {
	PolicyRef   *NamespacedLocalObjectReference           `json:"policyRef,omitempty"`
	ExternalRef *AccessApplicationPolicyExternalReference `json:"externalRef,omitempty"`
}

// NamespacedLocalObjectReference identifies a namespaced Flareway resource.
type NamespacedLocalObjectReference struct {
	// +kubebuilder:validation:MinLength=1
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// AccessOriginJWTMode controls origin JWT verification.
// +kubebuilder:validation:Enum=Required;Disabled
type AccessOriginJWTMode string

const (
	// AccessOriginJWTModeRequired is a supported API value.
	AccessOriginJWTModeRequired AccessOriginJWTMode = "Required"
	// AccessOriginJWTModeDisabled is a supported API value.
	AccessOriginJWTModeDisabled AccessOriginJWTMode = "Disabled"
)

// AccessOriginJWTSpec configures origin JWT enforcement.
type AccessOriginJWTSpec struct {
	// +kubebuilder:default=Required
	Mode                       AccessOriginJWTMode `json:"mode,omitempty"`
	AssumeGatewayTLSDecryption bool                `json:"assumeGatewayTLSDecryption,omitempty"`
}

// AccessApplicationSpec defines one self-hosted Cloudflare Access application.
// +kubebuilder:validation:XValidation:rule="(has(self.targetRefs) && size(self.targetRefs) > 0) || (has(self.privateDestinations) && size(self.privateDestinations) > 0)",message="at least one targetRef or privateDestination is required"
// +kubebuilder:validation:XValidation:rule="!has(self.targetRefs) || self.targetRefs.all(t, t.group == 'gateway.networking.k8s.io' && (t.kind == 'Gateway' || t.kind == 'HTTPRoute'))",message="targetRefs must reference gateway.networking.k8s.io Gateway or HTTPRoute objects"
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.externalRef)",message="ObserveOnly requires externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.externalRef)",message="AdoptById requires externalRef"
type AccessApplicationSpec struct {
	AccountRef *corev1.LocalObjectReference `json:"accountRef,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	TargetRefs []gatewayv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=100
	PrivateDestinations []AccessPrivateDestinationSpec `json:"privateDestinations,omitempty"`
	Application         AccessApplicationSettings      `json:"application"`
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Policies []AccessApplicationPolicyReference `json:"policies"`
	// +kubebuilder:default={}
	OriginJWT AccessOriginJWTSpec `json:"originJWT,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy                    `json:"managementPolicy,omitempty"`
	ExternalRef      *AccessApplicationExternalReference `json:"externalRef,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// AccessApplicationDestinationStatus records a compiled Access destination.
type AccessApplicationDestinationStatus struct {
	// +kubebuilder:validation:Enum=public;private
	Type       string           `json:"type"`
	URI        string           `json:"uri,omitempty"`
	Hostname   string           `json:"hostname,omitempty"`
	CIDR       string           `json:"cidr,omitempty"`
	PortRange  string           `json:"portRange,omitempty"`
	L4Protocol AccessL4Protocol `json:"l4Protocol,omitempty"`
	VNetID     string           `json:"vnetId,omitempty"`
}

// AccessApplicationDataPlaneStatus records the selected tunnel and Envoy domain.
type AccessApplicationDataPlaneStatus struct {
	Tunnel           string                `json:"tunnel,omitempty"`
	Listener         gatewayv1.SectionName `json:"listener,omitempty"`
	ProtectionDomain string                `json:"protectionDomain,omitempty"`
	EnvoyPort        int32                 `json:"envoyPort,omitempty"`
}

// AccessBypassApplicationStatus records an operator-owned public carve-out application.
type AccessBypassApplicationStatus struct {
	Hostname      string `json:"hostname"`
	Path          string `json:"path"`
	ApplicationID string `json:"applicationId"`
}

// AccessApplicationStatus records the remote application without exposing its AUD.
type AccessApplicationStatus struct {
	ApplicationID string `json:"applicationId,omitempty"`
	// +listType=atomic
	Destinations []AccessApplicationDestinationStatus `json:"destinations,omitempty"`
	// +listType=atomic
	DataPlanes []AccessApplicationDataPlaneStatus `json:"dataPlanes,omitempty"`
	// +listType=map
	// +listMapKey=hostname
	// +listMapKey=path
	BypassApplications []AccessBypassApplicationStatus `json:"bypassApplications,omitempty"`
	// +listType=atomic
	Ancestors []gatewayv1.PolicyAncestorStatus `json:"ancestors,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cfaa,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=Direct"
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Application",type=string,JSONPath=`.status.applicationId`

// AccessApplication attaches Cloudflare Access to Gateway API targets.
type AccessApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessApplicationSpec   `json:"spec,omitempty"`
	Status            AccessApplicationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessApplicationList contains AccessApplication objects.
type AccessApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessApplication `json:"items"`
}
