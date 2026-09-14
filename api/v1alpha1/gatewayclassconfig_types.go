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
	// DefaultConnectorImage is the pinned cloudflared image used by GatewayClassConfig defaulting.
	DefaultConnectorImage = "cloudflare/cloudflared:2026.9.1@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4"
	// DefaultProxyImage is the pinned Envoy image used by GatewayClassConfig defaulting.
	DefaultProxyImage = "envoyproxy/envoy:distroless-v1.39.1"
	// DefaultPrivateDNSImage is the pinned CoreDNS image used by GatewayClassConfig defaulting.
	DefaultPrivateDNSImage = "coredns/coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
)

// ConnectorProtocol selects the transport protocol used by cloudflared.
// +kubebuilder:validation:Enum=auto;quic;http2
type ConnectorProtocol string

const (
	// ConnectorProtocolAuto lets cloudflared select the protocol.
	ConnectorProtocolAuto ConnectorProtocol = "auto"
	// ConnectorProtocolQUIC is a supported API value.
	ConnectorProtocolQUIC ConnectorProtocol = "quic"
	// ConnectorProtocolHTTP2 is a supported API value.
	ConnectorProtocolHTTP2 ConnectorProtocol = "http2"
)

// DNSMode controls whether Flareway manages public DNS records.
// +kubebuilder:validation:Enum=Managed;External
type DNSMode string

const (
	// DNSModeManaged enables managed DNS records.
	DNSModeManaged DNSMode = "Managed"
	// DNSModeExternal is a supported API value.
	DNSModeExternal DNSMode = "External"
)

// OriginJWTMode controls the default Cloudflare Access origin JWT requirement.
// +kubebuilder:validation:Enum=Required;Disabled
type OriginJWTMode string

const (
	// OriginJWTModeRequired enables origin JWT validation.
	OriginJWTModeRequired OriginJWTMode = "Required"
	// OriginJWTModeDisabled is a supported API value.
	OriginJWTModeDisabled OriginJWTMode = "Disabled"
)

// ConnectorSpec configures the cloudflared connector containers.
type ConnectorSpec struct {
	// Image is the cloudflared container image.
	// +kubebuilder:default="cloudflare/cloudflared:2026.9.1@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4"
	Image string `json:"image,omitempty"`

	// Replicas is the desired number of connector pods.
	// +kubebuilder:default=2
	Replicas *int32 `json:"replicas,omitempty"`

	// Protocol is the transport protocol used to connect to Cloudflare.
	// +kubebuilder:default=auto
	Protocol ConnectorProtocol `json:"protocol,omitempty"`

	// GracePeriod is the cloudflared shutdown grace period.
	// +kubebuilder:default="60s"
	GracePeriod metav1.Duration `json:"gracePeriod,omitempty"`

	// Resources specifies compute resources for the cloudflared container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// ProxySpec configures the Envoy proxy containers.
type ProxySpec struct {
	// Image is the Envoy container image.
	// +kubebuilder:default="envoyproxy/envoy:distroless-v1.39.1"
	Image string `json:"image,omitempty"`

	// Resources specifies compute resources for the Envoy container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// StreamIdleTimeout is the Envoy downstream stream idle timeout.
	// +kubebuilder:default="1h"
	StreamIdleTimeout metav1.Duration `json:"streamIdleTimeout,omitempty"`

	// Concurrency is the number of Envoy worker threads.
	// +kubebuilder:default=1
	Concurrency *int32 `json:"concurrency,omitempty"`
}

// PrivateDNSSpec configures the CoreDNS sidecar used by private listeners.
type PrivateDNSSpec struct {
	// Image is the CoreDNS container image.
	// +kubebuilder:default="coredns/coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
	Image string `json:"image,omitempty"`

	// Resources specifies compute resources for the CoreDNS container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayClassDNSConfig configures DNS ownership for Gateways in a class.
type GatewayClassDNSConfig struct {
	// Mode controls whether Flareway manages public DNS records.
	// +kubebuilder:default=Managed
	Mode DNSMode `json:"mode,omitempty"`
}

// GatewayClassOriginJWTConfig configures the default Access origin JWT policy.
type GatewayClassOriginJWTConfig struct {
	// Mode controls whether Access applications require origin JWT validation.
	// +kubebuilder:default=Required
	Mode OriginJWTMode `json:"mode,omitempty"`
}

// ConformanceSpec configures the data-plane Service used by conformance mode.
type ConformanceSpec struct {
	// ServiceType selects how the conformance data plane is exposed.
	// +kubebuilder:default=LoadBalancer
	// +kubebuilder:validation:Enum=LoadBalancer;ClusterIP
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// GatewayClassConfigSpec defines defaults and operating mode for a GatewayClass.
// +kubebuilder:validation:XValidation:rule="!self.conformanceMode || !has(self.accountRef)",message="accountRef must be omitted when conformanceMode is true"
type GatewayClassConfigSpec struct {
	// AccountRef is the default CloudflareAccount used by Gateways in this class.
	AccountRef *corev1.LocalObjectReference `json:"accountRef,omitempty"`

	// Connector configures cloudflared.
	// +kubebuilder:default={}
	Connector ConnectorSpec `json:"connector,omitempty"`

	// Proxy configures Envoy.
	// +kubebuilder:default={}
	Proxy ProxySpec `json:"proxy,omitempty"`

	// PrivateDNS configures the CoreDNS sidecar for private listeners.
	// +kubebuilder:default={}
	PrivateDNS PrivateDNSSpec `json:"privateDNS,omitempty"`

	// DNS configures public DNS ownership.
	// +kubebuilder:default={}
	DNS GatewayClassDNSConfig `json:"dns,omitempty"`

	// OriginJWT configures the default Access origin JWT requirement.
	// +kubebuilder:default={}
	OriginJWT GatewayClassOriginJWTConfig `json:"originJWT,omitempty"`

	// ConformanceMode disables Cloudflare integration and exposes Envoy directly.
	// +kubebuilder:default=false
	ConformanceMode bool `json:"conformanceMode,omitempty"`

	// Conformance configures the conformance-mode data plane.
	// +kubebuilder:default={}
	Conformance ConformanceSpec `json:"conformance,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=gwcc,categories=flareway
// +kubebuilder:printcolumn:name="Conformance",type=boolean,JSONPath=`.spec.conformanceMode`

// GatewayClassConfig configures defaults and conformance behavior for a GatewayClass.
type GatewayClassConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GatewayClassConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayClassConfigList contains a list of GatewayClassConfig objects.
type GatewayClassConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClassConfig `json:"items"`
}
