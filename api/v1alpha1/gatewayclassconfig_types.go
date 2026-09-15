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
// +kubebuilder:validation:Enum=Auto;QUIC;HTTP2
type ConnectorProtocol string

const (
	// ConnectorProtocolAuto lets cloudflared choose the transport protocol.
	ConnectorProtocolAuto ConnectorProtocol = "Auto"
	// ConnectorProtocolQUIC uses the QUIC transport protocol.
	ConnectorProtocolQUIC ConnectorProtocol = "QUIC"
	// ConnectorProtocolHTTP2 uses the HTTP/2 transport protocol.
	ConnectorProtocolHTTP2 ConnectorProtocol = "HTTP2"
)

// DNSMode controls whether Flareway manages public DNS records.
// +kubebuilder:validation:Enum=Managed;External
type DNSMode string

const (
	// DNSModeManaged lets Flareway manage public DNS records.
	DNSModeManaged DNSMode = "Managed"
	// DNSModeExternal leaves public DNS records externally managed.
	DNSModeExternal DNSMode = "External"
)

// OriginJWTMode controls the default Cloudflare Access origin JWT requirement.
// +kubebuilder:validation:Enum=Required;Disabled
type OriginJWTMode string

const (
	// OriginJWTModeRequired requires Access origin JWT validation.
	OriginJWTModeRequired OriginJWTMode = "Required"
	// OriginJWTModeDisabled disables Access origin JWT validation.
	OriginJWTModeDisabled OriginJWTMode = "Disabled"
)

// ConnectorSpec configures the cloudflared connector containers.
type ConnectorSpec struct {
	// +kubebuilder:default="cloudflare/cloudflared:2026.9.1@sha256:b269e8abd07a5bf6f3f4be65d5050b2174eca89c56a0241a8ff32a16aec454e4"
	Image string `json:"image,omitempty"`
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=25
	Replicas *int32 `json:"replicas,omitempty"`
	// +kubebuilder:default=Auto
	Protocol ConnectorProtocol `json:"protocol,omitempty"`
	// +kubebuilder:default="60s"
	GracePeriod metav1.Duration             `json:"gracePeriod,omitempty"`
	Resources   corev1.ResourceRequirements `json:"resources,omitempty"`
}

// ProxySpec configures the Envoy proxy containers.
type ProxySpec struct {
	// +kubebuilder:default="envoyproxy/envoy:distroless-v1.39.1"
	Image     string                      `json:"image,omitempty"`
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// +kubebuilder:default="1h"
	StreamIdleTimeout metav1.Duration `json:"streamIdleTimeout,omitempty"`
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Concurrency *int32 `json:"concurrency,omitempty"`
}

// PrivateDNSSpec configures the CoreDNS sidecar used by private listeners.
type PrivateDNSSpec struct {
	// +kubebuilder:default="coredns/coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
	Image     string                      `json:"image,omitempty"`
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// DNSRecordSettings configures Cloudflare DNS record IP-family behavior.
// +kubebuilder:validation:XValidation:rule="!(has(self.ipv4Only) && self.ipv4Only && has(self.ipv6Only) && self.ipv6Only)",message="ipv4Only and ipv6Only cannot both be true"
type DNSRecordSettings struct {
	IPv4Only *bool `json:"ipv4Only,omitempty"`
	IPv6Only *bool `json:"ipv6Only,omitempty"`
}

// GatewayClassDNSConfig configures DNS ownership for Gateways in a class.
// +kubebuilder:validation:XValidation:rule="!has(self.ttl) || self.ttl == 1 || (self.ttl >= 60 && self.ttl <= 86400)",message="ttl must be 1 (automatic) or between 60 and 86400 seconds"
// +kubebuilder:validation:XValidation:rule="!has(self.proxied) || !self.proxied || !has(self.ttl) || self.ttl == 1",message="proxied DNS records require automatic ttl"
// +kubebuilder:validation:XValidation:rule="!has(self.settings) || ((!has(self.settings.ipv4Only) || !self.settings.ipv4Only) && (!has(self.settings.ipv6Only) || !self.settings.ipv6Only)) || (has(self.proxied) && self.proxied)",message="ipv4Only or ipv6Only requires proxied=true"
type GatewayClassDNSConfig struct {
	// +kubebuilder:default=Managed
	Mode DNSMode `json:"mode,omitempty"`
	// +kubebuilder:default=true
	Proxied  *bool              `json:"proxied,omitempty"`
	TTL      *int64             `json:"ttl,omitempty"`
	Settings *DNSRecordSettings `json:"settings,omitempty"`
}

// GatewayClassOriginJWTConfig configures the default Access origin JWT policy.
type GatewayClassOriginJWTConfig struct {
	// +kubebuilder:default=Required
	Mode OriginJWTMode `json:"mode,omitempty"`
}

// GatewayOriginRequestSpec contains only origin settings valid for cloudflared's loopback Envoy origin.
type GatewayOriginRequestSpec struct {
	ConnectTimeout   *metav1.Duration `json:"connectTimeout,omitempty"`
	KeepAliveTimeout *metav1.Duration `json:"keepAliveTimeout,omitempty"`
	TCPKeepAlive     *metav1.Duration `json:"tcpKeepAlive,omitempty"`
	// +kubebuilder:validation:Minimum=0
	KeepAliveConnections   *int64 `json:"keepAliveConnections,omitempty"`
	NoHappyEyeballs        *bool  `json:"noHappyEyeballs,omitempty"`
	DisableChunkedEncoding *bool  `json:"disableChunkedEncoding,omitempty"`
	HTTP2Origin            *bool  `json:"http2Origin,omitempty"`
}

// ConformanceSpec configures the data-plane Service used by conformance mode.
type ConformanceSpec struct {
	// +kubebuilder:default=LoadBalancer
	// +kubebuilder:validation:Enum=LoadBalancer;ClusterIP
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// GatewayClassConfigSpec defines defaults and operating mode for a GatewayClass.
// +kubebuilder:validation:XValidation:rule="!self.conformanceMode || !has(self.accountRef)",message="accountRef must be omitted when conformanceMode is true"
// +kubebuilder:validation:XValidation:rule="self.conformanceMode || (has(self.accountRef) && has(self.accountRef.name) && size(self.accountRef.name) > 0)",message="accountRef.name is required unless conformanceMode is true"
type GatewayClassConfigSpec struct {
	AccountRef *corev1.LocalObjectReference `json:"accountRef,omitempty"`
	// +kubebuilder:default={}
	Connector ConnectorSpec `json:"connector,omitempty"`
	// +kubebuilder:default={}
	Proxy ProxySpec `json:"proxy,omitempty"`
	// +kubebuilder:default={}
	PrivateDNS PrivateDNSSpec `json:"privateDNS,omitempty"`
	// +kubebuilder:default={}
	DNS GatewayClassDNSConfig `json:"dns,omitempty"`
	// +kubebuilder:default={}
	OriginJWT GatewayClassOriginJWTConfig `json:"originJWT,omitempty"`
	// +kubebuilder:default={}
	OriginRequest GatewayOriginRequestSpec `json:"originRequest,omitempty"`
	// +kubebuilder:default=false
	ConformanceMode bool `json:"conformanceMode,omitempty"`
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
	Spec              GatewayClassConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayClassConfigList contains a list of GatewayClassConfig objects.
type GatewayClassConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClassConfig `json:"items"`
}
