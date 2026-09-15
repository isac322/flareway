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
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// CloudflareTunnelFinalizer identifies the tunnel cleanup finalizer.
	CloudflareTunnelFinalizer = "flareway.bhyoo.com/tunnel"
	// CloudflareTunnelTeardownAnnotation requests tunnel teardown.
	CloudflareTunnelTeardownAnnotation = "flareway.bhyoo.com/teardown"

	// CloudflareTunnelConnectorTokenSecretKey stores the connector token.
	CloudflareTunnelConnectorTokenSecretKey = "token"
	// CloudflareTunnelManagementTokenSecretKey stores the management token.
	CloudflareTunnelManagementTokenSecretKey = "token"

	// CloudflareTunnelConditionAccepted reports whether the tunnel specification is valid.
	CloudflareTunnelConditionAccepted = "Accepted"
	// CloudflareTunnelConditionTunnelReady reports whether the remote tunnel is ready.
	CloudflareTunnelConditionTunnelReady = "TunnelReady"
	// CloudflareTunnelConditionConfigApplied reports whether tunnel configuration is applied.
	CloudflareTunnelConditionConfigApplied = "ConfigApplied"
	// CloudflareTunnelConditionDNSReady reports whether managed DNS records are ready.
	CloudflareTunnelConditionDNSReady = "DNSReady"
	// CloudflareTunnelConditionPrivateListenerDegraded reports a degraded private listener.
	CloudflareTunnelConditionPrivateListenerDegraded = "PrivateListenerDegraded"
	// CloudflareTunnelConditionReady reports whether the tunnel is ready.
	CloudflareTunnelConditionReady = "Ready"
	// CloudflareTunnelConditionCleanupBlocked reports blocked tunnel cleanup.
	CloudflareTunnelConditionCleanupBlocked = "CleanupBlocked"
	// CloudflareTunnelConditionConflict reports a remote ownership conflict.
	CloudflareTunnelConditionConflict = "Conflict"
)

// ManagementPolicy controls whether Flareway mutates a remote resource.
// +kubebuilder:validation:Enum=Managed;ObserveOnly
type ManagementPolicy string

const (
	// ManagementPolicyManaged lets Flareway manage the remote resource.
	ManagementPolicyManaged ManagementPolicy = "Managed"
	// ManagementPolicyObserveOnly prevents Flareway from mutating the remote resource.
	ManagementPolicyObserveOnly ManagementPolicy = "ObserveOnly"
)

// AdoptionMode controls explicit adoption of a remote resource.
// +kubebuilder:validation:Enum=None;AdoptById
type AdoptionMode string

const (
	// AdoptionModeNone disables adoption.
	AdoptionModeNone AdoptionMode = "None"
	// AdoptionModeAdoptByID adopts a remote resource by identifier.
	AdoptionModeAdoptByID AdoptionMode = "AdoptById"
)

// DeletionPolicy controls whether a managed remote resource is deleted or orphaned.
// +kubebuilder:validation:Enum=Delete;Orphan
type DeletionPolicy string

const (
	// DeletionPolicyDelete deletes the managed remote resource.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyOrphan leaves the managed remote resource in place.
	DeletionPolicyOrphan DeletionPolicy = "Orphan"
)

// AdoptionExpect declares remote attributes that must match before adoption.
type AdoptionExpect struct {
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	Domain string `json:"domain,omitempty"`
}

// AdoptionSpec configures explicit adoption of an existing remote object.
type AdoptionSpec struct {
	// +kubebuilder:default=None
	Mode   AdoptionMode   `json:"mode,omitempty"`
	Expect AdoptionExpect `json:"expect,omitempty"`
}

// TunnelRemoteType is the public representation of a Cloudflare tunnel type.
// +kubebuilder:validation:Enum=CloudflareTunnel;WARPConnector;WARP;Magic;IPSec;GRE;CNI
type TunnelRemoteType string

const (
	// TunnelRemoteTypeCloudflareTunnel identifies a Cloudflare Tunnel.
	TunnelRemoteTypeCloudflareTunnel TunnelRemoteType = "CloudflareTunnel"
	// TunnelRemoteTypeWARPConnector identifies a WARP Connector tunnel.
	TunnelRemoteTypeWARPConnector TunnelRemoteType = "WARPConnector"
	// TunnelRemoteTypeWARP identifies a WARP tunnel.
	TunnelRemoteTypeWARP TunnelRemoteType = "WARP"
	// TunnelRemoteTypeMagic identifies a Magic Transit tunnel.
	TunnelRemoteTypeMagic TunnelRemoteType = "Magic"
	// TunnelRemoteTypeIPSec identifies an IPsec tunnel.
	TunnelRemoteTypeIPSec TunnelRemoteType = "IPSec"
	// TunnelRemoteTypeGRE identifies a GRE tunnel.
	TunnelRemoteTypeGRE TunnelRemoteType = "GRE"
	// TunnelRemoteTypeCNI identifies a CNI tunnel.
	TunnelRemoteTypeCNI TunnelRemoteType = "CNI"
)

// TunnelConfigSource is the public representation of tunnel configuration ownership.
// +kubebuilder:validation:Enum=Local;Cloudflare
type TunnelConfigSource string

const (
	// TunnelConfigSourceLocal identifies locally managed tunnel configuration.
	TunnelConfigSourceLocal TunnelConfigSource = "Local"
	// TunnelConfigSourceCloudflare identifies remotely managed tunnel configuration.
	TunnelConfigSourceCloudflare TunnelConfigSource = "Cloudflare"
)

// CloudflareTunnelExternalReference identifies an existing Cloudflare Tunnel.
type CloudflareTunnelExternalReference struct {
	// +kubebuilder:validation:MinLength=1
	TunnelID string `json:"tunnelId"`
}

// CloudflareTunnelRemoteSpec configures the remote tunnel identity.
type CloudflareTunnelRemoteSpec struct {
	// Name defaults in the controller to "<cluster>-<namespace>-<name>".
	// +kubebuilder:validation:MaxLength=100
	Name        string                             `json:"name,omitempty"`
	ExternalRef *CloudflareTunnelExternalReference `json:"externalRef,omitempty"`
}

// CloudflareTunnelDNSConfig configures public DNS ownership.
// +kubebuilder:validation:XValidation:rule="!has(self.ttl) || self.ttl == 1 || (self.ttl >= 60 && self.ttl <= 86400)",message="ttl must be 1 (automatic) or between 60 and 86400 seconds"
// +kubebuilder:validation:XValidation:rule="!has(self.proxied) || !self.proxied || !has(self.ttl) || self.ttl == 1",message="proxied DNS records require automatic ttl"
// +kubebuilder:validation:XValidation:rule="!has(self.settings) || ((!has(self.settings.ipv4Only) || !self.settings.ipv4Only) && (!has(self.settings.ipv6Only) || !self.settings.ipv6Only)) || (has(self.proxied) && self.proxied)",message="ipv4Only or ipv6Only requires proxied=true"
type CloudflareTunnelDNSConfig struct {
	// +kubebuilder:default=Managed
	Mode DNSMode `json:"mode,omitempty"`
	// +kubebuilder:default="managed-by=flareway"
	// +kubebuilder:validation:MaxLength=100
	RecordComment string `json:"recordComment,omitempty"`
	// +kubebuilder:default=true
	Proxied  *bool              `json:"proxied,omitempty"`
	TTL      *int64             `json:"ttl,omitempty"`
	Settings *DNSRecordSettings `json:"settings,omitempty"`
}

// CloudflareTunnelHostnameRouteConfig configures automatic HostnameRoute creation.
type CloudflareTunnelHostnameRouteConfig struct {
	// +kubebuilder:default=true
	Create *bool `json:"create,omitempty"`
}

// CloudflareTunnelListener configures exposure for one Gateway listener.
type CloudflareTunnelListener struct {
	Name gatewayv1.SectionName `json:"name"`
	// +kubebuilder:default=Public
	Exposure          Exposure                     `json:"exposure,omitempty"`
	VirtualNetworkRef *corev1.LocalObjectReference `json:"virtualNetworkRef,omitempty"`
	// +kubebuilder:default={}
	HostnameRoute CloudflareTunnelHostnameRouteConfig `json:"hostnameRoute,omitempty"`
}

// CloudflareTunnelConfigurationMode selects Gateway aggregation or direct Cloudflare configuration.
// +kubebuilder:validation:Enum=Gateway;Direct
type CloudflareTunnelConfigurationMode string

const (
	// CloudflareTunnelConfigurationModeGateway derives configuration from a Gateway.
	CloudflareTunnelConfigurationModeGateway CloudflareTunnelConfigurationMode = "Gateway"
	// CloudflareTunnelConfigurationModeDirect uses the embedded direct configuration.
	CloudflareTunnelConfigurationModeDirect CloudflareTunnelConfigurationMode = "Direct"
)

// CloudflareTunnelConfiguration selects the single configuration writer for a tunnel.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'Direct' || has(self.direct)",message="Direct mode requires direct configuration"
// +kubebuilder:validation:XValidation:rule="!has(self.direct) || (has(self.mode) && self.mode == 'Direct')",message="direct configuration is only valid in Direct mode"
type CloudflareTunnelConfiguration struct {
	// +kubebuilder:default=Gateway
	Mode   CloudflareTunnelConfigurationMode    `json:"mode,omitempty"`
	Direct *CloudflareTunnelDirectConfiguration `json:"direct,omitempty"`
}

// CloudflareTunnelAddressService identifies a network origin without embedding its wire protocol.
type CloudflareTunnelAddressService struct {
	// Address is a host:port pair accepted by cloudflared.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Address string `json:"address"`
}

// CloudflareTunnelUnixService identifies a UNIX domain socket origin.
type CloudflareTunnelUnixService struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Path string `json:"path"`
}

// CloudflareTunnelHTTPStatusService configures the embedded HTTP status responder.
type CloudflareTunnelHTTPStatusService struct {
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	Code int32 `json:"code"`
}

// CloudflareTunnelBuiltinService is a marker for a parameterless cloudflared service.
type CloudflareTunnelBuiltinService struct{}

// CloudflareTunnelIngressService selects exactly one official cloudflared ingress service form.
// +kubebuilder:validation:XValidation:rule="(has(self.http)?1:0)+(has(self.https)?1:0)+(has(self.tcp)?1:0)+(has(self.ssh)?1:0)+(has(self.rdp)?1:0)+(has(self.smb)?1:0)+(has(self.unix)?1:0)+(has(self.unixTLS)?1:0)+(has(self.helloWorld)?1:0)+(has(self.httpStatus)?1:0)+(has(self.bastion)?1:0) == 1",message="exactly one ingress service must be configured"
type CloudflareTunnelIngressService struct {
	HTTP       *CloudflareTunnelAddressService    `json:"http,omitempty"`
	HTTPS      *CloudflareTunnelAddressService    `json:"https,omitempty"`
	TCP        *CloudflareTunnelAddressService    `json:"tcp,omitempty"`
	SSH        *CloudflareTunnelAddressService    `json:"ssh,omitempty"`
	RDP        *CloudflareTunnelAddressService    `json:"rdp,omitempty"`
	SMB        *CloudflareTunnelAddressService    `json:"smb,omitempty"`
	Unix       *CloudflareTunnelUnixService       `json:"unix,omitempty"`
	UnixTLS    *CloudflareTunnelUnixService       `json:"unixTLS,omitempty"`
	HelloWorld *CloudflareTunnelBuiltinService    `json:"helloWorld,omitempty"`
	HTTPStatus *CloudflareTunnelHTTPStatusService `json:"httpStatus,omitempty"`
	Bastion    *CloudflareTunnelBuiltinService    `json:"bastion,omitempty"`
}

// CloudflareTunnelOriginAccess configures Access JWT validation at cloudflared.
// +kubebuilder:validation:XValidation:rule="has(self.teamName) && size(self.teamName) > 0",message="teamName is required"
// +kubebuilder:validation:XValidation:rule="size(self.audTags) > 0",message="at least one audTag is required"
type CloudflareTunnelOriginAccess struct {
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=set
	AUDTags []string `json:"audTags"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	TeamName string `json:"teamName"`
	Required *bool  `json:"required,omitempty"`
}

// CloudflareTunnelIPRule configures one bastion or SOCKS5 source-IP rule.
type CloudflareTunnelIPRule struct {
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=49
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="prefix must be a valid IPv4 or IPv6 CIDR"
	Prefix string `json:"prefix"`
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// +listType=set
	Ports []int32 `json:"ports,omitempty"`
	Allow bool    `json:"allow"`
}

// CloudflareTunnelProxyType selects stream proxy translation behavior.
// +kubebuilder:validation:Enum=Regular;SOCKS5
type CloudflareTunnelProxyType string

const (
	// CloudflareTunnelProxyTypeRegular uses regular stream proxying.
	CloudflareTunnelProxyTypeRegular CloudflareTunnelProxyType = "Regular"
	// CloudflareTunnelProxyTypeSOCKS5 uses SOCKS5 proxying.
	CloudflareTunnelProxyTypeSOCKS5 CloudflareTunnelProxyType = "SOCKS5"
)

// CloudflareTunnelOriginRequest is the complete remotely configurable cloudflared origin policy.
type CloudflareTunnelOriginRequest struct {
	Access *CloudflareTunnelOriginAccess `json:"access,omitempty"`
	CAPool *string                       `json:"caPool,omitempty"`
	// +kubebuilder:validation:Minimum=0
	ConnectTimeout         *int64  `json:"connectTimeout,omitempty"`
	DisableChunkedEncoding *bool   `json:"disableChunkedEncoding,omitempty"`
	HTTP2Origin            *bool   `json:"http2Origin,omitempty"`
	HTTPHostHeader         *string `json:"httpHostHeader,omitempty"`
	// +kubebuilder:validation:Minimum=0
	KeepAliveConnections *int64 `json:"keepAliveConnections,omitempty"`
	// +kubebuilder:validation:Minimum=0
	KeepAliveTimeout *int64                     `json:"keepAliveTimeout,omitempty"`
	MatchSNIToHost   *bool                      `json:"matchSNIToHost,omitempty"`
	NoHappyEyeballs  *bool                      `json:"noHappyEyeballs,omitempty"`
	NoTLSVerify      *bool                      `json:"noTLSVerify,omitempty"`
	OriginServerName *string                    `json:"originServerName,omitempty"`
	ProxyType        *CloudflareTunnelProxyType `json:"proxyType,omitempty"`
	// +kubebuilder:validation:Minimum=0
	TCPKeepAlive *int64 `json:"tcpKeepAlive,omitempty"`
	// +kubebuilder:validation:Minimum=0
	TLSTimeout *int64 `json:"tlsTimeout,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	IPRules []CloudflareTunnelIPRule `json:"ipRules,omitempty"`
}

// CloudflareTunnelWARPRouting configures private-network origin dialing.
type CloudflareTunnelWARPRouting struct {
	Enabled *bool `json:"enabled,omitempty"`
	// +kubebuilder:validation:Minimum=0
	ConnectTimeout *int64 `json:"connectTimeout,omitempty"`
	// +kubebuilder:validation:Minimum=0
	TCPKeepAlive *int64 `json:"tcpKeepAlive,omitempty"`
	// +kubebuilder:validation:Minimum=0
	MaxActiveFlows *int64 `json:"maxActiveFlows,omitempty"`
}

// CloudflareTunnelIngressRule is one ordered direct-mode ingress rule.
// +kubebuilder:validation:XValidation:rule="!has(self.originRequest) || !has(self.originRequest.access) || has(self.service.http) || has(self.service.https) || has(self.service.unix) || has(self.service.unixTLS)",message="originRequest.access is only valid for HTTP origins"
// +kubebuilder:validation:XValidation:rule="!has(self.originRequest) || size(self.originRequest.ipRules) == 0 || has(self.service.bastion) || (has(self.originRequest.proxyType) && self.originRequest.proxyType == 'SOCKS5')",message="originRequest.ipRules requires Bastion or SOCKS5 proxy service"
type CloudflareTunnelIngressRule struct {
	// Hostname may be omitted only for the final catch-all rule.
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname,omitempty"`
	// Path is a Go regular expression evaluated by cloudflared.
	// +kubebuilder:validation:MaxLength=2048
	Path          string                         `json:"path,omitempty"`
	Service       CloudflareTunnelIngressService `json:"service"`
	OriginRequest *CloudflareTunnelOriginRequest `json:"originRequest,omitempty"`
}

// CloudflareTunnelDirectConfiguration is the whole-object configuration owned by Direct mode.
// +kubebuilder:validation:XValidation:rule="(!has(self.ingress[size(self.ingress)-1].hostname) || size(self.ingress[size(self.ingress)-1].hostname) == 0) && (!has(self.ingress[size(self.ingress)-1].path) || size(self.ingress[size(self.ingress)-1].path) == 0)",message="the final ingress rule must be a catch-all"
type CloudflareTunnelDirectConfiguration struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=200
	// +listType=atomic
	Ingress       []CloudflareTunnelIngressRule  `json:"ingress"`
	OriginRequest *CloudflareTunnelOriginRequest `json:"originRequest,omitempty"`
	WARPRouting   *CloudflareTunnelWARPRouting   `json:"warpRouting,omitempty"`
}

// CloudflareTunnelManagementResource selects a short-lived management-token capability.
// +kubebuilder:validation:Enum=Logs
type CloudflareTunnelManagementResource string

const (
	// CloudflareTunnelManagementResourceLogs grants access to tunnel logs.
	CloudflareTunnelManagementResourceLogs CloudflareTunnelManagementResource = "Logs"
)

// CloudflareTunnelManagementTokenRequest requests an owned Secret containing a short-lived token.
type CloudflareTunnelManagementTokenRequest struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	// +listType=set
	Resources []CloudflareTunnelManagementResource `json:"resources"`
}

// CloudflareTunnelSpec defines remote ownership and connector configuration.
// +kubebuilder:validation:XValidation:rule="self.managementPolicy != 'ObserveOnly' || has(self.tunnel.externalRef)",message="ObserveOnly requires tunnel.externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || has(self.tunnel.externalRef)",message="AdoptById requires tunnel.externalRef"
// +kubebuilder:validation:XValidation:rule="self.adoption.mode != 'AdoptById' || (has(self.adoption.expect) && has(self.adoption.expect.name) && size(self.adoption.expect.name) > 0)",message="AdoptById requires adoption.expect.name"
// +kubebuilder:validation:XValidation:rule="!has(self.tunnel.externalRef) || self.managementPolicy == 'ObserveOnly' || self.adoption.mode == 'AdoptById'",message="Managed externalRef requires adoption.mode AdoptById"
// +kubebuilder:validation:XValidation:rule="has(self.accountRef.name) && size(self.accountRef.name) > 0",message="accountRef.name is required"
// +kubebuilder:validation:XValidation:rule="!has(self.configuration.mode) || self.configuration.mode != 'Direct' || (!has(self.connector) && !has(self.proxy) && !has(self.privateDNS) && !has(self.originRequest) && (!has(self.listeners) || size(self.listeners) == 0))",message="Direct mode cannot use Gateway connector, proxy, privateDNS, originRequest, or listeners"
type CloudflareTunnelSpec struct {
	AccountRef corev1.LocalObjectReference `json:"accountRef"`
	// +kubebuilder:default={}
	Tunnel CloudflareTunnelRemoteSpec `json:"tunnel,omitempty"`
	// +kubebuilder:default=Managed
	ManagementPolicy ManagementPolicy `json:"managementPolicy,omitempty"`
	// +kubebuilder:default={}
	Adoption AdoptionSpec `json:"adoption,omitempty"`
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +kubebuilder:default={}
	Configuration CloudflareTunnelConfiguration `json:"configuration,omitempty"`
	// Gateway-mode overrides.
	Connector     *ConnectorSpec            `json:"connector,omitempty"`
	Proxy         *ProxySpec                `json:"proxy,omitempty"`
	PrivateDNS    *PrivateDNSSpec           `json:"privateDNS,omitempty"`
	OriginRequest *GatewayOriginRequestSpec `json:"originRequest,omitempty"`
	// DNS applies to hostnames owned by either configuration mode.
	// +kubebuilder:default={}
	DNS CloudflareTunnelDNSConfig `json:"dns,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Listeners       []CloudflareTunnelListener              `json:"listeners,omitempty"`
	ManagementToken *CloudflareTunnelManagementTokenRequest `json:"managementToken,omitempty"`
}

// ConnectorState is the public representation of observed tunnel health.
// +kubebuilder:validation:Enum=Healthy;Degraded;Down;Inactive
type ConnectorState string

const (
	// ConnectorStateHealthy reports a healthy connector.
	ConnectorStateHealthy ConnectorState = "Healthy"
	// ConnectorStateDegraded reports a degraded connector.
	ConnectorStateDegraded ConnectorState = "Degraded"
	// ConnectorStateDown reports an unavailable connector.
	ConnectorStateDown ConnectorState = "Down"
	// ConnectorStateInactive reports an inactive connector.
	ConnectorStateInactive ConnectorState = "Inactive"
)

// CloudflareTunnelConfigVersion records desired and observed whole-object configuration versions.
type CloudflareTunnelConfigVersion struct {
	Desired     int64        `json:"desired,omitempty"`
	DesiredHash string       `json:"desiredHash,omitempty"`
	Applied     int64        `json:"applied,omitempty"`
	Remote      int64        `json:"remote,omitempty"`
	CreatedAt   *metav1.Time `json:"createdAt,omitempty"`
}

// CloudflareTunnelConnectionStatus records one edge connection.
type CloudflareTunnelConnectionStatus struct {
	// +kubebuilder:validation:MinLength=1
	ID            string       `json:"id"`
	ClientID      string       `json:"clientId,omitempty"`
	ClientVersion string       `json:"clientVersion,omitempty"`
	ColoName      string       `json:"coloName,omitempty"`
	OpenedAt      *metav1.Time `json:"openedAt,omitempty"`
	OriginIP      string       `json:"originIp,omitempty"`
	UUID          string       `json:"uuid,omitempty"`
}

// CloudflareTunnelClientStatus records one bounded cloudflared client observation.
type CloudflareTunnelClientStatus struct {
	ID            string `json:"id"`
	Arch          string `json:"arch,omitempty"`
	ConfigVersion int64  `json:"configVersion,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=128
	// +listType=set
	Features []string     `json:"features,omitempty"`
	RunAt    *metav1.Time `json:"runAt,omitempty"`
	Version  string       `json:"version,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=id
	Connections []CloudflareTunnelConnectionStatus `json:"connections,omitempty"`
}

// HostnameGuard records the fail-closed state applied to a public hostname.
// +kubebuilder:validation:Enum=Forwarding;Blocked;Unprotected
type HostnameGuard string

const (
	// HostnameGuardForwarding allows traffic to reach the origin.
	HostnameGuardForwarding HostnameGuard = "Forwarding"
	// HostnameGuardBlocked prevents traffic from reaching the origin.
	HostnameGuardBlocked HostnameGuard = "Blocked"
	// HostnameGuardUnprotected reports a hostname without Access protection.
	HostnameGuardUnprotected HostnameGuard = "Unprotected"
)

// CloudflareTunnelHostnameStatus is owned by the gateway field manager.
type CloudflareTunnelHostnameStatus struct {
	Hostname          string        `json:"hostname"`
	ProtectionDomain  string        `json:"protectionDomain"`
	AccessApplication string        `json:"accessApplication"`
	Guard             HostnameGuard `json:"guard"`
	AppliedVersion    int64         `json:"appliedVersion,omitempty"`
}

// CloudflareTunnelDNSRecordStatus records a bounded projection of one managed DNS record.
type CloudflareTunnelDNSRecordStatus struct {
	Hostname string `json:"hostname"`
	RecordID string `json:"recordId"`
	ZoneID   string `json:"zoneId"`
	// OwnershipComment checkpoints the exact comment written when this record was owned.
	// +kubebuilder:validation:MaxLength=100
	OwnershipComment  string             `json:"ownershipComment,omitempty"`
	State             string             `json:"state,omitempty"`
	TTL               int64              `json:"ttl,omitempty"`
	Proxied           *bool              `json:"proxied,omitempty"`
	Proxiable         *bool              `json:"proxiable,omitempty"`
	Settings          *DNSRecordSettings `json:"settings,omitempty"`
	CreatedOn         *metav1.Time       `json:"createdOn,omitempty"`
	ModifiedOn        *metav1.Time       `json:"modifiedOn,omitempty"`
	CommentModifiedOn *metav1.Time       `json:"commentModifiedOn,omitempty"`
}

// ListenerBinding identifies the private Envoy listener binding strategy.
// +kubebuilder:validation:Enum=Loopback;PodIP
type ListenerBinding string

const (
	// ListenerBindingLoopback binds the private listener to loopback.
	ListenerBindingLoopback ListenerBinding = "Loopback"
	// ListenerBindingPodIP binds the private listener to the Pod IP.
	ListenerBindingPodIP ListenerBinding = "PodIP"
)

// CloudflareProtectionDomainStatus records one Envoy protection domain.
type CloudflareProtectionDomainStatus struct {
	Name      string `json:"name"`
	EnvoyPort int32  `json:"envoyPort"`
	Protected bool   `json:"protected"`
}

// CloudflareTunnelListenerStatus is owned by the gateway field manager.
type CloudflareTunnelListenerStatus struct {
	Name     gatewayv1.SectionName `json:"name"`
	Exposure Exposure              `json:"exposure"`
	Binding  ListenerBinding       `json:"binding,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	ProtectionDomains []CloudflareProtectionDomainStatus `json:"protectionDomains,omitempty"`
}

// CloudflareTunnelStatus contains bounded remote observations and disjoint controller-owned fields.
type CloudflareTunnelStatus struct {
	TunnelID                 string                       `json:"tunnelId,omitempty"`
	AccountID                string                       `json:"accountId,omitempty"`
	Name                     string                       `json:"name,omitempty"`
	TunnelType               TunnelRemoteType             `json:"tunnelType,omitempty"`
	ConfigSource             TunnelConfigSource           `json:"configSource,omitempty"`
	ConnectorState           ConnectorState               `json:"connectorState,omitempty"`
	CreatedAt                *metav1.Time                 `json:"createdAt,omitempty"`
	DeletedAt                *metav1.Time                 `json:"deletedAt,omitempty"`
	ConnectionsActiveAt      *metav1.Time                 `json:"connectionsActiveAt,omitempty"`
	ConnectionsInactiveAt    *metav1.Time                 `json:"connectionsInactiveAt,omitempty"`
	OrphanedTunnelID         string                       `json:"orphanedTunnelId,omitempty"`
	OwnershipVerified        bool                         `json:"ownershipVerified,omitempty"`
	ObservedGeneration       int64                        `json:"observedGeneration,omitempty"`
	ConnectorTokenSecretRef  *corev1.LocalObjectReference `json:"connectorTokenSecretRef,omitempty"`
	ManagementTokenSecretRef *corev1.LocalObjectReference `json:"managementTokenSecretRef,omitempty"`
	// +kubebuilder:validation:MaxItems=25
	// +listType=map
	// +listMapKey=id
	Clients []CloudflareTunnelClientStatus `json:"clients,omitempty"`
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Addresses []gatewayv1.GatewayStatusAddress `json:"addresses,omitempty"`
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=hostname
	DNSRecords []CloudflareTunnelDNSRecordStatus `json:"dnsRecords,omitempty"`
	// GatewayRef names the Gateway selected by the Tunnel controller.
	GatewayRef *corev1.LocalObjectReference `json:"gatewayRef,omitempty"`
	// GatewayUID binds GatewayRef to one exact live Kubernetes object.
	GatewayUID    types.UID                     `json:"gatewayUid,omitempty"`
	ConfigVersion CloudflareTunnelConfigVersion `json:"configVersion,omitempty"`
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=hostname
	// +listMapKey=protectionDomain
	// +listMapKey=accessApplication
	Hostnames []CloudflareTunnelHostnameStatus `json:"hostnames,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Listeners []CloudflareTunnelListenerStatus `json:"listeners,omitempty"`
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cft,categories=flareway
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tunnel",type=string,JSONPath=`.status.tunnelId`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.status.gatewayRef.name`

// CloudflareTunnel represents one remotely managed Cloudflare Tunnel and its Gateway data plane.
type CloudflareTunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CloudflareTunnelSpec   `json:"spec,omitempty"`
	Status            CloudflareTunnelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CloudflareTunnelList contains CloudflareTunnel objects.
type CloudflareTunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudflareTunnel `json:"items"`
}
