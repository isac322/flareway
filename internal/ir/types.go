/*
Copyright 2026 The Flareway Authors.

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

// Package ir contains the deterministic, Kubernetes-client-independent model
// consumed by the Envoy and dataplane translators.
package ir

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// Constants define the stable values used in the intermediate representation.
const (
	ExposurePublic  = "Public"
	ExposurePrivate = "Private"

	GuardForwarding  = "Forwarding"
	GuardBlocked     = "Blocked"
	GuardUnprotected = "Unprotected"

	ListenerBindingLoopback = "Loopback"
	ListenerBindingPodIP    = "PodIP"

	PathMatchExact             = "Exact"
	PathMatchRegularExpression = "RegularExpression"
	PathMatchPathPrefix        = "PathPrefix"

	StringMatchExact             = "Exact"
	StringMatchRegularExpression = "RegularExpression"

	PathModifierReplaceFullPath    = "ReplaceFullPath"
	PathModifierReplacePrefixMatch = "ReplacePrefixMatch"
)

// Gateway is the complete desired data-plane configuration for one Gateway.
type Gateway struct {
	Key                       types.NamespacedName `json:"key"`
	UID                       types.UID            `json:"uid"`
	ConformanceMode           bool                 `json:"conformanceMode"`
	InfrastructureLabels      map[string]string    `json:"infrastructureLabels,omitempty"`
	InfrastructureAnnotations map[string]string    `json:"infrastructureAnnotations,omitempty"`
	Cloudflare                *Cloudflare          `json:"cloudflare,omitempty"`
	Listeners                 []Listener           `json:"listeners,omitempty"`
	Domains                   []ProtectionDomain   `json:"domains,omitempty"`
	Clusters                  []Cluster            `json:"clusters,omitempty"`
	Secrets                   []TLSSecret          `json:"secrets,omitempty"`
}

// Cloudflare identifies the remotely managed tunnel used by a production
// Gateway. It is absent in conformance mode.
type Cloudflare struct {
	AccountID        string `json:"accountId"`
	TunnelName       string `json:"tunnelName"`
	TunnelID         string `json:"tunnelId,omitempty"`
	TokenSecretName  string `json:"tokenSecretName"`
	ManagementPolicy string `json:"managementPolicy"`
	Teardown         bool   `json:"teardown,omitempty"`
	WARPRouting      bool   `json:"warpRouting,omitempty"`
}

// Listener describes a Gateway listener and its actual Envoy bind port.
type Listener struct {
	Name      string  `json:"name"`
	Hostname  string  `json:"hostname,omitempty"`
	Port      int32   `json:"port"`
	EnvoyPort int32   `json:"envoyPort"`
	Protocol  string  `json:"protocol"`
	Exposure  string  `json:"exposure"`
	Binding   string  `json:"binding,omitempty"`
	TLS       *TLSRef `json:"tls,omitempty"`
}

// TLSRef names a TLSSecret in Gateway.Secrets.
type TLSRef struct {
	Secret string `json:"secret"`
}

// ProtectionDomain is an independently isolated Envoy listener/route table.
type ProtectionDomain struct {
	Name               string        `json:"name"`
	ListenerName       string        `json:"listenerName"`
	EnvoyPort          int32         `json:"envoyPort"`
	Protected          bool          `json:"protected"`
	OriginJWTDisabled  bool          `json:"originJWTDisabled,omitempty"`
	Access             *AccessGuard  `json:"access,omitempty"`
	AccessApplication  string        `json:"accessApplication,omitempty"`
	Guard              string        `json:"guard,omitempty"`
	StripAccessHeaders bool          `json:"stripAccessHeaders,omitempty"`
	IngressPaths       []PathMatch   `json:"ingressPaths,omitempty"`
	VirtualHosts       []VirtualHost `json:"virtualHosts,omitempty"`
}

// AccessGuard describes Cloudflare Access JWT enforcement for a domain.
type AccessGuard struct {
	AUD                    string `json:"aud"`
	TeamName               string `json:"teamName"`
	AuthDomain             string `json:"authDomain"`
	OptionsPreflightBypass bool   `json:"optionsPreflightBypass"`
}

// VirtualHost is an Envoy virtual host. Routes are already precedence-sorted.
type VirtualHost struct {
	Name     string  `json:"name"`
	Hostname string  `json:"hostname"`
	Routes   []Route `json:"routes,omitempty"`
}

// Route is one precedence-sorted HTTP route compiled from a Gateway API rule match.
type Route struct {
	Name     string        `json:"name"`
	Source   RouteSource   `json:"-"`
	Match    PathMatch     `json:"match"`
	Headers  []HeaderMatch `json:"headers,omitempty"`
	Query    []QueryMatch  `json:"query,omitempty"`
	Method   *string       `json:"method,omitempty"`
	Filters  Filters       `json:"filters,omitempty"`
	Backends []BackendRef  `json:"backends,omitempty"`
	Timeouts Timeouts      `json:"timeouts,omitempty"`
	Invalid  *Reason       `json:"invalid,omitempty"`
}

// RouteSource identifies the HTTPRoute rule that produced a flattened route.
// It lets access policy compilation partition routes without parsing generated
// xDS resource names.
type RouteSource struct {
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name,omitempty"`
	RuleName     string `json:"ruleName,omitempty"`
	RuleIndex    int    `json:"ruleIndex,omitempty"`
	MatchIndex   int    `json:"matchIndex,omitempty"`
	PathExplicit bool   `json:"pathExplicit,omitempty"`
}

// PathMatch is an Exact, RegularExpression, or PathPrefix matcher.
type PathMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// HeaderMatch matches one HTTP header.
type HeaderMatch struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// QueryMatch matches one query parameter.
type QueryMatch struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Filters contains all supported rule-level HTTPRoute filters.
type Filters struct {
	RequestHeaders  *HeaderModifier `json:"requestHeaders,omitempty"`
	ResponseHeaders *HeaderModifier `json:"responseHeaders,omitempty"`
	Redirect        *Redirect       `json:"redirect,omitempty"`
	URLRewrite      *URLRewrite     `json:"urlRewrite,omitempty"`
	Mirrors         []Mirror        `json:"mirrors,omitempty"`
	CORS            *CORS           `json:"cors,omitempty"`
}

// HeaderModifier is a deterministic representation of an HTTP header filter.
type HeaderModifier struct {
	Set    []HeaderValue `json:"set,omitempty"`
	Add    []HeaderValue `json:"add,omitempty"`
	Remove []string      `json:"remove,omitempty"`
}

// HeaderValue is a header name/value pair.
type HeaderValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Redirect describes a direct HTTP redirect response.
type Redirect struct {
	Scheme     string        `json:"scheme,omitempty"`
	Hostname   string        `json:"hostname,omitempty"`
	Port       *int32        `json:"port,omitempty"`
	StatusCode int           `json:"statusCode"`
	Path       *PathModifier `json:"path,omitempty"`
}

// URLRewrite describes host and path rewriting before proxying.
type URLRewrite struct {
	Hostname string        `json:"hostname,omitempty"`
	Path     *PathModifier `json:"path,omitempty"`
}

// PathModifier is a full-path or prefix replacement.
type PathModifier struct {
	Type    string `json:"type"`
	Replace string `json:"replace"`
}

// Mirror describes a request mirror destination and percentage.
type Mirror struct {
	Backend BackendRef `json:"backend"`
	Percent float64    `json:"percent"`
}

// CORS is the consumer-observable CORS policy attached to a route.
type CORS struct {
	AllowOrigins     []string `json:"allowOrigins,omitempty"`
	AllowMethods     []string `json:"allowMethods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	MaxAge           *int32   `json:"maxAge,omitempty"`
	AllowCredentials bool     `json:"allowCredentials,omitempty"`
}

// BackendRef is one weighted route or mirror backend. Invalid backends remain
// present with their original weight so the xDS translator can preserve the
// proportional 500 response required by Gateway API.
type BackendRef struct {
	Name        string         `json:"name"`
	Namespace   string         `json:"namespace"`
	ClusterName string         `json:"clusterName,omitempty"`
	Port        int32          `json:"port"`
	Weight      int32          `json:"weight"`
	Filters     BackendFilters `json:"filters,omitempty"`
	Invalid     *Reason        `json:"invalid,omitempty"`
}

// BackendFilters contains the filter types Gateway API permits per backend.
type BackendFilters struct {
	RequestHeaders  *HeaderModifier `json:"requestHeaders,omitempty"`
	ResponseHeaders *HeaderModifier `json:"responseHeaders,omitempty"`
	URLRewrite      *URLRewrite     `json:"urlRewrite,omitempty"`
}

// Timeouts retains distinct request and backend request limits. A pointer to
// zero is meaningful and represents an explicitly disabled timeout.
type Timeouts struct {
	Request        *time.Duration `json:"request,omitempty"`
	BackendRequest *time.Duration `json:"backendRequest,omitempty"`
}

// Cluster describes a Kubernetes Service backend and its ready endpoints.
type Cluster struct {
	Name        string      `json:"name"`
	Namespace   string      `json:"namespace"`
	Service     string      `json:"service"`
	Port        int32       `json:"port"`
	AppProtocol string      `json:"appProtocol,omitempty"`
	Endpoints   []Endpoint  `json:"endpoints,omitempty"`
	TLS         *BackendTLS `json:"tls,omitempty"`
}

// Endpoint is a ready EndpointSlice address and resolved port.
type Endpoint struct {
	Address string `json:"address"`
	Port    int32  `json:"port"`
}

// BackendTLS describes BackendTLSPolicy validation for a Cluster.
type BackendTLS struct {
	ServerName              string           `json:"serverName"`
	CACertificate           []byte           `json:"caCertificate,omitempty"`
	WellKnownCACertificates string           `json:"wellKnownCACertificates,omitempty"`
	SubjectAltNames         []SubjectAltName `json:"subjectAltNames,omitempty"`
}

// SubjectAltName is a typed DNS hostname or URI certificate identity.
type SubjectAltName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// TLSSecret contains material needed by an Envoy listener or validation context.
type TLSSecret struct {
	Name        string `json:"name"`
	Certificate []byte `json:"certificate,omitempty"`
	PrivateKey  []byte `json:"privateKey,omitempty"`
	CA          []byte `json:"ca,omitempty"`
}

// Reason records why a route or backend must return an error response.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
