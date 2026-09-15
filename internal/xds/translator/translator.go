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

// Package translator compiles the pure Flareway IR into an internally
// consistent Envoy v3 Delta xDS snapshot.
package translator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

const (
	jwtFilterName    = "envoy.filters.http.jwt_authn"
	routerFilterName = "envoy.filters.http.router"
	hcmFilterName    = "envoy.filters.network.http_connection_manager"
)

type routeGroup struct {
	key                string
	routeName          string
	address            string
	port               int32
	tlsSecret          string
	serverNames        []string
	access             *ir.AccessGuard
	protected          bool
	guard              string
	stripAccessHeaders bool
	virtualHosts       []ir.VirtualHost
	virtualHostIndex   map[string]int
}

// Build compiles gw into Listener, RouteConfiguration, Cluster,
// ClusterLoadAssignment, and Secret resources. Every resource type uses the
// same deterministic version, and the returned snapshot has a Delta version
// map ready for SnapshotCache publication.
func Build(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (*cachev3.Snapshot, error) {
	if gw == nil {
		return nil, errors.New("IR Gateway is nil")
	}
	gw = canonicalGateway(gw)
	streamIdleTimeout := time.Hour
	if cfg != nil && cfg.Spec.Proxy.StreamIdleTimeout.Duration != 0 {
		streamIdleTimeout = cfg.Spec.Proxy.StreamIdleTimeout.Duration
	}

	listenersByName := make(map[string]ir.Listener, len(gw.Listeners))
	for _, listener := range gw.Listeners {
		listenersByName[listener.Name] = listener
	}
	groups, err := groupDomains(gw, listenersByName)
	if err != nil {
		return nil, err
	}

	listeners, routes, jwksClusters, err := buildListeners(groups, streamIdleTimeout)
	if err != nil {
		return nil, err
	}
	clusters := make([]*clusterv3.Cluster, 0, len(gw.Clusters)+len(jwksClusters))
	assignments := make([]*endpointv3.ClusterLoadAssignment, 0, len(gw.Clusters))
	for _, cluster := range gw.Clusters {
		translated, assignment, err := buildCluster(cluster)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, translated)
		assignments = append(assignments, assignment)
	}
	clusters = append(clusters, jwksClusters...)

	secretInputs := make(map[string]ir.TLSSecret, len(gw.Secrets))
	for _, secret := range gw.Secrets {
		if _, exists := secretInputs[secret.Name]; exists {
			return nil, fmt.Errorf("duplicate TLS secret %q", secret.Name)
		}
		secretInputs[secret.Name] = secret
	}
	referencedSecrets := make(map[string]struct{})
	for _, group := range groups {
		if group.tlsSecret != "" {
			referencedSecrets[group.tlsSecret] = struct{}{}
		}
	}
	secrets := make([]*tlsv3.Secret, 0, len(referencedSecrets))
	for name := range referencedSecrets {
		secret, ok := secretInputs[name]
		if !ok {
			return nil, fmt.Errorf("listener TLS secret %q is missing from IR", name)
		}
		translated, err := buildSecret(secret)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, translated)
	}

	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Name < listeners[j].Name })
	sort.Slice(routes, func(i, j int) bool { return routes[i].Name < routes[j].Name })
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].ClusterName < assignments[j].ClusterName })
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })

	version, err := desiredVersion(gw, streamIdleTimeout)
	if err != nil {
		return nil, err
	}
	resources := map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: toResources(listeners),
		resourcev3.RouteType:    toResources(routes),
		resourcev3.ClusterType:  toResources(clusters),
		resourcev3.EndpointType: toResources(assignments),
		resourcev3.SecretType:   toResources(secrets),
	}
	snapshot, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return nil, fmt.Errorf("create xDS snapshot: %w", err)
	}
	if err := snapshot.Consistent(); err != nil {
		return nil, fmt.Errorf("create consistent xDS snapshot: %w", err)
	}
	if err := snapshot.ConstructVersionMap(); err != nil {
		return nil, fmt.Errorf("construct Delta xDS version map: %w", err)
	}
	return snapshot, nil
}

// SnapshotVersion returns the single version shared by every resource type.
// Empty desired configurations are valid and retain their deterministic
// version on the empty Listener resource set.
func SnapshotVersion(snapshot *cachev3.Snapshot) (string, error) {
	if snapshot == nil {
		return "", errors.New("snapshot is nil")
	}
	version := snapshot.GetVersion(resourcev3.ListenerType)
	if version == "" {
		return "", errors.New("snapshot has no version")
	}
	for _, typeURL := range []resourcev3.Type{
		resourcev3.RouteType,
		resourcev3.ClusterType,
		resourcev3.EndpointType,
		resourcev3.SecretType,
	} {
		current := snapshot.GetVersion(typeURL)
		if current != "" && current != version {
			return "", fmt.Errorf("snapshot resource versions differ: %q and %q", version, current)
		}
	}
	return version, nil
}

func groupDomains(gw *ir.Gateway, listeners map[string]ir.Listener) ([]routeGroup, error) {
	byKey := make(map[string]*routeGroup)
	for _, domain := range gw.Domains {
		listener, ok := listeners[domain.ListenerName]
		if !ok {
			if domain.Guard == ir.GuardBlocked {
				continue
			}
			return nil, fmt.Errorf("protection domain %q references unknown listener %q", domain.Name, domain.ListenerName)
		}
		if domain.Protected && !domain.OriginJWTDisabled && domain.Guard != ir.GuardBlocked &&
			(domain.Access == nil || len(domain.Access.AUDs) == 0) {
			return nil, fmt.Errorf("protection domain %q requires at least one Access audience", domain.Name)
		}
		port := domain.EnvoyPort
		if listener.Exposure == ir.ExposurePrivate {
			port = listener.Port
		} else if port == 0 {
			port = listener.EnvoyPort
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("protection domain %q has invalid Envoy port %d", domain.Name, port)
		}
		address := "127.0.0.1"
		if gw.ConformanceMode || (listener.Exposure == ir.ExposurePrivate && listener.Binding == ir.ListenerBindingPodIP) {
			address = "0.0.0.0"
		}
		tlsSecret := ""
		if listener.TLS != nil {
			tlsSecret = listener.TLS.Secret
		}
		accessKey, err := json.Marshal(domain.Access)
		if err != nil {
			return nil, fmt.Errorf("marshal access guard: %w", err)
		}
		bindAddress := net.JoinHostPort(address, strconv.Itoa(int(port)))
		isolationKey := ""
		if tlsSecret != "" {
			isolationKey = listener.Name
		}
		key := bindAddress + "|" + tlsSecret + "|" + isolationKey + "|" + string(accessKey) + "|" + strconv.FormatBool(domain.Protected) + "|" + domain.Guard + "|" + strconv.FormatBool(domain.StripAccessHeaders)
		group := byKey[key]
		if group == nil {
			group = &routeGroup{
				key:                key,
				routeName:          resourceName(domain.Name, "routes"),
				address:            address,
				port:               port,
				tlsSecret:          tlsSecret,
				access:             domain.Access,
				protected:          domain.Protected,
				guard:              domain.Guard,
				stripAccessHeaders: domain.StripAccessHeaders,
				virtualHostIndex:   make(map[string]int),
			}
			byKey[key] = group
		}
		if listener.Hostname != "" {
			group.serverNames = appendUnique(group.serverNames, listener.Hostname)
		}
		mergeVirtualHosts(group, domain.VirtualHosts)
	}

	groups := make([]routeGroup, 0, len(byKey))
	for _, group := range byKey {
		sort.Strings(group.serverNames)
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].key < groups[j].key })
	return groups, nil
}

func buildListeners(groups []routeGroup, streamIdleTimeout time.Duration) ([]*listenerv3.Listener, []*routev3.RouteConfiguration, []*clusterv3.Cluster, error) {
	listenersByBind := make(map[string]*listenerv3.Listener)
	cleartextChains := make(map[string]bool)
	tlsNames := make(map[string]map[string]struct{})
	routes := make([]*routev3.RouteConfiguration, 0, len(groups))
	jwksByHost := make(map[string]*clusterv3.Cluster)

	for _, group := range groups {
		routeConfig := &routev3.RouteConfiguration{
			Name:                     group.routeName,
			IgnorePortInHostMatching: true,
		}
		misdirectedNames, misdirectedCatchAll := otherTLSClaims(group, groups)
		blockedDomains := make(map[string]struct{}, len(misdirectedNames)+1)
		for _, hostname := range misdirectedNames {
			blockedDomains[hostname] = struct{}{}
		}
		if misdirectedCatchAll {
			blockedDomains["*"] = struct{}{}
		}
		for _, virtualHost := range group.virtualHosts {
			hostname := virtualHost.Hostname
			if hostname == "" {
				hostname = "*"
			}
			if _, blocked := blockedDomains[hostname]; blocked {
				continue
			}
			translated, err := buildDomainVirtualHost(virtualHost, group.guard, group.stripAccessHeaders)
			if err != nil {
				return nil, nil, nil, err
			}
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, translated)
		}
		for _, hostname := range protectedExactClaims(group, groups) {
			if _, alreadyClaimed := group.virtualHostIndex[hostname]; alreadyClaimed {
				continue
			}
			blocked, err := buildDomainVirtualHost(ir.VirtualHost{
				Name: resourceName("protected-"+hostname, "protected-host"), Hostname: hostname,
			}, ir.GuardBlocked, true)
			if err != nil {
				return nil, nil, nil, err
			}
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, blocked)
		}
		for _, hostname := range misdirectedNames {
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, misdirectedVirtualHost(hostname))
		}
		if misdirectedCatchAll {
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, misdirectedVirtualHost("*"))
		}
		routes = append(routes, routeConfig)

		filters, jwksHost, jwksName, err := buildHTTPFilters(group.access)
		if err != nil {
			return nil, nil, nil, err
		}
		if jwksHost != "" {
			if _, ok := jwksByHost[jwksHost]; !ok {
				cluster, err := buildJWKCluster(jwksHost, jwksName)
				if err != nil {
					return nil, nil, nil, err
				}
				jwksByHost[jwksHost] = cluster
			}
		}

		hcm := &hcmv3.HttpConnectionManager{
			StatPrefix: resourceName(group.routeName, "hcm"),
			RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{Rds: &hcmv3.Rds{
				ConfigSource:    adsConfigSource(),
				RouteConfigName: group.routeName,
			}},
			HttpFilters:                  filters,
			CommonHttpProtocolOptions:    &corev3.HttpProtocolOptions{IdleTimeout: durationpb.New(120 * time.Second)},
			StreamIdleTimeout:            durationpb.New(streamIdleTimeout),
			NormalizePath:                wrapperspb.Bool(true),
			MergeSlashes:                 true,
			PathWithEscapedSlashesAction: hcmv3.HttpConnectionManager_UNESCAPE_AND_REDIRECT,
			UpgradeConfigs:               []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "websocket"}},
		}
		if group.access != nil {
			hcm.LocalReplyConfig = jwtFailureLocalReplyConfig()
		}
		typedHCM, err := anypb.New(hcm)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("marshal HTTP connection manager: %w", err)
		}
		chain := &listenerv3.FilterChain{
			Name: resourceName(group.routeName, "filter-chain"),
			Filters: []*listenerv3.Filter{{
				Name:       hcmFilterName,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: typedHCM},
			}},
		}
		if group.tlsSecret != "" {
			if len(group.serverNames) > 0 {
				chain.FilterChainMatch = &listenerv3.FilterChainMatch{ServerNames: group.serverNames}
			}
			tlsContext, err := anypb.New(&tlsv3.DownstreamTlsContext{CommonTlsContext: &tlsv3.CommonTlsContext{
				TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{{
					Name:      group.tlsSecret,
					SdsConfig: adsConfigSource(),
				}},
				AlpnProtocols: []string{"h2", "http/1.1"},
			}})
			if err != nil {
				return nil, nil, nil, fmt.Errorf("marshal downstream TLS context: %w", err)
			}
			chain.TransportSocket = &corev3.TransportSocket{
				Name:       "envoy.transport_sockets.tls",
				ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsContext},
			}
		}

		bindKey := net.JoinHostPort(group.address, strconv.Itoa(int(group.port)))
		listener := listenersByBind[bindKey]
		if listener == nil {
			listener = &listenerv3.Listener{
				Name:    resourceName(group.address+"-"+strconv.Itoa(int(group.port)), "listener"),
				Address: socketAddress(group.address, uint32(group.port)),
			}
			listenersByBind[bindKey] = listener
		}
		if group.tlsSecret != "" && cleartextChains[bindKey] {
			return nil, nil, nil, fmt.Errorf("TLS and cleartext filter chains cannot share %s", bindKey)
		}
		if group.tlsSecret != "" {
			if err := ensureTLSInspector(listener); err != nil {
				return nil, nil, nil, err
			}
		}
		if group.tlsSecret != "" {
			if len(group.serverNames) == 0 {
				if listener.DefaultFilterChain != nil {
					return nil, nil, nil, fmt.Errorf("multiple catch-all TLS filter chains on %s", bindKey)
				}
				listener.DefaultFilterChain = chain
				continue
			}
			names := tlsNames[bindKey]
			if names == nil {
				names = make(map[string]struct{})
				tlsNames[bindKey] = names
			}
			for _, serverName := range group.serverNames {
				if _, exists := names[serverName]; exists {
					return nil, nil, nil, fmt.Errorf("TLS server name %q has multiple filter chains on %s", serverName, bindKey)
				}
				names[serverName] = struct{}{}
			}
		}
		if group.tlsSecret == "" {
			if len(listener.FilterChains) > 0 || listener.DefaultFilterChain != nil {
				return nil, nil, nil, fmt.Errorf("cleartext and TLS protection domains cannot share %s", bindKey)
			}
			cleartextChains[bindKey] = true
		}
		listener.FilterChains = append(listener.FilterChains, chain)
	}

	listeners := make([]*listenerv3.Listener, 0, len(listenersByBind))
	for _, listener := range listenersByBind {
		listeners = append(listeners, listener)
	}
	jwksClusters := make([]*clusterv3.Cluster, 0, len(jwksByHost))
	for _, cluster := range jwksByHost {
		jwksClusters = append(jwksClusters, cluster)
	}
	return listeners, routes, jwksClusters, nil
}
func ensureTLSInspector(listener *listenerv3.Listener) error {
	for _, filter := range listener.ListenerFilters {
		if filter.Name == "envoy.filters.listener.tls_inspector" {
			return nil
		}
	}
	typed, err := anypb.New(&tlsinspectorv3.TlsInspector{})
	if err != nil {
		return fmt.Errorf("marshal TLS inspector: %w", err)
	}
	listener.ListenerFilters = append(listener.ListenerFilters, &listenerv3.ListenerFilter{
		Name:       "envoy.filters.listener.tls_inspector",
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: typed},
	})
	return nil
}

func buildHTTPFilters(access *ir.AccessGuard) ([]*hcmv3.HttpFilter, string, string, error) {
	filters := make([]*hcmv3.HttpFilter, 0, 3)

	jwksHost := ""
	jwksName := ""
	if access != nil {
		jwksHost = normalizeAuthDomain(access.AuthDomain)
		audiences := access.AUDs
		if jwksHost == "" || len(audiences) == 0 {
			return nil, "", "", errors.New("protected domain requires authDomain and at least one AUD")
		}
		jwksName = "flareway-jwks-" + shortHash(jwksHost)
		jwt := &jwtauthnv3.JwtAuthentication{
			Providers: map[string]*jwtauthnv3.JwtProvider{
				"cloudflare-access": {
					Issuer:    "https://" + jwksHost,
					Audiences: audiences,
					JwksSourceSpecifier: &jwtauthnv3.JwtProvider_RemoteJwks{RemoteJwks: &jwtauthnv3.RemoteJwks{
						HttpUri: &corev3.HttpUri{
							Uri:              "https://" + jwksHost + "/cdn-cgi/access/certs",
							HttpUpstreamType: &corev3.HttpUri_Cluster{Cluster: jwksName},
							Timeout:          durationpb.New(5 * time.Second),
						},
						CacheDuration: durationpb.New(5 * time.Minute),
					}},
					FromHeaders:            []*jwtauthnv3.JwtHeader{{Name: "Cf-Access-Jwt-Assertion"}},
					FromCookies:            []string{"CF_Authorization"},
					Forward:                true,
					FailedStatusInMetadata: "flareway_auth_failure",
				},
			},
		}
		if access.OptionsPreflightBypass {
			jwt.Rules = append(jwt.Rules, &jwtauthnv3.RequirementRule{Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
				Headers: []*routev3.HeaderMatcher{{
					Name:                 ":method",
					HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{StringMatch: exactStringMatcher("OPTIONS")},
				}},
			}})
		}
		jwt.Rules = append(jwt.Rules, &jwtauthnv3.RequirementRule{
			Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
			RequirementType: &jwtauthnv3.RequirementRule_Requires{Requires: &jwtauthnv3.JwtRequirement{
				RequiresType: &jwtauthnv3.JwtRequirement_ProviderName{ProviderName: "cloudflare-access"},
			}},
		})
		typedJWT, err := anypb.New(jwt)
		if err != nil {
			return nil, "", "", fmt.Errorf("marshal JWT filter: %w", err)
		}
		filters = append(filters, &hcmv3.HttpFilter{
			Name:       jwtFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedJWT},
		})
	}
	typedCORS, err := anypb.New(&corsv3.Cors{})
	if err != nil {
		return nil, "", "", err
	}
	filters = append(filters, &hcmv3.HttpFilter{
		Name:       corsFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedCORS},
	})
	typedRouter, err := anypb.New(&routerv3.Router{})
	if err != nil {
		return nil, "", "", err
	}

	filters = append(filters, &hcmv3.HttpFilter{
		Name:       routerFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedRouter},
	})
	return filters, jwksHost, jwksName, nil
}
func protectedExactClaims(current routeGroup, groups []routeGroup) []string {
	if current.protected || !current.stripAccessHeaders {
		return nil
	}
	wildcards := make([]string, 0)
	for _, virtualHost := range current.virtualHosts {
		if strings.HasPrefix(virtualHost.Hostname, "*.") {
			wildcards = append(wildcards, strings.ToLower(virtualHost.Hostname))
		}
	}
	if len(wildcards) == 0 {
		return nil
	}
	claims := make([]string, 0)
	for _, candidate := range groups {
		if !candidate.protected {
			continue
		}
		for _, virtualHost := range candidate.virtualHosts {
			hostname := strings.ToLower(virtualHost.Hostname)
			if hostname == "" || hostname == "*" || strings.HasPrefix(hostname, "*.") {
				continue
			}
			for _, wildcard := range wildcards {
				suffix := strings.TrimPrefix(wildcard, "*")
				prefix := strings.TrimSuffix(hostname, suffix)
				if prefix != "" && !strings.Contains(prefix, ".") && strings.HasSuffix(hostname, suffix) {
					claims = appendUnique(claims, hostname)
					break
				}
			}
		}
	}
	sort.Strings(claims)
	return claims
}
func otherTLSClaims(current routeGroup, groups []routeGroup) ([]string, bool) {
	if current.tlsSecret == "" {
		return nil, false
	}
	names := make([]string, 0)
	catchAll := false
	for _, candidate := range groups {
		if candidate.key == current.key || candidate.tlsSecret == "" ||
			candidate.address != current.address || candidate.port != current.port {
			continue
		}
		if len(candidate.serverNames) == 0 {
			catchAll = true
			continue
		}
		for _, hostname := range candidate.serverNames {
			names = appendUnique(names, hostname)
		}
	}
	sort.Strings(names)
	return names, catchAll
}

func misdirectedVirtualHost(hostname string) *routev3.VirtualHost {
	return &routev3.VirtualHost{
		Name:    resourceName("misdirected-"+hostname, "misdirected"),
		Domains: []string{hostname},
		Routes: []*routev3.Route{{
			Name:  resourceName("misdirected-"+hostname, "misdirected"),
			Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
			Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
				Status: 421,
			}},
		}},
	}
}
func jwtFailureLocalReplyConfig() *hcmv3.LocalReplyConfig {
	status403 := &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_StatusCodeFilter{
			StatusCodeFilter: &accesslogv3.StatusCodeFilter{
				Comparison: &accesslogv3.ComparisonFilter{
					Op:    accesslogv3.ComparisonFilter_EQ,
					Value: &corev3.RuntimeUInt32{DefaultValue: 403},
				},
			},
		},
	}
	jwtFailure := &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_MetadataFilter{
			MetadataFilter: &accesslogv3.MetadataFilter{
				Matcher: &matcherv3.MetadataMatcher{
					Filter: jwtFilterName,
					Path: []*matcherv3.MetadataMatcher_PathSegment{
						{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "flareway_auth_failure"}},
						{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "code"}},
					},
					Value: &matcherv3.ValueMatcher{
						MatchPattern: &matcherv3.ValueMatcher_PresentMatch{PresentMatch: true},
					},
				},
				MatchIfKeyNotFound: wrapperspb.Bool(false),
			},
		},
	}
	return &hcmv3.LocalReplyConfig{Mappers: []*hcmv3.ResponseMapper{{
		Filter: &accesslogv3.AccessLogFilter{
			FilterSpecifier: &accesslogv3.AccessLogFilter_AndFilter{
				AndFilter: &accesslogv3.AndFilter{Filters: []*accesslogv3.AccessLogFilter{status403, jwtFailure}},
			},
		},
		StatusCode: wrapperspb.UInt32(401),
	}}}
}

func canonicalGateway(gw *ir.Gateway) *ir.Gateway {
	canonical := *gw
	canonical.Domains = slices.Clone(gw.Domains)
	for i := range canonical.Domains {
		if canonical.Domains[i].Access == nil {
			continue
		}
		access := *canonical.Domains[i].Access
		access.AUDs = access.CanonicalAUDs()
		canonical.Domains[i].Access = &access
	}
	return &canonical
}

func desiredVersion(gw *ir.Gateway, streamIdleTimeout time.Duration) (string, error) {
	payload := struct {
		Gateway           *ir.Gateway `json:"gateway"`
		StreamIdleTimeout string      `json:"streamIdleTimeout"`
	}{Gateway: gw, StreamIdleTimeout: streamIdleTimeout.String()}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal desired xDS state: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func toResources[T cachetypes.Resource](values []T) []cachetypes.Resource {
	out := make([]cachetypes.Resource, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out
}

func normalizeAuthDomain(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	return strings.Trim(value, "/")
}

func resourceName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	var out strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(value) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '_' {
			out.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.Trim(out.String(), "-")
	if name == "" {
		return fallback
	}
	return name
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

func mergeVirtualHosts(group *routeGroup, incoming []ir.VirtualHost) {
	for _, virtualHost := range incoming {
		hostname := virtualHost.Hostname
		if hostname == "" {
			hostname = "*"
		}
		index, exists := group.virtualHostIndex[hostname]
		if !exists {
			group.virtualHostIndex[hostname] = len(group.virtualHosts)
			group.virtualHosts = append(group.virtualHosts, virtualHost)
			continue
		}
		existing := &group.virtualHosts[index]
		for _, route := range virtualHost.Routes {
			duplicate := false
			for _, current := range existing.Routes {
				if current.Name == route.Name {
					duplicate = true
					break
				}
			}
			if !duplicate {
				existing.Routes = append(existing.Routes, route)
			}
		}
		sort.SliceStable(existing.Routes, func(i, j int) bool {
			return routePrecedes(existing.Routes[i], existing.Routes[j])
		})
	}
}

func routePrecedes(left, right ir.Route) bool {
	leftRank := pathMatchRank(left.Match.Type)
	rightRank := pathMatchRank(right.Match.Type)
	if leftRank != rightRank {
		return leftRank < rightRank
	}
	if left.Match.Type == ir.PathMatchPathPrefix && len(left.Match.Value) != len(right.Match.Value) {
		return len(left.Match.Value) > len(right.Match.Value)
	}
	if (left.Method != nil) != (right.Method != nil) {
		return left.Method != nil
	}
	if len(left.Headers) != len(right.Headers) {
		return len(left.Headers) > len(right.Headers)
	}
	if len(left.Query) != len(right.Query) {
		return len(left.Query) > len(right.Query)
	}
	return left.Name < right.Name
}

func pathMatchRank(matchType string) int {
	switch matchType {
	case ir.PathMatchExact:
		return 0
	case ir.PathMatchRegularExpression:
		return 1
	default:
		return 2
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
