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
	"google.golang.org/protobuf/proto"
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
	name               string // first protection domain in the group; names it in bind collision errors
	routeName          string
	address            string
	port               int32
	tlsSecret          string
	isolationKey       string
	serverNames        []string
	access             *ir.AccessGuard
	accessKey          string
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
	if err := rejectDuplicateResourceNames(resources); err != nil {
		return nil, err
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

// rejectDuplicateResourceNames fails the build when two resources of one type
// share a name. A snapshot indexes resources by name and keeps only the last,
// so a duplicate would silently replace one listener's routes or cluster with
// another's while every reference still resolves.
func rejectDuplicateResourceNames(resources map[resourcev3.Type][]cachetypes.Resource) error {
	for _, typeURL := range []resourcev3.Type{
		resourcev3.ListenerType, resourcev3.RouteType, resourcev3.ClusterType, resourcev3.EndpointType, resourcev3.SecretType,
	} {
		seen := make(map[string]struct{}, len(resources[typeURL]))
		for _, resource := range resources[typeURL] {
			name := cachev3.GetResourceName(resource)
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("xDS resource name %q is used by more than one %s", name, typeURL)
			}
			seen[name] = struct{}{}
		}
	}
	return nil
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
				name:               domain.Name,
				routeName:          resourceName(domain.Name, "routes"),
				address:            address,
				port:               port,
				tlsSecret:          tlsSecret,
				isolationKey:       isolationKey,
				access:             domain.Access,
				accessKey:          string(accessKey),
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

type bindOccupant struct {
	name string
	tls  bool
}

func bindCollisionError(occupant bindOccupant, name string, tls bool, bindKey string) error {
	if !occupant.tls && !tls {
		return fmt.Errorf("cleartext protection domains %q and %q cannot share %s", occupant.name, name, bindKey)
	}
	cleartext, secure := occupant.name, name
	if occupant.tls {
		cleartext, secure = name, occupant.name
	}
	return fmt.Errorf("cleartext protection domain %q and TLS protection domain %q cannot share %s", cleartext, secure, bindKey)
}

func buildListeners(groups []routeGroup, streamIdleTimeout time.Duration) ([]*listenerv3.Listener, []*routev3.RouteConfiguration, []*clusterv3.Cluster, error) {
	listenersByBind := make(map[string]*listenerv3.Listener)
	// occupants records the first group placed on each bind. A cleartext group
	// only lands on an empty bind, so a cleartext occupant is the bind's only
	// chain.
	occupants := make(map[string]bindOccupant)
	tlsNames := make(map[string]map[string]struct{})
	routes := make([]*routev3.RouteConfiguration, 0, len(groups))
	jwksByHost := make(map[string]*clusterv3.Cluster)

	for _, members := range filterChainMembers(groups) {
		group := members[0]
		guards, err := newChainGuards(members)
		if err != nil {
			return nil, nil, nil, err
		}
		routeConfig, err := buildChainRouteConfig(members, groups, guards)
		if err != nil {
			return nil, nil, nil, err
		}
		routes = append(routes, routeConfig)

		var filters []*hcmv3.HttpFilter
		var jwks []jwksSource
		enforcesJWT := false
		if guards == nil {
			var jwksHost, jwksName string
			filters, jwksHost, jwksName, err = buildHTTPFilters(group.access)
			if jwksHost != "" {
				jwks = []jwksSource{{host: jwksHost, name: jwksName}}
			}
			enforcesJWT = group.access != nil
		} else {
			filters, jwks, err = guards.httpFilters()
			enforcesJWT = len(guards.providers) > 0
		}
		if err != nil {
			return nil, nil, nil, err
		}
		for _, source := range jwks {
			if _, ok := jwksByHost[source.host]; !ok {
				cluster, err := buildJWKCluster(source.host, source.name)
				if err != nil {
					return nil, nil, nil, err
				}
				jwksByHost[source.host] = cluster
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
		if enforcesJWT {
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
		isTLS := group.tlsSecret != ""
		occupant, occupied := occupants[bindKey]
		if occupied && (!isTLS || !occupant.tls) {
			return nil, nil, nil, bindCollisionError(occupant, group.name, isTLS, bindKey)
		}
		if !occupied {
			occupants[bindKey] = bindOccupant{name: group.name, tls: isTLS}
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

// filterChainMembers partitions groups into the sets that share one filter
// chain. Route groups on one TLS bind with the same listener, certificate, and
// server names are reached by the same handshakes: a private listener's SNI is
// the listener hostname, not the requested host, so Envoy can only tell them
// apart by Host. Such groups share one chain and route table, and each virtual
// host enforces its own group's guard. Every other group has a chain of its
// own.
func filterChainMembers(groups []routeGroup) [][]routeGroup {
	chains := make([][]routeGroup, 0, len(groups))
	byKey := make(map[string]int)
	for _, group := range groups {
		if group.tlsSecret == "" {
			chains = append(chains, []routeGroup{group})
			continue
		}
		key := net.JoinHostPort(group.address, strconv.Itoa(int(group.port))) + "|" + group.tlsSecret + "|" +
			group.isolationKey + "|" + strings.Join(group.serverNames, ",")
		if index, ok := byKey[key]; ok {
			chains[index] = append(chains[index], group)
			continue
		}
		byKey[key] = len(chains)
		chains = append(chains, []routeGroup{group})
	}
	return chains
}

// buildChainRouteConfig builds the route table one filter chain serves.
// Members of a shared chain must serve disjoint hosts: one host has one
// virtual host and so one guard.
func buildChainRouteConfig(members, groups []routeGroup, guards *chainGuards) (*routev3.RouteConfiguration, error) {
	routeConfig := &routev3.RouteConfiguration{
		Name:                     members[0].routeName,
		IgnorePortInHostMatching: true,
	}
	misdirectedNames, misdirectedCatchAll := otherTLSClaims(members, groups)
	blockedDomains := make(map[string]struct{}, len(misdirectedNames)+1)
	for _, hostname := range misdirectedNames {
		blockedDomains[hostname] = struct{}{}
	}
	if misdirectedCatchAll {
		blockedDomains["*"] = struct{}{}
	}
	servedBy := make(map[string]string)
	for _, member := range members {
		for _, virtualHost := range member.virtualHosts {
			hostname := virtualHost.Hostname
			if hostname == "" {
				hostname = "*"
			}
			if _, blocked := blockedDomains[hostname]; blocked {
				continue
			}
			if other, served := servedBy[hostname]; served {
				return nil, fmt.Errorf("protection domains %q and %q serve host %q with different guards on one TLS filter chain", other, member.name, hostname)
			}
			servedBy[hostname] = member.name
			translated, err := buildDomainVirtualHost(virtualHost, member.guard, member.stripAccessHeaders)
			if err != nil {
				return nil, err
			}
			if err := guards.enforce(translated, member); err != nil {
				return nil, err
			}
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, translated)
		}
	}
	claimed := func(hostname string) bool {
		for _, member := range members {
			if _, ok := member.virtualHostIndex[hostname]; ok {
				return true
			}
		}
		return false
	}
	shadowed := make(map[string]struct{})
	for _, member := range members {
		for _, hostname := range protectedExactClaims(member, groups) {
			if _, done := shadowed[hostname]; done || claimed(hostname) {
				continue
			}
			shadowed[hostname] = struct{}{}
			blocked, err := buildDomainVirtualHost(ir.VirtualHost{
				Name: resourceName("protected-"+hostname, "protected-host"), Hostname: hostname,
			}, ir.GuardBlocked, true)
			if err != nil {
				return nil, err
			}
			if err := guards.disable(blocked); err != nil {
				return nil, err
			}
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, blocked)
		}
	}
	if misdirectedCatchAll {
		misdirectedNames = append(misdirectedNames, "*")
	}
	for _, hostname := range misdirectedNames {
		misdirected := misdirectedVirtualHost(hostname)
		if err := guards.disable(misdirected); err != nil {
			return nil, err
		}
		routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, misdirected)
	}
	return routeConfig, nil
}

// chainGuards enforces each member's guard per virtual host when route groups
// with different guards share one filter chain. One jwt_authn filter carries a
// requirement per Access guard, and every virtual host names its own: a
// Forwarding Access host requires its JWT, while Blocked, unprotected, and
// misdirected hosts answer locally or forward without one, exactly as they do
// on a chain of their own. A nil *chainGuards is a chain of one group, whose
// filter enforces the group's guard on every host.
type chainGuards struct {
	// providers maps a requirement name to the Access guard it verifies.
	providers map[string]*ir.AccessGuard
	// requirements maps a member key to its requirement name; a member that
	// verifies no JWT has none.
	requirements map[string]string
}

type jwksSource struct {
	host string
	name string
}

func newChainGuards(members []routeGroup) (*chainGuards, error) {
	if len(members) < 2 {
		return nil, nil
	}
	guards := &chainGuards{providers: make(map[string]*ir.AccessGuard), requirements: make(map[string]string)}
	accessKeys := make(map[string]string)
	for _, member := range members {
		if member.guard == ir.GuardBlocked || member.access == nil {
			continue
		}
		name := "cloudflare-access-" + shortHash(member.accessKey)
		if existing, ok := accessKeys[name]; ok && existing != member.accessKey {
			return nil, fmt.Errorf("access guards of protection domain %q collide on JWT requirement %q", member.name, name)
		}
		accessKeys[name] = member.accessKey
		guards.providers[name] = member.access
		guards.requirements[member.key] = name
	}
	return guards, nil
}

// httpFilters returns the shared chain's HTTP filters and the JWKS sources
// its providers fetch.
func (guards *chainGuards) httpFilters() ([]*hcmv3.HttpFilter, []jwksSource, error) {
	if len(guards.providers) == 0 {
		filters, err := httpFiltersWithJWT(nil)
		return filters, nil, err
	}
	names := make([]string, 0, len(guards.providers))
	for name := range guards.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	jwt := &jwtauthnv3.JwtAuthentication{
		Providers:      make(map[string]*jwtauthnv3.JwtProvider, len(names)),
		RequirementMap: make(map[string]*jwtauthnv3.JwtRequirement, len(names)),
		// Every virtual host names its requirement. A request that resolves
		// none still has to present a JWT rather than pass unverified.
		Rules: []*jwtauthnv3.RequirementRule{{
			Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
			RequirementType: &jwtauthnv3.RequirementRule_Requires{Requires: &jwtauthnv3.JwtRequirement{
				RequiresType: &jwtauthnv3.JwtRequirement_ProviderName{ProviderName: names[0]},
			}},
		}},
	}
	sources := make([]jwksSource, 0, len(names))
	for _, name := range names {
		provider, jwksHost, jwksName, err := accessJWTProvider(guards.providers[name])
		if err != nil {
			return nil, nil, err
		}
		jwt.Providers[name] = provider
		jwt.RequirementMap[name] = &jwtauthnv3.JwtRequirement{
			RequiresType: &jwtauthnv3.JwtRequirement_ProviderName{ProviderName: name},
		}
		sources = append(sources, jwksSource{host: jwksHost, name: jwksName})
	}
	filters, err := httpFiltersWithJWT(jwt)
	return filters, sources, err
}

// enforce applies member's guard to its virtual host on a shared chain. An
// OPTIONS preflight bypass becomes an OPTIONS twin ahead of every route that
// skips JWT verification, so preflights route exactly as the original
// requests would.
func (guards *chainGuards) enforce(virtualHost *routev3.VirtualHost, member routeGroup) error {
	if guards == nil || len(guards.providers) == 0 {
		return nil
	}
	requirement := guards.requirements[member.key]
	if err := setJWTRequirement(&virtualHost.TypedPerFilterConfig, requirement); err != nil {
		return err
	}
	if requirement == "" || !member.access.OptionsPreflightBypass {
		return nil
	}
	routes := make([]*routev3.Route, 0, 2*len(virtualHost.Routes))
	for _, route := range virtualHost.Routes {
		preflight := proto.Clone(route).(*routev3.Route)
		preflight.Name = route.Name + "-options-preflight"
		preflight.Match.Headers = append(preflight.Match.Headers, &routev3.HeaderMatcher{
			Name:                 ":method",
			HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{StringMatch: exactStringMatcher("OPTIONS")},
		})
		if err := setJWTRequirement(&preflight.TypedPerFilterConfig, ""); err != nil {
			return err
		}
		routes = append(routes, preflight, route)
	}
	virtualHost.Routes = routes
	return nil
}

// disable exempts a locally answered virtual host on a shared chain from JWT
// verification.
func (guards *chainGuards) disable(virtualHost *routev3.VirtualHost) error {
	if guards == nil || len(guards.providers) == 0 {
		return nil
	}
	return setJWTRequirement(&virtualHost.TypedPerFilterConfig, "")
}

// setJWTRequirement sets the jwt_authn per-route config: verify requirement,
// or skip verification when requirement is empty.
func setJWTRequirement(configs *map[string]*anypb.Any, requirement string) error {
	config := &jwtauthnv3.PerRouteConfig{RequirementSpecifier: &jwtauthnv3.PerRouteConfig_Disabled{Disabled: true}}
	if requirement != "" {
		config.RequirementSpecifier = &jwtauthnv3.PerRouteConfig_RequirementName{RequirementName: requirement}
	}
	typed, err := anypb.New(config)
	if err != nil {
		return fmt.Errorf("marshal JWT per-route config: %w", err)
	}
	if *configs == nil {
		*configs = make(map[string]*anypb.Any, 1)
	}
	(*configs)[jwtFilterName] = typed
	return nil
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
	if access == nil {
		filters, err := httpFiltersWithJWT(nil)
		return filters, "", "", err
	}
	provider, jwksHost, jwksName, err := accessJWTProvider(access)
	if err != nil {
		return nil, "", "", err
	}
	jwt := &jwtauthnv3.JwtAuthentication{
		Providers: map[string]*jwtauthnv3.JwtProvider{"cloudflare-access": provider},
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
	filters, err := httpFiltersWithJWT(jwt)
	if err != nil {
		return nil, "", "", err
	}
	return filters, jwksHost, jwksName, nil
}

// accessJWTProvider returns the jwt_authn provider verifying access, the
// Access team domain it fetches JWKS from, and that JWKS cluster's name.
func accessJWTProvider(access *ir.AccessGuard) (*jwtauthnv3.JwtProvider, string, string, error) {
	jwksHost := normalizeAuthDomain(access.AuthDomain)
	audiences := access.AUDs
	if jwksHost == "" || len(audiences) == 0 {
		return nil, "", "", errors.New("protected domain requires authDomain and at least one AUD")
	}
	jwksName := "flareway-jwks-" + shortHash(jwksHost)
	return &jwtauthnv3.JwtProvider{
		Issuer:    "https://" + jwksHost,
		Audiences: audiences,
		JwksSourceSpecifier: &jwtauthnv3.JwtProvider_RemoteJwks{RemoteJwks: &jwtauthnv3.RemoteJwks{
			HttpUri: &corev3.HttpUri{
				Uri:              "https://" + jwksHost + "/cdn-cgi/access/certs",
				HttpUpstreamType: &corev3.HttpUri_Cluster{Cluster: jwksName},
				Timeout:          durationpb.New(10 * time.Second),
			},
			CacheDuration: durationpb.New(5 * time.Minute),
		}},
		FromHeaders:            []*jwtauthnv3.JwtHeader{{Name: "Cf-Access-Jwt-Assertion"}},
		FromCookies:            []string{"CF_Authorization"},
		Forward:                true,
		FailedStatusInMetadata: "flareway_auth_failure",
	}, jwksHost, jwksName, nil
}

// httpFiltersWithJWT returns the HTTP filter chain: jwt_authn when jwt is
// set, then CORS and the router.
func httpFiltersWithJWT(jwt *jwtauthnv3.JwtAuthentication) ([]*hcmv3.HttpFilter, error) {
	filters := make([]*hcmv3.HttpFilter, 0, 3)
	if jwt != nil {
		// Providers and requirement_map are maps: marshal deterministically so
		// identical input hashes to the same Listener resource version.
		typedJWT := &anypb.Any{}
		if err := anypb.MarshalFrom(typedJWT, jwt, proto.MarshalOptions{Deterministic: true}); err != nil {
			return nil, fmt.Errorf("marshal JWT filter: %w", err)
		}
		filters = append(filters, &hcmv3.HttpFilter{
			Name:       jwtFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedJWT},
		})
	}
	typedCORS, err := anypb.New(&corsv3.Cors{})
	if err != nil {
		return nil, err
	}
	filters = append(filters, &hcmv3.HttpFilter{
		Name:       corsFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedCORS},
	})
	typedRouter, err := anypb.New(&routerv3.Router{})
	if err != nil {
		return nil, err
	}

	filters = append(filters, &hcmv3.HttpFilter{
		Name:       routerFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedRouter},
	})
	return filters, nil
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
				// Envoy's "*.example.com" matches any depth of subdomain,
				// not only single-label prefixes.
				prefix := strings.TrimSuffix(hostname, suffix)
				if prefix != "" && strings.HasSuffix(hostname, suffix) {
					claims = appendUnique(claims, hostname)
					break
				}
			}
		}
	}
	sort.Strings(claims)
	return claims
}

// otherTLSClaims returns the server names other filter chains on the bind of
// members claim, and whether one of them is the bind's catch-all chain.
func otherTLSClaims(members, groups []routeGroup) ([]string, bool) {
	current := members[0]
	if current.tlsSecret == "" {
		return nil, false
	}
	names := make([]string, 0)
	catchAll := false
	for _, candidate := range groups {
		if candidate.tlsSecret == "" || candidate.address != current.address || candidate.port != current.port ||
			slices.ContainsFunc(members, func(member routeGroup) bool { return member.key == candidate.key }) {
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
