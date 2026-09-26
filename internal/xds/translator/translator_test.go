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

package translator

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

type goldenProjection struct {
	VersionLength int                `json:"versionLength"`
	Listener      listenerProjection `json:"listener"`
	Routes        []routeProjection  `json:"routes"`
	Cluster       clusterProjection  `json:"cluster"`
	Endpoint      string             `json:"endpoint"`
	Secret        string             `json:"secret"`
}

type listenerProjection struct {
	Address                  string   `json:"address"`
	Port                     uint32   `json:"port"`
	ServerNames              []string `json:"serverNames"`
	TLSSecret                string   `json:"tlsSecret"`
	RouteConfig              string   `json:"routeConfig"`
	NormalizePath            bool     `json:"normalizePath"`
	MergeSlashes             bool     `json:"mergeSlashes"`
	EscapedSlashAction       string   `json:"escapedSlashAction"`
	StreamIdleTimeout        string   `json:"streamIdleTimeout"`
	ConnectionIdle           string   `json:"connectionIdle"`
	Websocket                bool     `json:"websocket"`
	IgnorePortInHostMatching bool     `json:"ignorePortInHostMatching"`
	TLSInspector             bool     `json:"tlsInspector"`
	ALPN                     []string `json:"alpn"`
}

type routeProjection struct {
	Name             string   `json:"name"`
	Action           string   `json:"action"`
	RuntimeNumerator uint32   `json:"runtimeNumerator,omitempty"`
	Clusters         []string `json:"clusters,omitempty"`
	PathRewrite      string   `json:"pathRewrite,omitempty"`
	HostRewrite      string   `json:"hostRewrite,omitempty"`
	Timeout          string   `json:"timeout,omitempty"`
	CORS             bool     `json:"cors,omitempty"`
	RedirectCode     string   `json:"redirectCode,omitempty"`
}

type clusterProjection struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	EDSService string   `json:"edsService"`
	HTTP2      bool     `json:"http2"`
	SNI        string   `json:"sni"`
	SANs       []string `json:"sans"`
}

func TestBuildGolden(t *testing.T) {
	method := "GET"
	zero := time.Duration(0)
	maxAge := int32(600)
	invalid := &ir.Reason{Code: "BackendNotFound", Message: "missing"}
	gw := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "default", Name: "gateway"},
		ConformanceMode: true,
		Listeners: []ir.Listener{{
			Name: "https", Hostname: "example.com", Port: 443, EnvoyPort: 10443,
			Protocol: "HTTPS", Exposure: ir.ExposurePublic, TLS: &ir.TLSRef{Secret: "listener-cert"},
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "public", ListenerName: "https", EnvoyPort: 10443,
			VirtualHosts: []ir.VirtualHost{{
				Name: "main", Hostname: "example.com",
				Routes: []ir.Route{
					{
						Name: "items", Match: ir.PathMatch{Type: ir.PathMatchExact, Value: "/v1/items"}, Method: &method,
						Headers: []ir.HeaderMatch{{Name: "x-tenant", Type: ir.StringMatchExact, Value: "blue"}},
						Query:   []ir.QueryMatch{{Name: "verbose", Type: ir.StringMatchExact, Value: "true"}},
						Filters: ir.Filters{
							URLRewrite: &ir.URLRewrite{Hostname: "upstream.example", Path: &ir.PathModifier{Type: ir.PathModifierReplaceFullPath, Replace: "/new"}},
							Mirrors:    []ir.Mirror{{Backend: ir.BackendRef{ClusterName: "backend-b"}, Percent: 25}},
							CORS:       &ir.CORS{AllowOrigins: []string{"https://app.example.com"}, AllowMethods: []string{"GET", "OPTIONS"}, MaxAge: &maxAge, AllowCredentials: true},
						},
						Backends: []ir.BackendRef{
							{Name: "a", ClusterName: "backend-a", Weight: 80},
							{Name: "missing", Weight: 20, Invalid: invalid},
						},
						Timeouts: ir.Timeouts{Request: &zero},
					},
					{
						Name: "redirect", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/old"},
						Filters: ir.Filters{Redirect: &ir.Redirect{Scheme: "https", Hostname: "example.com", StatusCode: 308, Path: &ir.PathModifier{Type: ir.PathModifierReplacePrefixMatch, Replace: "/new"}}},
					},
				},
			}},
		}},
		Clusters: []ir.Cluster{
			{Name: "backend-a", Port: 8080, AppProtocol: "kubernetes.io/h2c", Endpoints: []ir.Endpoint{{Address: "10.0.0.2", Port: 8080}}, TLS: &ir.BackendTLS{ServerName: "backend.default.svc", CACertificate: []byte("ca"), SubjectAltNames: []ir.SubjectAltName{{Type: "Hostname", Value: "backend.default.svc"}}}},
			{Name: "backend-b", Port: 8081, Endpoints: []ir.Endpoint{{Address: "10.0.0.3", Port: 8081}}},
		},
		Secrets: []ir.TLSSecret{{Name: "listener-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")}},
	}
	cfg := &v1alpha1.GatewayClassConfig{Spec: v1alpha1.GatewayClassConfigSpec{Proxy: v1alpha1.ProxySpec{StreamIdleTimeout: metav1.Duration{Duration: time.Hour}}}}

	snapshot, err := Build(gw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := projectSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := os.ReadFile(filepath.Join("testdata", "core.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(expected) {
		t.Fatalf("translator golden mismatch\n--- want\n%s--- got\n%s", expected, actual)
	}
}

func TestBuildKeepsCollidingLegacyBackendNamesDistinct(t *testing.T) {
	firstName := "k8s://team/api--admin:80"
	secondName := "k8s://team--api/admin:80"
	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "default", Name: "collision"},
		ConformanceMode: true,
		Listeners:       []ir.Listener{{Name: "http", Hostname: "api.example.com", EnvoyPort: 10080}},
		Domains: []ir.ProtectionDomain{{
			Name: "public", ListenerName: "http", EnvoyPort: 10080,
			VirtualHosts: []ir.VirtualHost{{
				Name: "api", Hostname: "api.example.com",
				Routes: []ir.Route{{
					Name:     "collision",
					Match:    ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
					Backends: []ir.BackendRef{{ClusterName: firstName, Weight: 1}},
					Filters:  ir.Filters{Mirrors: []ir.Mirror{{Backend: ir.BackendRef{ClusterName: secondName}, Percent: 100}}},
				}},
			}},
		}},
		Clusters: []ir.Cluster{
			{Name: firstName, Port: 80, Endpoints: []ir.Endpoint{{Address: "10.0.0.1", Port: 8081}}},
			{Name: secondName, Port: 80, Endpoints: []ir.Endpoint{{Address: "10.0.0.2", Port: 8082}}},
		},
	}

	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	clusters := snapshot.GetResources(resourcev3.ClusterType)
	assignments := snapshot.GetResources(resourcev3.EndpointType)
	if len(clusters) != 2 || len(assignments) != 2 {
		t.Fatalf("xDS clusters=%d endpoint assignments=%d, want two of each", len(clusters), len(assignments))
	}
	for _, expected := range []struct {
		name    string
		address string
		port    uint32
	}{
		{name: firstName, address: "10.0.0.1", port: 8081},
		{name: secondName, address: "10.0.0.2", port: 8082},
	} {
		cluster, ok := clusters[expected.name].(*clusterv3.Cluster)
		if !ok || cluster.EdsClusterConfig.ServiceName != expected.name {
			t.Fatalf("cluster %q = %#v", expected.name, clusters[expected.name])
		}
		assignment, ok := assignments[expected.name].(*endpointv3.ClusterLoadAssignment)
		if !ok || assignment.ClusterName != expected.name || len(assignment.Endpoints) != 1 ||
			len(assignment.Endpoints[0].LbEndpoints) != 1 {
			t.Fatalf("endpoint assignment %q = %#v", expected.name, assignments[expected.name])
		}
		socket := assignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress()
		if socket.Address != expected.address || socket.GetPortValue() != expected.port {
			t.Fatalf("endpoint assignment %q address = %s:%d, want %s:%d", expected.name, socket.Address, socket.GetPortValue(), expected.address, expected.port)
		}
	}

	routeConfig, ok := snapshot.GetResources(resourcev3.RouteType)["public"].(*routev3.RouteConfiguration)
	if !ok || len(routeConfig.VirtualHosts) != 1 || len(routeConfig.VirtualHosts[0].Routes) < 1 {
		t.Fatalf("route configuration = %#v", routeConfig)
	}
	action := routeConfig.VirtualHosts[0].Routes[0].GetRoute()
	if action == nil || len(action.GetWeightedClusters().Clusters) != 1 ||
		action.GetWeightedClusters().Clusters[0].Name != firstName {
		t.Fatalf("route action = %#v, want backend %q", action, firstName)
	}
	if len(action.RequestMirrorPolicies) != 1 || action.RequestMirrorPolicies[0].Cluster != secondName {
		t.Fatalf("mirror policies = %#v, want cluster %q", action.RequestMirrorPolicies, secondName)
	}
}

func TestBuildEmptySnapshot(t *testing.T) {
	snapshot, err := Build(&ir.Gateway{Key: types.NamespacedName{Namespace: "default", Name: "invalid"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	version, err := SnapshotVersion(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(version) != 64 {
		t.Fatalf("version length = %d, want 64", len(version))
	}
	if got := len(snapshot.GetResources(resourcev3.ListenerType)); got != 0 {
		t.Fatalf("listeners = %d, want 0", got)
	}
}

func TestBuildMergesDuplicateVirtualHostDomains(t *testing.T) {
	rootRoute := ir.Route{
		Name:     "root",
		Match:    ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
		Backends: []ir.BackendRef{{ClusterName: "backend", Weight: 1}},
	}
	specificRoute := ir.Route{
		Name:     "specific",
		Match:    ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/foo"},
		Backends: []ir.BackendRef{{ClusterName: "backend", Weight: 1}},
	}
	gw := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "default", Name: "shared-port"},
		ConformanceMode: true,
		Listeners: []ir.Listener{
			{Name: "one", Hostname: "a.example.com", EnvoyPort: 10080},
			{Name: "two", EnvoyPort: 10080},
		},
		Domains: []ir.ProtectionDomain{
			{Name: "one", ListenerName: "one", EnvoyPort: 10080, VirtualHosts: []ir.VirtualHost{{Name: "a-one", Hostname: "a.example.com", Routes: []ir.Route{rootRoute}}}},
			{Name: "two", ListenerName: "two", EnvoyPort: 10080, VirtualHosts: []ir.VirtualHost{{Name: "a-two", Hostname: "a.example.com", Routes: []ir.Route{specificRoute}}}},
		},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
	}
	snapshot, err := Build(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	resources := snapshot.GetResources(resourcev3.RouteType)
	if len(resources) != 1 {
		t.Fatalf("route configurations = %d, want 1", len(resources))
	}
	for _, resource := range resources {
		routeConfig := resource.(*routev3.RouteConfiguration)
		if len(routeConfig.VirtualHosts) != 1 {
			t.Fatalf("virtual hosts = %d, want one unique hostname", len(routeConfig.VirtualHosts))
		}
		if got := routeConfig.VirtualHosts[0].Domains; len(got) != 1 || got[0] != "a.example.com" {
			t.Fatalf("domains = %v, want [a.example.com]", got)
		}
		routes := routeConfig.VirtualHosts[0].Routes
		if len(routes) != 3 {
			t.Fatalf("merged route count = %d, want 3 including fallback", len(routes))
		}
		if routes[0].Name != "specific" || routes[1].Name != "root" {
			t.Fatalf("merged route order = %v, want specific then root then fallback", []string{routes[0].Name, routes[1].Name})
		}
	}
}

func TestBuildTLSCatchAllAndMisdirectedRequests(t *testing.T) {
	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "default", Name: "https"},
		ConformanceMode: true,
		Listeners: []ir.Listener{
			{Name: "named", Hostname: "api.example.com", EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "named-cert"}},
			{Name: "wildcard", Hostname: "*.example.com", EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "wildcard-cert"}},
			{Name: "catchall", EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "catchall-cert"}},
		},
		Domains: []ir.ProtectionDomain{
			{Name: "named", ListenerName: "named", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "named", Hostname: "api.example.com"}}},
			{Name: "wildcard", ListenerName: "wildcard", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "wildcard", Hostname: "*.example.com"}}},
			{Name: "catchall", ListenerName: "catchall", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "catchall", Hostname: "*"}}},
		},
		Secrets: []ir.TLSSecret{
			{Name: "named-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")},
			{Name: "wildcard-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")},
			{Name: "catchall-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")},
		},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := snapshot.GetResources(resourcev3.ListenerType)["0.0.0.0-10443"].(*listenerv3.Listener)
	if len(listener.FilterChains) != 2 {
		t.Fatalf("SNI filter chains = %d, want 2", len(listener.FilterChains))
	}
	if listener.DefaultFilterChain == nil {
		t.Fatal("catch-all HTTPS listener did not become the default filter chain")
	}
	namedRoutes := routeConfigForChain(t, snapshot, chainForServerName(t, listener, "api.example.com"))
	wildcardRoutes := routeConfigForChain(t, snapshot, chainForServerName(t, listener, "*.example.com"))
	catchAllRoutes := routeConfigForChain(t, snapshot, listener.DefaultFilterChain)
	if got := directStatusForDomain(t, namedRoutes, "*.example.com"); got != 421 {
		t.Fatalf("named TLS chain wildcard authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, namedRoutes, "*"); got != 421 {
		t.Fatalf("named TLS chain catch-all authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, wildcardRoutes, "api.example.com"); got != 421 {
		t.Fatalf("wildcard TLS chain exact authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, wildcardRoutes, "*"); got != 421 {
		t.Fatalf("wildcard TLS chain catch-all authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, catchAllRoutes, "api.example.com"); got != 421 {
		t.Fatalf("catch-all TLS chain exact authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, catchAllRoutes, "*.example.com"); got != 421 {
		t.Fatalf("catch-all TLS chain wildcard authority status = %d, want 421", got)
	}
	if got := directStatusForDomain(t, catchAllRoutes, "*"); got != 404 {
		t.Fatalf("catch-all TLS chain unknown authority status = %d, want 404", got)
	}
}

func TestBuildPrivateTLSJWTListenerAndRecordedPodIPFallback(t *testing.T) {
	gateway := &ir.Gateway{
		Key: types.NamespacedName{Namespace: "default", Name: "private"},
		Listeners: []ir.Listener{{
			Name: "private", Hostname: "admin.internal.example", Port: 443, EnvoyPort: 443,
			Protocol: "HTTPS", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback,
			TLS: &ir.TLSRef{Secret: "private-cert"},
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "private", ListenerName: "private", EnvoyPort: 443, Protected: true, Guard: ir.GuardForwarding,
			Access:       &ir.AccessGuard{AUDs: []string{"private-aud"}, TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
			VirtualHosts: []ir.VirtualHost{{Name: "private", Hostname: "admin.internal.example"}},
		}},
		Secrets: []ir.TLSSecret{{Name: "private-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")}},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-443"].(*listenerv3.Listener)
	if listener.Address.GetSocketAddress().Address != "127.0.0.1" {
		t.Fatalf("private listener address = %s", listener.Address.GetSocketAddress().Address)
	}
	if len(listener.FilterChains) != 1 || listener.FilterChains[0].TransportSocket == nil {
		t.Fatalf("private TLS filter chain = %#v", listener.FilterChains)
	}
	tlsContext := &tlsv3.DownstreamTlsContext{}
	if err := listener.FilterChains[0].TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatal(err)
	}
	secrets := tlsContext.CommonTlsContext.GetTlsCertificateSdsSecretConfigs()
	if len(secrets) != 1 || secrets[0].Name != "private-cert" {
		t.Fatalf("private TLS SDS secrets = %#v", secrets)
	}
	hcm := &hcmv3.HttpConnectionManager{}
	if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	if len(hcm.HttpFilters) < 2 || hcm.HttpFilters[0].Name != jwtFilterName {
		t.Fatalf("private HTTP filters = %#v", hcm.HttpFilters)
	}
	jwt := &jwtauthnv3.JwtAuthentication{}
	if err := hcm.HttpFilters[0].GetTypedConfig().UnmarshalTo(jwt); err != nil {
		t.Fatal(err)
	}
	if provider := jwt.Providers["cloudflare-access"]; provider == nil || !slices.Equal(provider.Audiences, []string{"private-aud"}) {
		t.Fatalf("single-AUD provider = %#v", provider)
	}

	gateway.Listeners[0].Binding = ir.ListenerBindingPodIP
	snapshot, err = Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-443"]; exists {
		t.Fatal("PodIP listener retained the loopback binding")
	}
	if _, exists := snapshot.GetResources(resourcev3.ListenerType)["0.0.0.0-443"]; !exists {
		t.Fatal("recorded PodIP fallback did not activate the wildcard pod binding")
	}
}

func TestApplyTimeouts(t *testing.T) {
	request := 30 * time.Second
	backend := 5 * time.Second
	zero := time.Duration(0)
	tests := []struct {
		name          string
		timeouts      ir.Timeouts
		wantTimeout   time.Duration
		wantMaxStream *time.Duration
	}{
		{name: "request only", timeouts: ir.Timeouts{Request: &request}, wantTimeout: request},
		{name: "distinct request and backend", timeouts: ir.Timeouts{Request: &request, BackendRequest: &backend}, wantTimeout: backend, wantMaxStream: &request},
		{name: "explicit zero request", timeouts: ir.Timeouts{Request: &zero}, wantTimeout: zero, wantMaxStream: &zero},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := &routev3.RouteAction{}
			applyTimeouts(action, test.timeouts)
			if got := action.Timeout.AsDuration(); got != test.wantTimeout {
				t.Fatalf("timeout = %s, want %s", got, test.wantTimeout)
			}
			if test.wantMaxStream == nil {
				if action.MaxStreamDuration != nil {
					t.Fatalf("max stream duration = %v, want nil", action.MaxStreamDuration)
				}
				return
			}
			if action.MaxStreamDuration == nil || action.MaxStreamDuration.MaxStreamDuration.AsDuration() != *test.wantMaxStream {
				t.Fatalf("max stream duration = %v, want %s", action.MaxStreamDuration, *test.wantMaxStream)
			}
		})
	}
}

func TestReplacePrefixMatchRootAvoidsDoubleSlash(t *testing.T) {
	routes, err := buildRoutes(ir.Route{
		Name:  "strip-prefix",
		Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/strip-prefix"},
		Filters: ir.Filters{URLRewrite: &ir.URLRewrite{
			Path: &ir.PathModifier{Type: ir.PathModifierReplacePrefixMatch, Replace: "/"},
		}},
		Backends: []ir.BackendRef{{ClusterName: "backend", Weight: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	action := routes[0].GetRoute()
	if action.GetRegexRewrite() == nil {
		t.Fatal("root prefix replacement did not use a slash-safe regex rewrite")
	}
	if got := action.GetRegexRewrite().Pattern.Regex; got != "^/strip-prefix/?(.*)$" {
		t.Fatalf("rewrite pattern = %q", got)
	}
	if got := action.GetRegexRewrite().Substitution; got != "/\\1" {
		t.Fatalf("rewrite substitution = %q", got)
	}
}

func TestCORSRejectsNonMatchingPreflightLocally(t *testing.T) {
	typed, err := buildCORS(&ir.CORS{
		AllowOrigins: []string{"https://allowed.example"},
		AllowMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := &corsv3.CorsPolicy{}
	if err := typed.UnmarshalTo(policy); err != nil {
		t.Fatal(err)
	}
	if policy.ForwardNotMatchingPreflights == nil || policy.ForwardNotMatchingPreflights.Value {
		t.Fatal("non-matching CORS preflights must not be forwarded to the backend")
	}
}
func TestBuildAccessIsolationJWTAndPublicHeaderStripping(t *testing.T) {
	backend := ir.BackendRef{Name: "backend", ClusterName: "backend", Weight: 1}
	gateway := &ir.Gateway{
		Key:       types.NamespacedName{Namespace: "default", Name: "access"},
		Listeners: []ir.Listener{{Name: "http", Hostname: "tools.example.com", EnvoyPort: 18080}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected, StripAccessHeaders: true,
				VirtualHosts: []ir.VirtualHost{{Name: "public", Hostname: "tools.example.com", Routes: []ir.Route{{
					Name: "public-v1", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/v1"}, Backends: []ir.BackendRef{backend},
				}}}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access: &ir.AccessGuard{
					AUDs: []string{"reports-read", "", "reports-admin", "reports-read"}, TeamName: "team",
					AuthDomain: "team.cloudflareaccess.com", OptionsPreflightBypass: true,
				},
				VirtualHosts: []ir.VirtualHost{{Name: "protected", Hostname: "tools.example.com", Routes: []ir.Route{{
					Name: "dashboard", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}, Backends: []ir.BackendRef{backend},
				}}}},
			},
		},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}

	publicListener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-18080"].(*listenerv3.Listener)
	publicRoutes := routeConfigForChain(t, snapshot, publicListener.FilterChains[0])
	removed := publicRoutes.VirtualHosts[0].RequestHeadersToRemove
	for _, header := range accessIdentityHeaders {
		found := false
		for _, candidate := range removed {
			if candidate == header {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("public virtual host does not strip %q: %v", header, removed)
		}
	}

	protectedListener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-18081"].(*listenerv3.Listener)
	hcm := &hcmv3.HttpConnectionManager{}
	if err := protectedListener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	if len(hcm.HttpFilters) < 2 || hcm.HttpFilters[0].Name != jwtFilterName {
		t.Fatalf("protected HTTP filters = %#v", hcm.HttpFilters)
	}
	jwt := &jwtauthnv3.JwtAuthentication{}
	if err := hcm.HttpFilters[0].GetTypedConfig().UnmarshalTo(jwt); err != nil {
		t.Fatal(err)
	}
	provider := jwt.Providers["cloudflare-access"]
	if provider == nil || provider.Issuer != "https://team.cloudflareaccess.com" ||
		!slices.Equal(provider.Audiences, []string{"reports-admin", "reports-read"}) ||
		len(provider.FromHeaders) != 1 || provider.FromHeaders[0].Name != "Cf-Access-Jwt-Assertion" ||
		len(provider.FromCookies) != 1 || provider.FromCookies[0] != "CF_Authorization" || !provider.Forward {
		t.Fatalf("Cloudflare JWT provider = %#v", provider)
	}
	if len(jwt.Rules) != 2 || len(jwt.Rules[0].Match.Headers) != 1 ||
		jwt.Rules[0].Match.Headers[0].Name != ":method" ||
		jwt.Rules[0].Match.Headers[0].GetStringMatch().GetExact() != "OPTIONS" ||
		jwt.Rules[0].GetRequires() != nil || jwt.Rules[1].GetRequires().GetProviderName() != "cloudflare-access" {
		t.Fatalf("JWT preflight/enforcement rules = %#v", jwt.Rules)
	}
	if len(snapshot.GetResources(resourcev3.RouteType)) != 2 {
		t.Fatalf("public/protected route tables were merged: %#v", snapshot.GetResources(resourcev3.RouteType))
	}
	firstVersion, err := SnapshotVersion(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	gateway.Domains[1].Access.AUDs = []string{"reports-admin", "reports-read", "reports-admin"}
	secondSnapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondVersion, err := SnapshotVersion(secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if firstVersion != secondVersion {
		t.Fatalf("equivalent audience sets produced different xDS versions: %q and %q", firstVersion, secondVersion)
	}
}

func TestBuildJWKSClusterPinsIPv4TLSAndTimeouts(t *testing.T) {
	const authDomain = "team.cloudflareaccess.com"
	gateway := &ir.Gateway{
		Key:       types.NamespacedName{Namespace: "default", Name: "jwks"},
		Listeners: []ir.Listener{{Name: "http", Hostname: "reports.example.com", EnvoyPort: 18080}},
		Domains: []ir.ProtectionDomain{{
			Name: "protected", ListenerName: "http", EnvoyPort: 18080, Protected: true, Guard: ir.GuardForwarding,
			Access: &ir.AccessGuard{
				AUDs: []string{"reports-read"}, TeamName: "team", AuthDomain: authDomain,
			},
			VirtualHosts: []ir.VirtualHost{{Name: "protected", Hostname: "reports.example.com", Routes: []ir.Route{{
				Name: "dashboard", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
				Backends: []ir.BackendRef{{Name: "backend", ClusterName: "backend", Weight: 1}},
			}}}},
		}},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}

	jwksName := "flareway-jwks-" + shortHash(authDomain)
	cluster, ok := snapshot.GetResources(resourcev3.ClusterType)[jwksName].(*clusterv3.Cluster)
	if !ok {
		t.Fatalf("JWKS cluster %q missing from snapshot: %#v", jwksName, snapshot.GetResources(resourcev3.ClusterType))
	}
	if cluster.GetType() != clusterv3.Cluster_STRICT_DNS {
		t.Fatalf("JWKS cluster type = %v, want STRICT_DNS", cluster.GetType())
	}
	if cluster.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("JWKS cluster DNS lookup family = %v, want V4_ONLY", cluster.GetDnsLookupFamily())
	}
	if got := cluster.ConnectTimeout.AsDuration(); got != 10*time.Second {
		t.Fatalf("JWKS cluster connect timeout = %v, want 10s", got)
	}
	endpoints := cluster.LoadAssignment.GetEndpoints()
	if len(endpoints) != 1 || len(endpoints[0].LbEndpoints) != 1 {
		t.Fatalf("JWKS cluster endpoints = %#v", endpoints)
	}
	endpoint := endpoints[0].LbEndpoints[0].GetEndpoint()
	if endpoint.Hostname != authDomain ||
		endpoint.Address.GetSocketAddress().GetAddress() != authDomain ||
		endpoint.Address.GetSocketAddress().GetPortValue() != 443 {
		t.Fatalf("JWKS endpoint = %#v", endpoint)
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatal(err)
	}
	validation := tlsContext.CommonTlsContext.GetValidationContext()
	if tlsContext.Sni != authDomain ||
		validation.GetTrustedCa().GetFilename() != "/etc/ssl/certs/ca-certificates.crt" ||
		len(validation.MatchTypedSubjectAltNames) != 1 ||
		validation.MatchTypedSubjectAltNames[0].SanType != tlsv3.SubjectAltNameMatcher_DNS ||
		validation.MatchTypedSubjectAltNames[0].Matcher.GetExact() != authDomain {
		t.Fatalf("JWKS upstream TLS context = %#v", tlsContext)
	}

	listener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-18080"].(*listenerv3.Listener)
	hcm := &hcmv3.HttpConnectionManager{}
	if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	jwt := &jwtauthnv3.JwtAuthentication{}
	if err := hcm.HttpFilters[0].GetTypedConfig().UnmarshalTo(jwt); err != nil {
		t.Fatal(err)
	}
	remote := jwt.Providers["cloudflare-access"].GetRemoteJwks()
	if remote == nil {
		t.Fatal("Cloudflare provider does not use remote JWKS")
	}
	if remote.HttpUri.Uri != "https://"+authDomain+"/cdn-cgi/access/certs" ||
		remote.HttpUri.GetCluster() != jwksName ||
		remote.HttpUri.Timeout.AsDuration() != 10*time.Second {
		t.Fatalf("remote JWKS HTTP URI = %#v", remote.HttpUri)
	}
}

func TestBuildRejectsProtectedEmptyAUDSet(t *testing.T) {
	for _, test := range []struct {
		name   string
		access *ir.AccessGuard
	}{
		{name: "absent"},
		{name: "empty", access: &ir.AccessGuard{AUDs: []string{"", ""}, AuthDomain: "team.cloudflareaccess.com"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := &ir.Gateway{
				Key:       types.NamespacedName{Namespace: "default", Name: "empty-aud"},
				Listeners: []ir.Listener{{Name: "http", EnvoyPort: 18080}},
				Domains: []ir.ProtectionDomain{{
					Name: "protected", ListenerName: "http", EnvoyPort: 18080, Protected: true, Guard: ir.GuardForwarding,
					Access:       test.access,
					VirtualHosts: []ir.VirtualHost{{Name: "protected", Hostname: "reports.example.com"}},
				}},
			}
			if _, err := Build(gateway, nil); err == nil {
				t.Fatal("Build() accepted a protected forwarding domain without an audience")
			}
		})
	}
}

// Envoy resources are addressed by name, and a snapshot keeps one resource per
// name. Two route tables that land on the same name would leave one listener
// serving the other listener's hosts, so Build must refuse instead of letting
// the snapshot drop one of them.
func TestBuildRejectsRouteTablesThatShareAName(t *testing.T) {
	access := &ir.AccessGuard{AUDs: []string{"aud"}, AuthDomain: "team.cloudflareaccess.com"}
	domain := func(name string, port int32, host string) ir.ProtectionDomain {
		return ir.ProtectionDomain{
			Name: name, ListenerName: "preview", EnvoyPort: port, Protected: true, Guard: ir.GuardForwarding, Access: access,
			VirtualHosts: []ir.VirtualHost{{Name: host, Hostname: host}},
		}
	}
	for _, test := range []struct {
		name    string
		domains []ir.ProtectionDomain
	}{
		{name: "same domain name on two ports", domains: []ir.ProtectionDomain{
			domain("preview-access", 18082, "app1.example.com"),
			domain("preview-access", 18083, "app2.example.com"),
		}},
		{name: "names that normalize to one resource name", domains: []ir.ProtectionDomain{
			domain("preview/access", 18082, "app1.example.com"),
			domain("preview-access", 18083, "app2.example.com"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := &ir.Gateway{
				Key:       types.NamespacedName{Namespace: "default", Name: "collision"},
				Listeners: []ir.Listener{{Name: "preview", Hostname: "*.example.com", EnvoyPort: 18081}},
				Domains:   test.domains,
			}
			if _, err := Build(gateway, nil); err == nil {
				t.Fatal("Build() published two route tables under one name")
			}
		})
	}
}

func TestBuildBlockedProtectionDomainReturns403WithoutJWTConfig(t *testing.T) {
	gateway := &ir.Gateway{
		Key:       types.NamespacedName{Namespace: "default", Name: "blocked-access"},
		Listeners: []ir.Listener{{Name: "http", Hostname: "admin.example.com", EnvoyPort: 18080}},
		Domains: []ir.ProtectionDomain{{
			Name: "blocked", ListenerName: "http", EnvoyPort: 18080, Protected: true, Guard: ir.GuardBlocked,
			VirtualHosts: []ir.VirtualHost{{Name: "blocked", Hostname: "admin.example.com"}},
		}},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-18080"].(*listenerv3.Listener)
	routes := routeConfigForChain(t, snapshot, listener.FilterChains[0])
	if got := directStatusForDomain(t, routes, "admin.example.com"); got != 403 {
		t.Fatalf("blocked origin status = %d, want 403", got)
	}
	hcm := &hcmv3.HttpConnectionManager{}
	if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	for _, filter := range hcm.HttpFilters {
		if filter.Name == jwtFilterName {
			t.Fatal("blocked no-AUD domain unexpectedly contains jwt_authn")
		}
	}
}

func TestBuildPublicWildcardBlocksProtectedExactHostname(t *testing.T) {
	gateway := &ir.Gateway{
		Key: types.NamespacedName{Namespace: "default", Name: "wildcard-isolation"},
		Listeners: []ir.Listener{
			{Name: "wildcard", Hostname: "*.example.com", EnvoyPort: 18080},
			{Name: "exact", Hostname: "admin.example.com", EnvoyPort: 18081},
		},
		Domains: []ir.ProtectionDomain{
			{
				Name: "wildcard-public", ListenerName: "wildcard", EnvoyPort: 18080, Guard: ir.GuardUnprotected, StripAccessHeaders: true,
				VirtualHosts: []ir.VirtualHost{{Name: "wildcard", Hostname: "*.example.com"}},
			},
			{
				Name: "exact-protected", ListenerName: "exact", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud"}, AuthDomain: "team.cloudflareaccess.com"},
				VirtualHosts: []ir.VirtualHost{{Name: "exact", Hostname: "admin.example.com"}},
			},
		},
	}
	snapshot, err := Build(gateway, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicListener := snapshot.GetResources(resourcev3.ListenerType)["127.0.0.1-18080"].(*listenerv3.Listener)
	publicRoutes := routeConfigForChain(t, snapshot, publicListener.FilterChains[0])
	if got := directStatusForDomain(t, publicRoutes, "admin.example.com"); got != 403 {
		t.Fatalf("protected exact hostname on public wildcard listener = %d, want 403", got)
	}
}

func chainForServerName(t *testing.T, listener *listenerv3.Listener, serverName string) *listenerv3.FilterChain {
	t.Helper()
	for _, chain := range listener.FilterChains {
		names := chain.GetFilterChainMatch().GetServerNames()
		if len(names) == 1 && names[0] == serverName {
			return chain
		}
	}
	t.Fatalf("filter chain for server name %q not found", serverName)
	return nil
}

func routeConfigForChain(t *testing.T, snapshot *cachev3.Snapshot, chain *listenerv3.FilterChain) *routev3.RouteConfiguration {
	t.Helper()
	hcm := &hcmv3.HttpConnectionManager{}
	if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	resource := snapshot.GetResources(resourcev3.RouteType)[hcm.GetRds().RouteConfigName]
	if resource == nil {
		t.Fatalf("route config %q not found", hcm.GetRds().RouteConfigName)
	}
	return resource.(*routev3.RouteConfiguration)
}

func directStatusForDomain(t *testing.T, routeConfig *routev3.RouteConfiguration, domain string) uint32 {
	t.Helper()
	for _, virtualHost := range routeConfig.VirtualHosts {
		if len(virtualHost.Domains) == 1 && virtualHost.Domains[0] == domain {
			routes := virtualHost.Routes
			if len(routes) == 0 || routes[len(routes)-1].GetDirectResponse() == nil {
				t.Fatalf("domain %q has no direct response", domain)
			}
			return routes[len(routes)-1].GetDirectResponse().Status
		}
	}
	t.Fatalf("domain %q not found", domain)
	return 0
}

func projectSnapshot(snapshot *cachev3.Snapshot) (goldenProjection, error) {
	version, err := SnapshotVersion(snapshot)
	if err != nil {
		return goldenProjection{}, err
	}
	listener, ok := snapshot.GetResources(resourcev3.ListenerType)["0.0.0.0-10443"].(*listenerv3.Listener)
	if !ok {
		return goldenProjection{}, fmt.Errorf("listener resource not found")
	}
	listenerProjection, err := listenerDetails(listener)
	if err != nil {
		return goldenProjection{}, err
	}
	routeConfig, ok := snapshot.GetResources(resourcev3.RouteType)["public"].(*routev3.RouteConfiguration)
	if !ok {
		return goldenProjection{}, fmt.Errorf("route resource not found")
	}
	listenerProjection.IgnorePortInHostMatching = routeConfig.IgnorePortInHostMatching
	routes := make([]routeProjection, 0, len(routeConfig.VirtualHosts[0].Routes))
	for _, route := range routeConfig.VirtualHosts[0].Routes {
		routes = append(routes, routeDetails(route))
	}
	cluster, ok := snapshot.GetResources(resourcev3.ClusterType)["backend-a"].(*clusterv3.Cluster)
	if !ok {
		return goldenProjection{}, fmt.Errorf("cluster resource not found")
	}
	clusterProjection, err := clusterDetails(cluster)
	if err != nil {
		return goldenProjection{}, err
	}
	assignment, ok := snapshot.GetResources(resourcev3.EndpointType)["backend-a"].(*endpointv3.ClusterLoadAssignment)
	if !ok {
		return goldenProjection{}, fmt.Errorf("endpoint resource not found")
	}
	endpoint := assignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress()
	secret, ok := snapshot.GetResources(resourcev3.SecretType)["listener-cert"].(*tlsv3.Secret)
	if !ok {
		return goldenProjection{}, fmt.Errorf("secret resource not found")
	}
	return goldenProjection{
		VersionLength: len(version),
		Listener:      listenerProjection,
		Routes:        routes,
		Cluster:       clusterProjection,
		Endpoint:      net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.GetPortValue()))),
		Secret:        secret.Name,
	}, nil
}

func listenerDetails(listener *listenerv3.Listener) (listenerProjection, error) {
	chain := listener.FilterChains[0]
	hcm := &hcmv3.HttpConnectionManager{}
	if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		return listenerProjection{}, err
	}
	tlsContext := &tlsv3.DownstreamTlsContext{}
	if err := chain.TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		return listenerProjection{}, err
	}
	return listenerProjection{
		Address:            listener.Address.GetSocketAddress().Address,
		Port:               listener.Address.GetSocketAddress().GetPortValue(),
		ServerNames:        chain.GetFilterChainMatch().GetServerNames(),
		TLSSecret:          tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].Name,
		RouteConfig:        hcm.GetRds().RouteConfigName,
		NormalizePath:      hcm.GetNormalizePath().GetValue(),
		MergeSlashes:       hcm.MergeSlashes,
		EscapedSlashAction: hcm.PathWithEscapedSlashesAction.String(),
		StreamIdleTimeout:  hcm.StreamIdleTimeout.AsDuration().String(),
		ConnectionIdle:     hcm.CommonHttpProtocolOptions.IdleTimeout.AsDuration().String(),
		Websocket:          len(hcm.UpgradeConfigs) == 1 && hcm.UpgradeConfigs[0].UpgradeType == "websocket",
		TLSInspector:       len(listener.ListenerFilters) == 1 && listener.ListenerFilters[0].Name == "envoy.filters.listener.tls_inspector",
		ALPN:               append([]string(nil), tlsContext.CommonTlsContext.AlpnProtocols...),
	}, nil
}

func routeDetails(route *routev3.Route) routeProjection {
	out := routeProjection{Name: route.Name, CORS: route.TypedPerFilterConfig[corsFilterName] != nil}
	switch {
	case route.GetDirectResponse() != nil:
		out.Action = fmt.Sprintf("direct-%d", route.GetDirectResponse().Status)
	case route.GetRedirect() != nil:
		out.Action = "redirect"
		out.RedirectCode = route.GetRedirect().ResponseCode.String()
	case route.GetRoute() != nil:
		out.Action = "route"
		for _, cluster := range route.GetRoute().GetWeightedClusters().Clusters {
			out.Clusters = append(out.Clusters, fmt.Sprintf("%s:%d", cluster.Name, cluster.Weight.GetValue()))
		}
		out.PathRewrite = route.GetRoute().PathRewrite
		out.HostRewrite = route.GetRoute().GetHostRewriteLiteral()
		if route.GetRoute().Timeout != nil {
			out.Timeout = route.GetRoute().Timeout.AsDuration().String()
		}
	}
	if route.Match.RuntimeFraction != nil {
		out.RuntimeNumerator = route.Match.RuntimeFraction.DefaultValue.Numerator
	}
	return out
}

func clusterDetails(cluster *clusterv3.Cluster) (clusterProjection, error) {
	protocol := &upstreamhttpv3.HttpProtocolOptions{}
	if err := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsKey].UnmarshalTo(protocol); err != nil {
		return clusterProjection{}, err
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		return clusterProjection{}, err
	}
	out := clusterProjection{
		Name:       cluster.Name,
		Type:       cluster.GetType().String(),
		EDSService: cluster.EdsClusterConfig.ServiceName,
		HTTP2:      protocol.GetExplicitHttpConfig().GetHttp2ProtocolOptions() != nil,
		SNI:        tlsContext.Sni,
	}
	for _, san := range tlsContext.CommonTlsContext.GetValidationContext().MatchTypedSubjectAltNames {
		out.SANs = append(out.SANs, san.SanType.String()+":"+san.Matcher.GetExact())
	}
	return out, nil
}
