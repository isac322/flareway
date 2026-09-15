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

package cloudflared

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/isac322/flareway/internal/ir"
	"k8s.io/apimachinery/pkg/types"
)

var updateGoldens = flag.Bool("update", false, "update cloudflared golden files")

func TestCompileGoldenAndDeterministicHash(t *testing.T) {
	gateway := testGateway()
	params, hash, err := Compile(gateway)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	payload, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	payload = append(payload, '\n')
	const goldenPath = "testdata/public-protected-blocked.golden.json"
	if *updateGoldens {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("create golden directory: %v", err)
		}
		if err := os.WriteFile(goldenPath, payload, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	// The former hardcoded true disabled Happy Eyeballs. The supported default
	// is false; every other byte of the Gateway-mode configuration remains
	// compatible with the existing golden.
	want = bytes.ReplaceAll(want, []byte(`"noHappyEyeballs": true`), []byte(`"noHappyEyeballs": false`))
	if string(payload) != string(want) {
		t.Fatalf("compiled configuration differs from golden\ngot:\n%s\nwant:\n%s", payload, want)
	}

	configPayload, err := json.Marshal(compileConfig(gateway))
	if err != nil {
		t.Fatalf("marshal config for hash: %v", err)
	}
	digest := sha256.Sum256(configPayload)
	if hash != hex.EncodeToString(digest[:]) {
		t.Fatalf("hash = %q, want SHA-256 of config %q", hash, hex.EncodeToString(digest[:]))
	}

	second, secondHash, err := Compile(gateway)
	if err != nil {
		t.Fatalf("second Compile() error = %v", err)
	}
	secondPayload, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second params: %v", err)
	}
	var compact bytesBody
	if err := json.Unmarshal(payload, &compact); err != nil {
		t.Fatalf("compact first params: %v", err)
	}
	firstPayload, _ := json.Marshal(compact)
	if string(secondPayload) != string(firstPayload) || secondHash != hash {
		t.Fatalf("Compile is not deterministic: first hash %q second %q", hash, secondHash)
	}
}

type bytesBody struct {
	Config json.RawMessage `json:"config"`
}

func TestCompileTeardownBlocksBeforeCatchAll(t *testing.T) {
	gateway := testGateway()
	gateway.Cloudflare.Teardown = true
	params, _, err := Compile(gateway)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	var request struct {
		Config struct {
			Ingress []struct {
				Hostname string `json:"hostname"`
				Service  string `json:"service"`
			} `json:"ingress"`
		} `json:"config"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if len(request.Config.Ingress) != 4 {
		t.Fatalf("ingress count = %d, want three hostname blocks plus catch-all", len(request.Config.Ingress))
	}
	for i, rule := range request.Config.Ingress[:len(request.Config.Ingress)-1] {
		if rule.Hostname == "" || rule.Service != "http_status:403" {
			t.Fatalf("rule %d = %#v, want hostname 403", i, rule)
		}
	}
	if got := request.Config.Ingress[len(request.Config.Ingress)-1].Service; got != "http_status:404" {
		t.Fatalf("catch-all = %q, want http_status:404", got)
	}
}

func TestCompileNestedPublicCarveOutBeforeProtected(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				IngressPaths: []ir.PathMatch{
					{Type: ir.PathMatchPathPrefix, Value: "/v1"},
					{Type: ir.PathMatchPathPrefix, Value: "/backend-api/tools"},
				},
				VirtualHosts: []ir.VirtualHost{{Hostname: "tools.example.com", Routes: []ir.Route{
					{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/v1"}},
					{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/backend-api/tools"}},
				}}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud-tools"}, TeamName: "team"},
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "tools.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}}}}},
			},
		},
	}
	payload, err := json.Marshal(compileConfig(gateway))
	if err != nil {
		t.Fatalf("marshal compiled config: %v", err)
	}
	var config struct {
		Ingress []struct {
			Path          string         `json:"path"`
			Service       string         `json:"service"`
			OriginRequest *originRequest `json:"originRequest"`
		} `json:"ingress"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("decode compiled config: %v", err)
	}
	if len(config.Ingress) != 4 {
		t.Fatalf("ingress = %#v", config.Ingress)
	}
	if config.Ingress[0].Path != "^/backend-api/tools(/|$)" || config.Ingress[1].Path != "^/v1(/|$)" {
		t.Fatalf("public carve-outs are not ordered most-specific first: %#v", config.Ingress)
	}
	if config.Ingress[0].OriginRequest == nil || config.Ingress[0].OriginRequest.Access != nil ||
		config.Ingress[1].OriginRequest == nil || config.Ingress[1].OriginRequest.Access != nil {
		t.Fatalf("public carve-outs contain Access validation: %#v", config.Ingress[:2])
	}
	if config.Ingress[2].Service != "http://127.0.0.1:18081" || config.Ingress[2].OriginRequest == nil ||
		config.Ingress[2].OriginRequest.Access == nil || config.Ingress[2].OriginRequest.Access.AUDTag[0] != "aud-tools" {
		t.Fatalf("protected remainder = %#v", config.Ingress[2])
	}
}

func TestCompileCanonicalizesMultipleAUDsForHost(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "reports", ListenerName: "http", EnvoyPort: 18080, Protected: true, Guard: ir.GuardForwarding,
			Access: &ir.AccessGuard{
				AUDs:     []string{"reports-read", "", "reports-admin", "reports-read"},
				TeamName: "team",
			},
			VirtualHosts: []ir.VirtualHost{{Hostname: "reports.example.com"}},
		}},
	}

	config := compileConfig(gateway)
	if len(config.Ingress) != 2 || config.Ingress[0].OriginRequest == nil || config.Ingress[0].OriginRequest.Access == nil {
		t.Fatalf("Reports ingress = %#v", config.Ingress)
	}
	if got, want := config.Ingress[0].OriginRequest.Access.AUDTag, []string{"reports-admin", "reports-read"}; !slices.Equal(got, want) {
		t.Fatalf("audTag = %v, want %v", got, want)
	}

	_, firstHash, err := Compile(gateway)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	gateway.Domains[0].Access.AUDs = []string{"reports-admin", "reports-read", "reports-admin"}
	_, secondHash, err := Compile(gateway)
	if err != nil {
		t.Fatalf("second Compile() error = %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("equivalent audience sets produced different hashes: %q and %q", firstHash, secondHash)
	}
}

func TestCompileEmptyAUDSetBlocksProtectedRemainderAfterCarveOut(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/v1"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "tools.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/v1"}}}}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"", ""}, TeamName: "team"},
				VirtualHosts: []ir.VirtualHost{{Hostname: "tools.example.com"}},
			},
		},
	}
	config := compileConfig(gateway)
	if len(config.Ingress) != 3 || config.Ingress[0].Path != "^/v1(/|$)" || config.Ingress[1].Service != "http_status:403" {
		t.Fatalf("empty AUD set fail-closed order = %#v", config.Ingress)
	}
}

func TestCompileHostnameSpecificityPrecedesProtectionCategory(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners: []ir.Listener{
			{Name: "wildcard", Exposure: ir.ExposurePublic},
			{Name: "exact", Exposure: ir.ExposurePublic},
		},
		Domains: []ir.ProtectionDomain{
			{
				Name: "wildcard-public", ListenerName: "wildcard", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "*.example.com"}},
			},
			{
				Name: "exact-protected", ListenerName: "exact", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud-exact"}, TeamName: "team"},
				VirtualHosts: []ir.VirtualHost{{Hostname: "admin.example.com"}},
			},
		},
	}
	config := compileConfig(gateway)
	if len(config.Ingress) != 3 || config.Ingress[0].Hostname != "admin.example.com" ||
		config.Ingress[0].OriginRequest == nil || config.Ingress[0].OriginRequest.Access == nil ||
		config.Ingress[1].Hostname != "*.example.com" {
		t.Fatalf("hostname specificity ordering = %#v", config.Ingress)
	}
}

func TestCompileMoreSpecificProtectedApplicationPathFirst(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "parent", ListenerName: "http", EnvoyPort: 18080, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud-parent"}, TeamName: "team"},
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "app.example.com"}},
			},
			{
				Name: "child", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud-child"}, TeamName: "team"},
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/admin"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "app.example.com"}},
			},
		},
	}
	config := compileConfig(gateway)
	if len(config.Ingress) != 3 || config.Ingress[0].Path != "^/admin(/|$)" ||
		config.Ingress[0].OriginRequest.Access.AUDTag[0] != "aud-child" ||
		config.Ingress[1].OriginRequest.Access.AUDTag[0] != "aud-parent" {
		t.Fatalf("protected path specificity ordering = %#v", config.Ingress)
	}
}

func TestCompileGatewayUsesEffectiveReachableOriginSettings(t *testing.T) {
	gateway := testGateway()
	connectTimeout := 11 * time.Second
	keepAliveTimeout := 12 * time.Second
	tcpKeepAlive := 13 * time.Second
	keepAliveConnections := int64(14)
	noHappyEyeballs := true
	disableChunkedEncoding := true
	http2Origin := true
	gateway.Cloudflare.OriginRequest = ir.GatewayOriginRequest{
		ConnectTimeout:         &connectTimeout,
		KeepAliveTimeout:       &keepAliveTimeout,
		TCPKeepAlive:           &tcpKeepAlive,
		KeepAliveConnections:   &keepAliveConnections,
		NoHappyEyeballs:        &noHappyEyeballs,
		DisableChunkedEncoding: &disableChunkedEncoding,
		HTTP2Origin:            &http2Origin,
	}

	config := compileConfig(gateway)
	assertGatewayOrigin := func(origin *originRequest) {
		t.Helper()
		if origin == nil ||
			origin.ConnectTimeout == nil || *origin.ConnectTimeout != 11 ||
			origin.KeepAliveTimeout == nil || *origin.KeepAliveTimeout != 12 ||
			origin.TCPKeepAlive == nil || *origin.TCPKeepAlive != 13 ||
			origin.KeepAliveConnections == nil || *origin.KeepAliveConnections != 14 ||
			origin.NoHappyEyeballs == nil || !*origin.NoHappyEyeballs ||
			origin.DisableChunkedEncoding == nil || !*origin.DisableChunkedEncoding ||
			origin.HTTP2Origin == nil || !*origin.HTTP2Origin {
			t.Fatalf("originRequest = %#v", origin)
		}
	}
	assertGatewayOrigin(config.OriginRequest)
	for _, rule := range config.Ingress {
		if strings.HasPrefix(rule.Service, "http://127.0.0.1:") {
			assertGatewayOrigin(rule.OriginRequest)
		}
	}

	fractional := 1500 * time.Millisecond
	gateway.Cloudflare.OriginRequest.ConnectTimeout = &fractional
	if _, _, err := Compile(gateway); err == nil || !strings.Contains(err.Error(), "whole-second precision") {
		t.Fatalf("Compile() error = %v, want whole-second precision rejection", err)
	}
}

func TestCompileDirectSerializesCompleteConfigurationDeterministically(t *testing.T) {
	connectTimeout := int64(3)
	tlsTimeout := int64(4)
	tcpKeepAlive := int64(5)
	keepAliveTimeout := int64(6)
	keepAliveConnections := int64(7)
	noHappyEyeballs := true
	matchSNIToHost := true
	noTLSVerify := false
	disableChunkedEncoding := true
	http2Origin := true
	httpHostHeader := "origin.example.com"
	originServerName := "tls.example.com"
	caPool := "/etc/cloudflared/ca.pem"
	proxyType := ir.OriginProxyTypeSOCKS5
	required := true
	warpEnabled := true
	maxActiveFlows := int64(9007199254740993)

	origin := ir.OriginRequest{
		Access: &ir.OriginAccess{
			AUDTags:  []string{"aud-z", "", "aud-a", "aud-z"},
			TeamName: "my-team",
			Required: &required,
		},
		CAPool:                 &caPool,
		ConnectTimeout:         &connectTimeout,
		DisableChunkedEncoding: &disableChunkedEncoding,
		HTTP2Origin:            &http2Origin,
		HTTPHostHeader:         &httpHostHeader,
		KeepAliveConnections:   &keepAliveConnections,
		KeepAliveTimeout:       &keepAliveTimeout,
		MatchSNIToHost:         &matchSNIToHost,
		NoHappyEyeballs:        &noHappyEyeballs,
		NoTLSVerify:            &noTLSVerify,
		OriginServerName:       &originServerName,
		ProxyType:              &proxyType,
		TCPKeepAlive:           &tcpKeepAlive,
		TLSTimeout:             &tlsTimeout,
		IPRules: []ir.OriginIPRule{
			{Prefix: "10.0.0.0/8", Ports: []int32{22, 443}, Allow: true},
			{Prefix: "0.0.0.0/0", Allow: false},
		},
	}

	address := func(value string) *ir.TunnelAddressService {
		return &ir.TunnelAddressService{Address: value}
	}
	unix := func(value string) *ir.TunnelUnixService {
		return &ir.TunnelUnixService{Path: value}
	}
	builtin := func() *ir.TunnelBuiltinService {
		return &ir.TunnelBuiltinService{}
	}
	services := []struct {
		service ir.TunnelIngressService
		wire    string
	}{
		{service: ir.TunnelIngressService{HTTP: address("origin.example.com:80")}, wire: "http://origin.example.com:80"},
		{service: ir.TunnelIngressService{HTTPS: address("origin.example.com:443")}, wire: "https://origin.example.com:443"},
		{service: ir.TunnelIngressService{TCP: address("origin.example.com:9000")}, wire: "tcp://origin.example.com:9000"},
		{service: ir.TunnelIngressService{SSH: address("origin.example.com:22")}, wire: "ssh://origin.example.com:22"},
		{service: ir.TunnelIngressService{RDP: address("origin.example.com:3389")}, wire: "rdp://origin.example.com:3389"},
		{service: ir.TunnelIngressService{SMB: address("origin.example.com:445")}, wire: "smb://origin.example.com:445"},
		{service: ir.TunnelIngressService{Unix: unix("/var/run/origin.sock")}, wire: "unix:/var/run/origin.sock"},
		{service: ir.TunnelIngressService{UnixTLS: unix("/var/run/origin-tls.sock")}, wire: "unix+tls:/var/run/origin-tls.sock"},
		{service: ir.TunnelIngressService{HelloWorld: builtin()}, wire: "hello_world"},
		{service: ir.TunnelIngressService{HTTPStatus: &ir.TunnelHTTPStatusService{Code: 204}}, wire: "http_status:204"},
		{service: ir.TunnelIngressService{Bastion: builtin()}, wire: "bastion"},
	}
	ingress := make([]ir.TunnelIngress, 0, len(services)+1)
	for index, service := range services {
		rule := ir.TunnelIngress{
			Hostname: "service-" + string(rune('a'+index)) + ".example.com",
			Path:     "^/ready$",
			Service:  service.service,
		}
		if index == 0 {
			rule.OriginRequest = &origin
		}
		ingress = append(ingress, rule)
	}
	ingress = append(ingress, ir.TunnelIngress{
		Service: ir.TunnelIngressService{HTTPStatus: &ir.TunnelHTTPStatusService{Code: 404}},
	})

	configuration := ir.TunnelConfiguration{
		Ingress:       ingress,
		OriginRequest: &origin,
		WARPRouting: &ir.WARPRouting{
			Enabled:        &warpEnabled,
			ConnectTimeout: &connectTimeout,
			TCPKeepAlive:   &tcpKeepAlive,
			MaxActiveFlows: &maxActiveFlows,
		},
	}
	params, hash, err := CompileDirect("account-id", configuration)
	if err != nil {
		t.Fatalf("CompileDirect() error = %v", err)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal direct params: %v", err)
	}
	var body bytesBody
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode direct params: %v", err)
	}
	var got configBody
	if err := json.Unmarshal(body.Config, &got); err != nil {
		t.Fatalf("decode direct config: %v", err)
	}
	if len(got.Ingress) != len(services)+1 {
		t.Fatalf("ingress count = %d, want %d", len(got.Ingress), len(services)+1)
	}
	for index, service := range services {
		if got.Ingress[index].Service != service.wire {
			t.Fatalf("ingress[%d].service = %q, want %q", index, got.Ingress[index].Service, service.wire)
		}
	}
	if got.Ingress[len(got.Ingress)-1].Hostname != "" || got.Ingress[len(got.Ingress)-1].Path != "" ||
		got.Ingress[len(got.Ingress)-1].Service != "http_status:404" {
		t.Fatalf("final ingress rule = %#v, want catch-all", got.Ingress[len(got.Ingress)-1])
	}
	assertCompleteOrigin(t, got.OriginRequest)
	assertCompleteOrigin(t, got.Ingress[0].OriginRequest)
	if got.WARPRouting == nil || got.WARPRouting.Enabled == nil || !*got.WARPRouting.Enabled ||
		got.WARPRouting.ConnectTimeout == nil || *got.WARPRouting.ConnectTimeout != 3 ||
		got.WARPRouting.TCPKeepAlive == nil || *got.WARPRouting.TCPKeepAlive != 5 ||
		got.WARPRouting.MaxActiveFlows == nil || *got.WARPRouting.MaxActiveFlows != 9007199254740993 {
		t.Fatalf("warp-routing = %#v", got.WARPRouting)
	}
	configPayload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal direct config: %v", err)
	}
	digest := sha256.Sum256(configPayload)
	if hash != hex.EncodeToString(digest[:]) {
		t.Fatalf("hash = %q, want SHA-256 %q", hash, hex.EncodeToString(digest[:]))
	}

	configuration.OriginRequest.Access.AUDTags = []string{"aud-a", "aud-z", "aud-a"}
	configuration.Ingress[0].OriginRequest.Access.AUDTags = []string{"aud-z", "aud-a"}
	configuration.OriginRequest.IPRules[0].Ports = []int32{443, 22, 443}
	second, secondHash, err := CompileDirect("different-account-id", configuration)
	if err != nil {
		t.Fatalf("second CompileDirect() error = %v", err)
	}
	secondPayload, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second direct params: %v", err)
	}
	if hash != secondHash || !bytes.Equal(payload, secondPayload) {
		t.Fatalf("equivalent direct configs were not deterministic: hashes %q and %q", hash, secondHash)
	}
}

func TestCompileDirectOmitsOptionalConfiguration(t *testing.T) {
	params, _, err := CompileDirect("account-id", ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{{
		Service: ir.TunnelIngressService{HTTPStatus: &ir.TunnelHTTPStatusService{Code: 404}},
	}}})
	if err != nil {
		t.Fatalf("CompileDirect() error = %v", err)
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal direct params: %v", err)
	}
	if bytes.Contains(payload, []byte(`originRequest`)) || bytes.Contains(payload, []byte(`warp-routing`)) {
		t.Fatalf("optional configuration was zero-filled: %s", payload)
	}

	regular := ir.OriginProxyTypeRegular
	params, _, err = CompileDirect("account-id", ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
		{
			Hostname: "app.example.com",
			Service:  ir.TunnelIngressService{HTTP: &ir.TunnelAddressService{Address: "origin.example.com:80"}},
			OriginRequest: &ir.OriginRequest{
				ProxyType: &regular,
			},
		},
		{Service: ir.TunnelIngressService{HTTPStatus: &ir.TunnelHTTPStatusService{Code: 404}}},
	}})
	if err != nil {
		t.Fatalf("CompileDirect(Regular proxy) error = %v", err)
	}
	payload, err = json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal Regular proxy params: %v", err)
	}
	if bytes.Contains(payload, []byte(`proxyType`)) {
		t.Fatalf("default Regular proxyType was not omitted: %s", payload)
	}
}

func TestCompileDirectRejectsInvalidConfiguration(t *testing.T) {
	negative := int64(-1)
	required := true
	status404 := ir.TunnelIngressService{HTTPStatus: &ir.TunnelHTTPStatusService{Code: 404}}
	access := &ir.OriginRequest{Access: &ir.OriginAccess{Required: &required, TeamName: "team", AUDTags: []string{"aud"}}}
	tests := []struct {
		name   string
		config ir.TunnelConfiguration
		match  string
	}{
		{name: "empty ingress", match: "ingress is empty"},
		{
			name: "catch-all before final",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Service: status404},
				{Service: status404},
			}},
			match: "catch-all rule before the final rule",
		},
		{
			name: "missing final catch-all",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{{
				Hostname: "app.example.com",
				Service:  ir.TunnelIngressService{HTTP: &ir.TunnelAddressService{Address: "origin.example.com:80"}},
			}}},
			match: "must be the catch-all rule",
		},
		{
			name: "invalid path regex",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Hostname: "app.example.com", Path: "[", Service: ir.TunnelIngressService{HelloWorld: &ir.TunnelBuiltinService{}}},
				{Service: status404},
			}},
			match: "not a valid regular expression",
		},
		{
			name: "multiple services",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Hostname: "app.example.com", Service: ir.TunnelIngressService{
					HTTP:  &ir.TunnelAddressService{Address: "origin.example.com:80"},
					HTTPS: &ir.TunnelAddressService{Address: "origin.example.com:443"},
				}},
				{Service: status404},
			}},
			match: "must select exactly one service",
		},
		{
			name: "invalid address",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Hostname: "app.example.com", Service: ir.TunnelIngressService{HTTP: &ir.TunnelAddressService{Address: "origin.example.com"}}},
				{Service: status404},
			}},
			match: "must be a host:port pair",
		},
		{
			name: "access on non HTTP service",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Hostname: "ssh.example.com", Service: ir.TunnelIngressService{SSH: &ir.TunnelAddressService{Address: "origin.example.com:22"}}, OriginRequest: access},
				{Service: status404},
			}},
			match: "access is only valid for HTTP origins",
		},
		{
			name: "IP rules on standard origin",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{
					Hostname:      "app.example.com",
					Service:       ir.TunnelIngressService{HTTP: &ir.TunnelAddressService{Address: "origin.example.com:80"}},
					OriginRequest: &ir.OriginRequest{IPRules: []ir.OriginIPRule{{Prefix: "10.0.0.0/8"}}},
				},
				{Service: status404},
			}},
			match: "ipRules requires Bastion or SOCKS5 proxy service",
		},
		{
			name: "invalid CIDR",
			config: ir.TunnelConfiguration{Ingress: []ir.TunnelIngress{
				{Hostname: "bastion.example.com", Service: ir.TunnelIngressService{Bastion: &ir.TunnelBuiltinService{}}, OriginRequest: &ir.OriginRequest{IPRules: []ir.OriginIPRule{{Prefix: "not-a-cidr"}}}},
				{Service: status404},
			}},
			match: "not a valid CIDR",
		},
		{
			name: "negative duration",
			config: ir.TunnelConfiguration{
				Ingress:       []ir.TunnelIngress{{Service: status404}},
				OriginRequest: &ir.OriginRequest{ConnectTimeout: &negative},
			},
			match: "must not be negative",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := CompileDirect("account-id", test.config)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("CompileDirect() error = %v, want containing %q", err, test.match)
			}
		})
	}
}

func assertCompleteOrigin(t *testing.T, origin *originRequest) {
	t.Helper()
	if origin == nil ||
		origin.Access == nil || origin.Access.Required == nil || !*origin.Access.Required ||
		origin.Access.TeamName != "my-team" ||
		!slices.Equal(origin.Access.AUDTag, []string{"aud-a", "aud-z"}) ||
		origin.CAPool == nil || *origin.CAPool != "/etc/cloudflared/ca.pem" ||
		origin.ConnectTimeout == nil || *origin.ConnectTimeout != 3 ||
		origin.DisableChunkedEncoding == nil || !*origin.DisableChunkedEncoding ||
		origin.HTTP2Origin == nil || !*origin.HTTP2Origin ||
		origin.HTTPHostHeader == nil || *origin.HTTPHostHeader != "origin.example.com" ||
		origin.KeepAliveConnections == nil || *origin.KeepAliveConnections != 7 ||
		origin.KeepAliveTimeout == nil || *origin.KeepAliveTimeout != 6 ||
		origin.MatchSNIToHost == nil || !*origin.MatchSNIToHost ||
		origin.NoHappyEyeballs == nil || !*origin.NoHappyEyeballs ||
		origin.NoTLSVerify == nil || *origin.NoTLSVerify ||
		origin.OriginServerName == nil || *origin.OriginServerName != "tls.example.com" ||
		origin.ProxyType == nil || *origin.ProxyType != "socks" ||
		origin.TCPKeepAlive == nil || *origin.TCPKeepAlive != 5 ||
		origin.TLSTimeout == nil || *origin.TLSTimeout != 4 ||
		len(origin.IPRules) != 2 ||
		origin.IPRules[0].Prefix != "10.0.0.0/8" ||
		!slices.Equal(origin.IPRules[0].Ports, []int32{22, 443}) ||
		!origin.IPRules[0].Allow ||
		origin.IPRules[1].Allow {
		t.Fatalf("originRequest = %#v", origin)
	}
}

func testGateway() *ir.Gateway {
	connectTimeout := 30 * time.Second
	keepAliveTimeout := 90 * time.Second
	keepAliveConnections := int64(100)
	noHappyEyeballs := false
	return &ir.Gateway{
		Key: types.NamespacedName{Namespace: "apps", Name: "example"},
		Cloudflare: &ir.Cloudflare{
			AccountID:        "account-id",
			TunnelName:       "example",
			TunnelID:         "11111111-1111-1111-1111-111111111111",
			TokenSecretName:  "flareway-tunnel-example",
			ManagementPolicy: "Managed",
			OriginRequest: ir.GatewayOriginRequest{
				ConnectTimeout:       &connectTimeout,
				KeepAliveTimeout:     &keepAliveTimeout,
				KeepAliveConnections: &keepAliveConnections,
				NoHappyEyeballs:      &noHappyEyeballs,
			},
		},
		Listeners: []ir.Listener{
			{Name: "protected", Exposure: ir.ExposurePublic},
			{Name: "public", Exposure: ir.ExposurePublic},
			{Name: "blocked", Exposure: ir.ExposurePublic},
			{Name: "private", Exposure: ir.ExposurePrivate},
		},
		Domains: []ir.ProtectionDomain{
			{
				Name: "protected", ListenerName: "protected", EnvoyPort: 18080, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUDs: []string{"aud-1"}, TeamName: "team"},
				VirtualHosts: []ir.VirtualHost{{Hostname: "protected.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/admin"}}}}},
			},
			{
				Name: "public", ListenerName: "public", EnvoyPort: 18081, Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "public.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}}}}},
			},
			{
				Name: "blocked", ListenerName: "blocked", EnvoyPort: 18082, Protected: true, Guard: ir.GuardBlocked,
				VirtualHosts: []ir.VirtualHost{{Hostname: "blocked.example.com"}},
			},
			{
				Name: "private", ListenerName: "private", EnvoyPort: 443,
				VirtualHosts: []ir.VirtualHost{{Hostname: "private.example.internal"}},
			},
		},
	}
}
