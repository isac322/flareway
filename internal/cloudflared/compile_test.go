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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

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
					{Type: ir.PathMatchPathPrefix, Value: "/backend-api/codex"},
				},
				VirtualHosts: []ir.VirtualHost{{Hostname: "codex.example.com", Routes: []ir.Route{
					{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/v1"}},
					{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/backend-api/codex"}},
				}}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUD: "aud-codex", TeamName: "team"},
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "codex.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}}}}},
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
	if config.Ingress[0].Path != "^/backend-api/codex(/|$)" || config.Ingress[1].Path != "^/v1(/|$)" {
		t.Fatalf("public carve-outs are not ordered most-specific first: %#v", config.Ingress)
	}
	if config.Ingress[0].OriginRequest == nil || config.Ingress[0].OriginRequest.Access != nil ||
		config.Ingress[1].OriginRequest == nil || config.Ingress[1].OriginRequest.Access != nil {
		t.Fatalf("public carve-outs contain Access validation: %#v", config.Ingress[:2])
	}
	if config.Ingress[2].Service != "http://127.0.0.1:18081" || config.Ingress[2].OriginRequest == nil ||
		config.Ingress[2].OriginRequest.Access == nil || config.Ingress[2].OriginRequest.Access.AUDTag[0] != "aud-codex" {
		t.Fatalf("protected remainder = %#v", config.Ingress[2])
	}
}

func TestCompileMissingAUDBlocksProtectedRemainderAfterCarveOut(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/v1"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "codex.example.com", Routes: []ir.Route{{Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/v1"}}}}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardBlocked,
				VirtualHosts: []ir.VirtualHost{{Hostname: "codex.example.com"}},
			},
		},
	}
	config := compileConfig(gateway)
	if len(config.Ingress) != 3 || config.Ingress[0].Path != "^/v1(/|$)" || config.Ingress[1].Service != "http_status:403" {
		t.Fatalf("missing AUD fail-closed order = %#v", config.Ingress)
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
				Access:       &ir.AccessGuard{AUD: "aud-exact", TeamName: "team"},
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
				Access:       &ir.AccessGuard{AUD: "aud-parent", TeamName: "team"},
				IngressPaths: []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/"}},
				VirtualHosts: []ir.VirtualHost{{Hostname: "app.example.com"}},
			},
			{
				Name: "child", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				Access:       &ir.AccessGuard{AUD: "aud-child", TeamName: "team"},
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

func testGateway() *ir.Gateway {
	return &ir.Gateway{
		Key: types.NamespacedName{Namespace: "apps", Name: "example"},
		Cloudflare: &ir.Cloudflare{
			AccountID:        "account-id",
			TunnelName:       "example",
			TunnelID:         "11111111-1111-1111-1111-111111111111",
			TokenSecretName:  "flareway-tunnel-example",
			ManagementPolicy: "Managed",
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
				Access:       &ir.AccessGuard{AUD: "aud-1", TeamName: "team"},
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
