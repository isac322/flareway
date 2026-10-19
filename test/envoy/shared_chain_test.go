//go:build envoy

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

package envoy_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// Every host of a private TLS listener shares the listener's SNI, so one
// filter chain serves them all and each virtual host enforces its own
// domain's guard: the listener's blocked wildcard host and api.example.com
// answer 403 locally, b.example.com and c.example.com forward only behind
// their own application's JWT, and c's OPTIONS preflight bypass applies to
// c alone.
func TestEnvoySharedPrivateChainEnforcesEachHostGuard(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	originPort, hits := startJWTOrigin(t, &key.PublicKey)
	certificate, privateKey := selfSignedCertificate(t)
	backend := []ir.Route{{
		Name: "backend", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
		Backends: []ir.BackendRef{{Name: "backend", ClusterName: "backend", Weight: 1}},
	}}
	const port = 10443
	gateway := &ir.Gateway{
		Key: types.NamespacedName{Namespace: "envoy-test", Name: "shared"},
		Listeners: []ir.Listener{{
			Name: "https", Hostname: "*.example.com", Port: port, EnvoyPort: port, Protocol: "HTTPS",
			Exposure: ir.ExposurePrivate, TLS: &ir.TLSRef{Secret: "cert"},
		}},
		Domains: []ir.ProtectionDomain{
			{Name: "https", ListenerName: "https", Protected: true, Guard: ir.GuardBlocked,
				VirtualHosts: []ir.VirtualHost{{Name: "wild", Hostname: "*.example.com"}}},
			{Name: "app-a", ListenerName: "https", Protected: true, Guard: ir.GuardBlocked, AccessApplication: "envoy-test/app-a",
				VirtualHosts: []ir.VirtualHost{{Name: "api", Hostname: "api.example.com", Routes: backend}}},
			{Name: "app-b", ListenerName: "https", Protected: true, Guard: ir.GuardForwarding, AccessApplication: "envoy-test/app-b",
				Access:       &ir.AccessGuard{AUDs: []string{jwtAudience}, AuthDomain: "access.test"},
				VirtualHosts: []ir.VirtualHost{{Name: "b", Hostname: "b.example.com", Routes: backend}}},
			{Name: "app-c", ListenerName: "https", Protected: true, Guard: ir.GuardForwarding, AccessApplication: "envoy-test/app-c",
				Access:       &ir.AccessGuard{AUDs: []string{"other-audience"}, AuthDomain: "access.test", OptionsPreflightBypass: true},
				VirtualHosts: []ir.VirtualHost{{Name: "c", Hostname: "c.example.com", Routes: backend}}},
		},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
		Secrets:  []ir.TLSSecret{{Name: "cert", Certificate: certificate, PrivateKey: privateKey}},
	}
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build shared private chain snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert shared chain snapshot to static Envoy bootstrap: %v", err)
	}
	for _, cluster := range bootstrap.StaticResources.Clusters {
		setClusterEndpoint(cluster, "host.docker.internal", originPort)
		if strings.HasPrefix(cluster.Name, "flareway-jwks-") {
			cluster.TransportSocket = nil
		}
	}
	for _, listener := range bootstrap.StaticResources.Listeners {
		listener.GetAddress().GetSocketAddress().Address = "0.0.0.0"
		if n := rewriteAllProviders(t, listener, localOriginURI(originPort)); n != 2 {
			t.Fatalf("rewrote %d JWKS providers, want 2", n)
		}
	}
	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), port)
	base := "https://" + strings.TrimPrefix(envoy.listenerURL, "http://")

	tokenB := signJWT(t, key, jwtAudience, time.Now().Add(5*time.Minute))
	tokenC := signJWT(t, key, "other-audience", time.Now().Add(5*time.Minute))
	request := func(method, host, token string) (int, string) {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
		}}
		req, err := http.NewRequest(method, base+"/", nil)
		if err != nil {
			return 0, err.Error()
		}
		req.Host = host
		if token != "" {
			req.Header.Set("Cf-Access-Jwt-Assertion", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, string(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := waitForHTTP(ctx, 250*time.Millisecond, func() (int, string, error) {
		status, body := request(http.MethodGet, "b.example.com", tokenB)
		return status, body, nil
	}, http.StatusOK); err != nil {
		t.Fatalf("b.example.com never answered 200: %v\ncontainer logs:\n%s", err, containerLogs(envoy.name))
	}
	before := hits.Load()
	cases := []struct {
		method, host, token string
		want                int
	}{
		{"GET", "b.example.com", tokenB, 200},
		{"GET", "b.example.com", "", 401},
		{"GET", "b.example.com", tokenC, 401},
		{"OPTIONS", "b.example.com", "", 401},
		{"GET", "api.example.com", tokenB, 403},
		{"GET", "api.example.com", "", 403},
		{"OPTIONS", "api.example.com", "", 403},
		{"GET", "x.example.com", tokenB, 403},
		{"GET", "c.example.com", tokenC, 200},
		{"GET", "c.example.com", tokenB, 401},
		{"GET", "c.example.com", "", 401},
		{"OPTIONS", "c.example.com", "", 200},
	}
	forwarded := int32(0)
	for _, c := range cases {
		status, body := request(c.method, c.host, c.token)
		t.Logf("%s %s token=%t -> %d %q", c.method, c.host, c.token != "", status, body)
		if status != c.want {
			t.Errorf("%s %s token=%t = %d, want %d", c.method, c.host, c.token != "", status, c.want)
		}
		if c.want == http.StatusOK {
			forwarded++
		}
	}
	if got := hits.Load() - before; got != forwarded {
		t.Errorf("backend hits = %d, want %d", got, forwarded)
	}
}

// rewriteAllProviders points every jwt_authn remote-JWKS provider in every
// filter chain of listener at uri and returns how many were rewritten.
func rewriteAllProviders(t *testing.T, listener *listenerv3.Listener, uri string) int {
	t.Helper()
	count := 0
	for _, chain := range listenerChains(listener) {
		for _, filter := range chain.Filters {
			hcm := &hcmv3.HttpConnectionManager{}
			if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
				t.Fatal(err)
			}
			for _, httpFilter := range hcm.HttpFilters {
				if httpFilter.Name != "envoy.filters.http.jwt_authn" {
					continue
				}
				jwt := &jwtauthnv3.JwtAuthentication{}
				if err := httpFilter.GetTypedConfig().UnmarshalTo(jwt); err != nil {
					t.Fatal(err)
				}
				for _, provider := range jwt.Providers {
					provider.GetRemoteJwks().HttpUri.Uri = uri
					count++
				}
				typed, err := anypb.New(jwt)
				if err != nil {
					t.Fatal(err)
				}
				httpFilter.ConfigType = &hcmv3.HttpFilter_TypedConfig{TypedConfig: typed}
			}
			typed, err := anypb.New(hcm)
			if err != nil {
				t.Fatal(err)
			}
			filter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: typed}
		}
	}
	return count
}
