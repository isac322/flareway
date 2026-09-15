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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

const (
	jwtIssuer   = "https://access.test"
	jwtAudience = "expected-audience"
	jwtKeyID    = "flareway-test-key"
)

func TestEnvoyJWTAuthn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	forgedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate forged RSA key: %v", err)
	}
	originPort, backendHits := startJWTOrigin(t, &key.PublicKey)

	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "envoy-test", Name: "jwt"},
		ConformanceMode: true,
		Listeners: []ir.Listener{{
			Name: "http", Hostname: "jwt.example.com", Port: 80, EnvoyPort: envoyListenerPort,
			Protocol: "HTTP", Exposure: ir.ExposurePrivate,
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "protected", ListenerName: "http", EnvoyPort: envoyListenerPort, Protected: true,
			Access: &ir.AccessGuard{AUDs: []string{jwtAudience}, AuthDomain: "access.test", OptionsPreflightBypass: true},
			VirtualHosts: []ir.VirtualHost{{
				Name: "protected", Hostname: "jwt.example.com",
				Routes: []ir.Route{{
					Name: "backend", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
					Backends: []ir.BackendRef{{Name: "backend", ClusterName: "backend", Weight: 1}},
				}},
			}},
		}},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
	}
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build JWT translator snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert JWT snapshot to static Envoy bootstrap: %v", err)
	}
	if err := pointJWTConfigAtLocalOrigin(bootstrap, originPort); err != nil {
		t.Fatal(err)
	}
	port, err := listenerPort(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), port)

	now := time.Now()
	valid := signJWT(t, key, jwtAudience, now.Add(5*time.Minute))
	wrongAudience := signJWT(t, key, "wrong-audience", now.Add(5*time.Minute))
	expired := signJWT(t, key, jwtAudience, now.Add(-time.Hour))
	forged := signJWT(t, forgedKey, jwtAudience, now.Add(5*time.Minute))

	var validBody string
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	err = waitForHTTP(readyCtx, 250*time.Millisecond, func() (int, string, error) {
		status, body, requestErr := envoyRequest(envoy.listenerURL, valid)
		if requestErr == nil && status == http.StatusOK {
			validBody = body
		}
		return status, body, requestErr
	}, http.StatusOK)
	if err != nil {
		t.Fatalf("Envoy did not accept valid JWT: %v\ncontainer logs:\n%s", err, containerLogs(envoy.name))
	}
	if validBody != "backend-ok" {
		t.Fatalf("valid JWT response body = %q, want backend-ok", validBody)
	}

	cookieStatus, cookieBody, err := envoyRequestWithCookie(envoy.listenerURL, valid)
	if err != nil {
		t.Fatalf("request Envoy with Access cookie: %v", err)
	}
	if cookieStatus != http.StatusOK || cookieBody != "backend-ok" {
		t.Fatalf("valid Access cookie = status %d body %q, want 200 backend-ok", cookieStatus, cookieBody)
	}
	optionsStatus, _, err := envoyMethodRequest(envoy.listenerURL, http.MethodOptions, "")
	if err != nil {
		t.Fatalf("request Envoy OPTIONS preflight: %v", err)
	}
	if optionsStatus != http.StatusOK {
		t.Fatalf("OPTIONS preflight status = %d, want 200", optionsStatus)
	}
	missingStatus, _, err := envoyMethodRequest(envoy.listenerURL, http.MethodGet, "")
	if err != nil {
		t.Fatalf("request Envoy without JWT: %v", err)
	}
	if missingStatus != http.StatusUnauthorized {
		t.Fatalf("missing JWT status = %d, want 401", missingStatus)
	}

	for name, token := range map[string]string{
		"wrong audience": wrongAudience,
		"expired":        expired,
		"forged":         forged,
	} {
		t.Run(name, func(t *testing.T) {
			status, body, err := envoyRequest(envoy.listenerURL, token)
			if err != nil {
				t.Fatalf("request Envoy: %v", err)
			}
			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%q", status, body)
			}
		})
	}
	if got := backendHits.Load(); got != 3 {
		t.Fatalf("backend requests = %d, want header JWT, cookie JWT, and OPTIONS only", got)
	}
}

func startJWTOrigin(t *testing.T, publicKey *rsa.PublicKey) (int, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen for local JWKS/backend server: %v", err)
	}
	jwks := json.RawMessage(mustJWKS(t, publicKey))
	hits := &atomic.Int32{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/jwks" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write(jwks)
			return
		}
		hits.Add(1)
		response.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(response, "backend-ok")
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener.Addr().(*net.TCPAddr).Port, hits
}

func pointJWTConfigAtLocalOrigin(bootstrap *bootstrapv3.Bootstrap, port int) error {
	backend, err := findCluster(bootstrap, "backend")
	if err != nil {
		return err
	}
	setClusterEndpoint(backend, "host.docker.internal", port)

	jwks, err := findClusterPrefix(bootstrap, "flareway-jwks-")
	if err != nil {
		return err
	}
	setClusterEndpoint(jwks, "host.docker.internal", port)
	jwks.TransportSocket = nil

	uri := localOriginURI(port)
	for _, listener := range bootstrap.StaticResources.Listeners {
		if err := rewriteJWTFilter(listener, uri); err == nil {
			return nil
		}
	}
	return fmt.Errorf("jwt_authn filter not found in bootstrap listeners")
}

func envoyRequest(baseURL, token string) (int, string, error) {
	return envoyMethodRequest(baseURL, http.MethodGet, token)
}

func envoyRequestWithCookie(baseURL, token string) (int, string, error) {
	request, err := http.NewRequest(http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = "jwt.example.com"
	request.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
	return doEnvoyRequest(request)
}

func envoyMethodRequest(baseURL, method, token string) (int, string, error) {
	request, err := http.NewRequest(method, baseURL+"/", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = "jwt.example.com"
	if token != "" {
		request.Header.Set("Cf-Access-Jwt-Assertion", token)
	}
	return doEnvoyRequest(request)
}

func doEnvoyRequest(request *http.Request) (int, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return response.StatusCode, "", err
	}
	return response.StatusCode, string(body), nil
}

func signJWT(t *testing.T, key *rsa.PrivateKey, audience string, expires time.Time) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"alg": "RS256", "kid": jwtKeyID, "typ": "JWT"})
	claims := mustJSON(t, map[string]any{
		"iss": jwtIssuer,
		"aud": []string{audience},
		"sub": "component-test",
		"iat": time.Now().Unix(),
		"exp": expires.Unix(),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustJWKS(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	exponent := big.NewInt(int64(key.E)).Bytes()
	return mustJSON(t, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"kid": jwtKeyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}

func rewriteJWTFilter(listener *listenerv3.Listener, uri string) error {
	for _, chain := range listener.FilterChains {
		for _, filter := range chain.Filters {
			if filter.Name != "envoy.filters.network.http_connection_manager" {
				continue
			}
			hcm := &hcmv3.HttpConnectionManager{}
			if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
				return fmt.Errorf("decode HCM: %w", err)
			}
			for _, httpFilter := range hcm.HttpFilters {
				if httpFilter.Name != "envoy.filters.http.jwt_authn" {
					continue
				}
				jwt := &jwtauthnv3.JwtAuthentication{}
				if err := httpFilter.GetTypedConfig().UnmarshalTo(jwt); err != nil {
					return fmt.Errorf("decode jwt_authn: %w", err)
				}
				provider := jwt.Providers["cloudflare-access"]
				if provider == nil || provider.GetRemoteJwks() == nil {
					return fmt.Errorf("cloudflare-access remote JWKS provider missing")
				}
				provider.GetRemoteJwks().HttpUri.Uri = uri
				typedJWT, err := anypb.New(jwt)
				if err != nil {
					return fmt.Errorf("encode jwt_authn: %w", err)
				}
				httpFilter.ConfigType = &hcmv3.HttpFilter_TypedConfig{TypedConfig: typedJWT}
				typedHCM, err := anypb.New(hcm)
				if err != nil {
					return fmt.Errorf("encode HCM: %w", err)
				}
				filter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: typedHCM}
				return nil
			}
		}
	}
	return fmt.Errorf("jwt_authn filter not found")
}

func localOriginURI(port int) string {
	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("host.docker.internal", fmt.Sprint(port)),
		Path:   "/jwks",
	}).String()
}
