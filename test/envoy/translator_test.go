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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestTranslatorSnapshotValidatesWithEnvoy(t *testing.T) {
	method := "GET"
	requestTimeout := 15 * time.Second
	backendTimeout := 5 * time.Second
	maxAge := int32(600)
	invalidBackend := &ir.Reason{Code: "BackendNotFound", Message: "missing backend"}
	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "envoy-test", Name: "validation"},
		ConformanceMode: true,
		Listeners: []ir.Listener{{
			Name: "http", Hostname: "example.com", Port: 80, EnvoyPort: envoyListenerPort,
			Protocol: "HTTP", Exposure: ir.ExposurePublic,
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "public", ListenerName: "http", EnvoyPort: envoyListenerPort,
			VirtualHosts: []ir.VirtualHost{{
				Name: "example", Hostname: "example.com",
				Routes: []ir.Route{
					{
						Name: "items", Match: ir.PathMatch{Type: ir.PathMatchExact, Value: "/v1/items"}, Method: &method,
						Headers: []ir.HeaderMatch{{Name: "x-tenant", Type: ir.StringMatchExact, Value: "blue"}},
						Query:   []ir.QueryMatch{{Name: "verbose", Type: ir.StringMatchRegularExpression, Value: "true|1"}},
						Filters: ir.Filters{
							RequestHeaders:  &ir.HeaderModifier{Set: []ir.HeaderValue{{Name: "x-flareway", Value: "validation"}}, Remove: []string{"x-remove"}},
							ResponseHeaders: &ir.HeaderModifier{Add: []ir.HeaderValue{{Name: "x-content-type-options", Value: "nosniff"}}},
							URLRewrite:      &ir.URLRewrite{Hostname: "backend.example", Path: &ir.PathModifier{Type: ir.PathModifierReplaceFullPath, Replace: "/rewritten"}},
							Mirrors:         []ir.Mirror{{Backend: ir.BackendRef{ClusterName: "mirror"}, Percent: 25}},
							CORS: &ir.CORS{
								AllowOrigins: []string{"https://*.example.com"}, AllowMethods: []string{"GET", "OPTIONS"},
								AllowHeaders: []string{"content-type", "x-tenant"}, ExposeHeaders: []string{"x-request-id"},
								MaxAge: &maxAge, AllowCredentials: true,
							},
						},
						Backends: []ir.BackendRef{
							{Name: "primary", ClusterName: "primary", Weight: 80},
							{Name: "missing", Weight: 20, Invalid: invalidBackend},
						},
						Timeouts: ir.Timeouts{Request: &requestTimeout, BackendRequest: &backendTimeout},
					},
					{
						Name: "redirect", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/old"},
						Filters: ir.Filters{Redirect: &ir.Redirect{
							Scheme: "https", Hostname: "example.com", StatusCode: 308,
							Path: &ir.PathModifier{Type: ir.PathModifierReplacePrefixMatch, Replace: "/new"},
						}},
					},
					{
						Name:  "strip-prefix",
						Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/strip-prefix"},
						Filters: ir.Filters{URLRewrite: &ir.URLRewrite{
							Path: &ir.PathModifier{Type: ir.PathModifierReplacePrefixMatch, Replace: "/"},
						}},
						Backends: []ir.BackendRef{{Name: "primary", ClusterName: "primary", Weight: 1}},
					},
				},
			}},
		}},
		Clusters: []ir.Cluster{
			{Name: "primary", Port: 8080, AppProtocol: "kubernetes.io/h2c", Endpoints: []ir.Endpoint{{Address: "127.0.0.1", Port: 8080}}},
			{Name: "mirror", Port: 8081, Endpoints: []ir.Endpoint{{Address: "127.0.0.1", Port: 8081}}},
		},
	}
	config := &v1alpha1.GatewayClassConfig{Spec: v1alpha1.GatewayClassConfigSpec{
		Proxy: v1alpha1.ProxySpec{StreamIdleTimeout: metav1.Duration{Duration: time.Hour}},
	}}

	snapshot, err := translator.Build(gateway, config)
	if err != nil {
		t.Fatalf("build translator snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert snapshot to static Envoy bootstrap: %v", err)
	}
	validateWithEnvoy(t, writeBootstrap(t, bootstrap))
}

func TestTranslatorMultiTLSChainsValidateWithEnvoy(t *testing.T) {
	certificate, privateKey := selfSignedCertificate(t)
	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "envoy-test", Name: "multi-tls"},
		ConformanceMode: true,
		Listeners: []ir.Listener{
			{Name: "named", Hostname: "api.example.com", Port: 443, EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "named-cert"}},
			{Name: "wildcard", Hostname: "*.example.com", Port: 443, EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "wildcard-cert"}},
			{Name: "catchall", Port: 443, EnvoyPort: 10443, Protocol: "HTTPS", TLS: &ir.TLSRef{Secret: "catchall-cert"}},
		},
		Domains: []ir.ProtectionDomain{
			{Name: "named", ListenerName: "named", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "named", Hostname: "api.example.com"}}},
			{Name: "wildcard", ListenerName: "wildcard", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "wildcard", Hostname: "*.example.com"}}},
			{Name: "catchall", ListenerName: "catchall", EnvoyPort: 10443, VirtualHosts: []ir.VirtualHost{{Name: "catchall", Hostname: "*"}}},
		},
		Secrets: []ir.TLSSecret{
			{Name: "named-cert", Certificate: certificate, PrivateKey: privateKey},
			{Name: "wildcard-cert", Certificate: certificate, PrivateKey: privateKey},
			{Name: "catchall-cert", Certificate: certificate, PrivateKey: privateKey},
		},
	}
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build multi-chain TLS snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert multi-chain snapshot to static Envoy bootstrap: %v", err)
	}
	validateWithEnvoy(t, writeBootstrap(t, bootstrap))
}

func selfSignedCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "api.example.com"},
		DNSNames:     []string{"api.example.com", "*.example.com"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal TLS key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
