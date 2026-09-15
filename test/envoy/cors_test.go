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
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestEnvoyCORSRejectsNonMatchingPreflightLocally(t *testing.T) {
	originPort, backendHits := startHTTPBackend(t)
	gateway := &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "envoy-test", Name: "cors"},
		ConformanceMode: true,
		Listeners: []ir.Listener{{
			Name: "http", Hostname: "cors.example.com", Port: 80, EnvoyPort: envoyListenerPort,
			Protocol: "HTTP", Exposure: ir.ExposurePublic,
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "cors", ListenerName: "http", EnvoyPort: envoyListenerPort,
			VirtualHosts: []ir.VirtualHost{{
				Name: "cors", Hostname: "cors.example.com",
				Routes: []ir.Route{{
					Name: "cors", Match: ir.PathMatch{Type: ir.PathMatchExact, Value: "/cors-1"},
					Filters: ir.Filters{CORS: &ir.CORS{
						AllowOrigins: []string{"https://allowed.example"},
						AllowMethods: []string{"GET", "OPTIONS"},
					}},
					Backends: []ir.BackendRef{{Name: "backend", ClusterName: "backend", Weight: 1}},
				}},
			}},
		}},
		Clusters: []ir.Cluster{{Name: "backend", Port: 8080}},
	}
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build CORS snapshot: %v", err)
	}
	bootstrap, err := staticBootstrap(snapshot)
	if err != nil {
		t.Fatalf("convert CORS snapshot: %v", err)
	}
	backend, err := findCluster(bootstrap, "backend")
	if err != nil {
		t.Fatal(err)
	}
	setClusterEndpoint(backend, "host.docker.internal", originPort)
	port, err := listenerPort(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	envoy := startEnvoy(t, writeBootstrap(t, bootstrap), port)

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	var authorityBody string
	if err := waitForHTTP(readyCtx, 250*time.Millisecond, func() (int, string, error) {
		status, body, requestErr := authorityRequest(envoy.listenerURL, "cors.example.com:1234")
		if requestErr == nil && status == http.StatusOK {
			authorityBody = body
		}
		return status, body, requestErr
	}, http.StatusOK); err != nil {
		t.Fatalf("authority with explicit port did not route: %v\ncontainer logs:\n%s", err, containerLogs(envoy.name))
	}
	if authorityBody != "cors.example.com:1234" {
		t.Fatalf("backend Host = %q, want original authority with port", authorityBody)
	}
	status, body, err := corsPreflight(envoy.listenerURL, "https://allowed.example")
	if err != nil || status != http.StatusOK {
		t.Fatalf("allowed CORS preflight status=%d body=%q error=%v", status, body, err)
	}
	status, body, err = corsPreflight(envoy.listenerURL, "https://denied.example")
	if err != nil {
		t.Fatalf("send non-matching CORS preflight: %v", err)
	}
	if status >= http.StatusInternalServerError {
		t.Fatalf("non-matching CORS preflight status=%d body=%q", status, body)
	}
	if got := backendHits.Load(); got != 1 {
		t.Fatalf("backend requests = %d, want only the explicit-port GET", got)
	}
}

func startHTTPBackend(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen for local backend: %v", err)
	}
	hits := &atomic.Int32{}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			hits.Add(1)
			_, _ = io.WriteString(response, request.Host)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener.Addr().(*net.TCPAddr).Port, hits
}

func corsPreflight(baseURL, origin string) (int, string, error) {
	request, err := http.NewRequest(http.MethodOptions, baseURL+"/cors-1", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = "cors.example.com"
	request.Header.Set("Origin", origin)
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, string(body), err
}

func authorityRequest(baseURL, authority string) (int, string, error) {
	request, err := http.NewRequest(http.MethodGet, baseURL+"/cors-1", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = authority
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, string(body), err
}
