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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/bootstrap"
	"github.com/isac322/flareway/internal/xds/pki"
	xdsserver "github.com/isac322/flareway/internal/xds/server"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestEnvoyActivatesUpdatedTLSClusterWithoutEDSTimeout(t *testing.T) {
	requireDocker(t)

	hostGatewayIP := resolveDockerHostGatewayIP(t)
	gwKey := types.NamespacedName{Namespace: "apps", Name: "eds-warming"}
	caSecret, _ := buildRenderedXDSDir(t, gwKey, bootstrap.Options{})
	serverTLS, err := pki.ServerTLSConfig(caSecret)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	xdsAddr := reserveLoopbackAddr(t)
	srv, err := xdsserver.New(xdsserver.Options{
		Address:          xdsAddr,
		TLSConfig:        serverTLS,
		KeepaliveTime:    ptr.To(time.Second),
		KeepaliveTimeout: ptr.To(500 * time.Millisecond),
		KeepaliveMinTime: ptr.To(500 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("xdsserver.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Start(ctx) }()

	// Bridge host loopback server through proxy bound to 0.0.0.0 so the Envoy container dials cleanly.
	proxy := startBlackholeProxy(t, xdsAddr)
	_, proxyPort, err := net.SplitHostPort(proxy.addr)
	if err != nil {
		t.Fatal(err)
	}

	xdsDir := writeRenderedXDSMaterial(t, gwKey, caSecret, bootstrap.Options{
		NodeCluster: gwKey.String(),
		XDSAddress:  "flareway-xds.flareway-system.svc.cluster.local:" + proxyPort,
	})
	exposeEnvoyAdminInTestDir(t, xdsDir)

	certPEM, tlsCert := selfSignedBackendCert(t, "backend.example")
	backendLn, err := tls.Listen("tcp4", "0.0.0.0:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backendLn.Close() })
	_, backendPortStr, err := net.SplitHostPort(backendLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	backendPort, err := strconv.Atoi(backendPortStr)
	if err != nil {
		t.Fatal(err)
	}
	backendSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}),
	}
	go func() { _ = backendSrv.Serve(backendLn) }()
	t.Cleanup(func() { _ = backendSrv.Close() })

	buildTLSSnapshot := func(san string) (*cachev3.Snapshot, string) {
		gateway := &ir.Gateway{
			Key:             gwKey,
			ConformanceMode: true,
			Listeners: []ir.Listener{{
				Name:      "http",
				Hostname:  "app.example.com",
				Port:      80,
				EnvoyPort: envoyListenerPort,
				Protocol:  "HTTP",
				Exposure:  ir.ExposurePublic,
			}},
			Domains: []ir.ProtectionDomain{{
				Name:         "public",
				ListenerName: "http",
				EnvoyPort:    envoyListenerPort,
				VirtualHosts: []ir.VirtualHost{{
					Name:     "app",
					Hostname: "app.example.com",
					Routes: []ir.Route{{
						Name:     "route",
						Match:    ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
						Backends: []ir.BackendRef{{Name: "tls-svc", ClusterName: "k8s://apps/tls-svc:443", Weight: 1}},
					}},
				}},
			}},
			Clusters: []ir.Cluster{{
				Name:      "k8s://apps/tls-svc:443",
				Namespace: "apps",
				Service:   "tls-svc",
				Port:      443,
				Endpoints: []ir.Endpoint{{Address: hostGatewayIP, Port: int32(backendPort)}},
				TLS: &ir.BackendTLS{
					ServerName:      "backend.example",
					CACertificate:   certPEM,
					SubjectAltNames: []ir.SubjectAltName{{Type: "Hostname", Value: san}},
				},
			}},
		}
		snap, buildErr := translator.Build(gateway, nil)
		if buildErr != nil {
			t.Fatalf("translator.Build(%q): %v", san, buildErr)
		}
		return snap, snap.GetVersion(resourcev3.ListenerType)
	}

	podID := dataplane.EnvoyNodeID(gwKey.Namespace, gwKey.Name, "pod-uid-1")
	v1Snap, v1Ver := buildTLSSnapshot("backend.example")
	if err := srv.SetSnapshot(ctx, gwKey.String(), v1Snap); err != nil {
		t.Fatalf("SetSnapshot v1: %v", err)
	}

	containerName := "flareway-envoy-eds-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	cleanupTarget := containerName
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", cleanupTarget).Run()
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer startCancel()
	createOut, err := exec.CommandContext(startCtx,
		"docker", "create", "--name", containerName,
		"--dns", "127.0.0.1",
		"--add-host", "host.docker.internal:host-gateway",
		"--add-host", "flareway-xds.flareway-system.svc.cluster.local:host-gateway",
		"-p", "127.0.0.1::"+strconv.Itoa(envoyListenerPort),
		"-p", "127.0.0.1::"+strconv.Itoa(envoyAdminPort),
		"-v", xdsDir+":/etc/flareway/xds:ro",
		envoyImage,
		"envoy",
		"-c", "/etc/flareway/xds/bootstrap.yaml",
		"--service-node", podID,
		"--service-cluster", gwKey.String(),
		"--concurrency", "1",
		"--disable-hot-restart",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("create Envoy container: %v\n%s", err, createOut)
	}
	containerID := strings.TrimSpace(string(createOut))
	if containerID == "" {
		containerID = containerName
	}
	cleanupTarget = containerID
	if startOut, err := exec.CommandContext(startCtx, "docker", "start", containerID).CombinedOutput(); err != nil {
		t.Fatalf("start Envoy container: %v\n%s", err, startOut)
	}

	listenerAddr := dockerPort(t, containerID, envoyListenerPort)
	adminAddr := dockerPort(t, containerID, envoyAdminPort)
	waitCtx, waitCancel := context.WithTimeout(ctx, 15*time.Second)
	defer waitCancel()
	if err := waitForHTTP(waitCtx, 100*time.Millisecond, func() (int, string, error) {
		if !srv.IsACKedForNodes(gwKey.String(), v1Ver, []string{podID}) {
			return 0, "", fmt.Errorf("v1 not ACKed yet")
		}
		return probeHostGET(listenerAddr, "app.example.com", "/")
	}, http.StatusOK); err != nil {
		t.Fatalf("initial TLS SAN match failed: %v\nlogs:\n%s", err, containerLogs(containerID))
	}

	beforeSANFailures, err := readEnvoySANFailureCount(waitCtx, adminAddr)
	if err != nil {
		t.Fatalf("read initial ssl.fail_verify_san: %v", err)
	}

	v2Snap, v2Ver := buildTLSSnapshot("wrong-san.example")
	mismatchCtx, mismatchCancel := context.WithTimeout(ctx, 3*time.Second)
	defer mismatchCancel()
	if err := srv.SetSnapshot(mismatchCtx, gwKey.String(), v2Snap); err != nil {
		t.Fatalf("SetSnapshot v2: %v", err)
	}

	if err := waitForHTTP(mismatchCtx, 100*time.Millisecond, func() (int, string, error) {
		if mismatchCtx.Err() != nil {
			return 0, "", mismatchCtx.Err()
		}
		if !srv.IsACKedForNodes(gwKey.String(), v2Ver, []string{podID}) {
			return 0, "", fmt.Errorf("v2 not ACKed yet: %s", srv.ACKDetailsForNodes(gwKey.String(), v2Ver, []string{podID}))
		}
		status, body, err := probeHostGETContext(mismatchCtx, listenerAddr, "app.example.com", "/")
		if err != nil {
			return 0, "", err
		}
		if mismatchCtx.Err() != nil {
			return 0, "", mismatchCtx.Err()
		}
		if status == http.StatusServiceUnavailable {
			afterSANFailures, err := readEnvoySANFailureCount(mismatchCtx, adminAddr)
			if err != nil {
				return 0, "", err
			}
			if mismatchCtx.Err() != nil {
				return 0, "", mismatchCtx.Err()
			}
			if afterSANFailures <= beforeSANFailures {
				return 0, "", fmt.Errorf("503 observed without ssl.fail_verify_san increase (before=%d after=%d)", beforeSANFailures, afterSANFailures)
			}
		}
		return status, body, nil
	}, http.StatusServiceUnavailable); err != nil {
		t.Fatalf("updated SAN mismatch did not activate within 3s (15s EDS warming stall?): %v\nlogs:\n%s", err, containerLogs(containerID))
	}

	logs := requireContainerLogs(t, containerID)
	if strings.Contains(logs, "initial fetch timed out") {
		t.Fatalf("Envoy logged initial fetch timeout waiting on EDS:\n%s", logs)
	}
	statCtx, statCancel := context.WithTimeout(ctx, 5*time.Second)
	defer statCancel()
	updateTimeouts, err := readEnvoyStatCount(statCtx, adminAddr, `cluster\..*\.update_timeout`)
	if err != nil {
		t.Fatalf("read Envoy cluster update_timeout stats: %v", err)
	}
	if updateTimeouts != 0 {
		t.Fatalf("Envoy logged %d cluster update_timeout(s)", updateTimeouts)
	}

	cancel()
	proxy.close()
	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatalf("xds server exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for xds server shutdown")
	}
}

func exposeEnvoyAdminInTestDir(t *testing.T, xdsDir string) {
	t.Helper()
	bootstrapPath := filepath.Join(xdsDir, "bootstrap.yaml")
	raw, err := os.ReadFile(bootstrapPath)
	if err != nil {
		t.Fatalf("read test bootstrap.yaml: %v", err)
	}
	const loopbackAdmin = "      address: 127.0.0.1\n      port_value: 19000"
	const anyAdmin = "      address: 0.0.0.0\n      port_value: 19000"
	updated := strings.Replace(string(raw), loopbackAdmin, anyAdmin, 1)
	if updated == string(raw) {
		t.Fatalf("unexpected bootstrap admin block:\n%s", string(raw))
	}
	if err := os.WriteFile(bootstrapPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("update test bootstrap.yaml: %v", err)
	}
}

func probeHostGETContext(ctx context.Context, addr, host, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

func requireContainerLogs(t *testing.T, target string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "logs", target).CombinedOutput()
	if err != nil {
		t.Fatalf("capture logs for %s: %v\n%s", target, err, out)
	}
	return string(out)
}

func readEnvoySANFailureCount(ctx context.Context, adminAddr string) (int64, error) {
	return readEnvoyStatCount(ctx, adminAddr, `cluster\..*\.ssl\.fail_verify_san`)
}

func readEnvoyStatCount(ctx context.Context, adminAddr, filter string) (int64, error) {
	q := url.Values{}
	q.Set("filter", filter)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+adminAddr+"/stats?"+q.Encode(), nil)
	if err != nil {
		return 0, fmt.Errorf("build Envoy stats request: %w", err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("query Envoy stats: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read Envoy stats: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Envoy stats status %d: %s", resp.StatusCode, string(raw))
	}
	var total int64
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		sep := strings.LastIndexByte(line, ':')
		if sep < 0 {
			return 0, fmt.Errorf("unexpected Envoy stat line %q", line)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line[sep+1:]), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse Envoy stat line %q: %w", line, err)
		}
		total += n
	}
	return total, nil
}

func resolveDockerHostGatewayIP(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx,
		"docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
		envoyImage, "getent", "hosts", "host.docker.internal",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("resolve host.docker.internal IP: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || net.ParseIP(fields[0]) == nil {
		t.Fatalf("unexpected getent output %q", strings.TrimSpace(string(out)))
	}
	return fields[0]
}

func selfSignedBackendCert(t *testing.T, dnsSAN string) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsSAN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dnsSAN},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, tlsCert
}
