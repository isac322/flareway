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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	typesv3 "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/bootstrap"
	"github.com/isac322/flareway/internal/xds/pki"
	xdsserver "github.com/isac322/flareway/internal/xds/server"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestBootstrapRenderValidatesWithRealEnvoy(t *testing.T) {
	requireDocker(t)

	gwKey := types.NamespacedName{Namespace: "apps", Name: "edge"}
	cases := []struct {
		name string
		opts bootstrap.Options
	}{
		{
			name: "default-30s-5s-30s",
			opts: bootstrap.Options{NodeCluster: gwKey.String()},
		},
		{
			name: "custom-1s-500ms-1s",
			opts: bootstrap.Options{
				NodeCluster:                     gwKey.String(),
				KeepaliveInterval:               time.Second,
				KeepaliveTimeout:                500 * time.Millisecond,
				KeepaliveConnectionIdleInterval: time.Second,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, xdsDir := buildRenderedXDSDir(t, gwKey, tc.opts)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			out, err := exec.CommandContext(ctx,
				"docker", "run", "--rm",
				"-v", xdsDir+":/etc/flareway/xds:ro",
				envoyImage,
				"envoy", "--mode", "validate",
				"-c", "/etc/flareway/xds/bootstrap.yaml",
				"--service-node", dataplane.EnvoyNodeID(gwKey.Namespace, gwKey.Name, "pod-uid-1"),
				"--service-cluster", gwKey.String(),
			).CombinedOutput()
			if err != nil {
				t.Fatalf("envoy --mode validate on rendered bootstrap (%s) failed: %v\n%s", tc.name, err, out)
			}
		})
	}
}

func TestEnvoyXDSKeepaliveIdleStabilityAndBlackholeReconnect(t *testing.T) {
	requireDocker(t)

	gwKey := types.NamespacedName{Namespace: "apps", Name: "edge"}
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

	proxy := startBlackholeProxy(t, xdsAddr)
	_, proxyPort, err := net.SplitHostPort(proxy.addr)
	if err != nil {
		t.Fatal(err)
	}

	xdsDir := writeRenderedXDSMaterial(t, gwKey, caSecret, bootstrap.Options{
		NodeCluster:                     gwKey.String(),
		XDSAddress:                      "flareway-xds.flareway-system.svc.cluster.local:" + proxyPort,
		KeepaliveInterval:               time.Second,
		KeepaliveTimeout:                500 * time.Millisecond,
		KeepaliveConnectionIdleInterval: time.Second,
	})

	// Host HTTP backend returning its configured version label.
	// Bind on all IPv4 interfaces so Docker containers reaching host.docker.internal can connect.
	var backendVersion atomic.Value
	backendVersion.Store("v1")
	backendLn, err := net.Listen("tcp4", "0.0.0.0:0")
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
			_, _ = io.WriteString(w, backendVersion.Load().(string))
		}),
	}
	go func() { _ = backendSrv.Serve(backendLn) }()
	t.Cleanup(func() { _ = backendSrv.Close() })

	podID := dataplane.EnvoyNodeID(gwKey.Namespace, gwKey.Name, "pod-uid-1")
	v1Snap, v1Ver := buildDynamicRoutingSnapshot(t, gwKey, "/v1", backendPort)
	if err := srv.SetSnapshot(ctx, gwKey.String(), v1Snap); err != nil {
		t.Fatalf("SetSnapshot v1: %v", err)
	}

	containerName := "flareway-envoy-ka-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer startCancel()
	if out, err := exec.CommandContext(startCtx,
		"docker", "run", "-d", "--name", containerName,
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
	).CombinedOutput(); err != nil {
		t.Fatalf("start Envoy container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
	})

	listenerAddr := dockerPort(t, containerName, envoyListenerPort)
	adminAddr := dockerPort(t, containerName, envoyAdminPort)
	waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
	defer waitCancel()
	if err := waitForHTTP(waitCtx, 100*time.Millisecond, func() (int, string, error) {
		if !srv.IsACKedForNodes(gwKey.String(), v1Ver, []string{podID}) {
			return 0, "", fmt.Errorf("v1 not ACKed yet (proxy accepts=%d): %s", proxy.acceptCount.Load(), srv.ACKDetailsForNodes(gwKey.String(), v1Ver, []string{podID}))
		}
		return probeHostGET(listenerAddr, "example.com", "/v1")
	}, http.StatusOK); err != nil {
		_, clusters, _ := probeHostGET(adminAddr, "localhost", "/clusters")
		t.Fatalf("initial Envoy dynamic convergence failed: %v\nclusters:\n%s\nlogs:\n%s", err, clusters, containerLogs(containerName))
	}

	// (a) Keep connection idle across >= 4 PING intervals (1s interval, 500ms MinTime).
	// maxPingStrikes=2 would kill the stream at ~3s if client keepalives triggered ENHANCE_YOUR_CALM.
	time.Sleep(4500 * time.Millisecond)
	if !srv.IsACKedForNodes(gwKey.String(), v1Ver, []string{podID}) {
		t.Fatalf("idle stream lost convergence: %s\nlogs:\n%s", srv.ACKDetailsForNodes(gwKey.String(), v1Ver, []string{podID}), containerLogs(containerName))
	}
	if accepts := proxy.acceptCount.Load(); accepts != 1 {
		t.Fatalf("proxy accept count during idle stability = %d, want 1 (connection churned)\nlogs:\n%s", accepts, containerLogs(containerName))
	}
	logs := containerLogs(containerName)
	if strings.Contains(strings.ToUpper(logs), "ENHANCE_YOUR_CALM") || strings.Contains(strings.ToLower(logs), "too_many_pings") {
		t.Fatalf("Envoy hit HTTP/2 ping enforcement during idle keepalive:\n%s", logs)
	}

	// Drain any earlier events before triggering the silent blackhole.
	for len(srv.Events()) > 0 {
		<-srv.Events()
	}

	// (b) Blackhole ONLY existing active connections without closing TCP sockets,
	// then publish v2 snapshot so routing can succeed only after keepalive reconnect.
	proxy.blackholeExisting()
	backendVersion.Store("v2")
	v2Snap, v2Ver := buildDynamicRoutingSnapshot(t, gwKey, "/v2", backendPort)
	if err := srv.SetSnapshot(ctx, gwKey.String(), v2Snap); err != nil {
		t.Fatalf("SetSnapshot v2: %v", err)
	}

	// Server keepalive closes the half-open stream and emits an XDSEvents wakeup.
	select {
	case ev := <-srv.Events():
		if ev.Object.GetNamespace() != gwKey.Namespace || ev.Object.GetName() != gwKey.Name {
			t.Fatalf("unexpected wakeup object %s/%s", ev.Object.GetNamespace(), ev.Object.GetName())
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("server did not close blackholed xDS stream and emit wakeup within 8s\nlogs:\n%s", containerLogs(containerName))
	}

	// Envoy keepalive detects the blackhole, reconnects cleanly, ACKs v2, and serves /v2.
	reconnectCtx, reconnectCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reconnectCancel()
	if err := waitForHTTP(reconnectCtx, 100*time.Millisecond, func() (int, string, error) {
		if !srv.IsACKedForNodes(gwKey.String(), v2Ver, []string{podID}) {
			return 0, "", fmt.Errorf("v2 not ACKed yet: %s", srv.ACKDetailsForNodes(gwKey.String(), v2Ver, []string{podID}))
		}
		return probeHostGET(listenerAddr, "example.com", "/v2")
	}, http.StatusOK); err != nil {
		t.Fatalf("Envoy did not recover after xDS blackhole: %v\nlogs:\n%s", err, containerLogs(containerName))
	}
	if accepts := proxy.acceptCount.Load(); accepts < 2 {
		t.Fatalf("proxy accept count after blackhole = %d, want >= 2", accepts)
	}
	status, body, err := probeHostGET(listenerAddr, "example.com", "/v2")
	if err != nil || status != http.StatusOK || body != "v2" {
		t.Fatalf("/v2 probe = (%d, %q, %v), want (200, %q, nil)", status, body, err, "v2")
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

func buildRenderedXDSDir(t *testing.T, gwKey types.NamespacedName, opts bootstrap.Options) (*corev1.Secret, string) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pki.SystemNamespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gwKey.Namespace}},
	).Build()
	ctx := context.Background()
	caSecret, err := pki.EnsureCA(ctx, kube)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if opts.NodeCluster == "" {
		return caSecret, ""
	}
	dir := writeRenderedXDSMaterial(t, gwKey, caSecret, opts)
	return caSecret, dir
}

func writeRenderedXDSMaterial(t *testing.T, gwKey types.NamespacedName, caSecret *corev1.Secret, opts bootstrap.Options) string {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pki.SystemNamespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gwKey.Namespace}},
		caSecret.DeepCopy(),
	).Build()
	owner := metav1.OwnerReference{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "Gateway",
		Name:       gwKey.Name,
		UID:        "gw-uid",
		Controller: ptr.To(true),
	}
	clientSecret, err := pki.EnsureClientCert(context.Background(), kube, gwKey, owner)
	if err != nil {
		t.Fatalf("EnsureClientCert: %v", err)
	}
	files, err := bootstrap.Render(opts)
	if err != nil {
		t.Fatalf("bootstrap.Render: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	caBytes := caSecret.Data["ca.crt"]
	if len(caBytes) == 0 {
		caBytes = caSecret.Data[corev1.TLSCertKey]
	}
	entries := map[string][]byte{
		"bootstrap.yaml":     []byte(files.BootstrapYAML),
		"client-secret.yaml": []byte(files.ClientSecretYAML),
		"ca-secret.yaml":     []byte(files.CASecretYAML),
		"tls.crt":            clientSecret.Data[corev1.TLSCertKey],
		"tls.key":            clientSecret.Data[corev1.TLSPrivateKeyKey],
		"ca.crt":             caBytes,
	}
	for name, content := range entries {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func buildDynamicRoutingSnapshot(t *testing.T, gwKey types.NamespacedName, path string, backendPort int) (*cachev3.Snapshot, string) {
	t.Helper()
	gateway := &ir.Gateway{
		Key:             gwKey,
		ConformanceMode: true,
		Listeners: []ir.Listener{{
			Name:      "http",
			Hostname:  "example.com",
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
				Name:     "example",
				Hostname: "example.com",
				Routes: []ir.Route{{
					Name:     "route",
					Match:    ir.PathMatch{Type: ir.PathMatchExact, Value: path},
					Backends: []ir.BackendRef{{Name: "backend", ClusterName: "backend", Weight: 1}},
				}},
			}},
		}},
		Clusters: []ir.Cluster{{
			Name:      "backend",
			Port:      int32(backendPort),
			Endpoints: []ir.Endpoint{{Address: "127.0.0.1", Port: int32(backendPort)}},
		}},
	}
	raw, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("translator.Build: %v", err)
	}
	version := raw.GetVersion(resourcev3.ListenerType)
	var listeners, routes, clusters []typesv3.Resource
	for _, res := range raw.GetResources(resourcev3.ListenerType) {
		listeners = append(listeners, res)
	}
	for _, res := range raw.GetResources(resourcev3.RouteType) {
		routes = append(routes, res)
	}
	for _, res := range raw.GetResources(resourcev3.ClusterType) {
		c := res.(*clusterv3.Cluster)
		setClusterEndpoint(c, "host.docker.internal", backendPort)
		clusters = append(clusters, c)
	}
	snap, err := cachev3.NewSnapshot(version, map[resourcev3.Type][]typesv3.Resource{
		resourcev3.ListenerType: listeners,
		resourcev3.RouteType:    routes,
		resourcev3.ClusterType:  clusters,
	})
	if err != nil {
		t.Fatalf("cachev3.NewSnapshot: %v", err)
	}
	if err := snap.ConstructVersionMap(); err != nil {
		t.Fatalf("ConstructVersionMap: %v", err)
	}
	return snap, version
}

type blackholeConn struct {
	client    net.Conn
	upstream  net.Conn
	blackhole atomic.Bool
}

type blackholeProxy struct {
	ln          net.Listener
	addr        string
	target      string
	acceptCount atomic.Int64
	mu          sync.Mutex
	conns       []*blackholeConn
}

func startBlackholeProxy(t *testing.T, target string) *blackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &blackholeProxy{ln: ln, addr: ln.Addr().String(), target: target}
	t.Cleanup(p.close)
	go p.serve()
	return p
}

func (p *blackholeProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.acceptCount.Add(1)
		upstream, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		bc := &blackholeConn{client: client, upstream: upstream}
		p.mu.Lock()
		p.conns = append(p.conns, bc)
		p.mu.Unlock()
		pipe := func(dst, src net.Conn) {
			buf := make([]byte, 32*1024)
			for {
				n, rerr := src.Read(buf)
				if n > 0 && !bc.blackhole.Load() {
					if _, werr := dst.Write(buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					if !bc.blackhole.Load() {
						_ = dst.Close()
					}
					return
				}
			}
		}
		go pipe(upstream, client)
		go pipe(client, upstream)
	}
}

func (p *blackholeProxy) blackholeExisting() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.blackhole.Store(true)
	}
}

func (p *blackholeProxy) close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.client.Close()
		_ = c.upstream.Close()
	}
}

func probeHostGET(addr, host, path string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
