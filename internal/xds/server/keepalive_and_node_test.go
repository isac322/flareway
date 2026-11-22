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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	typesv3 "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/isac322/flareway/internal/xds/pki"
)

func TestNewKeepaliveDefaultsAndValidation(t *testing.T) {
	_, caPool, _ := newTestGatewayCerts(t, types.NamespacedName{Namespace: "apps", Name: "edge"})
	serverTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}

	srv, err := New(Options{TLSConfig: serverTLS})
	if err != nil {
		t.Fatalf("New() default keepalive failed: %v", err)
	}
	if srv.keepaliveTime != DefaultKeepaliveTime || srv.keepaliveTimeout != DefaultKeepaliveTimeout || srv.keepaliveMinTime != DefaultKeepaliveMinTime {
		t.Fatalf("unexpected defaults: time=%s timeout=%s minTime=%s", srv.keepaliveTime, srv.keepaliveTimeout, srv.keepaliveMinTime)
	}
	if DefaultKeepaliveMinTime >= 30*time.Second {
		t.Fatalf("DefaultKeepaliveMinTime = %s, must stay below Envoy 30s default keepalive interval", DefaultKeepaliveMinTime)
	}

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{name: "time below 1s", opts: Options{TLSConfig: serverTLS, KeepaliveTime: ptr.To(500 * time.Millisecond)}},
		{name: "non-positive timeout", opts: Options{TLSConfig: serverTLS, KeepaliveTimeout: ptr.To(time.Duration(0))}},
		{name: "non-positive min time", opts: Options{TLSConfig: serverTLS, KeepaliveMinTime: ptr.To(-time.Second)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Fatalf("New(%s) succeeded, want error", tc.name)
			}
		})
	}
}

func TestAckTrackerIsACKedForNodesAndDetails(t *testing.T) {
	tracker := NewAckTracker()
	node, version := "apps/edge", "v1"
	pod1 := "apps/edge/pod-uid-alpha"
	pod2 := "apps/edge/pod-uid-beta"
	deadPod := "apps/edge/pod-uid-terminating"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "l1"}, map[string]struct{}{resourcev3.ListenerType: {}})

	if tracker.IsACKedForNodes(node, version, nil) {
		t.Fatal("empty nodeIDs must not converge non-empty snapshot")
	}
	if tracker.IsACKedForNodes(node, version, []string{""}) {
		t.Fatal("UID-less pod entry must not converge non-empty snapshot")
	}

	// Stream 1 connects for pod1 and ACKs.
	ackStream := func(streamID int64, nodeID, nonce string) {
		tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{
			Node:    &corev3.Node{Cluster: node, Id: nodeID},
			TypeUrl: resourcev3.ListenerType,
		})
		tracker.OnResponse(streamID, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.ListenerType,
			SystemVersionInfo: version,
			Nonce:             nonce,
		})
		tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.ListenerType,
			ResponseNonce: nonce,
		})
	}
	ackStream(1, pod1, "n1")
	if tracker.IsACKedForNodes(node, version, []string{pod1, pod2}) {
		t.Fatal("partial pod ACK converged 2-pod gateway")
	}
	details := tracker.ConvergenceDetailsForNodes(node, version, []string{pod1, pod2})
	if !strings.Contains(details, "1/2 dataplane Pod(s) connected") {
		t.Fatalf("details = %q, want 1/2 dataplane Pod(s) connected", details)
	}
	for _, secret := range []string{"pod-uid-alpha", "pod-uid-beta", "pod-uid-terminating"} {
		if strings.Contains(details, secret) {
			t.Fatalf("details %q leaked pod UID %q", details, secret)
		}
	}

	// Stream without node.id cannot satisfy a pod UID check.
	ackStream(99, "", "n99")
	if tracker.IsACKedForNodes(node, version, []string{pod1, pod2}) {
		t.Fatal("stream without node.id satisfied pod2")
	}
	tracker.OnStreamClosed(99)

	// Terminating pod has an un-ACKed stream, active pod1 + pod2 both ACK -> converges.
	tracker.OnRequest(3, &discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: node, Id: deadPod},
		TypeUrl: resourcev3.ListenerType,
	})
	ackStream(2, pod2, "n2")
	if !tracker.IsACKedForNodes(node, version, []string{pod1, pod2}) {
		t.Fatalf("all active pods ACKed yet IsACKedForNodes returned false; details=%q", tracker.ConvergenceDetailsForNodes(node, version, []string{pod1, pod2}))
	}

	// Peer NACK on pod2 blocks convergence without leaking UID.
	tracker.OnResponse(2, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl:           resourcev3.ListenerType,
		SystemVersionInfo: version,
		Nonce:             "n2b",
	})
	tracker.OnRequest(2, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:       resourcev3.ListenerType,
		ResponseNonce: "n2b",
		ErrorDetail:   &statuspb.Status{Message: "bad listener"},
	})
	if tracker.IsACKedForNodes(node, version, []string{pod1, pod2}) {
		t.Fatal("NACK on pod2 still converged")
	}
	nackDetails := tracker.ConvergenceDetailsForNodes(node, version, []string{pod1, pod2})
	if !strings.Contains(nackDetails, "NACK") || strings.Contains(nackDetails, "pod-uid-beta") {
		t.Fatalf("nackDetails = %q", nackDetails)
	}

	// Forget preserves stream node.id for subsequent snapshots where client omits Node.
	tracker.Forget(node)
	tracker.ExpectSnapshot(node, "v2", map[string]string{resourcev3.ListenerType: "l2"}, map[string]struct{}{resourcev3.ListenerType: {}})
	for _, s := range []struct {
		id    int64
		nonce string
	}{{1, "m1"}, {2, "m2"}} {
		tracker.OnResponse(s.id, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.ListenerType,
			SystemVersionInfo: "v2",
			Nonce:             s.nonce,
		})
		tracker.OnRequest(s.id, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: s.nonce})
	}
	if !tracker.IsACKedForNodes(node, "v2", []string{pod1, pod2}) {
		t.Fatal("Forget cleared stream nodeIDs")
	}

	// Closing pod2 stream drops convergence.
	if closedNode := tracker.OnStreamClosed(2); closedNode != node {
		t.Fatalf("OnStreamClosed() = %q, want %q", closedNode, node)
	}
	if tracker.IsACKedForNodes(node, "v2", []string{pod1, pod2}) {
		t.Fatal("closed stream remained converged")
	}
}

func TestServerNodeIDImmutabilityEventsAndKeepalive(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "apps", Name: "edge"}
	serverTLS, caPool, clientCert := newTestGatewayCerts(t, gwKey)

	addr := reserveLoopbackAddr(t)
	srv, err := New(Options{
		Address:          addr,
		TLSConfig:        serverTLS,
		KeepaliveTime:    ptr.To(time.Second),
		KeepaliveTimeout: ptr.To(500 * time.Millisecond),
		KeepaliveMinTime: ptr.To(500 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	routerAny, err := anypb.New(&routerv3.Router{})
	if err != nil {
		t.Fatal(err)
	}
	hcmAny, err := anypb.New(&hcmv3.HttpConnectionManager{
		StatPrefix: "test",
		RouteSpecifier: &hcmv3.HttpConnectionManager_RouteConfig{
			RouteConfig: &routev3.RouteConfiguration{
				Name: "test-route",
				VirtualHosts: []*routev3.VirtualHost{{
					Name:    "vhost",
					Domains: []string{"*"},
					Routes: []*routev3.Route{{
						Match:  &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
						Action: &routev3.Route_Route{Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "test-cluster"}}},
					}},
				}},
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{{
			Name:       "envoy.filters.http.router",
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: routerAny},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	listenerRes := &listenerv3.Listener{
		Name: "test-listener",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address: "127.0.0.1", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 18080},
		}}},
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       "envoy.filters.network.http_connection_manager",
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcmAny},
			}},
		}},
	}
	clusterRes := &clusterv3.Cluster{
		Name:                 "test-cluster",
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}
	snap, err := cachev3.NewSnapshot("v1", map[resourcev3.Type][]typesv3.Resource{
		resourcev3.ListenerType: {listenerRes},
		resourcev3.ClusterType:  {clusterRes},
	})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if err := srv.SetSnapshot(ctx, gwKey.String(), snap); err != nil {
		t.Fatalf("SetSnapshot: %v", err)
	}

	dial := func(ka keepalive.ClientParameters) *grpc.ClientConn {
		creds := credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      caPool,
			ServerName:   "flareway-xds.flareway-system.svc.cluster.local",
			Certificates: []tls.Certificate{clientCert},
		})
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithKeepaliveParams(ka))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	// Wait until server accepts connections using an ACKed stream s0, then verify
	// closing s0 emits XDSEvents wakeup *after* OnStreamClosed drops convergence.
	var conn *grpc.ClientConn
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := dial(keepalive.ClientParameters{
			Time:                time.Second,
			Timeout:             500 * time.Millisecond,
			PermitWithoutStream: true,
		})
		s0Ctx, s0Cancel := context.WithCancel(ctx)
		client := discoveryv3.NewAggregatedDiscoveryServiceClient(c)
		stream, serr := client.DeltaAggregatedResources(s0Ctx)
		if serr == nil {
			err = stream.Send(&discoveryv3.DeltaDiscoveryRequest{
				Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-1"},
				TypeUrl: resourcev3.ClusterType,
			})
			if err == nil {
				if lerr := stream.Send(&discoveryv3.DeltaDiscoveryRequest{
					TypeUrl: resourcev3.ListenerType,
				}); lerr == nil {
					for range 2 {
						resp, rerr := stream.Recv()
						if rerr != nil {
							err = rerr
							break
						}
						if aerr := stream.Send(&discoveryv3.DeltaDiscoveryRequest{
							TypeUrl:       resp.GetTypeUrl(),
							ResponseNonce: resp.GetNonce(),
						}); aerr != nil {
							err = aerr
							break
						}
					}
					if err == nil {
						for range 50 {
							if srv.IsACKedForNodes(gwKey.String(), "v1", []string{"apps/edge/uid-1"}) {
								break
							}
							time.Sleep(10 * time.Millisecond)
						}
						if !srv.IsACKedForNodes(gwKey.String(), "v1", []string{"apps/edge/uid-1"}) {
							t.Fatal("s0 did not converge before close")
						}
						conn = c
						s0Cancel()
						break
					}
				}
			}
		}
		s0Cancel()
		if time.Now().After(deadline) {
			t.Fatalf("server failed to accept mTLS stream: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wakeup event must arrive only after OnStreamClosed cleared convergence.
	select {
	case ev := <-srv.Events():
		if ev.Object.GetNamespace() != gwKey.Namespace || ev.Object.GetName() != gwKey.Name {
			t.Fatalf("unexpected wakeup object %s/%s", ev.Object.GetNamespace(), ev.Object.GetName())
		}
		if srv.IsACKedForNodes(gwKey.String(), "v1", []string{"apps/edge/uid-1"}) {
			t.Fatal("wakeup arrived while dead stream still counted as converged")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected stream-close wakeup from probe stream")
	}

	// 1. node.id immutability enforcement: switching node.id on stream returns PermissionDenied.
	adsClient := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	s1, err := adsClient.DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("open stream 1: %v", err)
	}
	if err := s1.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-1"},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("send initial request: %v", err)
	}
	// Receive initial empty/response so we know stream passed auth.
	if _, err := s1.Recv(); err != nil {
		t.Fatalf("recv initial response: %v", err)
	}
	// Keepalive test across >4 PING intervals (client Time=1s, server MinTime=500ms, maxPingStrikes=2 would kill at ~3s if violated).
	if err := s1.Send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("send follow-up without node: %v", err)
	}
	time.Sleep(4500 * time.Millisecond)
	// Switch node.id now -> must be rejected with PermissionDenied (not ENHANCE_YOUR_CALM!).
	err = s1.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-2"},
		TypeUrl: resourcev3.ClusterType,
	})
	if err == nil {
		err = recvUntilError(s1, 3*time.Second)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("switching node.id yielded %v (%v), want PermissionDenied", status.Code(err), err)
	}

	// Switching from initially empty node.id -> "uid-a" -> "uid-b" also rejected.
	s2, err := adsClient.DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("open stream 2: %v", err)
	}
	if err := s2.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String()},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("send empty node.id request: %v", err)
	}
	if _, err := s2.Recv(); err != nil {
		t.Fatalf("recv stream 2: %v", err)
	}
	if err := s2.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-a"},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("send late node.id request: %v", err)
	}
	err = s2.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-b"},
		TypeUrl: resourcev3.ClusterType,
	})
	if err == nil {
		err = recvUntilError(s2, 3*time.Second)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("switching late node.id yielded %v (%v), want PermissionDenied", status.Code(err), err)
	}

	// Cancel server context with open stream -> no wakeup after cancel.
	s3, err := adsClient.DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("open stream 3: %v", err)
	}
	if err := s3.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: "apps/edge/uid-c"},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatalf("send stream 3: %v", err)
	}
	if _, err := s3.Recv(); err != nil {
		t.Fatalf("recv stream 3: %v", err)
	}
	for len(srv.Events()) > 0 {
		<-srv.Events()
	}
	cancel()
	_ = conn.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("server.Start error = %v", err)
	}
	select {
	case ev := <-srv.Events():
		t.Fatalf("unexpected post-cancel event: %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

func newTestGatewayCerts(t *testing.T, gwKey types.NamespacedName) (*tls.Config, *x509.CertPool, tls.Certificate) {
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
	serverTLS, err := pki.ServerTLSConfig(caSecret)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	owner := metav1.OwnerReference{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "Gateway",
		Name:       gwKey.Name,
		UID:        "gw-uid",
		Controller: ptr.To(true),
	}
	clientSecret, err := pki.EnsureClientCert(ctx, kube, gwKey, owner)
	if err != nil {
		t.Fatalf("EnsureClientCert: %v", err)
	}
	clientCert, err := tls.X509KeyPair(clientSecret.Data[corev1.TLSCertKey], clientSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caSecret.Data["ca.crt"]) {
		if !caPool.AppendCertsFromPEM(caSecret.Data[corev1.TLSCertKey]) {
			t.Fatal("failed to parse CA cert")
		}
	}
	if !errors.Is(nil, nil) {
		t.Fatal("unreachable")
	}
	return serverTLS, caPool, clientCert
}

func recvUntilError(stream discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errors.New("timed out waiting for stream rejection")
	}
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}
