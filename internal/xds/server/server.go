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

// Package server provides Flareway's leader-elected Delta ADS server.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	xdslog "github.com/envoyproxy/go-control-plane/pkg/log"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// DefaultAddress is the default Delta ADS listen address.
	DefaultAddress = ":18000"
	// DefaultKeepaliveTime is the server HTTP/2 PING cadence for idle streams.
	DefaultKeepaliveTime = 30 * time.Second
	// DefaultKeepaliveTimeout is the server HTTP/2 keepalive ACK wait window.
	DefaultKeepaliveTimeout = 5 * time.Second
	// DefaultKeepaliveMinTime is the minimum interval allowed between client
	// HTTP/2 keepalive PINGs before ENHANCE_YOUR_CALM triggers. It stays below
	// Envoy's 30s default keepalive interval to absorb timer jitter.
	DefaultKeepaliveMinTime = 15 * time.Second
)

var snapshotResourceTypes = []resourcev3.Type{
	resourcev3.ListenerType,
	resourcev3.RouteType,
	resourcev3.ClusterType,
	resourcev3.EndpointType,
	resourcev3.SecretType,
}

// Options configures a Delta ADS server.
type Options struct {
	Address          string
	TLSConfig        *tls.Config
	Logger           logr.Logger
	KeepaliveTime    *time.Duration
	KeepaliveTimeout *time.Duration
	KeepaliveMinTime *time.Duration
}

// Server owns the snapshot cache, ACK tracker, and leader-elected gRPC
// lifecycle. It is safe to publish snapshots before Start is called.
type Server struct {
	address          string
	tlsConfig        *tls.Config
	logger           logr.Logger
	cache            *orderedDeltaCache
	tracker          *AckTracker
	events           chan event.GenericEvent
	keepaliveTime    time.Duration
	keepaliveTimeout time.Duration
	keepaliveMinTime time.Duration
}

var _ manager.Runnable = (*Server)(nil)
var _ manager.LeaderElectionRunnable = (*Server)(nil)

// New constructs a Delta ADS Runnable. TLSConfig must require and verify
// client certificates; pki.ServerTLSConfig returns a suitable configuration.
func New(opts Options) (*Server, error) {
	if opts.TLSConfig == nil {
		return nil, errors.New("xDS TLS configuration is required")
	}
	if opts.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || opts.TLSConfig.ClientCAs == nil {
		return nil, errors.New("xDS TLS configuration must require and verify client certificates")
	}
	keepaliveTime := DefaultKeepaliveTime
	if opts.KeepaliveTime != nil {
		if *opts.KeepaliveTime < time.Second {
			return nil, fmt.Errorf("xDS keepalive time %s must be at least 1s", *opts.KeepaliveTime)
		}
		keepaliveTime = *opts.KeepaliveTime
	}
	keepaliveTimeout := DefaultKeepaliveTimeout
	if opts.KeepaliveTimeout != nil {
		if *opts.KeepaliveTimeout <= 0 {
			return nil, fmt.Errorf("xDS keepalive timeout %s must be positive", *opts.KeepaliveTimeout)
		}
		keepaliveTimeout = *opts.KeepaliveTimeout
	}
	keepaliveMinTime := DefaultKeepaliveMinTime
	if opts.KeepaliveMinTime != nil {
		if *opts.KeepaliveMinTime <= 0 {
			return nil, fmt.Errorf("xDS keepalive minimum interval %s must be positive", *opts.KeepaliveMinTime)
		}
		keepaliveMinTime = *opts.KeepaliveMinTime
	}
	address := opts.Address
	if address == "" {
		address = DefaultAddress
	}
	logger := opts.Logger
	if logger.GetSink() == nil {
		logger = logr.Discard()
	}
	tracker := NewAckTracker()
	baseCache := cachev3.NewSnapshotCache(true, gatewayNodeHash{}, loggerAdapter{logger: logger.WithName("cache")})
	cache := newOrderedDeltaCache(baseCache, gatewayNodeHash{})
	return &Server{
		address:          address,
		tlsConfig:        opts.TLSConfig.Clone(),
		logger:           logger,
		cache:            cache,
		tracker:          tracker,
		events:           make(chan event.GenericEvent, 256),
		keepaliveTime:    keepaliveTime,
		keepaliveTimeout: keepaliveTimeout,
		keepaliveMinTime: keepaliveMinTime,
	}, nil
}

// Start serves Delta ADS until ctx is canceled. It implements
// controller-runtime manager.Runnable.
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("listen for xDS on %s: %w", s.address, err)
	}
	defer func() { _ = listener.Close() }()

	callbacks := serverv3.CallbackFuncs{
		DeltaStreamClosedFunc: func(streamID int64, _ *corev3.Node) {
			s.cache.OnStreamClosed(streamID)
			node := s.tracker.OnStreamClosed(streamID)
			if ctx.Err() != nil {
				return
			}
			namespace, name, ok := strings.Cut(node, "/")
			if !ok || namespace == "" || name == "" {
				return
			}
			select {
			case s.events <- event.GenericEvent{
				Object: &metav1.PartialObjectMetadata{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      name,
					},
				},
			}:
			default:
			}
		},
		StreamDeltaRequestFunc: func(streamID int64, req *discoverygrpc.DeltaDiscoveryRequest) error {
			s.cache.BindRequestStream(req, streamID)
			s.tracker.OnRequest(streamID, req)
			return nil
		},
		StreamDeltaResponseFunc: func(streamID int64, req *discoverygrpc.DeltaDiscoveryRequest, resp *discoverygrpc.DeltaDiscoveryResponse) {
			s.tracker.OnResponse(streamID, req, resp)
		},
	}
	xdsServer := serverv3.NewServer(ctx, s.cache, callbacks)
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(s.tlsConfig.Clone())),
		grpc.StreamInterceptor(sanAuthorizationInterceptor()),
		grpc.MaxConcurrentStreams(1_000_000),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: s.keepaliveTime, Timeout: s.keepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: s.keepaliveMinTime, PermitWithoutStream: true}),
	)
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, xdsServer)

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			grpcServer.GracefulStop()
		case <-stopped:
		}
	}()
	s.logger.Info("starting Delta ADS server", "address", s.address)
	err = grpcServer.Serve(listener)
	close(stopped)
	if err == nil || errors.Is(err, grpc.ErrServerStopped) || ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("serve xDS: %w", err)
}

// NeedLeaderElection makes the xDS server active only on the elected manager
// replica, matching the single-writer snapshot contract.
func (*Server) NeedLeaderElection() bool {
	return true
}

// SetSnapshot validates and publishes a complete snapshot for node, where node
// is the Gateway key "namespace/name".
func (s *Server) SetSnapshot(ctx context.Context, node string, snapshot *cachev3.Snapshot) error {
	if node == "" {
		return errors.New("xDS snapshot node key is required")
	}
	if snapshot == nil {
		return errors.New("xDS snapshot is nil")
	}
	if err := snapshot.Consistent(); err != nil {
		return fmt.Errorf("validate xDS snapshot for %s: %w", node, err)
	}
	if err := snapshot.ConstructVersionMap(); err != nil {
		return fmt.Errorf("construct Delta xDS version map for %s: %w", node, err)
	}
	version, fingerprints, err := snapshotVersionAndFingerprints(snapshot)
	if err != nil {
		return fmt.Errorf("inspect xDS snapshot for %s: %w", node, err)
	}
	s.tracker.ExpectSnapshot(node, version, fingerprints, snapshotRequiredTypes(snapshot))
	if err := s.cache.SetSnapshot(ctx, node, snapshot); err != nil {
		return fmt.Errorf("publish xDS snapshot for %s: %w", node, err)
	}
	return nil
}

// ClearSnapshot removes a Gateway snapshot and its convergence state.
func (s *Server) ClearSnapshot(node string) {
	s.cache.ClearSnapshot(node)
	s.tracker.Forget(node)
}

// IsACKed reports whether every live stream has proven the current resource
// fingerprints for its subscribed and required types. Matching initial versions
// on reconnect count as proof even when received before snapshot publication.
func (s *Server) IsACKed(node, version string) bool {
	return s.tracker.IsACKed(node, version)
}

// IsACKedForNodes reports whether every expected Envoy node.id on node has at
// least one live stream and every live stream for those node IDs has proven
// the requested snapshot fingerprints.
func (s *Server) IsACKedForNodes(node, version string, nodeIDs []string) bool {
	return s.tracker.IsACKedForNodes(node, version, nodeIDs)
}

// ACKDetails explains why the requested snapshot has not converged.
func (s *Server) ACKDetails(node, version string) string {
	return s.tracker.ConvergenceDetails(node, version)
}

// ACKDetailsForNodes explains why the expected Envoy pods have not converged
// without exposing stream or Pod UIDs.
func (s *Server) ACKDetailsForNodes(node, version string, nodeIDs []string) string {
	return s.tracker.ConvergenceDetailsForNodes(node, version, nodeIDs)
}

// Events emits a Gateway-keyed generic event when an xDS stream closes.
func (s *Server) Events() <-chan event.GenericEvent {
	return s.events
}

// LastNACK returns the latest rejection for node.
func (s *Server) LastNACK(node string) (version, detail string, ok bool) {
	nack, ok := s.tracker.LastNACK(node)
	if !ok {
		return "", "", false
	}
	return nack.Version, nack.Detail, true
}

// AckTracker exposes the read-only convergence source for diagnostics and
// focused controller integration.
func (s *Server) AckTracker() *AckTracker {
	return s.tracker
}

// Cache returns the underlying cache for xDS diagnostics.
func (s *Server) Cache() cachev3.SnapshotCache {
	return s.cache
}

type gatewayNodeHash struct{}

func (gatewayNodeHash) ID(node *corev3.Node) string {
	if node == nil {
		return ""
	}
	return node.GetCluster()
}

func snapshotVersionAndFingerprints(snapshot *cachev3.Snapshot) (string, map[string]string, error) {
	version := snapshot.GetVersion(resourcev3.ListenerType)
	if version == "" {
		return "", nil, errors.New("snapshot has no version")
	}
	fingerprints := make(map[string]string)
	for _, typeURL := range snapshotResourceTypes {
		current := snapshot.GetVersion(typeURL)
		if current != "" && current != version {
			return "", nil, fmt.Errorf("resource type %s has version %q, want %q", typeURL, current, version)
		}
		if len(snapshot.GetResources(typeURL)) == 0 {
			continue
		}
		fingerprint, err := fingerprintVersionMap(snapshot.GetVersionMap(string(typeURL)))
		if err != nil {
			return "", nil, fmt.Errorf("fingerprint resources for %s: %w", typeURL, err)
		}
		fingerprints[string(typeURL)] = fingerprint
	}
	return version, fingerprints, nil
}

func fingerprintVersionMap(versionMap map[string]string) (string, error) {
	data, err := json.Marshal(versionMap)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func snapshotRequiredTypes(snapshot *cachev3.Snapshot) map[string]struct{} {
	required := make(map[string]struct{})
	for _, typeURL := range []resourcev3.Type{resourcev3.ListenerType, resourcev3.ClusterType} {
		if len(snapshot.GetResources(typeURL)) > 0 {
			required[string(typeURL)] = struct{}{}
		}
	}
	for typeURL := range cachev3.GetAllResourceReferences(snapshot.Resources) {
		if len(snapshot.GetResources(typeURL)) > 0 {
			required[string(typeURL)] = struct{}{}
		}
	}
	for _, item := range snapshot.GetResources(resourcev3.ListenerType) {
		if listener, ok := item.(*listenerv3.Listener); ok {
			listenerSDSRequired(listener, snapshot, required)
		}
	}
	for _, item := range snapshot.GetResources(resourcev3.ClusterType) {
		if cluster, ok := item.(*clusterv3.Cluster); ok {
			clusterSDSRequired(cluster, snapshot, required)
		}
	}
	return required
}

func markSecretReference(name string, snapshot *cachev3.Snapshot, required map[string]struct{}) {
	if _, ok := snapshot.GetResources(resourcev3.SecretType)[name]; ok {
		required[string(resourcev3.SecretType)] = struct{}{}
	}
}

func listenerSDSRequired(listener *listenerv3.Listener, snapshot *cachev3.Snapshot, required map[string]struct{}) {
	chains := listener.GetFilterChains()
	if listener.GetDefaultFilterChain() != nil {
		chains = append(chains, listener.GetDefaultFilterChain())
	}
	for _, chain := range chains {
		socket := chain.GetTransportSocket()
		if socket == nil {
			continue
		}
		typed := socket.GetTypedConfig()
		if typed == nil {
			continue
		}
		ctx := &tlsv3.DownstreamTlsContext{}
		if typed.UnmarshalTo(ctx) != nil {
			continue
		}
		for _, cfg := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			markSecretReference(cfg.GetName(), snapshot, required)
		}
		if cfg := ctx.GetCommonTlsContext().GetValidationContextSdsSecretConfig(); cfg != nil {
			markSecretReference(cfg.GetName(), snapshot, required)
		}
		if combined := ctx.GetCommonTlsContext().GetCombinedValidationContext(); combined != nil {
			if cfg := combined.GetValidationContextSdsSecretConfig(); cfg != nil {
				markSecretReference(cfg.GetName(), snapshot, required)
			}
		}
	}
}

func clusterSDSRequired(cluster *clusterv3.Cluster, snapshot *cachev3.Snapshot, required map[string]struct{}) {
	socket := cluster.GetTransportSocket()
	if socket == nil {
		return
	}
	typed := socket.GetTypedConfig()
	if typed == nil {
		return
	}
	ctx := &tlsv3.UpstreamTlsContext{}
	if typed.UnmarshalTo(ctx) != nil {
		return
	}
	common := ctx.GetCommonTlsContext()
	for _, cfg := range common.GetTlsCertificateSdsSecretConfigs() {
		markSecretReference(cfg.GetName(), snapshot, required)
	}
	if cfg := common.GetValidationContextSdsSecretConfig(); cfg != nil {
		markSecretReference(cfg.GetName(), snapshot, required)
	}
	if combined := common.GetCombinedValidationContext(); combined != nil {
		if cfg := combined.GetValidationContextSdsSecretConfig(); cfg != nil {
			markSecretReference(cfg.GetName(), snapshot, required)
		}
	}
}

type loggerAdapter struct {
	logger logr.Logger
}

var _ xdslog.Logger = loggerAdapter{}

func (l loggerAdapter) Debugf(format string, args ...interface{}) {
	l.logger.V(1).Info(fmt.Sprintf(format, args...))
}

func (l loggerAdapter) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l loggerAdapter) Warnf(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l loggerAdapter) Errorf(format string, args ...interface{}) {
	l.logger.Error(errors.New("go-control-plane"), fmt.Sprintf(format, args...))
}
