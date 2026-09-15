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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	envoyImage        = "envoyproxy/envoy:v1.39.1"
	envoyListenerPort = 10080
	envoyAdminPort    = 19000
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("Docker is required for -tags envoy: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Fatalf("Docker daemon is required for -tags envoy: %v\n%s", err, output)
	}
}

func staticBootstrap(snapshot *cachev3.Snapshot) (*bootstrapv3.Bootstrap, error) {
	routes := make(map[string]*routev3.RouteConfiguration)
	for name, resource := range snapshot.GetResources(resourcev3.RouteType) {
		routeConfig, ok := resource.(*routev3.RouteConfiguration)
		if !ok {
			return nil, fmt.Errorf("route resource %q has type %T", name, resource)
		}
		routes[name] = routeConfig
	}
	assignments := make(map[string]*endpointv3.ClusterLoadAssignment)
	for name, resource := range snapshot.GetResources(resourcev3.EndpointType) {
		assignment, ok := resource.(*endpointv3.ClusterLoadAssignment)
		if !ok {
			return nil, fmt.Errorf("endpoint resource %q has type %T", name, resource)
		}
		assignments[name] = assignment
	}
	secretResources := make(map[string]*tlsv3.Secret)
	for name, resource := range snapshot.GetResources(resourcev3.SecretType) {
		secret, ok := resource.(*tlsv3.Secret)
		if !ok {
			return nil, fmt.Errorf("secret resource %q has type %T", name, resource)
		}
		secretResources[name] = secret
	}

	listeners := make([]*listenerv3.Listener, 0, len(snapshot.GetResources(resourcev3.ListenerType)))
	for name, resource := range snapshot.GetResources(resourcev3.ListenerType) {
		listener, ok := resource.(*listenerv3.Listener)
		if !ok {
			return nil, fmt.Errorf("listener resource %q has type %T", name, resource)
		}
		cloned := proto.Clone(listener).(*listenerv3.Listener)
		for _, chain := range listenerChains(cloned) {
			if err := inlineDownstreamTLS(chain, secretResources); err != nil {
				return nil, fmt.Errorf("inline TLS on listener %q: %w", name, err)
			}
			for _, filter := range chain.Filters {
				if filter.Name != "envoy.filters.network.http_connection_manager" {
					continue
				}
				hcm := &hcmv3.HttpConnectionManager{}
				if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
					return nil, fmt.Errorf("decode HCM on listener %q: %w", name, err)
				}
				rds := hcm.GetRds()
				if rds == nil {
					continue
				}
				routeConfig := routes[rds.RouteConfigName]
				if routeConfig == nil {
					return nil, fmt.Errorf("listener %q references missing route config %q", name, rds.RouteConfigName)
				}
				hcm.RouteSpecifier = &hcmv3.HttpConnectionManager_RouteConfig{
					RouteConfig: proto.Clone(routeConfig).(*routev3.RouteConfiguration),
				}
				typed, err := anypb.New(hcm)
				if err != nil {
					return nil, fmt.Errorf("encode static HCM on listener %q: %w", name, err)
				}
				filter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: typed}
			}
		}
		listeners = append(listeners, cloned)
	}

	clusters := make([]*clusterv3.Cluster, 0, len(snapshot.GetResources(resourcev3.ClusterType)))
	for name, resource := range snapshot.GetResources(resourcev3.ClusterType) {
		cluster, ok := resource.(*clusterv3.Cluster)
		if !ok {
			return nil, fmt.Errorf("cluster resource %q has type %T", name, resource)
		}
		cloned := proto.Clone(cluster).(*clusterv3.Cluster)
		if cloned.GetType() == clusterv3.Cluster_EDS {
			assignment := assignments[cloned.Name]
			if assignment == nil {
				return nil, fmt.Errorf("EDS cluster %q has no ClusterLoadAssignment", cloned.Name)
			}
			cloned.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}
			cloned.EdsClusterConfig = nil
			cloned.LoadAssignment = proto.Clone(assignment).(*endpointv3.ClusterLoadAssignment)
		}
		clusters = append(clusters, cloned)
	}

	secrets := make([]*tlsv3.Secret, 0, len(secretResources))
	for _, secret := range secretResources {
		secrets = append(secrets, proto.Clone(secret).(*tlsv3.Secret))
	}

	return &bootstrapv3.Bootstrap{
		Node: &corev3.Node{Id: "flareway-envoy-component", Cluster: "flareway-envoy-component"},
		StaticResources: &bootstrapv3.Bootstrap_StaticResources{
			Listeners: listeners,
			Clusters:  clusters,
			Secrets:   secrets,
		},
		Admin: &bootstrapv3.Admin{Address: socketAddress("0.0.0.0", envoyAdminPort)},
	}, nil
}

func listenerChains(listener *listenerv3.Listener) []*listenerv3.FilterChain {
	chains := append([]*listenerv3.FilterChain(nil), listener.FilterChains...)
	if listener.DefaultFilterChain != nil {
		chains = append(chains, listener.DefaultFilterChain)
	}
	return chains
}

func inlineDownstreamTLS(chain *listenerv3.FilterChain, secrets map[string]*tlsv3.Secret) error {
	if chain.TransportSocket == nil {
		return nil
	}
	context := &tlsv3.DownstreamTlsContext{}
	if err := chain.TransportSocket.GetTypedConfig().UnmarshalTo(context); err != nil {
		return fmt.Errorf("decode downstream TLS context: %w", err)
	}
	if context.CommonTlsContext == nil || len(context.CommonTlsContext.TlsCertificateSdsSecretConfigs) == 0 {
		return nil
	}
	for _, reference := range context.CommonTlsContext.TlsCertificateSdsSecretConfigs {
		secret := secrets[reference.Name]
		if secret == nil || secret.GetTlsCertificate() == nil {
			return fmt.Errorf("TLS certificate secret %q not found", reference.Name)
		}
		context.CommonTlsContext.TlsCertificates = append(
			context.CommonTlsContext.TlsCertificates,
			proto.Clone(secret.GetTlsCertificate()).(*tlsv3.TlsCertificate),
		)
	}
	context.CommonTlsContext.TlsCertificateSdsSecretConfigs = nil
	typed, err := anypb.New(context)
	if err != nil {
		return fmt.Errorf("encode downstream TLS context: %w", err)
	}
	chain.TransportSocket.ConfigType = &corev3.TransportSocket_TypedConfig{TypedConfig: typed}
	return nil
}

func writeBootstrap(t *testing.T, bootstrap *bootstrapv3.Bootstrap) string {
	t.Helper()
	data, err := (protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}).Marshal(bootstrap)
	if err != nil {
		t.Fatalf("marshal Envoy bootstrap: %v", err)
	}
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write Envoy bootstrap: %v", err)
	}
	return path
}

func validateWithEnvoy(t *testing.T, configPath string) {
	t.Helper()
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	mount := configPath + ":/etc/envoy/envoy.json:ro"
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-v", mount, envoyImage,
		"envoy", "--mode", "validate", "-c", "/etc/envoy/envoy.json")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Envoy rejected generated translator config: %v\n%s", err, output)
	}
}

type runningEnvoy struct {
	name        string
	listenerURL string
}

func startEnvoy(t *testing.T, configPath string, listenerPort int) runningEnvoy {
	t.Helper()
	requireDocker(t)
	if listenerPort <= 0 || listenerPort > 65535 {
		t.Fatalf("invalid Envoy listener port %d", listenerPort)
	}
	name := "flareway-envoy-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	mount := configPath + ":/etc/envoy/envoy.json:ro"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	args := []string{
		"run", "--rm", "-d", "--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"-p", "127.0.0.1::" + strconv.Itoa(listenerPort),
		"-p", "127.0.0.1::" + strconv.Itoa(envoyAdminPort),
		"-v", mount,
		envoyImage, "envoy", "-c", "/etc/envoy/envoy.json", "--concurrency", "1", "--disable-hot-restart",
	}
	if output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start Envoy container: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).Run()
	})

	listenerAddress := dockerPort(t, name, listenerPort)
	return runningEnvoy{name: name, listenerURL: "http://" + listenerAddress}
}

func listenerPort(bootstrap *bootstrapv3.Bootstrap) (int, error) {
	if bootstrap == nil || bootstrap.StaticResources == nil || len(bootstrap.StaticResources.Listeners) != 1 {
		return 0, fmt.Errorf("expected exactly one static listener")
	}
	socket := bootstrap.StaticResources.Listeners[0].GetAddress().GetSocketAddress()
	if socket == nil || socket.GetPortValue() == 0 {
		return 0, fmt.Errorf("static listener has no socket port")
	}
	return int(socket.GetPortValue()), nil
}

func dockerPort(t *testing.T, container string, port int) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "port", container, strconv.Itoa(port)+"/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("read Docker port for %s: %v\n%s", container, err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("Docker returned no mapping for %s/%d", container, port)
	}
	address := strings.TrimSpace(lines[len(lines)-1])
	host, mappedPort, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("parse Docker port %q: %v", address, err)
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, mappedPort)
}

func containerLogs(container string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "logs", container).CombinedOutput()
	if err != nil && len(output) == 0 {
		return err.Error()
	}
	return string(output)
}

func setClusterEndpoint(cluster *clusterv3.Cluster, host string, port int) {
	cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS}
	cluster.EdsClusterConfig = nil
	cluster.LoadAssignment = &endpointv3.ClusterLoadAssignment{
		ClusterName: cluster.Name,
		Endpoints: []*endpointv3.LocalityLbEndpoints{{
			LbEndpoints: []*endpointv3.LbEndpoint{{
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Hostname: host,
					Address:  socketAddress(host, port),
				}},
			}},
		}},
	}
}

func socketAddress(host string, port int) *corev3.Address {
	return &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
		Address:       host,
		PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: uint32(port)},
	}}}
}

func findCluster(bootstrap *bootstrapv3.Bootstrap, name string) (*clusterv3.Cluster, error) {
	for _, cluster := range bootstrap.StaticResources.Clusters {
		if cluster.Name == name {
			return cluster, nil
		}
	}
	return nil, fmt.Errorf("cluster %q not found", name)
}

func findClusterPrefix(bootstrap *bootstrapv3.Bootstrap, prefix string) (*clusterv3.Cluster, error) {
	var found *clusterv3.Cluster
	for _, cluster := range bootstrap.StaticResources.Clusters {
		if !strings.HasPrefix(cluster.Name, prefix) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple clusters have prefix %q", prefix)
		}
		found = cluster
	}
	if found == nil {
		return nil, fmt.Errorf("cluster prefix %q not found", prefix)
	}
	return found, nil
}

func waitForHTTP(ctx context.Context, interval time.Duration, request func() (int, string, error), wantStatus int) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastStatus int
	var lastBody string
	var lastErr error
	for {
		lastStatus, lastBody, lastErr = request()
		if lastErr == nil && lastStatus == wantStatus {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for HTTP status %d: last status=%d body=%q error=%v: %w", wantStatus, lastStatus, lastBody, lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}
