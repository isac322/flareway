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
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/isac322/flareway/internal/xds/translator"
)

func buildBoundClusterSnapshot(t *testing.T, version string, clusterSNIs map[string]string) *cachev3.Snapshot {
	t.Helper()
	clusters := make([]cachetypes.Resource, 0, len(clusterSNIs))
	endpoints := make([]cachetypes.Resource, 0, len(clusterSNIs))
	for name, sni := range clusterSNIs {
		var transport *corev3.TransportSocket
		if sni != "" {
			tlsAny, err := anypb.New(&tlsv3.UpstreamTlsContext{Sni: sni})
			if err != nil {
				t.Fatal(err)
			}
			transport = &corev3.TransportSocket{
				Name:       "envoy.transport_sockets.tls",
				ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsAny},
			}
		}
		clusters = append(clusters, &clusterv3.Cluster{
			Name: name,
			ClusterDiscoveryType: &clusterv3.Cluster_Type{
				Type: clusterv3.Cluster_EDS,
			},
			EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
				EdsConfig: &corev3.ConfigSource{
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
				},
			},
			TransportSocket: transport,
		})
		endpoints = append(endpoints, &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
						Address: &corev3.Address{Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address:       "127.0.0.1",
								PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 8080},
							},
						}},
					}},
				}},
			}},
		})
	}
	snap, err := cachev3.NewSnapshot(version, map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType:  clusters,
		resourcev3.EndpointType: endpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.ConstructVersionMap(); err != nil {
		t.Fatal(err)
	}
	cdsVersions := snap.VersionMap[resourcev3.ClusterType]
	edsVersions := snap.VersionMap[resourcev3.EndpointType]
	for name, edsVer := range edsVersions {
		edsVersions[name] = translator.BindEndpointVersion(edsVer, cdsVersions[name])
	}
	return snap
}

func drainDeltaResponses(ch chan cachev3.DeltaResponse) []cachev3.DeltaResponse {
	var out []cachev3.DeltaResponse
	for {
		select {
		case resp := <-ch:
			out = append(out, resp)
		default:
			return out
		}
	}
}

func TestOrderedDeltaCacheDefersUpdatedEDSUntilCDSSent(t *testing.T) {
	cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
	node := "default/gw"
	ch := make(chan cachev3.DeltaResponse, 16)

	v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example"})
	if err := cache.SetSnapshot(context.Background(), node, v1); err != nil {
		t.Fatal(err)
	}

	cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
	cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
	cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()

	edsReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a"}}
	edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, nil, false)
	cancelEDS, err := cache.CreateDeltaWatch(edsReq, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	initResps := drainDeltaResponses(ch)
	if len(initResps) != 2 {
		t.Fatalf("got %d initial responses, want 2 (CDS+EDS)", len(initResps))
	}
	cdsSub.SetReturnedResources(initResps[0].GetNextVersionMap())
	edsSub.SetReturnedResources(initResps[1].GetNextVersionMap())

	// Re-open both ACKed watches cleanly with non-empty nonces.
	cdsAckReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType, ResponseNonce: "n-cds-1"}
	cancelCDS, err = cache.CreateDeltaWatch(cdsAckReq, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()
	edsAckReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "n-eds-1"}
	cancelEDS, err = cache.CreateDeltaWatch(edsAckReq, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	// v2 adds cluster-b: sends CDS immediately and consumes the CDS watch, while EDS remains open on cluster-a.
	v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a1.example", "cluster-b": "b1.example"})
	if err := cache.SetSnapshot(context.Background(), node, v2); err != nil {
		t.Fatal(err)
	}
	v2Resps := drainDeltaResponses(ch)
	if len(v2Resps) != 1 || v2Resps[0].GetDeltaRequest().GetTypeUrl() != resourcev3.ClusterType {
		t.Fatalf("v2 responses = %v, want single CDS response", v2Resps)
	}
	v2CDSReturned := v2Resps[0].GetNextVersionMap()

	// v3 updates cluster-a TLS before Envoy has ACKed v2 CDS or subscribed to cluster-b EDS.
	v3 := buildBoundClusterSnapshot(t, "v3", map[string]string{"cluster-a": "a2.example", "cluster-b": "b1.example"})
	if err := cache.SetSnapshot(context.Background(), node, v3); err != nil {
		t.Fatal(err)
	}
	if premature := drainDeltaResponses(ch); len(premature) != 0 {
		t.Fatalf("rebound EDS sent ahead of CDS: got %d response(s)", len(premature))
	}

	// Envoy subscribes to cluster-b EDS to finish warming cluster-b from v2 CDS before ACKing CDS.
	// Cluster-b must receive its assignment, while cluster-a remains deferred and SystemVersionInfo stays empty.
	cancelEDS()
	edsSub.UpdateResourceSubscriptions([]string{"cluster-b"}, nil)
	edsWarmReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-b"}, ResponseNonce: "n-eds-1"}
	cancelEDS, err = cache.CreateDeltaWatch(edsWarmReq, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	warmResps := drainDeltaResponses(ch)
	if len(warmResps) != 1 {
		t.Fatalf("warming responses = %d, want 1", len(warmResps))
	}
	warmProto, err := warmResps[0].GetDeltaDiscoveryResponse()
	if err != nil {
		t.Fatal(err)
	}
	if len(warmProto.Resources) != 1 || warmProto.Resources[0].Name != "cluster-b" {
		t.Fatalf("warming EDS sent %v, want only cluster-b", warmProto.Resources)
	}
	if warmResps[0].GetResponseVersion() != "" {
		t.Fatalf("partial/deferred EDS carried SystemVersionInfo=%q, want empty", warmResps[0].GetResponseVersion())
	}
	edsSub.SetReturnedResources(warmResps[0].GetNextVersionMap())

	// Envoy ACKs warming EDS first, then ACKs v2 CDS.
	edsAck2Req := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "n-eds-2"}
	cancelEDS, err = cache.CreateDeltaWatch(edsAck2Req, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()
	if premature := drainDeltaResponses(ch); len(premature) != 0 {
		t.Fatalf("cluster-a EDS sent after EDS ACK before CDS update: %d", len(premature))
	}

	cdsSub.SetReturnedResources(v2CDSReturned)
	cdsAck2Req := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType, ResponseNonce: "n-cds-2"}
	cancelCDS, err = cache.CreateDeltaWatch(cdsAck2Req, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()

	ordered := drainDeltaResponses(ch)
	if len(ordered) != 2 {
		t.Fatalf("ordered CDS->EDS responses = %d, want 2", len(ordered))
	}
	if ordered[0].GetDeltaRequest().GetTypeUrl() != resourcev3.ClusterType {
		t.Fatalf("first response type = %s, want ClusterType", ordered[0].GetDeltaRequest().GetTypeUrl())
	}
	if ordered[1].GetDeltaRequest().GetTypeUrl() != resourcev3.EndpointType {
		t.Fatalf("second response type = %s, want EndpointType", ordered[1].GetDeltaRequest().GetTypeUrl())
	}
	edsProto, err := ordered[1].GetDeltaDiscoveryResponse()
	if err != nil {
		t.Fatal(err)
	}
	if len(edsProto.Resources) != 1 || edsProto.Resources[0].Name != "cluster-a" {
		t.Fatalf("unblocked EDS resources = %v, want cluster-a", edsProto.Resources)
	}
	if ordered[1].GetResponseVersion() != "v3" {
		t.Fatalf("unblocked EDS SystemVersionInfo = %q, want v3", ordered[1].GetResponseVersion())
	}
}

func TestOrderedDeltaCacheUnblocksPriorCDSClusterWarmingWhenSameClusterChangesAgain(t *testing.T) {
	cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
	node := "default/gw"
	ch := make(chan cachev3.DeltaResponse, 16)

	v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example"})
	if err := cache.SetSnapshot(context.Background(), node, v1); err != nil {
		t.Fatal(err)
	}
	cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
	cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
	cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()
	cdsResps := drainDeltaResponses(ch)
	cdsSub.SetReturnedResources(cdsResps[0].GetNextVersionMap())

	// v1 converges on CDS only? Or wildcard/initial cluster-a in both CDS and EDS:
	edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, nil, false)
	cancelEDS, err := cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a"},
	}, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()
	edsV1 := drainDeltaResponses(ch)
	if len(edsV1) != 1 {
		t.Fatalf("got %d v1 EDS responses, want 1", len(edsV1))
	}
	edsSub.SetReturnedResources(edsV1[0].GetNextVersionMap())
	cancelEDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.EndpointType, ResponseNonce: "eds-a1",
	}, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	cancelCDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType, ResponseNonce: "cds-1",
	}, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()

	// v2 sends CDS for cluster-b (sni b1.example) and consumes the CDS watch.
	v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a1.example", "cluster-b": "b1.example"})
	if err := cache.SetSnapshot(context.Background(), node, v2); err != nil {
		t.Fatal(err)
	}
	v2CDS := drainDeltaResponses(ch)
	if len(v2CDS) != 1 {
		t.Fatalf("got %d v2 responses, want 1", len(v2CDS))
	}

	// Before Envoy requests cluster-b EDS, v3 mutates cluster-b (sni b2.example).
	v3 := buildBoundClusterSnapshot(t, "v3", map[string]string{"cluster-a": "a1.example", "cluster-b": "b2.example"})
	if err := cache.SetSnapshot(context.Background(), node, v3); err != nil {
		t.Fatal(err)
	}

	// Envoy asks EDS for cluster-b (extending its cluster-a subscription) so b1.example can warm and ACK v2 CDS.
	cancelEDS()
	edsSub.UpdateResourceSubscriptions([]string{"cluster-b"}, nil)
	cancelEDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-b"}, ResponseNonce: "eds-a1",
	}, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	warmResps := drainDeltaResponses(ch)
	if len(warmResps) != 1 {
		t.Fatalf("warming response count = %d, want 1", len(warmResps))
	}
	if warmResps[0].GetResponseVersion() != "" {
		t.Fatalf("warming response SystemVersionInfo = %q, want empty", warmResps[0].GetResponseVersion())
	}
	edsSub.SetReturnedResources(warmResps[0].GetNextVersionMap())
	cancelEDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.EndpointType, ResponseNonce: "eds-b1",
	}, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()

	// Envoy finishes warming b1 and ACKs v2 CDS -> receives b2 CDS then b2 EDS at v3.
	cdsSub.SetReturnedResources(v2CDS[0].GetNextVersionMap())
	cancelCDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
		Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType, ResponseNonce: "cds-2",
	}, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()

	ordered := drainDeltaResponses(ch)
	if len(ordered) != 2 {
		t.Fatalf("got %d responses after CDS ACK, want 2", len(ordered))
	}
	if ordered[0].GetDeltaRequest().GetTypeUrl() != resourcev3.ClusterType || ordered[1].GetDeltaRequest().GetTypeUrl() != resourcev3.EndpointType {
		t.Fatalf("wrong order: %s then %s", ordered[0].GetDeltaRequest().GetTypeUrl(), ordered[1].GetDeltaRequest().GetTypeUrl())
	}
	if ordered[1].GetResponseVersion() != "v3" {
		t.Fatalf("final EDS SystemVersionInfo = %q, want v3", ordered[1].GetResponseVersion())
	}
}

func TestOrderedDeltaCacheDefersEDSBeforeCDSOnReconnect(t *testing.T) {
	cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
	node := "default/gw"
	ch := make(chan cachev3.DeltaResponse, 8)

	v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example"})
	v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a2.example"})
	if err := cache.SetSnapshot(context.Background(), node, v2); err != nil {
		t.Fatal(err)
	}

	// Reconnecting client subscribes EDS first holding v1 versions.
	edsInitial := map[string]string{"cluster-a": v1.GetVersionMap(resourcev3.EndpointType)["cluster-a"]}
	edsReq := &discoveryv3.DeltaDiscoveryRequest{
		Node:                    &corev3.Node{Cluster: node},
		TypeUrl:                 resourcev3.EndpointType,
		ResourceNamesSubscribe:  []string{"cluster-a"},
		InitialResourceVersions: edsInitial,
	}
	edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, edsInitial, false)
	cancelEDS, err := cache.CreateDeltaWatch(edsReq, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()
	if early := drainDeltaResponses(ch); len(early) != 0 {
		t.Fatalf("EDS sent before CDS on reconnect: %d response(s)", len(early))
	}

	cdsInitial := map[string]string{"cluster-a": v1.GetVersionMap(resourcev3.ClusterType)["cluster-a"]}
	cdsReq := &discoveryv3.DeltaDiscoveryRequest{
		Node:                    &corev3.Node{Cluster: node},
		TypeUrl:                 resourcev3.ClusterType,
		InitialResourceVersions: cdsInitial,
	}
	cdsSub := streamv3.NewDeltaSubscription(nil, nil, cdsInitial, true)
	cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()

	ordered := drainDeltaResponses(ch)
	if len(ordered) != 2 {
		t.Fatalf("got %d responses after CDS arrived, want 2", len(ordered))
	}
	if ordered[0].GetDeltaRequest().GetTypeUrl() != resourcev3.ClusterType || ordered[1].GetDeltaRequest().GetTypeUrl() != resourcev3.EndpointType {
		t.Fatalf("wrong reconnect order: %s then %s", ordered[0].GetDeltaRequest().GetTypeUrl(), ordered[1].GetDeltaRequest().GetTypeUrl())
	}
	if ordered[1].GetResponseVersion() != "v2" {
		t.Fatalf("reconnect EDS SystemVersionInfo = %q, want v2", ordered[1].GetResponseVersion())
	}
}
