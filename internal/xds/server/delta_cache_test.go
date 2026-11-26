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
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
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

func TestOrderedDeltaCacheServesProvisionalEDSBeforeCDSOnReconnect(t *testing.T) {
	v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example"})
	v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a2.example"})

	for _, tc := range []struct {
		name               string
		cdsInitialVersion  string
		expectCDSResources int
	}{
		{name: "stale_cds_on_reconnect", cdsInitialVersion: v1.GetVersionMap(resourcev3.ClusterType)["cluster-a"], expectCDSResources: 1},
		{name: "current_cds_paused_on_reconnect", cdsInitialVersion: v2.GetVersionMap(resourcev3.ClusterType)["cluster-a"], expectCDSResources: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
			node := "default/gw"
			ch := make(chan cachev3.DeltaResponse, 8)
			if err := cache.SetSnapshot(context.Background(), node, v2); err != nil {
				t.Fatal(err)
			}

			// Reconnecting client subscribes EDS first holding v1 endpoints while CDS is paused.
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

			early := drainDeltaResponses(ch)
			if len(early) != 1 {
				t.Fatalf("got %d early EDS responses, want 1 provisional response", len(early))
			}
			if early[0].GetResponseVersion() != "" {
				t.Fatalf("provisional EDS SystemVersionInfo = %q, want empty", early[0].GetResponseVersion())
			}
			earlyProto, err := early[0].GetDeltaDiscoveryResponse()
			if err != nil {
				t.Fatal(err)
			}
			provVer := earlyProto.Resources[0].Version
			targetVer := v2.GetVersionMap(resourcev3.EndpointType)["cluster-a"]
			if provVer == edsInitial["cluster-a"] || provVer == targetVer {
				t.Fatalf("provisional EDS version %q collided with old %q or target %q", provVer, edsInitial["cluster-a"], targetVer)
			}

			// Client ACKs provisional EDS; cache must hold steady without resending until CDS establishes state.
			edsSub.SetReturnedResources(early[0].GetNextVersionMap())
			cancelEDS, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
				Node:          &corev3.Node{Cluster: node},
				TypeUrl:       resourcev3.EndpointType,
				ResponseNonce: "eds-prov",
			}, &edsSub, ch)
			if err != nil {
				t.Fatal(err)
			}
			defer cancelEDS()
			if dup := drainDeltaResponses(ch); len(dup) != 0 {
				t.Fatalf("provisional EDS re-sent after ACK: %d response(s)", len(dup))
			}

			// Envoy unpauses CDS -> final CDS-bound EDS version ships right after CDS.
			cdsInitial := map[string]string{"cluster-a": tc.cdsInitialVersion}
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
			cdsProto, err := ordered[0].GetDeltaDiscoveryResponse()
			if err != nil {
				t.Fatal(err)
			}
			if len(cdsProto.Resources) != tc.expectCDSResources {
				t.Fatalf("CDS resources count = %d, want %d", len(cdsProto.Resources), tc.expectCDSResources)
			}
			edsProto, err := ordered[1].GetDeltaDiscoveryResponse()
			if err != nil {
				t.Fatal(err)
			}
			if len(edsProto.Resources) != 1 || edsProto.Resources[0].Version != targetVer {
				t.Fatalf("final reconnect EDS = %v, want target version %q", edsProto.Resources, targetVer)
			}
			if ordered[1].GetResponseVersion() != "v2" {
				t.Fatalf("reconnect EDS SystemVersionInfo = %q, want v2", ordered[1].GetResponseVersion())
			}
		})
	}

	t.Run("omitted_initial_version_and_repeated_reconnect_issue_fresh_provisional_versions", func(t *testing.T) {
		cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
		node := "default/gw"
		if err := cache.SetSnapshot(context.Background(), node, v2); err != nil {
			t.Fatal(err)
		}
		targetVer := v2.GetVersionMap(resourcev3.EndpointType)["cluster-a"]

		// Stream 1 reconnects omitting initial version (awaiting first assignment) while CDS is paused.
		ch1 := make(chan cachev3.DeltaResponse, 8)
		edsSub1 := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, nil, false)
		cancel1, err := cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
			Node:                   &corev3.Node{Cluster: node},
			TypeUrl:                resourcev3.EndpointType,
			ResourceNamesSubscribe: []string{"cluster-a"},
		}, &edsSub1, ch1)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel1()

		early1 := drainDeltaResponses(ch1)
		if len(early1) != 1 || early1[0].GetResponseVersion() != "" {
			t.Fatalf("stream 1 initial EDS = %v, want single provisional response", early1)
		}
		proto1, err := early1[0].GetDeltaDiscoveryResponse()
		if err != nil {
			t.Fatal(err)
		}
		prov1 := proto1.Resources[0].Version
		if prov1 == targetVer {
			t.Fatalf("stream 1 leaked final targetVer %q before CDS arrived", targetVer)
		}

		// Stream 2 reconnects holding prov1 from stream 1 while CDS is still paused.
		ch2 := make(chan cachev3.DeltaResponse, 8)
		edsInitial2 := map[string]string{"cluster-a": prov1}
		edsSub2 := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, edsInitial2, false)
		cancel2, err := cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
			Node:                    &corev3.Node{Cluster: node},
			TypeUrl:                 resourcev3.EndpointType,
			ResourceNamesSubscribe:  []string{"cluster-a"},
			InitialResourceVersions: edsInitial2,
		}, &edsSub2, ch2)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel2()

		early2 := drainDeltaResponses(ch2)
		if len(early2) != 1 || early2[0].GetResponseVersion() != "" {
			t.Fatalf("stream 2 initial EDS = %v, want fresh provisional response", early2)
		}
		proto2, err := early2[0].GetDeltaDiscoveryResponse()
		if err != nil {
			t.Fatal(err)
		}
		prov2 := proto2.Resources[0].Version
		if prov2 == prov1 || prov2 == targetVer {
			t.Fatalf("stream 2 provisional version %q collided with prov1=%q or target=%q", prov2, prov1, targetVer)
		}

		// Same-stream ACK suppresses resends until CDS arrives, then targetVer ships.
		edsSub2.SetReturnedResources(early2[0].GetNextVersionMap())
		cancel2, err = cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
			Node:          &corev3.Node{Cluster: node},
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "eds-prov-2",
		}, &edsSub2, ch2)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel2()
		if dup := drainDeltaResponses(ch2); len(dup) != 0 {
			t.Fatalf("stream 2 re-sent prov2 after ACK: %d response(s)", len(dup))
		}

		cdsInitial := map[string]string{"cluster-a": v2.GetVersionMap(resourcev3.ClusterType)["cluster-a"]}
		cdsSub := streamv3.NewDeltaSubscription(nil, nil, cdsInitial, true)
		cancelCDS, err := cache.CreateDeltaWatch(&discoveryv3.DeltaDiscoveryRequest{
			Node:                    &corev3.Node{Cluster: node},
			TypeUrl:                 resourcev3.ClusterType,
			InitialResourceVersions: cdsInitial,
		}, &cdsSub, ch2)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()

		ordered := drainDeltaResponses(ch2)
		if len(ordered) != 2 || ordered[1].GetResponseVersion() != "v2" {
			t.Fatalf("final ordered reconnect responses = %v, want CDS then v2 EDS", ordered)
		}
		finalEDS, err := ordered[1].GetDeltaDiscoveryResponse()
		if err != nil {
			t.Fatal(err)
		}
		if len(finalEDS.Resources) != 1 || finalEDS.Resources[0].Version != targetVer {
			t.Fatalf("final EDS resources = %v, want %q", finalEDS.Resources, targetVer)
		}
	})
}

func TestOrderedDeltaCacheReplaysUnprovenEndpointsWhenRejectedBatchCorrected(t *testing.T) {
	publish := func(t *testing.T, cache *orderedDeltaCache, tracker *AckTracker, node, ver string, snap *cachev3.Snapshot) {
		t.Helper()
		fps := make(map[string]string, 2)
		expRes := make(map[string]map[string]string, 2)
		for _, typeURL := range []string{resourcev3.ClusterType, resourcev3.EndpointType} {
			vm := snap.GetVersionMap(typeURL)
			fp, err := fingerprintVersionMap(vm)
			if err != nil {
				t.Fatal(err)
			}
			fps[typeURL] = fp
			expRes[typeURL] = vm
		}
		tracker.ExpectSnapshotResources(node, ver, fps, snapshotRequiredTypes(snap), expRes)
		if err := cache.SetSnapshot(context.Background(), node, snap); err != nil {
			t.Fatal(err)
		}
	}

	deliver := func(t *testing.T, cache *orderedDeltaCache, tracker *AckTracker, streamID int64, req *discoveryv3.DeltaDiscoveryRequest, resp cachev3.DeltaResponse, nonce string) *discoveryv3.DeltaDiscoveryResponse {
		t.Helper()
		proto, err := resp.GetDeltaDiscoveryResponse()
		if err != nil {
			t.Fatal(err)
		}
		proto.Nonce = nonce
		fp, hasFP := cache.ConsumeResponseFingerprint(proto)
		cache.OnResponse(streamID, req, proto)
		tracker.OnResponseWithFingerprint(streamID, req, proto, fp, hasFP)
		return proto
	}

	t.Run("correcting_sibling_replays_unchanged_unproven_assignment", func(t *testing.T) {
		cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
		tracker := NewAckTracker()
		node := "default/gw"
		streamID := int64(11)
		ch := make(chan cachev3.DeltaResponse, 16)

		v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example", "cluster-b": "b1.example"})
		publish(t, cache, tracker, node, "v1", v1)

		cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
		cache.BindRequestStream(cdsReq, streamID)
		tracker.OnRequest(streamID, cdsReq)
		cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
		cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()
		cdsResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, cdsReq, cdsResp, "c1")
		cdsSub.SetReturnedResources(cdsResp.GetNextVersionMap())
		cdsAck := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c1"}
		cache.BindRequestStream(cdsAck, streamID)
		cache.OnRequest(streamID, cdsAck)
		tracker.OnRequest(streamID, cdsAck)
		cancelCDS, err = cache.CreateDeltaWatch(cdsAck, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()

		// EDS sends both cluster-a and cluster-b together.
		edsReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a", "cluster-b"}}
		cache.BindRequestStream(edsReq, streamID)
		tracker.OnRequest(streamID, edsReq)
		edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a", "cluster-b"}, nil, nil, false)
		cancelEDS, err := cache.CreateDeltaWatch(edsReq, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		edsResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, edsReq, edsResp, "e1")
		edsSub.SetReturnedResources(edsResp.GetNextVersionMap())

		// Envoy NACKs the batch. Cache must suppress automatic retries of unchanged v1.
		edsNack := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "e1",
			ErrorDetail:   &statuspb.Status{Message: "rejected eds batch"},
		}
		cache.BindRequestStream(edsNack, streamID)
		cache.OnRequest(streamID, edsNack)
		tracker.OnRequest(streamID, edsNack)
		cancelEDS, err = cache.CreateDeltaWatch(edsNack, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if retries := drainDeltaResponses(ch); len(retries) != 0 {
			t.Fatalf("unchanged rejected EDS batch auto-retried %d time(s)", len(retries))
		}
		if tracker.IsACKed(node, "v1") {
			t.Fatal("NACKed v1 converged")
		}

		// v2 corrects cluster-b while cluster-a keeps identical version EA1.
		v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a1.example", "cluster-b": "b2.example"})
		publish(t, cache, tracker, node, "v2", v2)

		// SetSnapshot emits CDS update first and corrected+replayed EDS right behind it.
		resps := drainDeltaResponses(ch)
		if len(resps) != 2 || resps[0].GetDeltaRequest().GetTypeUrl() != resourcev3.ClusterType || resps[1].GetDeltaRequest().GetTypeUrl() != resourcev3.EndpointType {
			t.Fatalf("expected CDS then EDS replay+fix responses, got %v", resps)
		}
		deliver(t, cache, tracker, streamID, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, resps[0], "c2")
		cdsSub.SetReturnedResources(resps[0].GetNextVersionMap())
		cdsAck2 := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2"}
		cache.BindRequestStream(cdsAck2, streamID)
		cache.OnRequest(streamID, cdsAck2)
		tracker.OnRequest(streamID, cdsAck2)
		cancelCDS, err = cache.CreateDeltaWatch(cdsAck2, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()

		// Corrected EDS must include BOTH cluster-b@EB2 and replayed unproven cluster-a@EA1.
		edsProto2 := deliver(t, cache, tracker, streamID, edsNack, resps[1], "e2")
		if len(edsProto2.Resources) != 2 {
			t.Fatalf("EDS resources = %v, want both cluster-a replay and cluster-b fix", edsProto2.Resources)
		}
		edsAck := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e2"}
		cache.BindRequestStream(edsAck, streamID)
		cache.OnRequest(streamID, edsAck)
		tracker.OnRequest(streamID, edsAck)
		if !tracker.IsACKed(node, "v2") {
			t.Fatalf("corrected batch ACK failed to converge: %s", tracker.ConvergenceDetails(node, "v2"))
		}
		if _, hasNACK := tracker.LastNACK(node); hasNACK {
			t.Fatal("resolved batch still reported LastNACK")
		}

		// After EB2 is ACKed, stale EB1 must be cleared: reverting cluster-b to b1.example
		// must still ship EA/EB1 (no rollback suppression), and a later NACK must not loop.
		edsSub.SetReturnedResources(resps[1].GetNextVersionMap())
		edsAckOpen := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e2"}
		cache.BindRequestStream(edsAckOpen, streamID)
		cancelEDS, err = cache.CreateDeltaWatch(edsAckOpen, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()

		publish(t, cache, tracker, node, "v3", v1)
		revertResps := drainDeltaResponses(ch)
		if len(revertResps) != 2 || revertResps[1].GetDeltaRequest().GetTypeUrl() != resourcev3.EndpointType {
			t.Fatalf("revert to v1 failed to deliver EDS (rollback suppressed?): %v", revertResps)
		}
		deliver(t, cache, tracker, streamID, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, revertResps[0], "c3")
		cdsSub.SetReturnedResources(revertResps[0].GetNextVersionMap())
		cdsAck3 := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c3"}
		cache.BindRequestStream(cdsAck3, streamID)
		cache.OnRequest(streamID, cdsAck3)
		tracker.OnRequest(streamID, cdsAck3)

		deliver(t, cache, tracker, streamID, edsAckOpen, revertResps[1], "e3")
		edsSub.SetReturnedResources(revertResps[1].GetNextVersionMap())
		edsNack3 := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "e3",
			ErrorDetail:   &statuspb.Status{Message: "unrelated revert nack"},
		}
		cache.BindRequestStream(edsNack3, streamID)
		cache.OnRequest(streamID, edsNack3)
		tracker.OnRequest(streamID, edsNack3)
		cancelEDS, err = cache.CreateDeltaWatch(edsNack3, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if retries := drainDeltaResponses(ch); len(retries) != 0 {
			t.Fatalf("stale rejected entry triggered retry loop after NACK: %d response(s)", len(retries))
		}
	})

	t.Run("removing_rejected_sibling_replays_unchanged_unproven_assignment_without_loop", func(t *testing.T) {
		cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
		tracker := NewAckTracker()
		node := "default/gw"
		streamID := int64(12)
		ch := make(chan cachev3.DeltaResponse, 16)

		v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example", "cluster-b": "b1.example"})
		publish(t, cache, tracker, node, "v1", v1)

		cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
		cache.BindRequestStream(cdsReq, streamID)
		tracker.OnRequest(streamID, cdsReq)
		cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
		cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()
		cdsResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, cdsReq, cdsResp, "c1")
		cdsSub.SetReturnedResources(cdsResp.GetNextVersionMap())
		cdsAck := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c1"}
		cache.BindRequestStream(cdsAck, streamID)
		cache.OnRequest(streamID, cdsAck)
		tracker.OnRequest(streamID, cdsAck)
		cancelCDS, err = cache.CreateDeltaWatch(cdsAck, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()

		edsReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a", "cluster-b"}}
		cache.BindRequestStream(edsReq, streamID)
		tracker.OnRequest(streamID, edsReq)
		edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a", "cluster-b"}, nil, nil, false)
		cancelEDS, err := cache.CreateDeltaWatch(edsReq, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		edsResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, edsReq, edsResp, "e1")
		edsSub.SetReturnedResources(edsResp.GetNextVersionMap())

		edsNack := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "e1",
			ErrorDetail:   &statuspb.Status{Message: "rejected batch"},
		}
		cache.BindRequestStream(edsNack, streamID)
		cache.OnRequest(streamID, edsNack)
		tracker.OnRequest(streamID, edsNack)
		cancelEDS, err = cache.CreateDeltaWatch(edsNack, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if retries := drainDeltaResponses(ch); len(retries) != 0 {
			t.Fatalf("unexpected retry on unchanged NACKed batch: %v", retries)
		}

		// v2 removes cluster-b while keeping cluster-a at EA1.
		v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a1.example"})
		publish(t, cache, tracker, node, "v2", v2)

		var cdsMsg, edsMsg cachev3.DeltaResponse
		for _, r := range drainDeltaResponses(ch) {
			switch r.GetDeltaRequest().GetTypeUrl() {
			case resourcev3.ClusterType:
				cdsMsg = r
			case resourcev3.EndpointType:
				edsMsg = r
			}
		}
		if cdsMsg == nil || edsMsg == nil {
			t.Fatalf("expected CDS removal and EDS replay+removal, got cds=%v eds=%v", cdsMsg, edsMsg)
		}
		deliver(t, cache, tracker, streamID, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, cdsMsg, "c2")
		cdsAck2 := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2"}
		cache.BindRequestStream(cdsAck2, streamID)
		cache.OnRequest(streamID, cdsAck2)
		tracker.OnRequest(streamID, cdsAck2)

		edsProto2 := deliver(t, cache, tracker, streamID, edsNack, edsMsg, "e2")
		if len(edsProto2.Resources) != 1 || edsProto2.Resources[0].Name != "cluster-a" {
			t.Fatalf("expected cluster-a replay alongside cluster-b removal, got resources=%v", edsProto2.Resources)
		}
		edsSub.SetReturnedResources(edsMsg.GetNextVersionMap())

		// Re-NACKing e2 must not trigger an infinite retry loop once removed cluster-b was pruned.
		edsNack2 := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "e2",
			ErrorDetail:   &statuspb.Status{Message: "still failing a"},
		}
		cache.BindRequestStream(edsNack2, streamID)
		cache.OnRequest(streamID, edsNack2)
		tracker.OnRequest(streamID, edsNack2)
		cancelEDS, err = cache.CreateDeltaWatch(edsNack2, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if retries := drainDeltaResponses(ch); len(retries) != 0 {
			t.Fatalf("infinite retry loop after pruned rejection: %d response(s)", len(retries))
		}
	})

	t.Run("unsubscribing_single_rejected_resource_prunes_stale_rejection", func(t *testing.T) {
		cache := newOrderedDeltaCache(cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil), gatewayNodeHash{})
		tracker := NewAckTracker()
		node := "default/gw"
		streamID := int64(13)
		ch := make(chan cachev3.DeltaResponse, 16)

		v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example", "cluster-b": "b1.example"})
		publish(t, cache, tracker, node, "v1", v1)

		cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
		cache.BindRequestStream(cdsReq, streamID)
		tracker.OnRequest(streamID, cdsReq)
		cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
		cancelCDS, err := cache.CreateDeltaWatch(cdsReq, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()
		cdsResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, cdsReq, cdsResp, "c1")
		cdsSub.SetReturnedResources(cdsResp.GetNextVersionMap())
		cdsAck := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c1"}
		cache.BindRequestStream(cdsAck, streamID)
		cache.OnRequest(streamID, cdsAck)
		tracker.OnRequest(streamID, cdsAck)
		cancelCDS, err = cache.CreateDeltaWatch(cdsAck, &cdsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelCDS()

		// Cluster-a converges first; cluster-b is subscribed separately and NACKed.
		edsAReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a"}}
		cache.BindRequestStream(edsAReq, streamID)
		tracker.OnRequest(streamID, edsAReq)
		edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, nil, false)
		cancelEDS, err := cache.CreateDeltaWatch(edsAReq, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		edsAResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, edsAReq, edsAResp, "ea1")
		edsSub.SetReturnedResources(edsAResp.GetNextVersionMap())
		ackA := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "ea1"}
		cache.BindRequestStream(ackA, streamID)
		cache.OnRequest(streamID, ackA)
		tracker.OnRequest(streamID, ackA)

		cancelEDS()
		edsSub.UpdateResourceSubscriptions([]string{"cluster-b"}, nil)
		edsBReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-b"}, ResponseNonce: "ea1"}
		cache.BindRequestStream(edsBReq, streamID)
		tracker.OnRequest(streamID, edsBReq)
		cancelEDS, err = cache.CreateDeltaWatch(edsBReq, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		edsBResp := drainDeltaResponses(ch)[0]
		deliver(t, cache, tracker, streamID, edsBReq, edsBResp, "eb1")
		edsSub.SetReturnedResources(edsBResp.GetNextVersionMap())

		nackB := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl: resourcev3.EndpointType, ResponseNonce: "eb1",
			ErrorDetail: &statuspb.Status{Message: "bad b"},
		}
		cache.BindRequestStream(nackB, streamID)
		cache.OnRequest(streamID, nackB)
		tracker.OnRequest(streamID, nackB)

		// Envoy unsubscribes cluster-b before any response (filtered/removed both empty),
		// which must prune cluster-b from rejectedEndpoints.
		edsSub.UpdateResourceSubscriptions(nil, []string{"cluster-b"})
		unsubB := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl: resourcev3.EndpointType, ResourceNamesUnsubscribe: []string{"cluster-b"}, ResponseNonce: "eb1",
		}
		cache.BindRequestStream(unsubB, streamID)
		cache.OnRequest(streamID, unsubB)
		tracker.OnRequest(streamID, unsubB)
		cancelEDS, err = cache.CreateDeltaWatch(unsubB, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if empty := drainDeltaResponses(ch); len(empty) != 0 {
			t.Fatalf("expected no response on unsubscribe of healthy cluster-a, got %v", empty)
		}

		// Later update & NACK of cluster-a must NOT retry endlessly from unpruned cluster-b.
		v2 := buildBoundClusterSnapshot(t, "v2", map[string]string{"cluster-a": "a2.example"})
		publish(t, cache, tracker, node, "v2", v2)
		edsSub.UpdateResourceSubscriptions(nil, nil)
		var v2EDS cachev3.DeltaResponse
		for _, r := range drainDeltaResponses(ch) {
			if r.GetDeltaRequest().GetTypeUrl() == resourcev3.EndpointType {
				v2EDS = r
			}
		}
		if v2EDS == nil {
			t.Fatal("expected cluster-a@EA2 EDS response on v2")
		}
		deliver(t, cache, tracker, streamID, unsubB, v2EDS, "ea2")
		edsSub.SetReturnedResources(v2EDS.GetNextVersionMap())
		nackA2 := &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl: resourcev3.EndpointType, ResponseNonce: "ea2",
			ErrorDetail: &statuspb.Status{Message: "bad a2"},
		}
		cache.BindRequestStream(nackA2, streamID)
		cache.OnRequest(streamID, nackA2)
		tracker.OnRequest(streamID, nackA2)
		cancelEDS, err = cache.CreateDeltaWatch(nackA2, &edsSub, ch)
		if err != nil {
			t.Fatal(err)
		}
		defer cancelEDS()
		if retries := drainDeltaResponses(ch); len(retries) != 0 {
			t.Fatalf("stale unsubscribed cluster-b rejection triggered retry loop: %d response(s)", len(retries))
		}
	})
}
