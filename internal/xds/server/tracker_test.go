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
	"fmt"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

func TestAckTrackerRequiresEveryExpectedType(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{
		resourcev3.ListenerType: "listener",
		resourcev3.RouteType:    "route",
	}, nil)

	listenerRequest := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnRequest(7, listenerRequest)
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResourceNamesSubscribe: []string{"route-a"}})
	tracker.OnResponse(7, listenerRequest, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})
	if tracker.IsACKed(node, version) {
		t.Fatal("snapshot converged before subscribed RouteConfiguration ACK")
	}

	routeRequest := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.RouteType}
	tracker.OnResponse(7, routeRequest, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, SystemVersionInfo: version, Nonce: "2"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "2"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("snapshot did not converge after every expected ACK")
	}
}

func TestAckTrackerIgnoresUnsubscribedTypes(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{
		resourcev3.ListenerType: "listener",
		resourcev3.RouteType:    "route",
		resourcev3.SecretType:   "secret",
	}, nil)

	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	tracker.OnResponse(7,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})

	if !tracker.IsACKed(node, version) {
		t.Fatal("unsubscribed RouteConfiguration/Secret types blocked convergence")
	}
}

func TestAckTrackerAcceptsReconnectInitialResourceVersions(t *testing.T) {
	resourceVersions := map[string]string{"listener-a": "resource-hash-a"}
	fingerprint, err := fingerprintVersionMap(resourceVersions)
	if err != nil {
		t.Fatal(err)
	}

	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: fingerprint}, nil)
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: node},
		TypeUrl: resourcev3.ClusterType,
	})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                 resourcev3.ListenerType,
		InitialResourceVersions: resourceVersions,
	})
	if !tracker.IsACKed(node, version) {
		t.Fatalf("matching reconnect versions did not converge: %s", tracker.ConvergenceDetails(node, version))
	}

	mismatch := NewAckTracker()
	mismatch.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: fingerprint}, nil)
	mismatch.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{
		Node:                    &corev3.Node{Cluster: node},
		TypeUrl:                 resourcev3.ListenerType,
		InitialResourceVersions: map[string]string{"listener-a": "stale-hash"},
	})
	if mismatch.IsACKed(node, version) {
		t.Fatal("stale reconnect versions converged without a response ACK")
	}
}

func TestAckTrackerNewSubscriptionRequiresACK(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{
		resourcev3.ListenerType: "listener",
		resourcev3.RouteType:    "route",
	}, nil)

	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	tracker.OnResponse(7,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("snapshot did not converge while RouteConfiguration was unsubscribed")
	}

	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResourceNamesSubscribe: []string{"route-a"}})
	if tracker.IsACKed(node, version) {
		t.Fatal("new RouteConfiguration subscription did not require an ACK")
	}
	tracker.OnResponse(7,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, SystemVersionInfo: version, Nonce: "2"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "2"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("snapshot did not converge after the new subscription ACKed")
	}
}

func TestAckTrackerStreamCloseDropsExpectationWithoutSubscriber(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{
		resourcev3.ListenerType: "listener",
		resourcev3.RouteType:    "route",
	}, nil)

	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	tracker.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.RouteType})
	tracker.OnResponse(7,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})
	if tracker.IsACKed(node, version) {
		t.Fatal("snapshot converged while a subscribed RouteConfiguration ACK was pending")
	}

	tracker.OnStreamClosed(8)
	if !tracker.IsACKed(node, version) {
		t.Fatal("closed stream's RouteConfiguration subscription still blocked convergence")
	}
}

func TestAckTrackerStreamCloseKeepsExpectationWithRemainingSubscriber(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.RouteType: "route"}, nil)

	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.RouteType})
	tracker.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.RouteType})
	tracker.OnStreamClosed(7)
	if tracker.IsACKed(node, version) {
		t.Fatal("closing one of two RouteConfiguration subscribers dropped the ACK expectation")
	}

	tracker.OnResponse(8,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "1"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("snapshot did not converge after the remaining subscriber ACKed")
	}
}

func TestAckTrackerRequiresLiveStreamForNonEmptySnapshot(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, nil)
	if tracker.IsACKed(node, version) {
		t.Fatal("snapshot converged without a live xDS stream")
	}
	if details := tracker.ConvergenceDetails(node, version); details != "no live xDS stream" {
		t.Fatalf("convergence details = %q, want no live xDS stream", details)
	}

	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnResponse(7, request, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1",
	})
	if details := tracker.ConvergenceDetails(node, version); details != "want v1, 1 live stream(s), missing Listener(no ACK)" {
		t.Fatalf("convergence details = %q, want missing Listener without an ACK", details)
	}
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("live stream ACK did not converge")
	}
	if details := tracker.ConvergenceDetails(node, version); details != "" {
		t.Fatalf("converged snapshot details = %q, want empty", details)
	}
	tracker.OnStreamClosed(7)
	if tracker.IsACKed(node, version) {
		t.Fatal("snapshot stayed converged after the last xDS stream closed")
	}
}

func TestAckTrackerForgetPreservesLiveStreamIdentity(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnRequest(7, request)
	tracker.ExpectSnapshot(node, "v1", map[string]string{resourcev3.ListenerType: "listener-v1"}, nil)
	tracker.OnResponse(7, request, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl: resourcev3.ListenerType, SystemVersionInfo: "v1", Nonce: "nack",
	})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.ListenerType, ResponseNonce: "nack",
		ErrorDetail: &statuspb.Status{Message: "invalid listener"},
	})

	tracker.Forget(node)
	if _, ok := tracker.LastNACK(node); ok {
		t.Fatal("Forget retained a stale NACK")
	}

	tracker.ExpectSnapshot(node, "v2", map[string]string{resourcev3.ListenerType: "listener-v2"}, nil)
	tracker.OnResponse(7,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType},
		&discoveryv3.DeltaDiscoveryResponse{
			TypeUrl: resourcev3.ListenerType, SystemVersionInfo: "v2", Nonce: "ack",
		},
	)
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.ListenerType, ResponseNonce: "ack",
	})
	if !tracker.IsACKed(node, "v2") {
		t.Fatal("Forget dropped the live stream identity needed for node-less follow-up ACKs")
	}
}

func TestAckTrackerCorrelatesNodeLessFollowupResponsesToStream(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	streamID := int64(17)
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, nil)

	tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: node},
		TypeUrl: resourcev3.ListenerType,
	})
	tracker.OnResponse(streamID,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType},
		&discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.ListenerType,
			SystemVersionInfo: version,
			Nonce:             "node-less-response",
		},
	)
	tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:       resourcev3.ListenerType,
		ResponseNonce: "node-less-response",
	})

	if !tracker.IsACKed(node, version) {
		t.Fatal("node-less follow-up response was not correlated to the stream node")
	}
}

func TestAckTrackerRecordsNACKAndRecovers(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v2"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, nil)
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnResponse(8, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "3"})
	tracker.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl: resourcev3.ListenerType, ResponseNonce: "3",
		ErrorDetail: &statuspb.Status{Message: "invalid listener"},
	})
	if tracker.IsACKed(node, version) {
		t.Fatal("NACKed snapshot reported converged")
	}
	nack, ok := tracker.LastNACK(node)
	if !ok || nack.Version != version || nack.Detail != "invalid listener" {
		t.Fatalf("NACK = %#v, %v", nack, ok)
	}

	tracker.OnResponse(8, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "4"})
	tracker.OnRequest(8, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "4"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("ACK after NACK did not converge")
	}
	if _, ok := tracker.LastNACK(node); ok {
		t.Fatal("successful ACK did not clear matching NACK")
	}
}

func TestAckTrackerEmptySnapshotConverges(t *testing.T) {
	tracker := NewAckTracker()
	tracker.ExpectSnapshot("default/invalid", "empty-v1", nil, nil)
	if !tracker.IsACKed("default/invalid", "empty-v1") {
		t.Fatal("empty snapshot should converge immediately")
	}
}

func TestAckTrackerExpectsOnlyChangedDeltaTypes(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	tracker.ExpectSnapshot(node, "v1", map[string]string{
		resourcev3.ListenerType: "listener-a",
		resourcev3.EndpointType: "endpoint-a",
	}, nil)
	for streamID, typeURL := range []string{resourcev3.ListenerType, resourcev3.EndpointType} {
		nonce := typeURL + "-v1"
		request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: typeURL}
		tracker.OnResponse(int64(streamID), request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: typeURL, SystemVersionInfo: "v1", Nonce: nonce})
		tracker.OnRequest(int64(streamID), &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: nonce})
	}
	if !tracker.IsACKed(node, "v1") {
		t.Fatal("initial snapshot did not converge")
	}

	tracker.ExpectSnapshot(node, "v2", map[string]string{
		resourcev3.ListenerType: "listener-a",
		resourcev3.EndpointType: "endpoint-b",
	}, nil)
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.EndpointType}
	tracker.OnResponse(1, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v2", Nonce: "endpoint-v2"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "endpoint-v2"})
	if !tracker.IsACKed(node, "v2") {
		t.Fatal("unchanged Listener type incorrectly required a v2 ACK")
	}

	tracker.ExpectSnapshot(node, "v3", map[string]string{resourcev3.ListenerType: "listener-a"}, nil)
	if !tracker.IsACKed(node, "v3") {
		t.Fatal("resource type absent from the new snapshot blocked convergence")
	}
}

func TestAckTrackerCreditsLateEDSAckAcrossRouteOnlySnapshot(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"

	tracker.ExpectSnapshot(node, "v1", map[string]string{
		resourcev3.ClusterType:  "c1",
		resourcev3.EndpointType: "e1",
		resourcev3.RouteType:    "r1",
	}, nil)
	for _, tc := range []struct {
		typeURL string
		nonce   string
	}{
		{resourcev3.ClusterType, "c1-n"},
		{resourcev3.EndpointType, "e1-n"},
		{resourcev3.RouteType, "r1-n"},
	} {
		req := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: tc.typeURL}
		tracker.OnRequest(1, req)
		tracker.OnResponse(1, req, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: tc.typeURL, SystemVersionInfo: "v1", Nonce: tc.nonce})
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: tc.typeURL, ResponseNonce: tc.nonce})
	}
	if !tracker.IsACKed(node, "v1") {
		t.Fatal("v1 did not converge")
	}

	// v2 updates Cluster and Endpoint. Server emits both CDS and EDS for v2.
	tracker.ExpectSnapshot(node, "v2", map[string]string{
		resourcev3.ClusterType:  "c2",
		resourcev3.EndpointType: "e2",
		resourcev3.RouteType:    "r1",
	}, nil)
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ClusterType, SystemVersionInfo: "v2", Nonce: "c2-n"})
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v2", Nonce: "e2-n"})

	// Envoy ACKs CDS(v2) first; route-only v3 becomes current before EDS(v2) ACK arrives.
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2-n"})
	tracker.ExpectSnapshot(node, "v3", map[string]string{
		resourcev3.ClusterType:  "c2",
		resourcev3.EndpointType: "e2",
		resourcev3.RouteType:    "r2",
	}, nil)
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, SystemVersionInfo: "v3", Nonce: "r2-n"})

	// Late EDS(v2) ACK arrives carrying v2's SystemVersionInfo, which still matches v3's Endpoint fingerprint.
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e2-n"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "r2-n"})
	if !tracker.IsACKed(node, "v3") {
		t.Fatalf("late EDS ACK across route-only snapshot failed to converge: %s", tracker.ConvergenceDetails(node, "v3"))
	}
}

func TestAckTrackerRejectsQueuedResponseFromDifferentFingerprintAfterSupersedingSnapshot(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"

	tracker.ExpectSnapshot(node, "v2", map[string]string{resourcev3.EndpointType: "e2"}, nil)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.EndpointType})

	// v3 supersedes Endpoint fingerprint before queued v2 response's OnResponse runs.
	tracker.ExpectSnapshot(node, "v3", map[string]string{resourcev3.EndpointType: "e3"}, nil)
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v2", Nonce: "queued-v2"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "queued-v2"})
	if tracker.IsACKed(node, "v3") {
		t.Fatal("stale v2 response converged newer Endpoint fingerprint v3")
	}

	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType},
		&discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v3", Nonce: "v3-n"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "v3-n"})
	if !tracker.IsACKed(node, "v3") {
		t.Fatalf("current v3 response did not converge: %s", tracker.ConvergenceDetails(node, "v3"))
	}
}

func TestAckTrackerPreservesPartialEDSNACKUntilResolvedOrRemoved(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"

	// v1 establishes cluster-a.
	tracker.ExpectSnapshotResources(node, "v1", map[string]string{
		resourcev3.ClusterType:  "c-v1",
		resourcev3.EndpointType: "e-v1",
	}, nil, map[string]map[string]string{
		resourcev3.ClusterType:  {"cluster-a": "CA1"},
		resourcev3.EndpointType: {"cluster-a": "EA1"},
	})
	for _, tc := range []struct {
		typeURL string
		name    string
		ver     string
		nonce   string
	}{
		{resourcev3.ClusterType, "cluster-a", "CA1", "c1"},
		{resourcev3.EndpointType, "cluster-a", "EA1", "e1"},
	} {
		req := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: tc.typeURL}
		tracker.OnRequest(1, req)
		tracker.OnResponse(1, req, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           tc.typeURL,
			SystemVersionInfo: "v1",
			Nonce:             tc.nonce,
			Resources:         []*discoveryv3.Resource{{Name: tc.name, Version: tc.ver}},
		})
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: tc.typeURL, ResponseNonce: tc.nonce})
	}
	if !tracker.IsACKed(node, "v1") {
		t.Fatal("v1 did not converge")
	}

	// v2 adds cluster-b and rebinds cluster-a.
	tracker.ExpectSnapshotResources(node, "v2", map[string]string{
		resourcev3.ClusterType:  "c-v2",
		resourcev3.EndpointType: "e-v2",
	}, nil, map[string]map[string]string{
		resourcev3.ClusterType:  {"cluster-a": "CA2", "cluster-b": "CB1"},
		resourcev3.EndpointType: {"cluster-a": "EA2", "cluster-b": "EB1"},
	})
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl:           resourcev3.ClusterType,
		SystemVersionInfo: "v2",
		Nonce:             "c2",
		Resources:         []*discoveryv3.Resource{{Name: "cluster-a", Version: "CA2"}, {Name: "cluster-b", Version: "CB1"}},
	})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2"})

	// Partial EDS response (empty SystemVersionInfo) sends cluster-b@EB1, which Envoy NACKs.
	tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType}, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl:           resourcev3.EndpointType,
		SystemVersionInfo: "",
		Nonce:             "e-partial-b",
		Resources:         []*discoveryv3.Resource{{Name: "cluster-b", Version: "EB1"}},
	}, "", true)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:       resourcev3.EndpointType,
		ResponseNonce: "e-partial-b",
		ErrorDetail:   &statuspb.Status{Message: "invalid cluster-b endpoints"},
	})

	// Later response for cluster-a arrives labeled with v2 SystemVersionInfo, and Envoy ACKs it.
	// Convergence must remain blocked while cluster-b@EB1 has not been delivered and ACKed.
	tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType}, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl:           resourcev3.EndpointType,
		SystemVersionInfo: "v2",
		Nonce:             "e-rebound-a",
		Resources:         []*discoveryv3.Resource{{Name: "cluster-a", Version: "EA2"}},
	}, "e-v2", true)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e-rebound-a"})
	if tracker.IsACKed(node, "v2") {
		t.Fatal("rejected partial EDS assignment was ignored after sibling resource ACK")
	}
	if nack, ok := tracker.LastNACK(node); !ok || nack.Detail != "invalid cluster-b endpoints" {
		t.Fatalf("LastNACK = %#v, %v, want preserved partial EDS rejection", nack, ok)
	}

	// Unrelated v3 keeps the same Endpoints and must preserve the active rejection.
	tracker.ExpectSnapshotResources(node, "v3", map[string]string{
		resourcev3.ClusterType:  "c-v2",
		resourcev3.EndpointType: "e-v2",
	}, nil, map[string]map[string]string{
		resourcev3.ClusterType:  {"cluster-a": "CA2", "cluster-b": "CB1"},
		resourcev3.EndpointType: {"cluster-a": "EA2", "cluster-b": "EB1"},
	})
	if tracker.IsACKed(node, "v3") {
		t.Fatal("unchanged snapshot superseded active partial EDS rejection")
	}

	// v4 updates cluster-b@EB2, delivers it, and Envoy ACKs -> now converged and NACK cleared.
	tracker.ExpectSnapshotResources(node, "v4", map[string]string{
		resourcev3.ClusterType:  "c-v2",
		resourcev3.EndpointType: "e-v4",
	}, nil, map[string]map[string]string{
		resourcev3.ClusterType:  {"cluster-a": "CA2", "cluster-b": "CB1"},
		resourcev3.EndpointType: {"cluster-a": "EA2", "cluster-b": "EB2"},
	})
	tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType}, &discoveryv3.DeltaDiscoveryResponse{
		TypeUrl:           resourcev3.EndpointType,
		SystemVersionInfo: "v4",
		Nonce:             "e-b-fixed",
		Resources:         []*discoveryv3.Resource{{Name: "cluster-b", Version: "EB2"}},
	}, "e-v4", true)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e-b-fixed"})
	if !tracker.IsACKed(node, "v4") {
		t.Fatalf("resolved partial EDS assignment did not converge: %s", tracker.ConvergenceDetails(node, "v4"))
	}
	if _, ok := tracker.LastNACK(node); ok {
		t.Fatal("resolved partial EDS rejection still reported by LastNACK")
	}
}

func TestAckTrackerConvergesWhenRejectedOrUnsubscribedResourceRemoved(t *testing.T) {
	t.Run("removing_rejected_resource_promotes_convergence", func(t *testing.T) {
		tracker := NewAckTracker()
		node := "default/gateway"
		tracker.ExpectSnapshotResources(node, "v1", map[string]string{
			resourcev3.ClusterType:  "c-v1",
			resourcev3.EndpointType: "e-v1",
		}, nil, map[string]map[string]string{
			resourcev3.ClusterType:  {"cluster-a": "CA1", "cluster-b": "CB1"},
			resourcev3.EndpointType: {"cluster-a": "EA1", "cluster-b": "EB1"},
		})
		for _, tc := range []struct {
			typeURL string
			nonce   string
			res     []*discoveryv3.Resource
		}{
			{resourcev3.ClusterType, "c1", []*discoveryv3.Resource{{Name: "cluster-a", Version: "CA1"}, {Name: "cluster-b", Version: "CB1"}}},
			{resourcev3.EndpointType, "e1", []*discoveryv3.Resource{{Name: "cluster-a", Version: "EA1"}}},
		} {
			req := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: tc.typeURL}
			tracker.OnRequest(1, req)
			tracker.OnResponseWithFingerprint(1, req, &discoveryv3.DeltaDiscoveryResponse{
				TypeUrl:           tc.typeURL,
				SystemVersionInfo: "",
				Nonce:             tc.nonce,
				Resources:         tc.res,
			}, "", true)
			tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: tc.typeURL, ResponseNonce: tc.nonce})
		}

		// cluster-b@EB1 partial EDS is NACKed.
		tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.EndpointType,
			SystemVersionInfo: "",
			Nonce:             "e-b-nack",
			Resources:         []*discoveryv3.Resource{{Name: "cluster-b", Version: "EB1"}},
		}, "", true)
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       resourcev3.EndpointType,
			ResponseNonce: "e-b-nack",
			ErrorDetail:   &statuspb.Status{Message: "bad cluster-b"},
		})
		if tracker.IsACKed(node, "v1") {
			t.Fatal("NACKed cluster-b converged")
		}

		// v2 removes cluster-b without emitting a new EDS response.
		tracker.ExpectSnapshotResources(node, "v2", map[string]string{
			resourcev3.ClusterType:  "c-v2",
			resourcev3.EndpointType: "e-v2",
		}, nil, map[string]map[string]string{
			resourcev3.ClusterType:  {"cluster-a": "CA1"},
			resourcev3.EndpointType: {"cluster-a": "EA1"},
		})
		tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.ClusterType,
			SystemVersionInfo: "v2",
			Nonce:             "c2",
			RemovedResources:  []string{"cluster-b"},
		}, "c-v2", true)
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2"})
		if !tracker.IsACKed(node, "v2") {
			t.Fatalf("removing rejected resource did not promote convergence: %s", tracker.ConvergenceDetails(node, "v2"))
		}
		if _, ok := tracker.LastNACK(node); ok {
			t.Fatal("removed resource rejection remained in LastNACK")
		}
	})

	t.Run("unsubscribe_and_filtered_initial_versions_clear_stale_keys", func(t *testing.T) {
		tracker := NewAckTracker()
		node := "default/gateway"
		tracker.ExpectSnapshotResources(node, "v2", map[string]string{
			resourcev3.ClusterType:  "c-v2",
			resourcev3.EndpointType: "e-v2",
		}, nil, map[string]map[string]string{
			resourcev3.ClusterType:  {"cluster-a": "CA1"},
			resourcev3.EndpointType: {"cluster-a": "EA2"},
		})

		// Reconnecting Envoy holds cluster-z (unsubscribed) and cluster-b (about to unsubscribe).
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{
			Node:                    &corev3.Node{Cluster: node},
			TypeUrl:                 resourcev3.ClusterType,
			InitialResourceVersions: map[string]string{"cluster-a": "CA1"},
		})
		tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.ClusterType,
			SystemVersionInfo: "v2",
			Nonce:             "c2",
		}, "c-v2", true)
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "c2"})

		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                   resourcev3.EndpointType,
			ResourceNamesSubscribe:    []string{"cluster-a", "cluster-b"},
			ResourceNamesUnsubscribe:  nil,
			InitialResourceVersions:   map[string]string{"cluster-a": "EA1", "cluster-b": "EB1", "cluster-z": "EZ1"},
		})
		// EDS sends cluster-a@EA2 and cluster-b is unsubscribed before RemovedResources is needed.
		tracker.OnResponseWithFingerprint(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType}, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl:           resourcev3.EndpointType,
			SystemVersionInfo: "v2",
			Nonce:             "e2",
			Resources:         []*discoveryv3.Resource{{Name: "cluster-a", Version: "EA2"}},
		}, "e-v2", true)
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                  resourcev3.EndpointType,
			ResponseNonce:            "e2",
			ResourceNamesUnsubscribe: []string{"cluster-b"},
		})
		if !tracker.IsACKed(node, "v2") {
			t.Fatalf("unsubscribe/filtered InitialResourceVersions blocked convergence: %s", tracker.ConvergenceDetails(node, "v2"))
		}
	})

	t.Run("inflight_response_and_initial_mismatch_do_not_falsely_converge", func(t *testing.T) {
		// (a) In-flight v2 response blocks v3 revert from promoting convergence early,
		// and late v2 ACK clears stale converged state instead of leaving v3 falsely ACKed.
		tracker := NewAckTracker()
		node := "default/gateway"
		tracker.ExpectSnapshotResources(node, "v1", map[string]string{resourcev3.EndpointType: "e1"}, nil, map[string]map[string]string{
			resourcev3.EndpointType: {"cluster-a": "EA1"},
		})
		req := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.EndpointType}
		tracker.OnRequest(1, req)
		tracker.OnResponseWithFingerprint(1, req, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v1", Nonce: "e1",
			Resources: []*discoveryv3.Resource{{Name: "cluster-a", Version: "EA1"}},
		}, "e1", true)
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e1"})

		tracker.ExpectSnapshotResources(node, "v2", map[string]string{resourcev3.EndpointType: "e2"}, nil, map[string]map[string]string{
			resourcev3.EndpointType: {"cluster-a": "EA2"},
		})
		tracker.OnResponseWithFingerprint(1, req, &discoveryv3.DeltaDiscoveryResponse{
			TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v2", Nonce: "e2",
			Resources: []*discoveryv3.Resource{{Name: "cluster-a", Version: "EA2"}},
		}, "e2", true)

		// Snapshot reverts to EA1 while e2 is in flight.
		tracker.ExpectSnapshotResources(node, "v3", map[string]string{resourcev3.EndpointType: "e1"}, nil, map[string]map[string]string{
			resourcev3.EndpointType: {"cluster-a": "EA1"},
		})
		if tracker.IsACKed(node, "v3") {
			t.Fatal("v3 converged prematurely while e2 was still in flight")
		}
		tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "e2"})
		if tracker.IsACKed(node, "v3") {
			t.Fatal("v3 stayed converged after Envoy ACKed EA2")
		}

		// (b) Mismatched InitialResourceVersions must not be revived when snapshot cycles back.
		revive := NewAckTracker()
		revive.OnRequest(2, &discoveryv3.DeltaDiscoveryRequest{
			Node:                    &corev3.Node{Cluster: node},
			TypeUrl:                 resourcev3.EndpointType,
			InitialResourceVersions: map[string]string{"cluster-a": "EA1"},
		})
		revive.ExpectSnapshotResources(node, "v1", map[string]string{resourcev3.EndpointType: "e2"}, nil, map[string]map[string]string{
			resourcev3.EndpointType: {"cluster-a": "EA2"},
		})
		revive.ExpectSnapshotResources(node, "v2", map[string]string{resourcev3.EndpointType: "e1"}, nil, map[string]map[string]string{
			resourcev3.EndpointType: {"cluster-a": "EA1"},
		})
		if revive.IsACKed(node, "v2") {
			t.Fatal("mismatched InitialResourceVersions revived after snapshot cycled back")
		}
	})
}

func TestAckTrackerRetainsQueuedResponseFingerprintPastHistoryCap(t *testing.T) {
	baseCache := cachev3.NewSnapshotCache(true, gatewayNodeHash{}, nil)
	oc := newOrderedDeltaCache(baseCache, gatewayNodeHash{})
	tracker := NewAckTracker()
	node := "default/gateway"
	ch := make(chan cachev3.DeltaResponse, 8)

	v1 := buildBoundClusterSnapshot(t, "v1", map[string]string{"cluster-a": "a1.example"})
	fp1, err := fingerprintVersionMap(v1.GetVersionMap(resourcev3.EndpointType))
	if err != nil {
		t.Fatal(err)
	}
	cdsFP1, err := fingerprintVersionMap(v1.GetVersionMap(resourcev3.ClusterType))
	if err != nil {
		t.Fatal(err)
	}
	tracker.ExpectSnapshotResources(node, "v1", map[string]string{
		resourcev3.ClusterType:  cdsFP1,
		resourcev3.EndpointType: fp1,
	}, nil, map[string]map[string]string{
		resourcev3.ClusterType:  v1.GetVersionMap(resourcev3.ClusterType),
		resourcev3.EndpointType: v1.GetVersionMap(resourcev3.EndpointType),
	})
	if err := oc.SetSnapshot(t.Context(), node, v1); err != nil {
		t.Fatal(err)
	}

	cdsReq := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ClusterType}
	cdsSub := streamv3.NewDeltaSubscription(nil, nil, nil, true)
	cancelCDS, err := oc.CreateDeltaWatch(cdsReq, &cdsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelCDS()
	cdsResp := <-ch
	cdsProto, err := cdsResp.GetDeltaDiscoveryResponse()
	if err != nil {
		t.Fatal(err)
	}
	cdsProto.Nonce = "cds-1"
	cdsFP, hasCDSFP := oc.ConsumeResponseFingerprint(cdsProto)
	tracker.OnResponseWithFingerprint(1, cdsReq, cdsProto, cdsFP, hasCDSFP)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ClusterType, ResponseNonce: "cds-1"})

	// Materialize the EDS response while v1 is active, but do NOT deliver OnResponseWithFingerprint yet.
	edsReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResourceNamesSubscribe: []string{"cluster-a"}}
	edsSub := streamv3.NewDeltaSubscription([]string{"cluster-a"}, nil, nil, false)
	cancelEDS, err := oc.CreateDeltaWatch(edsReq, &edsSub, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEDS()
	queuedEDS := <-ch
	edsProto, err := queuedEDS.GetDeltaDiscoveryResponse()
	if err != nil {
		t.Fatal(err)
	}
	edsProto.Nonce = "queued-eds-1"

	// Publish more than maxTrackedVersionsPerNode (64) newer versions with unchanged Endpoint fingerprint.
	lastVersion := "v1"
	for i := 2; i <= maxTrackedVersionsPerNode+10; i++ {
		lastVersion = fmt.Sprintf("v%d", i)
		tracker.ExpectSnapshotResources(node, lastVersion, map[string]string{
			resourcev3.ClusterType:  cdsFP1,
			resourcev3.EndpointType: fp1,
		}, nil, map[string]map[string]string{
			resourcev3.ClusterType:  v1.GetVersionMap(resourcev3.ClusterType),
			resourcev3.EndpointType: v1.GetVersionMap(resourcev3.EndpointType),
		})
	}

	edsFP, hasEDSFP := oc.ConsumeResponseFingerprint(edsProto)
	if !hasEDSFP || edsFP != fp1 {
		t.Fatalf("ConsumeResponseFingerprint = (%q, %v), want (%q, true)", edsFP, hasEDSFP, fp1)
	}
	tracker.OnResponseWithFingerprint(1, edsReq, edsProto, edsFP, hasEDSFP)
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "queued-eds-1"})
	if !tracker.IsACKed(node, lastVersion) {
		t.Fatalf("queued EDS ACK after >64 intervening versions failed to converge: %s", tracker.ConvergenceDetails(node, lastVersion))
	}
}
