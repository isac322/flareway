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
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

func TestAckTrackerRequiresEveryExpectedType(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{
		resourcev3.ListenerType: "listener",
		resourcev3.RouteType:    "route",
	})

	listenerRequest := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnResponse(7, listenerRequest, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "1"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "1"})
	if tracker.IsACKed(node, version) {
		t.Fatal("snapshot converged before RouteConfiguration ACK")
	}

	routeRequest := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.RouteType}
	tracker.OnResponse(7, routeRequest, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, SystemVersionInfo: version, Nonce: "2"})
	tracker.OnRequest(7, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "2"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("snapshot did not converge after every expected ACK")
	}
}

func TestAckTrackerRecordsNACKAndRecovers(t *testing.T) {
	tracker := NewAckTracker()
	node := "default/gateway"
	version := "v2"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"})
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
	tracker.ExpectSnapshot("default/invalid", "empty-v1", nil)
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
	})
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
	})
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.EndpointType}
	tracker.OnResponse(3, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.EndpointType, SystemVersionInfo: "v2", Nonce: "endpoint-v2"})
	tracker.OnRequest(3, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.EndpointType, ResponseNonce: "endpoint-v2"})
	if !tracker.IsACKed(node, "v2") {
		t.Fatal("unchanged Listener type incorrectly required a v2 ACK")
	}

	tracker.ExpectSnapshot(node, "v3", map[string]string{resourcev3.ListenerType: "listener-a"})
	if !tracker.IsACKed(node, "v3") {
		t.Fatal("resource type absent from the new snapshot blocked convergence")
	}
}
