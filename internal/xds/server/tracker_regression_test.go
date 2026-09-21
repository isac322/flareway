/*
Copyright 2026 The Flareway Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

func TestAckTrackerRequiresEveryLiveReplicaACK(t *testing.T) {
	tracker := NewAckTracker()
	node, version := "default/gateway", "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, map[string]struct{}{resourcev3.ListenerType: {}})
	for _, streamID := range []int64{1, 2} {
		tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	}
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "a"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "a"})
	if tracker.IsACKed(node, version) {
		t.Fatal("one replica ACK incorrectly converged the node")
	}
	tracker.OnResponse(2, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "b"})
	tracker.OnRequest(2, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "b"})
	if !tracker.IsACKed(node, version) {
		t.Fatal("all live replica ACKs did not converge the node")
	}
}

func TestAckTrackerPeerNACKRemainsBlocking(t *testing.T) {
	tracker := NewAckTracker()
	node, version := "default/gateway", "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, map[string]struct{}{resourcev3.ListenerType: {}})
	for _, streamID := range []int64{1, 2} {
		tracker.OnRequest(streamID, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	}
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "a"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "a", ErrorDetail: &statuspb.Status{Message: "invalid listener"}})
	tracker.OnResponse(2, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "b"})
	tracker.OnRequest(2, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "b"})
	if tracker.IsACKed(node, version) {
		t.Fatal("peer ACK cleared another replica's NACK")
	}
	if nack, ok := tracker.LastNACK(node); !ok || nack.Detail != "invalid listener" {
		t.Fatalf("peer NACK was lost: %#v, %v", nack, ok)
	}
}

func TestAckTrackerReplacementStreamStartsUnproven(t *testing.T) {
	tracker := NewAckTracker()
	node, version := "default/gateway", "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener"}, map[string]struct{}{resourcev3.ListenerType: {}})
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType}
	tracker.OnRequest(1, request)
	tracker.OnResponse(1, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "a"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "a"})
	if !tracker.IsACKed(node, version) { t.Fatal("initial stream did not converge") }
	tracker.OnStreamClosed(1)
	tracker.OnRequest(2, request)
	if tracker.IsACKed(node, version) { t.Fatal("replacement stream inherited the closed stream ACK") }
}

func TestAckTrackerRequiredReferenceBlocksBeforeSubscription(t *testing.T) {
	tracker := NewAckTracker()
	node, version := "default/gateway", "v1"
	tracker.ExpectSnapshot(node, version, map[string]string{resourcev3.ListenerType: "listener", resourcev3.RouteType: "route"}, map[string]struct{}{resourcev3.ListenerType: {}, resourcev3.RouteType: {}})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: node}, TypeUrl: resourcev3.ListenerType})
	tracker.OnResponse(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType}, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.ListenerType, SystemVersionInfo: version, Nonce: "a"})
	tracker.OnRequest(1, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.ListenerType, ResponseNonce: "a"})
	if tracker.IsACKed(node, version) { t.Fatal("required route converged before its subscription and ACK") }
}
