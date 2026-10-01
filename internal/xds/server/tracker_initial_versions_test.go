package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const initialVersionsNode = "ns/gateway"

func expectInitialVersions(t *testing.T, tracker *AckTracker, version string, resources map[string]map[string]string) {
	t.Helper()
	fingerprints := make(map[string]string, len(resources))
	required := make(map[string]struct{}, len(resources))
	for typeURL, versions := range resources {
		fingerprint, err := fingerprintVersionMap(versions)
		if err != nil {
			t.Fatal(err)
		}
		fingerprints[typeURL] = fingerprint
		required[typeURL] = struct{}{}
	}
	tracker.ExpectSnapshot(initialVersionsNode, version, fingerprints, required)
}

func reportInitialVersions(tracker *AckTracker, streamID int64, typeURL string, versions map[string]string, withNode bool) {
	request := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, InitialResourceVersions: versions}
	if withNode {
		request.Node = &corev3.Node{Cluster: initialVersionsNode}
	}
	tracker.OnRequest(streamID, request)
}

func assertInitialConvergence(t *testing.T, tracker *AckTracker, version string, want bool) {
	t.Helper()
	if got := tracker.IsACKed(initialVersionsNode, version); got != want {
		t.Fatalf("snapshot convergence = %v, want %v: %s", got, want, tracker.ConvergenceDetails(initialVersionsNode, version))
	}
}

func ackInitialResponse(tracker *AckTracker, streamID int64, typeURL, version, nonce string, rejected bool) {
	request := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL}
	tracker.OnResponse(streamID, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: typeURL, SystemVersionInfo: version, Nonce: nonce})
	request.ResponseNonce = nonce
	if rejected {
		request.ErrorDetail = &statuspb.Status{Message: "rejected"}
	}
	tracker.OnRequest(streamID, request)
}

func TestAckTrackerInitialVersionsOrderingAndReplicas(t *testing.T) {
	for _, snapshotFirst := range []bool{false, true} {
		name := "reconnect-first"
		if snapshotFirst {
			name = "snapshot-first"
		}
		t.Run(name, func(t *testing.T) {
			tracker := NewAckTracker()
			routes := map[string]string{"route-a": "route-hash"}
			endpoints := map[string]string{"cluster-a": "endpoint-hash"}
			resources := map[string]map[string]string{resourcev3.RouteType: routes, resourcev3.EndpointType: endpoints}
			if snapshotFirst {
				expectInitialVersions(t, tracker, "v1", resources)
			}
			for _, streamID := range []int64{1, 2} {
				reportInitialVersions(tracker, streamID, resourcev3.RouteType, routes, true)
				// Delta clients send Node only in the first request of the stream.
				if streamID == 1 {
					reportInitialVersions(tracker, streamID, resourcev3.EndpointType, endpoints, false)
				} else {
					reportInitialVersions(tracker, streamID, resourcev3.EndpointType, nil, false)
				}
			}
			if !snapshotFirst {
				expectInitialVersions(t, tracker, "v1", resources)
			}
			assertInitialConvergence(t, tracker, "v1", false)
			ackInitialResponse(tracker, 2, resourcev3.EndpointType, "v1", "endpoint-ack", false)
			assertInitialConvergence(t, tracker, "v1", true)
		})
	}
}

func TestAckTrackerInitialVersionsRequireExactResources(t *testing.T) {
	for name, held := range map[string]map[string]string{
		"empty":             nil,
		"different-version": {"route-a": "stale", "route-b": "h2"},
		"missing-resource":  {"route-a": "h1"},
		"extra-resource":    {"route-a": "h1", "route-b": "h2", "route-c": "h3"},
	} {
		t.Run(name, func(t *testing.T) {
			tracker := NewAckTracker()
			reportInitialVersions(tracker, 1, resourcev3.RouteType, held, true)
			expectInitialVersions(t, tracker, "v1", map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1", "route-b": "h2"}})
			assertInitialConvergence(t, tracker, "v1", false)
			ackInitialResponse(tracker, 1, resourcev3.RouteType, "v1", "corrected", false)
			assertInitialConvergence(t, tracker, "v1", true)
		})
	}
}

func TestAckTrackerInitialVersionsAreImmutableEvidence(t *testing.T) {
	tracker := NewAckTracker()
	held := map[string]string{"route-a": "h1"}
	reportInitialVersions(tracker, 1, resourcev3.RouteType, held, true)
	held["route-a"] = "mutated"
	expectInitialVersions(t, tracker, "v1", map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}})
	assertInitialConvergence(t, tracker, "v1", true)
}

func TestAckTrackerInitialVersionsCannotConvergeAnotherGateway(t *testing.T) {
	tracker := NewAckTracker()
	resources := map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}}
	reportInitialVersions(tracker, 1, resourcev3.RouteType, resources[resourcev3.RouteType], true)
	otherNode := "ns/other-gateway"
	tracker.OnRequest(2, &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: otherNode}, TypeUrl: resourcev3.RouteType})
	fingerprint, err := fingerprintVersionMap(resources[resourcev3.RouteType])
	if err != nil {
		t.Fatal(err)
	}
	tracker.ExpectSnapshot(otherNode, "v1", map[string]string{resourcev3.RouteType: fingerprint}, map[string]struct{}{resourcev3.RouteType: {}})
	if tracker.IsACKed(otherNode, "v1") {
		t.Fatal("one Gateway's held resources converged another Gateway")
	}
	expectInitialVersions(t, tracker, "v1", resources)
	assertInitialConvergence(t, tracker, "v1", true)
	if tracker.IsACKed(otherNode, "v1") {
		t.Fatal("publishing one Gateway promoted another Gateway's stream")
	}
	ackInitialResponse(tracker, 2, resourcev3.RouteType, "v1", "other-gateway-ack", false)
	if !tracker.IsACKed(otherNode, "v1") {
		t.Fatal("other Gateway did not converge after its own ACK")
	}
}

func TestAckTrackerInitialVersionsDoNotSurviveCleanup(t *testing.T) {
	for _, cleanup := range []string{"stream-close", "forget"} {
		t.Run(cleanup, func(t *testing.T) {
			tracker := NewAckTracker()
			resources := map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}}
			reportInitialVersions(tracker, 1, resourcev3.RouteType, resources[resourcev3.RouteType], true)
			if cleanup == "stream-close" {
				tracker.OnStreamClosed(1)
				reportInitialVersions(tracker, 1, resourcev3.RouteType, nil, true)
			} else {
				tracker.Forget(initialVersionsNode)
			}
			expectInitialVersions(t, tracker, "v1", resources)
			assertInitialConvergence(t, tracker, "v1", false)
			ackInitialResponse(tracker, 1, resourcev3.RouteType, "v1", "fresh", false)
			assertInitialConvergence(t, tracker, "v1", true)
		})
	}
}

func TestAckTrackerInitialMismatchCannotConvergeLaterSnapshot(t *testing.T) {
	tracker := NewAckTracker()
	reportInitialVersions(tracker, 1, resourcev3.RouteType, map[string]string{"route-a": "h1"}, true)
	expectInitialVersions(t, tracker, "v1", map[string]map[string]string{resourcev3.RouteType: {"route-a": "h2"}})
	assertInitialConvergence(t, tracker, "v1", false)
	expectInitialVersions(t, tracker, "v2", map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}})
	assertInitialConvergence(t, tracker, "v2", false)
}

func TestAckTrackerInitialVersionsSupersededBeforeSnapshot(t *testing.T) {
	for _, event := range []string{"response", "nonce-request", "nack"} {
		t.Run(event, func(t *testing.T) {
			tracker := NewAckTracker()
			resources := map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}}
			reportInitialVersions(tracker, 1, resourcev3.RouteType, resources[resourcev3.RouteType], true)
			request := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: resourcev3.RouteType, ResponseNonce: "superseding"}
			if event != "nonce-request" {
				tracker.OnResponse(1, request, &discoveryv3.DeltaDiscoveryResponse{TypeUrl: resourcev3.RouteType, Nonce: "superseding", SystemVersionInfo: "v1"})
			}
			if event == "nack" {
				request.ErrorDetail = &statuspb.Status{Message: "rejected"}
			}
			if event != "response" {
				tracker.OnRequest(1, request)
			}
			expectInitialVersions(t, tracker, "v1", resources)
			assertInitialConvergence(t, tracker, "v1", false)
			ackInitialResponse(tracker, 1, resourcev3.RouteType, "v1", "new-response", false)
			assertInitialConvergence(t, tracker, "v1", true)
		})
	}
}

func TestAckTrackerAdoptedInitialVersionsCannotClearLaterNACK(t *testing.T) {
	tracker := NewAckTracker()
	resources := map[string]map[string]string{resourcev3.RouteType: {"route-a": "h1"}}
	reportInitialVersions(tracker, 1, resourcev3.RouteType, resources[resourcev3.RouteType], true)
	expectInitialVersions(t, tracker, "v1", resources)
	assertInitialConvergence(t, tracker, "v1", true)
	ackInitialResponse(tracker, 1, resourcev3.RouteType, "v1", "rejected-response", true)
	expectInitialVersions(t, tracker, "v1", resources)
	assertInitialConvergence(t, tracker, "v1", false)
	ackInitialResponse(tracker, 1, resourcev3.RouteType, "v1", "accepted-response", false)
	assertInitialConvergence(t, tracker, "v1", true)
}

func TestServerInitialVersionsBeforeSnapshotConvergeWithoutDeltaResponse(t *testing.T) {
	server, err := New(Options{TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}})
	if err != nil {
		t.Fatal(err)
	}
	// RDS is an explicitly named subscription. Unlike a first wildcard request,
	// identical named resources do not generate even an empty Delta response.
	hcm, err := anypb.New(&hcmv3.HttpConnectionManager{RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{Rds: &hcmv3.Rds{RouteConfigName: "route-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	listener := &listenerv3.Listener{Name: "listener-a", FilterChains: []*listenerv3.FilterChain{{Filters: []*listenerv3.Filter{{Name: "envoy.filters.network.http_connection_manager", ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcm}}}}}}
	snapshot, err := cachev3.NewSnapshot("v1", map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {listener},
		resourcev3.RouteType:    {&routev3.RouteConfiguration{Name: "route-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.ConstructVersionMap(); err != nil {
		t.Fatal(err)
	}
	versions := snapshot.GetVersionMap(resourcev3.RouteType)
	request := &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{Cluster: initialVersionsNode}, TypeUrl: resourcev3.RouteType, ResourceNamesSubscribe: []string{"route-a"}, InitialResourceVersions: versions}
	server.AckTracker().OnRequest(1, request)
	reportInitialVersions(server.AckTracker(), 1, resourcev3.ListenerType, snapshot.GetVersionMap(resourcev3.ListenerType), false)
	responses := make(chan cachev3.DeltaResponse, 1)
	cancel, err := server.Cache().CreateDeltaWatch(request, streamv3.NewDeltaSubscription(request.ResourceNamesSubscribe, nil, versions, true), responses)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if server.IsACKed(initialVersionsNode, "v1") {
		t.Fatal("unpublished snapshot converged")
	}
	if err := server.SetSnapshot(context.Background(), initialVersionsNode, snapshot); err != nil {
		t.Fatal(err)
	}
	select {
	case <-responses:
		t.Fatal("unchanged named resources generated a Delta response")
	default:
	}
	if !server.IsACKed(initialVersionsNode, "v1") {
		t.Fatalf("matching held resources did not converge after publication: %s", server.ACKDetails(initialVersionsNode, "v1"))
	}
}
