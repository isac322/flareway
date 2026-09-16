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
	"sync"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// NACK is the last rejected Delta xDS response for a node.
type NACK struct {
	Version string
	TypeURL string
	Detail  string
}

type pendingResponse struct {
	node    string
	version string
}

type expectedSnapshot struct {
	version string
	types   map[string]struct{}
}

// AckTracker correlates Delta response nonces with later ACK/NACK requests and
// reports convergence after every resource type changed by a snapshot has
// been ACKed.
type AckTracker struct {
	mu           sync.RWMutex
	pending      map[int64]map[string]map[string]pendingResponse
	nodes        map[int64]string
	expected     map[string]expectedSnapshot
	fingerprints map[string]map[string]string
	acked        map[string]map[string]string
	nacks        map[string]NACK
}

// NewAckTracker returns an empty, concurrency-safe tracker.
func NewAckTracker() *AckTracker {
	return &AckTracker{
		pending:      make(map[int64]map[string]map[string]pendingResponse),
		nodes:        make(map[int64]string),
		expected:     make(map[string]expectedSnapshot),
		fingerprints: make(map[string]map[string]string),
		acked:        make(map[string]map[string]string),
		nacks:        make(map[string]NACK),
	}
}

// ExpectSnapshot records only present resource types whose per-resource
// fingerprint changed. Delta xDS emits no response for unchanged types, and
// removed types do not block Gateway convergence.
func (t *AckTracker) ExpectSnapshot(node, version string, fingerprints map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	previous := t.fingerprints[node]
	if expected, ok := t.expected[node]; ok && expected.version == version && sameFingerprints(previous, fingerprints) {
		return
	}
	changed := make(map[string]struct{})
	for typeURL, fingerprint := range fingerprints {
		if previous[typeURL] != fingerprint {
			changed[typeURL] = struct{}{}
		}
	}
	current := make(map[string]string, len(fingerprints))
	for typeURL, fingerprint := range fingerprints {
		current[typeURL] = fingerprint
	}
	t.fingerprints[node] = current
	t.expected[node] = expectedSnapshot{version: version, types: changed}
	delete(t.nacks, node)
}

// OnResponse records the nonce/version tuple immediately before transmission.
func (t *AckTracker) OnResponse(streamID int64, req *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
	if req == nil || resp == nil || resp.GetNonce() == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	node := req.GetNode().GetCluster()
	if node != "" {
		t.nodes[streamID] = node
	} else {
		node = t.nodes[streamID]
	}
	if node == "" {
		return
	}
	byType := t.pending[streamID]
	if byType == nil {
		byType = make(map[string]map[string]pendingResponse)
		t.pending[streamID] = byType
	}
	byNonce := byType[resp.GetTypeUrl()]
	if byNonce == nil {
		byNonce = make(map[string]pendingResponse)
		byType[resp.GetTypeUrl()] = byNonce
	}
	byNonce[resp.GetNonce()] = pendingResponse{
		node:    node,
		version: resp.GetSystemVersionInfo(),
	}
}

// OnRequest consumes an ACK or NACK. Subscription-only requests have no nonce
// and do not alter convergence state.
func (t *AckTracker) OnRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) {
	if req == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if node := req.GetNode().GetCluster(); node != "" {
		t.nodes[streamID] = node
	}
	if req.GetResponseNonce() == "" {
		return
	}
	byType := t.pending[streamID]
	if byType == nil {
		return
	}
	byNonce := byType[req.GetTypeUrl()]
	pending, ok := byNonce[req.GetResponseNonce()]
	if !ok {
		return
	}
	delete(byNonce, req.GetResponseNonce())
	if len(byNonce) == 0 {
		delete(byType, req.GetTypeUrl())
	}
	if len(byType) == 0 {
		delete(t.pending, streamID)
	}

	if req.GetErrorDetail() != nil {
		t.nacks[pending.node] = NACK{
			Version: pending.version,
			TypeURL: req.GetTypeUrl(),
			Detail:  req.GetErrorDetail().GetMessage(),
		}
		if byAckType := t.acked[pending.node]; byAckType != nil {
			delete(byAckType, req.GetTypeUrl())
		}
		return
	}
	byAckType := t.acked[pending.node]
	if byAckType == nil {
		byAckType = make(map[string]string)
		t.acked[pending.node] = byAckType
	}
	byAckType[req.GetTypeUrl()] = pending.version
	if nack, ok := t.nacks[pending.node]; ok && nack.Version == pending.version && nack.TypeURL == req.GetTypeUrl() {
		delete(t.nacks, pending.node)
	}
}

// OnStreamClosed forgets nonce correlation state for a disconnected stream.
func (t *AckTracker) OnStreamClosed(streamID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, streamID)
	delete(t.nodes, streamID)
}

// Forget removes every convergence record associated with node.
func (t *AckTracker) Forget(node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.expected, node)
	delete(t.acked, node)
	delete(t.fingerprints, node)
	delete(t.nacks, node)
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			delete(t.nodes, streamID)
		}
	}
	for streamID, byType := range t.pending {
		for typeURL, byNonce := range byType {
			for nonce, pending := range byNonce {
				if pending.node == node {
					delete(byNonce, nonce)
				}
			}
			if len(byNonce) == 0 {
				delete(byType, typeURL)
			}
		}
		if len(byType) == 0 {
			delete(t.pending, streamID)
		}
	}
}

// IsACKed reports whether every expected resource type for node has ACKed the
// exact version. An empty expected set is already converged.
func (t *AckTracker) IsACKed(node, version string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok || expected.version != version {
		return false
	}
	acked := t.acked[node]
	for typeURL := range expected.types {
		if acked[typeURL] != version {
			return false
		}
	}
	return true
}

func sameFingerprints(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for typeURL, fingerprint := range left {
		if right[typeURL] != fingerprint {
			return false
		}
	}
	return true
}

// LastNACK returns the last rejection for the currently expected snapshot.
func (t *AckTracker) LastNACK(node string) (NACK, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	nack, ok := t.nacks[node]
	expected, expectedOK := t.expected[node]
	if !ok || !expectedOK || nack.Version != expected.version {
		return NACK{}, false
	}
	return nack, true
}
