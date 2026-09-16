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
	"sort"
	"strings"
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
// reports convergence after every subscribed resource type changed by a
// snapshot has been ACKed. Only types present in a node's active Delta
// subscriptions can receive a response, so unsubscribed types never block
// convergence.
type AckTracker struct {
	mu            sync.RWMutex
	pending       map[int64]map[string]map[string]pendingResponse
	nodes         map[int64]string
	subscriptions map[int64]map[string]struct{}
	expected      map[string]expectedSnapshot
	fingerprints  map[string]map[string]string
	acked         map[string]map[string]string
	nacks         map[string]NACK
}

// NewAckTracker returns an empty, concurrency-safe tracker.
func NewAckTracker() *AckTracker {
	return &AckTracker{
		pending:       make(map[int64]map[string]map[string]pendingResponse),
		nodes:         make(map[int64]string),
		subscriptions: make(map[int64]map[string]struct{}),
		expected:      make(map[string]expectedSnapshot),
		fingerprints:  make(map[string]map[string]string),
		acked:         make(map[string]map[string]string),
		nacks:         make(map[string]NACK),
	}
}

// ExpectSnapshot records only present resource types whose per-resource
// fingerprint changed. Delta xDS emits no response for unchanged types, and
// removed types do not block Gateway convergence. Changed types block
// convergence only while at least one stream for the node subscribes to them.
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
// A response also proves the stream holds an active subscription for the type.
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
	t.subscribeLocked(streamID, resp.GetTypeUrl())
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

// OnRequest consumes an ACK or NACK and records the stream's type
// subscription. Subscription-only requests have no nonce and do not alter
// convergence state beyond marking the type subscribed.
func (t *AckTracker) OnRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) {
	if req == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if node := req.GetNode().GetCluster(); node != "" {
		t.nodes[streamID] = node
	}
	t.subscribeLocked(streamID, req.GetTypeUrl())
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

// OnStreamClosed forgets nonce correlation and subscription state for a
// disconnected stream. Changed types lose their convergence expectation once
// no remaining stream for the node subscribes to them.
func (t *AckTracker) OnStreamClosed(streamID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, streamID)
	delete(t.nodes, streamID)
	delete(t.subscriptions, streamID)
}

// Forget removes every convergence record associated with node while keeping
// live stream identity and subscriptions. Delta requests carry Node only on
// the first request of a stream, so dropping that association here would make
// a later snapshot converge without an ACK.
func (t *AckTracker) Forget(node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.expected, node)
	delete(t.acked, node)
	delete(t.fingerprints, node)
	delete(t.nacks, node)
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

// IsACKed reports whether every changed resource type that at least one of
// node's streams subscribes to has ACKed the exact version. An empty expected
// set is already converged; a non-empty set requires a live stream so a dead
// or disconnected Envoy cannot converge vacuously.
func (t *AckTracker) IsACKed(node, version string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok || expected.version != version {
		return false
	}
	if len(expected.types) > 0 && !t.hasStreamLocked(node) {
		return false
	}
	acked := t.acked[node]
	for typeURL := range expected.types {
		if !t.subscribedLocked(node, typeURL) {
			continue
		}
		if acked[typeURL] != version {
			return false
		}
	}
	return true
}

// subscribeLocked records that streamID holds an active Delta subscription for
// typeURL. Callers must hold t.mu.
func (t *AckTracker) subscribeLocked(streamID int64, typeURL string) {
	if typeURL == "" {
		return
	}
	types := t.subscriptions[streamID]
	if types == nil {
		types = make(map[string]struct{})
		t.subscriptions[streamID] = types
	}
	types[typeURL] = struct{}{}
}

// hasStreamLocked reports whether node has any active Delta stream. Callers
// must hold t.mu.
func (t *AckTracker) hasStreamLocked(node string) bool {
	for _, streamNode := range t.nodes {
		if streamNode == node {
			return true
		}
	}
	return false
}

// subscribedLocked reports whether any stream associated with node subscribes
// to typeURL. Callers must hold t.mu.
func (t *AckTracker) subscribedLocked(node, typeURL string) bool {
	for streamID, streamNode := range t.nodes {
		if streamNode != node {
			continue
		}
		if _, ok := t.subscriptions[streamID][typeURL]; ok {
			return true
		}
	}
	return false
}

// ConvergenceDetails returns a concise, non-sensitive explanation when the
// requested snapshot has not converged.
func (t *AckTracker) ConvergenceDetails(node, version string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok {
		return "snapshot is not registered"
	}
	if expected.version != version {
		return fmt.Sprintf("expected version %s, requested %s", shortVersion(expected.version), shortVersion(version))
	}
	streams := 0
	for _, streamNode := range t.nodes {
		if streamNode == node {
			streams++
		}
	}
	if len(expected.types) > 0 && streams == 0 {
		return "no live xDS stream"
	}
	missing := make([]string, 0, len(expected.types))
	for typeURL := range expected.types {
		if !t.subscribedLocked(node, typeURL) {
			continue
		}
		ackedVersion := t.acked[node][typeURL]
		if ackedVersion != version {
			state := "no ACK"
			if ackedVersion != "" {
				state = "got " + shortVersion(ackedVersion)
			}
			missing = append(missing, fmt.Sprintf("%s(%s)", shortTypeURL(typeURL), state))
		}
	}
	sort.Strings(missing)
	if nack, found := t.nacks[node]; found && nack.Version == version {
		return fmt.Sprintf("NACK %s: %s", shortTypeURL(nack.TypeURL), nack.Detail)
	}
	if len(missing) > 0 {
		return fmt.Sprintf(
			"want %s, %d live stream(s), missing %s",
			shortVersion(version),
			streams,
			strings.Join(missing, ","),
		)
	}
	return ""
}

func shortTypeURL(typeURL string) string {
	if index := strings.LastIndexByte(typeURL, '.'); index >= 0 {
		return typeURL[index+1:]
	}
	return typeURL
}

func shortVersion(version string) string {
	if len(version) > 12 {
		return version[:12]
	}
	return version
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
