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

// NACK is the last rejected Delta xDS response for a stream.
type NACK struct {
	Version string
	TypeURL string
	Detail  string
}

type pendingResponse struct {
	node    string
	version string
}

// streamAck records the response version a stream acknowledged and the
// resource fingerprint that response carried. The fingerprint is the
// convergence evidence: an ACK for an older version still proves the stream
// holds the current resources when the type's fingerprint is unchanged.
type streamAck struct {
	version     string
	fingerprint string
}

type expectedSnapshot struct {
	version string
	// required holds the snapshot resource types a conformant Envoy is
	// guaranteed to subscribe to (bootstrap LDS/CDS plus every type referenced
	// by a delivered resource). Required types block convergence even before
	// the stream's subscription arrives; unreferenced types never will be
	// subscribed and must not block.
	required map[string]struct{}
}

// AckTracker correlates Delta response nonces with later ACK/NACK requests and
// reports convergence once every live stream for a node has ACKed the current
// resource fingerprint of each type it subscribes to or is required to
// subscribe to. ACK and NACK state is owned per stream: one Envoy replica can
// neither converge nor clear the rejection of a peer, and a closed stream's
// records are never inherited by its replacement.
type AckTracker struct {
	mu            sync.RWMutex
	pending       map[int64]map[string]map[string]pendingResponse
	nodes         map[int64]string
	subscriptions map[int64]map[string]struct{}
	expected      map[string]expectedSnapshot
	fingerprints  map[string]map[string]string
	acked         map[int64]map[string]streamAck
	nacks         map[int64]NACK
}

// NewAckTracker returns an empty, concurrency-safe tracker.
func NewAckTracker() *AckTracker {
	return &AckTracker{
		pending:       make(map[int64]map[string]map[string]pendingResponse),
		nodes:         make(map[int64]string),
		subscriptions: make(map[int64]map[string]struct{}),
		expected:      make(map[string]expectedSnapshot),
		fingerprints:  make(map[string]map[string]string),
		acked:         make(map[int64]map[string]streamAck),
		nacks:         make(map[int64]NACK),
	}
}

// ExpectSnapshot records the snapshot's per-type resource fingerprints and the
// set of required type URLs. Convergence is judged per stream against the
// fingerprint of every present type the stream subscribes to or must
// subscribe to, so an unchanged type never demands a new ACK while a
// republished snapshot still requires proof from every live stream.
func (t *AckTracker) ExpectSnapshot(node, version string, fingerprints map[string]string, required map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	previous := t.fingerprints[node]
	if expected, ok := t.expected[node]; ok && expected.version == version && sameFingerprints(previous, fingerprints) {
		return
	}
	requiredPresent := make(map[string]struct{}, len(required))
	for typeURL := range required {
		if _, ok := fingerprints[typeURL]; ok {
			requiredPresent[typeURL] = struct{}{}
		}
	}
	current := make(map[string]string, len(fingerprints))
	for typeURL, fingerprint := range fingerprints {
		current[typeURL] = fingerprint
	}
	t.fingerprints[node] = current
	t.expected[node] = expectedSnapshot{version: version, required: requiredPresent}
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			delete(t.nacks, streamID)
		}
	}
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
	node := req.GetNode().GetCluster()
	if node != "" {
		t.nodes[streamID] = node
	} else {
		node = t.nodes[streamID]
	}
	t.subscribeLocked(streamID, req.GetTypeUrl())
	if req.GetResponseNonce() == "" {
		t.acceptInitialVersionsLocked(streamID, node, req.GetTypeUrl(), req.GetInitialResourceVersions())
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
		t.nacks[streamID] = NACK{
			Version: pending.version,
			TypeURL: req.GetTypeUrl(),
			Detail:  req.GetErrorDetail().GetMessage(),
		}
		if byAckType := t.acked[streamID]; byAckType != nil {
			delete(byAckType, req.GetTypeUrl())
		}
		return
	}
	// Record the fingerprint the ACKed response carried. An ACK for a stale
	// version still proves the stream holds current resources when the type's
	// fingerprint is unchanged, so only the expected version's ACK is
	// recorded; anything older is ignored.
	if expected, ok := t.expected[pending.node]; ok && expected.version == pending.version {
		byAckType := t.acked[streamID]
		if byAckType == nil {
			byAckType = make(map[string]streamAck)
			t.acked[streamID] = byAckType
		}
		byAckType[req.GetTypeUrl()] = streamAck{
			version:     pending.version,
			fingerprint: t.fingerprints[pending.node][req.GetTypeUrl()],
		}
	}
	if nack, ok := t.nacks[streamID]; ok && nack.Version == pending.version && nack.TypeURL == req.GetTypeUrl() {
		delete(t.nacks, streamID)
	}
}

// acceptInitialVersionsLocked recognizes a reconnected Delta client that
// reports it already holds the exact current resource versions. The snapshot
// cache emits no response in that case, so the initial versions are the only
// protocol evidence available for convergence.
func (t *AckTracker) acceptInitialVersionsLocked(streamID int64, node, typeURL string, versions map[string]string) {
	if node == "" || typeURL == "" || len(versions) == 0 {
		return
	}
	expected, ok := t.expected[node]
	if !ok {
		return
	}
	fingerprint, err := fingerprintVersionMap(versions)
	if err != nil || fingerprint == "" || fingerprint != t.fingerprints[node][typeURL] {
		return
	}
	byType := t.acked[streamID]
	if byType == nil {
		byType = make(map[string]streamAck)
		t.acked[streamID] = byType
	}
	byType[typeURL] = streamAck{version: expected.version, fingerprint: fingerprint}
	if nack, found := t.nacks[streamID]; found && nack.Version == expected.version && nack.TypeURL == typeURL {
		delete(t.nacks, streamID)
	}
}

// OnStreamClosed forgets nonce correlation, subscription, and convergence
// state for a disconnected stream. The stream's ACK and NACK records die with
// it so a replacement stream starts unproven and cannot inherit them.
func (t *AckTracker) OnStreamClosed(streamID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, streamID)
	delete(t.nodes, streamID)
	delete(t.subscriptions, streamID)
	delete(t.acked, streamID)
	delete(t.nacks, streamID)
}

// Forget removes every convergence record associated with node while keeping
// live stream identity and subscriptions. Delta requests carry Node only on
// the first request of a stream, so dropping that association here would make
// a later snapshot converge without an ACK.
func (t *AckTracker) Forget(node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.expected, node)
	delete(t.fingerprints, node)
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			delete(t.acked, streamID)
			delete(t.nacks, streamID)
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

// IsACKed reports whether every live stream for node has proven it holds the
// requested snapshot: for each resource type present in the snapshot, a
// subscribed stream must have ACKed the current fingerprint, and a required
// type must be subscribed and ACKed even if its subscription has not arrived
// yet. A snapshot carrying no resources is converged immediately; a non-empty
// snapshot requires at least one live stream so a dead or disconnected Envoy
// cannot converge vacuously.
func (t *AckTracker) IsACKed(node, version string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok || expected.version != version {
		return false
	}
	present := t.fingerprints[node]
	if len(present) == 0 {
		return true
	}
	if !t.hasStreamLocked(node) {
		return false
	}
	for streamID, streamNode := range t.nodes {
		if streamNode != node {
			continue
		}
		if nack, ok := t.nacks[streamID]; ok && nack.Version == version {
			return false
		}
		acked := t.acked[streamID]
		for typeURL, fingerprint := range present {
			_, required := expected.required[typeURL]
			_, subscribed := t.subscriptions[streamID][typeURL]
			if !subscribed && !required {
				continue
			}
			if acked[typeURL].fingerprint != fingerprint {
				return false
			}
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

// streamIDsLocked returns the live stream IDs for node in ascending order so
// aggregated output is deterministic. Callers must hold t.mu.
func (t *AckTracker) streamIDsLocked(node string) []int64 {
	ids := make([]int64, 0, len(t.nodes))
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			ids = append(ids, streamID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// ConvergenceDetails returns a concise, non-sensitive explanation when the
// requested snapshot has not converged. Stream identity is never exposed: the
// message aggregates stream count and the worst per-type state only.
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
	streams := t.streamIDsLocked(node)
	present := t.fingerprints[node]
	if len(present) > 0 && len(streams) == 0 {
		return "no live xDS stream"
	}
	for _, streamID := range streams {
		if nack, found := t.nacks[streamID]; found && nack.Version == version {
			return fmt.Sprintf("NACK %s: %s", shortTypeURL(nack.TypeURL), nack.Detail)
		}
	}
	// Per type, report the worst state across streams: a required type no
	// stream has subscribed to yet outranks a missing ACK, which outranks a
	// stale ACK.
	const (
		staleAck = iota
		noAck
		notSubscribed
	)
	worst := make(map[string]int, len(present))
	for _, streamID := range streams {
		for typeURL, fingerprint := range present {
			_, required := expected.required[typeURL]
			_, subscribed := t.subscriptions[streamID][typeURL]
			if !subscribed && !required {
				continue
			}
			ack := t.acked[streamID][typeURL]
			if ack.fingerprint == fingerprint {
				continue
			}
			state := noAck
			switch {
			case !subscribed:
				state = notSubscribed
			case ack.version != "" || ack.fingerprint != "":
				state = staleAck
			}
			if state > worst[typeURL] {
				worst[typeURL] = state
			}
		}
	}
	missing := make([]string, 0, len(worst))
	for typeURL, state := range worst {
		var detail string
		switch state {
		case notSubscribed:
			detail = "not subscribed"
		case staleAck:
			detail = "stale ACK"
		default:
			detail = "no ACK"
		}
		missing = append(missing, fmt.Sprintf("%s(%s)", shortTypeURL(typeURL), detail))
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Sprintf(
			"want %s, %d live stream(s), missing %s",
			shortVersion(version),
			len(streams),
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

// LastNACK returns the earliest live stream's rejection for the currently
// expected snapshot.
func (t *AckTracker) LastNACK(node string) (NACK, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok {
		return NACK{}, false
	}
	for _, streamID := range t.streamIDsLocked(node) {
		if nack, found := t.nacks[streamID]; found && nack.Version == expected.version {
			return nack, true
		}
	}
	return NACK{}, false
}
