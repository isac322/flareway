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
	node        string
	version     string
	fingerprint string
	updated     map[string]string
	removed     []string
}

type rejectedResource struct {
	version string
	detail  string
}

const maxTrackedVersionsPerNode = 64

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
	mu                  sync.RWMutex
	pending             map[int64]map[string]map[string]pendingResponse
	nodes               map[int64]string
	nodeIDs             map[int64]string
	subscriptions       map[int64]map[string]struct{}
	expected            map[string]expectedSnapshot
	fingerprints        map[string]map[string]string
	expectedResources   map[string]map[string]map[string]string
	versionFingerprints map[string]map[string]map[string]string
	versionOrder        map[string][]string
	acked               map[int64]map[string]streamAck
	acceptedResources   map[int64]map[string]map[string]string
	rejectedResources   map[int64]map[string]map[string]rejectedResource
	nacks               map[int64]NACK
	// initialFingerprints holds bootstrap proof received before a snapshot is
	// known. Each stream/type has at most one immutable fingerprint, consumed
	// by the first expectation or superseding protocol activity.
	initialFingerprints map[int64]map[string]string
	// initialResourceMismatch records stream/type pairs whose bootstrap
	// InitialResourceVersions mismatched an expected snapshot and therefore
	// must not converge solely through snapshot cycling without a real ACK.
	initialResourceMismatch     map[int64]map[string]struct{}
	unconfirmedInitialResources map[int64]map[string]struct{}
}

// NewAckTracker returns an empty, concurrency-safe tracker.
func NewAckTracker() *AckTracker {
	return &AckTracker{
		pending:                     make(map[int64]map[string]map[string]pendingResponse),
		nodes:                       make(map[int64]string),
		nodeIDs:                     make(map[int64]string),
		subscriptions:               make(map[int64]map[string]struct{}),
		expected:                    make(map[string]expectedSnapshot),
		fingerprints:                make(map[string]map[string]string),
		expectedResources:           make(map[string]map[string]map[string]string),
		versionFingerprints:         make(map[string]map[string]map[string]string),
		versionOrder:                make(map[string][]string),
		acked:                       make(map[int64]map[string]streamAck),
		acceptedResources:           make(map[int64]map[string]map[string]string),
		rejectedResources:           make(map[int64]map[string]map[string]rejectedResource),
		nacks:                       make(map[int64]NACK),
		initialFingerprints:         make(map[int64]map[string]string),
		initialResourceMismatch:     make(map[int64]map[string]struct{}),
		unconfirmedInitialResources: make(map[int64]map[string]struct{}),
	}
}

// ExpectSnapshot records the snapshot's per-type resource fingerprints and the
// set of required type URLs. Convergence is judged per stream against the
// fingerprint of every present type the stream subscribes to or must
// subscribe to, so an unchanged type never demands a new ACK while a
// republished snapshot still requires proof from every live stream.
func (t *AckTracker) ExpectSnapshot(node, version string, fingerprints map[string]string, required map[string]struct{}) {
	t.ExpectSnapshotResources(node, version, fingerprints, required, nil)
}

// ExpectSnapshotResources records the snapshot's per-type fingerprints, required
// types, and expected per-resource versions for types whose convergence must be
// proven per resource (such as Endpoint assignments after partial NACKs).
func (t *AckTracker) ExpectSnapshotResources(node, version string, fingerprints map[string]string, required map[string]struct{}, expectedResources map[string]map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	previous := t.fingerprints[node]
	if expected, ok := t.expected[node]; ok && expected.version == version && sameFingerprints(previous, fingerprints) && sameNestedStringMaps(t.expectedResources[node], expectedResources) {
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
	var copiedExpected map[string]map[string]string
	if len(expectedResources) > 0 {
		copiedExpected = make(map[string]map[string]string, len(expectedResources))
		for typeURL, byName := range expectedResources {
			cloned := make(map[string]string, len(byName))
			for name, ver := range byName {
				cloned[name] = ver
			}
			copiedExpected[typeURL] = cloned
		}
	}
	t.fingerprints[node] = current
	t.expectedResources[node] = copiedExpected
	t.recordVersionFingerprintsLocked(node, version, current)
	t.expected[node] = expectedSnapshot{version: version, required: requiredPresent}
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			delete(t.nacks, streamID)
			for typeURL, byNonce := range t.pending[streamID] {
				if len(byNonce) > 0 {
					if byAckType := t.acked[streamID]; byAckType != nil {
						delete(byAckType, typeURL)
					}
				}
			}
			t.pruneRejectedResourcesLocked(streamID, copiedExpected)
			for typeURL, fingerprint := range t.initialFingerprints[streamID] {
				t.acceptInitialFingerprintLocked(streamID, node, typeURL, fingerprint)
			}
			// Initial holdings describe stream bootstrap, not future snapshots.
			// Consume even mismatches so fingerprint cycling cannot revive them.
			delete(t.initialFingerprints, streamID)
			t.reconcileAcceptedConvergenceLocked(streamID, version, current, copiedExpected)
		}
	}
}

// OnResponse records the nonce/version tuple immediately before transmission.
// A response also proves the stream holds an active subscription for the type.
func (t *AckTracker) OnResponse(streamID int64, req *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
	t.OnResponseWithFingerprint(streamID, req, resp, "", false)
}

// OnResponseWithFingerprint records the nonce, version, delivered resource
// versions, and optional originating type fingerprint before transmission.
func (t *AckTracker) OnResponseWithFingerprint(streamID int64, req *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse, fingerprint string, hasFingerprint bool) {
	if req == nil || resp == nil || resp.GetNonce() == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.recordStreamIdentityLocked(streamID, req)
	if node == "" {
		return
	}
	t.subscribeLocked(streamID, resp.GetTypeUrl())
	t.forgetInitialFingerprintLocked(streamID, resp.GetTypeUrl())
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
	respVersion := resp.GetSystemVersionInfo()
	fp := fingerprint
	if !hasFingerprint {
		fp = t.versionFingerprints[node][respVersion][resp.GetTypeUrl()]
	}
	var updated map[string]string
	if resList := resp.GetResources(); len(resList) > 0 {
		updated = make(map[string]string, len(resList))
		for _, res := range resList {
			if res.GetName() != "" {
				updated[res.GetName()] = res.GetVersion()
			}
		}
	}
	var removed []string
	if remList := resp.GetRemovedResources(); len(remList) > 0 {
		removed = append([]string(nil), remList...)
	}
	byNonce[resp.GetNonce()] = pendingResponse{
		node:        node,
		version:     respVersion,
		fingerprint: fp,
		updated:     updated,
		removed:     removed,
	}
}

// OnRequest consumes an ACK or NACK and records the stream's type
// subscription. Requests without a nonce may prove held resources through
// initial versions, even before the first snapshot is known.
func (t *AckTracker) OnRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) {
	if req == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.recordStreamIdentityLocked(streamID, req)
	typeURL := req.GetTypeUrl()
	t.subscribeLocked(streamID, typeURL)
	t.applyUnsubscribedResourcesLocked(streamID, typeURL, req.GetResourceNamesUnsubscribe())
	if req.GetResponseNonce() == "" {
		t.recordInitialAcceptedResourcesLocked(streamID, typeURL, req)
		t.acceptInitialVersionsLocked(streamID, node, typeURL, req.GetInitialResourceVersions())
		if len(req.GetResourceNamesUnsubscribe()) > 0 {
			t.reconcileTypeAcceptedConvergenceLocked(streamID, node, typeURL)
		}
		return
	}
	t.forgetInitialFingerprintLocked(streamID, typeURL)
	byType := t.pending[streamID]
	if byType == nil {
		return
	}
	byNonce := byType[typeURL]
	pending, ok := byNonce[req.GetResponseNonce()]
	if !ok {
		return
	}
	delete(byNonce, req.GetResponseNonce())
	if len(byNonce) == 0 {
		delete(byType, typeURL)
	}
	if len(byType) == 0 {
		delete(t.pending, streamID)
	}

	if req.GetErrorDetail() != nil {
		detail := req.GetErrorDetail().GetMessage()
		t.nacks[streamID] = NACK{
			Version: pending.version,
			TypeURL: typeURL,
			Detail:  detail,
		}
		if byAckType := t.acked[streamID]; byAckType != nil {
			delete(byAckType, typeURL)
		}
		t.recordRejectedResourcesLocked(streamID, typeURL, pending.updated, detail)
		return
	}

	t.applyAcceptedResourcesLocked(streamID, typeURL, pending.updated, pending.removed)

	expected, hasExpected := t.expected[pending.node]
	currentFingerprint := t.fingerprints[pending.node][typeURL]
	expectedRes, trackByResource := t.expectedResources[pending.node][typeURL]
	var convergedType bool
	if trackByResource {
		convergedType = hasExpected && currentFingerprint != "" &&
			!t.hasRejectedResourceInTypeLocked(streamID, typeURL, expectedRes) &&
			sameStringMap(t.acceptedResources[streamID][typeURL], expectedRes)
	} else {
		convergedType = hasExpected && pending.fingerprint != "" && pending.fingerprint == currentFingerprint
	}
	if convergedType {
		byAckType := t.acked[streamID]
		if byAckType == nil {
			byAckType = make(map[string]streamAck)
			t.acked[streamID] = byAckType
		}
		byAckType[typeURL] = streamAck{
			version:     expected.version,
			fingerprint: currentFingerprint,
		}
	} else if trackByResource {
		if byAckType := t.acked[streamID]; byAckType != nil {
			delete(byAckType, typeURL)
		}
	}
	if nack, ok := t.nacks[streamID]; ok && nack.TypeURL == typeURL &&
		(nack.Version == pending.version || (convergedType && nack.Version == expected.version)) {
		delete(t.nacks, streamID)
	}
}

func (t *AckTracker) recordVersionFingerprintsLocked(node, version string, current map[string]string) {
	if node == "" || version == "" {
		return
	}
	byVersion := t.versionFingerprints[node]
	if byVersion == nil {
		byVersion = make(map[string]map[string]string)
		t.versionFingerprints[node] = byVersion
	}
	if _, exists := byVersion[version]; exists {
		order := t.versionOrder[node]
		for i, existing := range order {
			if existing == version {
				order = append(order[:i], order[i+1:]...)
				break
			}
		}
		t.versionOrder[node] = append(order, version)
	} else {
		t.versionOrder[node] = append(t.versionOrder[node], version)
		if len(t.versionOrder[node]) > maxTrackedVersionsPerNode {
			oldest := t.versionOrder[node][0]
			t.versionOrder[node] = t.versionOrder[node][1:]
			delete(byVersion, oldest)
		}
	}
	copied := make(map[string]string, len(current))
	for k, v := range current {
		copied[k] = v
	}
	byVersion[version] = copied
}

// acceptInitialVersionsLocked recognizes a reconnected Delta client that
// reports it already holds the exact current resource versions. The snapshot
// cache can emit no response for unchanged named subscriptions, so initial
// versions may be the only protocol evidence available for convergence.
func (t *AckTracker) acceptInitialVersionsLocked(streamID int64, node, typeURL string, versions map[string]string) {
	if node == "" || typeURL == "" || len(versions) == 0 {
		return
	}
	fingerprint, err := fingerprintVersionMap(versions)
	if err != nil || fingerprint == "" {
		return
	}
	if _, ok := t.expected[node]; !ok {
		byType := t.initialFingerprints[streamID]
		if byType == nil {
			byType = make(map[string]string)
			t.initialFingerprints[streamID] = byType
		}
		byType[typeURL] = fingerprint
		return
	}
	t.acceptInitialFingerprintLocked(streamID, node, typeURL, fingerprint)
}

func (t *AckTracker) acceptInitialFingerprintLocked(streamID int64, node, typeURL, fingerprint string) {
	expected, ok := t.expected[node]
	if !ok || fingerprint != t.fingerprints[node][typeURL] {
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

func (t *AckTracker) forgetInitialFingerprintLocked(streamID int64, typeURL string) {
	byType := t.initialFingerprints[streamID]
	delete(byType, typeURL)
	if len(byType) == 0 {
		delete(t.initialFingerprints, streamID)
	}
}

// OnStreamClosed forgets nonce correlation, subscription, and convergence
// state for a disconnected stream, returning the cluster node key associated
// with the stream before removal. The stream's ACK and NACK records die with
// it so a replacement stream starts unproven and cannot inherit them.
func (t *AckTracker) OnStreamClosed(streamID int64) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.nodes[streamID]
	delete(t.pending, streamID)
	delete(t.nodes, streamID)
	delete(t.nodeIDs, streamID)
	delete(t.subscriptions, streamID)
	delete(t.acked, streamID)
	delete(t.acceptedResources, streamID)
	delete(t.rejectedResources, streamID)
	delete(t.nacks, streamID)
	delete(t.initialFingerprints, streamID)
	delete(t.initialResourceMismatch, streamID)
	delete(t.unconfirmedInitialResources, streamID)
	return node
}

func (t *AckTracker) recordStreamIdentityLocked(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) string {
	node := req.GetNode().GetCluster()
	if node != "" {
		t.nodes[streamID] = node
	} else {
		node = t.nodes[streamID]
	}
	if nodeID := req.GetNode().GetId(); nodeID != "" && t.nodeIDs[streamID] == "" {
		t.nodeIDs[streamID] = nodeID
	}
	return node
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
	delete(t.expectedResources, node)
	delete(t.versionFingerprints, node)
	delete(t.versionOrder, node)
	for streamID, streamNode := range t.nodes {
		if streamNode == node {
			delete(t.acked, streamID)
			delete(t.acceptedResources, streamID)
			delete(t.rejectedResources, streamID)
			delete(t.nacks, streamID)
			delete(t.initialFingerprints, streamID)
			delete(t.initialResourceMismatch, streamID)
			delete(t.unconfirmedInitialResources, streamID)
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
		if !t.streamConvergedLocked(node, streamID, expected, present) {
			return false
		}
	}
	return true
}

// IsACKedForNodes reports whether every expected Envoy node.id has at least one
// live stream on node and every live stream for those node IDs has ACKed the
// current snapshot fingerprints. Streams belonging to node IDs outside nodeIDs
// (such as terminating Pods) are excluded, while empty entries in nodeIDs or an
// empty slice for a non-empty snapshot never converge.
func (t *AckTracker) IsACKedForNodes(node, version string, nodeIDs []string) bool {
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
	if len(nodeIDs) == 0 {
		return false
	}
	byNodeID := t.nodeStreamsLocked(node)
	for _, wantNodeID := range nodeIDs {
		if wantNodeID == "" {
			return false
		}
		streams := byNodeID[wantNodeID]
		if len(streams) == 0 {
			return false
		}
		for _, streamID := range streams {
			if !t.streamConvergedLocked(node, streamID, expected, present) {
				return false
			}
		}
	}
	return true
}

func (t *AckTracker) streamConvergedLocked(node string, streamID int64, expected expectedSnapshot, present map[string]string) bool {
	if nack, ok := t.nacks[streamID]; ok && nack.Version == expected.version {
		return false
	}
	if _, rejected := t.firstActiveRejectionLocked(node, streamID); rejected {
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
	return true
}

func (t *AckTracker) nodeStreamsLocked(node string) map[string][]int64 {
	byNodeID := make(map[string][]int64)
	for streamID, streamNode := range t.nodes {
		if streamNode != node {
			continue
		}
		nodeID := t.nodeIDs[streamID]
		if nodeID == "" {
			continue
		}
		byNodeID[nodeID] = append(byNodeID[nodeID], streamID)
	}
	for nodeID := range byNodeID {
		sort.Slice(byNodeID[nodeID], func(i, j int) bool { return byNodeID[nodeID][i] < byNodeID[nodeID][j] })
	}
	return byNodeID
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
	if nackDetail := t.firstNACKDetailLocked(node, streams, version); nackDetail != "" {
		return nackDetail
	}
	missing := t.missingTypesLocked(expected, present, streams)
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

// ConvergenceDetailsForNodes explains why the expected Envoy pods have not
// converged without exposing stream or Pod UIDs.
func (t *AckTracker) ConvergenceDetailsForNodes(node, version string, nodeIDs []string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	expected, ok := t.expected[node]
	if !ok {
		return "snapshot is not registered"
	}
	if expected.version != version {
		return fmt.Sprintf("expected version %s, requested %s", shortVersion(expected.version), shortVersion(version))
	}
	present := t.fingerprints[node]
	if len(present) == 0 {
		return ""
	}
	if len(nodeIDs) == 0 {
		return "no active dataplane Pods"
	}
	wantIDs, missingUIDCount := uniqueNodeIDs(nodeIDs)
	totalWant := len(wantIDs) + missingUIDCount
	if len(wantIDs) == 0 {
		return fmt.Sprintf("no live xDS stream (%d dataplane Pod(s) missing node identity)", totalWant)
	}
	byNodeID := t.nodeStreamsLocked(node)
	connectedNodes := 0
	var streams []int64
	for _, wantNodeID := range wantIDs {
		nodeStreams := byNodeID[wantNodeID]
		if len(nodeStreams) == 0 {
			continue
		}
		connectedNodes++
		streams = append(streams, nodeStreams...)
	}
	if connectedNodes == 0 {
		return fmt.Sprintf("no live xDS stream (%d dataplane Pod(s) unconnected)", totalWant)
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i] < streams[j] })
	if nackDetail := t.firstNACKDetailLocked(node, streams, version); nackDetail != "" {
		return nackDetail
	}
	missing := t.missingTypesLocked(expected, present, streams)
	if len(missing) > 0 {
		if connectedNodes < totalWant {
			return fmt.Sprintf(
				"want %s, %d/%d dataplane Pod(s) connected, missing %s",
				shortVersion(version),
				connectedNodes,
				totalWant,
				strings.Join(missing, ","),
			)
		}
		return fmt.Sprintf(
			"want %s, %d/%d dataplane Pod(s) connected (%d live stream(s)), missing %s",
			shortVersion(version),
			connectedNodes,
			totalWant,
			len(streams),
			strings.Join(missing, ","),
		)
	}
	if missingUIDCount > 0 {
		return fmt.Sprintf("want %s, %d/%d dataplane Pod(s) connected (missing node identity)", shortVersion(version), connectedNodes, totalWant)
	}
	if connectedNodes < totalWant {
		return fmt.Sprintf("want %s, %d/%d dataplane Pod(s) connected", shortVersion(version), connectedNodes, totalWant)
	}
	return ""
}

func (t *AckTracker) firstNACKDetailLocked(node string, streams []int64, version string) string {
	for _, streamID := range streams {
		if nack, found := t.nacks[streamID]; found && nack.Version == version {
			return fmt.Sprintf("NACK %s: %s", shortTypeURL(nack.TypeURL), nack.Detail)
		}
		if nack, found := t.firstActiveRejectionLocked(node, streamID); found {
			return fmt.Sprintf("NACK %s: %s", shortTypeURL(nack.TypeURL), nack.Detail)
		}
	}
	return ""
}

func (t *AckTracker) missingTypesLocked(expected expectedSnapshot, present map[string]string, streams []int64) []string {
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
	return missing
}

func uniqueNodeIDs(nodeIDs []string) ([]string, int) {
	seen := make(map[string]struct{}, len(nodeIDs))
	unique := make([]string, 0, len(nodeIDs))
	missingUIDCount := 0
	for _, nodeID := range nodeIDs {
		if nodeID == "" {
			missingUIDCount++
			continue
		}
		if _, ok := seen[nodeID]; ok {
			continue
		}
		seen[nodeID] = struct{}{}
		unique = append(unique, nodeID)
	}
	sort.Strings(unique)
	return unique, missingUIDCount
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
		if nack, found := t.firstActiveRejectionLocked(node, streamID); found {
			nack.Version = expected.version
			return nack, true
		}
	}
	return NACK{}, false
}

func (t *AckTracker) recordInitialAcceptedResourcesLocked(streamID int64, typeURL string, req *discoveryv3.DeltaDiscoveryRequest) {
	versions := req.GetInitialResourceVersions()
	if typeURL == "" || len(versions) == 0 {
		return
	}
	if len(t.pending[streamID][typeURL]) > 0 {
		return
	}
	byType := t.acceptedResources[streamID]
	if byType != nil && byType[typeURL] != nil {
		return
	}
	if byType == nil {
		byType = make(map[string]map[string]string)
		t.acceptedResources[streamID] = byType
	}
	var allowed map[string]struct{}
	if subs := req.GetResourceNamesSubscribe(); len(subs) > 0 {
		wildcard := false
		for _, name := range subs {
			if name == "*" {
				wildcard = true
				break
			}
		}
		if !wildcard {
			allowed = make(map[string]struct{}, len(subs))
			for _, name := range subs {
				allowed[name] = struct{}{}
			}
		}
	}
	var unsubscribed map[string]struct{}
	if unsubs := req.GetResourceNamesUnsubscribe(); len(unsubs) > 0 {
		unsubscribed = make(map[string]struct{}, len(unsubs))
		for _, name := range unsubs {
			if name != "*" {
				unsubscribed[name] = struct{}{}
			}
		}
	}
	cloned := make(map[string]string, len(versions))
	for name, ver := range versions {
		if _, dropped := unsubscribed[name]; dropped {
			continue
		}
		if allowed != nil {
			if _, ok := allowed[name]; !ok {
				continue
			}
		}
		cloned[name] = ver
	}
	byType[typeURL] = cloned
	if unconfirmed := t.unconfirmedInitialResources[streamID]; unconfirmed == nil {
		t.unconfirmedInitialResources[streamID] = map[string]struct{}{typeURL: {}}
	} else {
		unconfirmed[typeURL] = struct{}{}
	}
	if node := t.nodes[streamID]; node != "" {
		if expectedRes, ok := t.expectedResources[node][typeURL]; ok && !sameStringMap(cloned, expectedRes) {
			t.markInitialResourceMismatchLocked(streamID, typeURL)
		}
	}
}

func (t *AckTracker) markInitialResourceMismatchLocked(streamID int64, typeURL string) {
	byType := t.initialResourceMismatch[streamID]
	if byType == nil {
		byType = make(map[string]struct{})
		t.initialResourceMismatch[streamID] = byType
	}
	byType[typeURL] = struct{}{}
}

func (t *AckTracker) clearInitialResourceMismatchLocked(streamID int64, typeURL string) {
	if unconfirmed := t.unconfirmedInitialResources[streamID]; unconfirmed != nil {
		delete(unconfirmed, typeURL)
		if len(unconfirmed) == 0 {
			delete(t.unconfirmedInitialResources, streamID)
		}
	}
	byType := t.initialResourceMismatch[streamID]
	if byType == nil {
		return
	}
	delete(byType, typeURL)
	if len(byType) == 0 {
		delete(t.initialResourceMismatch, streamID)
	}
}

func (t *AckTracker) hasInitialResourceMismatchLocked(streamID int64, typeURL string) bool {
	_, mismatched := t.initialResourceMismatch[streamID][typeURL]
	return mismatched
}

func (t *AckTracker) applyUnsubscribedResourcesLocked(streamID int64, typeURL string, unsubscribed []string) {
	if typeURL == "" || len(unsubscribed) == 0 {
		return
	}
	byType := t.acceptedResources[streamID]
	if byType == nil {
		return
	}
	accepted := byType[typeURL]
	if accepted == nil {
		return
	}
	for _, name := range unsubscribed {
		if name != "*" {
			delete(accepted, name)
		}
	}
}

func (t *AckTracker) reconcileAcceptedConvergenceLocked(streamID int64, version string, fingerprints map[string]string, expectedResources map[string]map[string]string) {
	if len(expectedResources) == 0 {
		return
	}
	for typeURL := range expectedResources {
		t.reconcileTypeWithExpectedLocked(streamID, version, typeURL, fingerprints[typeURL], expectedResources[typeURL])
	}
}

func (t *AckTracker) reconcileTypeAcceptedConvergenceLocked(streamID int64, node, typeURL string) {
	if node == "" || typeURL == "" {
		return
	}
	expected, ok := t.expected[node]
	if !ok {
		return
	}
	expectedRes, ok := t.expectedResources[node][typeURL]
	if !ok {
		return
	}
	t.reconcileTypeWithExpectedLocked(streamID, expected.version, typeURL, t.fingerprints[node][typeURL], expectedRes)
}

func (t *AckTracker) reconcileTypeWithExpectedLocked(streamID int64, version, typeURL, currentFingerprint string, expectedRes map[string]string) {
	if currentFingerprint == "" || len(t.pending[streamID][typeURL]) > 0 || t.hasRejectedResourceInTypeLocked(streamID, typeURL, expectedRes) {
		return
	}
	if t.hasInitialResourceMismatchLocked(streamID, typeURL) {
		return
	}
	if !sameStringMap(t.acceptedResources[streamID][typeURL], expectedRes) {
		if _, unconfirmed := t.unconfirmedInitialResources[streamID][typeURL]; unconfirmed {
			t.markInitialResourceMismatchLocked(streamID, typeURL)
		}
		return
	}
	if nack, ok := t.nacks[streamID]; ok && nack.Version == version && nack.TypeURL == typeURL {
		return
	}
	byAckType := t.acked[streamID]
	if byAckType == nil {
		byAckType = make(map[string]streamAck)
		t.acked[streamID] = byAckType
	}
	byAckType[typeURL] = streamAck{
		version:     version,
		fingerprint: currentFingerprint,
	}
	t.clearInitialResourceMismatchLocked(streamID, typeURL)
}

func (t *AckTracker) applyAcceptedResourcesLocked(streamID int64, typeURL string, updated map[string]string, removed []string) {
	if typeURL == "" || (len(updated) == 0 && len(removed) == 0) {
		return
	}
	byType := t.acceptedResources[streamID]
	if byType == nil {
		byType = make(map[string]map[string]string)
		t.acceptedResources[streamID] = byType
	}
	accepted := byType[typeURL]
	if accepted == nil {
		accepted = make(map[string]string, len(updated))
		byType[typeURL] = accepted
	}
	rejByType := t.rejectedResources[streamID]
	var rejected map[string]rejectedResource
	if rejByType != nil {
		rejected = rejByType[typeURL]
	}
	for name, ver := range updated {
		accepted[name] = ver
		if rejected != nil {
			delete(rejected, name)
		}
	}
	t.clearInitialResourceMismatchLocked(streamID, typeURL)
	for _, name := range removed {
		delete(accepted, name)
		if rejected != nil {
			delete(rejected, name)
		}
	}
	if rejected != nil && len(rejected) == 0 {
		delete(rejByType, typeURL)
		if len(rejByType) == 0 {
			delete(t.rejectedResources, streamID)
		}
	}
}

func (t *AckTracker) recordRejectedResourcesLocked(streamID int64, typeURL string, updated map[string]string, detail string) {
	if typeURL == "" || len(updated) == 0 {
		return
	}
	if byType := t.acceptedResources[streamID]; byType != nil {
		if accepted := byType[typeURL]; accepted != nil {
			for name := range updated {
				delete(accepted, name)
			}
		}
	}
	rejByType := t.rejectedResources[streamID]
	if rejByType == nil {
		rejByType = make(map[string]map[string]rejectedResource)
		t.rejectedResources[streamID] = rejByType
	}
	rejected := rejByType[typeURL]
	if rejected == nil {
		rejected = make(map[string]rejectedResource, len(updated))
		rejByType[typeURL] = rejected
	}
	for name, ver := range updated {
		rejected[name] = rejectedResource{version: ver, detail: detail}
	}
}

func (t *AckTracker) pruneRejectedResourcesLocked(streamID int64, expected map[string]map[string]string) {
	rejByType := t.rejectedResources[streamID]
	if len(rejByType) == 0 {
		return
	}
	for typeURL, byName := range rejByType {
		want := expected[typeURL]
		if len(want) == 0 {
			delete(rejByType, typeURL)
			continue
		}
		for name, rej := range byName {
			if wantVer, ok := want[name]; !ok || wantVer != rej.version {
				delete(byName, name)
			}
		}
		if len(byName) == 0 {
			delete(rejByType, typeURL)
		}
	}
	if len(rejByType) == 0 {
		delete(t.rejectedResources, streamID)
	}
}

func (t *AckTracker) hasRejectedResourceInTypeLocked(streamID int64, typeURL string, expected map[string]string) bool {
	byType := t.rejectedResources[streamID]
	if byType == nil {
		return false
	}
	rejected := byType[typeURL]
	for name, rej := range rejected {
		if wantVer, ok := expected[name]; ok && wantVer == rej.version {
			return true
		}
	}
	return false
}

func (t *AckTracker) firstActiveRejectionLocked(node string, streamID int64) (NACK, bool) {
	byType := t.rejectedResources[streamID]
	if len(byType) == 0 {
		return NACK{}, false
	}
	expected := t.expectedResources[node]
	if len(expected) == 0 {
		return NACK{}, false
	}
	typeURLs := make([]string, 0, len(byType))
	for typeURL := range byType {
		typeURLs = append(typeURLs, typeURL)
	}
	sort.Strings(typeURLs)
	for _, typeURL := range typeURLs {
		want := expected[typeURL]
		if len(want) == 0 {
			continue
		}
		byName := byType[typeURL]
		names := make([]string, 0, len(byName))
		for name := range byName {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rej := byName[name]
			if wantVer, ok := want[name]; ok && wantVer == rej.version {
				return NACK{
					TypeURL: typeURL,
					Detail:  rej.detail,
				}, true
			}
		}
	}
	return NACK{}, false
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for k, v := range left {
		if rv, ok := right[k]; !ok || rv != v {
			return false
		}
	}
	return true
}

func sameNestedStringMaps(left, right map[string]map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for typeURL, lm := range left {
		rm, ok := right[typeURL]
		if !ok || !sameStringMap(lm, rm) {
			return false
		}
	}
	return true
}
