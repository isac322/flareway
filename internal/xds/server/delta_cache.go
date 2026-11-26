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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/isac322/flareway/internal/xds/translator"
)

type orderedSnapshot struct {
	snapshot            cachev3.ResourceSnapshot
	clusterVersions     map[string]string
	rawEndpointVersions map[string]string
	targetEndpointVer   map[string]string
	typeFingerprints    map[string]string
}

type openDeltaWatch struct {
	id      int64
	request *cachev3.DeltaRequest
	sub     cachev3.Subscription
}

type provisionalEndpointRecord struct {
	version string
	target  string
}

type inFlightDeltaBatch struct {
	resources map[string]string
	removed   map[string]struct{}
}

type rejectedDeltaBatch struct {
	members map[string]string
}

type typeRejectionState struct {
	pending map[string]inFlightDeltaBatch
	batches []*rejectedDeltaBatch
	replay  map[string]struct{}
}

func newTypeRejectionState() *typeRejectionState {
	return &typeRejectionState{
		pending: make(map[string]inFlightDeltaBatch),
		replay:  make(map[string]struct{}),
	}
}

func (rs *typeRejectionState) rejectedVersion(name string) (string, bool) {
	for _, batch := range rs.batches {
		if ver, ok := batch.members[name]; ok {
			return ver, true
		}
	}
	return "", false
}

func (rs *typeRejectionState) recordNACK(sent map[string]string) {
	if len(sent) == 0 {
		return
	}
	merged := maps.Clone(sent)
	kept := make([]*rejectedDeltaBatch, 0, len(rs.batches)+1)
	for _, batch := range rs.batches {
		overlaps := false
		for name := range sent {
			if _, ok := batch.members[name]; ok {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, batch)
			continue
		}
		for name, ver := range batch.members {
			if _, replaced := sent[name]; !replaced {
				merged[name] = ver
			}
		}
	}
	kept = append(kept, &rejectedDeltaBatch{members: merged})
	rs.batches = kept
	for name := range sent {
		delete(rs.replay, name)
	}
}

func (rs *typeRejectionState) recordACK(sent inFlightDeltaBatch) {
	kept := make([]*rejectedDeltaBatch, 0, len(rs.batches))
	for _, batch := range rs.batches {
		touched := false
		for name := range sent.resources {
			if _, ok := batch.members[name]; ok {
				delete(batch.members, name)
				touched = true
			}
		}
		for name := range sent.removed {
			if _, ok := batch.members[name]; ok {
				delete(batch.members, name)
				touched = true
			}
		}
		if !touched {
			kept = append(kept, batch)
			continue
		}
		for name := range batch.members {
			rs.replay[name] = struct{}{}
		}
	}
	rs.batches = kept
}

func (rs *typeRejectionState) handleUnsubscribe(names []string) {
	if len(names) == 0 {
		return
	}
	removedSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		removedSet[name] = struct{}{}
		delete(rs.replay, name)
	}
	if len(removedSet) == 0 {
		return
	}
	kept := make([]*rejectedDeltaBatch, 0, len(rs.batches))
	for _, batch := range rs.batches {
		touched := false
		for name := range removedSet {
			if _, ok := batch.members[name]; ok {
				delete(batch.members, name)
				touched = true
			}
		}
		if !touched {
			kept = append(kept, batch)
			continue
		}
		for name := range batch.members {
			rs.replay[name] = struct{}{}
		}
	}
	rs.batches = kept
}

func (rs *typeRejectionState) prune(resources map[string]cachetypes.Resource, isWildcard bool, subscribed map[string]struct{}, pendingRemoval map[string]struct{}) {
	inScope := func(name string) bool {
		if _, ok := resources[name]; !ok {
			return false
		}
		if !isWildcard {
			_, ok := subscribed[name]
			return ok
		}
		return true
	}
	for name := range rs.replay {
		if !inScope(name) {
			delete(rs.replay, name)
		}
	}
	kept := make([]*rejectedDeltaBatch, 0, len(rs.batches))
	for _, batch := range rs.batches {
		touched := false
		for name := range batch.members {
			if _, removing := pendingRemoval[name]; removing {
				continue
			}
			if !inScope(name) {
				delete(batch.members, name)
				touched = true
			}
		}
		if len(batch.members) == 0 {
			continue
		}
		if touched {
			for name := range batch.members {
				rs.replay[name] = struct{}{}
			}
			continue
		}
		kept = append(kept, batch)
	}
	rs.batches = kept
}

type deltaStreamState struct {
	node                     string
	streamID                 int64
	streamSeq                int64
	value                    chan cachev3.DeltaResponse
	watches                  map[string]openDeltaWatch
	sentClusterVersions      map[string]string
	sentProvisionalEndpoints map[string]provisionalEndpointRecord
	typeRejections           map[string]*typeRejectionState
	cdsSeen                  bool
}

func (st *deltaStreamState) rejectionState(typeURL string) *typeRejectionState {
	rs := st.typeRejections[typeURL]
	if rs == nil {
		rs = newTypeRejectionState()
		st.typeRejections[typeURL] = rs
	}
	return rs
}

type deltaCachedResource struct {
	name     string
	version  string
	resource cachetypes.Resource
}

type orderedDeltaResponse struct {
	request           *discoveryv3.DeltaDiscoveryRequest
	systemVersionInfo string
	originFingerprint string
	onMarshal         func(*discoveryv3.DeltaDiscoveryResponse, string)
	resources         []deltaCachedResource
	removed           []string
	returnedResources map[string]string
	ctx               context.Context
	marshaled         atomic.Pointer[discoveryv3.DeltaDiscoveryResponse]
}

var _ cachev3.DeltaResponse = (*orderedDeltaResponse)(nil)

func (r *orderedDeltaResponse) GetDeltaDiscoveryResponse() (*discoveryv3.DeltaDiscoveryResponse, error) {
	if cached := r.marshaled.Load(); cached != nil {
		return cached, nil
	}
	typeURL := r.request.GetTypeUrl()
	items := make([]*discoveryv3.Resource, 0, len(r.resources))
	for _, item := range r.resources {
		raw, err := cachev3.MarshalResource(item.resource)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", item.name, err)
		}
		items = append(items, &discoveryv3.Resource{
			Name: item.name,
			Resource: &anypb.Any{
				TypeUrl: typeURL,
				Value:   raw,
			},
			Version: item.version,
		})
	}
	resp := &discoveryv3.DeltaDiscoveryResponse{
		Resources:         items,
		RemovedResources:  r.removed,
		TypeUrl:           typeURL,
		SystemVersionInfo: r.systemVersionInfo,
	}
	if r.onMarshal != nil {
		r.onMarshal(resp, r.originFingerprint)
	}
	r.marshaled.Store(resp)
	return resp, nil
}

func (r *orderedDeltaResponse) GetDeltaRequest() *discoveryv3.DeltaDiscoveryRequest {
	return r.request
}

func (r *orderedDeltaResponse) GetSystemVersion() (string, error) {
	return r.systemVersionInfo, nil
}

func (r *orderedDeltaResponse) GetResponseVersion() string {
	return r.systemVersionInfo
}

func (r *orderedDeltaResponse) GetNextVersionMap() map[string]string {
	return r.returnedResources
}

func (r *orderedDeltaResponse) GetReturnedResources() map[string]string {
	return r.returnedResources
}

func (r *orderedDeltaResponse) GetContext() context.Context {
	return r.ctx
}

// orderedDeltaCache wraps go-control-plane's SnapshotCache to enforce
// per-stream CDS-before-EDS ordering on Delta ADS streams. Updating an existing
// Cluster's version never pushes its rebound EDS version ahead of that
// Cluster's CDS update, while new/warming Clusters from earlier CDS responses
// still receive their EDS assignments immediately so warming cannot deadlock.
type orderedDeltaCache struct {
	base          cachev3.SnapshotCache
	hash          cachev3.NodeHash
	instanceNonce string

	nextWatchID   atomic.Int64
	nextStreamSeq atomic.Int64

	mu               sync.Mutex
	snapshots        map[string]*orderedSnapshot
	streams          map[chan cachev3.DeltaResponse]*deltaStreamState
	streamByID       map[int64]*deltaStreamState
	pendingReqStream map[*discoveryv3.DeltaDiscoveryRequest]int64

	fpMu             sync.Mutex
	sentFingerprints map[*discoveryv3.DeltaDiscoveryResponse]string
}

var _ cachev3.SnapshotCache = (*orderedDeltaCache)(nil)

func newInstanceNonce() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return hex.EncodeToString(buf[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

func newOrderedDeltaCache(base cachev3.SnapshotCache, hash cachev3.NodeHash) *orderedDeltaCache {
	return &orderedDeltaCache{
		base:             base,
		hash:             hash,
		instanceNonce:    newInstanceNonce(),
		snapshots:        make(map[string]*orderedSnapshot),
		streams:          make(map[chan cachev3.DeltaResponse]*deltaStreamState),
		streamByID:       make(map[int64]*deltaStreamState),
		pendingReqStream: make(map[*discoveryv3.DeltaDiscoveryRequest]int64),
		sentFingerprints: make(map[*discoveryv3.DeltaDiscoveryResponse]string),
	}
}

func (c *orderedDeltaCache) recordSentFingerprint(resp *discoveryv3.DeltaDiscoveryResponse, fingerprint string) {
	if resp == nil {
		return
	}
	c.fpMu.Lock()
	c.sentFingerprints[resp] = fingerprint
	c.fpMu.Unlock()
}

// ConsumeResponseFingerprint returns and removes the originating type
// fingerprint captured when the cache materialized resp, avoiding loss even if
// many snapshots publish while the response is buffered before transmission.
func (c *orderedDeltaCache) ConsumeResponseFingerprint(resp *discoveryv3.DeltaDiscoveryResponse) (string, bool) {
	if resp == nil {
		return "", false
	}
	c.fpMu.Lock()
	fp, ok := c.sentFingerprints[resp]
	if ok {
		delete(c.sentFingerprints, resp)
	}
	c.fpMu.Unlock()
	return fp, ok
}

func (c *orderedDeltaCache) BindRequestStream(req *discoveryv3.DeltaDiscoveryRequest, streamID int64) {
	if req == nil || streamID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingReqStream[req] = streamID
}

// OnResponse records delivered Delta resources and removals by nonce for any
// type so an eventual NACK isolates the rejected batch while keeping siblings
// eligible for replay once a batch correction or removal is ACKed.
func (c *orderedDeltaCache) OnResponse(streamID int64, _ *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
	if streamID == 0 || resp == nil || resp.GetNonce() == "" || resp.GetTypeUrl() == "" {
		return
	}
	resources := resp.GetResources()
	removedList := resp.GetRemovedResources()
	if len(resources) == 0 && len(removedList) == 0 {
		return
	}
	sent := make(map[string]string, len(resources))
	for _, res := range resources {
		if res.GetName() != "" {
			sent[res.GetName()] = res.GetVersion()
		}
	}
	removed := make(map[string]struct{}, len(removedList))
	for _, name := range removedList {
		if name != "" {
			removed[name] = struct{}{}
		}
	}
	if len(sent) == 0 && len(removed) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.streamByID[streamID]; ok {
		st.rejectionState(resp.GetTypeUrl()).pending[resp.GetNonce()] = inFlightDeltaBatch{
			resources: sent,
			removed:   removed,
		}
	}
}

// OnRequest reconciles per-type Delta batch rejection state on ACK, NACK, or
// explicit resource unsubscription.
func (c *orderedDeltaCache) OnRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) {
	if streamID == 0 || req == nil || req.GetTypeUrl() == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.streamByID[streamID]
	if !ok {
		return
	}
	rs := st.typeRejections[req.GetTypeUrl()]
	if rs == nil {
		return
	}
	if req.GetErrorDetail() == nil && len(req.GetResourceNamesUnsubscribe()) > 0 {
		rs.handleUnsubscribe(req.GetResourceNamesUnsubscribe())
	}
	nonce := req.GetResponseNonce()
	if nonce == "" {
		return
	}
	sent, ok := rs.pending[nonce]
	if !ok {
		return
	}
	delete(rs.pending, nonce)
	if req.GetErrorDetail() != nil {
		rs.recordNACK(sent.resources)
		return
	}
	rs.recordACK(sent)
}

func (c *orderedDeltaCache) OnStreamClosed(streamID int64) {
	if streamID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for req, id := range c.pendingReqStream {
		if id == streamID {
			delete(c.pendingReqStream, req)
		}
	}
	st, ok := c.streamByID[streamID]
	if !ok {
		return
	}
	delete(c.streamByID, streamID)
	delete(c.streams, st.value)
	clear(st.watches)
}

func (c *orderedDeltaCache) CreateWatch(req *cachev3.Request, sub cachev3.Subscription, value chan cachev3.Response) (func(), error) {
	return c.base.CreateWatch(req, sub, value)
}

func (c *orderedDeltaCache) Fetch(ctx context.Context, req *cachev3.Request) (cachev3.Response, error) {
	return c.base.Fetch(ctx, req)
}

func (c *orderedDeltaCache) GetSnapshot(node string) (cachev3.ResourceSnapshot, error) {
	return c.base.GetSnapshot(node)
}

func (c *orderedDeltaCache) GetStatusInfo(node string) cachev3.StatusInfo {
	return c.base.GetStatusInfo(node)
}

func (c *orderedDeltaCache) GetStatusKeys() []string {
	return c.base.GetStatusKeys()
}

func (c *orderedDeltaCache) ClearSnapshot(node string) {
	c.base.ClearSnapshot(node)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.snapshots, node)
}

func (c *orderedDeltaCache) SetSnapshot(ctx context.Context, node string, snapshot cachev3.ResourceSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("nil snapshot for node %s", node)
	}
	if err := snapshot.ConstructVersionMap(); err != nil {
		return fmt.Errorf("construct Delta version map: %w", err)
	}
	osnap, err := buildOrderedSnapshot(snapshot)
	if err != nil {
		return err
	}
	if err := c.base.SetSnapshot(ctx, node, snapshot); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshots[node] = osnap

	// Collect matching streams deterministically so ADS evaluation runs in strict
	// resource type order per stream: Cluster -> Endpoint -> Listener -> Route -> Secret.
	var matching []*deltaStreamState
	for _, st := range c.streams {
		if st.node == node {
			matching = append(matching, st)
		}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].streamID < matching[j].streamID })

	for _, st := range matching {
		if len(st.watches) == 0 {
			continue
		}
		typeURLs := make([]string, 0, len(st.watches))
		for typeURL := range st.watches {
			typeURLs = append(typeURLs, typeURL)
		}
		sort.Slice(typeURLs, func(i, j int) bool {
			return cachev3.GetResponseType(typeURLs[i]) < cachev3.GetResponseType(typeURLs[j])
		})
		for _, typeURL := range typeURLs {
			watch, exists := st.watches[typeURL]
			if !exists {
				continue
			}
			responded, err := c.evaluateWatchLocked(ctx, st, osnap, typeURL, watch)
			if err != nil {
				return err
			}
			if responded {
				delete(st.watches, typeURL)
			}
		}
	}
	return nil
}

func (c *orderedDeltaCache) CreateDeltaWatch(request *cachev3.DeltaRequest, sub cachev3.Subscription, value chan cachev3.DeltaResponse) (func(), error) {
	nodeID := c.hash.ID(request.GetNode())
	typeURL := request.GetTypeUrl()

	c.mu.Lock()
	defer c.mu.Unlock()

	streamID := c.pendingReqStream[request]
	delete(c.pendingReqStream, request)

	st, exists := c.streams[value]
	if !exists {
		st = &deltaStreamState{
			node:                     nodeID,
			streamID:                 streamID,
			streamSeq:                c.nextStreamSeq.Add(1),
			value:                    value,
			watches:                  make(map[string]openDeltaWatch),
			sentClusterVersions:      make(map[string]string),
			sentProvisionalEndpoints: make(map[string]provisionalEndpointRecord),
			typeRejections:           make(map[string]*typeRejectionState),
		}
		c.streams[value] = st
	} else {
		if st.node == "" && nodeID != "" {
			st.node = nodeID
		}
		if st.streamID == 0 && streamID != 0 {
			st.streamID = streamID
		}
	}
	if st.streamID != 0 {
		c.streamByID[st.streamID] = st
	}

	seededClusterState := false
	if typeURL == resourcev3.ClusterType {
		st.cdsSeen = true
		if len(st.sentClusterVersions) == 0 && sub != nil && len(sub.ReturnedResources()) > 0 {
			maps.Copy(st.sentClusterVersions, sub.ReturnedResources())
			seededClusterState = true
		}
	}

	snap := c.snapshots[st.node]
	if snap != nil {
		watch := openDeltaWatch{request: request, sub: sub}
		responded, err := c.evaluateWatchLocked(context.Background(), st, snap, typeURL, watch)
		if err != nil {
			return nil, err
		}
		if typeURL == resourcev3.ClusterType && (responded || seededClusterState) {
			if edsWatch, ok := st.watches[resourcev3.EndpointType]; ok {
				edsSent, err := c.evaluateWatchLocked(context.Background(), st, snap, resourcev3.EndpointType, edsWatch)
				if err != nil {
					return nil, err
				}
				if edsSent {
					delete(st.watches, resourcev3.EndpointType)
				}
			}
		}
		if responded {
			return func() {}, nil
		}
	}

	watchID := c.nextWatchID.Add(1)
	st.watches[typeURL] = openDeltaWatch{
		id:      watchID,
		request: request,
		sub:     sub,
	}
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		cur, ok := c.streams[value]
		if !ok || cur != st {
			return
		}
		if w, ok := cur.watches[typeURL]; ok && w.id == watchID {
			delete(cur.watches, typeURL)
		}
	}, nil
}

func (c *orderedDeltaCache) evaluateWatchLocked(ctx context.Context, st *deltaStreamState, snap *orderedSnapshot, typeURL string, watch openDeltaWatch) (bool, error) {
	if typeURL == resourcev3.EndpointType {
		return c.evaluateEndpointWatchLocked(ctx, st, snap, watch)
	}
	resources := snap.snapshot.GetResources(typeURL)
	versionMap := snap.snapshot.GetVersionMap(typeURL)
	sub := watch.sub
	rs := st.rejectionState(typeURL)
	filtered, removed, nextVersionMap, removedSet := collectDeltaWatchChanges(resources, sub, rs, func(name string) (string, bool) {
		return versionMap[name], false
	})
	resp := &orderedDeltaResponse{
		request:           watch.request,
		systemVersionInfo: snap.snapshot.GetVersion(typeURL),
		originFingerprint: snap.typeFingerprints[typeURL],
		onMarshal:         c.recordSentFingerprint,
		resources:         filtered,
		removed:           removed,
		returnedResources: nextVersionMap,
		ctx:               ctx,
	}
	if !shouldSendDeltaResponse(resp, watch.request, sub) {
		rs.prune(resources, sub.IsWildcard(), sub.SubscribedResources(), removedSet)
		return false, nil
	}
	select {
	case st.value <- resp:
		rs.prune(resources, sub.IsWildcard(), sub.SubscribedResources(), removedSet)
		for _, item := range filtered {
			delete(rs.replay, item.name)
		}
		if typeURL == resourcev3.ClusterType {
			updateSentClusterVersions(st.sentClusterVersions, sub, resp.returnedResources)
		}
		return true, nil
	case <-ctx.Done():
		return false, context.Canceled
	}
}

func (c *orderedDeltaCache) evaluateEndpointWatchLocked(ctx context.Context, st *deltaStreamState, snap *orderedSnapshot, watch openDeltaWatch) (bool, error) {
	resources := snap.snapshot.GetResources(resourcev3.EndpointType)
	sub := watch.sub
	prevMap := sub.ReturnedResources()
	rs := st.rejectionState(resourcev3.EndpointType)
	filtered, removed, nextVersionMap, removedSet := collectDeltaWatchChanges(resources, sub, rs, func(name string) (string, bool) {
		return effectiveEndpointVersionForStream(c.instanceNonce, st, snap, name, prevMap)
	})

	if len(filtered) == 0 && len(removed) == 0 && (!sub.IsWildcard() || watch.request.GetResponseNonce() != "") {
		rs.prune(resources, sub.IsWildcard(), sub.SubscribedResources(), removedSet)
		return false, nil
	}

	systemVersion := ""
	originFingerprint := ""
	if sameVersionMap(nextVersionMap, snap.targetEndpointVer) {
		systemVersion = snap.snapshot.GetVersion(resourcev3.EndpointType)
		originFingerprint = snap.typeFingerprints[resourcev3.EndpointType]
	}

	resp := &orderedDeltaResponse{
		request:           watch.request,
		systemVersionInfo: systemVersion,
		originFingerprint: originFingerprint,
		onMarshal:         c.recordSentFingerprint,
		resources:         filtered,
		removed:           removed,
		returnedResources: nextVersionMap,
		ctx:               ctx,
	}
	select {
	case st.value <- resp:
		rs.prune(resources, sub.IsWildcard(), sub.SubscribedResources(), removedSet)
		for _, item := range filtered {
			delete(rs.replay, item.name)
			if targetVer := snap.targetEndpointVer[item.name]; item.version != targetVer {
				st.sentProvisionalEndpoints[item.name] = provisionalEndpointRecord{version: item.version, target: targetVer}
			} else {
				delete(st.sentProvisionalEndpoints, item.name)
			}
		}
		for _, name := range removed {
			delete(st.sentProvisionalEndpoints, name)
		}
		return true, nil
	case <-ctx.Done():
		return false, context.Canceled
	}
}

func collectDeltaWatchChanges(
	resources map[string]cachetypes.Resource,
	sub cachev3.Subscription,
	rs *typeRejectionState,
	resolveVersion func(name string) (string, bool),
) (filtered []deltaCachedResource, removed []string, nextVersionMap map[string]string, removedSet map[string]struct{}) {
	prevMap := sub.ReturnedResources()
	subscribed := sub.SubscribedResources()
	removedSet = make(map[string]struct{})
	var replays []deltaCachedResource

	consider := func(name string, res cachetypes.Resource) {
		effectiveVer, deferUpdate := resolveVersion(name)
		prevVer, found := prevMap[name]
		if deferUpdate {
			if found {
				nextVersionMap[name] = prevVer
			}
			return
		}
		nextVersionMap[name] = effectiveVer
		_, replayRequested := rs.replay[name]
		rejVer, wasRejected := rs.rejectedVersion(name)
		if wasRejected && effectiveVer == rejVer && !replayRequested {
			return
		}
		item := deltaCachedResource{name: name, version: effectiveVer, resource: res}
		if !found || prevVer != effectiveVer {
			filtered = append(filtered, item)
		} else if replayRequested {
			replays = append(replays, item)
		}
	}

	if sub.IsWildcard() {
		nextVersionMap = make(map[string]string, len(resources))
		for name, res := range resources {
			consider(name, res)
		}
		for name := range prevMap {
			if _, ok := resources[name]; !ok {
				removed = append(removed, name)
				removedSet[name] = struct{}{}
			}
		}
	} else {
		nextVersionMap = make(map[string]string, len(subscribed))
		for name := range subscribed {
			if res, ok := resources[name]; ok {
				consider(name, res)
			} else if _, found := prevMap[name]; found {
				removed = append(removed, name)
				removedSet[name] = struct{}{}
			}
		}
	}

	// Ship fresh updates or removals before queued sibling replays so a still-invalid
	// replay cannot cause a NACK on an overlapping correction.
	if len(filtered) == 0 && len(removed) == 0 {
		filtered = replays
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].name < filtered[j].name })
	sort.Strings(removed)
	return filtered, removed, nextVersionMap, removedSet
}

func provisionalEndpointVersion(instanceNonce string, streamSeq int64, targetVer string) string {
	sum := sha256.Sum256([]byte("provisional\x00" + instanceNonce + "\x00" + strconv.FormatInt(streamSeq, 10) + "\x00" + targetVer))
	return hex.EncodeToString(sum[:])
}

func effectiveEndpointVersionForStream(instanceNonce string, st *deltaStreamState, snap *orderedSnapshot, clusterName string, prevMap map[string]string) (string, bool) {
	targetVer := snap.targetEndpointVer[clusterName]
	snapCDSVer, hasSnapCDS := snap.clusterVersions[clusterName]
	if !hasSnapCDS {
		return targetVer, false
	}

	sentCDSVer, hasSentCDS := st.sentClusterVersions[clusterName]
	prevVer, hasPrev := prevMap[clusterName]

	if hasSentCDS {
		if sentCDSVer == snapCDSVer {
			return targetVer, false
		}
		// CDS for this cluster has changed in the snapshot but the stream has not
		// yet received that CDS update. Keep already-active clusters at their
		// sent CDS binding until CDS ships, while still answering warming requests
		// (!hasPrev) or endpoint-IP changes against the previously sent CDS.
		if rawVer, ok := snap.rawEndpointVersions[clusterName]; ok && targetVer == translator.BindEndpointVersion(rawVer, snapCDSVer) {
			effective := translator.BindEndpointVersion(rawVer, sentCDSVer)
			if hasPrev && prevVer == effective {
				return prevVer, true
			}
			return effective, false
		}
		if hasPrev {
			return prevVer, true
		}
		return targetVer, false
	}

	// Stream has no recorded CDS state for this cluster yet. Serve a fresh
	// provisional assignment once per stream even when prevVer matches targetVer
	// (rollback) or a prior controller instance's provisional version (restart),
	// then suppress repeats on that stream and reserve targetVer for matching CDS.
	if rec, sentOnStream := st.sentProvisionalEndpoints[clusterName]; sentOnStream && rec.target == targetVer {
		if hasPrev && prevVer == rec.version {
			return rec.version, true
		}
		return rec.version, false
	}
	prov := provisionalEndpointVersion(instanceNonce, st.streamSeq, targetVer)
	if hasPrev && prevVer == prov {
		prov = provisionalEndpointVersion(instanceNonce, st.streamSeq, targetVer+"\x00"+prevVer)
	}
	return prov, false
}

func buildOrderedSnapshot(snapshot cachev3.ResourceSnapshot) (*orderedSnapshot, error) {
	endpointResources := snapshot.GetResources(resourcev3.EndpointType)
	rawEndpoints := make(map[string]string, len(endpointResources))
	for name, res := range endpointResources {
		raw, err := cachev3.MarshalResource(res)
		if err != nil {
			return nil, fmt.Errorf("marshal Endpoint %s: %w", name, err)
		}
		rawEndpoints[name] = cachev3.HashResource(raw)
	}
	typeFingerprints := make(map[string]string, len(snapshotResourceTypes))
	for _, typeURL := range snapshotResourceTypes {
		if len(snapshot.GetResources(typeURL)) == 0 {
			continue
		}
		fp, err := fingerprintVersionMap(snapshot.GetVersionMap(string(typeURL)))
		if err != nil {
			return nil, fmt.Errorf("fingerprint %s: %w", typeURL, err)
		}
		typeFingerprints[string(typeURL)] = fp
	}
	return &orderedSnapshot{
		snapshot:            snapshot,
		clusterVersions:     maps.Clone(snapshot.GetVersionMap(resourcev3.ClusterType)),
		rawEndpointVersions: rawEndpoints,
		targetEndpointVer:   maps.Clone(snapshot.GetVersionMap(resourcev3.EndpointType)),
		typeFingerprints:    typeFingerprints,
	}, nil
}

func shouldSendDeltaResponse(resp *orderedDeltaResponse, req *discoveryv3.DeltaDiscoveryRequest, sub cachev3.Subscription) bool {
	return len(resp.resources) > 0 || len(resp.removed) > 0 || (sub.IsWildcard() && req.GetResponseNonce() == "")
}

func updateSentClusterVersions(sent map[string]string, sub cachev3.Subscription, returned map[string]string) {
	if sub.IsWildcard() {
		clear(sent)
		maps.Copy(sent, returned)
		return
	}
	for name := range sent {
		if _, ok := returned[name]; !ok {
			if _, subscribed := sub.SubscribedResources()[name]; subscribed {
				delete(sent, name)
			}
		}
	}
	maps.Copy(sent, returned)
}

func sameVersionMap(left, right map[string]string) bool {
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
