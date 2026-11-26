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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

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

type deltaStreamState struct {
	node                string
	streamID            int64
	streamSeq           int64
	value               chan cachev3.DeltaResponse
	watches             map[string]openDeltaWatch
	sentClusterVersions map[string]string
	pendingEndpoints    map[string]map[string]string
	rejectedEndpoints   map[string]string
	cdsSeen             bool
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
	base cachev3.SnapshotCache
	hash cachev3.NodeHash

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

func newOrderedDeltaCache(base cachev3.SnapshotCache, hash cachev3.NodeHash) *orderedDeltaCache {
	return &orderedDeltaCache{
		base:             base,
		hash:             hash,
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

// OnResponse records the delivered Endpoint resource versions by nonce so an
// eventual NACK can mark all assignments from that batch eligible for replay
// once a subsequent snapshot introduces a correction.
func (c *orderedDeltaCache) OnResponse(streamID int64, _ *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
	if streamID == 0 || resp == nil || resp.GetNonce() == "" || resp.GetTypeUrl() != resourcev3.EndpointType {
		return
	}
	resources := resp.GetResources()
	if len(resources) == 0 {
		return
	}
	sent := make(map[string]string, len(resources))
	for _, res := range resources {
		if res.GetName() != "" {
			sent[res.GetName()] = res.GetVersion()
		}
	}
	if len(sent) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.streamByID[streamID]; ok {
		st.pendingEndpoints[resp.GetNonce()] = sent
	}
}

// OnRequest reconciles delivered Endpoint batch state on ACK or NACK.
func (c *orderedDeltaCache) OnRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) {
	if streamID == 0 || req == nil || req.GetTypeUrl() != resourcev3.EndpointType || req.GetResponseNonce() == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.streamByID[streamID]
	if !ok {
		return
	}
	sent, ok := st.pendingEndpoints[req.GetResponseNonce()]
	if !ok {
		return
	}
	delete(st.pendingEndpoints, req.GetResponseNonce())
	if req.GetErrorDetail() != nil {
		for name, ver := range sent {
			st.rejectedEndpoints[name] = ver
		}
		return
	}
	for name := range sent {
		delete(st.rejectedEndpoints, name)
	}
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
			node:                nodeID,
			streamID:            streamID,
			streamSeq:           c.nextStreamSeq.Add(1),
			value:               value,
			watches:             make(map[string]openDeltaWatch),
			sentClusterVersions: make(map[string]string),
			pendingEndpoints:    make(map[string]map[string]string),
			rejectedEndpoints:   make(map[string]string),
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
	resp := buildGenericDeltaResponse(ctx, watch.request, watch.sub, snap, typeURL)
	resp.onMarshal = c.recordSentFingerprint
	if !shouldSendDeltaResponse(resp, watch.request, watch.sub) {
		return false, nil
	}
	select {
	case st.value <- resp:
		if typeURL == resourcev3.ClusterType {
			updateSentClusterVersions(st.sentClusterVersions, watch.sub, resp.returnedResources)
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
	subscribed := sub.SubscribedResources()
	hasCorrection := hasRejectedEndpointCorrection(st, snap, resources, sub.IsWildcard(), subscribed, prevMap)

	var (
		filtered       []deltaCachedResource
		removed        []string
		nextVersionMap map[string]string
	)

	if sub.IsWildcard() {
		nextVersionMap = make(map[string]string, len(resources))
		for name, res := range resources {
			effectiveVer, deferUpdate := effectiveEndpointVersionForStream(st, snap, name, prevMap)
			prevVer, found := prevMap[name]
			if deferUpdate {
				if found {
					nextVersionMap[name] = prevVer
				}
				continue
			}
			nextVersionMap[name] = effectiveVer
			rejVer, wasRejected := st.rejectedEndpoints[name]
			suppressRejected := wasRejected && effectiveVer == rejVer && !hasCorrection
			replayRejected := wasRejected && effectiveVer == rejVer && hasCorrection
			if !suppressRejected && (!found || prevVer != effectiveVer || replayRejected) {
				filtered = append(filtered, deltaCachedResource{name: name, version: effectiveVer, resource: res})
			}
		}
		for name := range prevMap {
			if _, ok := resources[name]; !ok {
				removed = append(removed, name)
			}
		}
	} else {
		nextVersionMap = make(map[string]string, len(subscribed))
		for name := range subscribed {
			prevVer, found := prevMap[name]
			if res, ok := resources[name]; ok {
				effectiveVer, deferUpdate := effectiveEndpointVersionForStream(st, snap, name, prevMap)
				if deferUpdate {
					if found {
						nextVersionMap[name] = prevVer
					}
					continue
				}
				nextVersionMap[name] = effectiveVer
				rejVer, wasRejected := st.rejectedEndpoints[name]
				suppressRejected := wasRejected && effectiveVer == rejVer && !hasCorrection
				replayRejected := wasRejected && effectiveVer == rejVer && hasCorrection
				if !suppressRejected && (!found || prevVer != effectiveVer || replayRejected) {
					filtered = append(filtered, deltaCachedResource{name: name, version: effectiveVer, resource: res})
				}
			} else if found {
				removed = append(removed, name)
			}
		}
	}

	if len(filtered) == 0 && len(removed) == 0 && (!sub.IsWildcard() || watch.request.GetResponseNonce() != "") {
		if hasCorrection {
			pruneGoneRejectedEndpoints(st.rejectedEndpoints, resources, sub.IsWildcard(), subscribed)
		}
		return false, nil
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].name < filtered[j].name })
	sort.Strings(removed)

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
		if hasCorrection {
			pruneGoneRejectedEndpoints(st.rejectedEndpoints, resources, sub.IsWildcard(), subscribed)
		}
		return true, nil
	case <-ctx.Done():
		return false, context.Canceled
	}
}

func hasRejectedEndpointCorrection(st *deltaStreamState, snap *orderedSnapshot, resources map[string]cachetypes.Resource, isWildcard bool, subscribed map[string]struct{}, prevMap map[string]string) bool {
	if len(st.rejectedEndpoints) == 0 {
		return false
	}
	for name, rejVer := range st.rejectedEndpoints {
		if _, ok := resources[name]; !ok {
			return true
		}
		if !isWildcard {
			if _, ok := subscribed[name]; !ok {
				return true
			}
		}
		effectiveVer, deferUpdate := effectiveEndpointVersionForStream(st, snap, name, prevMap)
		if !deferUpdate && effectiveVer != rejVer {
			return true
		}
	}
	return false
}

func pruneGoneRejectedEndpoints(rejected map[string]string, resources map[string]cachetypes.Resource, isWildcard bool, subscribed map[string]struct{}) {
	for name := range rejected {
		if _, ok := resources[name]; !ok {
			delete(rejected, name)
			continue
		}
		if !isWildcard {
			if _, ok := subscribed[name]; !ok {
				delete(rejected, name)
			}
		}
	}
}

func provisionalEndpointVersion(streamSeq int64, targetVer string) string {
	sum := sha256.Sum256([]byte("provisional\x00" + strconv.FormatInt(streamSeq, 10) + "\x00" + targetVer))
	return hex.EncodeToString(sum[:])
}

func effectiveEndpointVersionForStream(st *deltaStreamState, snap *orderedSnapshot, clusterName string, prevMap map[string]string) (string, bool) {
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

	// Stream has no recorded CDS state for this cluster yet. Only pass through
	// targetVer when the client already holds that exact final CDS-bound version;
	// otherwise issue a unique provisional version once for this stream so any
	// warming or reconnecting cluster unblocks paused CDS while reserving
	// targetVer until matching CDS arrives.
	if hasPrev && prevVer == targetVer {
		return targetVer, false
	}
	prov := provisionalEndpointVersion(st.streamSeq, targetVer)
	if hasPrev && prevVer == prov {
		return prov, true
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

func buildGenericDeltaResponse(ctx context.Context, req *discoveryv3.DeltaDiscoveryRequest, sub cachev3.Subscription, osnap *orderedSnapshot, typeURL string) *orderedDeltaResponse {
	snapshot := osnap.snapshot
	resources := snapshot.GetResources(typeURL)
	versionMap := snapshot.GetVersionMap(typeURL)
	prevMap := sub.ReturnedResources()

	var (
		filtered       []deltaCachedResource
		removed        []string
		nextVersionMap map[string]string
	)

	if sub.IsWildcard() {
		nextVersionMap = make(map[string]string, len(resources))
		for name, res := range resources {
			ver := versionMap[name]
			nextVersionMap[name] = ver
			if prevVer, found := prevMap[name]; !found || prevVer != ver {
				filtered = append(filtered, deltaCachedResource{name: name, version: ver, resource: res})
			}
		}
		for name := range prevMap {
			if _, ok := resources[name]; !ok {
				removed = append(removed, name)
			}
		}
	} else {
		subscribed := sub.SubscribedResources()
		nextVersionMap = make(map[string]string, len(subscribed))
		for name := range subscribed {
			prevVer, found := prevMap[name]
			if res, ok := resources[name]; ok {
				ver := versionMap[name]
				if !found || prevVer != ver {
					filtered = append(filtered, deltaCachedResource{name: name, version: ver, resource: res})
				}
				nextVersionMap[name] = ver
			} else if found {
				removed = append(removed, name)
			}
		}
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].name < filtered[j].name })
	sort.Strings(removed)

	return &orderedDeltaResponse{
		request:           req,
		systemVersionInfo: snapshot.GetVersion(typeURL),
		originFingerprint: osnap.typeFingerprints[typeURL],
		resources:         filtered,
		removed:           removed,
		returnedResources: nextVersionMap,
		ctx:               ctx,
	}
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
