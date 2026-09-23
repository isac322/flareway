/*
Copyright 2026 Byeonghoon Yoo.

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

package sweep

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/internal/ownership"
)

// errIncompleteListing marks a remote listing that could not be fully
// collected. The pass is recorded as partial and its judgement abandoned.
var errIncompleteListing = errors.New("incomplete remote listing")

// listFailure classifies a remote list error: definitive client-side
// rejections (HTTP 4xx) propagate as-is (result=error); anything else —
// mid-pagination 5xx, transport errors — means the listing is incomplete
// and must not be judged (result=partial).
func listFailure(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if status, ok := flarecloudflare.StatusCode(err); ok && status >= 400 && status < 500 {
		return err
	}
	return errIncompleteListing
}

// zoneFailure records one listing scope that could not be collected,
// preserving the scope identifier and the wrapped cause.
type zoneFailure struct {
	zoneID string
	err    error
}

func (e *zoneFailure) Error() string {
	return "zone " + e.zoneID + ": " + e.err.Error()
}

func (e *zoneFailure) Unwrap() error {
	return e.err
}

// scopedListingError marks a multi-scope listing that completed for some
// scopes but failed for others. Unlike errIncompleteListing it is a typed
// partial: the DriftItems returned alongside it are safe — they were judged
// only against scopes whose listings completed — and the aggregate preserves
// which scopes failed and why, in discovery order.
//
// Is reports errIncompleteListing so the aggregate still classifies as an
// incomplete listing; RunTargetOnce must test for *scopedListingError before
// the generic sentinel or the safe items would be discarded. Unwrap returns
// the stored per-scope causes (each a *zoneFailure) so errors.Is/As reach
// both the scope identifiers and the original errors.
type scopedListingError struct {
	failures []error
}

func (e *scopedListingError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "scoped listing incomplete: %d zone failure(s)", len(e.failures))
	for _, f := range e.failures {
		fmt.Fprintf(&b, "; %v", f)
	}
	return b.String()
}

func (e *scopedListingError) Is(target error) bool {
	return target == errIncompleteListing
}

func (e *scopedListingError) Unwrap() []error {
	return e.failures
}

// scopedListingErr aggregates per-zone listing failures. A non-empty slice
// yields a *scopedListingError so RunTargetOnce can report a scoped partial
// that preserves the items judged against completed zones; an empty slice
// yields nil.
func scopedListingErr(failures []error) error {
	if len(failures) == 0 {
		return nil
	}
	return &scopedListingError{failures: failures}
}

// sweepClientFactory is an optional extension of ClientFactory: when the
// injected factory provides it, the sweep client is paced by the supplied
// limiter and the package skips its own Wait to avoid double-pacing.
type sweepClientFactory interface {
	SweepClient(token, accountID string, limiter *rate.Limiter) flarecloudflare.API
}

// AccountSweeperOptions carries one account's sweep dependencies.
type AccountSweeperOptions struct {
	AccountName       string
	AccountID         string
	Token             string
	Factory           flarecloudflare.ClientFactory
	Client            client.Client
	APIReader         client.Reader
	Invalidator       Invalidator
	Policy            freshness.Policy
	OperatorNamespace string
	RateLimit         float64
	RateBurst         int
	Targets           []TargetDescriptor
	// Events is the shared wakeup channel owned by Sweeper.
	Events chan event.GenericEvent
	Logger logr.Logger
}

// AccountSweeper runs every target loop for one Cloudflare account.
type AccountSweeper struct {
	accountName       string
	accountID         string
	token             string
	factory           flarecloudflare.ClientFactory
	client            client.Client
	apiReader         client.Reader
	invalidator       Invalidator
	policy            freshness.Policy
	operatorNamespace string
	limiter           *rate.Limiter
	targets           []TargetDescriptor
	events            chan event.GenericEvent
	logger            logr.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup

	remoteMu  sync.Mutex
	remoteAPI flarecloudflare.API

	mu               sync.Mutex
	zonesCache       []flarecloudflare.Zone
	zonesCachedAt    time.Time
	clusterIDCache   string
	ownershipKeyData []byte
	ownershipKeyDone bool
}

// NewAccountSweeper constructs a per-account sweeper. Exported so tests can
// drive RunTargetOnce directly without a manager.
func NewAccountSweeper(opts AccountSweeperOptions) *AccountSweeper {
	if opts.RateLimit <= 0 {
		opts.RateLimit = defaultSweepRateLimit
	}
	if opts.RateBurst <= 0 {
		opts.RateBurst = defaultSweepRateBurst
	}
	if opts.Targets == nil {
		opts.Targets = defaultTargets()
	}
	return &AccountSweeper{
		accountName:       opts.AccountName,
		accountID:         opts.AccountID,
		token:             opts.Token,
		factory:           opts.Factory,
		client:            opts.Client,
		apiReader:         opts.APIReader,
		invalidator:       opts.Invalidator,
		policy:            opts.Policy,
		operatorNamespace: opts.OperatorNamespace,
		limiter:           rate.NewLimiter(rate.Limit(opts.RateLimit), opts.RateBurst),
		targets:           opts.Targets,
		events:            opts.Events,
		logger:            opts.Logger,
	}
}

// Start launches one goroutine per target and returns immediately.
func (as *AccountSweeper) Start(ctx context.Context) {
	ctx, as.cancel = context.WithCancel(ctx)
	for i := range as.targets {
		target := as.targets[i]
		as.wg.Add(1)
		go as.runTargetLoop(ctx, target)
	}
}

// Stop cancels every target loop and waits for them to exit.
func (as *AccountSweeper) Stop() {
	if as.cancel != nil {
		as.cancel()
	}
	as.wg.Wait()
}

// runTargetLoop paces one kind: a randomized initial offset spreads the
// first pass across [0, min(T, 60s)), then each pass is followed by a
// jittered interval of T + [0, T/5).
func (as *AccountSweeper) runTargetLoop(ctx context.Context, target TargetDescriptor) {
	defer as.wg.Done()
	ttl := as.policy.TTL(target.Grade)
	if ttl <= 0 {
		as.logger.V(1).Info("sweep disabled for target grade", "kind", target.Kind)
		return
	}
	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

	delay := target.InitialDelay
	if delay <= 0 {
		delay = initialDelay(ttl, rng)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		as.runTarget(ctx, target)
		timer.Reset(jitteredInterval(ttl, rng))
	}
}

// runTarget executes one pass, records the result metric, and handles the
// classified drift items.
func (as *AccountSweeper) runTarget(ctx context.Context, target TargetDescriptor) {
	items, result, err := as.RunTargetOnce(ctx, target)
	switch {
	case err != nil && errors.Is(err, context.Canceled):
		// Shutdown: no metric, no log.
	case result == observability.SweepResultPartial:
		if err != nil {
			// Scoped partial: the aggregate names the failed scopes. Info,
			// not Error — a persistently denied scope produces this every
			// pass and must not become permanent error noise.
			as.logger.Info("target sweep partial: scoped listing incomplete (fail-closed for unlisted scopes)",
				"kind", target.Kind, "error", err.Error())
		} else {
			as.logger.Info("target sweep abandoned: incomplete listing (fail-closed)", "kind", target.Kind)
		}
		// Safe items from a scoped partial are dispatched normally; a
		// generic partial carries nil items and this is a no-op.
		as.handleDriftResults(ctx, items)
	case err != nil:
		as.logger.Error(err, "target sweep failed", "kind", target.Kind)
	default:
		as.handleDriftResults(ctx, items)
	}
}

// RunTargetOnce performs a single sweep pass for target and reports the
// outcome. It is exported so tests can drive passes without waiting for
// timers. The returned result is one of ok/partial/error. A partial pass
// returns nil items and nil error, except a scoped partial: when SweepFunc
// returns a *scopedListingError the pass is partial but the items judged
// against completed scopes are safe, so they are returned together with the
// aggregate error.
func (as *AccountSweeper) RunTargetOnce(ctx context.Context, target TargetDescriptor) ([]DriftItem, string, error) {
	items, err := target.SweepFunc(ctx, as)
	var scoped *scopedListingError
	switch {
	case err != nil && errors.Is(err, context.Canceled):
		return nil, "", err
	case err != nil && errors.As(err, &scoped):
		// Typed partial: must precede the errIncompleteListing branch —
		// scopedListingError.Is matches the sentinel, so the generic branch
		// would silently discard the safe items.
		observability.ObserveSweep(target.Kind, observability.SweepResultPartial)
		return items, observability.SweepResultPartial, err
	case err != nil && errors.Is(err, errIncompleteListing):
		observability.ObserveSweep(target.Kind, observability.SweepResultPartial)
		return nil, observability.SweepResultPartial, nil
	case err != nil:
		observability.ObserveSweep(target.Kind, observability.SweepResultError)
		return nil, observability.SweepResultError, err
	case items == nil:
		// A nil item slice without an error means the listing could not be
		// completed; judgement is abandoned (fail-closed).
		observability.ObserveSweep(target.Kind, observability.SweepResultPartial)
		return nil, observability.SweepResultPartial, nil
	}
	observability.ObserveSweep(target.Kind, observability.SweepResultOK)
	// Only a pass that judged a complete listing may publish the
	// last-success timestamp; partial passes must leave it stale.
	observability.SetSweepLastSuccess(target.Kind, time.Now())
	return items, observability.SweepResultOK, nil
}

// handleDriftResults records each drift, closes the object's gate through
// the latch, and emits the wakeup event.
func (as *AccountSweeper) handleDriftResults(_ context.Context, items []DriftItem) {
	for _, item := range items {
		observability.ObserveDrift(item.Kind, string(item.Case))
		as.logger.Info("drift detected by sweep",
			"kind", item.Kind, "target", item.TargetKind,
			"key", item.NamespacedName.String(), "case", string(item.Case),
			"remoteID", item.RemoteID, "reason", item.Reason)

		switch item.Case {
		case DriftCaseMissing, DriftCaseMismatch:
			if as.invalidator != nil {
				as.invalidator.Invalidate(item.TargetKind, item.NamespacedName, item.Reason)
			}
			as.emitEvent(item)
		case DriftCaseOrphan:
			// Orphans are observe-only: deleting a remote object is a
			// destructive write that belongs to the owning reconciler's
			// teardown path after a T0 fresh read, never to this loop.
		}
	}
}

// emitEvent performs a non-blocking send on the wakeup channel. A full
// buffer drops the event: the latch keeps the gate closed and the next
// pass re-emits while the drift persists.
func (as *AccountSweeper) emitEvent(item DriftItem) {
	if as.events == nil {
		return
	}
	object := &unstructured.Unstructured{}
	if gvk, ok := kindGVK[item.TargetKind]; ok {
		object.SetGroupVersionKind(gvk)
	}
	object.SetNamespace(item.NamespacedName.Namespace)
	object.SetName(item.NamespacedName.Name)
	select {
	case as.events <- event.GenericEvent{Object: object}:
	default:
		as.logger.V(1).Info("sweep event buffer full; deferring wakeup to next pass",
			"kind", item.TargetKind, "key", item.NamespacedName.String())
	}
}

// remote returns the account-scoped Cloudflare client and the pacing
// function to invoke before each remote call. When the factory provides a
// dedicated sweep client the limiter is already inside it and wait is a
// no-op; otherwise every call is paced by the account sweeper's limiter.
func (as *AccountSweeper) remote() (flarecloudflare.API, func(context.Context) error) {
	as.remoteMu.Lock()
	defer as.remoteMu.Unlock()
	if as.remoteAPI == nil {
		if factory, ok := as.factory.(sweepClientFactory); ok {
			as.remoteAPI = factory.SweepClient(as.token, as.accountID, as.limiter)
		} else {
			as.remoteAPI = as.factory.Client(as.token, as.accountID)
		}
	}
	if _, ok := as.factory.(sweepClientFactory); ok {
		// The limiter is already inside the client: no extra Wait.
		return as.remoteAPI, func(context.Context) error { return nil }
	}
	return as.remoteAPI, as.limiter.Wait
}

// zones returns the account's zones, cached briefly so several zone-scoped
// targets share one listing per minute instead of one per target.
func (as *AccountSweeper) zones(ctx context.Context) ([]flarecloudflare.Zone, error) {
	as.mu.Lock()
	if as.zonesCache != nil && time.Since(as.zonesCachedAt) < time.Minute {
		cached := as.zonesCache
		as.mu.Unlock()
		return cached, nil
	}
	as.mu.Unlock()

	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	zones, err := api.ListZones(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	as.mu.Lock()
	as.zonesCache = zones
	as.zonesCachedAt = time.Now()
	as.mu.Unlock()
	return zones, nil
}

// clusterID returns the kube-system UID, cached after the first read.
func (as *AccountSweeper) clusterID(ctx context.Context) (string, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.clusterIDCache != "" {
		return as.clusterIDCache, nil
	}
	var namespace corev1.Namespace
	if err := as.client.Get(ctx, types.NamespacedName{Name: "kube-system"}, &namespace); err != nil {
		return "", err
	}
	if namespace.UID == "" {
		return "", errors.New("kube-system Namespace has no UID")
	}
	as.clusterIDCache = string(namespace.UID)
	return as.clusterIDCache, nil
}

// ownershipKey resolves the cluster HMAC key for ownership markers. Like
// the reconcilers, failures degrade to a nil key (legacy plaintext
// markers); only a successful resolution is cached so a transient error
// does not pin the degraded mode.
func (as *AccountSweeper) ownershipKey(ctx context.Context) []byte {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.ownershipKeyDone {
		return as.ownershipKeyData
	}
	provider := ownership.NewSecretKeyProvider(as.client, as.operatorNamespace)
	key, err := provider.GetOrCreateKey(ctx)
	if err != nil {
		as.logger.Info("ownership key unavailable; using legacy ownership markers", "error", err.Error())
		return nil
	}
	as.ownershipKeyData = key
	as.ownershipKeyDone = true
	return key
}

// initialDelay draws the first-pass offset from [0, min(ttl, 60s)). The
// bound is guarded so a tiny TTL can never produce Int64N(0).
func initialDelay(ttl time.Duration, rng *rand.Rand) time.Duration {
	bound := ttl
	if bound > time.Minute {
		bound = time.Minute
	}
	if bound <= 1 {
		return 0
	}
	return time.Duration(rng.Int64N(int64(bound)))
}

// jitteredInterval returns ttl plus a positive jitter in [0, ttl/5). The
// jitter bound is guarded so small TTLs cannot produce Int64N(0).
func jitteredInterval(ttl time.Duration, rng *rand.Rand) time.Duration {
	jitterBound := int64(ttl) / 5
	if jitterBound <= 0 {
		return ttl
	}
	return ttl + time.Duration(rng.Int64N(jitterBound))
}
