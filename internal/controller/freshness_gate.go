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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/observability"
)

// gateInput is the canonical desired-hash input shared by every gated
// reconciler. Only spec-derived values, Kubernetes identity, and remote
// identifiers belong here.
//
// Status fields must never appear. A status value that oscillates would flip
// the hash on every pass, and the gate would stay shut forever while still
// paying the cost of recomputing it.
type gateInput struct {
	// Kind is the CRD kind and doubles as the bounded metric label.
	Kind string
	// Namespace and Name identify the object for the invalidation latch.
	Namespace string
	Name      string
	// UID distinguishes a recreated object from its predecessor.
	UID types.UID
	// RemoteID is the Cloudflare identifier this object is bound to. An empty
	// value is legitimate before the remote object exists; it simply produces a
	// different hash than the bound state.
	RemoteID string
	// AccountID and ClusterID bind the hash to one tenant and one cluster so a
	// restored backup in a different cluster cannot inherit a converged gate.
	AccountID string
	ClusterID string
	// Converged reports whether the object's live Kubernetes status currently
	// reflects a converged state for the current generation (e.g., Ready=True or
	// Programmed=True with ObservedGeneration == Generation). When false, the
	// gate closes with DecisionClosedUnconverged so cached TTL or sweep
	// confirmations never suppress recovery after a transient pre-gate failure.
	Converged bool
	// Spec is the spec-derived desired state. Callers pass the object's spec or
	// the compiled input they are about to send to Cloudflare.
	Spec any
}

// gateDecision carries the freshness verdict together with the desired hash the
// caller must persist once the remote write succeeds.
type gateDecision struct {
	freshness.Gate
	// DesiredHash is empty when the hash could not be computed, in which case
	// Gate.Open is false and the caller takes the normal remote path.
	DesiredHash string
}

// gateHashFailureDecision labels the one verdict this helper reaches without
// calling freshness.Policy.Evaluate: the desired hash could not be computed.
const gateHashFailureDecision = string(freshness.DecisionClosedHash)

// evaluateGate decides whether a reconciler may skip its remote reads this
// pass. It is the single implementation of the desired-hash gate; reconcilers
// call it rather than repeating the hash, latch, and metric plumbing.
//
// The gate only ever suppresses reads. A closed gate runs the existing
// reconcile path unchanged, and an open gate must leave conditions,
// observedGeneration, and events exactly as the previous converged pass left
// them (00-architecture.md D3).
//
// Any failure to compute the hash closes the gate. Falling back to "no hash, so
// nothing changed" would skip remote reads on exactly the objects whose desired
// state could not be determined.
func evaluateGate(
	policy freshness.Policy,
	latch *freshness.Latch,
	grade freshness.Grade,
	input gateInput,
	appliedHash string,
	appliedAt *metav1.Time,
	now time.Time,
) gateDecision {
	desired, err := freshness.DesiredHash(struct {
		Kind      string
		Namespace string
		Name      string
		UID       string
		RemoteID  string
		AccountID string
		ClusterID string
		Spec      any
	}{
		Kind:      input.Kind,
		Namespace: input.Namespace,
		Name:      input.Name,
		UID:       string(input.UID),
		RemoteID:  input.RemoteID,
		AccountID: input.AccountID,
		ClusterID: input.ClusterID,
		Spec:      input.Spec,
	})
	if err != nil || desired == "" {
		latch.Forget(input.Kind, types.NamespacedName{Namespace: input.Namespace, Name: input.Name})
		observability.ObserveGate(input.Kind, gateHashFailureDecision)
		return gateDecision{}
	}

	return evaluateGateWithHash(
		policy, latch, grade, input.Kind,
		types.NamespacedName{Namespace: input.Namespace, Name: input.Name},
		appliedHash, desired, appliedAt, input.Converged, now,
	)
}

// evaluateGateWithHash is evaluateGate for callers that already hold an
// authoritative desired hash and must not recompute one.
func evaluateGateWithHash(
	policy freshness.Policy,
	latch *freshness.Latch,
	grade freshness.Grade,
	kind string,
	key types.NamespacedName,
	appliedHash, desiredHash string,
	appliedAt *metav1.Time,
	converged bool,
	now time.Time,
) gateDecision {
	return evaluateGateWithHashForUID(policy, latch, grade, kind, key, "", appliedHash, desiredHash, appliedAt, converged, now)
}

// evaluateGateWithHashForUID is evaluateGateWithHash scoped optionally to a
// live object UID so replacements (e.g., deleted/recreated CloudflareTunnel UIDs)
// never observe or clear each other's freshness latch slots.
func evaluateGateWithHashForUID(
	policy freshness.Policy,
	latch *freshness.Latch,
	grade freshness.Grade,
	kind string,
	key types.NamespacedName,
	uid types.UID,
	appliedHash, desiredHash string,
	appliedAt *metav1.Time,
	converged bool,
	now time.Time,
) gateDecision {
	if grade == freshness.GradeAlways {
		return gateDecision{
			Gate:        freshness.Gate{Decision: freshness.DecisionNotGated},
			DesiredHash: desiredHash,
		}
	}
	forget := func() {
		if uid != "" {
			latch.ForgetForUID(kind, key, uid)
			return
		}
		latch.Forget(kind, key)
	}
	if !converged {
		forget()
		observability.ObserveGate(kind, string(freshness.DecisionClosedUnconverged))
		return gateDecision{
			Gate:        freshness.Gate{Decision: freshness.DecisionClosedUnconverged},
			DesiredHash: desiredHash,
		}
	}
	var invalidated bool
	if uid != "" {
		invalidated = latch.IsInvalidatedForUID(kind, key, uid)
	} else {
		invalidated = latch.IsInvalidated(kind, key)
	}

	var applied time.Time
	if appliedAt != nil {
		applied = appliedAt.Time
	}
	var verified time.Time
	var ok bool
	if uid != "" {
		verified, ok = latch.VerifiedAtForUID(kind, key, uid, desiredHash)
	} else {
		verified, ok = latch.VerifiedAt(kind, key, desiredHash)
	}
	if ok && verified.After(applied) {
		applied = verified
	}

	gate := policy.Evaluate(grade, appliedHash, desiredHash, applied, now, invalidated)
	if uid == "" {
		if confirmed, ok := latch.ConfirmedAt(kind, key, desiredHash); ok {
			swept := policy.EvaluateSweepConfirmed(grade, appliedHash, desiredHash, confirmed, now, invalidated)
			if swept.Open && (!gate.Open || swept.Requeue > gate.Requeue) {
				gate = swept
			}
		}
	}
	if !gate.Open && gate.Decision != freshness.DecisionNotGated {
		forget()
	}
	if gate.Decision != freshness.DecisionNotGated {
		observability.ObserveGate(kind, string(gate.Decision))
	}
	return gateDecision{Gate: gate, DesiredHash: desiredHash}
}

// forgetGate drops cached verification, sweep confirmation, and sweep baseline
// state and latches a "demoted" invalidation when a reconcile turns status
// unconverged (pre-gate failure or remote error), so a temporarily stale
// informer cache carrying Ready=True cannot reopen the gate before the next pass
// verifies live. Callers clear the latch via completeGateVerification once
// status converges.
func forgetGate(latch *freshness.Latch, kind string, key types.NamespacedName) {
	latch.Forget(kind, key)
	latch.Invalidate(kind, key, "demoted")
}

// forgetGateForLiveTunnelUID forgets cached verification/baseline state and
// latches a "demoted" invalidation only when the live API server still holds
// expectedUID for the CloudflareTunnel and tok was not retired concurrently.
// If the Tunnel is already absent (NotFound), absence is corroborated safely via
// retireTunnelIfConfirmedAbsent; if the live UID changed, nothing is wiped or
// recreated so a replacement Tunnel's epoch/invalidation stays intact.
func forgetGateForLiveTunnelUID(
	ctx context.Context,
	reader kubeclient.Reader,
	latch *freshness.Latch,
	tok freshness.LifetimeToken,
	expectedUID types.UID,
) {
	if latch == nil || reader == nil || expectedUID == "" {
		return
	}
	var live v1alpha1.CloudflareTunnel
	if err := reader.Get(ctx, tok.Key(), &live); err != nil {
		if apierrors.IsNotFound(err) {
			_, _ = retireTunnelIfConfirmedAbsent(ctx, reader, latch, tok.Key(), err)
			return
		}
		// Transient uncached read failure while live status may be unconverged:
		// fail closed only if tok was not concurrently retired.
		latch.ForgetAndInvalidateIfUnretired(tok, "demoted")
		return
	}
	if live.UID != expectedUID {
		return
	}
	writtenEpoch, applied := latch.ForgetAndInvalidateIfUnretiredWithEpoch(tok, "demoted")
	if !applied {
		return
	}
	var recheck v1alpha1.CloudflareTunnel
	recheckErr := reader.Get(ctx, tok.Key(), &recheck)
	if apierrors.IsNotFound(recheckErr) {
		latch.RemoveForUIDAtEpoch(tok.Kind(), tok.Key(), expectedUID, writtenEpoch)
		_, _ = retireTunnelIfConfirmedAbsent(ctx, reader, latch, tok.Key(), recheckErr)
		return
	}
	if recheckErr == nil && recheck.UID != expectedUID {
		latch.RemoveForUIDAtEpoch(tok.Kind(), tok.Key(), expectedUID, writtenEpoch)
	}
}

// statusConverged reports whether the object's live status is converged on the
// current generation with every required condition set to True.
func statusConverged(generation, observedGeneration int64, conditions []metav1.Condition, required ...string) bool {
	if observedGeneration != generation {
		return false
	}
	for _, conditionType := range required {
		if !conditionTrueForGeneration(conditions, conditionType, generation) {
			return false
		}
	}
	return true
}

// releaseGoneObject is the NotFound branch of every gated reconciler's
// initial Get: an object that no longer exists (deleted, or finalized after
// cleanup) must not keep freshness records in memory for the life of the
// process. Other errors are returned unchanged.
func releaseGoneObject(latch *freshness.Latch, kind string, key types.NamespacedName, err error) error {
	if apierrors.IsNotFound(err) {
		latch.Remove(kind, key)
		return nil
	}
	return err
}

// retireTunnelIfConfirmedAbsent corroborates a cached CloudflareTunnel
// NotFound error against reader (uncached APIReader) before retiring both
// CloudflareTunnel and CloudflareTunnelConfig latch keys via per-key
// LifetimeTokens so fresh replacement-UID state added concurrently is never
// wiped.
//
// Returns (true, nil) when uncached reader confirms NotFound, (false, nil)
// when uncached reader still observes a live tunnel (stale cache lag), or
// (false, err) when getErr is not NotFound or the uncached lookup fails
// transiently.
func retireTunnelIfConfirmedAbsent(
	ctx context.Context,
	reader kubeclient.Reader,
	latch *freshness.Latch,
	key types.NamespacedName,
	getErr error,
) (bool, error) {
	if !apierrors.IsNotFound(getErr) {
		return false, getErr
	}
	tokTunnel := latch.BeginLifetime("CloudflareTunnel", key)
	defer latch.EndLifetime(tokTunnel)
	tokConfig := latch.BeginLifetime(configFreshnessKind, key)
	defer latch.EndLifetime(tokConfig)
	var live v1alpha1.CloudflareTunnel
	confirmErr := reader.Get(ctx, key, &live)
	if confirmErr == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(confirmErr) {
		return false, fmt.Errorf("confirm CloudflareTunnel %s absence: %w", key, confirmErr)
	}
	latch.RemoveIfUntouched(tokTunnel)
	latch.RemoveIfUntouched(tokConfig)
	return true, nil
}

// pruneOtherTunnelConfigUIDs reclaims stale UID-scoped CloudflareTunnelConfig
// latch slots when a Tunnel has been replaced by a newer UID. Fast-paths to
// zero API reads when no other UID entries exist; otherwise holds a guarded
// PruneToken across an uncached directReader lookup so a stale cache snapshot
// or concurrent replacement-UID write never prunes live UID state.
func pruneOtherTunnelConfigUIDs(
	ctx context.Context,
	reader kubeclient.Reader,
	latch *freshness.Latch,
	key types.NamespacedName,
	observedUID types.UID,
) {
	if latch == nil || reader == nil || observedUID == "" || !latch.HasOtherUIDs(configFreshnessKind, key, observedUID) {
		return
	}
	tok := latch.BeginPrune(configFreshnessKind, key)
	defer latch.EndPrune(tok)
	var live v1alpha1.CloudflareTunnel
	if err := reader.Get(ctx, key, &live); err != nil || live.UID == "" {
		return
	}
	latch.PruneOtherUIDsIfUntouched(tok, live.UID)
}

// gateClusterID resolves the cluster identity used in the gate hash.
//
// Failure is deliberately not fatal. The gate is an optimization, and a
// reconcile that previously converged without reading kube-system must keep
// converging. An unresolved cluster ID yields an empty string, which produces
// a different hash than the stored one and closes the gate, so the object
// simply takes the normal remote path.
func gateClusterID(ctx context.Context, reader kubeclient.Client) string {
	clusterID, err := flarecloudflare.ClusterID(ctx, reader)
	if err != nil {
		return ""
	}
	return clusterID
}

// convergedRequeue is the requeue interval for a reconciler that just
// converged.
//
// A configured policy returns the grade TTL, so the next pass lands exactly
// when the gate expires. An unset or zeroed policy returns the caller's
// pre-gate interval instead: disabling freshness is the documented rollback,
// and a rollback that silently removed periodic reconciliation would leave
// remote-only changes undetected forever rather than restoring the old
// behaviour.
//
// Callers whose converged path had no periodic requeue before the gate must
// not use this helper; for them a zero policy correctly means no requeue.
func convergedRequeue(policy freshness.Policy, grade freshness.Grade, fallback time.Duration) time.Duration {
	if ttl := policy.TTL(grade); ttl > 0 {
		return ttl
	}
	return fallback
}

// gateStamp is the converged gate record a reconciler persists so the next
// pass can skip its remote reads.
type gateStamp struct {
	Hash string
	At   metav1.Time
	// Content, when set, lets the drift sweep confirm this desired state from
	// its listing (freshness.Latch.SetBaseline). Set it only when the listed
	// remote object carries everything this pass verified; leave it nil and
	// the object keeps its own per-TTL verify.
	Content freshness.ContentMatcher
}

// newGateStamp builds the stamp for a pass that just converged.
func newGateStamp(hash string, at time.Time) gateStamp {
	return gateStamp{Hash: hash, At: metav1.NewTime(at)}
}

// withContent returns the stamp with a content matcher for the sweep.
func (stamp gateStamp) withContent(matches freshness.ContentMatcher) gateStamp {
	stamp.Content = matches
	return stamp
}

// contentBaseline returns matches only when the remote object this pass just
// verified satisfies it. A matcher that rejects the very object the reconciler
// accepted as converged would make the sweep report drift on every pass, so
// such an object keeps its own per-TTL verify instead.
func contentBaseline(matches freshness.ContentMatcher, verified any) freshness.ContentMatcher {
	if matches == nil || !matches(verified) {
		return nil
	}
	return matches
}

// nextGateStamp decides what status must hold after a converged pass.
// status.appliedAt documents when appliedHash was recorded, so it moves only
// when the hash does; a re-verify that confirms the recorded hash leaves
// status untouched and reports changed=false. The verify time itself belongs
// in the latch (freshness.Latch.MarkVerified), which the caller records once
// the pass has persisted whatever it had to.
func nextGateStamp(storedHash string, storedAt *metav1.Time, stamp gateStamp) (string, *metav1.Time, bool) {
	if stamp.Hash == storedHash && storedAt != nil {
		return storedHash, storedAt, false
	}
	at := stamp.At
	return stamp.Hash, &at, true
}

func directStatusReader(writer kubeclient.Client, reader kubeclient.Reader) kubeclient.Reader {
	if reader != nil {
		return reader
	}
	return writer
}

// patchStatusWithDirectReader reads the live object from reader (uncached
// APIReader when configured) inside RetryOnConflict, guards UID/Generation
// identity, applies mutate, and submits an optimistic-locked status merge patch.
// It returns (false, nil) without clearing latches if the object was deleted
// or its UID/Generation changed concurrently.
func patchStatusWithDirectReader[T kubeclient.Object](
	ctx context.Context,
	writer kubeclient.Client,
	reader kubeclient.Reader,
	observed T,
	mutate func(live T) error,
) (bool, error) {
	key := kubeclient.ObjectKeyFromObject(observed)
	applied := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		live, ok := reflect.New(reflect.TypeOf(observed).Elem()).Interface().(T)
		if !ok {
			return fmt.Errorf("allocate live copy for %T", observed)
		}
		if err := directStatusReader(writer, reader).Get(ctx, key, live); err != nil {
			if apierrors.IsNotFound(err) {
				applied = false
				return nil
			}
			return err
		}
		if (observed.GetUID() != "" && live.GetUID() != observed.GetUID()) || live.GetGeneration() != observed.GetGeneration() {
			applied = false
			return nil
		}
		before, ok := live.DeepCopyObject().(T)
		if !ok {
			return fmt.Errorf("deep-copy live object %T", observed)
		}
		if err := mutate(live); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(before, live) {
			applied = true
			return nil
		}
		if err := writer.Status().Patch(ctx, live, kubeclient.MergeFromWithOptions(before, kubeclient.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsNotFound(err) {
				applied = false
				return nil
			}
			return fmt.Errorf("patch %T status: %w", observed, err)
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}

// completeGateVerification atomically releases an invalidation matching
// expectedEpoch and records verification timestamp and optional sweep baseline.
func completeGateVerification(latch *freshness.Latch, kind string, key types.NamespacedName, expectedEpoch uint64, stamp gateStamp) bool {
	return latch.CompleteVerification(kind, key, expectedEpoch, stamp.Hash, stamp.At.Time, stamp.Content)
}

// persistGateStampChecked re-reads the live object via reader (uncached
// APIReader), verifies UID, Generation, and converged status conditions on the
// live object, atomically writes AppliedHash/AppliedAt with optimistic locking
// if changed, and completes latch verification only when expectedEpoch still
// matches the latch's current invalidation epoch.
func persistGateStampChecked(
	ctx context.Context,
	writer kubeclient.Client,
	reader kubeclient.Reader,
	latch *freshness.Latch,
	observed kubeclient.Object,
	stamp gateStamp,
	expectedEpoch uint64,
) error {
	if writer == nil || observed == nil || stamp.Hash == "" {
		return nil
	}
	key := kubeclient.ObjectKeyFromObject(observed)
	var gateKind string
	persisted := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		live, ok := reflect.New(reflect.TypeOf(observed).Elem()).Interface().(kubeclient.Object)
		if !ok {
			return fmt.Errorf("allocate live copy for %T", observed)
		}
		if err := directStatusReader(writer, reader).Get(ctx, key, live); err != nil {
			if apierrors.IsNotFound(err) {
				persisted = false
				return nil
			}
			return err
		}
		if (observed.GetUID() != "" && live.GetUID() != observed.GetUID()) || live.GetGeneration() != observed.GetGeneration() {
			persisted = false
			return nil
		}
		kind, hash, at, converged, ok := gateObjectState(live)
		if !ok {
			return fmt.Errorf("persist freshness gate stamp: %T has no gate stamp fields", live)
		}
		gateKind = kind
		if !converged {
			persisted = false
			return nil
		}
		before, ok := live.DeepCopyObject().(kubeclient.Object)
		if !ok {
			return fmt.Errorf("deep-copy live object %T", live)
		}
		nextHash, nextAt, changed := nextGateStamp(*hash, *at, stamp)
		if changed {
			*hash, *at = nextHash, nextAt
			if err := writer.Status().Patch(ctx, live, kubeclient.MergeFromWithOptions(before, kubeclient.MergeFromWithOptimisticLock{})); err != nil {
				if apierrors.IsNotFound(err) {
					persisted = false
					return nil
				}
				return fmt.Errorf("persist freshness gate stamp: %w", err)
			}
		}
		persisted = true
		return nil
	})
	if err != nil {
		return err
	}
	if !persisted {
		return nil
	}
	completeGateVerification(latch, gateKind, key, expectedEpoch, stamp)
	return nil
}

// gateStampFields returns the gate kind and the status fields holding the
// stamp of a gated object, and reports whether the kind is one this operator
// gates.
func gateStampFields(object kubeclient.Object) (string, *string, **metav1.Time, bool) {
	kind, hash, at, _, ok := gateObjectState(object)
	return kind, hash, at, ok
}

// gateObjectState returns the gate kind, stamp field pointers, live status
// convergence for the object's current generation, and whether the object type
// is a gated kind.
func gateObjectState(object kubeclient.Object) (string, *string, **metav1.Time, bool, bool) {
	switch typed := object.(type) {
	case *v1alpha1.VirtualNetwork:
		return "VirtualNetwork", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted, v1alpha1.PrivateNetworkConditionReady), true
	case *v1alpha1.NetworkRoute:
		return "NetworkRoute", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted, v1alpha1.PrivateNetworkConditionReady), true
	case *v1alpha1.HostnameRoute:
		return "HostnameRoute", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted, v1alpha1.PrivateNetworkConditionReady), true
	case *v1alpha1.IdentityProvider:
		return "IdentityProvider", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.AccessGroup:
		return "AccessGroup", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.AccessPolicy:
		return "AccessPolicy", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.AccessCustomPage:
		return "AccessCustomPage", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.AccessCustomPageConditionAccepted, v1alpha1.AccessCustomPageConditionReady), true
	case *v1alpha1.AccessInfrastructureTarget:
		return "AccessInfrastructureTarget", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.AccessStandaloneApplication:
		return "AccessStandaloneApplication", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.AccessApplication:
		return "AccessApplication", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, accessApplicationConditionAccepted, accessApplicationConditionProgrammed), true
	case *v1alpha1.DeviceSettings:
		return "DeviceSettings", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.DeviceSettingsConditionAccepted, v1alpha1.DeviceSettingsConditionReady), true
	case *v1alpha1.DeviceProfile:
		return "DeviceProfile", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.DeviceProfileConditionAccepted, v1alpha1.DeviceProfileConditionReady), true
	case *v1alpha1.DevicePostureRule:
		return "DevicePostureRule", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.DevicePostureIntegration:
		return "DevicePostureIntegration", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.ServiceToken:
		return "ServiceToken", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, "Accepted", "Ready"), true
	case *v1alpha1.WARPConnector:
		return "WARPConnector", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.WARPConnectorConditionAccepted, v1alpha1.WARPConnectorConditionReady), true
	case *v1alpha1.ZeroTrustList:
		return "ZeroTrustList", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.ZeroTrustListConditionAccepted, v1alpha1.ZeroTrustListConditionReady), true
	case *v1alpha1.ZeroTrustGatewayPolicy:
		return "ZeroTrustGatewayPolicy", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionAccepted, v1alpha1.ZeroTrustGatewayPolicyConditionReady), true
	case *v1alpha1.ZeroTrustOrganization:
		return "ZeroTrustOrganization", &typed.Status.AppliedHash, &typed.Status.AppliedAt,
			statusConverged(typed.Generation, typed.Status.ObservedGeneration, typed.Status.Conditions, v1alpha1.ZeroTrustOrganizationConditionAccepted, v1alpha1.ZeroTrustOrganizationConditionReady), true
	default:
		return "", nil, nil, false, false
	}
}
