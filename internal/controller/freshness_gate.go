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
//
// The Gateway-mode tunnel configuration is the motivating case: its desired
// state is the compiled cloudflared configuration, and the hash that
// status.configVersion.desiredHash is compared against is the one
// cloudflaredconfig.Compile returns. Hashing the spec again here would produce
// a different value than the one the write path persists, so the gate would
// never open.
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
	if grade == freshness.GradeAlways {
		return gateDecision{
			Gate:        freshness.Gate{Decision: freshness.DecisionNotGated},
			DesiredHash: desiredHash,
		}
	}
	if !converged {
		latch.Forget(kind, key)
		observability.ObserveGate(kind, string(freshness.DecisionClosedUnconverged))
		return gateDecision{
			Gate:        freshness.Gate{Decision: freshness.DecisionClosedUnconverged},
			DesiredHash: desiredHash,
		}
	}
	invalidated := latch.IsInvalidated(kind, key)

	// The gate's age is measured from the most recent confirmation of this
	// exact desired hash: either the persisted appliedAt, or a later re-verify
	// kept in memory so that an unchanged re-verify need not write status. A
	// restart loses the in-memory record, which only ever makes the age
	// larger and the gate more likely to close.
	var applied time.Time
	if appliedAt != nil {
		applied = appliedAt.Time
	}
	if verified, ok := latch.VerifiedAt(kind, key, desiredHash); ok && verified.After(applied) {
		applied = verified
	}

	gate := policy.Evaluate(grade, appliedHash, desiredHash, applied, now, invalidated)
	// A sweep listing that confirmed the content of this exact desired hash
	// counts as a verify with a longer window (two grade periods), so that a
	// healthy sweep keeps the object from reading the remote itself. When
	// both are valid, the later expiry wins so the object wakes no earlier
	// than it has to. Invalidation and hash mismatches close it the same way.
	if confirmed, ok := latch.ConfirmedAt(kind, key, desiredHash); ok {
		swept := policy.EvaluateSweepConfirmed(grade, appliedHash, desiredHash, confirmed, now, invalidated)
		if swept.Open && (!gate.Open || swept.Requeue > gate.Requeue) {
			gate = swept
		}
	}
	// A closed gate sends this pass to the remote. Until it converges and
	// records again, nothing verified earlier may re-open the gate: a desired
	// state that changes and then changes back must not find an old verify
	// or a sweep confirmation the sweep kept renewing, and skip the pass that
	// brings status back in line.
	if !gate.Open && gate.Decision != freshness.DecisionNotGated {
		latch.Forget(kind, key)
	}
	// freshness.Policy.Evaluate already names the first condition that closed
	// the gate, so the label is never recomputed here and cannot drift from the
	// judgement it describes. DecisionNotGated means a T0 caller reached this
	// helper, which is a programming error rather than a gate outcome; leaving
	// it unobserved keeps the metric to real evaluations.
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
	latch.ForgetAndInvalidateIfUnretired(tok, "demoted")
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
