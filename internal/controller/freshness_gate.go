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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
		observability.ObserveGate(input.Kind, gateHashFailureDecision)
		return gateDecision{}
	}

	return evaluateGateWithHash(
		policy, latch, grade, input.Kind,
		types.NamespacedName{Namespace: input.Namespace, Name: input.Name},
		appliedHash, desired, appliedAt, now,
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
	now time.Time,
) gateDecision {
	invalidated := latch.IsInvalidated(kind, key)

	var applied time.Time
	if appliedAt != nil {
		applied = appliedAt.Time
	}

	gate := policy.Evaluate(grade, appliedHash, desiredHash, applied, now, invalidated)
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

// clearGate drops the invalidation latch for an object whose reconcile has
// converged, so the next pass is judged on hash and age alone.
func clearGate(latch *freshness.Latch, kind string, key types.NamespacedName) {
	latch.Clear(kind, key)
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
}

// newGateStamp builds the stamp for a pass that just converged.
func newGateStamp(hash string, at time.Time) gateStamp {
	return gateStamp{Hash: hash, At: metav1.NewTime(at)}
}

// persistGateStamp writes the converged gate stamp as its own status patch.
//
// It exists because most status patch helpers capture their merge base from
// the live object (client.MergeFrom(object.DeepCopy())). A caller that assigns
// the stamp before calling one of those helpers puts the new values into both
// the base and the target, so the merge patch carries no change and the stamp
// is silently dropped. The gate then never opens, the object reads the remote
// on every pass, and nothing anywhere reports a problem — the build, the
// linter, and the whole test suite stay green while the saving is zero.
//
// Re-reading the stored object and diffing against it makes the write
// independent of how each controller's own helper builds its base, so the
// mechanism is identical for every kind instead of correct for some.
//
// The extra patch lands only on a pass that actually converged, which is
// exactly the pass that stops happening once the gate starts opening.
func persistGateStamp(
	ctx context.Context,
	writer kubeclient.Client,
	object kubeclient.Object,
	stamp gateStamp,
) error {
	if writer == nil || object == nil || stamp.Hash == "" {
		return nil
	}
	current, ok := object.DeepCopyObject().(kubeclient.Object)
	if !ok {
		return nil
	}
	if err := writer.Get(ctx, kubeclient.ObjectKeyFromObject(object), current); err != nil {
		// A deleted object has nothing to stamp; anything else is reported so
		// the caller does not treat an unstamped pass as converged.
		return kubeclient.IgnoreNotFound(err)
	}
	before, ok := current.DeepCopyObject().(kubeclient.Object)
	if !ok {
		return nil
	}
	if !applyGateStamp(current, stamp) {
		return fmt.Errorf("persist freshness gate stamp: %T has no gate stamp fields", current)
	}
	if err := writer.Status().Patch(ctx, current, kubeclient.MergeFrom(before)); err != nil {
		return fmt.Errorf("persist freshness gate stamp: %w", err)
	}
	return nil
}

// applyGateStamp writes the stamp onto a gated object and reports whether the
// kind is one this operator gates. A gated controller whose kind is missing
// here would otherwise persist nothing and lose its saving silently, so the
// false result is turned into an error by the caller rather than ignored.
func applyGateStamp(object kubeclient.Object, stamp gateStamp) bool {
	at := stamp.At
	switch typed := object.(type) {
	case *v1alpha1.VirtualNetwork:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.NetworkRoute:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.HostnameRoute:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.IdentityProvider:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessGroup:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessPolicy:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessCustomPage:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessInfrastructureTarget:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessStandaloneApplication:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.AccessApplication:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.DeviceSettings:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.DeviceProfile:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.DevicePostureRule:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.DevicePostureIntegration:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.ServiceToken:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.WARPConnector:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.ZeroTrustList:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.ZeroTrustGatewayPolicy:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	case *v1alpha1.ZeroTrustOrganization:
		typed.Status.AppliedHash, typed.Status.AppliedAt = stamp.Hash, &at
	default:
		return false
	}
	return true
}
