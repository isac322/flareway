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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	// tunnelStatusFieldManager is the shared field manager that owns every
	// Flareway condition type under CloudflareTunnel status.conditions. The
	// flareway-tunnel and flareway-gateway managers keep their data fields but
	// must never carry conditions again: a single writer deriving Ready inside
	// the same document as its inputs is what keeps the pair consistent.
	tunnelStatusFieldManager = "flareway-tunnel-status"
	// tunnelConditionMaxAttempts bounds the optimistic-concurrency retry loop.
	// Each attempt re-reads the live object and re-merges the same authored
	// deltas; remote actions are never replayed.
	tunnelConditionMaxAttempts = 3
)

// tunnelFlarewayConditionTypes is the complete set of Flareway condition types
// the shared manager may own. External condition types are never placed in the
// apply document: under +listType=map an omitted entry stays untouched and
// unowned, so carrying one would steal foreign ownership.
var tunnelFlarewayConditionTypes = map[string]struct{}{
	v1alpha1.CloudflareTunnelConditionAccepted:                {},
	v1alpha1.CloudflareTunnelConditionTunnelReady:             {},
	v1alpha1.CloudflareTunnelConditionConfigApplied:           {},
	v1alpha1.CloudflareTunnelConditionDNSReady:                {},
	v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded: {},
	v1alpha1.CloudflareTunnelConditionReady:                   {},
	v1alpha1.CloudflareTunnelConditionCleanupBlocked:          {},
	v1alpha1.CloudflareTunnelConditionConflict:                {},
	v1alpha1.CloudflareTunnelConditionDriftDetected:           {},
}

// tunnelConditionUpdate is one conditions transaction against a single
// CloudflareTunnel.
type tunnelConditionUpdate struct {
	// Observed is the tunnel snapshot this pass based its decisions on. The
	// helper refuses to write when the live object no longer matches its UID,
	// generation, or configuration mode.
	Observed *v1alpha1.CloudflareTunnel
	// Conditions holds the authored deltas for this pass only — never the
	// computed Ready condition and never entries carried from a cached read.
	// Non-authored Flareway entries are carried verbatim from the live object.
	// A nil slice performs ownership migration and the Ready clamp only.
	Conditions []metav1.Condition
	// Now is the transition timestamp for entries whose Status actually
	// changed this pass and for a derived Ready. Same-status authored entries
	// keep the live lastTransitionTime. A zero value falls back to
	// metav1.Now().
	Now metav1.Time
	// ReadyOverride forces an explicit lifecycle-policy Ready value (for
	// example ObserveOnly's Ready=False). It wins over derivation but never
	// over the unconditional clamp: an override cannot produce Ready=True
	// while an input is unmet. An authored Ready inside Conditions is treated
	// as the override when this field is nil.
	ReadyOverride *metav1.Condition
	// Validate is an optional caller guard re-evaluated against the fresh
	// live object on every attempt (for example the Gateway writer's
	// ownership checkpoint). A non-nil error aborts without writing.
	Validate func(*v1alpha1.CloudflareTunnel) error
}

// patchTunnelConditions commits CloudflareTunnel status.conditions under the
// shared flareway-tunnel-status manager as one optimistic-concurrency
// transaction: fresh read, identity check, verbatim carry of non-authored
// Flareway entries, in-document Ready derivation, then a resourceVersion-pinned
// status apply. A 409 restarts the attempt against the new live object; remote
// actions are never replayed. The write is skipped only when the merged
// Flareway set is semantically equal to live AND the shared manager already
// owns every Flareway condition type in the document — otherwise the apply
// doubles as the one-shot ownership claim. A legacy co-owner that never
// releases (a deleted Gateway, a Gateway-mode tunnel now in Direct mode) does
// not force a write every pass: once the shared manager covers the set, equal
// content means the commit is a no-op. The unconditional Ready clamp runs on
// every commit, including the claim-only one, so a torn (ConfigApplied=False,
// Ready=True) pair is repaired atomically while promotion is never folded into
// a claim.
func patchTunnelConditions(ctx context.Context, c client.Client, reader client.Reader, update tunnelConditionUpdate) error {
	if c == nil {
		return errors.New("tunnel conditions update requires a client")
	}
	if update.Observed == nil {
		return errors.New("tunnel conditions update requires an observed CloudflareTunnel")
	}
	if reader == nil {
		reader = c
	}
	now := update.Now
	if now.IsZero() {
		now = metav1.Now()
	}
	key := client.ObjectKeyFromObject(update.Observed)
	var lastErr error
	for attempt := 0; attempt < tunnelConditionMaxAttempts; attempt++ {
		var live v1alpha1.CloudflareTunnel
		if err := reader.Get(ctx, key, &live); err != nil {
			// A missing tunnel is a failed durability checkpoint, not a
			// successful commit: callers that invalidate before remote
			// mutation must not proceed on a deleted object. Top-level
			// Reconcile may IgnoreNotFound on its own read.
			return fmt.Errorf("read live CloudflareTunnel %s for conditions: %w", key, err)
		}
		if err := tunnelConditionIdentityCheck(update.Observed, &live); err != nil {
			return err
		}
		if update.Validate != nil {
			if err := update.Validate(&live); err != nil {
				return err
			}
		}
		merged := mergeTunnelConditions(&live, update.Conditions, update.ReadyOverride, now)
		if tunnelConditionsDeepEqual(live.Status.Conditions, merged) && tunnelSharedConditionCoverage(&live, merged) {
			return nil
		}
		apply, err := tunnelConditionsApply(&live, merged)
		if err != nil {
			return err
		}
		err = c.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(tunnelStatusFieldManager), client.ForceOwnership)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("apply CloudflareTunnel %s conditions: %w", key, err)
		}
		lastErr = err
	}
	return fmt.Errorf("apply CloudflareTunnel %s conditions: conflict after %d attempts: %w", key, tunnelConditionMaxAttempts, lastErr)
}

// tunnelConditionIdentityCheck enforces the shared Tier-1 precondition: the
// live object must still be the same tunnel (UID), the same spec revision
// (generation), and the same configuration mode the caller observed. Writer
// ownership gates are caller-specific and belong in tunnelConditionUpdate.Validate.
func tunnelConditionIdentityCheck(observed, live *v1alpha1.CloudflareTunnel) error {
	if live.UID != observed.UID {
		return fmt.Errorf("CloudflareTunnel %s/%s UID changed from %s to %s; aborting conditions write", observed.Namespace, observed.Name, observed.UID, live.UID)
	}
	if live.Generation != observed.Generation {
		return fmt.Errorf("CloudflareTunnel %s/%s generation changed from %d to %d; aborting conditions write", observed.Namespace, observed.Name, observed.Generation, live.Generation)
	}
	if mode := tunnelConfigurationMode(live); mode != tunnelConfigurationMode(observed) {
		return fmt.Errorf("CloudflareTunnel %s/%s configuration mode changed to %s; aborting conditions write", observed.Namespace, observed.Name, mode)
	}
	return nil
}

// mergeTunnelConditions overlays the authored deltas onto the live Flareway
// condition set. Non-authored Flareway entries are carried verbatim so a stale
// caller snapshot can neither restamp nor resurrect them. An authored entry
// whose Status matches live keeps the live lastTransitionTime; a changed
// Status keeps the caller-stamped transition time (falling back to now). An
// authored Ready is lifted out as the effective override; the derived Ready
// entry is appended last when one belongs in the document.
func mergeTunnelConditions(live *v1alpha1.CloudflareTunnel, authored []metav1.Condition, override *metav1.Condition, now metav1.Time) []metav1.Condition {
	authoredByType := make(map[string]metav1.Condition, len(authored))
	order := make([]string, 0, len(authored))
	inputAuthored := false
	for _, condition := range authored {
		if _, known := tunnelFlarewayConditionTypes[condition.Type]; !known {
			continue
		}
		if _, isInput := tunnelReadyInputConditions[condition.Type]; isInput {
			inputAuthored = true
		}
		if condition.Type == v1alpha1.CloudflareTunnelConditionReady {
			if override == nil {
				candidate := condition
				override = &candidate
			}
			continue
		}
		if _, exists := authoredByType[condition.Type]; !exists {
			order = append(order, condition.Type)
		}
		authoredByType[condition.Type] = condition
	}
	merged := make([]metav1.Condition, 0, len(live.Status.Conditions)+len(order)+1)
	consumed := make(map[string]struct{}, len(authoredByType))
	for _, condition := range live.Status.Conditions {
		if _, known := tunnelFlarewayConditionTypes[condition.Type]; !known {
			continue
		}
		if condition.Type == v1alpha1.CloudflareTunnelConditionReady {
			continue
		}
		update, found := authoredByType[condition.Type]
		if !found {
			merged = append(merged, condition)
			continue
		}
		consumed[condition.Type] = struct{}{}
		// An authored update whose nonzero observedGeneration is older than
		// the live entry describes a previous spec and is ignored; a zero
		// observedGeneration inherits the live value. Same-status updates
		// keep the live lastTransitionTime.
		if update.ObservedGeneration != 0 && condition.ObservedGeneration > update.ObservedGeneration {
			merged = append(merged, condition)
			continue
		}
		if update.ObservedGeneration == 0 {
			update.ObservedGeneration = condition.ObservedGeneration
		}
		if condition.Status == update.Status {
			update.LastTransitionTime = condition.LastTransitionTime
		} else if update.LastTransitionTime.IsZero() {
			update.LastTransitionTime = now
		}
		merged = append(merged, update)
	}
	for _, conditionType := range order {
		if _, done := consumed[conditionType]; done {
			continue
		}
		update := authoredByType[conditionType]
		if update.ObservedGeneration == 0 {
			update.ObservedGeneration = live.Generation
		}
		if update.LastTransitionTime.IsZero() {
			update.LastTransitionTime = now
		}
		merged = append(merged, update)
	}
	if ready, derived := deriveTunnelReadyCondition(live, merged, override, inputAuthored, now); derived {
		merged = append(merged, ready)
	}
	return merged
}

// deriveTunnelReadyCondition computes the Ready entry for the merged document.
// An explicit lifecycle override wins over derivation; otherwise Ready is
// derived whenever this pass authored an input, carried verbatim when it did
// not, and unconditionally clamped to False while any input is unmet. A live
// object without a Ready entry never has one invented for it unless this pass
// authored an input or an override. The second return reports whether a Ready
// entry belongs in the document at all.
func deriveTunnelReadyCondition(live *v1alpha1.CloudflareTunnel, merged []metav1.Condition, override *metav1.Condition, inputAuthored bool, now metav1.Time) (metav1.Condition, bool) {
	liveReady := gatewaystatus.FindCondition(live.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)
	inputsMet := gatewaystatus.ConditionTrue(merged, v1alpha1.CloudflareTunnelConditionTunnelReady) &&
		gatewaystatus.ConditionTrue(merged, v1alpha1.CloudflareTunnelConditionConfigApplied) &&
		gatewaystatus.ConditionTrue(merged, v1alpha1.CloudflareTunnelConditionDNSReady)
	if liveReady == nil && !inputAuthored && override == nil {
		return metav1.Condition{}, false
	}
	var ready metav1.Condition
	switch {
	case override != nil:
		ready = *override
		ready.Type = v1alpha1.CloudflareTunnelConditionReady
		if ready.ObservedGeneration == 0 {
			ready.ObservedGeneration = live.Generation
		}
	case !inputAuthored:
		// No input was authored this pass: carry the live Ready verbatim and
		// apply only the unconditional clamp. liveReady is non-nil here — the
		// early return above covered the absent case.
		ready = *liveReady
		if ready.Status == metav1.ConditionTrue && !inputsMet {
			ready.Status = metav1.ConditionFalse
			ready.Reason = "Pending"
			ready.Message = "TunnelReady, ConfigApplied, and DNSReady must all be True"
			ready.LastTransitionTime = now
		}
		return ready, true
	case inputsMet:
		ready = metav1.Condition{
			Type:               v1alpha1.CloudflareTunnelConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             "Ready",
			Message:            "Tunnel, data-plane configuration, and DNS are ready",
			ObservedGeneration: live.Generation,
			LastTransitionTime: now,
		}
	default:
		ready = metav1.Condition{
			Type:               v1alpha1.CloudflareTunnelConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "Pending",
			Message:            "TunnelReady, ConfigApplied, and DNSReady must all be True",
			ObservedGeneration: live.Generation,
			LastTransitionTime: now,
		}
	}
	if !inputsMet {
		ready.Status = metav1.ConditionFalse
		if ready.Reason == "" {
			ready.Reason = "Pending"
		}
		if ready.Message == "" {
			ready.Message = "TunnelReady, ConfigApplied, and DNSReady must all be True"
		}
	}
	if liveReady != nil && liveReady.Status == ready.Status {
		ready.LastTransitionTime = liveReady.LastTransitionTime
	} else if ready.LastTransitionTime.IsZero() {
		ready.LastTransitionTime = now
	}
	return ready, true
}

// tunnelConditionsDeepEqual compares only the Flareway condition set; external
// entries are outside the shared manager's ownership and never gate the skip.
func tunnelConditionsDeepEqual(live, merged []metav1.Condition) bool {
	liveSet := tunnelFlarewayConditionSet(live)
	mergedSet := tunnelFlarewayConditionSet(merged)
	if len(liveSet) != len(mergedSet) {
		return false
	}
	for conditionType, liveCondition := range liveSet {
		mergedCondition, found := mergedSet[conditionType]
		if !found || !tunnelConditionSemanticallyEqual(liveCondition, mergedCondition) {
			return false
		}
	}
	return true
}

func tunnelFlarewayConditionSet(conditions []metav1.Condition) map[string]metav1.Condition {
	set := make(map[string]metav1.Condition, len(conditions))
	for _, condition := range conditions {
		if _, known := tunnelFlarewayConditionTypes[condition.Type]; known {
			set[condition.Type] = condition
		}
	}
	return set
}

func tunnelConditionSemanticallyEqual(left, right metav1.Condition) bool {
	return left.Type == right.Type &&
		left.Status == right.Status &&
		left.Reason == right.Reason &&
		left.Message == right.Message &&
		left.ObservedGeneration == right.ObservedGeneration &&
		left.LastTransitionTime.Equal(&right.LastTransitionTime)
}

// tunnelSharedConditionCoverage reports whether the shared
// flareway-tunnel-status manager already owns every Flareway condition type
// present in the merged document. Ownership is positive coverage, not the
// absence of other owners: a legacy co-owner that can never release (a
// deleted Gateway, or a Gateway-mode tunnel that transitioned to Direct)
// must not force a write every pass once the shared manager has claimed the
// set. Foreign ownership of a custom condition type is outside the Flareway
// set and never affects the result.
func tunnelSharedConditionCoverage(live *v1alpha1.CloudflareTunnel, merged []metav1.Condition) bool {
	needed := make(map[string]struct{}, len(merged))
	for _, condition := range merged {
		if _, known := tunnelFlarewayConditionTypes[condition.Type]; known {
			needed[condition.Type] = struct{}{}
		}
	}
	for _, entry := range live.ManagedFields {
		if entry.Manager != tunnelStatusFieldManager || entry.FieldsV1 == nil {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			continue
		}
		status, _ := fields["f:status"].(map[string]any)
		conditions, _ := status["f:conditions"].(map[string]any)
		for key := range conditions {
			delete(needed, tunnelConditionKeyType(key))
		}
	}
	return len(needed) == 0
}

// tunnelConditionKeyType extracts the condition type from a managedFields map
// key of the form k:{"type":"Ready"}.
func tunnelConditionKeyType(key string) string {
	const prefix = `k:{"type":"`
	if !strings.HasPrefix(key, prefix) {
		return ""
	}
	rest := key[len(prefix):]
	if end := strings.IndexByte(rest, '"'); end >= 0 {
		return rest[:end]
	}
	return ""
}

// tunnelConditionsApply builds the status apply document carrying the merged
// Flareway condition set pinned to the live resourceVersion, which turns the
// apply into an optimistic-concurrency check.
func tunnelConditionsApply(live *v1alpha1.CloudflareTunnel, merged []metav1.Condition) (*unstructured.Unstructured, error) {
	entries := make([]any, 0, len(merged))
	for i := range merged {
		entry, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&merged[i])
		if err != nil {
			return nil, fmt.Errorf("convert CloudflareTunnel condition %s: %w", merged[i].Type, err)
		}
		entries = append(entries, entry)
	}
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "CloudflareTunnel",
		"metadata": map[string]any{
			"name":      live.Name,
			"namespace": live.Namespace,
		},
		"status": map[string]any{
			"conditions": entries,
		},
	}}
	apply.SetResourceVersion(live.ResourceVersion)
	return apply, nil
}
