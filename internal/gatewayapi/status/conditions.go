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

This file adapts condition merging from cfgate/cfgate
internal/controller/status/conditions.go at v0.2.0-alpha.5 and controller-entry
preservation from internal/controller/httproute_controller.go at the same
version, Copyright cfgate Authors, licensed under Apache-2.0.
*/

// Package status provides deterministic helpers for merging Kubernetes and
// Gateway API status entries without disturbing fields owned by other
// controllers.
package status

import (
	"reflect"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// MaxConditionMessageLength is the maximum Kubernetes condition message size.
const MaxConditionMessageLength = 32768

// NewCondition constructs a condition using the caller-supplied transition
// time. Supplying the reconciliation timestamp explicitly keeps all conditions
// produced by one reconciliation deterministic.
func NewCondition(
	conditionType string,
	conditionStatus metav1.ConditionStatus,
	reason string,
	message string,
	observedGeneration int64,
	transitionTime metav1.Time,
) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            truncateConditionMessage(message),
		ObservedGeneration: observedGeneration,
		LastTransitionTime: transitionTime,
	}
}

// MergeConditions merges updates by condition type without modifying the input
// slice. Existing condition order is retained, new types are appended in update
// order, and the last update for a duplicate type wins.
//
// LastTransitionTime changes only when Status changes. An update whose nonzero
// ObservedGeneration is older than the stored generation is ignored, as
// required by Gateway API status ownership rules. A zero ObservedGeneration
// inherits the previous value.
func MergeConditions(
	conditions []metav1.Condition,
	transitionTime metav1.Time,
	updates ...metav1.Condition,
) []metav1.Condition {
	if len(updates) == 0 {
		return slices.Clone(conditions)
	}

	updateOrder := make([]string, 0, len(updates))
	updatesByType := make(map[string]metav1.Condition, len(updates))
	for _, update := range updates {
		if _, exists := updatesByType[update.Type]; !exists {
			updateOrder = append(updateOrder, update.Type)
		}
		updatesByType[update.Type] = update
	}

	result := make([]metav1.Condition, 0, len(conditions)+len(updatesByType))
	consumed := make(map[string]struct{}, len(updatesByType))
	for _, previous := range conditions {
		update, found := updatesByType[previous.Type]
		if !found {
			result = append(result, previous)
			continue
		}

		consumed[previous.Type] = struct{}{}
		if update.ObservedGeneration != 0 && previous.ObservedGeneration > update.ObservedGeneration {
			result = append(result, previous)
			continue
		}

		result = append(result, mergeCondition(previous, update, transitionTime))
	}

	for _, conditionType := range updateOrder {
		if _, exists := consumed[conditionType]; exists {
			continue
		}
		update := updatesByType[conditionType]
		update.Message = truncateConditionMessage(update.Message)
		update.LastTransitionTime = transitionTime
		result = append(result, update)
	}

	return result
}

// SetCondition adds or updates one condition.
func SetCondition(
	conditions []metav1.Condition,
	transitionTime metav1.Time,
	condition metav1.Condition,
) []metav1.Condition {
	return MergeConditions(conditions, transitionTime, condition)
}

// FindCondition returns the condition with conditionType, or nil when absent.
func FindCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// RemoveCondition returns a copy of conditions without conditionType.
func RemoveCondition(conditions []metav1.Condition, conditionType string) []metav1.Condition {
	result := make([]metav1.Condition, 0, len(conditions))
	for _, condition := range conditions {
		if condition.Type != conditionType {
			result = append(result, condition)
		}
	}
	return result
}

// ConditionTrue reports whether conditionType is present and True.
func ConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	condition := FindCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// ConditionFalse reports whether conditionType is present and False.
func ConditionFalse(conditions []metav1.Condition, conditionType string) bool {
	condition := FindCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionFalse
}

// ConditionUnknown reports whether conditionType is absent or Unknown.
func ConditionUnknown(conditions []metav1.Condition, conditionType string) bool {
	condition := FindCondition(conditions, conditionType)
	return condition == nil || condition.Status == metav1.ConditionUnknown
}

// ReplaceRouteParentStatuses replaces only entries owned by controllerName.
// Entries written by other controllers retain their order and contents. For a
// replacement with the same ParentRef, conditions are merged so unchanged
// condition statuses retain their transition times.
func ReplaceRouteParentStatuses(
	parents []gatewayv1.RouteParentStatus,
	controllerName gatewayv1.GatewayController,
	transitionTime metav1.Time,
	replacements ...gatewayv1.RouteParentStatus,
) []gatewayv1.RouteParentStatus {
	owned := make([]gatewayv1.RouteParentStatus, 0, len(parents))
	result := make([]gatewayv1.RouteParentStatus, 0, len(parents)+len(replacements))
	for _, parent := range parents {
		if parent.ControllerName == controllerName {
			owned = append(owned, parent)
			continue
		}
		result = append(result, parent)
	}

	for _, replacement := range replacements {
		replacement.ControllerName = controllerName
		if previous := findRouteParentStatus(owned, replacement.ParentRef); previous != nil {
			replacement.Conditions = MergeConditions(previous.Conditions, transitionTime, replacement.Conditions...)
		} else {
			replacement.Conditions = MergeConditions(nil, transitionTime, replacement.Conditions...)
		}
		result = append(result, replacement)
	}

	return result
}

// ReplacePolicyAncestorStatuses replaces only entries owned by controllerName.
// Entries written by other controllers retain their order and contents. For a
// replacement with the same AncestorRef, conditions are merged so unchanged
// condition statuses retain their transition times.
func ReplacePolicyAncestorStatuses(
	ancestors []gatewayv1.PolicyAncestorStatus,
	controllerName gatewayv1.GatewayController,
	transitionTime metav1.Time,
	replacements ...gatewayv1.PolicyAncestorStatus,
) []gatewayv1.PolicyAncestorStatus {
	owned := make([]gatewayv1.PolicyAncestorStatus, 0, len(ancestors))
	result := make([]gatewayv1.PolicyAncestorStatus, 0, len(ancestors)+len(replacements))
	for _, ancestor := range ancestors {
		if ancestor.ControllerName == controllerName {
			owned = append(owned, ancestor)
			continue
		}
		result = append(result, ancestor)
	}

	for _, replacement := range replacements {
		replacement.ControllerName = controllerName
		if previous := findPolicyAncestorStatus(owned, replacement.AncestorRef); previous != nil {
			replacement.Conditions = MergeConditions(previous.Conditions, transitionTime, replacement.Conditions...)
		} else {
			replacement.Conditions = MergeConditions(nil, transitionTime, replacement.Conditions...)
		}
		result = append(result, replacement)
	}

	return result
}

func mergeCondition(previous, update metav1.Condition, transitionTime metav1.Time) metav1.Condition {
	update.Message = truncateConditionMessage(update.Message)
	if update.ObservedGeneration == 0 {
		update.ObservedGeneration = previous.ObservedGeneration
	}
	if previous.Status == update.Status {
		update.LastTransitionTime = previous.LastTransitionTime
	} else {
		update.LastTransitionTime = transitionTime
	}
	return update
}

func findRouteParentStatus(
	parents []gatewayv1.RouteParentStatus,
	parentRef gatewayv1.ParentReference,
) *gatewayv1.RouteParentStatus {
	for i := range parents {
		if reflect.DeepEqual(parents[i].ParentRef, parentRef) {
			return &parents[i]
		}
	}
	return nil
}

func findPolicyAncestorStatus(
	ancestors []gatewayv1.PolicyAncestorStatus,
	ancestorRef gatewayv1.ParentReference,
) *gatewayv1.PolicyAncestorStatus {
	for i := range ancestors {
		if reflect.DeepEqual(ancestors[i].AncestorRef, ancestorRef) {
			return &ancestors[i]
		}
	}
	return nil
}

func truncateConditionMessage(message string) string {
	if len(message) <= MaxConditionMessageLength {
		return message
	}
	return message[:MaxConditionMessageLength-3] + "..."
}
