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

package observability

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Event reasons emitted for actionable controller state transitions.
const (
	EventReasonConflict        = "Conflict"
	EventReasonCleanupBlocked  = "CleanupBlocked"
	EventReasonSecurityBlocked = "SecurityBlocked"
)

var eventMessages = map[string]string{
	EventReasonConflict:        "Ownership or desired-state conflict detected",
	EventReasonCleanupBlocked:  "Cleanup is blocked by outstanding dependencies",
	EventReasonSecurityBlocked: "The requested operation was denied by authorization policy",
}

// EmitConditionTransitions emits warning Events only when an object enters one
// of Flareway's operator-actionable states. Condition messages are deliberately
// excluded because upstream API errors can contain sensitive response details.
func EmitConditionTransitions(recorder record.EventRecorder, object client.Object, before, after runtime.Object) {
	if recorder == nil || object == nil || after == nil {
		return
	}
	oldStates := eventStates(before)
	newStates := eventStates(after)
	for _, reason := range []string{EventReasonConflict, EventReasonCleanupBlocked, EventReasonSecurityBlocked} {
		if newStates[reason] && !oldStates[reason] {
			recorder.Event(object, corev1.EventTypeWarning, reason, eventMessages[reason])
		}
	}
}

func eventStates(object runtime.Object) map[string]bool {
	states := map[string]bool{}
	if object == nil {
		return states
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return states
	}
	conditionSets := make([][]any, 0, 2)
	if conditions, found, err := unstructured.NestedSlice(raw, "status", "conditions"); err == nil && found {
		conditionSets = append(conditionSets, conditions)
	}
	if listeners, found, err := unstructured.NestedSlice(raw, "status", "listeners"); err == nil && found {
		for _, item := range listeners {
			listener, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if conditions, found, err := unstructured.NestedSlice(listener, "conditions"); err == nil && found {
				conditionSets = append(conditionSets, conditions)
			}
		}
	}
	for _, conditions := range conditionSets {
		for _, item := range conditions {
			condition, ok := item.(map[string]any)
			if !ok {
				continue
			}
			conditionType, _, _ := unstructured.NestedString(condition, "type")
			status, _, _ := unstructured.NestedString(condition, "status")
			reason, _, _ := unstructured.NestedString(condition, "reason")
			message, _, _ := unstructured.NestedString(condition, "message")
			if ((conditionType == EventReasonConflict || conditionType == "Conflicted") && status == string(corev1.ConditionTrue)) || reason == EventReasonConflict {
				states[EventReasonConflict] = true
			}
			if conditionType == EventReasonCleanupBlocked && status == string(corev1.ConditionTrue) {
				states[EventReasonCleanupBlocked] = true
			}
			authorizationDenied := reason == "RefNotPermitted" ||
				(reason == "UnsupportedValue" && strings.Contains(strings.ToLower(message), "not granted"))
			if status == string(corev1.ConditionFalse) && authorizationDenied {
				states[EventReasonSecurityBlocked] = true
			}
		}
	}
	return states
}
