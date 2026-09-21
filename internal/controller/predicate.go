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
	"maps"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// desiredStateChangedPredicate filters update events that cannot change the
// desired state a reconciler converges on: status-only writes. Unlike a bare
// predicate.GenerationChangedPredicate it still passes metadata lifecycle
// changes — finalizer edits, deletionTimestamp, labels, and annotations do not
// bump metadata.generation on custom resources, but reconcilers add finalizers
// and return, read labels/annotations as desired-state inputs, and run
// finalizer logic when deletionTimestamp is set. Dropping those events would
// stall first reconcile and deletion.
var desiredStateChangedPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldObject, newObject := e.ObjectOld, e.ObjectNew
		if oldObject == nil || newObject == nil {
			return false
		}
		return oldObject.GetGeneration() != newObject.GetGeneration() ||
			!maps.Equal(oldObject.GetLabels(), newObject.GetLabels()) ||
			!maps.Equal(oldObject.GetAnnotations(), newObject.GetAnnotations()) ||
			!slices.Equal(oldObject.GetFinalizers(), newObject.GetFinalizers()) ||
			!oldObject.GetDeletionTimestamp().Equal(newObject.GetDeletionTimestamp())
	},
}

var _ predicate.Predicate = desiredStateChangedPredicate
