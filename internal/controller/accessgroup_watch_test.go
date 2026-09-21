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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// A dependency change must enqueue dependent AccessGroups in every namespace:
// CloudflareAccount grants permit cross-namespace references, so an
// AccessGroup in tenant-a may reference a dependency living in platform.
func TestAccessGroupWatchEnqueuesCrossNamespaceDependents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	dependent := types.NamespacedName{Namespace: "tenant-a", Name: "dependent-group"}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(&v1alpha1.AccessGroup{ObjectMeta: metav1.ObjectMeta{Name: dependent.Name, Namespace: dependent.Namespace}}).
		Build()
	reconciler := &AccessGroupReconciler{Client: kube, Scheme: scheme}

	crossDep := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "posture-rule", Namespace: "platform"}}
	if requests := reconciler.groupsForDependency(ctx, crossDep); !accessGroupRequestsContain(requests, dependent) {
		t.Fatalf("groupsForDependency(cross-namespace dependency) = %v, want a request for %s", requests, dependent)
	}

	localDep := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "posture-rule", Namespace: "tenant-a"}}
	if requests := reconciler.groupsForDependency(ctx, localDep); !accessGroupRequestsContain(requests, dependent) {
		t.Fatalf("groupsForDependency(same-namespace dependency) = %v, want a request for %s", requests, dependent)
	}
}

func accessGroupRequestsContain(requests []reconcile.Request, name types.NamespacedName) bool {
	for _, request := range requests {
		if request.NamespacedName == name {
			return true
		}
	}
	return false
}
