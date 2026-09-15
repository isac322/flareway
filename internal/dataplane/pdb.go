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

package dataplane

import (
	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// BuildPDB keeps at least one dataplane Pod available during voluntary
// disruptions.
func BuildPDB(gw *ir.Gateway, _ *v1alpha1.GatewayClassConfig) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{APIVersion: policyv1.SchemeGroupVersion.String(), Kind: "PodDisruptionBudget"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            ResourceName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          resourceLabels(gw),
			Annotations:     map[string]string{ManagedByLabelKey: managedByValue(gw)},
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: ptr.To(intstr.FromInt32(1)),
			Selector:     &metav1.LabelSelector{MatchLabels: selectorLabels(gw)},
		},
	}
}
