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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// dataplaneScheduling resolves the pod placement fields for the dataplane
// Deployment. User-provided values are deep-copied so the shared
// GatewayClassConfig (informer-cached in conformance mode) is never mutated.
// When the user does not configure pod anti-affinity, a soft hostname spread
// term is injected so replicas prefer distinct nodes. An explicit empty
// podAntiAffinity ({}) opts out. Term-less affinity objects are normalized to
// nil because server-side apply cannot remove previously applied terms with
// an empty object.
func dataplaneScheduling(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (map[string]string, []corev1.Toleration, *corev1.Affinity, []corev1.TopologySpreadConstraint) {
	if cfg == nil {
		return nil, nil, &corev1.Affinity{PodAntiAffinity: defaultPodAntiAffinity(gw)}, nil
	}
	scheduling := cfg.Spec.Scheduling.DeepCopy()
	affinity := scheduling.Affinity
	if affinity == nil {
		affinity = &corev1.Affinity{}
	}
	if nodeAffinity := affinity.NodeAffinity; nodeAffinity != nil &&
		nodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil &&
		len(nodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
		affinity.NodeAffinity = nil
	}
	if podAffinity := affinity.PodAffinity; podAffinity != nil &&
		len(podAffinity.RequiredDuringSchedulingIgnoredDuringExecution) == 0 &&
		len(podAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
		affinity.PodAffinity = nil
	}
	if antiAffinity := affinity.PodAntiAffinity; antiAffinity == nil {
		affinity.PodAntiAffinity = defaultPodAntiAffinity(gw)
	} else if len(antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) == 0 &&
		len(antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
		affinity.PodAntiAffinity = nil
	}
	if affinity.NodeAffinity == nil && affinity.PodAffinity == nil && affinity.PodAntiAffinity == nil {
		affinity = nil
	}
	return scheduling.NodeSelector, scheduling.Tolerations, affinity, scheduling.TopologySpreadConstraints
}

// defaultPodAntiAffinity spreads dataplane replicas across nodes. The selector
// matches only stable identity labels (never the config-hash label) and
// matchLabelKeys scopes each term to pods of the same revision.
func defaultPodAntiAffinity(gw *ir.Gateway) *corev1.PodAntiAffinity {
	return &corev1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
			{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					TopologyKey:    corev1.LabelHostname,
					MatchLabelKeys: []string{appsv1.DefaultDeploymentUniqueLabelKey},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: selectorLabels(gw),
					},
				},
			},
		},
	}
}
