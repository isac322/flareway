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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// BuildService returns the Service that exposes Gateway listeners to the
// conformance runner. Each declared listener port targets its Envoy bind port.
// It returns nil in Cloudflare mode: Envoy binds those listeners to loopback
// ports that only the co-located cloudflared can reach, so a Service would
// publish ports that refuse every connection.
func BuildService(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) *corev1.Service {
	if !conformanceMode(gw, cfg) {
		return nil
	}
	ports := make([]corev1.ServicePort, 0, len(gw.Listeners))
	seen := make(map[int32]struct{}, len(gw.Listeners))
	for i, listener := range gw.Listeners {
		if listener.Port <= 0 {
			// Listeners left over from removal can carry a zero port; a
			// non-positive Service port is rejected by the API server.
			continue
		}
		if _, exists := seen[listener.Port]; exists {
			continue
		}
		seen[listener.Port] = struct{}{}
		ports = append(ports, corev1.ServicePort{
			Name:       listenerPortName(i),
			Protocol:   corev1.ProtocolTCP,
			Port:       listener.Port,
			TargetPort: intstr.FromInt32(listener.EnvoyPort),
		})
	}
	selector := selectorLabels(gw)
	if len(ports) == 0 {
		// Services with no ports are rejected by the API server. Keep the
		// invalid Gateway fail-closed with a ClusterIP Service that has no
		// selector and therefore no automatically managed endpoints.
		ports = []corev1.ServicePort{{
			Name:       "health",
			Protocol:   corev1.ProtocolTCP,
			Port:       EnvoyHealthPort,
			TargetPort: intstr.FromInt32(EnvoyHealthPort),
		}}
		selector = nil
	}

	serviceType := corev1.ServiceTypeClusterIP
	if selector != nil {
		serviceType = corev1.ServiceTypeLoadBalancer
		if cfg != nil && cfg.Spec.Conformance.ServiceType != "" {
			serviceType = cfg.Spec.Conformance.ServiceType
		}
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            ResourceName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          mergeMetadata(gw.InfrastructureLabels, resourceLabels(gw)),
			Annotations:     mergeMetadata(gw.InfrastructureAnnotations, map[string]string{ManagedByLabelKey: managedByValue(gw)}),
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType,
			Selector: selector,
			Ports:    ports,
		},
	}
}
