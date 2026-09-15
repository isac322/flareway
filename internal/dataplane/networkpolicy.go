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
	"sort"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// BuildNetworkPolicy isolates the dataplane while allowing listener traffic,
// node-origin health probes, operator metrics probes, xDS, DNS, and backends.
func BuildNetworkPolicy(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig, operatorNamespace string) *networkingv1.NetworkPolicy {
	if operatorNamespace == "" {
		operatorNamespace = DefaultOperatorNamespace
	}

	ingress := make([]networkingv1.NetworkPolicyIngressRule, 0, 3)
	if conformanceMode(gw, cfg) {
		listenerPorts := networkPorts(listenerEnvoyPorts(gw), corev1.ProtocolTCP)
		if len(listenerPorts) > 0 {
			// Only conformance mode exposes Envoy listener ports. Cloudflare
			// mode binds them to loopback for cloudflared-only ingress.
			ingress = append(ingress, networkingv1.NetworkPolicyIngressRule{Ports: listenerPorts})
		}
	}
	// Kubelet probes commonly originate from node addresses, which Kubernetes
	// NetworkPolicy cannot select. Limit that unavoidable allowance to 19001.
	ingress = append(ingress, networkingv1.NetworkPolicyIngressRule{
		Ports: networkPorts([]int32{EnvoyHealthPort}, corev1.ProtocolTCP),
	})
	if !conformanceMode(gw, cfg) {
		ingress = append(ingress, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": operatorNamespace,
			}}}},
			Ports: networkPorts([]int32{CloudflaredMetricsPort}, corev1.ProtocolTCP),
		})
	}

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": operatorNamespace,
			}}}},
			Ports: networkPorts([]int32{XDSPort}, corev1.ProtocolTCP),
		},
		{Ports: append(networkPorts([]int32{53}, corev1.ProtocolUDP), networkPorts([]int32{53}, corev1.ProtocolTCP)...)},
	}
	if backendPorts := clusterPorts(gw); len(backendPorts) > 0 {
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{Ports: networkPorts(backendPorts, corev1.ProtocolTCP)})
	}
	if !conformanceMode(gw, cfg) {
		// cloudflared connects to the edge over QUIC or HTTP/2. TCP 443 also
		// supports certificate and ancillary HTTPS requests.
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(7844))},
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(7844))},
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(443))},
		}})
	}

	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: networkingv1.SchemeGroupVersion.String(), Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            ResourceName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          resourceLabels(gw),
			Annotations:     map[string]string{ManagedByLabelKey: managedByValue(gw)},
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels(gw)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func listenerEnvoyPorts(gw *ir.Gateway) []int32 {
	ports := make([]int32, 0, len(gw.Listeners))
	for _, listener := range gw.Listeners {
		ports = append(ports, listener.EnvoyPort)
	}
	return uniqueSortedPorts(ports)
}

func clusterPorts(gw *ir.Gateway) []int32 {
	ports := make([]int32, 0, len(gw.Clusters))
	for _, cluster := range gw.Clusters {
		if len(cluster.Endpoints) == 0 {
			ports = append(ports, cluster.Port)
			continue
		}
		for _, endpoint := range cluster.Endpoints {
			ports = append(ports, endpoint.Port)
		}
	}
	return uniqueSortedPorts(ports)
}

func uniqueSortedPorts(ports []int32) []int32 {
	seen := make(map[int32]struct{}, len(ports))
	unique := make([]int32, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		unique = append(unique, port)
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })
	return unique
}

func networkPorts(ports []int32, protocol corev1.Protocol) []networkingv1.NetworkPolicyPort {
	result := make([]networkingv1.NetworkPolicyPort, 0, len(ports))
	for _, port := range ports {
		result = append(result, networkingv1.NetworkPolicyPort{
			Protocol: ptr.To(protocol),
			Port:     ptr.To(intstr.FromInt32(port)),
		})
	}
	return result
}
