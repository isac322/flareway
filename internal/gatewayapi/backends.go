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
*/

package gatewayapi

import (
	"crypto/x509"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"

	"github.com/isac322/flareway/internal/gatewayapi/status"
	"github.com/isac322/flareway/internal/ir"
)

func compileHTTPBackendRef(in Inputs, route *gatewayv1.HTTPRoute, ref gatewayv1.HTTPBackendRef) (ir.BackendRef, gatewayv1.RouteConditionReason, string) {
	return compileBackendObjectRef(in, route, ref.BackendObjectReference, ref.Weight, ref.Filters)
}

func compileBackendObjectRef(in Inputs, route *gatewayv1.HTTPRoute, ref gatewayv1.BackendObjectReference, weightValue *int32, filters []gatewayv1.HTTPRouteFilter) (ir.BackendRef, gatewayv1.RouteConditionReason, string) {
	namespace := route.Namespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}
	weight := int32(1)
	if weightValue != nil {
		weight = *weightValue
	}
	result := ir.BackendRef{Name: string(ref.Name), Namespace: namespace, Port: 0, Weight: weight}
	if ref.Port != nil {
		result.Port = int32(*ref.Port)
	}
	group := ""
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := "Service"
	if ref.Kind != nil && *ref.Kind != "" {
		kind = string(*ref.Kind)
	}
	if group != "" || kind != "Service" {
		return invalidBackend(result, gatewayv1.RouteReasonInvalidKind, fmt.Sprintf("backend %s/%s must reference a core Service", namespace, ref.Name))
	}
	if namespace != route.Namespace && !IsCrossNamespaceReferencePermitted(
		ReferenceSource{Group: gatewayv1.Group(gatewayGroup), Kind: gatewayv1.Kind("HTTPRoute"), Namespace: gatewayv1.Namespace(route.Namespace)},
		ReferenceTarget{Group: "", Kind: "Service", Namespace: gatewayv1.Namespace(namespace), Name: ref.Name},
		in.ReferenceGrants,
	) {
		return invalidBackend(result, gatewayv1.RouteReasonRefNotPermitted, fmt.Sprintf("backend Service %s/%s is not permitted by a ReferenceGrant", namespace, ref.Name))
	}
	service := findService(in.Services, namespace, string(ref.Name))
	if service == nil || service.Spec.Type == corev1.ServiceTypeExternalName {
		return invalidBackend(result, gatewayv1.RouteReasonBackendNotFound, fmt.Sprintf("backend Service %s/%s was not found", namespace, ref.Name))
	}
	if in.CloudflareAccount != nil {
		decision := authz.Evaluate(
			in.CloudflareAccount,
			namespaceByName(in.Namespaces, route.Namespace),
			authz.Request{Backend: &authz.BackendRequest{
				Namespace: namespaceByName(in.Namespaces, namespace),
				Kind:      v1alpha1.BackendKindService,
			}},
		)
		if !decision.Allowed {
			return invalidBackend(result, gatewayv1.RouteReasonRefNotPermitted, decision.Message)
		}
	}
	servicePort := findServicePort(service, result.Port)
	if servicePort == nil {
		return invalidBackend(result, gatewayv1.RouteReasonBackendNotFound, fmt.Sprintf("backend Service %s/%s has no port %d", namespace, ref.Name, result.Port))
	}
	if servicePort.AppProtocol != nil && !supportedAppProtocol(*servicePort.AppProtocol) {
		return invalidBackend(result, gatewayv1.RouteReasonUnsupportedProtocol, fmt.Sprintf("backend Service %s/%s uses unsupported appProtocol %q", namespace, ref.Name, *servicePort.AppProtocol))
	}
	if policy := winningBackendTLSPolicy(in.BackendTLSPolicies, service, servicePort); policy != nil {
		if message := backendTLSPolicyValidationError(in, policy); message != "" {
			return invalidBackend(result, gatewayv1.RouteReasonUnsupportedProtocol, message)
		}
	}
	result.ClusterName = clusterName(namespace, string(ref.Name), result.Port)
	backendFilters, filterInvalid := compileBackendFilters(filters)
	if filterInvalid != nil {
		result.Invalid = filterInvalid
		return result, gatewayv1.RouteReasonInvalidKind, filterInvalid.Message
	}
	result.Filters = backendFilters
	return result, gatewayv1.RouteReasonResolvedRefs, "references resolved"
}

func invalidBackend(backend ir.BackendRef, reason gatewayv1.RouteConditionReason, message string) (ir.BackendRef, gatewayv1.RouteConditionReason, string) {
	backend.Invalid = &ir.Reason{Code: string(reason), Message: message}
	return backend, reason, message
}

func compileBackendFilters(filters []gatewayv1.HTTPRouteFilter) (ir.BackendFilters, *ir.Reason) {
	result := ir.BackendFilters{}
	for _, filter := range filters {
		switch filter.Type {
		case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
			if filter.RequestHeaderModifier == nil {
				return result, unsupportedFilter("backend RequestHeaderModifier has no configuration")
			}
			result.RequestHeaders = compileHeaderModifier(*filter.RequestHeaderModifier)
		case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
			if filter.ResponseHeaderModifier == nil {
				return result, unsupportedFilter("backend ResponseHeaderModifier has no configuration")
			}
			result.ResponseHeaders = compileHeaderModifier(*filter.ResponseHeaderModifier)
		case gatewayv1.HTTPRouteFilterURLRewrite:
			if filter.URLRewrite == nil {
				return result, unsupportedFilter("backend URLRewrite has no configuration")
			}
			result.URLRewrite = compileURLRewrite(*filter.URLRewrite)
		default:
			return result, unsupportedFilter(fmt.Sprintf("uses unsupported backend filter type %q", filter.Type))
		}
	}
	return result, nil
}

func buildClusters(in Inputs, gateway *ir.Gateway) []ir.Cluster {
	backends := make(map[string]ir.BackendRef)
	for _, domain := range gateway.Domains {
		for _, virtualHost := range domain.VirtualHosts {
			for _, route := range virtualHost.Routes {
				for _, backend := range route.Backends {
					if backend.Invalid == nil {
						backends[backend.ClusterName] = backend
					}
				}
				for _, mirror := range route.Filters.Mirrors {
					if mirror.Backend.Invalid == nil {
						backends[mirror.Backend.ClusterName] = mirror.Backend
					}
				}
			}
		}
	}
	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}
	slices.Sort(names)
	clusters := make([]ir.Cluster, 0, len(names))
	for _, name := range names {
		backend := backends[name]
		service := findService(in.Services, backend.Namespace, backend.Name)
		if service == nil {
			continue
		}
		servicePort := findServicePort(service, backend.Port)
		if servicePort == nil {
			continue
		}
		cluster := ir.Cluster{Name: name, Namespace: backend.Namespace, Service: backend.Name, Port: backend.Port}
		if servicePort.AppProtocol != nil {
			cluster.AppProtocol = *servicePort.AppProtocol
		}
		cluster.Endpoints = extractEndpoints(in.EndpointSlices, service, servicePort)
		cluster.TLS = resolveBackendTLS(in, service, servicePort)
		clusters = append(clusters, cluster)
	}
	return clusters
}

func findService(services []corev1.Service, namespace, name string) *corev1.Service {
	for i := range services {
		if services[i].Namespace == namespace && services[i].Name == name {
			return &services[i]
		}
	}
	return nil
}

func findServicePort(service *corev1.Service, port int32) *corev1.ServicePort {
	for i := range service.Spec.Ports {
		if service.Spec.Ports[i].Port == port {
			return &service.Spec.Ports[i]
		}
	}
	return nil
}

func supportedAppProtocol(protocol string) bool {
	return protocol == "" || strings.EqualFold(protocol, "HTTP") || strings.EqualFold(protocol, "HTTPS") || protocol == "kubernetes.io/h2c" || strings.HasPrefix(protocol, "kubernetes.io/ws")
}

func clusterName(namespace, service string, port int32) string {
	return fmt.Sprintf("%s--%s--%d", namespace, service, port)
}

func extractEndpoints(endpointSlices []discoveryv1.EndpointSlice, service *corev1.Service, servicePort *corev1.ServicePort) []ir.Endpoint {
	result := make([]ir.Endpoint, 0)
	seen := make(map[ir.Endpoint]struct{})
	for i := range endpointSlices {
		slice := &endpointSlices[i]
		if slice.Namespace != service.Namespace || slice.Labels[discoveryv1.LabelServiceName] != service.Name {
			continue
		}
		port := endpointPort(slice, servicePort)
		if port == 0 {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				continue
			}
			for _, address := range endpoint.Addresses {
				resolved := ir.Endpoint{Address: address, Port: port}
				if _, exists := seen[resolved]; exists {
					continue
				}
				seen[resolved] = struct{}{}
				result = append(result, resolved)
			}
		}
	}
	slices.SortFunc(result, func(a, b ir.Endpoint) int {
		if cmp := strings.Compare(a.Address, b.Address); cmp != 0 {
			return cmp
		}
		return int(a.Port - b.Port)
	})
	return result
}

func endpointPort(slice *discoveryv1.EndpointSlice, servicePort *corev1.ServicePort) int32 {
	for _, port := range slice.Ports {
		if port.Port == nil {
			continue
		}
		if servicePort.Name != "" && port.Name != nil && *port.Name == servicePort.Name {
			return *port.Port
		}
	}
	if len(slice.Ports) == 1 && slice.Ports[0].Port != nil {
		return *slice.Ports[0].Port
	}
	return 0
}

func resolveBackendTLS(in Inputs, service *corev1.Service, servicePort *corev1.ServicePort) *ir.BackendTLS {
	winner := winningBackendTLSPolicy(in.BackendTLSPolicies, service, servicePort)
	if winner == nil || backendTLSPolicyValidationError(in, winner) != "" {
		return nil
	}
	validation := winner.Spec.Validation
	result := &ir.BackendTLS{ServerName: string(validation.Hostname)}
	for _, san := range validation.SubjectAltNames {
		value := string(san.Hostname)
		if san.Type == gatewayv1.URISubjectAltNameType {
			value = string(san.URI)
		}
		result.SubjectAltNames = append(result.SubjectAltNames, ir.SubjectAltName{Type: string(san.Type), Value: value})
	}
	if len(result.SubjectAltNames) == 0 {
		result.SubjectAltNames = []ir.SubjectAltName{{Type: string(gatewayv1.HostnameSubjectAltNameType), Value: result.ServerName}}
	}
	if validation.WellKnownCACertificates != nil {
		result.WellKnownCACertificates = string(*validation.WellKnownCACertificates)
		return result
	}
	for _, ref := range validation.CACertificateRefs {
		configMap := findConfigMap(in.ConfigMaps, winner.Namespace, string(ref.Name))
		bundle := configMapCABundle(configMap)
		if len(result.CACertificate) > 0 && result.CACertificate[len(result.CACertificate)-1] != '\n' {
			result.CACertificate = append(result.CACertificate, '\n')
		}
		result.CACertificate = append(result.CACertificate, bundle...)
	}
	return result
}

func winningBackendTLSPolicy(policies []gatewayv1.BackendTLSPolicy, service *corev1.Service, servicePort *corev1.ServicePort) *gatewayv1.BackendTLSPolicy {
	matches := matchingBackendTLSPolicies(policies, service, servicePort)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

func backendTLSPolicyValidationError(in Inputs, policy *gatewayv1.BackendTLSPolicy) string {
	validation := policy.Spec.Validation
	if validation.WellKnownCACertificates != nil {
		if *validation.WellKnownCACertificates != gatewayv1.WellKnownCACertificatesSystem {
			return fmt.Sprintf("BackendTLSPolicy %s/%s uses unsupported wellKnownCACertificates %q", policy.Namespace, policy.Name, *validation.WellKnownCACertificates)
		}
		return ""
	}
	if len(validation.CACertificateRefs) == 0 {
		return fmt.Sprintf("BackendTLSPolicy %s/%s has no CA certificate source", policy.Namespace, policy.Name)
	}
	for _, ref := range validation.CACertificateRefs {
		if ref.Group != "" || ref.Kind != "ConfigMap" {
			return fmt.Sprintf("BackendTLSPolicy %s/%s CA reference must be a core ConfigMap", policy.Namespace, policy.Name)
		}
		configMap := findConfigMap(in.ConfigMaps, policy.Namespace, string(ref.Name))
		bundle := configMapCABundle(configMap)
		if len(bundle) == 0 {
			return fmt.Sprintf("BackendTLSPolicy %s/%s CA ConfigMap %s is missing ca.crt", policy.Namespace, policy.Name, ref.Name)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(bundle) {
			return fmt.Sprintf("BackendTLSPolicy %s/%s CA ConfigMap %s contains malformed certificates", policy.Namespace, policy.Name, ref.Name)
		}
	}
	return ""
}

func matchingBackendTLSPolicies(policies []gatewayv1.BackendTLSPolicy, service *corev1.Service, servicePort *corev1.ServicePort) []*gatewayv1.BackendTLSPolicy {
	sectionMatches := make([]*gatewayv1.BackendTLSPolicy, 0)
	wholeServiceMatches := make([]*gatewayv1.BackendTLSPolicy, 0)
	for i := range policies {
		policy := &policies[i]
		if policy.Namespace != service.Namespace {
			continue
		}
		for _, target := range policy.Spec.TargetRefs {
			if target.Group != "" || target.Kind != "Service" || string(target.Name) != service.Name {
				continue
			}
			if target.SectionName != nil {
				if string(*target.SectionName) == servicePort.Name {
					sectionMatches = append(sectionMatches, policy)
				}
				continue
			}
			wholeServiceMatches = append(wholeServiceMatches, policy)
			break
		}
	}
	result := wholeServiceMatches
	if len(sectionMatches) > 0 {
		result = sectionMatches
	}
	slices.SortFunc(result, func(a, b *gatewayv1.BackendTLSPolicy) int {
		if cmp := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	return result
}

func findConfigMap(configMaps []corev1.ConfigMap, namespace, name string) *corev1.ConfigMap {
	for i := range configMaps {
		if configMaps[i].Namespace == namespace && configMaps[i].Name == name {
			return &configMaps[i]
		}
	}
	return nil
}

func configMapCABundle(configMap *corev1.ConfigMap) []byte {
	if configMap == nil {
		return nil
	}
	if value := configMap.Data["ca.crt"]; value != "" {
		return []byte(value)
	}
	return slices.Clone(configMap.BinaryData["ca.crt"])
}

func populateBackendTLSPolicyStatuses(in Inputs, gateway *ir.Gateway, statuses *Statuses, now metav1.Time) {
	type serviceReference struct {
		namespace string
		name      string
		port      int32
	}
	references := make(map[serviceReference]struct{})
	for _, domain := range gateway.Domains {
		for _, virtualHost := range domain.VirtualHosts {
			for _, route := range virtualHost.Routes {
				for _, backend := range route.Backends {
					references[serviceReference{namespace: backend.Namespace, name: backend.Name, port: backend.Port}] = struct{}{}
				}
				for _, mirror := range route.Filters.Mirrors {
					backend := mirror.Backend
					references[serviceReference{namespace: backend.Namespace, name: backend.Name, port: backend.Port}] = struct{}{}
				}
			}
		}
	}
	ordered := make([]serviceReference, 0, len(references))
	for reference := range references {
		ordered = append(ordered, reference)
	}
	slices.SortFunc(ordered, func(a, b serviceReference) int {
		if cmp := strings.Compare(a.namespace, b.namespace); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.name, b.name); cmp != 0 {
			return cmp
		}
		return int(a.port - b.port)
	})
	for _, reference := range ordered {
		service := findService(in.Services, reference.namespace, reference.name)
		if service == nil {
			continue
		}
		servicePort := findServicePort(service, reference.port)
		if servicePort == nil {
			continue
		}
		policies := matchingBackendTLSPolicies(in.BackendTLSPolicies, service, servicePort)
		if len(policies) == 0 {
			continue
		}
		winner := policies[0]
		for index, policy := range policies {
			if index > 0 {
				recordBackendTLSPolicyStatus(policy, gateway, statuses, now, false, gatewayv1.PolicyReasonConflicted, fmt.Sprintf("conflicts with older BackendTLSPolicy %s/%s", winner.Namespace, winner.Name), true, gatewayv1.BackendTLSPolicyReasonResolvedRefs, "references resolved")
				continue
			}
			message := backendTLSPolicyValidationError(in, winner)
			if message == "" {
				recordBackendTLSPolicyStatus(policy, gateway, statuses, now, true, gatewayv1.PolicyReasonAccepted, "policy accepted", true, gatewayv1.BackendTLSPolicyReasonResolvedRefs, "references resolved")
				continue
			}
			acceptedReason := gatewayv1.BackendTLSPolicyReasonNoValidCACertificate
			resolvedReason := gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef
			if strings.Contains(message, "wellKnownCACertificates") {
				acceptedReason = gatewayv1.PolicyReasonInvalid
				resolvedReason = gatewayv1.BackendTLSPolicyReasonInvalidKind
			} else if strings.Contains(message, "must be a core ConfigMap") {
				resolvedReason = gatewayv1.BackendTLSPolicyReasonInvalidKind
			}
			recordBackendTLSPolicyStatus(policy, gateway, statuses, now, false, acceptedReason, message, false, resolvedReason, message)
		}
	}
}

func recordBackendTLSPolicyStatus(policy *gatewayv1.BackendTLSPolicy, gateway *ir.Gateway, statuses *Statuses, now metav1.Time, accepted bool, acceptedReason gatewayv1.PolicyConditionReason, acceptedMessage string, resolved bool, resolvedReason gatewayv1.PolicyConditionReason, resolvedMessage string) {
	key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
	current, found := statuses.BackendTLSPolicies[key]
	if !found {
		current = policy.Status
	}
	ancestor := gatewayv1.PolicyAncestorStatus{
		AncestorRef: gatewayv1.ParentReference{
			Group:     new(gatewayv1.Group(gatewayGroup)),
			Kind:      new(gatewayv1.Kind("Gateway")),
			Namespace: new(gatewayv1.Namespace(gateway.Key.Namespace)),
			Name:      gatewayv1.ObjectName(gateway.Key.Name),
		},
		ControllerName: ControllerName,
		Conditions: []metav1.Condition{
			status.NewCondition(string(gatewayv1.PolicyConditionAccepted), conditionStatus(accepted), string(acceptedReason), acceptedMessage, policy.Generation, now),
			status.NewCondition(string(gatewayv1.BackendTLSPolicyConditionResolvedRefs), conditionStatus(resolved), string(resolvedReason), resolvedMessage, policy.Generation, now),
		},
	}
	current.Ancestors = status.ReplacePolicyAncestorStatuses(current.Ancestors, ControllerName, now, ancestor)
	statuses.BackendTLSPolicies[key] = current
}
