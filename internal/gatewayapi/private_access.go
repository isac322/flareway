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
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
)

// CompilePrivateDestinations resolves every private destination through a
// platform route object. Caller-provided CIDRs can only narrow a referenced
// NetworkRoute and can never create an independent destination.
func CompilePrivateDestinations(in Inputs, application *v1alpha1.AccessApplication) AccessApplicationCompilation {
	result := AccessApplicationCompilation{Accepted: true, Reason: "Accepted", Message: "Private destinations are valid"}
	if application == nil {
		return result
	}
	hasPrivate := false
	for _, destination := range application.Spec.Destinations {
		hasPrivate = hasPrivate || destination.Type == v1alpha1.AccessApplicationDestinationPrivate
	}
	if !hasPrivate {
		return result
	}
	if in.CloudflareTunnel != nil && in.CloudflareTunnel.Status.DeletedAt != nil {
		return accessLossFailure("CloudflareTunnel is remotely deleted and private destinations are unavailable while it drains", AccessTargetLossTunnel)
	}
	if in.CloudflareAccount == nil {
		return accessFailure("TargetNotFound", "CloudflareAccount is required for private destinations")
	}
	applicationNamespace := namespaceByName(in.Namespaces, application.Namespace)
	if applicationNamespace == nil {
		return accessFailure("TargetNotFound", fmt.Sprintf("Namespace %q was not found", application.Namespace))
	}
	seenDestination := make(map[string]struct{})
	seenAncestor := make(map[string]struct{})
	for index, destination := range application.Spec.Destinations {
		if destination.Type != v1alpha1.AccessApplicationDestinationPrivate {
			continue
		}
		if destination.Private == nil {
			return accessFailure("Invalid", fmt.Sprintf("destinations[%d].private is required", index))
		}
		private := destination.Private
		if (private.NetworkRouteRef == nil) == (private.HostnameRouteRef == nil) {
			return accessFailure("Invalid", fmt.Sprintf("destinations[%d].private must reference exactly one route", index))
		}
		if private.PortRange == "" {
			return accessFailure("Invalid", fmt.Sprintf("destinations[%d].private.portRange is required", index))
		}

		if private.NetworkRouteRef != nil {
			route := networkRouteByName(in.NetworkRoutes, application.Namespace, private.NetworkRouteRef.Name)
			if route == nil {
				return accessLossFailure(fmt.Sprintf("NetworkRoute %s/%s was not found", application.Namespace, private.NetworkRouteRef.Name), AccessTargetLossNetworkRoute)
			}
			if !route.DeletionTimestamp.IsZero() {
				return accessLossFailure(fmt.Sprintf("NetworkRoute %s/%s is deleting", route.Namespace, route.Name), AccessTargetLossNetworkRoute)
			}
			if failure := authorizePrivateRoute(in, application, applicationNamespace, route.Namespace, route.Spec.AccountRef.Name, route.Spec.AllowedNamespaces, authz.PrivateRouteNetwork, route.Labels); failure != nil {
				return *failure
			}
			if !networkRouteAppliedCurrent(route) {
				return accessLossFailure(fmt.Sprintf("NetworkRoute %s/%s is not ready", route.Namespace, route.Name), AccessTargetLossNetworkRoute)
			}
			cidr, err := resolvedPrivateCIDR(route.Status.Applied.Network, private.CIDR)
			if err != nil {
				return accessFailure("RefNotPermitted", fmt.Sprintf("NetworkRoute %s/%s: %v", route.Namespace, route.Name, err))
			}
			appendCompiledDestination(&result, seenDestination, AccessDestination{
				Type: v1alpha1.AccessApplicationDestinationPrivate, CIDR: cidr, PortRange: private.PortRange,
				L4Protocol: cloneAccessL4Protocol(private.L4Protocol), VNetID: route.Status.Applied.VirtualNetworkID,
			})
			appendAccessAncestor(&result, seenAncestor, AccessAncestor{Group: v1alpha1.Group, Kind: "NetworkRoute", Namespace: route.Namespace, Name: route.Name})
			continue
		}

		route := hostnameRouteByName(in.HostnameRoutes, application.Namespace, private.HostnameRouteRef.Name)
		if route == nil {
			return accessLossFailure(fmt.Sprintf("HostnameRoute %s/%s was not found", application.Namespace, private.HostnameRouteRef.Name), AccessTargetLossHostnameRoute)
		}
		if !route.DeletionTimestamp.IsZero() {
			return accessLossFailure(fmt.Sprintf("HostnameRoute %s/%s is deleting", route.Namespace, route.Name), AccessTargetLossHostnameRoute)
		}
		if failure := authorizePrivateRoute(in, application, applicationNamespace, route.Namespace, route.Spec.AccountRef.Name, route.Spec.AllowedNamespaces, authz.PrivateRouteHostname, route.Labels); failure != nil {
			return *failure
		}
		if !hostnameRouteAppliedCurrent(route) {
			return accessLossFailure(fmt.Sprintf("HostnameRoute %s/%s is not ready", route.Namespace, route.Name), AccessTargetLossHostnameRoute)
		}
		appendCompiledDestination(&result, seenDestination, AccessDestination{
			Type: v1alpha1.AccessApplicationDestinationPrivate, Hostname: normalizePrivateHostname(route.Status.Applied.Hostname), PortRange: private.PortRange,
			L4Protocol: cloneAccessL4Protocol(private.L4Protocol),
		})
		appendAccessAncestor(&result, seenAncestor, AccessAncestor{Group: v1alpha1.Group, Kind: "HostnameRoute", Namespace: route.Namespace, Name: route.Name})
	}
	result.OriginJWTEnforced = false
	sortAccessCompilation(&result)
	return result
}

func cloneAccessL4Protocol(value *v1alpha1.AccessL4Protocol) *v1alpha1.AccessL4Protocol {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func authorizePrivateRoute(
	in Inputs,
	application *v1alpha1.AccessApplication,
	applicationNamespace *corev1.Namespace,
	routeNamespace, routeAccount string,
	allowed v1alpha1.AllowedNamespaces,
	kind authz.PrivateRouteKind,
	routeLabels map[string]string,
) *AccessApplicationCompilation {
	if routeAccount != in.CloudflareAccount.Name {
		failure := accessFailure("RefNotPermitted", fmt.Sprintf("%s accountRef %q does not match AccessApplication account %q", kind, routeAccount, in.CloudflareAccount.Name))
		return &failure
	}
	if application.Spec.AccountRef.Name != routeAccount {
		failure := accessFailure("RefNotPermitted", fmt.Sprintf("AccessApplication accountRef %q does not match %s account %q", application.Spec.AccountRef.Name, kind, routeAccount))
		return &failure
	}
	if !allowedNamespace(routeNamespace, applicationNamespace, allowed) {
		failure := accessFailure("RefNotPermitted", fmt.Sprintf("%s allowedNamespaces does not permit namespace %q", kind, application.Namespace))
		return &failure
	}
	decision := authz.Evaluate(in.CloudflareAccount, applicationNamespace, authz.Request{
		Exposure:     v1alpha1.ExposurePrivate,
		PrivateRoute: &authz.PrivateRouteRequest{Kind: kind, Labels: routeLabels},
	})
	if !decision.Allowed {
		failure := accessFailure(decision.Reason, decision.Message)
		return &failure
	}
	return nil
}

func allowedNamespace(routeNamespace string, namespace *corev1.Namespace, allowed v1alpha1.AllowedNamespaces) bool {
	from := allowed.From
	if from == "" {
		from = v1alpha1.AllowedNamespaceFromSame
	}
	switch from {
	case v1alpha1.AllowedNamespaceFromSame:
		return routeNamespace == namespace.Name
	case v1alpha1.AllowedNamespaceFromAll:
		return true
	case v1alpha1.AllowedNamespaceFromSelector:
		if allowed.Selector == nil {
			return false
		}
		selector, err := metav1.LabelSelectorAsSelector(allowed.Selector)
		return err == nil && selector.Matches(labels.Set(namespace.Labels))
	default:
		return false
	}
}

func resolvedPrivateCIDR(routeCIDR, requestedCIDR string) (string, error) {
	route, err := netip.ParsePrefix(routeCIDR)
	if err != nil {
		return "", fmt.Errorf("route network %q is invalid", routeCIDR)
	}
	route = route.Masked()
	if requestedCIDR == "" {
		return route.String(), nil
	}
	requested, err := netip.ParsePrefix(requestedCIDR)
	if err != nil {
		return "", fmt.Errorf("requested CIDR %q is invalid", requestedCIDR)
	}
	requested = requested.Masked()
	if route.Addr().BitLen() != requested.Addr().BitLen() || route.Bits() > requested.Bits() || !route.Contains(requested.Addr()) {
		return "", fmt.Errorf("requested CIDR %s is not contained by route %s", requested, route)
	}
	return requested.String(), nil
}

func privateListenerVNetID(in Inputs, listenerName string) string {
	if in.CloudflareTunnel == nil || in.CloudflareTunnel.Status.DeletedAt != nil {
		return ""
	}
	vnetName := ""
	for _, listener := range in.CloudflareTunnel.Spec.Listeners {
		if string(listener.Name) == listenerName && listener.VirtualNetworkRef != nil {
			vnetName = listener.VirtualNetworkRef.Name
			break
		}
	}
	for index := range in.VirtualNetworks {
		vnet := &in.VirtualNetworks[index]
		if vnet.Namespace != in.CloudflareTunnel.Namespace ||
			vnet.Spec.AccountRef.Name != in.CloudflareTunnel.Spec.AccountRef.Name ||
			vnet.Status.VirtualNetworkID == "" || vnet.Status.ObservedGeneration != vnet.Generation ||
			!acceptedForGeneration(vnet.Status.Conditions, vnet.Generation) {
			continue
		}
		if (vnetName != "" && vnet.Name == vnetName) || (vnetName == "" && vnet.Spec.IsDefault) {
			return vnet.Status.VirtualNetworkID
		}
	}
	return ""
}

func networkRouteAppliedCurrent(route *v1alpha1.NetworkRoute) bool {
	return route != nil && route.DeletionTimestamp.IsZero() && route.Status.RouteID != "" &&
		route.Status.ObservedGeneration == route.Generation &&
		route.Status.Applied.ObservedGeneration == route.Generation &&
		route.Status.Applied.Network != "" && route.Status.Applied.TunnelID != "" &&
		route.Status.Applied.VirtualNetworkID != "" && acceptedForGeneration(route.Status.Conditions, route.Generation)
}

func hostnameRouteAppliedCurrent(route *v1alpha1.HostnameRoute) bool {
	return route != nil && route.DeletionTimestamp.IsZero() && route.Status.RouteID != "" &&
		route.Status.ObservedGeneration == route.Generation &&
		route.Status.Applied.ObservedGeneration == route.Generation &&
		route.Status.Applied.Hostname != "" && route.Status.Applied.TunnelID != "" &&
		acceptedForGeneration(route.Status.Conditions, route.Generation)
}

func acceptedForGeneration(conditions []metav1.Condition, generation int64) bool {
	for _, condition := range conditions {
		if condition.Type == v1alpha1.PrivateNetworkConditionAccepted {
			return condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == generation
		}
	}
	return false
}

func privateRoutesRequireWARP(in Inputs) bool {
	if in.CloudflareTunnel == nil || in.CloudflareTunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
		in.CloudflareTunnel.Status.DeletedAt != nil ||
		in.CloudflareTunnel.Status.TunnelID == "" || !in.CloudflareTunnel.Status.OwnershipVerified {
		return false
	}
	tunnelID := in.CloudflareTunnel.Status.TunnelID
	for index := range in.NetworkRoutes {
		route := &in.NetworkRoutes[index]
		if networkRouteAppliedCurrent(route) && route.Status.Applied.TunnelID == tunnelID {
			return true
		}
	}
	for index := range in.HostnameRoutes {
		route := &in.HostnameRoutes[index]
		if hostnameRouteAppliedCurrent(route) && route.Status.Applied.TunnelID == tunnelID {
			return true
		}
	}
	return false
}

func networkRouteByName(routes []v1alpha1.NetworkRoute, namespace, name string) *v1alpha1.NetworkRoute {
	for index := range routes {
		if routes[index].Namespace == namespace && routes[index].Name == name {
			return &routes[index]
		}
	}
	return nil
}

func hostnameRouteByName(routes []v1alpha1.HostnameRoute, namespace, name string) *v1alpha1.HostnameRoute {
	for index := range routes {
		if routes[index].Namespace == namespace && routes[index].Name == name {
			return &routes[index]
		}
	}
	return nil
}

func normalizePrivateHostname(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}
