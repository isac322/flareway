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
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	"github.com/isac322/flareway/internal/dataplane"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
	"github.com/isac322/flareway/internal/ir"
)

type privatePrerequisiteResult struct {
	Pending  string
	Degraded bool
}

func (r *GatewayReconciler) reconcilePrivatePrerequisites(
	ctx context.Context,
	gateway *ir.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	account *v1alpha1.CloudflareAccount,
	inputs gatewayInputsView,
) (privatePrerequisiteResult, error) {
	hasPrivate := hasPrivateIRListener(gateway)
	if tunnel != nil && (!hasPrivate || account != nil) {
		if !tunnel.DeletionTimestamp.IsZero() && tunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] == "true" {
			if err := r.deletePlatformHostnameRoutes(ctx, tunnel, inputs.HostnameRoutes); err != nil {
				return privatePrerequisiteResult{}, err
			}
			blockPrivateDomains(gateway)
			return privatePrerequisiteResult{Pending: "Private listener teardown is removing platform HostnameRoutes"}, nil
		}
		if changed, err := r.reconcileGeneratedHostnameRoutes(ctx, gateway, tunnel, account, inputs.HostnameRoutes); err != nil {
			return privatePrerequisiteResult{}, err
		} else if changed {
			blockPrivateDomains(gateway)
			return privatePrerequisiteResult{Pending: "Private listener routes are converging after a block-first update"}, nil
		}
	}
	if !hasPrivate {
		return privatePrerequisiteResult{}, nil
	}
	if tunnel == nil || account == nil || tunnel.Status.TunnelID == "" {
		blockPrivateDomains(gateway)
		return privatePrerequisiteResult{Pending: "Private listeners require a ready CloudflareTunnel and CloudflareAccount"}, nil
	}

	settings, message, err := r.privateDeviceSettings(ctx, account)
	if err != nil {
		return privatePrerequisiteResult{}, err
	}
	if message != "" {
		blockPrivateDomains(gateway)
		return privatePrerequisiteResult{Pending: message}, nil
	}
	if !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled {
		blockPrivateDomains(gateway)
		return privatePrerequisiteResult{Pending: "Private listeners require DeviceSettings gatewayProxyEnabled and gatewayUdpProxyEnabled"}, nil
	}

	for _, listener := range gateway.Listeners {
		if listener.Exposure != ir.ExposurePrivate {
			continue
		}
		if !privateListenerHasReadyVNet(listener.Name, tunnel, account, inputs.VirtualNetworks) {
			blockPrivateDomains(gateway)
			return privatePrerequisiteResult{Pending: fmt.Sprintf("Private listener %q requires a ready VirtualNetwork in the same account", listener.Name)}, nil
		}
		ready, created, err := r.ensurePrivateHostnameRoute(ctx, gateway.UID, listener, tunnel, account, inputs)
		if err != nil {
			return privatePrerequisiteResult{}, err
		}
		if !ready {
			blockPrivateDomains(gateway)
			if created {
				return privatePrerequisiteResult{Pending: fmt.Sprintf("Waiting for the platform HostnameRoute for private listener %q", listener.Name)}, nil
			}
			return privatePrerequisiteResult{Pending: fmt.Sprintf("Private listener %q requires a ready HostnameRoute targeting this tunnel", listener.Name)}, nil
		}
	}

	if application := privateOriginJWTWithoutTLSContract(gateway, inputs.AccessApplications); application != "" {
		blockPrivateDomains(gateway)
		return privatePrerequisiteResult{Pending: fmt.Sprintf("Private AccessApplication %s requires assumeGatewayTLSDecryption=true before origin JWT enforcement can be programmed", application)}, nil
	}
	return privatePrerequisiteResult{Degraded: privateUsesPodIPBinding(gateway)}, nil
}

// gatewayInputsView limits the controller helper to the M4 objects it needs and
// keeps the prerequisite logic independent from translation implementation details.
type gatewayInputsView struct {
	Namespaces         []corev1.Namespace
	VirtualNetworks    []v1alpha1.VirtualNetwork
	NetworkRoutes      []v1alpha1.NetworkRoute
	HostnameRoutes     []v1alpha1.HostnameRoute
	AccessApplications []v1alpha1.AccessApplication
}

func privateInputsView(namespaces []corev1.Namespace, virtualNetworks []v1alpha1.VirtualNetwork, networkRoutes []v1alpha1.NetworkRoute, hostnameRoutes []v1alpha1.HostnameRoute, applications []v1alpha1.AccessApplication) gatewayInputsView {
	return gatewayInputsView{Namespaces: namespaces, VirtualNetworks: virtualNetworks, NetworkRoutes: networkRoutes, HostnameRoutes: hostnameRoutes, AccessApplications: applications}
}

type observedDeviceSettings struct {
	GatewayProxyEnabled    bool
	GatewayUDPProxyEnabled bool
}

func (r *GatewayReconciler) privateDeviceSettings(ctx context.Context, account *v1alpha1.CloudflareAccount) (observedDeviceSettings, string, error) {
	var objects v1alpha1.DeviceSettingsList
	if err := r.List(ctx, &objects); err != nil {
		if !apimeta.IsNoMatchError(err) {
			return observedDeviceSettings{}, "", fmt.Errorf("list DeviceSettings: %w", err)
		}
	} else {
		candidates := make([]v1alpha1.DeviceSettings, 0, len(objects.Items))
		for i := range objects.Items {
			object := &objects.Items[i]
			if object.Name != "default" || !object.DeletionTimestamp.IsZero() ||
				object.Spec.AccountRef.Name != account.Name ||
				effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged ||
				object.Status.ObservedGeneration != object.Generation ||
				!conditionTrueForGeneration(object.Status.Conditions, v1alpha1.DeviceSettingsConditionAccepted, object.Generation) {
				continue
			}
			var namespace corev1.Namespace
			if err := r.Get(ctx, types.NamespacedName{Name: object.Namespace}, &namespace); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return observedDeviceSettings{}, "", fmt.Errorf("get DeviceSettings namespace %q: %w", object.Namespace, err)
			}
			if !authz.Evaluate(account, &namespace, authz.Request{PlatformObject: true}).Allowed {
				continue
			}
			candidates = append(candidates, *object.DeepCopy())
		}
		slices.SortFunc(candidates, func(left, right v1alpha1.DeviceSettings) int {
			if compared := left.CreationTimestamp.Compare(right.CreationTimestamp.Time); compared != 0 {
				return compared
			}
			return strings.Compare(client.ObjectKeyFromObject(&left).String(), client.ObjectKeyFromObject(&right).String())
		})
		if len(candidates) > 0 {
			object := &candidates[0]
			if object.Status.Observed.GatewayProxyEnabled == nil || object.Status.Observed.GatewayUDPProxyEnabled == nil {
				return observedDeviceSettings{}, "Authorized DeviceSettings/default has not observed the remote account settings yet", nil
			}
			return observedDeviceSettings{
				GatewayProxyEnabled:    *object.Status.Observed.GatewayProxyEnabled,
				GatewayUDPProxyEnabled: *object.Status.Observed.GatewayUDPProxyEnabled,
			}, "", nil
		}
	}
	api, err := r.cloudflareClient(ctx, account)
	if err != nil {
		return observedDeviceSettings{}, "Cloudflare device settings could not be read: " + err.Error(), nil
	}
	settings, err := api.GetDeviceSettings(ctx)
	if err != nil {
		return observedDeviceSettings{}, "Cloudflare device settings could not be read: " + err.Error(), nil
	}
	return observedDeviceSettings{GatewayProxyEnabled: settings.GatewayProxyEnabled, GatewayUDPProxyEnabled: settings.GatewayUDPProxyEnabled}, "", nil
}

func conditionTrueForGeneration(conditions []metav1.Condition, conditionType string, generation int64) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == generation
		}
	}
	return false
}

func (r *GatewayReconciler) ensurePrivateHostnameRoute(
	ctx context.Context,
	gatewayUID types.UID,
	listener ir.Listener,
	tunnel *v1alpha1.CloudflareTunnel,
	account *v1alpha1.CloudflareAccount,
	inputs gatewayInputsView,
) (ready, created bool, err error) {
	for index := range inputs.HostnameRoutes {
		route := &inputs.HostnameRoutes[index]
		if normalizePrivateName(route.Spec.Hostname) != normalizePrivateName(listener.Hostname) ||
			route.Spec.AccountRef.Name != account.Name || !privateRouteTargetsTunnel(route.Spec.TunnelRef, route.Namespace, tunnel) {
			continue
		}
		return currentHostnameRouteApplied(route) &&
			route.Status.Applied.TunnelID == tunnel.Status.TunnelID, false, nil
	}

	if !hostnameRouteCreationEnabled(tunnel, listener.Name) {
		return false, false, nil
	}
	gatewayNamespace := namespaceMetadata(inputs.Namespaces, tunnel.Namespace)
	if gatewayNamespace == nil {
		return false, false, nil
	}
	decision := authz.Evaluate(account, gatewayNamespace, authz.Request{
		Hostname: listener.Hostname, Exposure: v1alpha1.ExposurePrivate, PlatformObject: true,
	})
	if !decision.Allowed {
		return false, false, nil
	}
	platformNamespace := r.OperatorNamespace
	if platformNamespace == "" {
		platformNamespace = dataplane.DefaultOperatorNamespace
	}
	name := privateHostnameRouteName(tunnel.Namespace, tunnel.Name, listener.Name)
	route := &v1alpha1.HostnameRoute{
		TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "HostnameRoute"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: platformNamespace,
			Labels: map[string]string{
				"flareway.bhyoo.com/platform-object":  "true",
				"flareway.bhyoo.com/gateway":          tunnel.Namespace + "--" + tunnel.Name,
				"flareway.bhyoo.com/source-namespace": tunnel.Namespace,
			},
			Annotations: map[string]string{
				"flareway.bhyoo.com/source-gateway-uid": string(gatewayUID),
			},
		},
		Spec: v1alpha1.HostnameRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Hostname:   listener.Hostname,
			TunnelRef:  v1alpha1.NamespacedObjectReference{Name: tunnel.Name, Namespace: tunnel.Namespace},
			AllowedNamespaces: v1alpha1.AllowedNamespaces{
				From: v1alpha1.AllowedNamespaceFromSelector,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": tunnel.Namespace,
				}},
			},
			Comment:          fmt.Sprintf("flareway private listener %s/%s/%s", tunnel.Namespace, tunnel.Name, listener.Name),
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := r.Create(ctx, route); err != nil && !apierrors.IsAlreadyExists(err) {
		return false, false, fmt.Errorf("create platform HostnameRoute %s/%s: %w", platformNamespace, name, err)
	}
	return false, true, nil
}

func (r *GatewayReconciler) deletePlatformHostnameRoutes(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, routes []v1alpha1.HostnameRoute) error {
	for index := range routes {
		route := &routes[index]
		if route.Labels["flareway.bhyoo.com/platform-object"] != "true" ||
			!privateRouteTargetsTunnel(route.Spec.TunnelRef, route.Namespace, tunnel) {
			continue
		}
		if err := r.Delete(ctx, route); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete platform HostnameRoute %s/%s: %w", route.Namespace, route.Name, err)
		}
	}
	return nil
}

func (r *GatewayReconciler) reconcileGeneratedHostnameRoutes(ctx context.Context, gateway *ir.Gateway, tunnel *v1alpha1.CloudflareTunnel, account *v1alpha1.CloudflareAccount, routes []v1alpha1.HostnameRoute) (bool, error) {
	platformNamespace := r.OperatorNamespace
	if platformNamespace == "" {
		platformNamespace = dataplane.DefaultOperatorNamespace
	}
	desired := make(map[types.NamespacedName]ir.Listener)
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePrivate && hostnameRouteCreationEnabled(tunnel, listener.Name) {
			desired[types.NamespacedName{Namespace: platformNamespace, Name: privateHostnameRouteName(tunnel.Namespace, tunnel.Name, listener.Name)}] = listener
		}
	}
	changed := false
	for index := range routes {
		route := &routes[index]
		if route.Namespace != platformNamespace || route.Labels["flareway.bhyoo.com/platform-object"] != "true" || route.Annotations["flareway.bhyoo.com/source-gateway-uid"] != string(gateway.UID) {
			continue
		}
		key := client.ObjectKeyFromObject(route)
		listener, retained := desired[key]
		if !retained {
			if err := r.Delete(ctx, route); err != nil && !apierrors.IsNotFound(err) {
				return false, fmt.Errorf("delete obsolete generated HostnameRoute %s: %w", key, err)
			}
			changed = true
			continue
		}
		before := route.DeepCopy()
		if route.Labels == nil {
			route.Labels = map[string]string{}
		}
		route.Labels["flareway.bhyoo.com/platform-object"] = "true"
		route.Labels["flareway.bhyoo.com/gateway"] = tunnel.Namespace + "--" + tunnel.Name
		route.Labels["flareway.bhyoo.com/source-namespace"] = tunnel.Namespace
		if route.Annotations == nil {
			route.Annotations = map[string]string{}
		}
		route.Annotations["flareway.bhyoo.com/source-gateway-uid"] = string(gateway.UID)
		route.Spec.AccountRef = corev1.LocalObjectReference{Name: account.Name}
		route.Spec.Hostname = listener.Hostname
		route.Spec.TunnelRef = v1alpha1.NamespacedObjectReference{Name: tunnel.Name, Namespace: tunnel.Namespace}
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": tunnel.Namespace}}}
		route.Spec.Comment = fmt.Sprintf("flareway private listener %s/%s/%s", tunnel.Namespace, tunnel.Name, listener.Name)
		route.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		route.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
		if !reflect.DeepEqual(before.Spec, route.Spec) || !reflect.DeepEqual(before.Labels, route.Labels) || !reflect.DeepEqual(before.Annotations, route.Annotations) {
			if err := r.Patch(ctx, route, client.MergeFrom(before)); err != nil {
				return false, fmt.Errorf("repair generated HostnameRoute %s: %w", key, err)
			}
			changed = true
		}
	}
	return changed, nil
}

func privateListenerCondition(gateway *ir.Gateway, state privatePrerequisiteResult, now metav1.Time) metav1.Condition {
	status := metav1.ConditionFalse
	reason := "Loopback"
	message := "Private listeners are isolated on pod loopback"
	switch {
	case !hasPrivateIRListener(gateway):
		reason = "NotApplicable"
		message = "Gateway has no private listeners"
	case state.Degraded:
		status = metav1.ConditionTrue
		reason = "PodIPFallback"
		message = "Private listeners use the recorded PodIP fallback and rely on NetworkPolicy isolation"
	case state.Pending != "":
		reason = "Pending"
		message = state.Pending
	}
	return metav1.Condition{
		Type:               v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	}
}

func hasPrivateIRListener(gateway *ir.Gateway) bool {
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePrivate {
			return true
		}
	}
	return false
}

func blockPrivateDomains(gateway *ir.Gateway) {
	privateListeners := make(map[string]struct{})
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePrivate {
			privateListeners[listener.Name] = struct{}{}
		}
	}
	for index := range gateway.Domains {
		if _, private := privateListeners[gateway.Domains[index].ListenerName]; !private {
			continue
		}
		gateway.Domains[index].Guard = ir.GuardBlocked
		gateway.Domains[index].Access = nil
	}
}

func privateOriginJWTWithoutTLSContract(gateway *ir.Gateway, applications []v1alpha1.AccessApplication) string {
	privateListeners := make(map[string]struct{})
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePrivate {
			privateListeners[listener.Name] = struct{}{}
		}
	}
	byKey := make(map[string]*v1alpha1.AccessApplication, len(applications))
	for index := range applications {
		application := &applications[index]
		byKey[application.Namespace+"/"+application.Name] = application
	}
	for _, domain := range gateway.Domains {
		if _, private := privateListeners[domain.ListenerName]; !private || domain.AccessApplication == "" {
			continue
		}
		application := byKey[domain.AccessApplication]
		if application == nil || effectivePrivateOriginJWTMode(application) == v1alpha1.AccessOriginJWTModeDisabled {
			continue
		}
		if !application.Spec.OriginJWT.AssumeGatewayTLSDecryption {
			return domain.AccessApplication
		}
	}
	return ""
}

func effectivePrivateOriginJWTMode(application *v1alpha1.AccessApplication) v1alpha1.AccessOriginJWTMode {
	if application.Spec.OriginJWT.Mode == "" {
		return v1alpha1.AccessOriginJWTModeRequired
	}
	return application.Spec.OriginJWT.Mode
}

func privateListenerHasReadyVNet(listenerName string, tunnel *v1alpha1.CloudflareTunnel, account *v1alpha1.CloudflareAccount, vnets []v1alpha1.VirtualNetwork) bool {
	name := ""
	for _, listener := range tunnel.Spec.Listeners {
		if string(listener.Name) == listenerName && listener.VirtualNetworkRef != nil {
			name = listener.VirtualNetworkRef.Name
			break
		}
	}
	for index := range vnets {
		vnet := &vnets[index]
		if vnet.Namespace != tunnel.Namespace || vnet.Spec.AccountRef.Name != account.Name || vnet.Status.VirtualNetworkID == "" ||
			!gatewaystatus.ConditionTrue(vnet.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
			continue
		}
		if (name != "" && vnet.Name == name) || (name == "" && vnet.Spec.IsDefault) {
			return true
		}
	}
	return false
}

func hostnameRouteCreationEnabled(tunnel *v1alpha1.CloudflareTunnel, listenerName string) bool {
	for _, listener := range tunnel.Spec.Listeners {
		if string(listener.Name) != listenerName {
			continue
		}
		return listener.HostnameRoute.Create == nil || *listener.HostnameRoute.Create
	}
	return true
}

func privateRouteTargetsTunnel(ref v1alpha1.NamespacedObjectReference, routeNamespace string, tunnel *v1alpha1.CloudflareTunnel) bool {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = routeNamespace
	}
	return namespace == tunnel.Namespace && ref.Name == tunnel.Name
}

func privateUsesPodIPBinding(gateway *ir.Gateway) bool {
	for _, listener := range gateway.Listeners {
		if listener.Exposure == ir.ExposurePrivate && listener.Binding == ir.ListenerBindingPodIP {
			return true
		}
	}
	return false
}

func normalizePrivateName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func privateHostnameRouteName(namespace, tunnel, listener string) string {
	base := sanitizePrivateName(namespace + "-" + tunnel + "-" + listener)
	if len(base) <= 63 {
		return base
	}
	sum := sha256.Sum256([]byte(base))
	return strings.TrimRight(base[:50], "-") + fmt.Sprintf("-%x", sum[:6])
}

func (r *GatewayReconciler) mapPrivateRouteToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	var ref v1alpha1.NamespacedObjectReference
	switch route := object.(type) {
	case *v1alpha1.NetworkRoute:
		ref = route.Spec.TunnelRef
	case *v1alpha1.HostnameRoute:
		ref = route.Spec.TunnelRef
	default:
		return nil
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = object.GetNamespace()
	}
	return r.mapTunnelToGateways(ctx, &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: namespace},
	})
}

func (r *GatewayReconciler) mapVirtualNetworkToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	vnet, ok := object.(*v1alpha1.VirtualNetwork)
	if !ok {
		return nil
	}
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels, client.InNamespace(vnet.Namespace)); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list CloudflareTunnels for VirtualNetwork", "virtualNetwork", client.ObjectKeyFromObject(vnet))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range tunnels.Items {
		tunnel := &tunnels.Items[index]
		for _, listener := range tunnel.Spec.Listeners {
			if listener.Exposure != v1alpha1.ExposurePrivate {
				continue
			}
			if listener.VirtualNetworkRef == nil {
				if !vnet.Spec.IsDefault {
					continue
				}
			} else if listener.VirtualNetworkRef.Name != vnet.Name {
				continue
			}
			requests = append(requests, r.mapTunnelToGateways(ctx, tunnel)...)
			break
		}
	}
	return deduplicateRequests(requests)
}

func sanitizePrivateName(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func namespaceMetadata(namespaces []corev1.Namespace, name string) *corev1.Namespace {
	for index := range namespaces {
		if namespaces[index].Name == name {
			return &namespaces[index]
		}
	}
	return nil
}

func currentHostnameRouteApplied(route *v1alpha1.HostnameRoute) bool {
	if route == nil || !route.DeletionTimestamp.IsZero() || route.Status.RouteID == "" ||
		route.Status.ObservedGeneration != route.Generation ||
		route.Status.Applied.ObservedGeneration != route.Generation ||
		route.Status.Applied.Hostname == "" || route.Status.Applied.TunnelID == "" {
		return false
	}
	for _, condition := range route.Status.Conditions {
		if condition.Type == v1alpha1.PrivateNetworkConditionAccepted {
			return condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == route.Generation
		}
	}
	return false
}
