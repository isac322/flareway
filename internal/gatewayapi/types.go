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
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// Inputs is a complete, cached object snapshot consumed by Translate. Translate
// never reads from a Kubernetes client and never mutates any object in Inputs.
type Inputs struct {
	Gateway            *gatewayv1.Gateway
	GatewayClass       *gatewayv1.GatewayClass
	GatewayClassConfig *v1alpha1.GatewayClassConfig
	CloudflareTunnel   *v1alpha1.CloudflareTunnel
	CloudflareAccount  *v1alpha1.CloudflareAccount
	AccessApplications []v1alpha1.AccessApplication
	AUDSecrets         map[types.NamespacedName]AUDSecret
	VirtualNetworks    []v1alpha1.VirtualNetwork
	NetworkRoutes      []v1alpha1.NetworkRoute
	HostnameRoutes     []v1alpha1.HostnameRoute
	Namespaces         []corev1.Namespace
	HTTPRoutes         []gatewayv1.HTTPRoute
	ReferenceGrants    []gatewayv1.ReferenceGrant
	BackendTLSPolicies []gatewayv1.BackendTLSPolicy
	Services           []corev1.Service
	EndpointSlices     []discoveryv1.EndpointSlice
	Secrets            []corev1.Secret
	ConfigMaps         []corev1.ConfigMap
	Now                metav1.Time
}

// Statuses contains desired Gateway API statuses. Route and policy maps are
// keyed by namespaced name. HTTPRoute entries preserve parent statuses owned by
// other controllers and replace only ControllerName entries.
type Statuses struct {
	Gateway            gatewayv1.GatewayStatus
	HTTPRoutes         map[types.NamespacedName]gatewayv1.HTTPRouteStatus
	BackendTLSPolicies map[types.NamespacedName]gatewayv1.PolicyStatus
	AccessApplications map[types.NamespacedName]AccessApplicationCompilation
}
