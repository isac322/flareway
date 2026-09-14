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

// Package rbac holds aggregate RBAC markers that span multiple controllers.
package rbac

// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications;accessgroups;accesspolicies;cloudflareaccounts;cloudflaretunnels;deviceposturerules;deviceprofiles;devicesettings;gatewayclassconfigs;hostnameroutes;identityproviders;networkroutes;servicetokens;virtualnetworks;zerotrustgatewaypolicies;zerotrustlists;zerotrustorganizations,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/status;accessgroups/status;accesspolicies/status;cloudflareaccounts/status;cloudflaretunnels/status;deviceposturerules/status;deviceprofiles/status;devicesettings/status;gatewayclassconfigs/status;hostnameroutes/status;identityproviders/status;networkroutes/status;servicetokens/status;virtualnetworks/status;zerotrustgatewaypolicies/status;zerotrustlists/status;zerotrustorganizations/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/finalizers;accessgroups/finalizers;accesspolicies/finalizers;cloudflareaccounts/finalizers;cloudflaretunnels/finalizers;deviceposturerules/finalizers;deviceprofiles/finalizers;devicesettings/finalizers;gatewayclassconfigs/finalizers;hostnameroutes/finalizers;identityproviders/finalizers;networkroutes/finalizers;servicetokens/finalizers;virtualnetworks/finalizers;zerotrustgatewaypolicies/finalizers;zerotrustlists/finalizers;zerotrustorganizations/finalizers,verbs=patch;update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=backendtlspolicies;gatewayclasses;gateways;httproutes;referencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=backendtlspolicies/status;gatewayclasses/status;gateways/status;httproutes/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=create;delete;get;list;patch;update;watch
