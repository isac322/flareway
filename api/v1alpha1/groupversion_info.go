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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Group is the API group for Flareway resources.
	Group = "flareway.bhyoo.com"
	// Version is the API version for Flareway resources.
	Version = "v1alpha1"
)

var (
	// GroupVersion identifies the Flareway v1alpha1 API group and version.
	GroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeGroupVersion is the group and version used by Kubebuilder-generated API registrations.
	SchemeGroupVersion = GroupVersion

	// SchemeBuilder registers Flareway API types with a runtime scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds all Flareway v1alpha1 API types to a runtime scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&AccessApplication{},
		&AccessApplicationList{},
		&AccessGroup{},
		&AccessGroupList{},
		&AccessPolicy{},
		&AccessPolicyList{},
		&CloudflareAccount{},
		&HostnameRoute{},
		&HostnameRouteList{},
		&NetworkRoute{},
		&NetworkRouteList{},
		&CloudflareAccountList{},
		&CloudflareTunnel{},
		&CloudflareTunnelList{},
		&DevicePostureRule{},
		&DeviceProfile{},
		&DeviceProfileList{},
		&DeviceSettings{},
		&DeviceSettingsList{},
		&DevicePostureRuleList{},
		&GatewayClassConfig{},
		&GatewayClassConfigList{},
		&IdentityProvider{},
		&IdentityProviderList{},
		&ServiceToken{},
		&ServiceTokenList{},
		&VirtualNetwork{},
		&VirtualNetworkList{},
		&ZeroTrustGatewayPolicy{},
		&ZeroTrustGatewayPolicyList{},
		&ZeroTrustList{},
		&ZeroTrustListList{},
		&ZeroTrustOrganization{},
		&ZeroTrustOrganizationList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
