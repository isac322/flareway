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
	"slices"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// ControllerName is the Gateway API controller name owned by Flareway.
const ControllerName gatewayv1.GatewayController = "flareway.bhyoo.com/gateway-controller"

var supportedFeatures = []features.FeatureName{
	features.SupportBackendTLSPolicy,
	features.SupportBackendTLSPolicySANValidation,
	features.SupportGateway,
	features.SupportGatewayHTTPListenerIsolation,
	features.SupportGatewayHTTPSListenerDetectMisdirectedRequests,
	features.SupportGatewayInfrastructurePropagation,
	features.SupportHTTPRoute,
	features.SupportHTTPRoute303RedirectStatusCode,
	features.SupportHTTPRoute307RedirectStatusCode,
	features.SupportHTTPRoute308RedirectStatusCode,
	features.SupportHTTPRouteBackendProtocolH2C,
	features.SupportHTTPRouteBackendProtocolWebSocket,
	features.SupportHTTPRouteBackendTimeout,
	features.SupportHTTPRouteCORS,
	features.SupportHTTPRouteHostRewrite,
	features.SupportHTTPRouteMethodMatching,
	features.SupportHTTPRouteParentRefPort,
	features.SupportHTTPRoutePathRedirect,
	features.SupportHTTPRoutePathRewrite,
	features.SupportHTTPRoutePortRedirect,
	features.SupportHTTPRouteQueryParamMatching,
	features.SupportHTTPRouteRequestMirror,
	features.SupportHTTPRouteRequestMultipleMirrors,
	features.SupportHTTPRouteRequestPercentageMirror,
	features.SupportHTTPRouteRequestTimeout,
	features.SupportHTTPRouteResponseHeaderModification,
	features.SupportHTTPRouteSchemeRedirect,
	features.SupportReferenceGrant,
}

func init() {
	slices.Sort(supportedFeatures)
}

// SupportedFeatures returns the sorted conformance features claimed by
// Flareway. The returned slice is safe for callers to modify.
func SupportedFeatures() []features.FeatureName {
	return slices.Clone(supportedFeatures)
}
