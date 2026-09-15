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

This file is adapted from Envoy Gateway's
internal/gatewayapi/helpers.go at v1.9.1
(commit 0260554fd4f33b787aad77a129fc0ffeb00c1f29),
Copyright Envoy Gateway Authors, licensed under Apache-2.0.
*/

package gatewayapi

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

// ReferenceSource identifies the object that contains a reference to an object
// in another namespace.
type ReferenceSource struct {
	Group     gatewayv1.Group
	Kind      gatewayv1.Kind
	Namespace gatewayv1.Namespace
}

// ReferenceTarget identifies the object referenced by ReferenceSource.
type ReferenceTarget struct {
	Group     gatewayv1.Group
	Kind      gatewayv1.Kind
	Namespace gatewayv1.Namespace
	Name      gatewayv1.ObjectName
}

// IsCrossNamespaceReferencePermitted reports whether a reference is local or is
// permitted by a ReferenceGrant in the target namespace.
func IsCrossNamespaceReferencePermitted(
	from ReferenceSource,
	to ReferenceTarget,
	referenceGrants []gatewayv1.ReferenceGrant,
) bool {
	if from.Namespace == to.Namespace {
		return true
	}

	for i := range referenceGrants {
		referenceGrant := &referenceGrants[i]
		if gatewayv1.Namespace(referenceGrant.Namespace) != to.Namespace {
			continue
		}

		fromAllowed := false
		for _, grantFrom := range referenceGrant.Spec.From {
			if grantFrom.Namespace == from.Namespace && grantFrom.Group == from.Group && grantFrom.Kind == from.Kind {
				fromAllowed = true
				break
			}
		}
		if !fromAllowed {
			continue
		}

		for _, grantTo := range referenceGrant.Spec.To {
			if grantTo.Group != to.Group || grantTo.Kind != to.Kind {
				continue
			}
			if grantTo.Name == nil || *grantTo.Name == "" || *grantTo.Name == to.Name {
				return true
			}
		}
	}

	return false
}
