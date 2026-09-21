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

package sweep

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// sweepDeviceProfiles covers DeviceProfile CRs against
// ListCustomDeviceProfiles. The remote name is optional
// (spec.profile.fields.name) and carries no ownership marker, so orphan
// detection is impossible.
func sweepDeviceProfiles(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListCustomDeviceProfiles(ctx)
	if err != nil {
		return nil, listFailure(err)
	}

	var list v1alpha1.DeviceProfileList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list DeviceProfiles: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		profile := &list.Items[i]
		if profile.Spec.AccountRef.Name != as.accountName || deleting(profile) || observeOnly(profile.Spec.ManagementPolicy) {
			continue
		}
		expectedName := ""
		if profile.Spec.Profile.Fields != nil && profile.Spec.Profile.Fields.Name != nil {
			expectedName = *profile.Spec.Profile.Fields.Name
		}
		refs = append(refs, localRef{
			kind: "DeviceProfile", key: types.NamespacedName{Namespace: profile.Namespace, Name: profile.Name},
			uid: profile.UID, remoteID: profile.Status.ProfileID, expectedName: expectedName,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.DeviceProfile]{
		kind:   "DeviceProfile",
		idOf:   func(p flarecloudflare.DeviceProfile) string { return p.PolicyID },
		listed: accountScopeListed,
		nameOf: func(p flarecloudflare.DeviceProfile) string { return p.Name },
	}), nil
}

// sweepDevicePostureRules covers DevicePostureRule CRs against
// ListDevicePostureRules. Remote names follow accessRemoteName.
func sweepDevicePostureRules(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListDevicePostureRules(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}

	var list v1alpha1.DevicePostureRuleList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list DevicePostureRules: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		rule := &list.Items[i]
		if rule.Spec.AccountRef.Name != as.accountName || deleting(rule) || observeOnly(rule.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "DevicePostureRule", key: types.NamespacedName{Namespace: rule.Namespace, Name: rule.Name},
			uid: rule.UID, remoteID: rule.Status.RuleID,
			expectedName: accessRemoteNameValue(clusterID, rule.Namespace, rule.Spec.Name),
			specName:     rule.Spec.Name,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.DevicePostureRule]{
		kind:   "DevicePostureRule",
		idOf:   func(r flarecloudflare.DevicePostureRule) string { return r.ID },
		listed: accountScopeListed,
		nameOf: func(r flarecloudflare.DevicePostureRule) string { return r.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(r flarecloudflare.DevicePostureRule) string { return r.ID },
			func(r flarecloudflare.DevicePostureRule) string { return r.Name }),
	}), nil
}

// sweepDevicePostureIntegrations covers DevicePostureIntegration CRs
// against ListDevicePostureIntegrations. Remote names follow
// accessRemoteName.
func sweepDevicePostureIntegrations(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListDevicePostureIntegrations(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}

	var list v1alpha1.DevicePostureIntegrationList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list DevicePostureIntegrations: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		integration := &list.Items[i]
		if integration.Spec.AccountRef.Name != as.accountName || deleting(integration) || observeOnly(integration.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "DevicePostureIntegration", key: types.NamespacedName{Namespace: integration.Namespace, Name: integration.Name},
			uid: integration.UID, remoteID: integration.Status.IntegrationID,
			expectedName: accessRemoteNameValue(clusterID, integration.Namespace, integration.Spec.Name),
			specName:     integration.Spec.Name,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.DevicePostureIntegration]{
		kind:   "DevicePostureIntegration",
		idOf:   func(i flarecloudflare.DevicePostureIntegration) string { return i.ID },
		listed: accountScopeListed,
		nameOf: func(i flarecloudflare.DevicePostureIntegration) string { return i.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(i flarecloudflare.DevicePostureIntegration) string { return i.ID },
			func(i flarecloudflare.DevicePostureIntegration) string { return i.Name }),
	}), nil
}
