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

// sweepZeroTrustGatewayPolicies covers ZeroTrustGatewayPolicy CRs against
// ListGatewayRules. Remote rules carry no ownership marker and the remote
// name is the raw spec.name, so orphan detection is impossible.
func sweepZeroTrustGatewayPolicies(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListGatewayRules(ctx)
	if err != nil {
		return nil, listFailure(err)
	}

	var list v1alpha1.ZeroTrustGatewayPolicyList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list ZeroTrustGatewayPolicies: %w", err)
	}
	var refs []localRef
	descriptions := make(map[types.NamespacedName]*string)
	for i := range list.Items {
		policy := &list.Items[i]
		if policy.Spec.AccountRef.Name != as.accountName || deleting(policy) || observeOnly(policy.Spec.ManagementPolicy) {
			continue
		}
		key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
		refs = append(refs, localRef{
			kind: "ZeroTrustGatewayPolicy", key: key,
			uid: policy.UID, remoteID: policy.Status.RuleID,
			expectedName: policy.Spec.Name,
		})
		descriptions[key] = policy.Spec.Description
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.GatewayRule]{
		kind:   "ZeroTrustGatewayPolicy",
		idOf:   func(r flarecloudflare.GatewayRule) string { return r.ID },
		listed: accountScopeListed,
		nameOf: func(r flarecloudflare.GatewayRule) string { return r.Name },
		extra: func(ref localRef, remote flarecloudflare.GatewayRule) string {
			if want := descriptions[ref.key]; want != nil && remote.Description != *want {
				return fmt.Sprintf("remote description %q does not match spec description %q", remote.Description, *want)
			}
			return ""
		},
	}), nil
}

// sweepZeroTrustLists covers ZeroTrustList CRs against ListGatewayLists.
// Remote lists carry no ownership marker and the remote name is the raw
// spec.name, so orphan detection is impossible.
func sweepZeroTrustLists(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListGatewayLists(ctx)
	if err != nil {
		return nil, listFailure(err)
	}

	var list v1alpha1.ZeroTrustListList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list ZeroTrustLists: %w", err)
	}
	var refs []localRef
	typesByKey := make(map[types.NamespacedName]string)
	for i := range list.Items {
		ztList := &list.Items[i]
		if ztList.Spec.AccountRef.Name != as.accountName || deleting(ztList) || observeOnly(ztList.Spec.ManagementPolicy) {
			continue
		}
		key := types.NamespacedName{Namespace: ztList.Namespace, Name: ztList.Name}
		refs = append(refs, localRef{
			kind: "ZeroTrustList", key: key,
			uid: ztList.UID, remoteID: ztList.Status.ListID,
			expectedName: ztList.Spec.Name,
		})
		typesByKey[key] = string(ztList.Spec.Type)
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.GatewayList]{
		kind:   "ZeroTrustList",
		idOf:   func(l flarecloudflare.GatewayList) string { return l.ID },
		listed: accountScopeListed,
		nameOf: func(l flarecloudflare.GatewayList) string { return l.Name },
		extra: func(ref localRef, remote flarecloudflare.GatewayList) string {
			if want := typesByKey[ref.key]; want != "" && string(remote.Type) != want {
				return fmt.Sprintf("remote list type %q does not match spec type %q", remote.Type, want)
			}
			return ""
		},
	}), nil
}
