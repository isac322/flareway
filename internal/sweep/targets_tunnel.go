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
	"strings"

	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// desiredTunnelName mirrors the controller's desiredTunnelName: an explicit
// spec.tunnel.name wins, otherwise the generated "<clusterID>-<ns>-<name>".
func desiredTunnelName(tunnel *v1alpha1.CloudflareTunnel, clusterID string) string {
	if tunnel.Spec.Tunnel.Name != "" {
		return tunnel.Spec.Tunnel.Name
	}
	return strings.Join([]string{clusterID, tunnel.Namespace, tunnel.Name}, "-")
}

// sweepCloudflareTunnels covers CloudflareTunnel CRs against ListTunnels.
// Orphan detection is limited to generated names ("<clusterID>-..."): a
// custom spec.tunnel.name cannot be attributed, so it is never a candidate.
func sweepCloudflareTunnels(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListTunnels(ctx, flarecloudflare.TunnelListOptions{})
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}

	var list v1alpha1.CloudflareTunnelList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list CloudflareTunnels: %w", err)
	}
	var refs []localRef
	expectedNames := make(map[string]bool)
	for i := range list.Items {
		tunnel := &list.Items[i]
		if tunnel.Spec.AccountRef.Name != as.accountName || deleting(tunnel) || observeOnly(tunnel.Spec.ManagementPolicy) {
			continue
		}
		expected := desiredTunnelName(tunnel, clusterID)
		expectedNames[expected] = true
		refs = append(refs, localRef{
			kind: "CloudflareTunnel", key: types.NamespacedName{Namespace: tunnel.Namespace, Name: tunnel.Name},
			uid: tunnel.UID, remoteID: tunnel.Status.TunnelID, expectedName: expected,
		})
	}

	live := make([]flarecloudflare.Tunnel, 0, len(remotes))
	for _, remote := range remotes {
		if !remote.Deleted() {
			live = append(live, remote)
		}
	}
	generatedPrefix := clusterID + "-"
	return classify(refs, live, classifyOptions[flarecloudflare.Tunnel]{
		kind:    "CloudflareTunnel",
		content: contentCheck[flarecloudflare.Tunnel](ctx, as),
		idOf:    func(t flarecloudflare.Tunnel) string { return t.ID },
		listed:  accountScopeListed,
		nameOf:  func(t flarecloudflare.Tunnel) string { return t.Name },
		orphan: func(remote flarecloudflare.Tunnel, _ map[string]bool) (types.NamespacedName, bool) {
			if !strings.HasPrefix(remote.Name, generatedPrefix) || expectedNames[remote.Name] {
				return types.NamespacedName{}, false
			}
			return types.NamespacedName{}, true
		},
	}), nil
}

// sweepWARPConnectors covers WARPConnector CRs against ListWARPConnectors.
// The remote name is the raw spec.name with no ownership marker, so orphan
// detection is impossible and intentionally absent.
func sweepWARPConnectors(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListWARPConnectors(ctx, flarecloudflare.WARPConnectorListFilter{})
	if err != nil {
		return nil, listFailure(err)
	}

	var list v1alpha1.WARPConnectorList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list WARPConnectors: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		connector := &list.Items[i]
		if connector.Spec.AccountRef.Name != as.accountName || deleting(connector) || observeOnly(connector.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "WARPConnector", key: types.NamespacedName{Namespace: connector.Namespace, Name: connector.Name},
			uid: connector.UID, remoteID: connector.Status.TunnelID,
			expectedName: strings.TrimSpace(connector.Spec.Name),
		})
	}

	live := make([]flarecloudflare.WARPConnector, 0, len(remotes))
	for _, remote := range remotes {
		if !remote.Deleted() {
			live = append(live, remote)
		}
	}
	return classify(refs, live, classifyOptions[flarecloudflare.WARPConnector]{
		kind:    "WARPConnector",
		content: contentCheck[flarecloudflare.WARPConnector](ctx, as),
		idOf:    func(c flarecloudflare.WARPConnector) string { return c.ID },
		listed:  accountScopeListed,
		nameOf:  func(c flarecloudflare.WARPConnector) string { return c.Name },
	}), nil
}
