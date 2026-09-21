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
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// privateOrphan builds the orphan predicate for private-network kinds whose
// remote objects carry a comment ownership marker ("flareway <clusterID>/
// <ns>/<name>", the signed hmac: form, or the truncated sha256: form).
// Legacy markers attribute by parsing; signed markers verify against every
// live CR; unattributable markers are skipped rather than guessed.
func privateOrphan[R any](clusterID string, key []byte, refs []localRef, idOf, commentOf func(R) string) func(R, map[string]bool) (types.NamespacedName, bool) {
	return func(remote R, _ map[string]bool) (types.NamespacedName, bool) {
		comment := commentOf(remote)
		ownerCluster, namespace, name, ok := parsePrivateOwnerComment(comment)
		if !ok {
			// Signed or truncated marker: verify against each live CR.
			for _, ref := range refs {
				if flarecloudflare.IsOwnedPrivateResourceSigned(comment, key, clusterID, ref.key.Namespace, ref.specName) {
					if ref.remoteID != idOf(remote) {
						return ref.key, true
					}
					return types.NamespacedName{}, false
				}
			}
			return types.NamespacedName{}, false
		}
		if ownerCluster != clusterID {
			return types.NamespacedName{}, false
		}
		for _, ref := range refs {
			if ref.key.Namespace == namespace && ref.specName == name {
				if ref.remoteID != idOf(remote) {
					return ref.key, true
				}
				return types.NamespacedName{}, false
			}
		}
		return types.NamespacedName{Namespace: namespace, Name: name}, true
	}
}

// sweepVirtualNetworks covers VirtualNetwork CRs against ListVirtualNetworks.
func sweepVirtualNetworks(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListVirtualNetworks(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	key := as.ownershipKey(ctx)

	var list v1alpha1.VirtualNetworkList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list VirtualNetworks: %w", err)
	}
	var refs []localRef
	defaults := make(map[types.NamespacedName]bool)
	for i := range list.Items {
		network := &list.Items[i]
		if network.Spec.AccountRef.Name != as.accountName || deleting(network) || observeOnly(network.Spec.ManagementPolicy) {
			continue
		}
		nn := types.NamespacedName{Namespace: network.Namespace, Name: network.Name}
		refs = append(refs, localRef{
			kind: "VirtualNetwork", key: nn,
			uid: network.UID, remoteID: network.Status.VirtualNetworkID,
			expectedName: network.Spec.Name, specName: network.Name,
		})
		defaults[nn] = network.Spec.IsDefault
	}

	live := make([]flarecloudflare.VirtualNetwork, 0, len(remotes))
	for _, remote := range remotes {
		if !remote.Deleted {
			live = append(live, remote)
		}
	}
	return classify(refs, live, classifyOptions[flarecloudflare.VirtualNetwork]{
		kind:   "VirtualNetwork",
		idOf:   func(v flarecloudflare.VirtualNetwork) string { return v.ID },
		listed: accountScopeListed,
		nameOf: func(v flarecloudflare.VirtualNetwork) string { return v.Name },
		extra: func(ref localRef, remote flarecloudflare.VirtualNetwork) string {
			if remote.IsDefault != defaults[ref.key] {
				return fmt.Sprintf("remote isDefault %t does not match spec isDefault %t", remote.IsDefault, defaults[ref.key])
			}
			return ""
		},
		orphan: privateOrphan(clusterID, key, refs,
			func(v flarecloudflare.VirtualNetwork) string { return v.ID },
			func(v flarecloudflare.VirtualNetwork) string { return v.Comment }),
	}), nil
}

// sweepNetworkRoutes covers NetworkRoute CRs against ListNetworkRoutes.
func sweepNetworkRoutes(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListNetworkRoutes(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	key := as.ownershipKey(ctx)

	var list v1alpha1.NetworkRouteList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list NetworkRoutes: %w", err)
	}
	var refs []localRef
	networks := make(map[types.NamespacedName]string)
	for i := range list.Items {
		route := &list.Items[i]
		if route.Spec.AccountRef.Name != as.accountName || deleting(route) || observeOnly(route.Spec.ManagementPolicy) {
			continue
		}
		nn := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		refs = append(refs, localRef{
			kind: "NetworkRoute", key: nn,
			uid: route.UID, remoteID: route.Status.RouteID, specName: route.Name,
		})
		networks[nn] = route.Spec.Network
	}

	live := make([]flarecloudflare.NetworkRoute, 0, len(remotes))
	for _, remote := range remotes {
		if !remote.Deleted {
			live = append(live, remote)
		}
	}
	return classify(refs, live, classifyOptions[flarecloudflare.NetworkRoute]{
		kind:   "NetworkRoute",
		idOf:   func(r flarecloudflare.NetworkRoute) string { return r.ID },
		listed: accountScopeListed,
		nameOf: func(flarecloudflare.NetworkRoute) string { return "" },
		extra: func(ref localRef, remote flarecloudflare.NetworkRoute) string {
			want, ok := networks[ref.key]
			if !ok {
				return ""
			}
			wantPrefix, err := netip.ParsePrefix(want)
			if err != nil {
				return ""
			}
			remotePrefix, err := netip.ParsePrefix(remote.Network)
			if err != nil || remotePrefix.Masked() != wantPrefix.Masked() {
				return fmt.Sprintf("remote network %q does not match spec network %q", remote.Network, want)
			}
			return ""
		},
		orphan: privateOrphan(clusterID, key, refs,
			func(r flarecloudflare.NetworkRoute) string { return r.ID },
			func(r flarecloudflare.NetworkRoute) string { return r.Comment }),
	}), nil
}

// sweepHostnameRoutes covers HostnameRoute CRs against ListHostnameRoutes.
func sweepHostnameRoutes(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListHostnameRoutes(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	key := as.ownershipKey(ctx)

	var list v1alpha1.HostnameRouteList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list HostnameRoutes: %w", err)
	}
	var refs []localRef
	hostnames := make(map[types.NamespacedName]string)
	for i := range list.Items {
		route := &list.Items[i]
		if route.Spec.AccountRef.Name != as.accountName || deleting(route) || observeOnly(route.Spec.ManagementPolicy) {
			continue
		}
		nn := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		refs = append(refs, localRef{
			kind: "HostnameRoute", key: nn,
			uid: route.UID, remoteID: route.Status.RouteID, specName: route.Name,
		})
		// cloudflarePrivateHostname strips the "*." wildcard prefix.
		hostnames[nn] = strings.TrimPrefix(route.Spec.Hostname, "*.")
	}

	live := make([]flarecloudflare.HostnameRoute, 0, len(remotes))
	for _, remote := range remotes {
		if !remote.Deleted {
			live = append(live, remote)
		}
	}
	return classify(refs, live, classifyOptions[flarecloudflare.HostnameRoute]{
		kind:   "HostnameRoute",
		idOf:   func(r flarecloudflare.HostnameRoute) string { return r.ID },
		listed: accountScopeListed,
		nameOf: func(flarecloudflare.HostnameRoute) string { return "" },
		extra: func(ref localRef, remote flarecloudflare.HostnameRoute) string {
			want := hostnames[ref.key]
			if want != "" && !strings.EqualFold(remote.Hostname, want) {
				return fmt.Sprintf("remote hostname %q does not match spec hostname %q", remote.Hostname, want)
			}
			return ""
		},
		orphan: privateOrphan(clusterID, key, refs,
			func(r flarecloudflare.HostnameRoute) string { return r.ID },
			func(r flarecloudflare.HostnameRoute) string { return r.Comment }),
	}), nil
}
