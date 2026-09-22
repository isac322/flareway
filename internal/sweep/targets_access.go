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

// accessScopes returns the account scope plus every zone scope. Zone-scoped
// kinds must list each zone or their objects would be judged missing.
// listed records which scopes were covered so refs in unlisted scopes are
// skipped.
func (as *AccountSweeper) accessScopes(ctx context.Context) ([]flarecloudflare.AccessScope, map[string]bool, error) {
	scopes := []flarecloudflare.AccessScope{{}}
	listed := map[string]bool{"": true}
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, zone := range zones {
		scopes = append(scopes, flarecloudflare.AccessScope{ZoneID: zone.ID})
		listed[zone.ID] = true
	}
	return scopes, listed, nil
}

// zoneIDByName maps a normalized spec.zone DNS name (lowercase, no
// trailing dot — the controller's normalization) to the zone ID.
func zoneIDByName(zones []flarecloudflare.Zone) map[string]string {
	byName := make(map[string]string, len(zones))
	for _, zone := range zones {
		byName[normalizeZoneName(zone.Name)] = zone.ID
	}
	return byName
}

// normalizeZoneName mirrors the controller's spec.zone normalization.
func normalizeZoneName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// resolveScope maps a spec.zone value to the listing scope: "" stays
// account scope, a known zone name becomes its ID, an unknown zone name
// returns ok=false so the ref is never judged against a listing that
// cannot contain it.
func resolveScope(zoneName string, byName map[string]string) (string, bool) {
	if zoneName == "" {
		return "", true
	}
	id, ok := byName[normalizeZoneName(zoneName)]
	return id, ok
}

// listAccessApplications collects applications across every scope. Any
// scope that fails makes the whole listing incomplete (fail-closed).
func (as *AccountSweeper) listAccessApplications(ctx context.Context, api flarecloudflare.API, wait func(context.Context) error, scopes []flarecloudflare.AccessScope) ([]flarecloudflare.AccessApplication, error) {
	var all []flarecloudflare.AccessApplication
	for _, scope := range scopes {
		if err := wait(ctx); err != nil {
			return nil, err
		}
		apps, err := api.ListAccessApplications(ctx, scope)
		if err != nil {
			return nil, listFailure(err)
		}
		all = append(all, apps...)
	}
	return all, nil
}

// sweepAccessApplications covers AccessApplication CRs. Remote ownership
// is proven by the managed tag plus an owner tag (HMAC or legacy).
func sweepAccessApplications(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	scopes, listed, err := as.accessScopes(ctx)
	if err != nil {
		return nil, err
	}
	remotes, err := as.listAccessApplications(ctx, api, wait, scopes)
	if err != nil {
		return nil, err
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	key := as.ownershipKey(ctx)
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, err
	}
	byName := zoneIDByName(zones)

	var list v1alpha1.AccessApplicationList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessApplications: %w", err)
	}
	var refs []localRef
	markers := make(map[types.NamespacedName][]string)
	for i := range list.Items {
		app := &list.Items[i]
		if app.Spec.AccountRef.Name != as.accountName || deleting(app) || observeOnly(app.Spec.ManagementPolicy) {
			continue
		}
		scope, ok := resolveScope(app.Spec.Zone, byName)
		if !ok {
			continue
		}
		expectedName := app.Spec.Application.Name
		if expectedName == "" {
			expectedName = app.Namespace + "/" + app.Name
		}
		ref := localRef{
			kind: "AccessApplication", key: types.NamespacedName{Namespace: app.Namespace, Name: app.Name},
			uid: app.UID, remoteID: app.Status.ApplicationID, expectedName: expectedName,
			specName: app.Name, scope: scope,
		}
		refs = append(refs, ref)
		markers[ref.key] = accessOwnerMarkers(key, clusterID, app.Namespace, app.Name, app.UID)
	}

	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessApplication]{
		kind:   "AccessApplication",
		idOf:   func(a flarecloudflare.AccessApplication) string { return a.ID },
		listed: scopeListed(listed),
		nameOf: func(a flarecloudflare.AccessApplication) string { return a.Name },
		extra: func(ref localRef, remote flarecloudflare.AccessApplication) string {
			mine := markers[ref.key]
			if !hasAnyTag(remote.Tags, []string{accessManagedTag}) {
				return "remote application lost the flareway-managed tag"
			}
			if !hasAnyTag(remote.Tags, mine) {
				return "remote application lost this object's owner tag"
			}
			if foreign := foreignOwnerTags(remote.Tags, mine); len(foreign) > 0 {
				return fmt.Sprintf("remote application carries foreign owner tags %v", foreign)
			}
			return ""
		},
		orphan: func(remote flarecloudflare.AccessApplication, _ map[string]bool) (types.NamespacedName, bool) {
			if !hasAnyTag(remote.Tags, []string{accessManagedTag}) || hasBypassTag(remote.Tags) {
				return types.NamespacedName{}, false
			}
			for _, ref := range refs {
				if hasAnyTag(remote.Tags, markers[ref.key]) {
					// The owner tag matches a live CR: orphan only when the
					// CR's recorded remote ID points elsewhere (the remote
					// was replaced out-of-band).
					if ref.remoteID != remote.ID {
						return ref.key, true
					}
					return types.NamespacedName{}, false
				}
			}
			return types.NamespacedName{}, false
		},
	}), nil
}

// sweepAccessStandaloneApplications covers AccessStandaloneApplication
// CRs. They carry no owner tags, so matching is by status ID and the
// generated "flareway/<clusterID>/<ns>/<name>" remote name.
func sweepAccessStandaloneApplications(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	scopes, listed, err := as.accessScopes(ctx)
	if err != nil {
		return nil, err
	}
	remotes, err := as.listAccessApplications(ctx, api, wait, scopes)
	if err != nil {
		return nil, err
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, err
	}
	byName := zoneIDByName(zones)

	var list v1alpha1.AccessStandaloneApplicationList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessStandaloneApplications: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		app := &list.Items[i]
		if app.Spec.AccountRef.Name != as.accountName || deleting(app) || observeOnly(app.Spec.ManagementPolicy) {
			continue
		}
		scope, ok := resolveScope(app.Spec.Zone, byName)
		if !ok {
			continue
		}
		expectedName := app.Spec.Application.Name
		if expectedName == "" && app.Spec.Type != v1alpha1.AccessStandaloneApplicationTypeWARP {
			expectedName = accessRemoteNameValue(clusterID, app.Namespace, app.Name)
		}
		refs = append(refs, localRef{
			kind: "AccessStandaloneApplication", key: types.NamespacedName{Namespace: app.Namespace, Name: app.Name},
			uid: app.UID, remoteID: app.Status.ApplicationID, expectedName: expectedName,
			specName: app.Name, scope: scope,
		})
	}

	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessApplication]{
		kind:   "AccessStandaloneApplication",
		idOf:   func(a flarecloudflare.AccessApplication) string { return a.ID },
		listed: scopeListed(listed),
		nameOf: func(a flarecloudflare.AccessApplication) string { return a.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(a flarecloudflare.AccessApplication) string { return a.ID },
			func(a flarecloudflare.AccessApplication) string { return a.Name }),
	}), nil
}

// accessNamedOrphan builds the orphan predicate for kinds whose remote
// name is accessRemoteName(clusterID, ns, specName). A remote whose name
// parses with our cluster ID and matches no live CR's specName is an
// orphan candidate; a remote matching a CR whose recorded ID points
// elsewhere is an orphan attributed to that CR.
func accessNamedOrphan[R any](clusterID string, refs []localRef, idOf, nameOf func(R) string) func(R, map[string]bool) (types.NamespacedName, bool) {
	return func(remote R, _ map[string]bool) (types.NamespacedName, bool) {
		ownerCluster, namespace, specName, ok := parseAccessRemoteName(nameOf(remote))
		if !ok || ownerCluster != clusterID {
			return types.NamespacedName{}, false
		}
		for _, ref := range refs {
			if ref.key.Namespace == namespace && ref.specName == specName {
				if ref.remoteID != idOf(remote) {
					return ref.key, true
				}
				return types.NamespacedName{}, false
			}
		}
		return types.NamespacedName{Namespace: namespace, Name: specName}, true
	}
}

func sweepAccessPolicies(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListAccessPolicies(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	var list v1alpha1.AccessPolicyList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessPolicies: %w", err)
	}
	var refs []localRef
	decisions := make(map[types.NamespacedName]string)
	for i := range list.Items {
		policy := &list.Items[i]
		if policy.Spec.AccountRef.Name != as.accountName || deleting(policy) || observeOnly(policy.Spec.ManagementPolicy) {
			continue
		}
		key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
		refs = append(refs, localRef{
			kind: "AccessPolicy", key: key,
			uid: policy.UID, remoteID: policy.Status.PolicyID,
			expectedName: accessRemoteNameValue(clusterID, policy.Namespace, policy.Spec.Name),
			specName:     policy.Spec.Name,
		})
		decisions[key] = string(policy.Spec.Decision)
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessPolicy]{
		kind:   "AccessPolicy",
		idOf:   func(p flarecloudflare.AccessPolicy) string { return p.ID },
		listed: accountScopeListed,
		nameOf: func(p flarecloudflare.AccessPolicy) string { return p.Name },
		extra: func(ref localRef, remote flarecloudflare.AccessPolicy) string {
			if want := decisions[ref.key]; want != "" && remote.Decision != want {
				return fmt.Sprintf("remote decision %q does not match spec decision %q", remote.Decision, want)
			}
			return ""
		},
		orphan: accessNamedOrphan(clusterID, refs,
			func(p flarecloudflare.AccessPolicy) string { return p.ID },
			func(p flarecloudflare.AccessPolicy) string { return p.Name }),
	}), nil
}

func sweepAccessGroups(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	scopes, listed, err := as.accessScopes(ctx)
	if err != nil {
		return nil, err
	}
	var remotes []flarecloudflare.AccessGroup
	for _, scope := range scopes {
		if err := wait(ctx); err != nil {
			return nil, err
		}
		groups, err := api.ListAccessGroups(ctx, flarecloudflare.AccessGroupListOptions{Scope: scope})
		if err != nil {
			return nil, listFailure(err)
		}
		remotes = append(remotes, groups...)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, err
	}
	byName := zoneIDByName(zones)

	var list v1alpha1.AccessGroupList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessGroups: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		group := &list.Items[i]
		if group.Spec.AccountRef.Name != as.accountName || deleting(group) || observeOnly(group.Spec.ManagementPolicy) {
			continue
		}
		scope, ok := resolveScope(group.Spec.Zone, byName)
		if !ok {
			continue
		}
		refs = append(refs, localRef{
			kind: "AccessGroup", key: types.NamespacedName{Namespace: group.Namespace, Name: group.Name},
			uid: group.UID, remoteID: group.Status.GroupID,
			expectedName: accessRemoteNameValue(clusterID, group.Namespace, group.Spec.Name),
			specName:     group.Spec.Name, scope: scope,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessGroup]{
		kind:   "AccessGroup",
		idOf:   func(g flarecloudflare.AccessGroup) string { return g.ID },
		listed: scopeListed(listed),
		nameOf: func(g flarecloudflare.AccessGroup) string { return g.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(g flarecloudflare.AccessGroup) string { return g.ID },
			func(g flarecloudflare.AccessGroup) string { return g.Name }),
	}), nil
}

func sweepServiceTokens(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	scopes, listed, err := as.accessScopes(ctx)
	if err != nil {
		return nil, err
	}
	var remotes []flarecloudflare.ServiceToken
	for _, scope := range scopes {
		if err := wait(ctx); err != nil {
			return nil, err
		}
		tokens, err := api.ListServiceTokens(ctx, scope)
		if err != nil {
			return nil, listFailure(err)
		}
		remotes = append(remotes, tokens...)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, err
	}
	byName := zoneIDByName(zones)

	var list v1alpha1.ServiceTokenList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list ServiceTokens: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		token := &list.Items[i]
		if token.Spec.AccountRef.Name != as.accountName || deleting(token) || observeOnly(token.Spec.ManagementPolicy) {
			continue
		}
		scope, ok := resolveScope(token.Spec.Zone, byName)
		if !ok {
			continue
		}
		refs = append(refs, localRef{
			kind: "ServiceToken", key: types.NamespacedName{Namespace: token.Namespace, Name: token.Name},
			uid: token.UID, remoteID: token.Status.TokenID,
			expectedName: accessRemoteNameValue(clusterID, token.Namespace, token.Spec.Name),
			specName:     token.Spec.Name, scope: scope,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.ServiceToken]{
		kind:   "ServiceToken",
		idOf:   func(t flarecloudflare.ServiceToken) string { return t.ID },
		listed: scopeListed(listed),
		nameOf: func(t flarecloudflare.ServiceToken) string { return t.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(t flarecloudflare.ServiceToken) string { return t.ID },
			func(t flarecloudflare.ServiceToken) string { return t.Name }),
	}), nil
}

func sweepIdentityProviders(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListIdentityProviders(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	var list v1alpha1.IdentityProviderList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list IdentityProviders: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		idp := &list.Items[i]
		if idp.Spec.AccountRef.Name != as.accountName || deleting(idp) || observeOnly(idp.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "IdentityProvider", key: types.NamespacedName{Namespace: idp.Namespace, Name: idp.Name},
			uid: idp.UID, remoteID: idp.Status.IDPID,
			expectedName: accessRemoteNameValue(clusterID, idp.Namespace, idp.Spec.Name),
			specName:     idp.Spec.Name,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.IdentityProvider]{
		kind:   "IdentityProvider",
		idOf:   func(p flarecloudflare.IdentityProvider) string { return p.ID },
		listed: accountScopeListed,
		nameOf: func(p flarecloudflare.IdentityProvider) string { return p.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(p flarecloudflare.IdentityProvider) string { return p.ID },
			func(p flarecloudflare.IdentityProvider) string { return p.Name }),
	}), nil
}

func sweepAccessCustomPages(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListAccessCustomPages(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	var list v1alpha1.AccessCustomPageList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessCustomPages: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		page := &list.Items[i]
		if page.Spec.AccountRef.Name != as.accountName || deleting(page) || observeOnly(page.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "AccessCustomPage", key: types.NamespacedName{Namespace: page.Namespace, Name: page.Name},
			uid: page.UID, remoteID: page.Status.CustomPageID,
			expectedName: accessRemoteNameValue(clusterID, page.Namespace, page.Spec.Name),
			specName:     page.Spec.Name,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessCustomPageSummary]{
		kind:   "AccessCustomPage",
		idOf:   func(p flarecloudflare.AccessCustomPageSummary) string { return p.ID },
		listed: accountScopeListed,
		nameOf: func(p flarecloudflare.AccessCustomPageSummary) string { return p.Name },
		orphan: accessNamedOrphan(clusterID, refs,
			func(p flarecloudflare.AccessCustomPageSummary) string { return p.ID },
			func(p flarecloudflare.AccessCustomPageSummary) string { return p.Name }),
	}), nil
}

func sweepAccessInfrastructureTargets(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	if err := wait(ctx); err != nil {
		return nil, err
	}
	remotes, err := api.ListAccessInfrastructureTargets(ctx)
	if err != nil {
		return nil, listFailure(err)
	}
	var list v1alpha1.AccessInfrastructureTargetList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list AccessInfrastructureTargets: %w", err)
	}
	var refs []localRef
	for i := range list.Items {
		target := &list.Items[i]
		if target.Spec.AccountRef.Name != as.accountName || deleting(target) || observeOnly(target.Spec.ManagementPolicy) {
			continue
		}
		refs = append(refs, localRef{
			kind: "AccessInfrastructureTarget", key: types.NamespacedName{Namespace: target.Namespace, Name: target.Name},
			uid: target.UID, remoteID: target.Status.TargetID,
			expectedName: target.Spec.Hostname,
		})
	}
	return classify(refs, remotes, classifyOptions[flarecloudflare.AccessInfrastructureTarget]{
		kind:      "AccessInfrastructureTarget",
		idOf:      func(t flarecloudflare.AccessInfrastructureTarget) string { return t.ID },
		listed:    accountScopeListed,
		nameOf:    func(t flarecloudflare.AccessInfrastructureTarget) string { return t.Hostname },
		nameEqual: strings.EqualFold,
		// Remote targets carry no ownership marker: no orphan detection.
	}), nil
}
