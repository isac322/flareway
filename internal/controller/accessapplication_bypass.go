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

package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	pathpkg "path"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

func (r *AccessApplicationReconciler) reconcileBypassApplications(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	bypasses []gatewayapi.AccessBypass,
	ownerTag string,
	clusterID string,
) ([]v1alpha1.AccessBypassApplicationStatus, *bypassExpectation, error) {
	declarations, err := declaredBypassChildren(application)
	if err != nil {
		return nil, nil, err
	}
	observeOnly := effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly
	existing := make(map[string]v1alpha1.AccessBypassApplicationStatus, len(application.Status.BypassApplications))
	for _, child := range application.Status.BypassApplications {
		existing[bypassStatusKey(child.Hostname, child.Path)] = child
	}
	if observeOnly {
		result := make([]v1alpha1.AccessBypassApplicationStatus, 0, len(bypasses))
		for _, bypass := range bypasses {
			key := bypassStatusKey(bypass.Hostname, bypass.Path)
			declared, found := declarations[key]
			if !found || declared.ExternalRef == nil {
				return nil, nil, fmt.Errorf("validation BypassNotDeclared: ObserveOnly bypass %s%s requires a declared externalRef", bypass.Hostname, bypass.Path)
			}
			child, err := remote.GetAccessApplication(ctx, scope, declared.ExternalRef.ApplicationID)
			if err != nil {
				return nil, nil, fmt.Errorf("observe bypass Access application %s%s: %w", bypass.Hostname, bypass.Path, err)
			}
			if err := verifyAccessApplicationExpectation(child, declared.Adoption.Expect); err != nil {
				return nil, nil, err
			}
			policyID := ""
			if len(child.Policies) > 0 {
				policyID = child.Policies[0].ID
			}
			result = append(result, v1alpha1.AccessBypassApplicationStatus{
				Hostname: bypass.Hostname, Path: bypass.Path, ApplicationID: child.ID,
				Name: child.Name, PolicyID: policyID, Origin: v1alpha1.AccessBypassApplicationOriginAdopted,
				DeletionPolicy: effectiveBypassDeletionPolicy(declared.DeletionPolicy),
			})
		}
		sortBypassStatuses(result)
		return result, nil, nil
	}

	parentName := accessApplicationRemoteName(application)
	// D13: writes carry exactly one owner marker and one bypass marker — the
	// signed owner tag when the cluster ownership key is available, the legacy
	// plaintext tag otherwise. Reads still accept every generation of marker.
	signingKey, ownerTags, writeOwnerTag := r.accessOwnerTags(ctx, application, ownerTag)
	ownedRemote, err := listOwnedBypassApplications(ctx, remote, scope, ownerTags, signingKey)
	if err != nil {
		return nil, nil, err
	}
	needsDefaultPolicy := false
	for _, bypass := range bypasses {
		declared, found := declarations[bypassStatusKey(bypass.Hostname, bypass.Path)]
		needsDefaultPolicy = needsDefaultPolicy || !found || declared.PolicyRef == nil
	}
	var defaultPolicyID string
	if needsDefaultPolicy {
		bypassPolicy, err := remote.EnsureBypassPolicy(ctx, "flareway/"+clusterID+"/bypass-everyone")
		if err != nil {
			return nil, nil, fmt.Errorf("ensure account bypass policy: %w", err)
		}
		defaultPolicyID = bypassPolicy.ID
	}

	expectation := &bypassExpectation{ownerTags: ownerTags, signingKey: signingKey}
	falseValue := false
	result := make([]v1alpha1.AccessBypassApplicationStatus, 0, len(bypasses))
	desiredKeys := make(map[string]struct{}, len(bypasses))
	desiredTags := make(map[string]struct{}, len(bypasses))
	for _, bypass := range bypasses {
		key := bypassStatusKey(bypass.Hostname, bypass.Path)
		desiredKeys[key] = struct{}{}
		declared, declaredFound := declarations[key]
		childName := bypassChildApplicationName(parentName, bypass.Hostname, bypass.Path)
		deletionPolicy := v1alpha1.DeletionPolicyDelete
		if declaredFound {
			if declared.Name != "" {
				childName = declared.Name
			}
			deletionPolicy = effectiveBypassDeletionPolicy(declared.DeletionPolicy)
		}
		// Reads accept every marker generation; the write carries only the
		// digest derived from the owner tag this reconcile writes.
		bypassMarkers := accessBypassMarkersForOwners(signingKey, ownerTags, childName)
		tagName := accessBypassTag(writeOwnerTag, childName)
		for _, marker := range bypassMarkers {
			desiredTags[marker] = struct{}{}
		}
		policyID := defaultPolicyID
		if declaredFound && declared.PolicyRef != nil {
			policyID, err = r.resolveBypassPolicyReference(ctx, application, application.Spec.AccountRef.Name, remote, *declared.PolicyRef)
			if err != nil {
				return nil, nil, err
			}
		}
		uri := strings.TrimSuffix(strings.ToLower(bypass.Hostname), "/") + bypass.Path
		tags := []string{accessManagedTag, tagName, writeOwnerTag}
		slices.Sort(tags)
		input := flarecloudflare.AccessApplicationInput{
			Type:                   flarecloudflare.AccessApplicationTypeSelfHosted,
			Domain:                 uri,
			Name:                   childName,
			Destinations:           []flarecloudflare.AccessApplicationDestination{{Type: flarecloudflare.AccessApplicationDestinationTypePublic, URI: uri}},
			Policies:               []flarecloudflare.AccessApplicationPolicyAttachment{{ID: policyID, Precedence: 1}},
			SessionDuration:        "0s",
			AppLauncherVisible:     &falseValue,
			AutoRedirectToIdentity: &falseValue,
			AllowedIDPs:            []string{},
			Tags:                   tags,
		}

		var child flarecloudflare.AccessApplication
		origin := v1alpha1.AccessBypassApplicationOriginRecovered
		selected := false
		previous := existing[key]
		if declaredFound && declared.ExternalRef != nil {
			if declared.Adoption.Mode != v1alpha1.AdoptionModeAdoptByID {
				return nil, nil, fmt.Errorf("managed bypass %s%s externalRef requires adoption.mode AdoptById", bypass.Hostname, bypass.Path)
			}
			child, err = remote.GetAccessApplication(ctx, scope, declared.ExternalRef.ApplicationID)
			if err != nil {
				return nil, nil, fmt.Errorf("get adopted bypass Access application %s%s: %w", bypass.Hostname, bypass.Path, err)
			}
			managedRecovery := false
			if previous.ApplicationID == declared.ExternalRef.ApplicationID &&
				previous.Origin == v1alpha1.AccessBypassApplicationOriginAdopted &&
				previous.Name != "" {
				previousMarkers := accessBypassMarkersForOwners(signingKey, ownerTags, previous.Name)
				if !ownedBypassApplication(child, ownerTags, previousMarkers, previous.Name) {
					return nil, nil, fmt.Errorf("ownership conflict: adopted bypass Access application %q is not owned by this resource", previous.ApplicationID)
				}
				managedRecovery = true
			} else if previous.ApplicationID == "" && ownedBypassApplication(child, ownerTags, bypassMarkers, childName) {
				managedRecovery = true
			}
			if !managedRecovery {
				if err := verifyAccessApplicationExpectation(child, declared.Adoption.Expect); err != nil {
					return nil, nil, err
				}
			}
			origin = v1alpha1.AccessBypassApplicationOriginAdopted
			selected = true
		}
		if !selected {
			if previous.ApplicationID != "" {
				child, err = remote.GetAccessApplication(ctx, scope, previous.ApplicationID)
				if err == nil {
					if !ownedBypassApplication(child, ownerTags, bypassMarkers, childName) {
						return nil, nil, fmt.Errorf("ownership conflict: bypass Access application %q is not owned by this resource", previous.ApplicationID)
					}
					origin = previous.Origin
					if origin == "" {
						origin = v1alpha1.AccessBypassApplicationOriginRecovered
					}
					selected = true
				} else if !isRemoteNotFound(err) {
					return nil, nil, err
				}
			}
		}
		if !selected {
			for _, marker := range bypassMarkers {
				recovered, found := ownedRemote[marker]
				if !found {
					continue
				}
				if recovered.Name != childName {
					return nil, nil, fmt.Errorf("ownership conflict: bypass tag %q belongs to Access application name %q, want %q", marker, recovered.Name, childName)
				}
				child = recovered
				origin = v1alpha1.AccessBypassApplicationOriginRecovered
				selected = true
				break
			}
		}
		if selected {
			if !accessApplicationMatchesInput(child, input) {
				if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
					return nil, nil, fmt.Errorf("ensure bypass Access tags for %s%s: %w", bypass.Hostname, bypass.Path, err)
				}
				child, err = remote.UpdateAccessApplication(ctx, scope, child.ID, input)
			}
		} else {
			if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
				return nil, nil, fmt.Errorf("ensure bypass Access tags for %s%s: %w", bypass.Hostname, bypass.Path, err)
			}
			var created flarecloudflare.AccessApplicationCreateResult
			created, err = remote.CreateAccessApplication(ctx, scope, input)
			if err == nil {
				child = created.Application
				origin = v1alpha1.AccessBypassApplicationOriginCreated
			} else {
				createErr := err
				recovered, found, recoveryErr := findOwnedBypassApplication(ctx, remote, scope, ownerTags, bypassMarkers, childName)
				switch {
				case recoveryErr != nil:
					err = errors.Join(createErr, recoveryErr)
				case found:
					child = recovered
					origin = v1alpha1.AccessBypassApplicationOriginRecovered
					err = nil
				default:
					err = createErr
				}
			}
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reconcile bypass Access application for %s%s: %w", bypass.Hostname, bypass.Path, err)
		}
		status := v1alpha1.AccessBypassApplicationStatus{
			Hostname: bypass.Hostname, Path: bypass.Path, ApplicationID: child.ID,
			Name: child.Name, PolicyID: policyID, Origin: origin, DeletionPolicy: deletionPolicy,
		}
		if !reflect.DeepEqual(existing[key], status) {
			if err := r.persistChildID(ctx, application, status); err != nil {
				return nil, nil, err
			}
			upsertLocalBypassStatus(application, status)
			existing[key] = status
		}
		result = append(result, status)
		expectation.children = append(expectation.children, bypassChildExpectation{id: child.ID, input: input})
	}
	expectation.desiredTags = desiredTags

	prune := make(map[string]v1alpha1.AccessBypassApplicationStatus)
	for _, status := range application.Status.BypassApplications {
		if _, retained := desiredKeys[bypassStatusKey(status.Hostname, status.Path)]; retained || status.ApplicationID == "" {
			continue
		}
		prune[status.ApplicationID] = status
	}
	for tagName, child := range ownedRemote {
		if _, retained := desiredTags[tagName]; retained {
			continue
		}
		if _, known := prune[child.ID]; !known {
			prune[child.ID] = v1alpha1.AccessBypassApplicationStatus{
				ApplicationID: child.ID, Name: child.Name, Origin: v1alpha1.AccessBypassApplicationOriginRecovered,
				DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			}
		}
	}
	deleteTags := make(map[string]struct{})
	for _, id := range sortedBypassPruneIDs(prune) {
		status := prune[id]
		child, err := remote.GetAccessApplication(ctx, scope, id)
		if isRemoteNotFound(err) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("get obsolete bypass Access application %s: %w", id, err)
		}
		childName := status.Name
		if childName == "" && status.Hostname != "" {
			childName = bypassChildApplicationName(parentName, status.Hostname, status.Path)
		}
		pruneMarkers := accessBypassMarkersForOwners(signingKey, ownerTags, childName)
		if !ownedBypassApplication(child, ownerTags, pruneMarkers, childName) {
			continue
		}
		if effectiveBypassDeletionPolicy(status.DeletionPolicy) == v1alpha1.DeletionPolicyOrphan {
			input := accessApplicationInputFromObserved(child)
			input.Tags = removeAccessTags(input.Tags, append(append([]string{accessManagedTag}, ownerTags...), pruneMarkers...)...)
			if !accessApplicationMatchesInput(child, input) {
				if _, err := remote.UpdateAccessApplication(ctx, scope, child.ID, input); err != nil {
					return nil, nil, fmt.Errorf("orphan bypass Access application %s: %w", id, err)
				}
			}
		} else if err := remote.DeleteAccessApplication(ctx, scope, id); err != nil && !isRemoteNotFound(err) {
			return nil, nil, fmt.Errorf("delete obsolete bypass Access application %s: %w", id, err)
		}
		for _, marker := range pruneMarkers {
			deleteTags[marker] = struct{}{}
		}
	}
	for _, tagName := range sortedStringKeys(deleteTags) {
		if err := remote.DeleteAccessTag(ctx, tagName); err != nil && !isRemoteNotFound(err) {
			return nil, nil, fmt.Errorf("delete obsolete bypass Access tag %q: %w", tagName, err)
		}
	}
	sortBypassStatuses(result)
	return result, expectation, nil
}

// bypassExpectation is what a converged pass established about an
// application's bypass children, in a form a drift sweep's application
// listing can check: every desired child exists with its desired content, and
// no other application carries this owner's bypass marker (the pass would
// have pruned it).
type bypassExpectation struct {
	children    []bypassChildExpectation
	ownerTags   []string
	signingKey  []byte
	desiredTags map[string]struct{}
}

type bypassChildExpectation struct {
	id    string
	input flarecloudflare.AccessApplicationInput
}

// matches reports whether the listed applications still satisfy the
// expectation. A nil expectation (ObserveOnly) never matches.
func (expectation *bypassExpectation) matches(listed map[string]flarecloudflare.AccessApplication) bool {
	if expectation == nil || listed == nil {
		return false
	}
	ids := make(map[string]struct{}, len(expectation.children))
	for _, child := range expectation.children {
		remote, found := listed[child.id]
		if !found || !accessApplicationPoliciesEmbedded(remote) || !accessApplicationMatchesInput(remote, child.input) {
			return false
		}
		ids[child.id] = struct{}{}
	}
	for _, application := range listed {
		tagName, owned := ownedBypassApplicationTag(application, expectation.ownerTags, expectation.signingKey)
		if !owned {
			continue
		}
		if _, desired := expectation.desiredTags[tagName]; !desired {
			return false
		}
		if _, known := ids[application.ID]; !known {
			return false
		}
	}
	return true
}

func listOwnedBypassApplications(ctx context.Context, remote AccessApplicationCloudflareClient, scope flarecloudflare.AccessScope, ownerTags []string, key []byte) (map[string]flarecloudflare.AccessApplication, error) {
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list bypass Access applications for ownership recovery: %w", err)
	}
	result := make(map[string]flarecloudflare.AccessApplication)
	for _, application := range applications {
		tagName, owned := ownedBypassApplicationTag(application, ownerTags, key)
		if !owned {
			continue
		}
		if existing, found := result[tagName]; found && existing.ID != application.ID {
			return nil, fmt.Errorf("multiple Access applications carry bypass tag %q", tagName)
		}
		result[tagName] = application
	}
	return result, nil
}

func findOwnedBypassApplication(ctx context.Context, remote AccessApplicationCloudflareClient, scope flarecloudflare.AccessScope, ownerTags, bypassTags []string, expectedName string) (flarecloudflare.AccessApplication, bool, error) {
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return flarecloudflare.AccessApplication{}, false, fmt.Errorf("list bypass Access applications for ownership recovery: %w", err)
	}
	var found flarecloudflare.AccessApplication
	for _, application := range applications {
		if !ownedBypassApplication(application, ownerTags, bypassTags, expectedName) {
			continue
		}
		if found.ID != "" && found.ID != application.ID {
			return flarecloudflare.AccessApplication{}, false, fmt.Errorf("multiple Access applications carry bypass tags %v and name %q", bypassTags, expectedName)
		}
		found = application
	}
	return found, found.ID != "", nil
}

func validateBypassDeclarations(application *v1alpha1.AccessApplication, compilation gatewayapi.AccessApplicationCompilation) *gatewayapi.AccessApplicationCompilation {
	declarations, err := declaredBypassChildren(application)
	if err != nil {
		invalid := rejectedFrom(compilation, "Invalid", err.Error())
		return &invalid
	}
	compiled := make(map[string]struct{}, len(compilation.Bypass))
	for _, bypass := range compilation.Bypass {
		compiled[bypassStatusKey(bypass.Hostname, bypass.Path)] = struct{}{}
	}
	for key, declaration := range declarations {
		if _, found := compiled[key]; found {
			continue
		}
		invalid := rejectedFrom(compilation, "BypassNotCompiled", fmt.Sprintf("declared bypass %s%s is not compiled from a public HTTPRoute carve-out", declaration.Hostname, declaration.Path))
		return &invalid
	}
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		for _, bypass := range compilation.Bypass {
			declaration, found := declarations[bypassStatusKey(bypass.Hostname, bypass.Path)]
			if found && declaration.ExternalRef != nil {
				continue
			}
			invalid := rejectedFrom(compilation, "BypassNotDeclared", fmt.Sprintf("ObserveOnly bypass %s%s requires a declared externalRef", bypass.Hostname, bypass.Path))
			return &invalid
		}
	}
	return nil
}

func declaredBypassChildren(application *v1alpha1.AccessApplication) (map[string]v1alpha1.AccessBypassChildSpec, error) {
	result := make(map[string]v1alpha1.AccessBypassChildSpec, len(application.Spec.Bypass.Children))
	for index, child := range application.Spec.Bypass.Children {
		hostname := strings.ToLower(strings.TrimSuffix(child.Hostname, "."))
		path, err := normalizeBypassPath(child.Path)
		if err != nil {
			return nil, fmt.Errorf("bypass.children[%d].path: %w", index, err)
		}
		child.Hostname = hostname
		child.Path = path
		key := bypassStatusKey(hostname, path)
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("multiple bypass child declarations normalize to %s%s", hostname, path)
		}
		result[key] = child
	}
	return result, nil
}

func normalizeBypassPath(value string) (string, error) {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(decoded, "/") {
		return "", fmt.Errorf("path %q must start with /", value)
	}
	normalized := pathpkg.Clean(decoded)
	if normalized == "." || normalized == "" {
		return "/", nil
	}
	return normalized, nil
}

func (r *AccessApplicationReconciler) resolveBypassPolicyReference(
	ctx context.Context,
	application *v1alpha1.AccessApplication,
	accountName string,
	remote AccessApplicationCloudflareClient,
	reference v1alpha1.AccessApplicationPolicyReference,
) (string, error) {
	if reference.ExternalRef != nil {
		policy, err := remote.GetAccessPolicy(ctx, reference.ExternalRef.PolicyID)
		if err != nil {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external bypass Access policy %q could not be resolved: %v", reference.ExternalRef.PolicyID, err)}
		}
		if policy.Decision != string(v1alpha1.AccessPolicyDecisionBypass) {
			return "", accessValidationError{reason: "Invalid", message: fmt.Sprintf("external Access policy %q has decision %q, want Bypass", policy.ID, policy.Decision)}
		}
		return policy.ID, nil
	}
	if reference.PolicyRef == nil {
		return "", accessValidationError{reason: "Invalid", message: "bypass policy reference is empty"}
	}
	namespace := reference.PolicyRef.Namespace
	if namespace == "" {
		namespace = application.Namespace
	}
	var policy v1alpha1.AccessPolicy
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.PolicyRef.Name}, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessPolicy %s/%s was not found", namespace, reference.PolicyRef.Name)}
		}
		return "", fmt.Errorf("get AccessPolicy %s/%s: %w", namespace, reference.PolicyRef.Name, err)
	}
	if policy.Spec.Decision != v1alpha1.AccessPolicyDecisionBypass {
		return "", accessValidationError{reason: "Invalid", message: fmt.Sprintf("the AccessPolicy %s/%s has decision %q, want Bypass", namespace, policy.Name, policy.Spec.Decision)}
	}
	if policy.Spec.AccountRef.Name != accountName {
		return "", fmt.Errorf("the AccessPolicy %s/%s uses CloudflareAccount %q, want %q", namespace, policy.Name, policy.Spec.AccountRef.Name, accountName)
	}
	if namespace != application.Namespace {
		var applicationNamespace corev1.Namespace
		if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, &applicationNamespace); err != nil {
			return "", fmt.Errorf("get AccessApplication namespace: %w", err)
		}
		allowed := false
		var account v1alpha1.CloudflareAccount
		if err := r.Get(ctx, types.NamespacedName{Name: accountName}, &account); err != nil {
			return "", fmt.Errorf("get CloudflareAccount %q: %w", accountName, err)
		}
		for _, grant := range account.Spec.Grants {
			selector, err := metav1.LabelSelectorAsSelector(&grant.NamespaceSelector)
			if err == nil && selector.Matches(labels.Set(applicationNamespace.Labels)) && grant.AccessPolicyRefs == v1alpha1.GrantPermissionAllowed {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("the AccessPolicy %s/%s is not permitted by CloudflareAccount grants", namespace, policy.Name)
		}
	}
	if policy.Status.PolicyID == "" || !gatewaystatus.ConditionTrue(policy.Status.Conditions, accessApplicationConditionAccepted) || !policy.DeletionTimestamp.IsZero() {
		return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessPolicy %s/%s is not accepted", namespace, policy.Name)}
	}
	policyID := policy.Status.PolicyID
	if effectiveManagementPolicy(policy.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		observed, err := remote.GetAccessPolicy(ctx, policyID)
		if err != nil {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessPolicy %s/%s remote policy could not be resolved: %v", namespace, policy.Name, err)}
		}
		if observed.Decision != string(v1alpha1.AccessPolicyDecisionBypass) {
			return "", accessValidationError{reason: "Invalid", message: fmt.Sprintf("the AccessPolicy %s/%s remote decision is %q, want Bypass", namespace, policy.Name, observed.Decision)}
		}
	}
	return policyID, nil
}

func ownedBypassApplication(application flarecloudflare.AccessApplication, ownerTags, bypassTags []string, expectedName string) bool {
	return application.Name == expectedName &&
		hasAccessTag(application.Tags, accessManagedTag) &&
		hasAnyAccessTag(application.Tags, ownerTags) &&
		hasAnyAccessTag(application.Tags, bypassTags)
}

func sortBypassStatuses(values []v1alpha1.AccessBypassApplicationStatus) {
	slices.SortFunc(values, func(left, right v1alpha1.AccessBypassApplicationStatus) int {
		return strings.Compare(bypassStatusKey(left.Hostname, left.Path), bypassStatusKey(right.Hostname, right.Path))
	})
}

func sortedBypassPruneIDs(values map[string]v1alpha1.AccessBypassApplicationStatus) []string {
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	slices.Sort(result)
	return result
}

func removeAccessTags(values []string, removed ...string) []string {
	remove := make(map[string]struct{}, len(removed))
	for _, value := range removed {
		remove[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, found := remove[value]; !found {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func effectiveBypassDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

// ownedBypassApplicationTag returns the bypass marker the application carries,
// accepting both the legacy plaintext and the HMAC marker forms.
func ownedBypassApplicationTag(application flarecloudflare.AccessApplication, ownerTags []string, key []byte) (string, bool) {
	if !hasAccessTag(application.Tags, accessManagedTag) || !hasAnyAccessTag(application.Tags, ownerTags) {
		return "", false
	}
	for _, owner := range ownerTags {
		for _, marker := range accessBypassMarkers(key, owner, application.Name) {
			if hasAccessTag(application.Tags, marker) {
				return marker, true
			}
		}
	}
	return "", false
}

func upsertLocalBypassStatus(application *v1alpha1.AccessApplication, child v1alpha1.AccessBypassApplicationStatus) {
	key := bypassStatusKey(child.Hostname, child.Path)
	for index := range application.Status.BypassApplications {
		if bypassStatusKey(application.Status.BypassApplications[index].Hostname, application.Status.BypassApplications[index].Path) == key {
			application.Status.BypassApplications[index] = child
			return
		}
	}
	application.Status.BypassApplications = append(application.Status.BypassApplications, child)
}

func bypassStatusKey(hostname, path string) string {
	return strings.ToLower(strings.TrimSuffix(hostname, ".")) + "\x00" + path
}

func bypassChildApplicationName(parentName, hostname, path string) string {
	pathName := strings.Trim(strings.ReplaceAll(path, "/", "-"), "-")
	if pathName == "" {
		pathName = "root"
	}
	hostName := strings.NewReplacer(".", "-", "*", "wildcard").Replace(hostname)
	identity := sha256.Sum256([]byte(bypassStatusKey(hostname, path)))
	return fmt.Sprintf("%s/bypass/%s-%s-%x", parentName, hostName, pathName, identity[:6])
}

func (r *AccessApplicationReconciler) persistChildID(ctx context.Context, application *v1alpha1.AccessApplication, child v1alpha1.AccessBypassApplicationStatus) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current v1alpha1.AccessApplication
		if err := r.Get(ctx, client.ObjectKeyFromObject(application), &current); err != nil {
			return err
		}
		before := current.DeepCopy()
		key := bypassStatusKey(child.Hostname, child.Path)
		replaced := false
		for index := range current.Status.BypassApplications {
			if bypassStatusKey(current.Status.BypassApplications[index].Hostname, current.Status.BypassApplications[index].Path) == key {
				current.Status.BypassApplications[index] = child
				replaced = true
				break
			}
		}
		if !replaced {
			current.Status.BypassApplications = append(current.Status.BypassApplications, child)
		}
		return r.Status().Patch(ctx, &current, client.MergeFrom(before))
	})
}

// accessApplicationDeletionTargets classifies remote applications into the
// parent and bypass children owned by this AccessApplication. ownerTags
// carries every accepted owner marker (legacy plaintext plus the HMAC marker
// when the cluster key is available) and key signs the bypass markers.
func accessApplicationDeletionTargets(
	application *v1alpha1.AccessApplication,
	ownerTags []string,
	key []byte,
	applications []flarecloudflare.AccessApplication,
) (map[string]struct{}, map[string]struct{}, map[string]struct{}, error) {
	parentIDs := make(map[string]struct{})
	childIDs := make(map[string]struct{})
	bypassTags := make(map[string]struct{})
	childrenByID := make(map[string]v1alpha1.AccessBypassApplicationStatus, len(application.Status.BypassApplications))
	for _, child := range application.Status.BypassApplications {
		if child.ApplicationID != "" {
			childrenByID[child.ApplicationID] = child
		}
	}
	if _, duplicate := childrenByID[application.Status.ApplicationID]; application.Status.ApplicationID != "" && duplicate {
		return nil, nil, nil, fmt.Errorf("access application %s is recorded as both parent and bypass child", application.Status.ApplicationID)
	}
	parentName := accessApplicationRemoteName(application)
	for _, candidate := range applications {
		if !hasAccessTag(candidate.Tags, accessManagedTag) || !hasAnyAccessTag(candidate.Tags, ownerTags) {
			continue
		}
		if candidate.ID == application.Status.ApplicationID || candidate.Name == parentName {
			parentIDs[candidate.ID] = struct{}{}
			continue
		}
		if status, found := childrenByID[candidate.ID]; found {
			childName := status.Name
			if childName == "" {
				childName = bypassChildApplicationName(parentName, status.Hostname, status.Path)
			}
			markers := accessBypassMarkersForOwners(key, ownerTags, childName)
			if ownedBypassApplication(candidate, ownerTags, markers, childName) {
				childIDs[candidate.ID] = struct{}{}
				for _, marker := range markers {
					bypassTags[marker] = struct{}{}
				}
			}
			continue
		}
		tagName, owned := ownedBypassApplicationTag(candidate, ownerTags, key)
		if owned {
			childIDs[candidate.ID] = struct{}{}
			bypassTags[tagName] = struct{}{}
		}
	}
	return parentIDs, childIDs, bypassTags, nil
}
