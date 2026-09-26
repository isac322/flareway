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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	deviceProfileAccountIndex             = ".spec.accountRef.name.deviceProfile"
	deviceProfileAccountCredentialIndex   = ".spec.credentials.apiTokenSecretRef.deviceProfile"
	deviceProfileCloudflareAccountIDIndex = ".spec.accountId.deviceProfile"
	deviceProfileEntryLimit               = 1000
)

var privateHostnameRanges = []string{
	"100.80.0.0/16",
	"172.64.128.0/20",
	"2606:4700:0cf1:4000::/64",
}

// NewDeviceProfileCloudflareClient constructs an account-scoped device profile client.
type NewDeviceProfileCloudflareClient func(token, accountID string) (flarecloudflare.DeviceProfileAPI, error)

// DeviceProfileClientFromFactory adapts the shared production Cloudflare factory.
func DeviceProfileClientFromFactory(factory flarecloudflare.ClientFactory) NewDeviceProfileCloudflareClient {
	return func(token, accountID string) (flarecloudflare.DeviceProfileAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

// DeviceProfileReconciler is the sole aggregate writer for device profile fields and lists.
type DeviceProfileReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewDeviceProfileCloudflareClient
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceprofiles/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflareaccounts;networkroutes;hostnameroutes;accessapplications;virtualnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one DeviceProfile with the aggregate Cloudflare device profile.
func (r *DeviceProfileReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.DeviceProfile)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "DeviceProfile", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DeviceProfileFinalizer) {
		before := object.DeepCopy()
		controllerutil.AddFinalizer(object, v1alpha1.DeviceProfileFinalizer)
		if err := r.Patch(ctx, object, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add DeviceProfile finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}
	if err := r.refreshLiveStatus(ctx, object); err != nil {
		return ctrl.Result{}, err
	}

	api, account, namespace, err := r.clientForProfile(ctx, object)
	if err != nil {
		return r.finishRemoteError(ctx, object, err)
	}
	desired, err := r.aggregate(ctx, object, account, namespace)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	input, err := r.profileInput(ctx, object)
	if err != nil {
		return r.finishError(ctx, object, err)
	}

	profileID := declaredDeviceProfileID(object)
	if conflicts, err := r.writerConflicts(ctx, object, account.Spec.AccountID, profileID); err != nil {
		return r.finishRemoteError(ctx, object, err)
	} else if len(conflicts) > 0 {
		return r.finishConflict(ctx, object, profileID, conflicts)
	}
	var decision gateDecision
	if effectiveDeviceProfileManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		clusterID := gateClusterID(ctx, r.Client)
		decision = evaluateGate(r.Freshness, r.Invalidator, freshness.GradeIndirect, gateInput{
			Kind: "DeviceProfile", Namespace: object.Namespace, Name: object.Name,
			UID: object.UID, RemoteID: profileID,
			AccountID: account.Spec.AccountID, ClusterID: clusterID,
			Spec: struct {
				Spec     any `json:"spec"`
				Input    any `json:"input"`
				Include  any `json:"include"`
				Exclude  any `json:"exclude"`
				Fallback any `json:"fallback"`
			}{Spec: object.Spec, Input: input, Include: desired.include, Exclude: desired.exclude, Fallback: desired.fallback},
		}, object.Status.AppliedHash, object.Status.AppliedAt, time.Now())
		if decision.Open {
			return ctrl.Result{RequeueAfter: decision.Requeue}, nil
		}
	}

	remote, acquired, err := r.resolveRemoteProfile(ctx, api, object, input)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if acquired {
		message := "Custom device profile was created; whole-list ownership will be applied"
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			message = "Custom device profile was explicitly adopted; whole-list ownership will be applied"
		}
		// Checkpoint ownership only: desired lists become applied status after remote list synchronization.
		pending := deviceProfileStatus(object, remote.PolicyID, true, lastAppliedDeviceProfile(object), nil, nil, metav1.ConditionFalse, "Pending", message)
		if err := r.patchStatus(ctx, object, pending); err != nil {
			return ctrl.Result{}, err
		}
		object.Status = pending
	}
	profileID = remote.PolicyID
	if conflicts, err := r.writerConflicts(ctx, object, account.Spec.AccountID, profileID); err != nil {
		return r.finishRemoteError(ctx, object, err)
	} else if len(conflicts) > 0 {
		return r.finishConflict(ctx, object, profileID, conflicts)
	}

	ref := remoteProfileRef(object.Spec.Profile.Kind, profileID)
	include, err := api.GetDeviceProfileInclude(ctx, ref)
	if err != nil {
		return r.finishRemoteError(ctx, object, fmt.Errorf("get device profile include list: %w", err))
	}
	exclude, err := api.GetDeviceProfileExclude(ctx, ref)
	if err != nil {
		return r.finishRemoteError(ctx, object, fmt.Errorf("get device profile exclude list: %w", err))
	}
	fallback, err := api.GetDeviceProfileFallbackDomains(ctx, ref)
	if err != nil {
		return r.finishRemoteError(ctx, object, fmt.Errorf("get device profile fallback domains: %w", err))
	}
	wouldApply := profileDiff(remote, input, include, exclude, fallback, desired)

	if effectiveDeviceProfileManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		preservesOwnership := object.Status.OwnershipVerified && object.Status.ProfileID == profileID
		status := deviceProfileStatus(object, profileID, preservesOwnership, desired, nil, &wouldApply, metav1.ConditionTrue, "Observed", "Device profile is observed without mutation")
		return ctrl.Result{}, r.patchStatus(ctx, object, status)
	}
	if object.Spec.Profile.Kind == v1alpha1.DeviceProfileKindCustom && !object.Status.OwnershipVerified {
		return r.finishError(ctx, object, deviceProfileInvalid("Conflict", "custom profile %q is not verified as created by this DeviceProfile", profileID))
	}
	if err := syncDeviceProfile(ctx, api, ref, object.Spec.SplitTunnel.Mode, input, include, exclude, fallback, desired, wouldApply); err != nil {
		return r.finishRemoteError(ctx, object, err)
	}
	status := deviceProfileStatus(object, profileID, true, desired, nil, nil, metav1.ConditionTrue, "Ready", "Device profile fields and whole lists are synchronized")
	verifiedAt := time.Now()
	if decision.DesiredHash != "" {
		// appliedAt moves only with appliedHash; an unchanged re-verify is
		// recorded in the latch once status is persisted.
		status.AppliedHash, status.AppliedAt, _ = nextGateStamp(object.Status.AppliedHash, object.Status.AppliedAt, newGateStamp(decision.DesiredHash, verifiedAt))
	}
	clearGate(r.Invalidator, "DeviceProfile", request.NamespacedName)
	if err := r.patchStatus(ctx, object, status); err != nil {
		return ctrl.Result{}, err
	}
	r.Invalidator.MarkVerified("DeviceProfile", request.NamespacedName, decision.DesiredHash, verifiedAt)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeIndirect)}, nil
}

type aggregatedDeviceProfile struct {
	include         []flarecloudflare.SplitTunnelEntry
	exclude         []flarecloudflare.SplitTunnelEntry
	fallback        []flarecloudflare.FallbackDomain
	appliedInclude  []v1alpha1.DeviceProfileAppliedSplitTunnelEntry
	appliedExclude  []v1alpha1.DeviceProfileAppliedSplitTunnelEntry
	appliedFallback []v1alpha1.DeviceProfileAppliedFallbackDomain
}

type splitCandidate struct {
	entry      v1alpha1.DeviceProfileSplitTunnelEntry
	provenance string
	priority   int
}

type accumulatedSplit struct {
	entry      v1alpha1.DeviceProfileSplitTunnelEntry
	provenance map[string]struct{}
	priority   int
}

func (r *DeviceProfileReconciler) aggregate(ctx context.Context, profile *v1alpha1.DeviceProfile, account *v1alpha1.CloudflareAccount, namespace *corev1.Namespace) (aggregatedDeviceProfile, error) {
	candidates := make([]splitCandidate, 0, len(profile.Spec.SplitTunnel.Static)+8)
	for _, entry := range profile.Spec.SplitTunnel.Static {
		candidates = append(candidates, splitCandidate{entry: entry, provenance: "spec.splitTunnel.static", priority: 0})
	}

	sources := profile.Spec.SplitTunnel.RouteSources
	if sources.NetworkRoutes != nil {
		selector, err := metav1.LabelSelectorAsSelector(&sources.NetworkRoutes.Selector)
		if err != nil {
			return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "compile NetworkRoute selector: %v", err)
		}
		var routes v1alpha1.NetworkRouteList
		if err := r.List(ctx, &routes); err != nil {
			return aggregatedDeviceProfile{}, err
		}
		for i := range routes.Items {
			route := &routes.Items[i]
			if route.DeletionTimestamp != nil || route.Spec.AccountRef.Name != account.Name || !selector.Matches(labels.Set(route.Labels)) || !metaConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
				continue
			}
			allowed, err := privateRouteAllowsNamespace(route.Namespace, route.Spec.AllowedNamespaces, namespace)
			if err != nil {
				return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "the NetworkRoute %s/%s allowedNamespaces: %v", route.Namespace, route.Name, err)
			}
			if !allowed {
				return aggregatedDeviceProfile{}, deviceProfileInvalid("RefNotPermitted", "the NetworkRoute %s/%s does not allow namespace %q", route.Namespace, route.Name, namespace.Name)
			}
			decision := authz.Evaluate(account, namespace, authz.Request{Exposure: v1alpha1.ExposurePrivate, PrivateRoute: &authz.PrivateRouteRequest{Kind: authz.PrivateRouteNetwork, Labels: route.Labels}})
			if !decision.Allowed {
				return aggregatedDeviceProfile{}, deviceProfileInvalid(decision.Reason, "the NetworkRoute %s/%s: %s", route.Namespace, route.Name, decision.Message)
			}
			value := route.Status.Applied.Network
			if value == "" {
				continue
			}
			candidates = append(candidates, splitCandidate{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Address: &value, Description: "NetworkRoute " + route.Namespace + "/" + route.Name}, provenance: "NetworkRoute/" + route.Namespace + "/" + route.Name, priority: 1})
		}
	}
	if sources.HostnameRoutes != nil {
		selector, err := metav1.LabelSelectorAsSelector(&sources.HostnameRoutes.Selector)
		if err != nil {
			return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "compile HostnameRoute selector: %v", err)
		}
		var routes v1alpha1.HostnameRouteList
		if err := r.List(ctx, &routes); err != nil {
			return aggregatedDeviceProfile{}, err
		}
		for i := range routes.Items {
			route := &routes.Items[i]
			if route.DeletionTimestamp != nil || route.Spec.AccountRef.Name != account.Name || !selector.Matches(labels.Set(route.Labels)) || !metaConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
				continue
			}
			allowed, err := privateRouteAllowsNamespace(route.Namespace, route.Spec.AllowedNamespaces, namespace)
			if err != nil {
				return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "the HostnameRoute %s/%s allowedNamespaces: %v", route.Namespace, route.Name, err)
			}
			if !allowed {
				return aggregatedDeviceProfile{}, deviceProfileInvalid("RefNotPermitted", "the HostnameRoute %s/%s does not allow namespace %q", route.Namespace, route.Name, namespace.Name)
			}
			value := route.Status.Applied.Hostname
			if value == "" {
				continue
			}
			decision := authz.Evaluate(account, namespace, authz.Request{Hostname: value, Exposure: v1alpha1.ExposurePrivate, PrivateRoute: &authz.PrivateRouteRequest{Kind: authz.PrivateRouteHostname, Labels: route.Labels}})
			if !decision.Allowed {
				return aggregatedDeviceProfile{}, deviceProfileInvalid(decision.Reason, "the HostnameRoute %s/%s: %s", route.Namespace, route.Name, decision.Message)
			}
			candidates = append(candidates, splitCandidate{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Host: &value, Description: "HostnameRoute " + route.Namespace + "/" + route.Name}, provenance: "HostnameRoute/" + route.Namespace + "/" + route.Name, priority: 1})
		}
	}
	if sources.PrivateHostnameRange {
		if profile.Spec.SplitTunnel.Mode != v1alpha1.DeviceProfileSplitTunnelModeInclude {
			return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "privateHostnameRange requires Include mode")
		}
		for _, address := range privateHostnameRanges {
			value := address
			candidates = append(candidates, splitCandidate{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Address: &value, Description: "Cloudflare private hostname range"}, provenance: "privateHostnameRange", priority: 1})
		}
	}
	if sources.AccessApplications != nil {
		if profile.Spec.SplitTunnel.Mode != v1alpha1.DeviceProfileSplitTunnelModeInclude {
			return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "the AccessApplication sources require Include mode")
		}
		selector, err := metav1.LabelSelectorAsSelector(&sources.AccessApplications.NamespaceSelector)
		if err != nil {
			return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "compile AccessApplication namespace selector: %v", err)
		}
		var namespaces corev1.NamespaceList
		if err := r.List(ctx, &namespaces, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return aggregatedDeviceProfile{}, err
		}
		slices.SortFunc(namespaces.Items, func(a, b corev1.Namespace) int { return strings.Compare(a.Name, b.Name) })
		for i := range namespaces.Items {
			var applications v1alpha1.AccessApplicationList
			if err := r.List(ctx, &applications, client.InNamespace(namespaces.Items[i].Name)); err != nil {
				return aggregatedDeviceProfile{}, err
			}
			for j := range applications.Items {
				application := &applications.Items[j]
				if application.DeletionTimestamp != nil || application.Spec.AccountRef.Name != account.Name || !metaConditionTrue(application.Status.Conditions, "Accepted") {
					continue
				}
				for _, destination := range application.Status.Destinations {
					if destination.Type != v1alpha1.AccessApplicationDestinationPublic || destination.URI == "" {
						continue
					}
					hostname, err := publicDestinationHostname(destination.URI)
					if err != nil {
						return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "the AccessApplication %s/%s destination %q: %v", application.Namespace, application.Name, destination.URI, err)
					}
					decision := authz.Evaluate(account, &namespaces.Items[i], authz.Request{Hostname: hostname, Exposure: v1alpha1.ExposurePublic})
					if !decision.Allowed {
						return aggregatedDeviceProfile{}, deviceProfileInvalid(decision.Reason, "the AccessApplication %s/%s hostname %q: %s", application.Namespace, application.Name, hostname, decision.Message)
					}
					value := hostname
					candidates = append(candidates, splitCandidate{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Host: &value, Description: "AccessApplication " + application.Namespace + "/" + application.Name}, provenance: "AccessApplication/" + application.Namespace + "/" + application.Name, priority: 1})
				}
			}
		}
	}

	applied, remote, err := normalizeSplitCandidates(candidates)
	if err != nil {
		return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "%v", err)
	}
	if len(remote) > deviceProfileEntryLimit {
		return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "split-tunnel aggregate has %d entries; maximum is %d", len(remote), deviceProfileEntryLimit)
	}
	fallbackApplied, fallbackRemote, err := normalizeFallbackDomains(profile.Spec.FallbackDomains.Static)
	if err != nil {
		return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "%v", err)
	}

	result := aggregatedDeviceProfile{fallback: fallbackRemote, appliedFallback: fallbackApplied}
	switch profile.Spec.SplitTunnel.Mode {
	case v1alpha1.DeviceProfileSplitTunnelModeInclude:
		result.include = remote
		result.appliedInclude = applied
	case v1alpha1.DeviceProfileSplitTunnelModeExclude:
		result.exclude = remote
		result.appliedExclude = applied
	default:
		return aggregatedDeviceProfile{}, deviceProfileInvalid("Invalid", "unsupported splitTunnel.mode %q", profile.Spec.SplitTunnel.Mode)
	}
	return result, nil
}

func normalizeSplitCandidates(candidates []splitCandidate) ([]v1alpha1.DeviceProfileAppliedSplitTunnelEntry, []flarecloudflare.SplitTunnelEntry, error) {
	entries := make(map[string]*accumulatedSplit, len(candidates))
	for _, candidate := range candidates {
		entry, key, err := normalizeSplitEntry(candidate.entry)
		if err != nil {
			return nil, nil, err
		}
		current, found := entries[key]
		if !found {
			entries[key] = &accumulatedSplit{entry: entry, provenance: map[string]struct{}{candidate.provenance: {}}, priority: candidate.priority}
			continue
		}
		current.provenance[candidate.provenance] = struct{}{}
		if candidate.priority < current.priority || candidate.priority == current.priority && strings.Compare(entry.Description, current.entry.Description) < 0 {
			current.entry.Description = entry.Description
			current.priority = candidate.priority
		}
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	applied := make([]v1alpha1.DeviceProfileAppliedSplitTunnelEntry, 0, len(keys))
	remote := make([]flarecloudflare.SplitTunnelEntry, 0, len(keys))
	for _, key := range keys {
		value := entries[key]
		provenance := make([]string, 0, len(value.provenance))
		for source := range value.provenance {
			provenance = append(provenance, source)
		}
		slices.Sort(provenance)
		applied = append(applied, v1alpha1.DeviceProfileAppliedSplitTunnelEntry{Entry: statusSplitEntry(value.entry), Provenance: provenance})
		remote = append(remote, cloudflareSplitEntry(value.entry))
	}
	return applied, remote, nil
}

func normalizeSplitEntry(entry v1alpha1.DeviceProfileSplitTunnelEntry) (v1alpha1.DeviceProfileSplitTunnelEntry, string, error) {
	if (entry.Address == nil) == (entry.Host == nil) {
		return entry, "", errors.New("split-tunnel entry requires exactly one of address or host")
	}
	entry.Description = strings.TrimSpace(entry.Description)
	if entry.Address != nil {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(*entry.Address))
		if err != nil {
			return entry, "", fmt.Errorf("invalid split-tunnel address %q: %w", *entry.Address, err)
		}
		value := prefix.Masked().String()
		entry.Address = &value
		entry.Host = nil
		return entry, "address:" + value, nil
	}
	value := normalizeDomain(*entry.Host)
	if value == "" {
		return entry, "", errors.New("split-tunnel host is empty")
	}
	entry.Host = &value
	entry.Address = nil
	return entry, "host:" + value, nil
}

func cloudflareSplitEntry(entry v1alpha1.DeviceProfileSplitTunnelEntry) flarecloudflare.SplitTunnelEntry {
	remote := flarecloudflare.SplitTunnelEntry{Description: entry.Description}
	if entry.Address != nil {
		remote.Address = *entry.Address
	}
	if entry.Host != nil {
		remote.Host = *entry.Host
	}
	return remote
}

func statusSplitEntry(entry v1alpha1.DeviceProfileSplitTunnelEntry) v1alpha1.DeviceProfileStatusSplitTunnelEntry {
	return v1alpha1.DeviceProfileStatusSplitTunnelEntry(entry)
}

func normalizeFallbackDomains(entries []v1alpha1.DeviceProfileFallbackDomain) ([]v1alpha1.DeviceProfileAppliedFallbackDomain, []flarecloudflare.FallbackDomain, error) {
	bySuffix := make(map[string]v1alpha1.DeviceProfileFallbackDomain, len(entries))
	for _, entry := range entries {
		entry.Suffix = normalizeDomain(entry.Suffix)
		entry.Description = strings.TrimSpace(entry.Description)
		if entry.Suffix == "" {
			return nil, nil, errors.New("fallback domain suffix is empty")
		}
		servers := make([]string, 0, len(entry.DNSServer))
		seenServers := map[string]struct{}{}
		for _, server := range entry.DNSServer {
			address, err := netip.ParseAddr(strings.TrimSpace(server))
			if err != nil {
				return nil, nil, fmt.Errorf("fallback domain %q has invalid DNS server %q", entry.Suffix, server)
			}
			value := address.Unmap().String()
			if _, found := seenServers[value]; !found {
				seenServers[value] = struct{}{}
				servers = append(servers, value)
			}
		}
		slices.Sort(servers)
		entry.DNSServer = servers
		if current, found := bySuffix[entry.Suffix]; found && !fallbackDomainEqual(current, entry) {
			return nil, nil, fmt.Errorf("fallback domain %q has conflicting definitions", entry.Suffix)
		}
		bySuffix[entry.Suffix] = entry
	}
	keys := make([]string, 0, len(bySuffix))
	for key := range bySuffix {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	applied := make([]v1alpha1.DeviceProfileAppliedFallbackDomain, 0, len(keys))
	remote := make([]flarecloudflare.FallbackDomain, 0, len(keys))
	for _, key := range keys {
		entry := bySuffix[key]
		applied = append(applied, v1alpha1.DeviceProfileAppliedFallbackDomain{Entry: statusFallbackDomain(entry), Provenance: []string{"spec.fallbackDomains.static"}})
		remote = append(remote, flarecloudflare.FallbackDomain{Suffix: entry.Suffix, Description: entry.Description, DNSServer: slices.Clone(entry.DNSServer)})
	}
	return applied, remote, nil
}

func fallbackDomainEqual(a, b v1alpha1.DeviceProfileFallbackDomain) bool {
	return a.Suffix == b.Suffix && a.Description == b.Description && slices.Equal(a.DNSServer, b.DNSServer)
}

func statusFallbackDomain(entry v1alpha1.DeviceProfileFallbackDomain) v1alpha1.DeviceProfileStatusFallbackDomain {
	return v1alpha1.DeviceProfileStatusFallbackDomain{Suffix: entry.Suffix, Description: entry.Description, DNSServer: slices.Clone(entry.DNSServer)}
}

func publicDestinationHostname(uri string) (string, error) {
	value := strings.TrimSpace(uri)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid public destination URI")
		}
		return normalizeDomain(parsed.Hostname()), nil
	}
	host := value
	if index := strings.IndexByte(host, '/'); index >= 0 {
		host = host[:index]
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = normalizeDomain(host)
	if host == "" {
		return "", errors.New("public destination hostname is empty")
	}
	return host, nil
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func (r *DeviceProfileReconciler) profileInput(ctx context.Context, object *v1alpha1.DeviceProfile) (flarecloudflare.DeviceProfileInput, error) {
	input := flarecloudflare.DeviceProfileInput{Match: object.Spec.Profile.Match, Precedence: object.Spec.Profile.Precedence}
	if fields := object.Spec.Profile.Fields; fields != nil {
		input.Name = fields.Name
		input.Description = fields.Description
		input.Enabled = fields.Enabled
		input.SwitchLocked = fields.SwitchLocked
		input.CaptivePortal = fields.CaptivePortal
		input.AllowModeSwitch = fields.AllowModeSwitch
		input.AllowUpdates = fields.AllowUpdates
		input.AllowedToLeave = fields.AllowedToLeave
		input.AutoConnect = fields.AutoConnect
		input.DisableAutoFallback = fields.DisableAutoFallback
		input.ExcludeOfficeIPs = fields.ExcludeOfficeIPs
		input.SupportURL = fields.SupportURL
		input.LANAllowMinutes = fields.LANAllowMinutes
		input.LANAllowSubnetSize = fields.LANAllowSubnetSize
		input.RegisterInterfaceIPWithDNS = fields.RegisterInterfaceIPWithDNS
		input.SCCMVPNBoundarySupport = fields.SCCMVPNBoundarySupport
		if fields.TunnelProtocol != nil {
			value := string(*fields.TunnelProtocol)
			input.TunnelProtocol = &value
		}
		if fields.ServiceModeV2 != nil {
			input.ServiceModeV2 = &flarecloudflare.DeviceProfileServiceModeV2{Mode: string(fields.ServiceModeV2.Mode), Port: fields.ServiceModeV2.Port}
		}
		if fields.VirtualNetworks != nil {
			resolved, err := r.resolveProfileVirtualNetworks(ctx, object, fields.VirtualNetworks)
			if err != nil {
				return flarecloudflare.DeviceProfileInput{}, err
			}
			input.VirtualNetworks = resolved
		}
	}
	suffixes := make([]flarecloudflare.DNSSearchSuffix, 0, len(object.Spec.DNSSearchSuffixes))
	seen := map[string]struct{}{}
	for _, suffix := range object.Spec.DNSSearchSuffixes {
		suffix.Suffix = normalizeDomain(suffix.Suffix)
		if suffix.Suffix == "" {
			return flarecloudflare.DeviceProfileInput{}, deviceProfileInvalid("Invalid", "the DNS search suffix is empty")
		}
		if _, found := seen[suffix.Suffix]; found {
			return flarecloudflare.DeviceProfileInput{}, deviceProfileInvalid("Invalid", "the DNS search suffix %q is duplicated", suffix.Suffix)
		}
		seen[suffix.Suffix] = struct{}{}
		suffixes = append(suffixes, flarecloudflare.DNSSearchSuffix{Suffix: suffix.Suffix, Description: strings.TrimSpace(suffix.Description)})
	}
	input.DNSSearchSuffixes = &suffixes
	return input, nil
}

func (r *DeviceProfileReconciler) resolveProfileVirtualNetworks(ctx context.Context, object *v1alpha1.DeviceProfile, refs *v1alpha1.DeviceProfileVirtualNetworks) (*flarecloudflare.DeviceProfileVirtualNetworks, error) {
	resolve := func(name string) (string, error) {
		var network v1alpha1.VirtualNetwork
		if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: name}, &network); err != nil {
			return "", deviceProfileInvalid("TargetNotFound", "resolve VirtualNetwork %s/%s: %v", object.Namespace, name, err)
		}
		if network.Spec.AccountRef.Name != object.Spec.AccountRef.Name {
			return "", deviceProfileInvalid("RefNotPermitted", "the VirtualNetwork %s/%s uses CloudflareAccount %q", object.Namespace, name, network.Spec.AccountRef.Name)
		}
		if !metaConditionTrue(network.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) || network.Status.VirtualNetworkID == "" {
			return "", deviceProfileInvalid("Pending", "the VirtualNetwork %s/%s is not accepted with a remote ID", object.Namespace, name)
		}
		return network.Status.VirtualNetworkID, nil
	}
	defaultAllowed := slices.ContainsFunc(refs.AllowedRefs, func(ref corev1.LocalObjectReference) bool {
		return ref.Name == refs.DefaultRef.Name
	})
	if !defaultAllowed {
		return nil, deviceProfileInvalid("Invalid", "virtualNetworks.defaultRef %q must also appear in allowedRefs", refs.DefaultRef.Name)
	}
	defaultID, err := resolve(refs.DefaultRef.Name)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(refs.AllowedRefs))
	seen := map[string]struct{}{}
	for _, ref := range refs.AllowedRefs {
		id, err := resolve(ref.Name)
		if err != nil {
			return nil, err
		}
		if _, found := seen[id]; !found {
			seen[id] = struct{}{}
			allowed = append(allowed, id)
		}
	}
	slices.Sort(allowed)
	return &flarecloudflare.DeviceProfileVirtualNetworks{Default: defaultID, Allowed: allowed}, nil
}

func (r *DeviceProfileReconciler) resolveRemoteProfile(ctx context.Context, api flarecloudflare.DeviceProfileAPI, object *v1alpha1.DeviceProfile, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, bool, error) {
	switch object.Spec.Profile.Kind {
	case v1alpha1.DeviceProfileKindDefault:
		remote, err := api.GetDefaultDeviceProfile(ctx)
		if err == nil && !remote.Default {
			return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "the Cloudflare service returned a custom profile from the default profile endpoint")
		}
		return remote, false, err
	case v1alpha1.DeviceProfileKindCustom:
		managementPolicy := effectiveDeviceProfileManagementPolicy(object.Spec.ManagementPolicy)
		externalID := ""
		if object.Spec.ExternalRef != nil {
			externalID = object.Spec.ExternalRef.ProfileID
		}
		if managementPolicy == v1alpha1.ManagementPolicyManaged && object.Status.ProfileID != "" && externalID != "" && object.Status.ProfileID != externalID {
			return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "owned custom profile %q does not match externalRef.profileId %q", object.Status.ProfileID, externalID)
		}
		if managementPolicy == v1alpha1.ManagementPolicyManaged && object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			if externalID == "" {
				return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Invalid", "adoption mode AdoptById requires externalRef.profileId")
			}
			remote, err := api.GetCustomDeviceProfile(ctx, externalID)
			acquired := err == nil && (!object.Status.OwnershipVerified || object.Status.ProfileID != externalID)
			return validateResolvedCustomProfile(remote, acquired, object, err)
		}
		if managementPolicy == v1alpha1.ManagementPolicyObserveOnly && externalID != "" {
			remote, err := api.GetCustomDeviceProfile(ctx, externalID)
			return validateResolvedCustomProfile(remote, false, object, err)
		}
		if object.Status.ProfileID != "" {
			if managementPolicy == v1alpha1.ManagementPolicyManaged && !object.Status.OwnershipVerified {
				return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "custom profile %q is not verified as created or explicitly adopted by this DeviceProfile", object.Status.ProfileID)
			}
			remote, err := api.GetCustomDeviceProfile(ctx, object.Status.ProfileID)
			return validateResolvedCustomProfile(remote, false, object, err)
		}
		if managementPolicy == v1alpha1.ManagementPolicyManaged {
			remote, err := api.CreateCustomDeviceProfile(ctx, input)
			return validateResolvedCustomProfile(remote, err == nil, object, err)
		}
		profiles, err := api.ListCustomDeviceProfiles(ctx)
		if err != nil {
			return flarecloudflare.DeviceProfile{}, false, err
		}
		matches := make([]flarecloudflare.DeviceProfile, 0, 1)
		for _, candidate := range profiles {
			if customProfileMatches(candidate, input) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 0 {
			return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("TargetNotFound", "no custom device profile matches name, match, and precedence")
		}
		if len(matches) > 1 {
			return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "%d custom device profiles match name, match, and precedence", len(matches))
		}
		return validateResolvedCustomProfile(matches[0], false, object, nil)
	default:
		return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Invalid", "unsupported profile.kind %q", object.Spec.Profile.Kind)
	}
}

func customProfileMatches(candidate flarecloudflare.DeviceProfile, input flarecloudflare.DeviceProfileInput) bool {
	return input.Name != nil && candidate.Name == *input.Name &&
		input.Match != nil && candidate.Match == *input.Match &&
		input.Precedence != nil && candidate.Precedence == *input.Precedence
}

func validateResolvedCustomProfile(remote flarecloudflare.DeviceProfile, acquired bool, object *v1alpha1.DeviceProfile, err error) (flarecloudflare.DeviceProfile, bool, error) {
	if err != nil {
		return flarecloudflare.DeviceProfile{}, false, err
	}
	if remote.Default {
		return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "custom profile reference %q resolves to the account default profile", remote.PolicyID)
	}
	if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
		return flarecloudflare.DeviceProfile{}, false, deviceProfileInvalid("Conflict", "remote custom profile name %q does not match expected %q", remote.Name, expected)
	}
	return remote, acquired, nil
}

func remoteProfileRef(kind v1alpha1.DeviceProfileKind, id string) flarecloudflare.DeviceProfileRef {
	remoteKind := flarecloudflare.DeviceProfileKindCustom
	if kind == v1alpha1.DeviceProfileKindDefault {
		remoteKind = flarecloudflare.DeviceProfileKindDefault
	}
	return flarecloudflare.DeviceProfileRef{Kind: remoteKind, ID: id}
}

func syncDeviceProfile(ctx context.Context, api flarecloudflare.DeviceProfileAPI, ref flarecloudflare.DeviceProfileRef, mode v1alpha1.DeviceProfileSplitTunnelMode, input flarecloudflare.DeviceProfileInput, remoteInclude, remoteExclude []flarecloudflare.SplitTunnelEntry, remoteFallback []flarecloudflare.FallbackDomain, desired aggregatedDeviceProfile, diff v1alpha1.DeviceProfileWouldApplyStatus) error {
	switch mode {
	case v1alpha1.DeviceProfileSplitTunnelModeInclude:
		if len(remoteExclude) > 0 {
			if _, err := api.ReplaceDeviceProfileExclude(ctx, ref, []flarecloudflare.SplitTunnelEntry{}); err != nil {
				return fmt.Errorf("clear inactive device profile exclude list: %w", err)
			}
		}
		if !splitTunnelEntriesEqual(remoteInclude, desired.include) {
			if _, err := api.ReplaceDeviceProfileInclude(ctx, ref, desired.include); err != nil {
				return fmt.Errorf("replace device profile include list: %w", err)
			}
		}
	case v1alpha1.DeviceProfileSplitTunnelModeExclude:
		if len(remoteInclude) > 0 {
			if _, err := api.ReplaceDeviceProfileInclude(ctx, ref, []flarecloudflare.SplitTunnelEntry{}); err != nil {
				return fmt.Errorf("clear inactive device profile include list: %w", err)
			}
		}
		if !splitTunnelEntriesEqual(remoteExclude, desired.exclude) {
			if _, err := api.ReplaceDeviceProfileExclude(ctx, ref, desired.exclude); err != nil {
				return fmt.Errorf("replace device profile exclude list: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported split tunnel mode %q", mode)
	}
	if !fallbackDomainsEqual(remoteFallback, desired.fallback) {
		if _, err := api.ReplaceDeviceProfileFallbackDomains(ctx, ref, desired.fallback); err != nil {
			return fmt.Errorf("replace device profile fallback domains: %w", err)
		}
	}
	if len(diff.ProfileFields) > 0 || len(diff.DNSSearchSuffixes.Add) > 0 || len(diff.DNSSearchSuffixes.Remove) > 0 {
		if ref.Kind == flarecloudflare.DeviceProfileKindDefault {
			if _, err := api.UpdateDefaultDeviceProfile(ctx, input); err != nil {
				return fmt.Errorf("update default device profile fields: %w", err)
			}
		} else if _, err := api.UpdateCustomDeviceProfile(ctx, ref.ID, input); err != nil {
			return fmt.Errorf("update custom device profile fields: %w", err)
		}
	}
	return nil
}

func profileDiff(remote flarecloudflare.DeviceProfile, desiredInput flarecloudflare.DeviceProfileInput, remoteInclude, remoteExclude []flarecloudflare.SplitTunnelEntry, remoteFallback []flarecloudflare.FallbackDomain, desired aggregatedDeviceProfile) v1alpha1.DeviceProfileWouldApplyStatus {
	return v1alpha1.DeviceProfileWouldApplyStatus{
		ProfileFields:     differingProfileFields(remote, desiredInput),
		Include:           splitTunnelDiff(remoteInclude, desired.include),
		Exclude:           splitTunnelDiff(remoteExclude, desired.exclude),
		FallbackDomains:   fallbackDomainDiff(remoteFallback, desired.fallback),
		DNSSearchSuffixes: dnsSearchSuffixDiff(remote.DNSSearchSuffixes, dereferenceDNSSearchSuffixes(desiredInput.DNSSearchSuffixes)),
	}
}

func differingProfileFields(remote flarecloudflare.DeviceProfile, desired flarecloudflare.DeviceProfileInput) []string {
	fields := make([]string, 0, 20)
	appendIf := func(name string, changed bool) {
		if changed {
			fields = append(fields, name)
		}
	}
	appendIf("name", desired.Name != nil && remote.Name != *desired.Name)
	appendIf("description", desired.Description != nil && remote.Description != *desired.Description)
	appendIf("enabled", desired.Enabled != nil && remote.Enabled != *desired.Enabled)
	appendIf("match", desired.Match != nil && remote.Match != *desired.Match)
	appendIf("precedence", desired.Precedence != nil && remote.Precedence != *desired.Precedence)
	appendIf("switchLocked", desired.SwitchLocked != nil && remote.SwitchLocked != *desired.SwitchLocked)
	appendIf("captivePortal", desired.CaptivePortal != nil && remote.CaptivePortal != *desired.CaptivePortal)
	appendIf("allowModeSwitch", desired.AllowModeSwitch != nil && remote.AllowModeSwitch != *desired.AllowModeSwitch)
	appendIf("allowUpdates", desired.AllowUpdates != nil && remote.AllowUpdates != *desired.AllowUpdates)
	appendIf("allowedToLeave", desired.AllowedToLeave != nil && remote.AllowedToLeave != *desired.AllowedToLeave)
	appendIf("autoConnect", desired.AutoConnect != nil && remote.AutoConnect != *desired.AutoConnect)
	appendIf("disableAutoFallback", desired.DisableAutoFallback != nil && remote.DisableAutoFallback != *desired.DisableAutoFallback)
	appendIf("excludeOfficeIps", desired.ExcludeOfficeIPs != nil && remote.ExcludeOfficeIPs != *desired.ExcludeOfficeIPs)
	appendIf("supportUrl", desired.SupportURL != nil && remote.SupportURL != *desired.SupportURL)
	appendIf("lanAllowMinutes", desired.LANAllowMinutes != nil && remote.LANAllowMinutes != *desired.LANAllowMinutes)
	appendIf("lanAllowSubnetSize", desired.LANAllowSubnetSize != nil && remote.LANAllowSubnetSize != *desired.LANAllowSubnetSize)
	appendIf("registerInterfaceIpWithDns", desired.RegisterInterfaceIPWithDNS != nil && remote.RegisterInterfaceIPWithDNS != *desired.RegisterInterfaceIPWithDNS)
	appendIf("sccmVpnBoundarySupport", desired.SCCMVPNBoundarySupport != nil && remote.SCCMVPNBoundarySupport != *desired.SCCMVPNBoundarySupport)
	appendIf("tunnelProtocol", desired.TunnelProtocol != nil && remote.TunnelProtocol != *desired.TunnelProtocol)
	appendIf("serviceModeV2", desired.ServiceModeV2 != nil && !deviceProfileServiceModeEqual(remote.ServiceModeV2, *desired.ServiceModeV2))
	appendIf("virtualNetworks", desired.VirtualNetworks != nil && !deviceProfileVirtualNetworksEqual(remote.VirtualNetworks, *desired.VirtualNetworks))
	slices.Sort(fields)
	return fields
}

func deviceProfileServiceModeEqual(remote flarecloudflare.DeviceProfileServiceModeV2, desired flarecloudflare.DeviceProfileServiceModeV2) bool {
	return remote.Mode == desired.Mode && pointerInt32Equal(remote.Port, desired.Port)
}

func deviceProfileVirtualNetworksEqual(remote flarecloudflare.DeviceProfileVirtualNetworks, desired flarecloudflare.DeviceProfileVirtualNetworks) bool {
	remoteAllowed := slices.Clone(remote.Allowed)
	desiredAllowed := slices.Clone(desired.Allowed)
	slices.Sort(remoteAllowed)
	slices.Sort(desiredAllowed)
	return remote.Default == desired.Default && slices.Equal(remoteAllowed, desiredAllowed)
}

func pointerInt32Equal(a, b *int32) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func splitTunnelDiff(remote, desired []flarecloudflare.SplitTunnelEntry) v1alpha1.DeviceProfileSplitTunnelDiff {
	remoteMap := make(map[string]v1alpha1.DeviceProfileStatusSplitTunnelEntry, len(remote))
	desiredMap := make(map[string]v1alpha1.DeviceProfileStatusSplitTunnelEntry, len(desired))
	for _, entry := range canonicalRemoteSplitEntries(remote) {
		remoteMap[splitEntryPayloadKey(entry)] = entry
	}
	for _, entry := range canonicalRemoteSplitEntries(desired) {
		desiredMap[splitEntryPayloadKey(entry)] = entry
	}
	var diff v1alpha1.DeviceProfileSplitTunnelDiff
	for key, entry := range desiredMap {
		if _, found := remoteMap[key]; !found {
			diff.Add = append(diff.Add, entry)
		}
	}
	for key, entry := range remoteMap {
		if _, found := desiredMap[key]; !found {
			diff.Remove = append(diff.Remove, entry)
		}
	}
	slices.SortFunc(diff.Add, func(a, b v1alpha1.DeviceProfileStatusSplitTunnelEntry) int {
		return strings.Compare(splitEntryPayloadKey(a), splitEntryPayloadKey(b))
	})
	slices.SortFunc(diff.Remove, func(a, b v1alpha1.DeviceProfileStatusSplitTunnelEntry) int {
		return strings.Compare(splitEntryPayloadKey(a), splitEntryPayloadKey(b))
	})
	return diff
}

func canonicalRemoteSplitEntries(entries []flarecloudflare.SplitTunnelEntry) []v1alpha1.DeviceProfileStatusSplitTunnelEntry {
	result := make([]v1alpha1.DeviceProfileStatusSplitTunnelEntry, 0, len(entries))
	for _, remote := range entries {
		entry := v1alpha1.DeviceProfileStatusSplitTunnelEntry{Description: strings.TrimSpace(remote.Description)}
		if remote.Address != "" {
			value := strings.TrimSpace(remote.Address)
			if prefix, err := netip.ParsePrefix(value); err == nil {
				value = prefix.Masked().String()
			}
			entry.Address = &value
		} else {
			value := normalizeDomain(remote.Host)
			entry.Host = &value
		}
		result = append(result, entry)
	}
	return result
}

func splitEntryPayloadKey(entry v1alpha1.DeviceProfileStatusSplitTunnelEntry) string {
	if entry.Address != nil {
		return "address:" + *entry.Address + "\x00" + entry.Description
	}
	if entry.Host != nil {
		return "host:" + *entry.Host + "\x00" + entry.Description
	}
	return "invalid:\x00" + entry.Description
}

func splitTunnelEntriesEqual(a, b []flarecloudflare.SplitTunnelEntry) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := canonicalRemoteSplitEntries(a), canonicalRemoteSplitEntries(b)
	slices.SortFunc(left, func(a, b v1alpha1.DeviceProfileStatusSplitTunnelEntry) int {
		return strings.Compare(splitEntryPayloadKey(a), splitEntryPayloadKey(b))
	})
	slices.SortFunc(right, func(a, b v1alpha1.DeviceProfileStatusSplitTunnelEntry) int {
		return strings.Compare(splitEntryPayloadKey(a), splitEntryPayloadKey(b))
	})
	for index := range left {
		if splitEntryPayloadKey(left[index]) != splitEntryPayloadKey(right[index]) {
			return false
		}
	}
	return true
}

func fallbackDomainDiff(remote, desired []flarecloudflare.FallbackDomain) v1alpha1.DeviceProfileFallbackDomainDiff {
	remoteMap := canonicalFallbackMap(remote)
	desiredMap := canonicalFallbackMap(desired)
	var diff v1alpha1.DeviceProfileFallbackDomainDiff
	for key, entry := range desiredMap {
		if _, found := remoteMap[key]; !found {
			diff.Add = append(diff.Add, entry)
		}
	}
	for key, entry := range remoteMap {
		if _, found := desiredMap[key]; !found {
			diff.Remove = append(diff.Remove, entry)
		}
	}
	slices.SortFunc(diff.Add, func(a, b v1alpha1.DeviceProfileStatusFallbackDomain) int {
		return strings.Compare(fallbackPayloadKey(a), fallbackPayloadKey(b))
	})
	slices.SortFunc(diff.Remove, func(a, b v1alpha1.DeviceProfileStatusFallbackDomain) int {
		return strings.Compare(fallbackPayloadKey(a), fallbackPayloadKey(b))
	})
	return diff
}

func canonicalFallbackMap(entries []flarecloudflare.FallbackDomain) map[string]v1alpha1.DeviceProfileStatusFallbackDomain {
	result := make(map[string]v1alpha1.DeviceProfileStatusFallbackDomain, len(entries))
	for _, entry := range canonicalFallbackEntries(entries) {
		result[fallbackPayloadKey(entry)] = entry
	}
	return result
}

func canonicalFallbackEntries(entries []flarecloudflare.FallbackDomain) []v1alpha1.DeviceProfileStatusFallbackDomain {
	result := make([]v1alpha1.DeviceProfileStatusFallbackDomain, 0, len(entries))
	for _, remote := range entries {
		servers := slices.Clone(remote.DNSServer)
		for i := range servers {
			if address, err := netip.ParseAddr(strings.TrimSpace(servers[i])); err == nil {
				servers[i] = address.Unmap().String()
			}
		}
		slices.Sort(servers)
		result = append(result, v1alpha1.DeviceProfileStatusFallbackDomain{Suffix: normalizeDomain(remote.Suffix), Description: strings.TrimSpace(remote.Description), DNSServer: servers})
	}
	return result
}

func fallbackPayloadKey(entry v1alpha1.DeviceProfileStatusFallbackDomain) string {
	return entry.Suffix + "\x00" + entry.Description + "\x00" + strings.Join(entry.DNSServer, "\x00")
}

func fallbackDomainsEqual(a, b []flarecloudflare.FallbackDomain) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := canonicalFallbackEntries(a), canonicalFallbackEntries(b)
	slices.SortFunc(left, func(a, b v1alpha1.DeviceProfileStatusFallbackDomain) int {
		return strings.Compare(fallbackPayloadKey(a), fallbackPayloadKey(b))
	})
	slices.SortFunc(right, func(a, b v1alpha1.DeviceProfileStatusFallbackDomain) int {
		return strings.Compare(fallbackPayloadKey(a), fallbackPayloadKey(b))
	})
	for index := range left {
		if fallbackPayloadKey(left[index]) != fallbackPayloadKey(right[index]) {
			return false
		}
	}
	return true
}

func dnsSearchSuffixDiff(remote, desired []flarecloudflare.DNSSearchSuffix) v1alpha1.DeviceProfileDNSSearchSuffixDiff {
	toMap := func(entries []flarecloudflare.DNSSearchSuffix) map[string]v1alpha1.DeviceProfileDNSSearchSuffix {
		result := make(map[string]v1alpha1.DeviceProfileDNSSearchSuffix, len(entries))
		for _, entry := range entries {
			value := v1alpha1.DeviceProfileDNSSearchSuffix{Suffix: normalizeDomain(entry.Suffix), Description: strings.TrimSpace(entry.Description)}
			result[value.Suffix+"\x00"+value.Description] = value
		}
		return result
	}
	remoteMap, desiredMap := toMap(remote), toMap(desired)
	var diff v1alpha1.DeviceProfileDNSSearchSuffixDiff
	for key, entry := range desiredMap {
		if _, found := remoteMap[key]; !found {
			diff.Add = append(diff.Add, entry)
		}
	}
	for key, entry := range remoteMap {
		if _, found := desiredMap[key]; !found {
			diff.Remove = append(diff.Remove, entry)
		}
	}
	slices.SortFunc(diff.Add, func(a, b v1alpha1.DeviceProfileDNSSearchSuffix) int {
		return strings.Compare(a.Suffix+"\x00"+a.Description, b.Suffix+"\x00"+b.Description)
	})
	slices.SortFunc(diff.Remove, func(a, b v1alpha1.DeviceProfileDNSSearchSuffix) int {
		return strings.Compare(a.Suffix+"\x00"+a.Description, b.Suffix+"\x00"+b.Description)
	})
	return diff
}

func dereferenceDNSSearchSuffixes(value *[]flarecloudflare.DNSSearchSuffix) []flarecloudflare.DNSSearchSuffix {
	if value == nil {
		return nil
	}
	return *value
}

func (r *DeviceProfileReconciler) writerConflicts(ctx context.Context, current *v1alpha1.DeviceProfile, accountID, profileID string) ([]string, error) {
	if effectiveDeviceProfileManagementPolicy(current.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
		return nil, nil
	}
	var accounts v1alpha1.CloudflareAccountList
	if err := r.List(ctx, &accounts, client.MatchingFields{deviceProfileCloudflareAccountIDIndex: accountID}); err != nil {
		return nil, err
	}
	conflicts := make([]string, 0)
	for accountIndex := range accounts.Items {
		account := &accounts.Items[accountIndex]
		var profiles v1alpha1.DeviceProfileList
		if err := r.List(ctx, &profiles, client.MatchingFields{deviceProfileAccountIndex: account.Name}); err != nil {
			return nil, err
		}
		for profileIndex := range profiles.Items {
			candidate := &profiles.Items[profileIndex]
			if candidate.UID == current.UID || candidate.Spec.Profile.Kind != current.Spec.Profile.Kind {
				continue
			}
			eligible, err := r.eligibleManagedWriter(ctx, candidate, account)
			if err != nil {
				return nil, err
			}
			if !eligible {
				continue
			}
			candidateID := declaredDeviceProfileID(candidate)
			if current.Spec.Profile.Kind == v1alpha1.DeviceProfileKindDefault || profileID != "" && candidateID == profileID {
				conflicts = append(conflicts, candidate.Namespace+"/"+candidate.Name)
			}
		}
	}
	slices.Sort(conflicts)
	return slices.Compact(conflicts), nil
}

func (r *DeviceProfileReconciler) eligibleManagedWriter(ctx context.Context, candidate *v1alpha1.DeviceProfile, account *v1alpha1.CloudflareAccount) (bool, error) {
	if !candidate.DeletionTimestamp.IsZero() || effectiveDeviceProfileManagementPolicy(candidate.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
		return false, nil
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) || !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return false, nil
	}
	namespace := new(corev1.Namespace)
	if err := r.Get(ctx, types.NamespacedName{Name: candidate.Namespace}, namespace); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if !authz.Evaluate(account, namespace, authz.Request{PlatformObject: true}).Allowed {
		return false, nil
	}
	accepted := statusutil.FindCondition(candidate.Status.Conditions, v1alpha1.DeviceProfileConditionAccepted)
	if accepted != nil && accepted.ObservedGeneration == candidate.Generation && accepted.Status == metav1.ConditionFalse {
		writerConflict := accepted.Reason == "Conflict" && len(candidate.Status.Conflicts) > 0
		if accepted.Reason != "Pending" && !writerConflict {
			return false, nil
		}
	}
	return true, nil
}

func declaredDeviceProfileID(profile *v1alpha1.DeviceProfile) string {
	if profile.Spec.ExternalRef != nil {
		return profile.Spec.ExternalRef.ProfileID
	}
	return profile.Status.ProfileID
}

func (r *DeviceProfileReconciler) clientForProfile(ctx context.Context, object *v1alpha1.DeviceProfile) (flarecloudflare.DeviceProfileAPI, *v1alpha1.CloudflareAccount, *corev1.Namespace, error) {
	if object.Spec.AccountRef.Name == "" {
		return nil, nil, nil, errors.New("accountRef.name is required")
	}
	if r.NewCloudflareClient == nil {
		return nil, nil, nil, errors.New("cloudflare device profile client factory is required")
	}
	account := new(v1alpha1.CloudflareAccount)
	if err := r.Get(ctx, types.NamespacedName{Name: object.Spec.AccountRef.Name}, account); err != nil {
		return nil, nil, nil, fmt.Errorf("get CloudflareAccount %q: %w", object.Spec.AccountRef.Name, err)
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) || !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return nil, nil, nil, fmt.Errorf("the CloudflareAccount %q is not ready", account.Name)
	}
	namespace := new(corev1.Namespace)
	if err := r.Get(ctx, types.NamespacedName{Name: object.Namespace}, namespace); err != nil {
		return nil, nil, nil, fmt.Errorf("get DeviceProfile namespace %q: %w", object.Namespace, err)
	}
	decision := authz.Evaluate(account, namespace, authz.Request{PlatformObject: true})
	if !decision.Allowed {
		return nil, nil, nil, fmt.Errorf("%s: %s", decision.Reason, decision.Message)
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, nil, nil, fmt.Errorf("get Cloudflare API token Secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	token := secret.Data[key]
	if len(token) == 0 {
		return nil, nil, nil, fmt.Errorf("cloudflare API token Secret %s/%s has no non-empty %q key", ref.Namespace, ref.Name, key)
	}
	api, err := r.NewCloudflareClient(string(token), account.Spec.AccountID)
	if err != nil {
		return nil, nil, nil, err
	}
	return api, account, namespace, nil
}

func (r *DeviceProfileReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.DeviceProfile) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DeviceProfileFinalizer) {
		return nil
	}
	shouldDelete := object.Spec.Profile.Kind == v1alpha1.DeviceProfileKindCustom && effectiveDeviceProfileManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged && effectiveDeviceProfileDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.ProfileID != "" && object.Status.OwnershipVerified
	if shouldDelete {
		api, account, _, err := r.clientForProfile(ctx, object)
		if err != nil {
			return err
		}
		conflicts, err := r.writerConflicts(ctx, object, account.Spec.AccountID, object.Status.ProfileID)
		if err != nil {
			return err
		}
		if len(conflicts) == 0 {
			if err := api.DeleteCustomDeviceProfile(ctx, object.Status.ProfileID); err != nil && !flarecloudflare.IsNotFound(err) {
				return fmt.Errorf("delete custom device profile %q: %w", object.Status.ProfileID, err)
			}
		}
	}
	before := object.DeepCopy()
	controllerutil.RemoveFinalizer(object, v1alpha1.DeviceProfileFinalizer)
	return r.Patch(ctx, object, client.MergeFrom(before))
}

type deviceProfileProblem struct {
	reason  string
	message string
}

func (e *deviceProfileProblem) Error() string { return e.message }

func deviceProfileInvalid(reason, format string, args ...any) error {
	return &deviceProfileProblem{reason: reason, message: fmt.Sprintf(format, args...)}
}

func (r *DeviceProfileReconciler) finishError(ctx context.Context, object *v1alpha1.DeviceProfile, err error) (ctrl.Result, error) {
	var problem *deviceProfileProblem
	if errors.As(err, &problem) {
		status := deviceProfileStatus(object, object.Status.ProfileID, object.Status.OwnershipVerified, lastAppliedDeviceProfile(object), nil, nil, metav1.ConditionFalse, problem.reason, problem.message)
		return ctrl.Result{}, r.patchStatus(ctx, object, status)
	}
	return r.finishRemoteError(ctx, object, err)
}

func (r *DeviceProfileReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.DeviceProfile, err error) (ctrl.Result, error) {
	status := deviceProfileStatus(object, object.Status.ProfileID, object.Status.OwnershipVerified, lastAppliedDeviceProfile(object), nil, nil, metav1.ConditionFalse, "Pending", err.Error())
	_ = r.patchStatus(ctx, object, status)
	return ctrl.Result{}, err
}

func (r *DeviceProfileReconciler) finishConflict(ctx context.Context, object *v1alpha1.DeviceProfile, profileID string, conflicts []string) (ctrl.Result, error) {
	message := "another Managed DeviceProfile targets the same remote profile: " + strings.Join(conflicts, ", ")
	status := deviceProfileStatus(object, profileID, object.Status.OwnershipVerified, lastAppliedDeviceProfile(object), conflicts, nil, metav1.ConditionFalse, "Conflict", message)
	return ctrl.Result{}, r.patchStatus(ctx, object, status)
}

// lastAppliedDeviceProfile re-publishes the last confirmed applied lists so a
// failure before remote replacement does not read as a successful withdrawal.
func lastAppliedDeviceProfile(object *v1alpha1.DeviceProfile) aggregatedDeviceProfile {
	return aggregatedDeviceProfile{
		appliedInclude:  object.Status.AppliedInclude,
		appliedExclude:  object.Status.AppliedExclude,
		appliedFallback: object.Status.AppliedFallback,
	}
}

func deviceProfileStatus(object *v1alpha1.DeviceProfile, profileID string, ownership bool, desired aggregatedDeviceProfile, conflicts []string, wouldApply *v1alpha1.DeviceProfileWouldApplyStatus, conditionStatus metav1.ConditionStatus, reason, message string) v1alpha1.DeviceProfileStatus {
	return v1alpha1.DeviceProfileStatus{
		ProfileID:         profileID,
		OwnershipVerified: ownership,
		AppliedInclude:    desired.appliedInclude,
		AppliedExclude:    desired.appliedExclude,
		AppliedFallback:   desired.appliedFallback,
		Conflicts:         slices.Clone(conflicts),
		WouldApply:        wouldApply,
		Conditions: statusutil.MergeConditions(object.Status.Conditions, metav1.Now(),
			metav1.Condition{Type: v1alpha1.DeviceProfileConditionAccepted, Status: conditionStatus, Reason: reason, Message: message, ObservedGeneration: object.Generation},
			metav1.Condition{Type: v1alpha1.DeviceProfileConditionReady, Status: conditionStatus, Reason: reason, Message: message, ObservedGeneration: object.Generation},
		),
		ObservedGeneration: object.Generation,
		AppliedHash:        object.Status.AppliedHash,
		AppliedAt:          object.Status.AppliedAt,
	}
}

func (r *DeviceProfileReconciler) patchStatus(ctx context.Context, object *v1alpha1.DeviceProfile, status v1alpha1.DeviceProfileStatus) error {
	current := new(v1alpha1.DeviceProfile)
	if err := r.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		return client.IgnoreNotFound(err)
	}
	before := current.DeepCopy()
	current.Status = status
	if err := r.Status().Patch(ctx, current, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("patch DeviceProfile status: %w", err)
	}
	return nil
}

func effectiveDeviceProfileManagementPolicy(policy v1alpha1.ManagementPolicy) v1alpha1.ManagementPolicy {
	if policy == "" {
		return v1alpha1.ManagementPolicyObserveOnly
	}
	return policy
}

func effectiveDeviceProfileDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

func (r *DeviceProfileReconciler) refreshLiveStatus(ctx context.Context, object *v1alpha1.DeviceProfile) error {
	if r.APIReader == nil {
		return nil
	}
	live := new(v1alpha1.DeviceProfile)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(object), live); err != nil {
		return client.IgnoreNotFound(err)
	}
	if live.UID == object.UID && live.Generation == object.Generation {
		object.Status = live.Status
	}
	return nil
}

// SetupWithManager registers the DeviceProfile controller and aggregate input watches.
func (r *DeviceProfileReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = manager.GetAPIReader()
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.DeviceProfile{}, deviceProfileAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.DeviceProfile).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index DeviceProfile accounts: %w", err)
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.CloudflareAccount{}, deviceProfileCloudflareAccountIDIndex, func(object client.Object) []string {
		accountID := object.(*v1alpha1.CloudflareAccount).Spec.AccountID
		if accountID == "" {
			return nil
		}
		return []string{accountID}
	}); err != nil {
		return fmt.Errorf("index DeviceProfile Cloudflare account IDs: %w", err)
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.CloudflareAccount{}, deviceProfileAccountCredentialIndex, func(object client.Object) []string {
		ref := object.(*v1alpha1.CloudflareAccount).Spec.Credentials.APITokenSecretRef
		if ref.Namespace == "" || ref.Name == "" {
			return nil
		}
		return []string{ref.Namespace + "/" + ref.Name}
	}); err != nil {
		return fmt.Errorf("index DeviceProfile account credential Secrets: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.DeviceProfile{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.profilesForAccount)).
		Watches(&v1alpha1.DeviceProfile{}, handler.EnqueueRequestsFromMapFunc(r.profilesForProfilePeer)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.profilesForCredentialSecret)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.profilesForNetworkRoute)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.profilesForHostnameRoute)).
		Watches(&v1alpha1.AccessApplication{}, handler.EnqueueRequestsFromMapFunc(r.profilesForAccessApplication)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.profilesForVirtualNetwork)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.profilesForNamespace)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1})
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("device-profile", r))
}

func (r *DeviceProfileReconciler) profilesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	account, ok := object.(*v1alpha1.CloudflareAccount)
	if !ok || account.Spec.AccountID == "" {
		return nil
	}
	var aliases v1alpha1.CloudflareAccountList
	if err := r.List(ctx, &aliases, client.MatchingFields{deviceProfileCloudflareAccountIDIndex: account.Spec.AccountID}); err != nil {
		return nil
	}
	seen := map[types.NamespacedName]struct{}{}
	requests := make([]reconcile.Request, 0)
	for i := range aliases.Items {
		for _, request := range r.listProfileRequests(ctx, client.MatchingFields{deviceProfileAccountIndex: aliases.Items[i].Name}, nil) {
			if _, found := seen[request.NamespacedName]; found {
				continue
			}
			seen[request.NamespacedName] = struct{}{}
			requests = append(requests, request)
		}
	}
	slices.SortFunc(requests, func(a, b reconcile.Request) int {
		return strings.Compare(a.String(), b.String())
	})
	return requests
}

func (r *DeviceProfileReconciler) profilesForProfilePeer(ctx context.Context, object client.Object) []reconcile.Request {
	profile, ok := object.(*v1alpha1.DeviceProfile)
	if !ok {
		return nil
	}
	account := new(v1alpha1.CloudflareAccount)
	if err := r.Get(ctx, types.NamespacedName{Name: profile.Spec.AccountRef.Name}, account); err != nil {
		return nil
	}
	requests := r.profilesForAccount(ctx, account)
	self := client.ObjectKeyFromObject(profile)
	return slices.DeleteFunc(requests, func(request reconcile.Request) bool {
		return request.NamespacedName == self
	})
}

func (r *DeviceProfileReconciler) profilesForCredentialSecret(ctx context.Context, object client.Object) []reconcile.Request {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}
	var accounts v1alpha1.CloudflareAccountList
	if err := r.List(ctx, &accounts, client.MatchingFields{deviceProfileAccountCredentialIndex: secret.Namespace + "/" + secret.Name}); err != nil {
		return nil
	}
	seen := map[types.NamespacedName]struct{}{}
	requests := make([]reconcile.Request, 0)
	for i := range accounts.Items {
		for _, request := range r.profilesForAccount(ctx, &accounts.Items[i]) {
			if _, found := seen[request.NamespacedName]; found {
				continue
			}
			seen[request.NamespacedName] = struct{}{}
			requests = append(requests, request)
		}
	}
	slices.SortFunc(requests, func(a, b reconcile.Request) int {
		return strings.Compare(a.String(), b.String())
	})
	return requests
}

func (r *DeviceProfileReconciler) profilesForNetworkRoute(ctx context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*v1alpha1.NetworkRoute)
	if !ok {
		return nil
	}
	return r.listProfileRequests(ctx, client.MatchingFields{deviceProfileAccountIndex: route.Spec.AccountRef.Name}, func(profile *v1alpha1.DeviceProfile) bool {
		source := profile.Spec.SplitTunnel.RouteSources.NetworkRoutes
		return source != nil && labelSelectorMatches(source.Selector, route.Labels)
	})
}

func (r *DeviceProfileReconciler) profilesForHostnameRoute(ctx context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*v1alpha1.HostnameRoute)
	if !ok {
		return nil
	}
	return r.listProfileRequests(ctx, client.MatchingFields{deviceProfileAccountIndex: route.Spec.AccountRef.Name}, func(profile *v1alpha1.DeviceProfile) bool {
		source := profile.Spec.SplitTunnel.RouteSources.HostnameRoutes
		return source != nil && labelSelectorMatches(source.Selector, route.Labels)
	})
}

func (r *DeviceProfileReconciler) profilesForAccessApplication(ctx context.Context, object client.Object) []reconcile.Request {
	application, ok := object.(*v1alpha1.AccessApplication)
	if !ok {
		return nil
	}
	namespace := new(corev1.Namespace)
	if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, namespace); err != nil {
		return nil
	}
	return r.listProfileRequests(ctx, nil, func(profile *v1alpha1.DeviceProfile) bool {
		source := profile.Spec.SplitTunnel.RouteSources.AccessApplications
		return source != nil && application.Spec.AccountRef.Name == profile.Spec.AccountRef.Name && labelSelectorMatches(source.NamespaceSelector, namespace.Labels)
	})
}

func (r *DeviceProfileReconciler) profilesForVirtualNetwork(ctx context.Context, object client.Object) []reconcile.Request {
	network, ok := object.(*v1alpha1.VirtualNetwork)
	if !ok {
		return nil
	}
	return r.listProfileRequests(ctx, client.InNamespace(network.Namespace), func(profile *v1alpha1.DeviceProfile) bool {
		fields := profile.Spec.Profile.Fields
		if fields == nil || fields.VirtualNetworks == nil {
			return false
		}
		if fields.VirtualNetworks.DefaultRef.Name == network.Name {
			return true
		}
		return slices.ContainsFunc(fields.VirtualNetworks.AllowedRefs, func(ref corev1.LocalObjectReference) bool { return ref.Name == network.Name })
	})
}

func (r *DeviceProfileReconciler) profilesForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	namespace, ok := object.(*corev1.Namespace)
	if !ok {
		return nil
	}
	return r.listProfileRequests(ctx, nil, func(profile *v1alpha1.DeviceProfile) bool {
		if profile.Namespace == namespace.Name {
			return true
		}
		source := profile.Spec.SplitTunnel.RouteSources.AccessApplications
		return source != nil && labelSelectorMatches(source.NamespaceSelector, namespace.Labels)
	})
}

func (r *DeviceProfileReconciler) listProfileRequests(ctx context.Context, options client.ListOption, keep func(*v1alpha1.DeviceProfile) bool) []reconcile.Request {
	var list v1alpha1.DeviceProfileList
	var opts []client.ListOption
	if options != nil {
		opts = append(opts, options)
	}
	if err := r.List(ctx, &list, opts...); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		if keep != nil && !keep(&list.Items[i]) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}

func labelSelectorMatches(selector metav1.LabelSelector, objectLabels map[string]string) bool {
	compiled, err := metav1.LabelSelectorAsSelector(&selector)
	return err == nil && compiled.Matches(labels.Set(objectLabels))
}
