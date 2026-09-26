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
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

const accessGroupAccountIndex = accessAccountIndex + ".accessGroup"

// AccessGroupReconciler manages reusable Cloudflare Access groups.
type AccessGroupReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups;identityproviders;deviceposturerules;servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessGroup with its Cloudflare Access group.
func (r *AccessGroupReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessGroup)
	if err := r.reader().Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "AccessGroup", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessGroupFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessGroupFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	scope := flarecloudflare.AccessScope{ZoneID: object.Status.ZoneID}
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Status.GroupID}, object.Status.OwnershipVerified, metav1.ConditionFalse, privateErrorReason(err), err.Error())
		return ctrl.Result{}, err
	}
	scope, err = accessGroupScope(object.Spec.Zone, account.Status.Verified.Zones)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Status.GroupID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "Invalid", err.Error())
	}
	include, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Include)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Status.GroupID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	require, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Require)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Status.GroupID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	exclude, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Exclude)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Status.GroupID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}

	name := object.Spec.Name
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly {
		name, err = accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	input := flarecloudflare.AccessGroupInput{
		Name: name, Include: include, Require: require, Exclude: exclude, IsDefault: object.Spec.IsDefault,
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.GroupID == "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{}, false, metav1.ConditionFalse, "Invalid", "ObserveOnly requires externalRef.groupId")
		}
		remote, getErr := api.GetAccessGroup(ctx, scope, object.Spec.ExternalRef.GroupID)
		if getErr != nil {
			reason := accessGroupErrorReason(getErr)
			if patchErr := r.patchStatus(ctx, object, scope, flarecloudflare.AccessGroup{ID: object.Spec.ExternalRef.GroupID}, false, metav1.ConditionFalse, reason, getErr.Error()); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			if reason == "Unsupported" {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, getErr
		}
		if conflict := validateObservedAccessGroup(object, input, remote); conflict != "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, false, metav1.ConditionFalse, "Conflict", conflict)
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, false, metav1.ConditionTrue, "Observed", "Access group is observed without mutation")
	}

	// T1 gate: the managed path below reads the remote group before any write.
	// ObserveOnly above stays ungated (safety condition 9 — observation is the
	// feature). Adoption scans inside ensureManaged are T0 by construction:
	// the gate only opens once status.groupId is bound and the applied hash
	// matches, so a first-time adoption always reads fresh.
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "AccessGroup", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.GroupID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}

	remote, owned, conflict, ensureErr := r.ensureManaged(ctx, api, scope, object, input)
	if ensureErr != nil {
		reason := accessGroupErrorReason(ensureErr)
		if patchErr := r.patchStatus(ctx, object, scope, remote, owned, metav1.ConditionFalse, reason, ensureErr.Error()); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		if reason == "Unsupported" {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, ensureErr
	}
	if conflict != "" {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, false, metav1.ConditionFalse, "Conflict", conflict)
	}
	if err := r.patchStatus(ctx, object, scope, remote, owned, metav1.ConditionTrue, "Ready", "Access group is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, r.Invalidator, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "AccessGroup", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeAuthz)}, nil
}
func (r *AccessGroupReconciler) ensureManaged(ctx context.Context, api flarecloudflare.AccessGroupAPI, scope flarecloudflare.AccessScope, object *v1alpha1.AccessGroup, input flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, bool, string, error) {
	id := object.Status.GroupID
	var remote flarecloudflare.AccessGroup
	forceUpdate := false
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.GroupID == "" {
				return remote, false, "AdoptById requires externalRef.groupId", nil
			}
			id = object.Spec.ExternalRef.GroupID
			observed, err := api.GetAccessGroup(ctx, scope, id)
			if err != nil {
				return remote, false, "", err
			}
			expectedName := object.Spec.Adoption.Expect.Name
			if expectedName == "" {
				expectedName = input.Name
			}
			if observed.Name != expectedName {
				return observed, false, fmt.Sprintf("remote Access group name %q does not match adoption expectation %q", observed.Name, expectedName), nil
			}
			remote = observed
			forceUpdate = true
		case object.Spec.ExternalRef != nil:
			return remote, false, "Managed externalRef requires adoption.mode AdoptById", nil
		default:
			recovered, found, err := findAccessGroupByName(ctx, api, scope, input.Name)
			if err != nil {
				return remote, false, "", err
			}
			if !found {
				created, err := api.CreateAccessGroup(ctx, scope, input)
				return created, created.ID != "", "", err
			}
			id, remote = recovered.ID, recovered
			forceUpdate = object.Status.ObservedGeneration != object.Generation
		}
	} else {
		if !object.Status.OwnershipVerified {
			return remote, false, "remote Access group ID is not verified as owned or adopted", nil
		}
		observed, err := api.GetAccessGroup(ctx, scope, id)
		if err != nil {
			return remote, false, "", err
		}
		remote = observed
		forceUpdate = remote.IsDefault == nil && (object.Status.ObservedGeneration != object.Generation || !metaConditionTrue(object.Status.Conditions, "Ready"))
	}
	if !forceUpdate && accessGroupMatchesInput(remote, input) {
		return remote, true, "", nil
	}
	updated, err := api.UpdateAccessGroup(ctx, scope, id, input)
	if updated.ID == "" {
		updated.ID = id
	}
	return updated, id != "", "", err
}

func findAccessGroupByName(ctx context.Context, api flarecloudflare.AccessGroupAPI, scope flarecloudflare.AccessScope, name string) (flarecloudflare.AccessGroup, bool, error) {
	remotes, err := api.ListAccessGroups(ctx, flarecloudflare.AccessGroupListOptions{Scope: scope, Name: name})
	if err != nil {
		return flarecloudflare.AccessGroup{}, false, err
	}
	var found flarecloudflare.AccessGroup
	for i := range remotes {
		if remotes[i].Name != name {
			continue
		}
		if found.ID != "" {
			return flarecloudflare.AccessGroup{}, false, fmt.Errorf("multiple remote Access groups have name %q", name)
		}
		found = remotes[i]
	}
	return found, found.ID != "", nil
}

func validateObservedAccessGroup(object *v1alpha1.AccessGroup, input flarecloudflare.AccessGroupInput, remote flarecloudflare.AccessGroup) string {
	if conflict := accessGroupInputConflict(remote, input); conflict != "" {
		return conflict
	}
	if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
		return fmt.Sprintf("remote Access group name %q does not match expectation %q", remote.Name, expected)
	}
	return ""
}

func accessGroupMatchesInput(remote flarecloudflare.AccessGroup, input flarecloudflare.AccessGroupInput) bool {
	return accessGroupInputConflict(remote, input) == ""
}

func accessGroupInputConflict(remote flarecloudflare.AccessGroup, input flarecloudflare.AccessGroupInput) string {
	switch {
	case remote.Name != input.Name:
		return fmt.Sprintf("remote Access group name %q does not match desired %q", remote.Name, input.Name)
	case !reflect.DeepEqual(remote.Include, input.Include):
		return "remote Access group include rules do not match desired rules"
	case !reflect.DeepEqual(remote.Require, input.Require):
		return "remote Access group require rules do not match desired rules"
	case !reflect.DeepEqual(remote.Exclude, input.Exclude):
		return "remote Access group exclude rules do not match desired rules"
	case remote.IsDefault != nil && *remote.IsDefault != input.IsDefault:
		return fmt.Sprintf("remote Access group isDefault=%t does not match desired isDefault=%t", *remote.IsDefault, input.IsDefault)
	default:
		return ""
	}
}

func accessGroupScope(zoneName string, zones []v1alpha1.CloudflareVerifiedZone) (flarecloudflare.AccessScope, error) {
	if zoneName == "" {
		return flarecloudflare.AccessScope{}, nil
	}
	normalized := strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, zone := range zones {
		if strings.ToLower(strings.TrimSuffix(zone.Name, ".")) == normalized {
			if zone.ID == "" {
				return flarecloudflare.AccessScope{}, fmt.Errorf("zone %q has no verified ID in CloudflareAccount status.verified.zones", zoneName)
			}
			return flarecloudflare.AccessScope{ZoneID: zone.ID}, nil
		}
	}
	return flarecloudflare.AccessScope{}, fmt.Errorf("zone %q is not present in CloudflareAccount status.verified.zones", zoneName)
}
func accessGroupErrorReason(err error) string {
	var unsupported *flarecloudflare.UnsupportedAccessPolicyFieldError
	if errors.As(err, &unsupported) {
		return "Unsupported"
	}
	return "CloudflareError"
}

func (r *AccessGroupReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessGroup) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessGroupFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.GroupID != "" && object.Status.OwnershipVerified {
		api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		scope, err := accessGroupScope(object.Spec.Zone, account.Status.Verified.Zones)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteAccessGroup(ctx, scope, object.Status.GroupID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessGroupFinalizer)
	return r.Patch(ctx, object, base)
}
func accessGroupObservedState(remote flarecloudflare.AccessGroup) (*v1alpha1.AccessGroupObservedState, error) {
	include, err := accessRulesObserved(remote.Include)
	if err != nil {
		return nil, fmt.Errorf("convert observed Access group include rules: %w", err)
	}
	require, err := accessRulesObserved(remote.Require)
	if err != nil {
		return nil, fmt.Errorf("convert observed Access group require rules: %w", err)
	}
	exclude, err := accessRulesObserved(remote.Exclude)
	if err != nil {
		return nil, fmt.Errorf("convert observed Access group exclude rules: %w", err)
	}
	defaultRules, err := accessRulesObserved(remote.Default)
	if err != nil {
		return nil, fmt.Errorf("convert observed Access group default rules: %w", err)
	}
	var isDefault *bool
	if remote.IsDefault != nil {
		value := *remote.IsDefault
		isDefault = &value
	}
	return &v1alpha1.AccessGroupObservedState{
		Name: remote.Name, Include: include, Require: require, Exclude: exclude, IsDefault: isDefault, Default: defaultRules,
	}, nil
}

func (r *AccessGroupReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessGroup, scope flarecloudflare.AccessScope, remote flarecloudflare.AccessGroup, owned bool, status metav1.ConditionStatus, reason, message string) error {
	generation := object.Generation
	persistIdentity := remote.ID != "" && (status == metav1.ConditionTrue || owned || object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly)
	if status == metav1.ConditionTrue && remote.ID == "" {
		return fmt.Errorf("remote Access group response omitted ID")
	}
	if persistIdentity {
		if err := r.persistIdentity(ctx, object, scope, remote.ID, owned); err != nil {
			return err
		}
	}
	var observed *v1alpha1.AccessGroupObservedState
	if remote.Name != "" {
		var err error
		observed, err = accessGroupObservedState(remote)
		if err != nil {
			return err
		}
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current := new(v1alpha1.AccessGroup)
		if err := r.reader().Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
			return err
		}
		if current.Generation != generation {
			return nil
		}
		base := client.MergeFrom(current.DeepCopy())
		if observed != nil {
			current.Status.Observed = observed
		}
		if persistIdentity {
			current.Status.GroupID = remote.ID
			current.Status.ZoneID = scope.ZoneID
			current.Status.OwnershipVerified = owned
		}
		current.Status.AppliedHash = object.Status.AppliedHash
		current.Status.AppliedAt = object.Status.AppliedAt
		current.Status.ObservedGeneration = generation
		current.Status.Conditions = mergeAccessConditions(current.Status.Conditions, r.now(), accessCondition(generation, "Accepted", status, reason, message), accessCondition(generation, "Ready", status, reason, message))
		if err := r.Status().Patch(ctx, current, base); err != nil {
			return err
		}
		*object = *current
		return nil
	})
}

func (r *AccessGroupReconciler) persistIdentity(ctx context.Context, object *v1alpha1.AccessGroup, scope flarecloudflare.AccessScope, id string, owned bool) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current := new(v1alpha1.AccessGroup)
		if err := r.reader().Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
			return err
		}
		if current.Status.GroupID == id && current.Status.ZoneID == scope.ZoneID && current.Status.OwnershipVerified == owned {
			*object = *current
			return nil
		}
		base := client.MergeFrom(current.DeepCopy())
		current.Status.GroupID = id
		current.Status.ZoneID = scope.ZoneID
		current.Status.OwnershipVerified = owned
		if err := r.Status().Patch(ctx, current, base); err != nil {
			return err
		}
		*object = *current
		return nil
	})
}
func (r *AccessGroupReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *AccessGroupReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// SetupWithManager registers the AccessGroup controller and dependency watches.
func (r *AccessGroupReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = manager.GetAPIReader()
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessGroup{}, accessGroupAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessGroup).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessGroup accounts: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).For(&v1alpha1.AccessGroup{}, builder.WithPredicates(desiredStateChangedPredicate)).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.groupsForAccount)).Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Watches(&v1alpha1.DevicePostureRule{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.groupsForNamespace))
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("access-group", r))
}
func (r *AccessGroupReconciler) groupsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessGroupList
	if err := r.List(ctx, &list, client.MatchingFields{accessGroupAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return accessGroupRequests(list.Items)
}
func (r *AccessGroupReconciler) groupsForDependency(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.AccessGroupList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	return accessGroupRequests(list.Items)
}
func (r *AccessGroupReconciler) groupsForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessGroupList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return accessGroupRequests(list.Items)
}
func accessGroupRequests(items []v1alpha1.AccessGroup) []reconcile.Request {
	out := make([]reconcile.Request, len(items))
	for i := range items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}}
	}
	return out
}
