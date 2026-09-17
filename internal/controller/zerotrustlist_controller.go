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
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// ZeroTrustListReconciler owns a Cloudflare Gateway list and all its items.
type ZeroTrustListReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	APIReader           client.Reader
	NewCloudflareClient NewGatewayCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustlists;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustlists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustlists/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one ZeroTrustList with its Cloudflare Gateway list.
func (r *ZeroTrustListReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ZeroTrustList)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustListFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ZeroTrustListFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add ZeroTrustList finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}
	account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		if err := r.checkSingleWriter(ctx, object, account.Spec.AccountID); err != nil {
			return r.finishError(ctx, object, err)
		}
	}
	if r.NewCloudflareClient == nil {
		return r.finishError(ctx, object, fmt.Errorf("cloudflare Gateway client factory is required"))
	}
	api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	desiredItems := canonicalListItems(object.Spec.Items)

	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		remote, resolveErr := observeGatewayList(ctx, api, object)
		if resolveErr != nil {
			return r.finishRemoteOrValidationError(ctx, object, resolveErr)
		}
		owned := object.Status.OwnershipVerified && object.Status.ListID != "" && object.Status.ListID == remote.ID
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, owned, zeroTrustListDiff(desiredItems, remote.Items), metav1.ConditionTrue, "Observed", "Zero Trust list is observed without mutation")
	}
	remote, err := r.ensureManaged(ctx, api, object, desiredItems)
	if err != nil {
		return r.finishRemoteOrValidationError(ctx, object, err)
	}
	if err := r.patchStatus(ctx, object, remote, true, nil, metav1.ConditionTrue, "Ready", "Zero Trust list is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: globalRequeue}, nil
}

func observeGatewayList(ctx context.Context, api flarecloudflare.GatewayListAPI, object *v1alpha1.ZeroTrustList) (flarecloudflare.GatewayList, error) {
	id := object.Status.ListID
	if object.Spec.ExternalRef != nil {
		id = object.Spec.ExternalRef.ListID
	}
	if id != "" {
		remote, err := api.GetGatewayList(ctx, id)
		if err != nil {
			return flarecloudflare.GatewayList{}, err
		}
		if !object.Status.OwnershipVerified {
			if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
				return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list name %q does not match expectation %q", remote.Name, expected)
			}
		}
		if remote.Type != flarecloudflare.GatewayListType(object.Spec.Type) {
			return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list type %q does not match spec.type %q", remote.Type, object.Spec.Type)
		}
		return remote, nil
	}
	lists, err := api.ListGatewayLists(ctx)
	if err != nil {
		return flarecloudflare.GatewayList{}, err
	}
	matches := make([]flarecloudflare.GatewayList, 0, 1)
	for _, list := range lists {
		if list.Name == object.Spec.Name {
			matches = append(matches, list)
		}
	}
	if len(matches) == 0 {
		return flarecloudflare.GatewayList{}, privateInvalid("TargetNotFound", "the Cloudflare Gateway list %q was not found", object.Spec.Name)
	}
	if len(matches) > 1 {
		return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "multiple Cloudflare Gateway lists are named %q", object.Spec.Name)
	}
	if matches[0].Type != flarecloudflare.GatewayListType(object.Spec.Type) {
		return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list type %q does not match spec.type %q", matches[0].Type, object.Spec.Type)
	}
	return api.GetGatewayList(ctx, matches[0].ID)
}

func (r *ZeroTrustListReconciler) ensureManaged(ctx context.Context, api flarecloudflare.GatewayListAPI, object *v1alpha1.ZeroTrustList, items []string) (flarecloudflare.GatewayList, error) {
	id := object.Status.ListID
	adopting := object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID
	acquiring := adopting && !object.Status.OwnershipVerified
	if adopting {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.ListID == "" {
			return flarecloudflare.GatewayList{}, privateInvalid("Invalid", "adoption mode AdoptById requires externalRef.listId")
		}
		if id != "" && id != object.Spec.ExternalRef.ListID {
			return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "status list ID %q does not match adoption target %q", id, object.Spec.ExternalRef.ListID)
		}
		id = object.Spec.ExternalRef.ListID
		remote, err := api.GetGatewayList(ctx, id)
		if err != nil {
			return flarecloudflare.GatewayList{}, err
		}
		if acquiring {
			expected := object.Spec.Adoption.Expect.Name
			if expected == "" {
				expected = object.Spec.Name
			}
			if remote.Name != expected {
				return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list name %q does not match adoption expectation %q", remote.Name, expected)
			}
		}
		if remote.Type != flarecloudflare.GatewayListType(object.Spec.Type) {
			return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list type %q does not match immutable spec.type %q", remote.Type, object.Spec.Type)
		}
	} else if object.Spec.ExternalRef != nil {
		return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
	}
	if id == "" {
		lists, err := api.ListGatewayLists(ctx)
		if err != nil {
			return flarecloudflare.GatewayList{}, err
		}
		for _, list := range lists {
			if list.Name == object.Spec.Name {
				return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "the Cloudflare Gateway list %q already exists and cannot be adopted without AdoptById", object.Spec.Name)
			}
		}
		input := flarecloudflare.GatewayListInput{Name: object.Spec.Name, Type: flarecloudflare.GatewayListType(object.Spec.Type), Items: gatewayListItems(items)}
		return api.CreateGatewayList(ctx, input)
	}
	if !adopting && !object.Status.OwnershipVerified {
		return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote Gateway list ID is not verified as owned")
	}
	remote, err := api.GetGatewayList(ctx, id)
	if err != nil {
		return flarecloudflare.GatewayList{}, err
	}
	if remote.Type != flarecloudflare.GatewayListType(object.Spec.Type) {
		return flarecloudflare.GatewayList{}, privateInvalid("Conflict", "remote list type %q does not match immutable spec.type %q", remote.Type, object.Spec.Type)
	}
	if remote.Name != object.Spec.Name {
		remote, err = api.UpdateGatewayList(ctx, id, object.Spec.Name)
		if err != nil {
			return flarecloudflare.GatewayList{}, err
		}
	}
	if !equalGatewayListItems(remote.Items, items) {
		return api.ReplaceGatewayListItems(ctx, id, object.Spec.Name, gatewayListItems(items))
	}
	return remote, nil
}

func (r *ZeroTrustListReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.ZeroTrustList, accountID string) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var list v1alpha1.ZeroTrustListList
	if err := reader.List(ctx, &list); err != nil {
		return err
	}
	key := client.ObjectKeyFromObject(object)
	identity := zeroTrustListIdentity(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() ||
			effectiveGlobalManagementPolicy(other.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
			continue
		}
		preserveOwner := other.Status.OwnershipVerified && other.Status.ListID != ""
		otherAccountID, eligible := globalContenderAccountID(ctx, reader, other.Namespace, other.Spec.AccountRef.Name, other.Status.Conditions, preserveOwner)
		if !eligible || otherAccountID != accountID {
			continue
		}
		if identity != zeroTrustListIdentity(other) {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if globalObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, key) {
			return privateInvalid("Conflict", "the ZeroTrustList %s is the earlier authorized writer for Cloudflare account ID %q and the same remote list", otherKey, accountID)
		}
	}
	return nil
}

func zeroTrustListIdentity(object *v1alpha1.ZeroTrustList) string {
	if object.Status.ListID != "" {
		return "id:" + object.Status.ListID
	}
	if object.Spec.ExternalRef != nil && object.Spec.ExternalRef.ListID != "" {
		return "id:" + object.Spec.ExternalRef.ListID
	}
	return "name:" + object.Spec.Name
}

func canonicalListItems(items []string) []string {
	result := append([]string(nil), items...)
	slices.Sort(result)
	return slices.Compact(result)
}

func gatewayListItems(items []string) []flarecloudflare.GatewayListItem {
	result := make([]flarecloudflare.GatewayListItem, len(items))
	for i := range items {
		result[i] = flarecloudflare.GatewayListItem{Value: items[i]}
	}
	return result
}

func equalGatewayListItems(remote []flarecloudflare.GatewayListItem, desired []string) bool {
	values := make([]string, len(remote))
	for i := range remote {
		values[i] = remote[i].Value
	}
	return slices.Equal(canonicalListItems(values), desired)
}

func zeroTrustListDiff(desired []string, remote []flarecloudflare.GatewayListItem) *v1alpha1.ZeroTrustListItemsDiff {
	remoteValues := make([]string, len(remote))
	for i := range remote {
		remoteValues[i] = remote[i].Value
	}
	remoteValues = canonicalListItems(remoteValues)
	add := make([]string, 0)
	remove := make([]string, 0)
	for _, value := range desired {
		if _, found := slices.BinarySearch(remoteValues, value); !found {
			add = append(add, value)
		}
	}
	for _, value := range remoteValues {
		if _, found := slices.BinarySearch(desired, value); !found {
			remove = append(remove, value)
		}
	}
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	return &v1alpha1.ZeroTrustListItemsDiff{Add: add, Remove: remove}
}

func (r *ZeroTrustListReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ZeroTrustList) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustListFinalizer) {
		return nil
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged && effectiveGlobalDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.ListID != "" && object.Status.OwnershipVerified {
		account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		if r.NewCloudflareClient == nil {
			return fmt.Errorf("cloudflare Gateway client factory is required")
		}
		api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteGatewayList(ctx, object.Status.ListID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ZeroTrustListFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *ZeroTrustListReconciler) finishError(ctx context.Context, object *v1alpha1.ZeroTrustList, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.GatewayList{ID: object.Status.ListID}, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if privateIsValidationError(err) {
		if privateErrorReason(err) == "Pending" {
			return ctrl.Result{RequeueAfter: globalRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustListReconciler) finishRemoteOrValidationError(ctx context.Context, object *v1alpha1.ZeroTrustList, err error) (ctrl.Result, error) {
	if privateIsValidationError(err) {
		return r.finishError(ctx, object, err)
	}
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.GatewayList{ID: object.Status.ListID}, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustListReconciler) patchStatus(ctx context.Context, object *v1alpha1.ZeroTrustList, remote flarecloudflare.GatewayList, owned bool, wouldApply *v1alpha1.ZeroTrustListItemsDiff, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if remote.ID != "" {
		object.Status.ListID = remote.ID
	}
	if status == metav1.ConditionTrue {
		items := make([]string, len(remote.Items))
		for i := range remote.Items {
			items[i] = remote.Items[i].Value
		}
		items = canonicalListItems(items)
		object.Status.Observed = &v1alpha1.ZeroTrustListObservedState{Name: remote.Name, Type: v1alpha1.ZeroTrustListType(remote.Type), Items: items}
		object.Status.OwnershipVerified = owned
		object.Status.WouldApply = wouldApply
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = globalConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *ZeroTrustListReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ZeroTrustList controller and singleton watches.
func (r *ZeroTrustListReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ZeroTrustList{}, zeroTrustListAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ZeroTrustList).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ZeroTrustList accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.ZeroTrustList{}).Watches(&v1alpha1.ZeroTrustList{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.forAccount)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).Complete(observedReconciler("zero-trust-list", r))
}

func (r *ZeroTrustListReconciler) forWriterChange(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustListList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func (r *ZeroTrustListReconciler) forAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustListList
	if err := r.List(ctx, &list, client.MatchingFields{zeroTrustListAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}
