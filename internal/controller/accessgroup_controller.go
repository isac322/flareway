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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const accessGroupAccountIndex = accessAccountIndex + ".accessGroup"

// AccessGroupReconciler manages reusable Cloudflare Access groups.
type AccessGroupReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups;identityproviders;deviceposturerules;servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessgroups/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessGroup with its Cloudflare Access group.
func (r *AccessGroupReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessGroup)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
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
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, object.Status.GroupID, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id := object.Spec.ExternalRef.GroupID
		remote, getErr := api.GetAccessGroup(ctx, id)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote group name does not match expectation")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Access group is observed")
	}
	include, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Include)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.GroupID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	require, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Require)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.GroupID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	exclude, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Exclude)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.GroupID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.AccessGroupInput{Name: name, Include: include, Require: require, Exclude: exclude}
	id := object.Status.GroupID
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.GroupID
			remote, getErr := api.GetAccessGroup(ctx, id)
			if getErr != nil {
				return ctrl.Result{}, getErr
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote group name does not match adoption expectation")
			}
		} else {
			remote, createErr := api.CreateAccessGroup(ctx, input)
			if createErr != nil {
				return ctrl.Result{}, createErr
			}
			id = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote group ID is not verified as owned or adopted")
		}
		if _, err = api.UpdateAccessGroup(ctx, id, input); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Access group is synchronized")
}
func (r *AccessGroupReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessGroup) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessGroupFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.GroupID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteAccessGroup(ctx, object.Status.GroupID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessGroupFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *AccessGroupReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessGroup, id string, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.GroupID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *AccessGroupReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the AccessGroup controller and dependency watches.
func (r *AccessGroupReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessGroup{}, accessGroupAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessGroup).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessGroup accounts: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.AccessGroup{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.groupsForAccount)).Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Watches(&v1alpha1.DevicePostureRule{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.groupsForDependency)).Complete(observedReconciler("access-group", r))
}
func (r *AccessGroupReconciler) groupsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessGroupList
	if err := r.List(ctx, &list, client.MatchingFields{accessGroupAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return accessGroupRequests(list.Items)
}
func (r *AccessGroupReconciler) groupsForDependency(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessGroupList
	if err := r.List(ctx, &list, client.InNamespace(object.GetNamespace())); err != nil {
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
