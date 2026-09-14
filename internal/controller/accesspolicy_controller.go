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

const accessPolicyAccountIndex = accessAccountIndex + ".accessPolicy"

// AccessPolicyReconciler manages reusable Cloudflare Access policies.
type AccessPolicyReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies;accessgroups;identityproviders;deviceposturerules;servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessPolicy with its Cloudflare Access policy.
func (r *AccessPolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessPolicy)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessPolicyFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessPolicyFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if object.Spec.Decision == v1alpha1.AccessPolicyDecisionBypass {
		return ctrl.Result{}, r.patchStatus(ctx, object, "", metav1.ConditionFalse, "Invalid", "bypass policies are operator-managed; make the route rule public instead")
	}
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, object.Status.PolicyID, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		policyID := object.Spec.ExternalRef.PolicyID
		remote, getErr := api.GetAccessPolicy(ctx, policyID)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, policyID, metav1.ConditionFalse, "Conflict", fmt.Sprintf("remote policy name %q does not match expected %q", remote.Name, object.Spec.Adoption.Expect.Name))
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, policyID, metav1.ConditionTrue, "Ready", "Access policy is observed")
	}

	include, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Include)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.PolicyID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	require, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Require)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.PolicyID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	exclude, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Exclude)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.PolicyID, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.AccessPolicyInput{
		Name: name, Decision: string(object.Spec.Decision), Include: include, Require: require, Exclude: exclude,
		SessionDuration: object.Spec.SessionDuration, IsolationRequired: object.Spec.IsolationRequired,
	}
	if object.Spec.PurposeJustification != nil {
		input.PurposeJustificationRequired = object.Spec.PurposeJustification.Required
		input.PurposeJustificationPrompt = object.Spec.PurposeJustification.Prompt
	}
	if object.Spec.Approval != nil {
		input.ApprovalRequired = object.Spec.Approval.Required
		for _, group := range object.Spec.Approval.Groups {
			input.ApprovalGroups = append(input.ApprovalGroups, flarecloudflare.AccessApprovalGroup{
				ApprovalsNeeded: group.ApprovalsNeeded, EmailAddresses: group.EmailAddresses, EmailListID: group.EmailListID,
			})
		}
	}
	policyID := object.Status.PolicyID
	if policyID == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			policyID = object.Spec.ExternalRef.PolicyID
			remote, getErr := api.GetAccessPolicy(ctx, policyID)
			if getErr != nil {
				return ctrl.Result{}, getErr
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, policyID, metav1.ConditionFalse, "Conflict", "remote policy name does not match adoption expectation")
			}
		} else {
			remote, createErr := api.CreateAccessPolicy(ctx, input)
			if createErr != nil {
				return ctrl.Result{}, createErr
			}
			policyID = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, policyID, metav1.ConditionFalse, "Conflict", "remote policy ID is not verified as owned or adopted")
		}
		if _, err = api.UpdateAccessPolicy(ctx, policyID, input); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, policyID, metav1.ConditionTrue, "Ready", "Access policy is synchronized")
}

func (r *AccessPolicyReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessPolicy) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessPolicyFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.PolicyID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteAccessPolicy(ctx, object.Status.PolicyID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessPolicyFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *AccessPolicyReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessPolicy, id string, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.PolicyID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *AccessPolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the AccessPolicy controller and dependency watches.
func (r *AccessPolicyReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessPolicy{}, accessPolicyAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessPolicy).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessPolicy accounts: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.AccessPolicy{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.policiesForAccount)).Watches(&v1alpha1.AccessGroup{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.DevicePostureRule{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Complete(observedReconciler("access-policy", r))
}
func (r *AccessPolicyReconciler) policiesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessPolicyList
	if err := r.List(ctx, &list, client.MatchingFields{accessPolicyAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
func (r *AccessPolicyReconciler) policiesForDependency(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessPolicyList
	if err := r.List(ctx, &list, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
