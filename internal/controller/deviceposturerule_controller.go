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

const devicePostureAccountIndex = accessAccountIndex + ".devicePosture"

// DevicePostureRuleReconciler manages Cloudflare Zero Trust posture rules.
type DevicePostureRuleReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=deviceposturerules/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one DevicePostureRule with its Cloudflare posture rule.
func (r *DevicePostureRuleReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.DevicePostureRule)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureRuleFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.DevicePostureRuleFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, object.Status.RuleID, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id := object.Spec.ExternalRef.RuleID
		remote, getErr := api.GetDevicePostureRule(ctx, id)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote device posture rule name does not match expectation")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Device posture rule is observed")
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	description := object.Spec.Description
	if description != "" {
		description += "\n"
	}
	description += name
	input := flarecloudflare.DevicePostureRuleInput{
		Name: name, Type: object.Spec.Type, Description: description, Schedule: object.Spec.Schedule,
		Expiration: object.Spec.Expiration, Match: object.Spec.Match, Input: object.Spec.Input,
	}
	id := object.Status.RuleID
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.RuleID
			remote, getErr := api.GetDevicePostureRule(ctx, id)
			if getErr != nil {
				return ctrl.Result{}, getErr
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote device posture rule name does not match adoption expectation")
			}
		} else {
			remote, createErr := api.CreateDevicePostureRule(ctx, input)
			if createErr != nil {
				return ctrl.Result{}, createErr
			}
			id = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote device posture rule ID is not verified as owned or adopted")
		}
		if _, err = api.UpdateDevicePostureRule(ctx, id, input); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Device posture rule is synchronized")
}
func (r *DevicePostureRuleReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.DevicePostureRule) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureRuleFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.RuleID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteDevicePostureRule(ctx, object.Status.RuleID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.DevicePostureRuleFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *DevicePostureRuleReconciler) patchStatus(ctx context.Context, object *v1alpha1.DevicePostureRule, id string, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.RuleID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *DevicePostureRuleReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the DevicePostureRule controller and account watch.
func (r *DevicePostureRuleReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.DevicePostureRule{}, devicePostureAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.DevicePostureRule).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index DevicePostureRule accounts: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.DevicePostureRule{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.rulesForAccount)).Complete(observedReconciler("device-posture-rule", r))
}
func (r *DevicePostureRuleReconciler) rulesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureRuleList
	if err := r.List(ctx, &list, client.MatchingFields{devicePostureAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
