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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// ZeroTrustOrganizationReconciler owns the account organization singleton.
type ZeroTrustOrganizationReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	APIReader           client.Reader
	NewCloudflareClient NewOrganizationCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges the ZeroTrustOrganization singleton with Cloudflare.
func (r *ZeroTrustOrganizationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ZeroTrustOrganization)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add ZeroTrustOrganization finalizer: %w", err)
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
		return r.finishError(ctx, object, fmt.Errorf("cloudflare organization client factory is required"))
	}
	api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	observed, err := api.GetOrganization(ctx)
	if err != nil {
		return r.finishRemoteError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		return ctrl.Result{}, r.patchStatus(ctx, object, observed, organizationDiff(object.Spec, observed), metav1.ConditionTrue, "Observed", "Zero Trust organization is observed without mutation")
	}
	if organizationDiff(object.Spec, observed) != nil {
		if _, err = api.UpdateOrganization(ctx, organizationInput(object.Spec)); err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
		observed, err = api.GetOrganization(ctx)
		if err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
	}
	if err := r.patchStatus(ctx, object, observed, nil, metav1.ConditionTrue, "Ready", "Zero Trust organization is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: globalRequeue}, nil
}
func (r *ZeroTrustOrganizationReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, accountID string) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var list v1alpha1.ZeroTrustOrganizationList
	if err := reader.List(ctx, &list); err != nil {
		return err
	}
	key := client.ObjectKeyFromObject(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() ||
			effectiveGlobalManagementPolicy(other.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
			continue
		}
		otherAccountID, eligible := globalContenderAccountID(ctx, reader, other.Namespace, other.Spec.AccountRef.Name, other.Status.Conditions, false)
		if !eligible || otherAccountID != accountID {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if globalObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, key) {
			return privateInvalid("Conflict", "ZeroTrustOrganization %s is the earlier authorized writer for Cloudflare account ID %q", otherKey, accountID)
		}
	}
	return nil
}

func organizationInput(spec v1alpha1.ZeroTrustOrganizationSpec) flarecloudflare.OrganizationInput {
	return flarecloudflare.OrganizationInput{
		SessionDuration:          spec.SessionDuration,
		WARPAuthSessionDuration:  spec.WARPAuthSessionDuration,
		AllowAuthenticateViaWARP: spec.AllowAuthenticateViaWARP,
		IsUIReadOnly:             spec.IsUIReadOnly,
		DenyUnmatchedRequests:    spec.DenyUnmatchedRequests,
		WARPAuthNonBrowser401:    spec.WARPAuthNonBrowser401,
	}
}

func organizationObserved(remote flarecloudflare.Organization) v1alpha1.ZeroTrustOrganizationValues {
	return v1alpha1.ZeroTrustOrganizationValues{
		SessionDuration:          stringPointerValue(remote.SessionDuration),
		WARPAuthSessionDuration:  stringPointerValue(remote.WARPAuthSessionDuration),
		AllowAuthenticateViaWARP: boolPointerValue(remote.AllowAuthenticateViaWARP),
		IsUIReadOnly:             boolPointerValue(remote.IsUIReadOnly),
		DenyUnmatchedRequests:    boolPointerValue(remote.DenyUnmatchedRequests),
		WARPAuthNonBrowser401:    boolPointerValue(remote.WARPAuthNonBrowser401),
	}
}

func organizationDiff(spec v1alpha1.ZeroTrustOrganizationSpec, remote flarecloudflare.Organization) *v1alpha1.ZeroTrustOrganizationValues {
	diff := &v1alpha1.ZeroTrustOrganizationValues{}
	changed := false
	if spec.SessionDuration != nil && *spec.SessionDuration != remote.SessionDuration {
		diff.SessionDuration = spec.SessionDuration
		changed = true
	}
	if spec.WARPAuthSessionDuration != nil && *spec.WARPAuthSessionDuration != remote.WARPAuthSessionDuration {
		diff.WARPAuthSessionDuration = spec.WARPAuthSessionDuration
		changed = true
	}
	if spec.AllowAuthenticateViaWARP != nil && *spec.AllowAuthenticateViaWARP != remote.AllowAuthenticateViaWARP {
		diff.AllowAuthenticateViaWARP = spec.AllowAuthenticateViaWARP
		changed = true
	}
	if spec.IsUIReadOnly != nil && *spec.IsUIReadOnly != remote.IsUIReadOnly {
		diff.IsUIReadOnly = spec.IsUIReadOnly
		changed = true
	}
	if spec.DenyUnmatchedRequests != nil && *spec.DenyUnmatchedRequests != remote.DenyUnmatchedRequests {
		diff.DenyUnmatchedRequests = spec.DenyUnmatchedRequests
		changed = true
	}
	if spec.WARPAuthNonBrowser401 != nil && *spec.WARPAuthNonBrowser401 != remote.WARPAuthNonBrowser401 {
		diff.WARPAuthNonBrowser401 = spec.WARPAuthNonBrowser401
		changed = true
	}
	if !changed {
		return nil
	}
	return diff
}

func (r *ZeroTrustOrganizationReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ZeroTrustOrganization) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *ZeroTrustOrganizationReconciler) finishError(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.Organization{}, nil, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
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

func (r *ZeroTrustOrganizationReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.Organization{}, nil, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustOrganizationReconciler) patchStatus(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, remote flarecloudflare.Organization, wouldApply *v1alpha1.ZeroTrustOrganizationValues, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.AuthDomain = remote.AuthDomain
		object.Status.Name = remote.Name
		object.Status.Observed = organizationObserved(remote)
		object.Status.WouldApply = wouldApply
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = globalConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *ZeroTrustOrganizationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ZeroTrustOrganization controller and singleton watches.
func (r *ZeroTrustOrganizationReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ZeroTrustOrganization{}, organizationAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ZeroTrustOrganization).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ZeroTrustOrganization accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.ZeroTrustOrganization{}).
		Watches(&v1alpha1.ZeroTrustOrganization{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.forAccount)).
		Complete(observedReconciler("zero-trust-organization", r))
}

func (r *ZeroTrustOrganizationReconciler) forWriterChange(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustOrganizationList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func (r *ZeroTrustOrganizationReconciler) forAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustOrganizationList
	if err := r.List(ctx, &list, client.MatchingFields{organizationAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func stringPointerValue(value string) *string { result := value; return &result }
