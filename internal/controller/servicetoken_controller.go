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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

const (
	serviceTokenAccountIndex  = accessAccountIndex + ".serviceToken"
	serviceTokenRefreshBefore = 7 * 24 * time.Hour
)

// ServiceTokenReconciler manages Cloudflare Access service tokens and their one-time Secrets.
type ServiceTokenReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile converges one ServiceToken and preserves its one-time credential Secret.
func (r *ServiceTokenReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ServiceToken)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ServiceTokenFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ServiceTokenFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Pending", err.Error(), nil)
		return ctrl.Result{}, err
	}
	id := object.Status.TokenID
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id = object.Spec.ExternalRef.TokenID
		remote, getErr := api.GetServiceToken(ctx, id)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionFalse, "Conflict", "remote service token name does not match expectation", nil)
		}
		return ctrl.Result{RequeueAfter: r.requeueAfter(remote.ExpiresAt)}, r.patchStatus(ctx, object, remote, metav1.ConditionTrue, "Ready", "Service token is observed", nil)
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.ServiceTokenInput{Name: name, Duration: object.Spec.Duration}
	if id == "" {
		recoveredID, recoverErr := r.recoverTokenID(ctx, object)
		if recoverErr != nil {
			return ctrl.Result{}, recoverErr
		}
		if recoveredID != "" {
			remote, getErr := api.GetServiceToken(ctx, recoveredID)
			if getErr != nil {
				return ctrl.Result{}, getErr
			}
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionTrue, "Recovered", "Recovered service token ownership from its Secret", nil)
		}
	}

	var remote flarecloudflare.ServiceToken
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.TokenID
			remote, err = api.GetServiceToken(ctx, id)
			if err != nil {
				return ctrl.Result{}, err
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionFalse, "Conflict", "remote service token name does not match adoption expectation", nil)
			}
		} else {
			issued, createErr := api.CreateServiceToken(ctx, input)
			if createErr != nil {
				return ctrl.Result{}, createErr
			}
			if err = r.writeSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret); err != nil {
				return ctrl.Result{}, err
			}
			remote, err = api.GetServiceToken(ctx, issued.ID)
			if err != nil {
				remote = issued.ServiceToken
			}
			id = issued.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionFalse, "Conflict", "remote service token ID is not verified as owned or adopted", nil)
		}
		remote, err = api.UpdateServiceToken(ctx, id, input)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err = r.requireExistingSecret(ctx, object); err != nil && !rotationRequested(object) {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionFalse, "SecretMissing", "service token Secret is missing; update rotation.requestedAt to rotate explicitly", nil)
		}
	}

	var rotatedAt *metav1.Time
	if object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationManual && rotationRequested(object) {
		grace, parseErr := time.ParseDuration(object.Spec.Rotation.GraceDuration)
		if parseErr != nil {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, metav1.ConditionFalse, "Invalid", fmt.Sprintf("parse rotation graceDuration: %v", parseErr), nil)
		}
		issued, rotateErr := api.RotateServiceToken(ctx, id, r.now().Add(grace))
		if rotateErr != nil {
			return ctrl.Result{}, rotateErr
		}
		if err = r.writeSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret); err != nil {
			return ctrl.Result{}, err
		}
		remote = issued.ServiceToken
		if refreshed, getErr := api.GetServiceToken(ctx, id); getErr == nil {
			remote = refreshed
		}
		stamp := metav1.NewTime(r.now())
		rotatedAt = &stamp
	}
	if object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationOnExpiry &&
		!remote.ExpiresAt.IsZero() && !remote.ExpiresAt.After(r.now().Add(serviceTokenRefreshBefore)) {
		remote, err = api.RefreshServiceToken(ctx, id)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: r.requeueAfter(remote.ExpiresAt)}, r.patchStatus(ctx, object, remote, metav1.ConditionTrue, "Ready", "Service token is synchronized", rotatedAt)
}
func rotationRequested(object *v1alpha1.ServiceToken) bool {
	return object.Spec.Rotation.RequestedAt != nil && (object.Status.ObservedRotationRequest == nil || object.Spec.Rotation.RequestedAt.After(object.Status.ObservedRotationRequest.Time))
}
func (r *ServiceTokenReconciler) requireExistingSecret(ctx context.Context, object *v1alpha1.ServiceToken) error {
	var secret corev1.Secret
	return r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, &secret)
}
func (r *ServiceTokenReconciler) writeSecret(ctx context.Context, object *v1alpha1.ServiceToken, tokenID, clientID, clientSecret string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
			return err
		}
		secret.Type = corev1.SecretTypeOpaque
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] = tokenID
		secret.Data[v1alpha1.ServiceTokenClientIDKey] = []byte(clientID)
		secret.Data[v1alpha1.ServiceTokenClientSecretKey] = []byte(clientSecret)
		return nil
	})
	return err
}

func (r *ServiceTokenReconciler) recoverTokenID(ctx context.Context, object *v1alpha1.ServiceToken) (string, error) {
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, owner := range secret.OwnerReferences {
		if owner.UID == object.UID && owner.Controller != nil && *owner.Controller {
			return secret.Annotations[v1alpha1.ServiceTokenIDAnnotation], nil
		}
	}
	return "", nil
}
func (r *ServiceTokenReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ServiceToken) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ServiceTokenFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.TokenID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteServiceToken(ctx, object.Status.TokenID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ServiceTokenFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *ServiceTokenReconciler) patchStatus(ctx context.Context, object *v1alpha1.ServiceToken, remote flarecloudflare.ServiceToken, status metav1.ConditionStatus, reason, message string, rotatedAt *metav1.Time) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.TokenID = remote.ID
		object.Status.ClientID = remote.ClientID
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
		if !remote.ExpiresAt.IsZero() {
			stamp := metav1.NewTime(remote.ExpiresAt)
			object.Status.ExpiresAt = &stamp
		}
	}
	if rotatedAt != nil {
		object.Status.RotatedAt = rotatedAt
	}
	if object.Spec.Rotation.RequestedAt != nil && reason == "Ready" {
		object.Status.ObservedRotationRequest = object.Spec.Rotation.RequestedAt.DeepCopy()
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *ServiceTokenReconciler) requeueAfter(expires time.Time) time.Duration {
	if expires.IsZero() {
		return 6 * time.Hour
	}
	next := expires.Add(-serviceTokenRefreshBefore).Sub(r.now())
	if next < time.Minute {
		return time.Minute
	}
	return next
}
func (r *ServiceTokenReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ServiceToken controller and account watch.
func (r *ServiceTokenReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ServiceToken{}, serviceTokenAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ServiceToken).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ServiceToken accounts: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.ServiceToken{}).Owns(&corev1.Secret{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.tokensForAccount)).Complete(observedReconciler("service-token", r))
}
func (r *ServiceTokenReconciler) tokensForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ServiceTokenList
	if err := r.List(ctx, &list, client.MatchingFields{serviceTokenAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
