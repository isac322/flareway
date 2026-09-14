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
	identityProviderAccountIndex = accessAccountIndex + ".identityProvider"
	identityProviderSecretIndex  = ".spec.config.clientSecretRef"
)

// IdentityProviderReconciler manages Cloudflare Access identity providers.
type IdentityProviderReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one IdentityProvider with its Cloudflare identity provider.
func (r *IdentityProviderReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.IdentityProvider)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.IdentityProviderFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.IdentityProviderFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, object.Status.IDPID, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id := object.Spec.ExternalRef.IDPID
		remote, getErr := api.GetIdentityProvider(ctx, id)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote identity provider name does not match expectation")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Identity provider is observed")
	}
	secretValue, err := r.clientSecret(ctx, object)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, object.Status.IDPID, metav1.ConditionFalse, "SecretNotFound", err.Error())
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.IdentityProviderInput{Name: name, Type: object.Spec.Type, Config: object.Spec.Config, SCIMConfig: object.Spec.SCIMConfig, ClientSecret: secretValue}
	id := object.Status.IDPID
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.IDPID
			remote, getErr := api.GetIdentityProvider(ctx, id)
			if getErr != nil {
				return ctrl.Result{}, getErr
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote identity provider name does not match adoption expectation")
			}
		} else {
			remote, createErr := api.CreateIdentityProvider(ctx, input)
			if createErr != nil {
				return ctrl.Result{}, createErr
			}
			id = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionFalse, "Conflict", "remote identity provider ID is not verified as owned or adopted")
		}
		if _, err = api.UpdateIdentityProvider(ctx, id, input); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, id, metav1.ConditionTrue, "Ready", "Identity provider is synchronized")
}
func (r *IdentityProviderReconciler) clientSecret(ctx context.Context, object *v1alpha1.IdentityProvider) (string, error) {
	ref := object.Spec.Config.ClientSecretRef
	if ref == nil {
		return "", nil
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: ref.Name}, &secret); err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = "clientSecret"
	}
	value := trimSecret(secret.Data[key])
	if value == "" {
		return "", fmt.Errorf("secret %s/%s has no non-empty %q key", object.Namespace, ref.Name, key)
	}
	return value, nil
}
func (r *IdentityProviderReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.IdentityProvider) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.IdentityProviderFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.IDPID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteIdentityProvider(ctx, object.Status.IDPID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.IdentityProviderFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *IdentityProviderReconciler) patchStatus(ctx context.Context, object *v1alpha1.IdentityProvider, id string, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.IDPID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *IdentityProviderReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the IdentityProvider controller and dependency watches.
func (r *IdentityProviderReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.IdentityProvider{}, identityProviderAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.IdentityProvider).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index IdentityProvider accounts: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.IdentityProvider{}, identityProviderSecretIndex, func(object client.Object) []string {
		ref := object.(*v1alpha1.IdentityProvider).Spec.Config.ClientSecretRef
		if ref == nil {
			return nil
		}
		return []string{object.GetNamespace() + "/" + ref.Name}
	}); err != nil {
		return fmt.Errorf("index IdentityProvider Secrets: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.IdentityProvider{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.providersForAccount)).Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.providersForSecret)).Complete(observedReconciler("identity-provider", r))
}
func (r *IdentityProviderReconciler) providersForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.IdentityProviderList
	if err := r.List(ctx, &list, client.MatchingFields{identityProviderAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return identityProviderRequests(list.Items)
}
func (r *IdentityProviderReconciler) providersForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.IdentityProviderList
	if err := r.List(ctx, &list, client.MatchingFields{identityProviderSecretIndex: object.GetNamespace() + "/" + object.GetName()}); err != nil {
		return nil
	}
	return identityProviderRequests(list.Items)
}
func identityProviderRequests(items []v1alpha1.IdentityProvider) []reconcile.Request {
	out := make([]reconcile.Request, len(items))
	for i := range items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}}
	}
	return out
}
