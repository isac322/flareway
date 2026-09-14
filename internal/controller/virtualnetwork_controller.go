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
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// VirtualNetworkReconciler manages Cloudflare Zero Trust virtual networks.
type VirtualNetworkReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewPrivateNetworkCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one VirtualNetwork with its Cloudflare virtual network.
func (r *VirtualNetworkReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.VirtualNetwork)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.VirtualNetworkFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.VirtualNetworkFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add VirtualNetwork finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
		return r.finishError(ctx, object, err)
	}
	if err = r.checkSingleWriter(ctx, object); err != nil {
		return r.finishError(ctx, object, err)
	}
	ownerComment, err := privateOwnerComment(ctx, r.Client, object, object.Spec.Comment)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	api, err := privateNetworkClient(ctx, r.Client, account, r.NewCloudflareClient)
	if err != nil {
		return r.finishError(ctx, object, err)
	}

	policy := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy)
	if policy == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.VirtualNetworkID == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "ObserveOnly requires externalRef.virtualNetworkId"))
		}
		remote, getErr := api.GetVirtualNetwork(ctx, object.Spec.ExternalRef.VirtualNetworkID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if conflict := validateObservedVirtualNetwork(object, remote); conflict != "" {
			return r.finishError(ctx, object, privateInvalid("Conflict", "%s", conflict))
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, metav1.ConditionTrue, "Observed", "Virtual network is observed without mutation")
	}

	input := flarecloudflare.VirtualNetworkInput{Name: object.Spec.Name, IsDefault: object.Spec.IsDefault, Comment: ownerComment}
	remote, err := r.ensureManaged(ctx, api, object, input)
	if err != nil {
		if privateIsValidationError(err) {
			return r.finishError(ctx, object, err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, remote, true, metav1.ConditionTrue, "Ready", "Virtual network is synchronized")
}

func (r *VirtualNetworkReconciler) ensureManaged(ctx context.Context, api flarecloudflare.VirtualNetworkAPI, object *v1alpha1.VirtualNetwork, input flarecloudflare.VirtualNetworkInput) (flarecloudflare.VirtualNetwork, error) {
	id := object.Status.VirtualNetworkID
	var remote flarecloudflare.VirtualNetwork
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.VirtualNetworkID == "" {
				return flarecloudflare.VirtualNetwork{}, privateInvalid("Invalid", "AdoptById requires externalRef.virtualNetworkId")
			}
			id = object.Spec.ExternalRef.VirtualNetworkID
			observed, err := api.GetVirtualNetwork(ctx, id)
			if err != nil {
				return flarecloudflare.VirtualNetwork{}, err
			}
			if observed.Deleted {
				return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "remote virtual network %q is deleted", id)
			}
			expectedName := object.Spec.Adoption.Expect.Name
			if expectedName == "" {
				expectedName = object.Spec.Name
			}
			if observed.Name != expectedName {
				return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "remote virtual network name %q does not match adoption expectation %q", observed.Name, expectedName)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "Managed externalRef requires adoption.mode AdoptById")
		default:
			recovered, found, err := findOwnedVirtualNetwork(ctx, api, input.Comment)
			if err != nil {
				return flarecloudflare.VirtualNetwork{}, err
			}
			if found {
				id, remote = recovered.ID, recovered
			} else {
				return api.CreateVirtualNetwork(ctx, input)
			}
		}
	} else {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "remote virtual network ID is not verified as owned or adopted")
		}
		observed, err := api.GetVirtualNetwork(ctx, id)
		if err != nil {
			return flarecloudflare.VirtualNetwork{}, err
		}
		remote = observed
	}
	if remote.Deleted {
		return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "remote virtual network %q is deleted", id)
	}
	return api.UpdateVirtualNetwork(ctx, id, input)
}

func findOwnedVirtualNetwork(ctx context.Context, api flarecloudflare.VirtualNetworkAPI, comment string) (flarecloudflare.VirtualNetwork, bool, error) {
	remotes, err := api.ListVirtualNetworks(ctx)
	if err != nil {
		return flarecloudflare.VirtualNetwork{}, false, err
	}
	var found flarecloudflare.VirtualNetwork
	for i := range remotes {
		if remotes[i].Deleted || !privateCommentOwnedBy(remotes[i].Comment, comment) {
			continue
		}
		if found.ID != "" {
			return flarecloudflare.VirtualNetwork{}, false, privateInvalid("Conflict", "multiple remote virtual networks carry ownership comment %q", comment)
		}
		found = remotes[i]
	}
	return found, found.ID != "", nil
}

func validateObservedVirtualNetwork(object *v1alpha1.VirtualNetwork, remote flarecloudflare.VirtualNetwork) string {
	if remote.Deleted {
		return fmt.Sprintf("remote virtual network %q is deleted", remote.ID)
	}
	if remote.Name != object.Spec.Name {
		return fmt.Sprintf("remote virtual network name %q does not match spec.name %q", remote.Name, object.Spec.Name)
	}
	if remote.IsDefault != object.Spec.IsDefault {
		return fmt.Sprintf("remote virtual network isDefault=%t does not match spec.isDefault=%t", remote.IsDefault, object.Spec.IsDefault)
	}
	if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
		return fmt.Sprintf("remote virtual network name %q does not match expectation %q", remote.Name, expected)
	}
	return ""
}

func (r *VirtualNetworkReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.VirtualNetwork) error {
	var list v1alpha1.VirtualNetworkList
	if err := r.List(ctx, &list); err != nil {
		return err
	}
	thisKey := client.ObjectKeyFromObject(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() || other.Spec.AccountRef.Name != object.Spec.AccountRef.Name {
			continue
		}
		conflict := other.Spec.Name == object.Spec.Name || (object.Spec.IsDefault && other.Spec.IsDefault)
		if !conflict {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if privateObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, thisKey) {
			return privateInvalid("Conflict", "VirtualNetwork %s is the earlier writer for this account name or default network", otherKey)
		}
	}
	return nil
}

func (r *VirtualNetworkReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.VirtualNetwork) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.VirtualNetworkFinalizer) {
		return nil
	}
	if blockedBy, err := r.networkRouteReferences(ctx, object); err != nil {
		return err
	} else if blockedBy != "" {
		return fmt.Errorf("VirtualNetwork deletion is blocked by NetworkRoute %s", blockedBy)
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly && effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.VirtualNetworkID != "" && object.Status.OwnershipVerified {
		account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
			return err
		}
		api, err := privateNetworkClient(ctx, r.Client, account, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteVirtualNetwork(ctx, object.Status.VirtualNetworkID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.VirtualNetworkFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *VirtualNetworkReconciler) finishError(ctx context.Context, object *v1alpha1.VirtualNetwork, err error) (ctrl.Result, error) {
	patchErr := r.patchStatus(ctx, object, flarecloudflare.VirtualNetwork{ID: object.Status.VirtualNetworkID}, object.Status.OwnershipVerified, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
	if patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if privateIsValidationError(err) {
		if privateErrorReason(err) == "Pending" {
			return ctrl.Result{RequeueAfter: privateNetworkRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *VirtualNetworkReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.VirtualNetwork, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.VirtualNetwork{ID: object.Status.VirtualNetworkID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *VirtualNetworkReconciler) patchStatus(ctx context.Context, object *v1alpha1.VirtualNetwork, remote flarecloudflare.VirtualNetwork, owned bool, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if remote.ID != "" {
		object.Status.VirtualNetworkID = remote.ID
	}
	if status == metav1.ConditionTrue {
		object.Status.Name = remote.Name
		object.Status.IsDefault = remote.IsDefault
		object.Status.Comment = remote.Comment
		object.Status.OwnershipVerified = owned
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = privateConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *VirtualNetworkReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the VirtualNetwork controller and dependency watches.
func (r *VirtualNetworkReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.VirtualNetwork{}, virtualNetworkAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.VirtualNetwork).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index VirtualNetwork accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.VirtualNetwork{}).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworksForAccount)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworkPeers)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworkForNetworkRoute)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(observedReconciler("virtual-network", r))
}

func (r *VirtualNetworkReconciler) virtualNetworksForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.VirtualNetworkList
	if err := r.List(ctx, &list, client.MatchingFields{virtualNetworkAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return virtualNetworkRequests(list.Items)
}

func (r *VirtualNetworkReconciler) virtualNetworkPeers(ctx context.Context, object client.Object) []reconcile.Request {
	virtualNetwork, ok := object.(*v1alpha1.VirtualNetwork)
	if !ok {
		return nil
	}
	return r.virtualNetworksForAccount(ctx, &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: virtualNetwork.Spec.AccountRef.Name}})
}

func (r *VirtualNetworkReconciler) virtualNetworkForNetworkRoute(_ context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*v1alpha1.NetworkRoute)
	if !ok || route.Spec.VirtualNetworkRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.VirtualNetworkRef.Name}}}
}

func (r *VirtualNetworkReconciler) networkRouteReferences(ctx context.Context, object *v1alpha1.VirtualNetwork) (string, error) {
	var routes v1alpha1.NetworkRouteList
	if err := r.List(ctx, &routes, client.InNamespace(object.Namespace)); err != nil {
		return "", err
	}
	for i := range routes.Items {
		route := &routes.Items[i]
		if route.DeletionTimestamp.IsZero() && route.Spec.VirtualNetworkRef.Name == object.Name {
			return client.ObjectKeyFromObject(route).String(), nil
		}
	}
	return "", nil
}

func virtualNetworkRequests(items []v1alpha1.VirtualNetwork) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for i := range items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}})
	}
	return requests
}
