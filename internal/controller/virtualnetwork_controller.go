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
)

// VirtualNetworkReconciler manages Cloudflare Zero Trust virtual networks.
type VirtualNetworkReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewPrivateNetworkCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one VirtualNetwork with its Cloudflare virtual network.
func (r *VirtualNetworkReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.VirtualNetwork)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "VirtualNetwork", request.NamespacedName, err)
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
	if err = r.checkSingleWriter(ctx, account, object); err != nil {
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
			return r.finishError(ctx, object, privateInvalid("Invalid", "management policy ObserveOnly requires externalRef.virtualNetworkId"))
		}
		remote, getErr := api.GetVirtualNetwork(ctx, object.Spec.ExternalRef.VirtualNetworkID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if conflict := validateObservedVirtualNetwork(object, remote); conflict != "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, metav1.ConditionFalse, "Conflict", conflict)
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, metav1.ConditionTrue, "Observed", "Virtual network is observed without mutation")
	}

	input := flarecloudflare.VirtualNetworkInput{Name: object.Spec.Name, IsDefault: object.Spec.IsDefault, Comment: ownerComment}
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeTraffic, gateInput{
		Kind: "VirtualNetwork", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.VirtualNetworkID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: object.Spec,
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}
	remote, err := r.ensureManaged(ctx, api, object, input)
	if err != nil {
		if privateIsValidationError(err) && remote.ID != "" {
			owned := object.Status.OwnershipVerified || privateCommentOwnedBy(remote.Comment, input.Comment)
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, owned, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
		}
		if privateIsValidationError(err) {
			return r.finishError(ctx, object, err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	if err := r.patchStatus(ctx, object, remote, true, metav1.ConditionTrue, "Ready", "Virtual network is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	stamp := newGateStamp(decision.DesiredHash, r.now())
	// ListVirtualNetworks returns every field this pass compared, so the
	// sweep's listing can stand in for this pass's own read.
	stamp = stamp.withContent(contentBaseline(func(listed any) bool {
		vnet, ok := listed.(flarecloudflare.VirtualNetwork)
		return ok && vnet.ID == remote.ID && !vnet.Deleted &&
			privateCommentOwnedBy(vnet.Comment, input.Comment) &&
			!virtualNetworkNeedsUpdate(input, vnet)
	}, remote))
	if err := persistGateStamp(ctx, r.Client, r.Invalidator, object, stamp); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "VirtualNetwork", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeTraffic)}, nil
}

func (r *VirtualNetworkReconciler) ensureManaged(ctx context.Context, api flarecloudflare.VirtualNetworkAPI, object *v1alpha1.VirtualNetwork, input flarecloudflare.VirtualNetworkInput) (flarecloudflare.VirtualNetwork, error) {
	id := object.Status.VirtualNetworkID
	var remote flarecloudflare.VirtualNetwork
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.VirtualNetworkID == "" {
				return flarecloudflare.VirtualNetwork{}, privateInvalid("Invalid", "adoption mode AdoptById requires externalRef.virtualNetworkId")
			}
			id = object.Spec.ExternalRef.VirtualNetworkID
			observed, err := api.GetVirtualNetwork(ctx, id)
			if err != nil {
				return flarecloudflare.VirtualNetwork{}, err
			}
			if observed.Deleted {
				return observed, privateInvalid("Conflict", "remote virtual network %q is deleted", id)
			}
			expectedName := object.Spec.Adoption.Expect.Name
			if expectedName == "" {
				expectedName = object.Spec.Name
			}
			if observed.Name != expectedName {
				return observed, privateInvalid("Conflict", "remote virtual network name %q does not match adoption expectation %q", observed.Name, expectedName)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
		default:
			recovered, found, err := findOwnedVirtualNetwork(ctx, api, input.Comment)
			if err != nil {
				return flarecloudflare.VirtualNetwork{}, err
			}
			if found {
				id, remote = recovered.ID, recovered
				break
			}
			created, createErr := api.CreateVirtualNetwork(ctx, input)
			if createErr != nil {
				return flarecloudflare.VirtualNetwork{}, createErr
			}
			id, remote = created.ID, created
		}
	} else {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.VirtualNetwork{}, privateInvalid("Conflict", "remote virtual network ID is not verified as owned or adopted")
		}
		observed, err := api.GetVirtualNetwork(ctx, id)
		if err != nil {
			return flarecloudflare.VirtualNetwork{}, err
		}
		if !privateCommentOwnedBy(observed.Comment, input.Comment) {
			return observed, privateInvalid("Conflict", "remote virtual network %q no longer carries this object's ownership comment", id)
		}
		remote = observed
	}
	if id == "" || remote.ID == "" {
		return remote, privateInvalid("Conflict", "the Cloudflare service returned a virtual network without an ID")
	}
	if remote.Deleted {
		return remote, privateInvalid("Conflict", "remote virtual network %q is deleted", id)
	}
	if !virtualNetworkNeedsUpdate(input, remote) {
		return remote, nil
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
	if object.Spec.Comment != "" && remote.Comment != object.Spec.Comment {
		return "remote virtual network comment does not match spec.comment"
	}
	if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
		return fmt.Sprintf("remote virtual network name %q does not match expectation %q", remote.Name, expected)
	}
	return ""
}

func virtualNetworkNeedsUpdate(input flarecloudflare.VirtualNetworkInput, remote flarecloudflare.VirtualNetwork) bool {
	return remote.Name != input.Name || remote.IsDefault != input.IsDefault || remote.Comment != input.Comment
}

func (r *VirtualNetworkReconciler) checkSingleWriter(ctx context.Context, account *v1alpha1.CloudflareAccount, object *v1alpha1.VirtualNetwork) error {
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
		if !privateObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, thisKey) {
			continue
		}
		// A contender is eligible only while the account grants its namespace;
		// an unauthorized peer cannot squat the name or default claim.
		if _, err := authorizePrivateNamespace(ctx, r.Client, account, other.Namespace, authz.Request{PlatformObject: true}); err != nil {
			if privateIsValidationError(err) {
				continue
			}
			return err
		}
		return privateInvalid("Conflict", "the VirtualNetwork %s is the earlier writer for this account name or default network", otherKey)
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
		message := fmt.Sprintf("the VirtualNetwork deletion is blocked by NetworkRoute %s", blockedBy)
		if err := r.patchCleanupBlocked(ctx, object, message); err != nil {
			return err
		}
		return fmt.Errorf("%s", message)
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly &&
		effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete &&
		object.Status.VirtualNetworkID != "" && object.Status.OwnershipVerified {
		account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
			return err
		}
		ownerComment, err := privateOwnerComment(ctx, r.Client, object, object.Spec.Comment)
		if err != nil {
			return err
		}
		api, err := privateNetworkClient(ctx, r.Client, account, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		remote, err := api.GetVirtualNetwork(ctx, object.Status.VirtualNetworkID)
		if err != nil {
			if !flarecloudflare.IsNotFound(err) {
				return err
			}
		} else if !remote.Deleted {
			if remote.IsDefault != object.Status.IsDefault {
				return privateInvalid("Conflict", "refusing to delete virtual network %q after its default flag changed", remote.ID)
			}
			if !privateCommentOwnedBy(remote.Comment, ownerComment) {
				return privateInvalid("Conflict", "refusing to delete virtual network %q without this object's ownership comment", remote.ID)
			}
			if object.Status.Name != "" && remote.Name != object.Status.Name {
				return privateInvalid("Conflict", "refusing to delete virtual network %q after its name changed from %q to %q", remote.ID, object.Status.Name, remote.Name)
			}
			if err = ignoreRemoteNotFound(api.DeleteVirtualNetwork(ctx, object.Status.VirtualNetworkID)); err != nil {
				return err
			}
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.VirtualNetworkFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *VirtualNetworkReconciler) patchCleanupBlocked(ctx context.Context, object *v1alpha1.VirtualNetwork, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		privateCondition(object.Generation, "CleanupBlocked", metav1.ConditionTrue, "Referenced", message),
		privateCondition(object.Generation, v1alpha1.PrivateNetworkConditionReady, metav1.ConditionFalse, "CleanupBlocked", message),
	)
	return r.Status().Patch(ctx, object, base)
}

func (r *VirtualNetworkReconciler) finishError(ctx context.Context, object *v1alpha1.VirtualNetwork, err error) (ctrl.Result, error) {
	patchErr := r.patchStatus(ctx, object, virtualNetworkFromStatus(object), object.Status.OwnershipVerified, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
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
	if patchErr := r.patchStatus(ctx, object, virtualNetworkFromStatus(object), object.Status.OwnershipVerified, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *VirtualNetworkReconciler) patchStatus(ctx context.Context, object *v1alpha1.VirtualNetwork, remote flarecloudflare.VirtualNetwork, owned bool, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	observeOnly := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly
	persistIdentity := remote.ID != "" && (status == metav1.ConditionTrue || owned || observeOnly)
	if persistIdentity {
		object.Status.VirtualNetworkID = remote.ID
		object.Status.Name = remote.Name
		object.Status.IsDefault = remote.IsDefault
		object.Status.Comment = remote.Comment
		object.Status.CreatedAt = privateMetaTime(remote.CreatedAt)
		object.Status.DeletedAt = privateMetaTimePointer(remote.DeletedAt)
		object.Status.OwnershipVerified = owned
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = privateConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func virtualNetworkFromStatus(object *v1alpha1.VirtualNetwork) flarecloudflare.VirtualNetwork {
	remote := flarecloudflare.VirtualNetwork{
		ID: object.Status.VirtualNetworkID, Name: object.Status.Name,
		IsDefault: object.Status.IsDefault, Comment: object.Status.Comment,
	}
	if object.Status.CreatedAt != nil {
		remote.CreatedAt = object.Status.CreatedAt.Time
	}
	if object.Status.DeletedAt != nil {
		deletedAt := object.Status.DeletedAt.Time
		remote.DeletedAt = &deletedAt
		remote.Deleted = true
	}
	return remote
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
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.VirtualNetwork{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworksForAccount)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworkPeers), builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworkForNetworkRoute)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.virtualNetworksForNamespace)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1})
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("virtual-network", r))
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
	if !ok {
		return nil
	}
	requests := make([]reconcile.Request, 0, 2)
	if route.Spec.VirtualNetworkRef != nil && route.Spec.VirtualNetworkRef.Name != "" {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.VirtualNetworkRef.Name}})
	}
	if route.Spec.IPLookup != nil && route.Spec.IPLookup.VirtualNetworkRef != nil && route.Spec.IPLookup.VirtualNetworkRef.Name != "" {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.IPLookup.VirtualNetworkRef.Name}
		if len(requests) == 0 || requests[0].NamespacedName != key {
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}
	}
	return requests
}

func (r *VirtualNetworkReconciler) virtualNetworksForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.VirtualNetworkList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return virtualNetworkRequests(list.Items)
}

func (r *VirtualNetworkReconciler) networkRouteReferences(ctx context.Context, object *v1alpha1.VirtualNetwork) (string, error) {
	var routes v1alpha1.NetworkRouteList
	if err := r.List(ctx, &routes, client.InNamespace(object.Namespace)); err != nil {
		return "", err
	}
	var blockers []string
	for i := range routes.Items {
		route := &routes.Items[i]
		if route.DeletionTimestamp.IsZero() && (referencesVirtualNetwork(route.Spec.VirtualNetworkRef, object.Name) ||
			(route.Spec.IPLookup != nil && referencesVirtualNetwork(route.Spec.IPLookup.VirtualNetworkRef, object.Name))) {
			blockers = append(blockers, client.ObjectKeyFromObject(route).String())
		}
	}
	if len(blockers) == 0 {
		return "", nil
	}
	slices.Sort(blockers)
	return blockers[0], nil
}

func referencesVirtualNetwork(reference *corev1.LocalObjectReference, name string) bool {
	return reference != nil && reference.Name == name
}

func virtualNetworkRequests(items []v1alpha1.VirtualNetwork) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for i := range items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}})
	}
	return requests
}
