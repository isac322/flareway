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
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
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

// NetworkRouteReconciler manages Cloudflare private CIDR routes.
type NetworkRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewPrivateNetworkCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes;virtualnetworks;cloudflaretunnels;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one NetworkRoute with its Cloudflare private network route.
func (r *NetworkRouteReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.NetworkRoute)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.NetworkRouteFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.NetworkRouteFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add NetworkRoute finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	prefix, err := parseMaskedPrefix(object.Spec.Network)
	if err != nil {
		return r.finishError(ctx, object, privateInvalid("Invalid", "%v", err))
	}
	account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
		return r.finishError(ctx, object, err)
	}
	tunnel, err := resolvePrivateTunnel(ctx, r.Client, account, object.Namespace, object.Spec.TunnelRef, object.Spec.AllowedNamespaces, authz.PrivateRouteNetwork, object.Labels, "")
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	virtualNetwork, err := resolvePrivateVirtualNetwork(ctx, r.Client, account, object.Namespace, object.Spec.VirtualNetworkRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if err = r.checkOverlap(ctx, object, prefix, virtualNetwork.Status.VirtualNetworkID); err != nil {
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

	input := flarecloudflare.NetworkRouteInput{Network: prefix.String(), TunnelID: tunnel.id, VirtualNetworkID: virtualNetwork.Status.VirtualNetworkID, Comment: ownerComment}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "ObserveOnly requires externalRef.routeId"))
		}
		remote, getErr := api.GetNetworkRoute(ctx, object.Spec.ExternalRef.RouteID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if conflict := validateObservedNetworkRoute(input, remote); conflict != "" {
			return r.finishError(ctx, object, privateInvalid("Conflict", "%s", conflict))
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, metav1.ConditionTrue, "Observed", "Network route is observed without mutation")
	}
	remote, err := r.ensureManaged(ctx, api, object, input)
	if err != nil {
		if privateIsValidationError(err) {
			return r.finishError(ctx, object, err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, remote, true, metav1.ConditionTrue, "Ready", "Network route is synchronized")
}

func (r *NetworkRouteReconciler) ensureManaged(ctx context.Context, api flarecloudflare.NetworkRouteAPI, object *v1alpha1.NetworkRoute, input flarecloudflare.NetworkRouteInput) (flarecloudflare.NetworkRoute, error) {
	id := object.Status.RouteID
	var remote flarecloudflare.NetworkRoute
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
				return flarecloudflare.NetworkRoute{}, privateInvalid("Invalid", "AdoptById requires externalRef.routeId")
			}
			id = object.Spec.ExternalRef.RouteID
			observed, err := api.GetNetworkRoute(ctx, id)
			if err != nil {
				return flarecloudflare.NetworkRoute{}, err
			}
			if conflict := validateAdoptedNetworkRoute(input, observed); conflict != "" {
				return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "%s", conflict)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "Managed externalRef requires adoption.mode AdoptById")
		default:
			recovered, found, err := findOwnedNetworkRoute(ctx, api, input.Comment)
			if err != nil {
				return flarecloudflare.NetworkRoute{}, err
			}
			if found {
				id, remote = recovered.ID, recovered
			} else {
				return api.CreateNetworkRoute(ctx, input)
			}
		}
	} else {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "remote network route ID is not verified as owned or adopted")
		}
		observed, err := api.GetNetworkRoute(ctx, id)
		if err != nil {
			return flarecloudflare.NetworkRoute{}, err
		}
		remote = observed
	}
	if remote.Deleted {
		return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "remote network route %q is deleted", id)
	}
	return api.UpdateNetworkRoute(ctx, id, input)
}

func findOwnedNetworkRoute(ctx context.Context, api flarecloudflare.NetworkRouteAPI, comment string) (flarecloudflare.NetworkRoute, bool, error) {
	remotes, err := api.ListNetworkRoutes(ctx)
	if err != nil {
		return flarecloudflare.NetworkRoute{}, false, err
	}
	var found flarecloudflare.NetworkRoute
	for i := range remotes {
		if remotes[i].Deleted || !privateCommentOwnedBy(remotes[i].Comment, comment) {
			continue
		}
		if found.ID != "" {
			return flarecloudflare.NetworkRoute{}, false, privateInvalid("Conflict", "multiple remote network routes carry ownership comment %q", comment)
		}
		found = remotes[i]
	}
	return found, found.ID != "", nil
}

func validateObservedNetworkRoute(input flarecloudflare.NetworkRouteInput, remote flarecloudflare.NetworkRoute) string {
	if remote.Deleted {
		return fmt.Sprintf("remote network route %q is deleted", remote.ID)
	}
	if remote.Network != input.Network || remote.TunnelID != input.TunnelID || remote.VirtualNetworkID != input.VirtualNetworkID {
		return fmt.Sprintf("remote network route target (%s, %s, %s) does not match resolved target (%s, %s, %s)", remote.Network, remote.TunnelID, remote.VirtualNetworkID, input.Network, input.TunnelID, input.VirtualNetworkID)
	}
	return ""
}

func validateAdoptedNetworkRoute(input flarecloudflare.NetworkRouteInput, remote flarecloudflare.NetworkRoute) string {
	return validateObservedNetworkRoute(input, remote)
}

func (r *NetworkRouteReconciler) checkOverlap(ctx context.Context, object *v1alpha1.NetworkRoute, prefix netip.Prefix, virtualNetworkID string) error {
	var list v1alpha1.NetworkRouteList
	if err := r.List(ctx, &list); err != nil {
		return err
	}
	thisKey := client.ObjectKeyFromObject(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || other.Spec.AccountRef.Name != object.Spec.AccountRef.Name {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if other.Status.RouteID != "" {
			applied := other.Status.Applied
			if applied.Network == "" || applied.VirtualNetworkID == "" {
				return privateInvalid("Invalid", "applied NetworkRoute %s has an incomplete status.applied claim", otherKey)
			}
			otherPrefix, err := parseMaskedPrefix(applied.Network)
			if err != nil {
				return privateInvalid("Invalid", "applied NetworkRoute %s has invalid status.applied.network: %v", otherKey, err)
			}
			if applied.VirtualNetworkID == virtualNetworkID && prefixesOverlap(prefix, otherPrefix) {
				return privateInvalid("Invalid", "network %s overlaps applied NetworkRoute %s network %s in the same virtual network", prefix, otherKey, otherPrefix)
			}
			continue
		}
		if !other.DeletionTimestamp.IsZero() || object.Status.RouteID != "" {
			continue
		}
		if other.Namespace != object.Namespace || other.Spec.VirtualNetworkRef.Name != object.Spec.VirtualNetworkRef.Name {
			continue
		}
		otherPrefix, err := parseMaskedPrefix(other.Spec.Network)
		if err != nil || !prefixesOverlap(prefix, otherPrefix) {
			continue
		}
		if privateObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, thisKey) {
			return privateInvalid("Invalid", "network %s overlaps earlier unprogrammed NetworkRoute %s network %s in the same virtual network", prefix, otherKey, otherPrefix)
		}
	}
	return nil
}

func (r *NetworkRouteReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.NetworkRoute) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.NetworkRouteFinalizer) {
		return nil
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly && effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.RouteID != "" && object.Status.OwnershipVerified {
		account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
			return err
		}
		targetKey := namespacedReferenceKey(object.Namespace, object.Spec.TunnelRef)
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, targetKey.Namespace, authz.Request{
			Exposure:     v1alpha1.ExposurePrivate,
			PrivateRoute: &authz.PrivateRouteRequest{Kind: authz.PrivateRouteNetwork, Labels: object.Labels},
		}); err != nil {
			return err
		}
		api, err := privateNetworkClient(ctx, r.Client, account, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteNetworkRoute(ctx, object.Status.RouteID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.NetworkRouteFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *NetworkRouteReconciler) finishError(ctx context.Context, object *v1alpha1.NetworkRoute, err error) (ctrl.Result, error) {
	applied := object.Status.Applied
	patchErr := r.patchStatus(ctx, object, flarecloudflare.NetworkRoute{ID: object.Status.RouteID, Network: applied.Network, TunnelID: applied.TunnelID, VirtualNetworkID: applied.VirtualNetworkID, Comment: object.Status.Comment}, object.Status.OwnershipVerified, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
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

func (r *NetworkRouteReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.NetworkRoute, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.NetworkRoute{ID: object.Status.RouteID}, object.Status.OwnershipVerified, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *NetworkRouteReconciler) patchStatus(ctx context.Context, object *v1alpha1.NetworkRoute, remote flarecloudflare.NetworkRoute, owned bool, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if remote.ID != "" {
		object.Status.RouteID = remote.ID
	}
	if status == metav1.ConditionTrue {
		object.Status.Applied = v1alpha1.NetworkRouteAppliedStatus{
			Network: remote.Network, TunnelID: remote.TunnelID, VirtualNetworkID: remote.VirtualNetworkID,
			ObservedGeneration: object.Generation,
		}
		object.Status.Comment = remote.Comment
		object.Status.OwnershipVerified = owned
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = privateConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *NetworkRouteReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the NetworkRoute controller and dependency watches.
func (r *NetworkRouteReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.NetworkRoute{}, networkRouteAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.NetworkRoute).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index NetworkRoute accountRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.NetworkRoute{}, networkRouteTunnelIndex, func(object client.Object) []string {
		route := object.(*v1alpha1.NetworkRoute)
		return []string{namespacedReferenceKey(route.Namespace, route.Spec.TunnelRef).String()}
	}); err != nil {
		return fmt.Errorf("index NetworkRoute tunnelRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.NetworkRoute{}, networkRouteVNetIndex, func(object client.Object) []string {
		route := object.(*v1alpha1.NetworkRoute)
		return []string{types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.VirtualNetworkRef.Name}.String()}
	}); err != nil {
		return fmt.Errorf("index NetworkRoute virtualNetworkRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.NetworkRoute{}).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForAccount)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForTunnel)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForVirtualNetwork)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutePeers)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allNetworkRoutes)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(observedReconciler("network-route", r))
}

func (r *NetworkRouteReconciler) networkRoutesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listNetworkRouteRequests(ctx, client.MatchingFields{networkRouteAccountIndex: object.GetName()})
}

func (r *NetworkRouteReconciler) networkRoutesForTunnel(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listNetworkRouteRequests(ctx, client.MatchingFields{networkRouteTunnelIndex: client.ObjectKeyFromObject(object).String()})
}

func (r *NetworkRouteReconciler) networkRoutesForVirtualNetwork(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listNetworkRouteRequests(ctx, client.MatchingFields{networkRouteVNetIndex: client.ObjectKeyFromObject(object).String()})
}

func (r *NetworkRouteReconciler) networkRoutePeers(ctx context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*v1alpha1.NetworkRoute)
	if !ok {
		return nil
	}
	return r.listNetworkRouteRequests(ctx, client.MatchingFields{networkRouteAccountIndex: route.Spec.AccountRef.Name})
}

func (r *NetworkRouteReconciler) allNetworkRoutes(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.listNetworkRouteRequests(ctx)
}

func (r *NetworkRouteReconciler) listNetworkRouteRequests(ctx context.Context, options ...client.ListOption) []reconcile.Request {
	var list v1alpha1.NetworkRouteList
	if err := r.List(ctx, &list, options...); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}
