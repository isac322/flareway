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
	"errors"
	"fmt"
	"net/netip"
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

// NetworkRouteReconciler manages Cloudflare private CIDR routes.
type NetworkRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewPrivateNetworkCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes;virtualnetworks;cloudflaretunnels;warpconnectors;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
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
	virtualNetworkID := ""
	if object.Spec.VirtualNetworkRef != nil {
		virtualNetwork, resolveErr := resolvePrivateVirtualNetwork(ctx, r.Client, account, object.Namespace, object.Spec.VirtualNetworkRef.Name)
		if resolveErr != nil {
			return r.finishError(ctx, object, resolveErr)
		}
		virtualNetworkID = virtualNetwork.Status.VirtualNetworkID
	}
	if err = r.checkOverlap(ctx, object, prefix, virtualNetworkID); err != nil {
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

	input := flarecloudflare.NetworkRouteInput{
		Network: prefix.String(), TunnelID: tunnel.id, TunnelType: tunnel.tunnelType,
		VirtualNetworkID: virtualNetworkID, Comment: ownerComment,
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "management policy ObserveOnly requires externalRef.routeId"))
		}
		remote, getErr := api.GetNetworkRoute(ctx, object.Spec.ExternalRef.RouteID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if conflict := validateObservedNetworkRoute(input, remote); conflict != "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, false, metav1.ConditionFalse, "Conflict", conflict)
		}
		lookup, lookupErr := r.resolveNetworkRouteIPLookup(ctx, api, object, account)
		if lookupErr != nil {
			return r.finishIPLookupError(ctx, object, remote, false, true, lookupErr)
		}
		return ctrl.Result{}, r.patchStatusWithIPLookup(ctx, object, remote, lookup, false, true, metav1.ConditionTrue, "Observed", "Network route is observed without mutation")
	}
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeTraffic, gateInput{
		Kind: "NetworkRoute", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.RouteID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}
	remote, err := r.ensureManaged(ctx, api, object, input)
	if err != nil {
		if privateIsValidationError(err) && remote.ID != "" {
			owned := object.Status.OwnershipVerified || privateCommentOwnedBy(remote.Comment, input.Comment)
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, owned, false, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
		}
		if privateIsValidationError(err) {
			return r.finishError(ctx, object, err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	lookup, lookupErr := r.resolveNetworkRouteIPLookup(ctx, api, object, account)
	if lookupErr != nil {
		return r.finishIPLookupError(ctx, object, remote, true, true, lookupErr)
	}
	if err := r.patchStatusWithIPLookup(ctx, object, remote, lookup, true, true, metav1.ConditionTrue, "Ready", "Network route is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "NetworkRoute", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeTraffic)}, nil
}

func (r *NetworkRouteReconciler) ensureManaged(ctx context.Context, api flarecloudflare.NetworkRouteAPI, object *v1alpha1.NetworkRoute, input flarecloudflare.NetworkRouteInput) (flarecloudflare.NetworkRoute, error) {
	id := object.Status.RouteID
	var remote flarecloudflare.NetworkRoute
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
				return flarecloudflare.NetworkRoute{}, privateInvalid("Invalid", "adoption mode AdoptById requires externalRef.routeId")
			}
			id = object.Spec.ExternalRef.RouteID
			observed, err := api.GetNetworkRoute(ctx, id)
			if err != nil {
				return flarecloudflare.NetworkRoute{}, err
			}
			if conflict := validateAdoptedNetworkRoute(input, observed); conflict != "" {
				return observed, privateInvalid("Conflict", "%s", conflict)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
		default:
			recovered, found, err := findOwnedNetworkRoute(ctx, api, input.Comment)
			if err != nil {
				return flarecloudflare.NetworkRoute{}, err
			}
			if found {
				id, remote = recovered.ID, recovered
				break
			}
			created, createErr := api.CreateNetworkRoute(ctx, input)
			if createErr != nil {
				return flarecloudflare.NetworkRoute{}, createErr
			}
			id, remote = created.ID, created
		}
	} else {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.NetworkRoute{}, privateInvalid("Conflict", "remote network route ID is not verified as owned or adopted")
		}
		observed, err := api.GetNetworkRoute(ctx, id)
		if err != nil {
			return flarecloudflare.NetworkRoute{}, err
		}
		if !privateCommentOwnedBy(observed.Comment, input.Comment) {
			return observed, privateInvalid("Conflict", "remote network route %q no longer carries this object's ownership comment", id)
		}
		remote = observed
	}
	if id == "" || remote.ID == "" {
		return remote, privateInvalid("Conflict", "the Cloudflare service returned a network route without an ID")
	}
	if remote.Deleted {
		return remote, privateInvalid("Conflict", "remote network route %q is deleted", id)
	}
	if conflict := validatePrivateTunnelType(input.TunnelType, remote.TunnelType, "network route", remote.ID); conflict != "" {
		return remote, privateInvalid("Conflict", "%s", conflict)
	}
	if !networkRouteNeedsUpdate(input, remote) {
		return remote, nil
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
	if conflict := validatePrivateTunnelType(input.TunnelType, remote.TunnelType, "network route", remote.ID); conflict != "" {
		return conflict
	}
	if remote.Network != input.Network || remote.TunnelID != input.TunnelID ||
		input.VirtualNetworkID != "" && remote.VirtualNetworkID != input.VirtualNetworkID {
		return fmt.Sprintf("remote network route target (%s, %s, %s) does not match resolved target (%s, %s, %s)", remote.Network, remote.TunnelID, remote.VirtualNetworkID, input.Network, input.TunnelID, input.VirtualNetworkID)
	}
	return ""
}

func validateAdoptedNetworkRoute(input flarecloudflare.NetworkRouteInput, remote flarecloudflare.NetworkRoute) string {
	return validateObservedNetworkRoute(input, remote)
}

func networkRouteNeedsUpdate(input flarecloudflare.NetworkRouteInput, remote flarecloudflare.NetworkRoute) bool {
	return remote.Network != input.Network ||
		remote.TunnelID != input.TunnelID ||
		input.VirtualNetworkID != "" && remote.VirtualNetworkID != input.VirtualNetworkID ||
		remote.Comment != input.Comment
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
			claimSource, claimNetwork, claimVirtualNetworkID := "applied", applied.Network, applied.VirtualNetworkID
			if claimNetwork == "" {
				claimSource, claimNetwork, claimVirtualNetworkID = "observed", other.Status.Network, other.Status.VirtualNetworkID
			}
			if claimNetwork == "" {
				return privateInvalid("Invalid", "NetworkRoute %s has no recorded remote network identity", otherKey)
			}
			otherPrefix, err := parseMaskedPrefix(claimNetwork)
			if err != nil {
				return privateInvalid("Invalid", "NetworkRoute %s has invalid %s network %q: %v", otherKey, claimSource, claimNetwork, err)
			}
			if !prefixesOverlap(prefix, otherPrefix) {
				continue
			}
			if other.Spec.VirtualNetworkRef != nil && claimVirtualNetworkID == "" {
				return privateInvalid("Invalid", "NetworkRoute %s has an incomplete %s claim", otherKey, claimSource)
			}
			sameVirtualNetwork := claimVirtualNetworkID == virtualNetworkID
			if virtualNetworkID == "" && object.Spec.VirtualNetworkRef == nil && other.Spec.VirtualNetworkRef == nil {
				sameVirtualNetwork = claimSource == "observed" || applied.ObservedGeneration == other.Generation
			}
			if sameVirtualNetwork {
				return privateInvalid("Invalid", "network %s overlaps %s NetworkRoute %s network %s in the same virtual network", prefix, claimSource, otherKey, otherPrefix)
			}
			continue
		}
		if !other.DeletionTimestamp.IsZero() || object.Status.RouteID != "" {
			continue
		}
		if privateVirtualNetworkReferenceName(other.Spec.VirtualNetworkRef) != privateVirtualNetworkReferenceName(object.Spec.VirtualNetworkRef) {
			continue
		}
		if other.Spec.VirtualNetworkRef != nil && other.Namespace != object.Namespace {
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
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly &&
		effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete &&
		object.Status.RouteID != "" && object.Status.OwnershipVerified {
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
		ownerComment, err := privateOwnerComment(ctx, r.Client, object, object.Spec.Comment)
		if err != nil {
			return err
		}
		api, err := privateNetworkClient(ctx, r.Client, account, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		remote, err := api.GetNetworkRoute(ctx, object.Status.RouteID)
		if err != nil {
			if !flarecloudflare.IsNotFound(err) {
				return err
			}
		} else if !remote.Deleted {
			if !privateCommentOwnedBy(remote.Comment, ownerComment) {
				return privateInvalid("Conflict", "refusing to delete network route %q without this object's ownership comment", remote.ID)
			}
			expectedTunnelType, typeErr := privateTunnelTypeForReference(object.Spec.TunnelRef.Kind)
			if typeErr != nil {
				return typeErr
			}
			recordedType := object.Status.Applied.TunnelType
			if recordedType == "" {
				recordedType = object.Status.TunnelType
			}
			if recordedType != "" && recordedType != privateTunnelRemoteType(expectedTunnelType) {
				return privateInvalid("Conflict", "refusing to delete network route after tunnelRef.kind changed from %q to %q", recordedType, privateTunnelRemoteType(expectedTunnelType))
			}
			var candidates []flarecloudflare.NetworkRouteInput
			if object.Status.Applied.Network != "" {
				candidates = append(candidates, flarecloudflare.NetworkRouteInput{
					Network: object.Status.Applied.Network, TunnelID: object.Status.Applied.TunnelID,
					TunnelType: expectedTunnelType, VirtualNetworkID: object.Status.Applied.VirtualNetworkID,
				})
			}
			if object.Status.Network != "" {
				candidates = append(candidates, flarecloudflare.NetworkRouteInput{
					Network: object.Status.Network, TunnelID: object.Status.TunnelID,
					TunnelType: expectedTunnelType, VirtualNetworkID: object.Status.VirtualNetworkID,
				})
			}
			if len(candidates) == 0 {
				return privateInvalid("Conflict", "refusing to delete network route %q without a recorded remote identity", remote.ID)
			}
			matched := false
			var conflict string
			for _, candidate := range candidates {
				if conflict = validateObservedNetworkRoute(candidate, remote); conflict == "" {
					matched = true
					break
				}
			}
			if !matched {
				return privateInvalid("Conflict", "refusing to delete changed network route: %s", conflict)
			}
			if err = ignoreRemoteNotFound(api.DeleteNetworkRoute(ctx, object.Status.RouteID)); err != nil {
				return err
			}
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.NetworkRouteFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *NetworkRouteReconciler) resolveNetworkRouteIPLookup(ctx context.Context, api flarecloudflare.NetworkRouteIPAPI, object *v1alpha1.NetworkRoute, account *v1alpha1.CloudflareAccount) (*v1alpha1.NetworkRouteIPLookupStatus, error) {
	if object.Spec.IPLookup == nil {
		return nil, nil
	}
	ip, err := netip.ParseAddr(object.Spec.IPLookup.IP)
	if err != nil {
		return nil, privateInvalid("Invalid", "ipLookup.ip %q is not a valid IP address: %v", object.Spec.IPLookup.IP, err)
	}
	virtualNetworkID := ""
	if object.Spec.IPLookup.VirtualNetworkRef != nil {
		virtualNetwork, resolveErr := resolvePrivateVirtualNetwork(ctx, r.Client, account, object.Namespace, object.Spec.IPLookup.VirtualNetworkRef.Name)
		if resolveErr != nil {
			return nil, resolveErr
		}
		virtualNetworkID = virtualNetwork.Status.VirtualNetworkID
	}
	var fallback *bool
	if object.Spec.IPLookup.DefaultVirtualNetworkFallback != nil {
		value := *object.Spec.IPLookup.DefaultVirtualNetworkFallback
		fallback = &value
	}
	remote, err := api.LookupNetworkRoute(ctx, flarecloudflare.NetworkRouteLookupInput{
		IP: ip.String(), VirtualNetworkID: virtualNetworkID, DefaultVirtualNetworkFallback: fallback,
	})
	if err != nil {
		return nil, err
	}
	if remote.ID == "" {
		return nil, errors.New("the IP lookup returned a network route without an ID")
	}
	if remote.Deleted {
		return nil, privateInvalid("Conflict", "the IP lookup returned deleted network route %q", remote.ID)
	}
	tunnelType := privateTunnelRemoteType(remote.TunnelType)
	if remote.TunnelType != "" && tunnelType == "" {
		return nil, privateInvalid("Conflict", "the IP lookup returned network route %q with unsupported tunnel type %q", remote.ID, remote.TunnelType)
	}
	return &v1alpha1.NetworkRouteIPLookupStatus{
		IP: ip.String(), VirtualNetworkID: virtualNetworkID, DefaultVirtualNetworkFallback: fallback,
		Result: &v1alpha1.NetworkRouteIPLookupResultStatus{
			RouteID: remote.ID, Network: remote.Network, TunnelID: remote.TunnelID,
			TunnelName: remote.TunnelName, TunnelType: tunnelType,
			VirtualNetworkID: remote.VirtualNetworkID, VirtualNetworkName: remote.VirtualNetworkName,
			Comment: remote.Comment, CreatedAt: privateMetaTime(remote.CreatedAt), DeletedAt: privateMetaTimePointer(remote.DeletedAt),
		},
		ObservedGeneration: object.Generation,
	}, nil
}

func (r *NetworkRouteReconciler) finishIPLookupError(ctx context.Context, object *v1alpha1.NetworkRoute, remote flarecloudflare.NetworkRoute, owned, applied bool, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, remote, owned, applied, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
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
func (r *NetworkRouteReconciler) finishError(ctx context.Context, object *v1alpha1.NetworkRoute, err error) (ctrl.Result, error) {
	patchErr := r.patchStatus(ctx, object, networkRouteFromStatus(object), object.Status.OwnershipVerified, false, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
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
	if patchErr := r.patchStatus(ctx, object, networkRouteFromStatus(object), object.Status.OwnershipVerified, false, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *NetworkRouteReconciler) patchStatus(ctx context.Context, object *v1alpha1.NetworkRoute, remote flarecloudflare.NetworkRoute, owned, applied bool, status metav1.ConditionStatus, reason, message string) error {
	return r.patchStatusInternal(ctx, object, remote, object.Status.IPLookup, false, owned, applied, status, reason, message)
}

func (r *NetworkRouteReconciler) patchStatusWithIPLookup(ctx context.Context, object *v1alpha1.NetworkRoute, remote flarecloudflare.NetworkRoute, lookup *v1alpha1.NetworkRouteIPLookupStatus, owned, applied bool, status metav1.ConditionStatus, reason, message string) error {
	return r.patchStatusInternal(ctx, object, remote, lookup, true, owned, applied, status, reason, message)
}

func (r *NetworkRouteReconciler) patchStatusInternal(ctx context.Context, object *v1alpha1.NetworkRoute, remote flarecloudflare.NetworkRoute, lookup *v1alpha1.NetworkRouteIPLookupStatus, updateLookup, owned, applied bool, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	observeOnly := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly
	persistIdentity := remote.ID != "" && (status == metav1.ConditionTrue || owned || observeOnly)
	if persistIdentity {
		object.Status.RouteID = remote.ID
		object.Status.Network = remote.Network
		object.Status.TunnelID = remote.TunnelID
		object.Status.TunnelName = remote.TunnelName
		object.Status.TunnelType = privateTunnelRemoteType(remote.TunnelType)
		object.Status.VirtualNetworkID = remote.VirtualNetworkID
		object.Status.VirtualNetworkName = remote.VirtualNetworkName
		object.Status.Comment = remote.Comment
		object.Status.CreatedAt = privateMetaTime(remote.CreatedAt)
		object.Status.DeletedAt = privateMetaTimePointer(remote.DeletedAt)
		object.Status.OwnershipVerified = owned
	}
	if applied && remote.ID != "" {
		object.Status.Applied = v1alpha1.NetworkRouteAppliedStatus{
			Network: remote.Network, TunnelID: remote.TunnelID,
			TunnelType: privateTunnelRemoteType(remote.TunnelType), VirtualNetworkID: remote.VirtualNetworkID,
			ObservedGeneration: object.Generation,
		}
	}
	if updateLookup {
		object.Status.IPLookup = lookup
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = privateConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func networkRouteFromStatus(object *v1alpha1.NetworkRoute) flarecloudflare.NetworkRoute {
	remote := flarecloudflare.NetworkRoute{
		ID: object.Status.RouteID, Network: object.Status.Network, TunnelID: object.Status.TunnelID,
		TunnelName: object.Status.TunnelName, TunnelType: flarecloudflare.NetworkTunnelType(object.Status.TunnelType),
		VirtualNetworkID: object.Status.VirtualNetworkID, VirtualNetworkName: object.Status.VirtualNetworkName,
		Comment: object.Status.Comment,
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
		keys := make([]string, 0, 2)
		if route.Spec.VirtualNetworkRef != nil {
			keys = append(keys, types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.VirtualNetworkRef.Name}.String())
		}
		if route.Spec.IPLookup != nil && route.Spec.IPLookup.VirtualNetworkRef != nil {
			lookupKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Spec.IPLookup.VirtualNetworkRef.Name}.String()
			if len(keys) == 0 || keys[0] != lookupKey {
				keys = append(keys, lookupKey)
			}
		}
		return keys
	}); err != nil {
		return fmt.Errorf("index NetworkRoute virtual network references: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.NetworkRoute{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForAccount)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForTunnel)).
		Watches(&v1alpha1.WARPConnector{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForTunnel)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutesForVirtualNetwork)).
		// Peer status is an overlap-check input; filtering status-only updates would strand routes rejected as Invalid.
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.networkRoutePeers)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allNetworkRoutes)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1})
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("network-route", r))
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
