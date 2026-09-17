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
	"strings"
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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
)

// HostnameRouteReconciler manages Cloudflare private hostname routes.
type HostnameRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewPrivateNetworkCloudflareClient
	OperatorNamespace   string
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=hostnameroutes;cloudflaretunnels;warpconnectors;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=hostnameroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=hostnameroutes/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one HostnameRoute with its Cloudflare private hostname route.
func (r *HostnameRouteReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.HostnameRoute)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.HostnameRouteFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.HostnameRouteFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add HostnameRoute finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	hostname, err := normalizedPrivateHostname(object.Spec.Hostname)
	if err != nil {
		return r.finishError(ctx, object, privateInvalid("Invalid", "%v", err))
	}
	account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if err = r.authorizeManagement(ctx, object, account, hostname); err != nil {
		return r.finishError(ctx, object, err)
	}
	tunnel, err := resolvePrivateTunnel(ctx, r.Client, account, object.Namespace, object.Spec.TunnelRef, object.Spec.AllowedNamespaces, authz.PrivateRouteHostname, object.Labels, hostname)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if err = r.checkOverlap(ctx, object, hostname); err != nil {
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

	input := flarecloudflare.HostnameRouteInput{
		Hostname: cloudflarePrivateHostname(hostname), TunnelID: tunnel.id,
		TunnelType: tunnel.tunnelType, Comment: ownerComment,
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "management policy ObserveOnly requires externalRef.routeId"))
		}
		remote, getErr := api.GetHostnameRoute(ctx, object.Spec.ExternalRef.RouteID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if conflict := validateObservedHostnameRoute(input, remote); conflict != "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, hostname, false, false, metav1.ConditionFalse, "Conflict", conflict)
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, hostname, false, true, metav1.ConditionTrue, "Observed", "Hostname route is observed without mutation")
	}
	remote, err := r.ensureManaged(ctx, api, object, input)
	if err != nil {
		if privateIsValidationError(err) && remote.ID != "" {
			owned := object.Status.OwnershipVerified || privateCommentOwnedBy(remote.Comment, input.Comment)
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, hostname, owned, false, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
		}
		if privateIsValidationError(err) {
			return r.finishError(ctx, object, err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	return ctrl.Result{}, r.patchStatus(ctx, object, remote, hostname, true, true, metav1.ConditionTrue, "Ready", "Hostname route is synchronized")
}

func (r *HostnameRouteReconciler) authorizeManagement(ctx context.Context, object *v1alpha1.HostnameRoute, account *v1alpha1.CloudflareAccount, hostname string) error {
	sourceNamespace, generated, err := r.validateGeneratedRoute(ctx, object, account, hostname)
	if err != nil {
		return err
	}
	if !generated {
		_, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true})
		return err
	}
	_, err = authorizePrivateNamespace(ctx, r.Client, account, sourceNamespace, authz.Request{
		Hostname:       hostname,
		Exposure:       v1alpha1.ExposurePrivate,
		PlatformObject: true,
		PrivateRoute:   &authz.PrivateRouteRequest{Kind: authz.PrivateRouteHostname, Labels: object.Labels},
	})
	return err
}

func (r *HostnameRouteReconciler) validateGeneratedRoute(ctx context.Context, object *v1alpha1.HostnameRoute, account *v1alpha1.CloudflareAccount, hostname string) (string, bool, error) {
	operatorNamespace := r.OperatorNamespace
	if operatorNamespace == "" {
		operatorNamespace = dataplane.DefaultOperatorNamespace
	}
	if object.Namespace != operatorNamespace || object.Labels[generatedPlatformObjectLabel] != "true" {
		return "", false, nil
	}
	sourceNamespace := object.Labels[generatedSourceNamespaceLabel]
	if sourceNamespace == "" {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute requires label %s", generatedSourceNamespaceLabel)
	}
	if effectiveTunnelReferenceKind(object.Spec.TunnelRef.Kind) != v1alpha1.TunnelReferenceKindCloudflareTunnel ||
		object.Spec.TunnelRef.Namespace != sourceNamespace || object.Spec.TunnelRef.Name == "" {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute tunnelRef must explicitly target its source CloudflareTunnel namespace")
	}
	tunnelKey := types.NamespacedName{Namespace: sourceNamespace, Name: object.Spec.TunnelRef.Name}
	tunnel := new(v1alpha1.CloudflareTunnel)
	if err := r.Get(ctx, tunnelKey, tunnel); err != nil {
		return "", true, privateInvalid("RefNotPermitted", "resolve generated HostnameRoute CloudflareTunnel %s: %v", tunnelKey, err)
	}
	if !tunnel.DeletionTimestamp.IsZero() || tunnel.Spec.AccountRef.Name != account.Name ||
		tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
		tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" ||
		tunnel.Status.GatewayUID == "" || !tunnel.Status.OwnershipVerified {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Tunnel is not an ownership-verified, UID-bound Gateway Tunnel for CloudflareAccount %q", account.Name)
	}
	gatewayKey := types.NamespacedName{Namespace: sourceNamespace, Name: tunnel.Status.GatewayRef.Name}
	gateway := new(gatewayv1.Gateway)
	if err := r.Get(ctx, gatewayKey, gateway); err != nil {
		return "", true, privateInvalid("RefNotPermitted", "resolve generated HostnameRoute source Gateway %s: %v", gatewayKey, err)
	}
	if gateway.GetDeletionTimestamp() != nil {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Gateway %s is deleting", gatewayKey)
	}
	if gateway.UID != tunnel.Status.GatewayUID {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Gateway UID does not match the Tunnel ownership checkpoint")
	}
	if object.Annotations[sourceGatewayUIDAnnotation] == "" || object.Annotations[sourceGatewayUIDAnnotation] != string(gateway.UID) {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Gateway UID proof is missing or stale")
	}
	tunnelName, explicit, supported := referencedTunnelName(gateway)
	if !supported {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Gateway uses an unsupported infrastructure reference")
	}
	if tunnelName == "" {
		tunnelName = gateway.Name
	}
	if tunnelName != tunnel.Name {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute source Gateway does not resolve to Tunnel %s", tunnelKey)
	}
	if !explicit && !metav1.IsControlledBy(tunnel, gateway) {
		return "", true, privateInvalid("RefNotPermitted", "implicit generated HostnameRoute Tunnel is not controlled by the current source Gateway UID")
	}
	listenerName := matchingPrivateListenerName(gateway, tunnel, object.Name, hostname)
	if listenerName == "" {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute does not match a current private Gateway listener")
	}
	if object.Spec.AccountRef.Name != account.Name ||
		effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged ||
		effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) != v1alpha1.DeletionPolicyDelete ||
		object.Spec.ExternalRef != nil || object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID ||
		object.Labels[generatedGatewayLabel] != sourceNamespace+"--"+tunnel.Name ||
		object.Spec.Comment != fmt.Sprintf("flareway private listener %s/%s/%s", sourceNamespace, tunnel.Name, listenerName) {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute metadata or lifecycle does not match its source listener")
	}
	if object.Spec.AllowedNamespaces.From != v1alpha1.AllowedNamespaceFromSelector ||
		object.Spec.AllowedNamespaces.Selector == nil ||
		len(object.Spec.AllowedNamespaces.Selector.MatchLabels) != 1 ||
		object.Spec.AllowedNamespaces.Selector.MatchLabels["kubernetes.io/metadata.name"] != sourceNamespace ||
		len(object.Spec.AllowedNamespaces.Selector.MatchExpressions) != 0 {
		return "", true, privateInvalid("RefNotPermitted", "generated HostnameRoute allowedNamespaces does not exactly select its source namespace")
	}
	return sourceNamespace, true, nil
}

func matchingPrivateListenerName(gateway *gatewayv1.Gateway, tunnel *v1alpha1.CloudflareTunnel, routeName, hostname string) string {
	for i := range gateway.Spec.Listeners {
		listener := &gateway.Spec.Listeners[i]
		if listener.Hostname == nil || string(*listener.Hostname) != hostname ||
			privateHostnameRouteName(tunnel.Namespace, tunnel.Name, string(listener.Name)) != routeName {
			continue
		}
		for j := range tunnel.Spec.Listeners {
			binding := &tunnel.Spec.Listeners[j]
			if binding.Name == listener.Name && binding.Exposure == v1alpha1.ExposurePrivate {
				return string(listener.Name)
			}
		}
	}
	return ""
}

func (r *HostnameRouteReconciler) ensureManaged(ctx context.Context, api flarecloudflare.HostnameRouteAPI, object *v1alpha1.HostnameRoute, input flarecloudflare.HostnameRouteInput) (flarecloudflare.HostnameRoute, error) {
	id := object.Status.RouteID
	var remote flarecloudflare.HostnameRoute
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RouteID == "" {
				return flarecloudflare.HostnameRoute{}, privateInvalid("Invalid", "adoption mode AdoptById requires externalRef.routeId")
			}
			id = object.Spec.ExternalRef.RouteID
			observed, err := api.GetHostnameRoute(ctx, id)
			if err != nil {
				return flarecloudflare.HostnameRoute{}, err
			}
			if conflict := validateObservedHostnameRoute(input, observed); conflict != "" {
				return observed, privateInvalid("Conflict", "%s", conflict)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return flarecloudflare.HostnameRoute{}, privateInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
		default:
			recovered, found, err := findOwnedHostnameRoute(ctx, api, input.Comment)
			if err != nil {
				return flarecloudflare.HostnameRoute{}, err
			}
			if found {
				id, remote = recovered.ID, recovered
				break
			}
			created, createErr := api.CreateHostnameRoute(ctx, input)
			if createErr != nil {
				return flarecloudflare.HostnameRoute{}, createErr
			}
			id, remote = created.ID, created
		}
	} else {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.HostnameRoute{}, privateInvalid("Conflict", "remote hostname route ID is not verified as owned or adopted")
		}
		observed, err := api.GetHostnameRoute(ctx, id)
		if err != nil {
			return flarecloudflare.HostnameRoute{}, err
		}
		if !privateCommentOwnedBy(observed.Comment, input.Comment) {
			return observed, privateInvalid("Conflict", "remote hostname route %q no longer carries this object's ownership comment", id)
		}
		remote = observed
	}
	if id == "" || remote.ID == "" {
		return remote, privateInvalid("Conflict", "the Cloudflare service returned a hostname route without an ID")
	}
	if remote.Deleted {
		return remote, privateInvalid("Conflict", "remote hostname route %q is deleted", id)
	}
	if conflict := validatePrivateTunnelType(input.TunnelType, remote.TunnelType, "hostname route", remote.ID); conflict != "" {
		return remote, privateInvalid("Conflict", "%s", conflict)
	}
	if !hostnameRouteNeedsUpdate(input, remote) {
		return remote, nil
	}
	return api.UpdateHostnameRoute(ctx, id, input)
}

func findOwnedHostnameRoute(ctx context.Context, api flarecloudflare.HostnameRouteAPI, comment string) (flarecloudflare.HostnameRoute, bool, error) {
	remotes, err := api.ListHostnameRoutes(ctx)
	if err != nil {
		return flarecloudflare.HostnameRoute{}, false, err
	}
	var found flarecloudflare.HostnameRoute
	for i := range remotes {
		if remotes[i].Deleted || !privateCommentOwnedBy(remotes[i].Comment, comment) {
			continue
		}
		if found.ID != "" {
			return flarecloudflare.HostnameRoute{}, false, privateInvalid("Conflict", "multiple remote hostname routes carry ownership comment %q", comment)
		}
		found = remotes[i]
	}
	return found, found.ID != "", nil
}

func validateObservedHostnameRoute(input flarecloudflare.HostnameRouteInput, remote flarecloudflare.HostnameRoute) string {
	if remote.Deleted {
		return fmt.Sprintf("remote hostname route %q is deleted", remote.ID)
	}
	if conflict := validatePrivateTunnelType(input.TunnelType, remote.TunnelType, "hostname route", remote.ID); conflict != "" {
		return conflict
	}
	if remote.Hostname != input.Hostname || remote.TunnelID != input.TunnelID {
		return fmt.Sprintf("remote hostname route target (%s, %s) does not match resolved target (%s, %s)", remote.Hostname, remote.TunnelID, input.Hostname, input.TunnelID)
	}
	return ""
}

func hostnameRouteNeedsUpdate(input flarecloudflare.HostnameRouteInput, remote flarecloudflare.HostnameRoute) bool {
	return remote.Hostname != input.Hostname || remote.TunnelID != input.TunnelID || remote.Comment != input.Comment
}

func (r *HostnameRouteReconciler) checkOverlap(ctx context.Context, object *v1alpha1.HostnameRoute, hostname string) error {
	var list v1alpha1.HostnameRouteList
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
			claimSource, claim := "applied", other.Status.Applied.Hostname
			if claim == "" {
				claimSource, claim = "observed", other.Status.Hostname
			}
			if claim == "" {
				return privateInvalid("Invalid", "HostnameRoute %s has no recorded remote hostname identity", otherKey)
			}
			claims := []string{claim}
			if claimSource == "observed" && !strings.HasPrefix(claim, "*.") {
				claims = append(claims, "*."+claim)
			}
			for _, candidate := range claims {
				otherHostname, err := normalizedPrivateHostname(candidate)
				if err != nil {
					return privateInvalid("Invalid", "HostnameRoute %s has invalid %s hostname %q: %v", otherKey, claimSource, candidate, err)
				}
				if privateHostnamesOverlap(hostname, otherHostname) {
					return privateInvalid("Invalid", "hostname %s overlaps %s HostnameRoute %s hostname %s", hostname, claimSource, otherKey, otherHostname)
				}
			}
			continue
		}
		if !other.DeletionTimestamp.IsZero() || object.Status.RouteID != "" {
			continue
		}
		otherHostname, err := normalizedPrivateHostname(other.Spec.Hostname)
		if err != nil || !privateHostnamesOverlap(hostname, otherHostname) {
			continue
		}
		if privateObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, thisKey) {
			return privateInvalid("Invalid", "hostname %s overlaps earlier unprogrammed HostnameRoute %s hostname %s", hostname, otherKey, otherHostname)
		}
	}
	return nil
}

func (r *HostnameRouteReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.HostnameRoute) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.HostnameRouteFinalizer) {
		return nil
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly &&
		effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete &&
		object.Status.RouteID != "" && object.Status.OwnershipVerified {
		account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		managementNamespace, namespaceErr := r.deletionManagementNamespace(object)
		if namespaceErr != nil {
			return namespaceErr
		}
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, managementNamespace, authz.Request{PlatformObject: true}); err != nil {
			return err
		}
		targetKey := namespacedReferenceKey(object.Namespace, object.Spec.TunnelRef)
		authorizedHostname := object.Status.Applied.Hostname
		if authorizedHostname == "" {
			authorizedHostname, err = normalizedPrivateHostname(object.Spec.Hostname)
			if err != nil {
				return err
			}
		}
		if _, err = authorizePrivateNamespace(ctx, r.Client, account, targetKey.Namespace, authz.Request{
			Hostname:     authorizedHostname,
			Exposure:     v1alpha1.ExposurePrivate,
			PrivateRoute: &authz.PrivateRouteRequest{Kind: authz.PrivateRouteHostname, Labels: object.Labels},
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
		remote, err := api.GetHostnameRoute(ctx, object.Status.RouteID)
		if err != nil {
			if !flarecloudflare.IsNotFound(err) {
				return err
			}
		} else if !remote.Deleted {
			if !privateCommentOwnedBy(remote.Comment, ownerComment) {
				return privateInvalid("Conflict", "refusing to delete hostname route %q without this object's ownership comment", remote.ID)
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
				return privateInvalid("Conflict", "refusing to delete hostname route after tunnelRef.kind changed from %q to %q", recordedType, privateTunnelRemoteType(expectedTunnelType))
			}
			var candidates []flarecloudflare.HostnameRouteInput
			if object.Status.Applied.Hostname != "" {
				candidates = append(candidates, flarecloudflare.HostnameRouteInput{
					Hostname: cloudflarePrivateHostname(object.Status.Applied.Hostname),
					TunnelID: object.Status.Applied.TunnelID, TunnelType: expectedTunnelType,
				})
			}
			if object.Status.Hostname != "" {
				candidates = append(candidates, flarecloudflare.HostnameRouteInput{
					Hostname: object.Status.Hostname,
					TunnelID: object.Status.TunnelID, TunnelType: expectedTunnelType,
				})
			}
			if len(candidates) == 0 {
				return privateInvalid("Conflict", "refusing to delete hostname route %q without a recorded remote identity", remote.ID)
			}
			matched := false
			var conflict string
			for _, candidate := range candidates {
				if conflict = validateObservedHostnameRoute(candidate, remote); conflict == "" {
					matched = true
					break
				}
			}
			if !matched {
				return privateInvalid("Conflict", "refusing to delete changed hostname route: %s", conflict)
			}
			if err = ignoreRemoteNotFound(api.DeleteHostnameRoute(ctx, object.Status.RouteID)); err != nil {
				return err
			}
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.HostnameRouteFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *HostnameRouteReconciler) deletionManagementNamespace(object *v1alpha1.HostnameRoute) (string, error) {
	operatorNamespace := r.OperatorNamespace
	if operatorNamespace == "" {
		operatorNamespace = dataplane.DefaultOperatorNamespace
	}
	if object.Namespace != operatorNamespace || object.Labels[generatedPlatformObjectLabel] != "true" {
		return object.Namespace, nil
	}
	sourceNamespace := object.Labels[generatedSourceNamespaceLabel]
	if !object.Status.OwnershipVerified || sourceNamespace == "" || object.Annotations[sourceGatewayUIDAnnotation] == "" {
		return "", privateInvalid("RefNotPermitted", "generated HostnameRoute deletion lacks verified source ownership")
	}
	return sourceNamespace, nil
}

func (r *HostnameRouteReconciler) finishError(ctx context.Context, object *v1alpha1.HostnameRoute, err error) (ctrl.Result, error) {
	patchErr := r.patchStatus(ctx, object, hostnameRouteFromStatus(object), object.Status.Applied.Hostname, object.Status.OwnershipVerified, false, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err))
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

func (r *HostnameRouteReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.HostnameRoute, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, hostnameRouteFromStatus(object), object.Status.Applied.Hostname, object.Status.OwnershipVerified, false, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *HostnameRouteReconciler) patchStatus(ctx context.Context, object *v1alpha1.HostnameRoute, remote flarecloudflare.HostnameRoute, hostname string, owned, applied bool, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	observeOnly := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly
	persistIdentity := remote.ID != "" && (status == metav1.ConditionTrue || owned || observeOnly)
	if persistIdentity {
		object.Status.RouteID = remote.ID
		object.Status.Hostname = remote.Hostname
		object.Status.TunnelID = remote.TunnelID
		object.Status.TunnelName = remote.TunnelName
		object.Status.TunnelType = privateTunnelRemoteType(remote.TunnelType)
		object.Status.Comment = remote.Comment
		object.Status.CreatedAt = privateMetaTime(remote.CreatedAt)
		object.Status.DeletedAt = privateMetaTimePointer(remote.DeletedAt)
		object.Status.OwnershipVerified = owned
	}
	if applied && remote.ID != "" {
		object.Status.Applied = v1alpha1.HostnameRouteAppliedStatus{
			Hostname: hostname, TunnelID: remote.TunnelID,
			TunnelType: privateTunnelRemoteType(remote.TunnelType), ObservedGeneration: object.Generation,
		}
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = privateConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func hostnameRouteFromStatus(object *v1alpha1.HostnameRoute) flarecloudflare.HostnameRoute {
	remote := flarecloudflare.HostnameRoute{
		ID: object.Status.RouteID, Hostname: object.Status.Hostname,
		TunnelID: object.Status.TunnelID, TunnelName: object.Status.TunnelName,
		TunnelType: flarecloudflare.NetworkTunnelType(object.Status.TunnelType),
		Comment:    object.Status.Comment,
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

func (r *HostnameRouteReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the HostnameRoute controller and dependency watches.
func (r *HostnameRouteReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.OperatorNamespace == "" {
		r.OperatorNamespace = dataplane.DefaultOperatorNamespace
	}
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.HostnameRoute{}, hostnameRouteAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.HostnameRoute).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index HostnameRoute accountRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.HostnameRoute{}, hostnameRouteTunnelIndex, func(object client.Object) []string {
		route := object.(*v1alpha1.HostnameRoute)
		return []string{namespacedReferenceKey(route.Namespace, route.Spec.TunnelRef).String()}
	}); err != nil {
		return fmt.Errorf("index HostnameRoute tunnelRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.HostnameRoute{}, hostnameRouteSourceNamespaceIndex, func(object client.Object) []string {
		namespace := object.GetLabels()[generatedSourceNamespaceLabel]
		if namespace == "" {
			return nil
		}
		return []string{namespace}
	}); err != nil {
		return fmt.Errorf("index HostnameRoute source namespace: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.HostnameRoute{}).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.hostnameRoutesForAccount)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.hostnameRoutesForTunnel)).
		Watches(&v1alpha1.WARPConnector{}, handler.EnqueueRequestsFromMapFunc(r.hostnameRoutesForTunnel)).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.hostnameRoutesForGateway)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.hostnameRoutePeers)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allHostnameRoutes)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(observedReconciler("hostname-route", r))
}

func (r *HostnameRouteReconciler) hostnameRoutesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listHostnameRouteRequests(ctx, client.MatchingFields{hostnameRouteAccountIndex: object.GetName()})
}

func (r *HostnameRouteReconciler) hostnameRoutesForTunnel(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listHostnameRouteRequests(ctx, client.MatchingFields{hostnameRouteTunnelIndex: client.ObjectKeyFromObject(object).String()})
}

func (r *HostnameRouteReconciler) hostnameRoutesForGateway(ctx context.Context, object client.Object) []reconcile.Request {
	if object.GetNamespace() == "" {
		return nil
	}
	return r.listHostnameRouteRequests(ctx, client.MatchingFields{hostnameRouteSourceNamespaceIndex: object.GetNamespace()})
}

func (r *HostnameRouteReconciler) hostnameRoutePeers(ctx context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*v1alpha1.HostnameRoute)
	if !ok {
		return nil
	}
	return r.listHostnameRouteRequests(ctx, client.MatchingFields{hostnameRouteAccountIndex: route.Spec.AccountRef.Name})
}

func (r *HostnameRouteReconciler) allHostnameRoutes(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.listHostnameRouteRequests(ctx)
}

func (r *HostnameRouteReconciler) listHostnameRouteRequests(ctx context.Context, options ...client.ListOption) []reconcile.Request {
	var list v1alpha1.HostnameRouteList
	if err := r.List(ctx, &list, options...); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}
