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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

const (
	accessInfrastructureTargetAccountIndex = accessAccountIndex + ".infrastructureTarget"
	accessInfrastructureTargetVNetIndex    = ".spec.ip.virtualNetworkRef.infrastructureTarget"
)

// AccessInfrastructureTargetReconciler manages Cloudflare Access infrastructure targets.
type AccessInfrastructureTargetReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessinfrastructuretargets;virtualnetworks;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessinfrastructuretargets,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessinfrastructuretargets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessinfrastructuretargets/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessInfrastructureTarget with its Cloudflare target.
func (r *AccessInfrastructureTargetReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessInfrastructureTarget)
	if err := r.reader().Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "AccessInfrastructureTarget", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessInfrastructureTargetFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessInfrastructureTargetFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add AccessInfrastructureTarget finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	api, account, err := accessClientForAccount(ctx, r.readClient(), object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		return r.finishError(ctx, object, privateErrorReason(err), err)
	}
	input, err := r.resolveInput(ctx, object, account)
	if err != nil {
		return r.finishError(ctx, object, infrastructureTargetErrorReason(err), err)
	}

	if effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.TargetID == "" {
			return r.finishError(ctx, object, "Invalid", errors.New("management policy ObserveOnly requires externalRef.targetId"))
		}
		remote, getErr := api.GetAccessInfrastructureTarget(ctx, object.Spec.ExternalRef.TargetID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if expected := object.Spec.Adoption.Expect.Hostname; expected != "" && !strings.EqualFold(remote.Hostname, expected) {
			return r.finishObserved(ctx, object, remote, nil, metav1.ConditionFalse, "Conflict", fmt.Sprintf("remote target hostname %q does not match expected %q", remote.Hostname, expected))
		}
		wouldApply := infrastructureTargetWouldApply(input, remote)
		if wouldApply != nil {
			return r.finishObserved(ctx, object, remote, wouldApply, metav1.ConditionFalse, "Drifted", "Infrastructure target differs from the desired state")
		}
		return r.finishObserved(ctx, object, remote, nil, metav1.ConditionTrue, "Observed", "Infrastructure target is observed without mutation")
	}

	// T1 gate: the managed path below reads the remote target before any
	// write. ObserveOnly above stays ungated (safety condition 9). Adoption
	// reads inside ensureManaged are T0 by construction: the gate only
	// opens once status.targetId is bound and the applied hash matches.
	clusterID, err := flarecloudflare.ClusterID(ctx, r.readClient())
	if err != nil {
		return r.finishError(ctx, object, "Pending", err)
	}
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "AccessInfrastructureTarget", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.TargetID,
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
		if infrastructureTargetIsValidationError(err) {
			return r.finishError(ctx, object, infrastructureTargetErrorReason(err), err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	if err := r.patchStatus(ctx, object, remote, true, nil, metav1.ConditionTrue, metav1.ConditionTrue, "Ready", "Infrastructure target is synchronized", object.Status.AppliedHash, object.Status.AppliedAt); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, r.Invalidator, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "AccessInfrastructureTarget", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeAuthz)}, nil
}

func (r *AccessInfrastructureTargetReconciler) ensureManaged(ctx context.Context, api flarecloudflare.AccessInfrastructureTargetAPI, object *v1alpha1.AccessInfrastructureTarget, input flarecloudflare.AccessInfrastructureTargetInput) (flarecloudflare.AccessInfrastructureTarget, error) {
	id := object.Status.TargetID
	var remote flarecloudflare.AccessInfrastructureTarget
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.TargetID == "" {
				return remote, infrastructureTargetInvalid("Invalid", "adoption mode AdoptById requires externalRef.targetId")
			}
			id = object.Spec.ExternalRef.TargetID
			observed, err := api.GetAccessInfrastructureTarget(ctx, id)
			if err != nil {
				return remote, err
			}
			if expected := object.Spec.Adoption.Expect.Hostname; expected != "" && !strings.EqualFold(observed.Hostname, expected) {
				return remote, infrastructureTargetInvalid("Conflict", "remote target hostname %q does not match adoption expectation %q", observed.Hostname, expected)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return remote, infrastructureTargetInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
		default:
			return api.CreateAccessInfrastructureTarget(ctx, input)
		}
	} else {
		if !object.Status.OwnershipVerified {
			return remote, infrastructureTargetInvalid("Conflict", "remote infrastructure target ID is not verified as owned or adopted")
		}
		observed, err := api.GetAccessInfrastructureTarget(ctx, id)
		if err != nil {
			return remote, err
		}
		remote = observed
	}
	if infrastructureTargetMatches(input, remote) {
		return remote, nil
	}
	return api.UpdateAccessInfrastructureTarget(ctx, id, input)
}

func (r *AccessInfrastructureTargetReconciler) resolveInput(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, account *v1alpha1.CloudflareAccount) (flarecloudflare.AccessInfrastructureTargetInput, error) {
	input := flarecloudflare.AccessInfrastructureTargetInput{Hostname: object.Spec.Hostname}
	if object.Spec.IP.IPV4 != nil {
		virtualNetworkID, err := r.resolveVirtualNetwork(ctx, object, account, object.Spec.IP.IPV4.VirtualNetworkRef, object.Spec.IP.IPV4.VirtualNetworkID)
		if err != nil {
			return input, fmt.Errorf("resolve ipv4 virtual network: %w", err)
		}
		input.IPV4 = &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: object.Spec.IP.IPV4.IPAddr, VirtualNetworkID: virtualNetworkID}
	}
	if object.Spec.IP.IPV6 != nil {
		virtualNetworkID, err := r.resolveVirtualNetwork(ctx, object, account, object.Spec.IP.IPV6.VirtualNetworkRef, object.Spec.IP.IPV6.VirtualNetworkID)
		if err != nil {
			return input, fmt.Errorf("resolve ipv6 virtual network: %w", err)
		}
		input.IPV6 = &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: object.Spec.IP.IPV6.IPAddr, VirtualNetworkID: virtualNetworkID}
	}
	if input.IPV4 == nil && input.IPV6 == nil {
		return input, infrastructureTargetInvalid("Invalid", "at least one target IP address is required")
	}
	return input, nil
}

func (r *AccessInfrastructureTargetReconciler) resolveVirtualNetwork(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, account *v1alpha1.CloudflareAccount, reference *v1alpha1.NamespacedLocalObjectReference, externalID string) (string, error) {
	if reference == nil {
		return externalID, nil
	}
	namespace := reference.Namespace
	if namespace == "" {
		namespace = object.Namespace
	}
	if _, err := authorizePrivateNamespace(ctx, r.readClient(), account, namespace, authz.Request{PlatformObject: true}); err != nil {
		return "", err
	}
	var virtualNetwork v1alpha1.VirtualNetwork
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, &virtualNetwork); err != nil {
		return "", infrastructureTargetInvalid("TargetNotFound", "get VirtualNetwork %s/%s: %v", namespace, reference.Name, err)
	}
	if !virtualNetwork.DeletionTimestamp.IsZero() {
		return "", infrastructureTargetInvalid("TargetNotFound", "the VirtualNetwork %s/%s is deleting", namespace, reference.Name)
	}
	if virtualNetwork.Spec.AccountRef.Name != account.Name {
		return "", infrastructureTargetInvalid("RefNotPermitted", "the VirtualNetwork %s/%s uses CloudflareAccount %q, want %q", namespace, reference.Name, virtualNetwork.Spec.AccountRef.Name, account.Name)
	}
	if virtualNetwork.Status.VirtualNetworkID == "" || !metaConditionTrue(virtualNetwork.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
		return "", infrastructureTargetInvalid("Pending", "the VirtualNetwork %s/%s is not ready", namespace, reference.Name)
	}
	return virtualNetwork.Status.VirtualNetworkID, nil
}

func infrastructureTargetMatches(input flarecloudflare.AccessInfrastructureTargetInput, remote flarecloudflare.AccessInfrastructureTarget) bool {
	return strings.EqualFold(input.Hostname, remote.Hostname) && infrastructureTargetAddressMatches(input.IPV4, remote.IPV4) && infrastructureTargetAddressMatches(input.IPV6, remote.IPV6)
}

func infrastructureTargetAddressMatches(left, right *flarecloudflare.AccessInfrastructureTargetAddress) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.IPAddr == right.IPAddr && left.VirtualNetworkID == right.VirtualNetworkID
}

func infrastructureTargetWouldApply(input flarecloudflare.AccessInfrastructureTargetInput, remote flarecloudflare.AccessInfrastructureTarget) *v1alpha1.AccessInfrastructureTargetObservedState {
	if infrastructureTargetMatches(input, remote) {
		return nil
	}
	return &v1alpha1.AccessInfrastructureTargetObservedState{
		Hostname: input.Hostname,
		IP:       infrastructureTargetStatusIP(flarecloudflare.AccessInfrastructureTarget{IPV4: input.IPV4, IPV6: input.IPV6}),
	}
}

func (r *AccessInfrastructureTargetReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessInfrastructureTargetFinalizer) {
		return nil
	}
	if effectiveManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly && effectiveInfrastructureTargetDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.TargetID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.readClient(), object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.BulkDeleteAccessInfrastructureTargets(ctx, []string{object.Status.TargetID})); err != nil {
			return fmt.Errorf("delete Access infrastructure target %q: %w", object.Status.TargetID, err)
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessInfrastructureTargetFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *AccessInfrastructureTargetReconciler) finishError(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, reason string, err error) (ctrl.Result, error) {
	remote := infrastructureTargetFromStatus(object.Status)
	if patchErr := r.patchStatus(ctx, object, remote, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, metav1.ConditionFalse, reason, err.Error(), object.Status.AppliedHash, object.Status.AppliedAt); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if infrastructureTargetIsValidationError(err) {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *AccessInfrastructureTargetReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, infrastructureTargetFromStatus(object.Status), object.Status.OwnershipVerified, nil, metav1.ConditionFalse, metav1.ConditionFalse, "CloudflareError", err.Error(), object.Status.AppliedHash, object.Status.AppliedAt); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *AccessInfrastructureTargetReconciler) finishObserved(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, remote flarecloudflare.AccessInfrastructureTarget, wouldApply *v1alpha1.AccessInfrastructureTargetObservedState, ready metav1.ConditionStatus, reason, message string) (ctrl.Result, error) {
	owned := object.Status.OwnershipVerified && object.Status.TargetID == remote.ID
	return ctrl.Result{}, r.patchStatus(ctx, object, remote, owned, wouldApply, metav1.ConditionTrue, ready, reason, message, object.Status.AppliedHash, object.Status.AppliedAt)
}

func (r *AccessInfrastructureTargetReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessInfrastructureTarget, remote flarecloudflare.AccessInfrastructureTarget, owned bool, wouldApply *v1alpha1.AccessInfrastructureTargetObservedState, accepted, ready metav1.ConditionStatus, reason, message, appliedHash string, appliedAt *metav1.Time) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.AppliedHash = appliedHash
	object.Status.AppliedAt = appliedAt
	if remote.ID != "" {
		object.Status.TargetID = remote.ID
		object.Status.OwnershipVerified = owned
	}
	if remote.Hostname != "" {
		object.Status.Hostname = remote.Hostname
		object.Status.IP = infrastructureTargetStatusIP(remote)
	}
	object.Status.WouldApply = wouldApply
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		accessCondition(object.Generation, "Accepted", accepted, reason, message),
		accessCondition(object.Generation, "Ready", ready, reason, message),
	)
	return r.Status().Patch(ctx, object, base)
}

func infrastructureTargetStatusIP(remote flarecloudflare.AccessInfrastructureTarget) v1alpha1.AccessInfrastructureTargetIPStatus {
	status := v1alpha1.AccessInfrastructureTargetIPStatus{}
	if remote.IPV4 != nil {
		status.IPV4 = &v1alpha1.AccessInfrastructureTargetIPAddressStatus{IPAddr: remote.IPV4.IPAddr, VirtualNetworkID: remote.IPV4.VirtualNetworkID}
	}
	if remote.IPV6 != nil {
		status.IPV6 = &v1alpha1.AccessInfrastructureTargetIPAddressStatus{IPAddr: remote.IPV6.IPAddr, VirtualNetworkID: remote.IPV6.VirtualNetworkID}
	}
	return status
}

func infrastructureTargetFromStatus(status v1alpha1.AccessInfrastructureTargetStatus) flarecloudflare.AccessInfrastructureTarget {
	remote := flarecloudflare.AccessInfrastructureTarget{ID: status.TargetID, Hostname: status.Hostname}
	if status.IP.IPV4 != nil {
		remote.IPV4 = &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: status.IP.IPV4.IPAddr, VirtualNetworkID: status.IP.IPV4.VirtualNetworkID}
	}
	if status.IP.IPV6 != nil {
		remote.IPV6 = &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: status.IP.IPV6.IPAddr, VirtualNetworkID: status.IP.IPV6.VirtualNetworkID}
	}
	return remote
}

type infrastructureTargetValidationError struct {
	reason  string
	message string
}

func (err infrastructureTargetValidationError) Error() string { return err.message }

func infrastructureTargetInvalid(reason, format string, args ...any) error {
	return infrastructureTargetValidationError{reason: reason, message: fmt.Sprintf(format, args...)}
}

func infrastructureTargetIsValidationError(err error) bool {
	var validation infrastructureTargetValidationError
	return errors.As(err, &validation)
}

func infrastructureTargetErrorReason(err error) string {
	var validation infrastructureTargetValidationError
	if errors.As(err, &validation) {
		return validation.reason
	}
	return "Pending"
}
func effectiveInfrastructureTargetDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

func (r *AccessInfrastructureTargetReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *AccessInfrastructureTargetReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *AccessInfrastructureTargetReconciler) readClient() client.Client {
	if r.APIReader == nil {
		return r.Client
	}
	return infrastructureTargetReadClient{Client: r.Client, reader: r.APIReader}
}

type infrastructureTargetReadClient struct {
	client.Client
	reader client.Reader
}

func (c infrastructureTargetReadClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	return c.reader.Get(ctx, key, object, options...)
}

// SetupWithManager registers target indexes and dependency watches.
func (r *AccessInfrastructureTargetReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = manager.GetAPIReader()
	}
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.AccessInfrastructureTarget{}, accessInfrastructureTargetAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessInfrastructureTarget).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessInfrastructureTarget accountRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.AccessInfrastructureTarget{}, accessInfrastructureTargetVNetIndex, func(object client.Object) []string {
		target := object.(*v1alpha1.AccessInfrastructureTarget)
		keys := make([]string, 0, 2)
		if target.Spec.IP.IPV4 != nil && target.Spec.IP.IPV4.VirtualNetworkRef != nil {
			keys = append(keys, infrastructureTargetVNetKey(target.Namespace, *target.Spec.IP.IPV4.VirtualNetworkRef).String())
		}
		if target.Spec.IP.IPV6 != nil && target.Spec.IP.IPV6.VirtualNetworkRef != nil {
			keys = append(keys, infrastructureTargetVNetKey(target.Namespace, *target.Spec.IP.IPV6.VirtualNetworkRef).String())
		}
		return keys
	}); err != nil {
		return fmt.Errorf("index AccessInfrastructureTarget virtualNetworkRef: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.AccessInfrastructureTarget{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.targetsForAccount)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.targetsForVirtualNetwork)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allInfrastructureTargets))
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("access-infrastructure-target", r))
}

func infrastructureTargetVNetKey(namespace string, reference v1alpha1.NamespacedLocalObjectReference) types.NamespacedName {
	if reference.Namespace != "" {
		namespace = reference.Namespace
	}
	return types.NamespacedName{Namespace: namespace, Name: reference.Name}
}

func (r *AccessInfrastructureTargetReconciler) targetsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listInfrastructureTargetRequests(ctx, client.MatchingFields{accessInfrastructureTargetAccountIndex: object.GetName()})
}

func (r *AccessInfrastructureTargetReconciler) targetsForVirtualNetwork(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listInfrastructureTargetRequests(ctx, client.MatchingFields{accessInfrastructureTargetVNetIndex: client.ObjectKeyFromObject(object).String()})
}

func (r *AccessInfrastructureTargetReconciler) allInfrastructureTargets(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.listInfrastructureTargetRequests(ctx)
}

func (r *AccessInfrastructureTargetReconciler) listInfrastructureTargetRequests(ctx context.Context, options ...client.ListOption) []reconcile.Request {
	var list v1alpha1.AccessInfrastructureTargetList
	if err := r.List(ctx, &list, options...); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}
