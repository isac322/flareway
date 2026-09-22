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
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

const (
	accessCustomPageAccountIndex  = accessAccountIndex + ".accessCustomPage"
	accessCustomPageHTMLMaxLength = 262144
	accessCustomPageRequeue       = 30 * time.Second
)

// AccessCustomPageReconciler manages account-level Cloudflare Access custom pages.
type AccessCustomPageReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Recorder            recorder.EventRecorder
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesscustompages;accessapplications;accessstandaloneapplications;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesscustompages,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesscustompages/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesscustompages/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessCustomPage with its Cloudflare custom page.
func (r *AccessCustomPageReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessCustomPage)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessCustomPageFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessCustomPageFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		return ctrl.Result{}, r.finishError(ctx, object, privateErrorReason(err), err)
	}
	input, err := r.customPageInput(ctx, object)
	if err != nil {
		return ctrl.Result{}, r.finishError(ctx, object, "Invalid", err)
	}
	if effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil {
			return ctrl.Result{}, r.finishError(ctx, object, "Invalid", errors.New("management policy ObserveOnly for AccessCustomPage requires externalRef"))
		}
		remote, getErr := api.GetAccessCustomPage(ctx, object.Spec.ExternalRef.CustomPageID)
		if getErr != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, getErr)
		}
		drift := accessCustomPageDrift(input, remote)
		message := "Access custom page is observed without mutation"
		if len(drift) > 0 {
			message += "; drift detected in " + strings.Join(drift, ", ")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, false, metav1.ConditionTrue, "Observed", message, drift, nil, false, object.Status.AppliedHash, object.Status.AppliedAt)
	}

	// T1 gate: the managed path below reads the remote custom page before
	// any write. ObserveOnly above stays ungated (safety condition 9).
	// Adoption reads inside reconcileManaged are T0 by construction: the
	// gate only opens once status.customPageId is bound and the applied
	// hash matches.
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "AccessCustomPage", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.CustomPageID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}

	remote, warningsObserved, err := r.reconcileManaged(ctx, api, object, input)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	var warnings []flarecloudflare.AccessCustomPageWarning
	if warningsObserved {
		warnings = remote.Warnings
		r.recordWarnings(object, warnings)
	}
	if err := r.patchStatus(ctx, object, remote, true, metav1.ConditionTrue, "Ready", "Access custom page is synchronized", nil, warnings, warningsObserved, object.Status.AppliedHash, object.Status.AppliedAt); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "AccessCustomPage", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeAuthz)}, nil
}

func (r *AccessCustomPageReconciler) reconcileManaged(ctx context.Context, api flarecloudflare.AccessCustomPageAPI, object *v1alpha1.AccessCustomPage, input flarecloudflare.AccessCustomPageInput) (flarecloudflare.AccessCustomPage, bool, error) {
	id := object.Status.CustomPageID
	if id != "" {
		if !object.Status.OwnershipVerified {
			return flarecloudflare.AccessCustomPage{}, false, accessValidationError{reason: "Conflict", message: "remote custom page ID is not verified as owned or adopted"}
		}
		remote, err := api.GetAccessCustomPage(ctx, id)
		if err != nil {
			return flarecloudflare.AccessCustomPage{}, false, err
		}
		if len(accessCustomPageDrift(input, remote)) == 0 {
			return remote, false, nil
		}
		updated, err := api.UpdateAccessCustomPage(ctx, id, input)
		return updated, true, err
	}
	if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
		if object.Spec.ExternalRef == nil {
			return flarecloudflare.AccessCustomPage{}, false, accessValidationError{reason: "Invalid", message: "adoption mode AdoptById for AccessCustomPage requires externalRef"}
		}
		remote, err := api.GetAccessCustomPage(ctx, object.Spec.ExternalRef.CustomPageID)
		if err != nil {
			return flarecloudflare.AccessCustomPage{}, false, err
		}
		if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
			return flarecloudflare.AccessCustomPage{}, false, accessValidationError{reason: "Conflict", message: fmt.Sprintf("adoption conflict: Access custom page name %q does not match expected %q", remote.Name, expected)}
		}
		if len(accessCustomPageDrift(input, remote)) == 0 {
			return remote, false, nil
		}
		updated, err := api.UpdateAccessCustomPage(ctx, remote.ID, input)
		return updated, true, err
	}
	if object.Spec.ExternalRef != nil {
		return flarecloudflare.AccessCustomPage{}, false, accessValidationError{reason: "Invalid", message: "managed AccessCustomPage externalRef requires adoption.mode AdoptById"}
	}
	created, err := api.CreateAccessCustomPage(ctx, input)
	return created, true, err
}

func (r *AccessCustomPageReconciler) customPageInput(ctx context.Context, object *v1alpha1.AccessCustomPage) (flarecloudflare.AccessCustomPageInput, error) {
	if object.Spec.Name == "" {
		return flarecloudflare.AccessCustomPageInput{}, errors.New("custom page name is required")
	}
	if object.Spec.HTML == "" {
		return flarecloudflare.AccessCustomPageInput{}, errors.New("custom page HTML is required")
	}
	if len(object.Spec.HTML) > accessCustomPageHTMLMaxLength {
		return flarecloudflare.AccessCustomPageInput{}, fmt.Errorf("custom page HTML exceeds the %d-character limit", accessCustomPageHTMLMaxLength)
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return flarecloudflare.AccessCustomPageInput{}, err
	}
	input := flarecloudflare.AccessCustomPageInput{Name: name, Type: object.Spec.Type, HTML: object.Spec.HTML}
	if object.Spec.ContractVersion > 0 {
		value := object.Spec.ContractVersion
		input.ContractVersion = &value
	}
	return input, nil
}

func accessCustomPageDrift(desired flarecloudflare.AccessCustomPageInput, observed flarecloudflare.AccessCustomPage) []string {
	fields := make([]string, 0, 4)
	if desired.Name != observed.Name {
		fields = append(fields, "name")
	}
	if desired.Type != observed.Type {
		fields = append(fields, "type")
	}
	if desired.HTML != observed.HTML {
		fields = append(fields, "html")
	}
	contractVersion := int64(0)
	if desired.ContractVersion != nil {
		contractVersion = *desired.ContractVersion
	}
	if contractVersion != observed.ContractVersion {
		fields = append(fields, "contractVersion")
	}
	return fields
}

func (r *AccessCustomPageReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessCustomPage) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessCustomPageFinalizer) {
		return ctrl.Result{}, nil
	}
	references, err := r.referencingApplications(ctx, object)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(references) > 0 {
		message := "Access custom page is still referenced by " + strings.Join(references, ", ")
		if patchErr := r.patchCleanupBlocked(ctx, object, message); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: accessCustomPageRequeue}, nil
	}
	if effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged &&
		customPageDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete &&
		object.Status.CustomPageID != "" && object.Status.OwnershipVerified {
		api, _, clientErr := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if clientErr != nil {
			return ctrl.Result{}, clientErr
		}
		deletedID, deleteErr := api.DeleteAccessCustomPage(ctx, object.Status.CustomPageID)
		if deleteErr != nil && !flarecloudflare.IsNotFound(deleteErr) {
			return ctrl.Result{}, deleteErr
		}
		if deleteErr == nil && deletedID != "" && deletedID != object.Status.CustomPageID {
			return ctrl.Result{}, fmt.Errorf("delete Access custom page %q returned ID %q", object.Status.CustomPageID, deletedID)
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessCustomPageFinalizer)
	return ctrl.Result{}, r.Patch(ctx, object, base)
}

func (r *AccessCustomPageReconciler) referencingApplications(ctx context.Context, page *v1alpha1.AccessCustomPage) ([]string, error) {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications); err != nil {
		return nil, fmt.Errorf("list AccessApplications referencing custom page: %w", err)
	}
	references := make([]string, 0)
	for index := range applications.Items {
		application := &applications.Items[index]
		if customPageIsReferenced(application.Spec.Application, application.Namespace, page) {
			references = append(references, application.Namespace+"/"+application.Name)
		}
	}
	var standaloneApplications v1alpha1.AccessStandaloneApplicationList
	if err := r.List(ctx, &standaloneApplications); err != nil {
		return nil, fmt.Errorf("list AccessStandaloneApplications referencing custom page: %w", err)
	}
	for index := range standaloneApplications.Items {
		application := &standaloneApplications.Items[index]
		if customPageIsReferenced(application.Spec.Application, application.Namespace, page) {
			references = append(references, application.Namespace+"/"+application.Name)
		}
	}
	slices.Sort(references)
	return slices.Compact(references), nil
}

func customPageIsReferenced(settings v1alpha1.AccessApplicationSettings, applicationNamespace string, page *v1alpha1.AccessCustomPage) bool {
	for _, ref := range settings.CustomPageRefs {
		matches := ref.ExternalID != "" && ref.ExternalID == page.Status.CustomPageID
		if ref.ObjectRef != nil {
			namespace := ref.ObjectRef.Namespace
			if namespace == "" {
				namespace = applicationNamespace
			}
			matches = matches || namespace == page.Namespace && ref.ObjectRef.Name == page.Name
		}
		if matches {
			return true
		}
	}
	return false
}

func customPageDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

func (r *AccessCustomPageReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessCustomPage, remote flarecloudflare.AccessCustomPage, owned bool, status metav1.ConditionStatus, reason, message string, drift []string, warnings []flarecloudflare.AccessCustomPageWarning, warningsObserved bool, appliedHash string, appliedAt *metav1.Time) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.AppliedHash = appliedHash
	object.Status.AppliedAt = appliedAt
	if remote.ID != "" {
		object.Status.CustomPageID = remote.ID
		object.Status.OwnershipVerified = owned
		object.Status.Observed = &v1alpha1.AccessCustomPageObservedStatus{
			Name: remote.Name, Type: remote.Type, ContractVersion: remote.ContractVersion,
		}
	}
	conditions := []metav1.Condition{
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionAccepted, status, reason, message),
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionReady, status, reason, message),
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionCleanupBlocked, metav1.ConditionFalse, "NotBlocked", "No cleanup is pending"),
	}
	switch {
	case status != metav1.ConditionTrue:
		conditions = append(conditions, accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionDegraded, metav1.ConditionTrue, reason, message))
	case len(warnings) > 0:
		conditions = append(conditions, accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionDegraded, metav1.ConditionTrue, "TemplateWarnings", formatCustomPageWarnings(warnings)))
	case len(drift) > 0:
		conditions = append(conditions, accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionDegraded, metav1.ConditionTrue, "DriftDetected", "Observed custom page differs in "+strings.Join(drift, ", ")))
	default:
		degraded := accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionDegraded, metav1.ConditionFalse, "Healthy", "No custom page drift or template warnings were detected")
		if previous := meta.FindStatusCondition(object.Status.Conditions, v1alpha1.AccessCustomPageConditionDegraded); !warningsObserved && previous != nil && previous.Status == metav1.ConditionTrue && previous.Reason == "TemplateWarnings" {
			// GET cannot re-observe template warnings; keep the last observed signal.
			degraded.Status = metav1.ConditionTrue
			degraded.Reason = previous.Reason
			degraded.Message = previous.Message
		}
		conditions = append(conditions, degraded)
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), conditions...)
	return r.Status().Patch(ctx, object, base)
}

func (r *AccessCustomPageReconciler) patchCleanupBlocked(ctx context.Context, object *v1alpha1.AccessCustomPage, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionReady, metav1.ConditionFalse, "CleanupBlocked", message),
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionDegraded, metav1.ConditionTrue, "CleanupBlocked", message),
		accessCondition(object.Generation, v1alpha1.AccessCustomPageConditionCleanupBlocked, metav1.ConditionTrue, "Referenced", message),
	)
	return r.Status().Patch(ctx, object, base)
}

func (r *AccessCustomPageReconciler) finishError(ctx context.Context, object *v1alpha1.AccessCustomPage, reason string, err error) error {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.AccessCustomPage{}, object.Status.OwnershipVerified, metav1.ConditionFalse, reason, err.Error(), nil, nil, false, object.Status.AppliedHash, object.Status.AppliedAt); patchErr != nil {
		return errors.Join(err, patchErr)
	}
	return err
}

func (r *AccessCustomPageReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.AccessCustomPage, err error) error {
	var validation accessValidationError
	if errors.As(err, &validation) {
		return r.finishError(ctx, object, validation.reason, err)
	}
	return r.finishError(ctx, object, "CloudflareError", err)
}

func (r *AccessCustomPageReconciler) recordWarnings(object *v1alpha1.AccessCustomPage, warnings []flarecloudflare.AccessCustomPageWarning) {
	if r.Recorder == nil {
		return
	}
	for _, warning := range warnings {
		location := warning.Tier
		if warning.Ref != "" {
			location += ":" + warning.Ref
		}
		r.Recorder.Eventf(object, nil, corev1.EventTypeWarning, "TemplateWarning", "ReconcileAccessCustomPage", "%s: %s", location, warning.Message)
	}
}

func formatCustomPageWarnings(warnings []flarecloudflare.AccessCustomPageWarning) string {
	messages := make([]string, len(warnings))
	for index := range warnings {
		location := warnings[index].Tier
		if warnings[index].Ref != "" {
			location += ":" + warnings[index].Ref
		}
		messages[index] = location + ": " + warnings[index].Message
	}
	return strings.Join(messages, "; ")
}

func (r *AccessCustomPageReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the AccessCustomPage controller and dependency watches.
func (r *AccessCustomPageReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessCustomPage{}, accessCustomPageAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessCustomPage).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessCustomPage accounts: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.AccessCustomPage{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.pagesForAccount)).
		Watches(&v1alpha1.AccessApplication{}, handler.EnqueueRequestsFromMapFunc(r.pagesForApplication)).
		Watches(&v1alpha1.AccessStandaloneApplication{}, handler.EnqueueRequestsFromMapFunc(r.pagesForStandaloneApplication)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.pagesForNamespace))
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("access-custom-page", r))
}

func (r *AccessCustomPageReconciler) pagesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessCustomPageList
	if err := r.List(ctx, &list, client.MatchingFields{accessCustomPageAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return accessCustomPageRequests(list.Items)
}

func (r *AccessCustomPageReconciler) pagesForApplication(_ context.Context, object client.Object) []reconcile.Request {
	application := object.(*v1alpha1.AccessApplication)
	return pagesForCustomPageRefs(application.Namespace, application.Spec.Application.CustomPageRefs)
}

func (r *AccessCustomPageReconciler) pagesForStandaloneApplication(_ context.Context, object client.Object) []reconcile.Request {
	application := object.(*v1alpha1.AccessStandaloneApplication)
	return pagesForCustomPageRefs(application.Namespace, application.Spec.Application.CustomPageRefs)
}

func pagesForCustomPageRefs(defaultNamespace string, refs []v1alpha1.AccessCustomPageReference) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(refs))
	for _, ref := range refs {
		if ref.ObjectRef == nil {
			continue
		}
		namespace := ref.ObjectRef.Namespace
		if namespace == "" {
			namespace = defaultNamespace
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: ref.ObjectRef.Name}})
	}
	return requests
}

func (r *AccessCustomPageReconciler) pagesForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessCustomPageList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return accessCustomPageRequests(list.Items)
}

func accessCustomPageRequests(items []v1alpha1.AccessCustomPage) []reconcile.Request {
	result := make([]reconcile.Request, len(items))
	for index := range items {
		result[index] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[index].Namespace, Name: items[index].Name}}
	}
	return result
}
