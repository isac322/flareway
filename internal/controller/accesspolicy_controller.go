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

const accessPolicyAccountIndex = accessAccountIndex + ".accessPolicy"

// AccessPolicyReconciler manages reusable Cloudflare Access policies.
type AccessPolicyReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies;accessgroups;identityproviders;deviceposturerules;servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one AccessPolicy with its Cloudflare Access policy.
func (r *AccessPolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessPolicy)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessPolicyFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessPolicyFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
	if err != nil {
		return r.finishAccessPolicyError(ctx, object, privateErrorReason(err), err)
	}
	include, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Include)
	if err != nil {
		return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	require, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Require)
	if err != nil {
		return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	if object.Spec.Require == nil {
		require = nil
	}
	exclude, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, object.Spec.Exclude)
	if err != nil {
		return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "RefNotPermitted", err.Error())
	}
	if object.Spec.Exclude == nil {
		exclude = nil
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return r.finishAccessPolicyError(ctx, object, "Pending", err)
	}
	input := accessPolicyInput(object.Spec, name, include, require, exclude)

	if effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil {
			return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "Invalid", "ObserveOnly AccessPolicy requires externalRef")
		}
		remote, getErr := api.GetAccessPolicy(ctx, object.Spec.ExternalRef.PolicyID)
		if getErr != nil {
			return r.finishAccessPolicyError(ctx, object, "CloudflareError", getErr)
		}
		var wouldApply *v1alpha1.AccessPolicyObservedState
		message := "Access policy is observed without mutation"
		if !flarecloudflare.AccessPolicyMatchesInput(remote, input) {
			wouldApply, err = accessPolicyStateFromInput(input)
			if err != nil {
				return r.finishAccessPolicyError(ctx, object, "Unsupported", err)
			}
			message = "Access policy drift is observed without mutation"
		}
		owned := object.Status.OwnershipVerified && object.Status.PolicyID == remote.ID
		return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, &remote, owned, wouldApply, metav1.ConditionTrue, "Observed", message)
	}

	policyID := object.Status.PolicyID
	owned := object.Status.OwnershipVerified
	var remote flarecloudflare.AccessPolicy
	if policyID == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			if object.Spec.ExternalRef == nil {
				return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, false, nil, metav1.ConditionFalse, "Invalid", "AdoptById AccessPolicy requires externalRef")
			}
			remote, err = api.GetAccessPolicy(ctx, object.Spec.ExternalRef.PolicyID)
			if err != nil {
				return r.finishAccessPolicyError(ctx, object, "CloudflareError", err)
			}
			if err = validateAccessPolicyAdoption(object, input, remote); err != nil {
				return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, false, nil, metav1.ConditionFalse, "Conflict", err.Error())
			}
			policyID = remote.ID
			owned = true
			if !flarecloudflare.AccessPolicyMatchesInput(remote, input) {
				remote, err = api.UpdateAccessPolicy(ctx, policyID, input)
				if err != nil {
					return r.finishAccessPolicyError(ctx, object, accessPolicyErrorReason(err), err)
				}
			}
		} else {
			remote, err = api.CreateAccessPolicy(ctx, input)
			if err != nil {
				return r.finishAccessPolicyError(ctx, object, accessPolicyErrorReason(err), err)
			}
			policyID = remote.ID
			owned = true
		}
	} else {
		if !owned {
			return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, nil, false, nil, metav1.ConditionFalse, "Conflict", "remote policy ID is not verified as created or explicitly adopted by this AccessPolicy")
		}
		remote, err = api.GetAccessPolicy(ctx, policyID)
		if err != nil {
			return r.finishAccessPolicyError(ctx, object, "CloudflareError", err)
		}
		if !flarecloudflare.AccessPolicyMatchesInput(remote, input) {
			remote, err = api.UpdateAccessPolicy(ctx, policyID, input)
			if err != nil {
				return r.finishAccessPolicyError(ctx, object, accessPolicyErrorReason(err), err)
			}
		}
	}
	if remote.ID == "" {
		remote.ID = policyID
	}
	return ctrl.Result{}, r.patchAccessPolicyStatus(ctx, object, &remote, owned, nil, metav1.ConditionTrue, "Ready", "Access policy is synchronized")
}

func accessPolicyInput(spec v1alpha1.AccessPolicySpec, name string, include, require, exclude []flarecloudflare.ResolvedAccessRule) flarecloudflare.AccessPolicyInput {
	input := flarecloudflare.AccessPolicyInput{
		Name:              name,
		Decision:          string(spec.Decision),
		Include:           include,
		Require:           require,
		Exclude:           exclude,
		SessionDuration:   spec.SessionDuration,
		IsolationRequired: spec.IsolationRequired,
	}
	if spec.PurposeJustification != nil {
		input.PurposeJustificationRequired = new(spec.PurposeJustification.Required)
		input.PurposeJustificationPrompt = spec.PurposeJustification.Prompt
	}
	if spec.Approval != nil {
		input.ApprovalRequired = new(spec.Approval.Required)
		input.ApprovalGroups = make([]flarecloudflare.AccessApprovalGroup, len(spec.Approval.Groups))
		for i := range spec.Approval.Groups {
			input.ApprovalGroups[i] = flarecloudflare.AccessApprovalGroup{
				ApprovalsNeeded: spec.Approval.Groups[i].ApprovalsNeeded,
				EmailAddresses:  append([]string(nil), spec.Approval.Groups[i].EmailAddresses...),
				EmailListID:     spec.Approval.Groups[i].EmailListID,
			}
		}
	}
	if spec.ConnectionRules != nil {
		input.ConnectionRules = &flarecloudflare.AccessPolicyConnectionRules{}
		if spec.ConnectionRules.RDP != nil {
			input.ConnectionRules.RDP = &flarecloudflare.AccessPolicyRDPConnectionRules{
				AllowedClipboardLocalToRemoteFormats: accessClipboardFormats(spec.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats),
				AllowedClipboardRemoteToLocalFormats: accessClipboardFormats(spec.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats),
			}
		}
	}
	if spec.MFAConfig != nil {
		input.MFAConfig = &flarecloudflare.AccessPolicyMFAConfig{
			AllowedAuthenticators: accessMFAAuthenticators(spec.MFAConfig.AllowedAuthenticators),
			MFADisabled:           spec.MFAConfig.MFADisabled,
			SessionDuration:       spec.MFAConfig.SessionDuration,
		}
	}
	return input
}

func validateAccessPolicyAdoption(object *v1alpha1.AccessPolicy, input flarecloudflare.AccessPolicyInput, remote flarecloudflare.AccessPolicy) error {
	expectedName := object.Spec.Adoption.Expect.Name
	if expectedName == "" {
		expectedName = input.Name
	}
	if remote.Name != expectedName {
		return fmt.Errorf("remote policy name %q does not match adoption expectation %q", remote.Name, expectedName)
	}
	if remote.Decision != input.Decision {
		return fmt.Errorf("remote policy decision %q does not match adoption expectation %q", remote.Decision, input.Decision)
	}
	return nil
}

func accessPolicyStateFromRemote(remote flarecloudflare.AccessPolicy) (*v1alpha1.AccessPolicyObservedState, error) {
	include, err := accessRulesObserved(remote.Include)
	if err != nil {
		return nil, err
	}
	require, err := accessRulesObserved(remote.Require)
	if err != nil {
		return nil, err
	}
	exclude, err := accessRulesObserved(remote.Exclude)
	if err != nil {
		return nil, err
	}
	return &v1alpha1.AccessPolicyObservedState{
		Name:                 remote.Name,
		Decision:             v1alpha1.AccessPolicyDecision(remote.Decision),
		Include:              include,
		Require:              require,
		Exclude:              exclude,
		SessionDuration:      remote.SessionDuration,
		PurposeJustification: &v1alpha1.AccessPolicyPurposeJustification{Required: remote.PurposeJustificationRequired, Prompt: remote.PurposeJustificationPrompt},
		Approval:             accessPolicyApprovalObserved(remote.ApprovalRequired, remote.ApprovalGroups),
		IsolationRequired:    new(remote.IsolationRequired),
		ConnectionRules:      accessPolicyConnectionRulesObserved(remote.ConnectionRules),
		MFAConfig:            accessPolicyMFAObserved(remote.MFAConfig),
	}, nil
}

func accessPolicyStateFromInput(input flarecloudflare.AccessPolicyInput) (*v1alpha1.AccessPolicyObservedState, error) {
	include, err := accessRulesObserved(input.Include)
	if err != nil {
		return nil, err
	}
	require, err := accessRulesObserved(input.Require)
	if err != nil {
		return nil, err
	}
	exclude, err := accessRulesObserved(input.Exclude)
	if err != nil {
		return nil, err
	}
	state := &v1alpha1.AccessPolicyObservedState{
		Name:              input.Name,
		Decision:          v1alpha1.AccessPolicyDecision(input.Decision),
		Include:           include,
		Require:           require,
		Exclude:           exclude,
		SessionDuration:   input.SessionDuration,
		IsolationRequired: input.IsolationRequired,
	}
	if input.PurposeJustificationRequired != nil {
		state.PurposeJustification = &v1alpha1.AccessPolicyPurposeJustification{
			Required: *input.PurposeJustificationRequired,
			Prompt:   input.PurposeJustificationPrompt,
		}
	}
	if input.ApprovalRequired != nil {
		state.Approval = accessPolicyApprovalObserved(*input.ApprovalRequired, input.ApprovalGroups)
	}
	if input.ConnectionRules != nil {
		state.ConnectionRules = accessPolicyConnectionRulesObserved(*input.ConnectionRules)
	}
	if input.MFAConfig != nil {
		state.MFAConfig = accessPolicyMFAObserved(*input.MFAConfig)
	}
	return state, nil
}

func accessPolicyApprovalObserved(required bool, groups []flarecloudflare.AccessApprovalGroup) *v1alpha1.AccessPolicyApproval {
	out := &v1alpha1.AccessPolicyApproval{Required: required, Groups: make([]v1alpha1.AccessPolicyApprovalGroup, len(groups))}
	for i := range groups {
		out.Groups[i] = v1alpha1.AccessPolicyApprovalGroup{
			ApprovalsNeeded: groups[i].ApprovalsNeeded,
			EmailAddresses:  append([]string(nil), groups[i].EmailAddresses...),
			EmailListID:     groups[i].EmailListID,
		}
	}
	return out
}

func accessPolicyConnectionRulesObserved(value flarecloudflare.AccessPolicyConnectionRules) *v1alpha1.AccessPolicyConnectionRules {
	out := &v1alpha1.AccessPolicyConnectionRules{}
	if value.RDP != nil {
		out.RDP = &v1alpha1.AccessPolicyRDPConnectionRules{
			AllowedClipboardLocalToRemoteFormats: accessClipboardFormatsObserved(value.RDP.AllowedClipboardLocalToRemoteFormats),
			AllowedClipboardRemoteToLocalFormats: accessClipboardFormatsObserved(value.RDP.AllowedClipboardRemoteToLocalFormats),
		}
	}
	return out
}

func accessPolicyMFAObserved(value flarecloudflare.AccessPolicyMFAConfig) *v1alpha1.AccessPolicyMFAConfig {
	return &v1alpha1.AccessPolicyMFAConfig{
		AllowedAuthenticators: accessMFAAuthenticatorsObserved(value.AllowedAuthenticators),
		MFADisabled:           value.MFADisabled,
		SessionDuration:       value.SessionDuration,
	}
}

func accessClipboardFormats(values []v1alpha1.AccessPolicyClipboardFormat) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func accessClipboardFormatsObserved(values []string) []v1alpha1.AccessPolicyClipboardFormat {
	if values == nil {
		return nil
	}
	out := make([]v1alpha1.AccessPolicyClipboardFormat, len(values))
	for i := range values {
		out[i] = v1alpha1.AccessPolicyClipboardFormat(values[i])
	}
	return out
}

func accessMFAAuthenticators(values []v1alpha1.AccessPolicyMFAAuthenticator) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i := range values {
		out[i] = string(values[i])
	}
	return out
}

func accessMFAAuthenticatorsObserved(values []string) []v1alpha1.AccessPolicyMFAAuthenticator {
	if values == nil {
		return nil
	}
	out := make([]v1alpha1.AccessPolicyMFAAuthenticator, len(values))
	for i := range values {
		out[i] = v1alpha1.AccessPolicyMFAAuthenticator(values[i])
	}
	return out
}

func accessRulesObserved(values []flarecloudflare.ResolvedAccessRule) ([]v1alpha1.AccessRuleObservation, error) {
	if values == nil {
		return nil, nil
	}
	out := make([]v1alpha1.AccessRuleObservation, len(values))
	for i := range values {
		value := values[i]
		switch value.Kind {
		case "email", "emailDomain", "emailList", "everyone", "ip", "ipList", "certificate", "commonName",
			"group", "azureAD", "githubOrganization", "gsuite", "okta", "saml", "oidc", "serviceToken",
			"anyValidServiceToken", "externalEvaluation", "geo", "authMethod", "devicePosture", "loginMethod",
			"authContext", "linkedAppToken", "userRiskScore", "cloudflareAccountMember":
		default:
			return nil, &flarecloudflare.UnsupportedAccessPolicyFieldError{Field: "rule kind", Value: value.Kind}
		}
		out[i] = v1alpha1.AccessRuleObservation{
			Kind:               value.Kind,
			Value:              value.Value,
			Value2:             value.Value2,
			Value3:             value.Value3,
			Values:             append([]string(nil), value.Values...),
			ID:                 value.ID,
			IdentityProviderID: value.IdentityProviderID,
			AccountID:          value.AccountID,
		}
	}
	return out, nil
}

func (r *AccessPolicyReconciler) finishAccessPolicyError(ctx context.Context, object *v1alpha1.AccessPolicy, reason string, err error) (ctrl.Result, error) {
	if accessPolicyErrorReason(err) == "Unsupported" {
		reason = "Unsupported"
	}
	if patchErr := r.patchAccessPolicyStatus(ctx, object, nil, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, reason, err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if reason == "Unsupported" || reason == "Invalid" || reason == "Conflict" {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func accessPolicyErrorReason(err error) string {
	var unsupported *flarecloudflare.UnsupportedAccessPolicyFieldError
	if errors.As(err, &unsupported) {
		return "Unsupported"
	}
	return "CloudflareError"
}

func (r *AccessPolicyReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessPolicy) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessPolicyFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.PolicyID != "" && object.Status.OwnershipVerified {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		if err = ignoreRemoteNotFound(api.DeleteAccessPolicy(ctx, object.Status.PolicyID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessPolicyFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *AccessPolicyReconciler) patchAccessPolicyStatus(ctx context.Context, object *v1alpha1.AccessPolicy, remote *flarecloudflare.AccessPolicy, owned bool, wouldApply *v1alpha1.AccessPolicyObservedState, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue && remote != nil {
		observed, err := accessPolicyStateFromRemote(*remote)
		if err != nil {
			return err
		}
		object.Status.PolicyID = remote.ID
		object.Status.OwnershipVerified = owned
		object.Status.Observed = observed
		object.Status.WouldApply = wouldApply
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}
func (r *AccessPolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the AccessPolicy controller and dependency watches.
func (r *AccessPolicyReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessPolicy{}, accessPolicyAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessPolicy).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessPolicy accounts: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.AccessPolicy{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.policiesForAccount)).Watches(&v1alpha1.AccessGroup{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.DevicePostureRule{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.policiesForDependency)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.policiesForNamespace)).Complete(observedReconciler("access-policy", r))
}
func (r *AccessPolicyReconciler) policiesForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessPolicyList
	if err := r.List(ctx, &list, client.MatchingFields{accessPolicyAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
func (r *AccessPolicyReconciler) policiesForDependency(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessPolicyList
	if err := r.List(ctx, &list, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
func (r *AccessPolicyReconciler) policiesForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AccessPolicyList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
