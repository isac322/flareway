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
	"reflect"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// ZeroTrustGatewayPolicyReconciler owns one l4 or dns Gateway rule.
type ZeroTrustGatewayPolicyReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	APIReader           client.Reader
	NewCloudflareClient NewGatewayCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustgatewaypolicies;zerotrustlists;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustgatewaypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustgatewaypolicies/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one ZeroTrustGatewayPolicy with its Cloudflare Gateway rule.
func (r *ZeroTrustGatewayPolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ZeroTrustGatewayPolicy)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustGatewayPolicyFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ZeroTrustGatewayPolicyFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add ZeroTrustGatewayPolicy finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}
	account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		if err := r.checkSingleWriter(ctx, object, account.Spec.AccountID); err != nil {
			return r.finishError(ctx, object, err)
		}
	}
	resolved, err := resolveGatewayPolicyDesired(ctx, r.Client, object)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if r.NewCloudflareClient == nil {
		return r.finishError(ctx, object, fmt.Errorf("cloudflare Gateway client factory is required"))
	}
	api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}

	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		remote, resolveErr := observeGatewayRule(ctx, api, object)
		if resolveErr != nil {
			return r.finishRemoteOrValidationError(ctx, object, resolveErr)
		}
		observed := gatewayRuleObserved(remote)
		wouldApply := gatewayPolicyWouldApply(resolved, observed)
		owned := object.Status.OwnershipVerified && object.Status.RuleID != "" && object.Status.RuleID == remote.ID
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, owned, wouldApply, metav1.ConditionTrue, "Observed", "Zero Trust Gateway policy is observed without mutation")
	}

	ownerDescription, err := globalOwnerDescription(ctx, r.Client, object, valueOrEmpty(resolved.Description))
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	input := gatewayRuleInput(resolved, ownerDescription)
	remote, err := r.ensureManaged(ctx, api, object, input, ownerDescription)
	if err != nil {
		return r.finishRemoteOrValidationError(ctx, object, err)
	}
	if err := r.patchStatus(ctx, object, remote, true, nil, metav1.ConditionTrue, "Ready", "Zero Trust Gateway policy is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: globalRequeue}, nil
}

func resolveGatewayPolicyDesired(ctx context.Context, kube client.Client, object *v1alpha1.ZeroTrustGatewayPolicy) (v1alpha1.ZeroTrustGatewayPolicyDesiredState, error) {
	result := v1alpha1.ZeroTrustGatewayPolicyDesiredState{
		Name: object.Spec.Name, Description: object.Spec.Description, Enabled: object.Spec.Enabled,
		Precedence: object.Spec.Precedence, Filters: append([]v1alpha1.ZeroTrustGatewayFilter(nil), object.Spec.Filters...),
		Action: object.Spec.Action, Traffic: object.Spec.Traffic, Identity: object.Spec.Identity,
		DevicePosture: object.Spec.DevicePosture, RuleSettings: object.Spec.RuleSettings,
	}
	refs := append([]v1alpha1.ZeroTrustGatewayListReference(nil), object.Spec.ListRefs...)
	slices.SortFunc(refs, func(left, right v1alpha1.ZeroTrustGatewayListReference) int {
		return strings.Compare(right.Name, left.Name)
	})
	for _, ref := range refs {
		list := new(v1alpha1.ZeroTrustList)
		if err := kube.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: ref.Name}, list); err != nil {
			return result, privateInvalid("TargetNotFound", "ZeroTrustList %s/%s was not found: %v", object.Namespace, ref.Name, err)
		}
		if !list.DeletionTimestamp.IsZero() || list.Spec.AccountRef.Name != object.Spec.AccountRef.Name {
			return result, privateInvalid("RefNotPermitted", "ZeroTrustList %s/%s is deleting or uses a different CloudflareAccount", object.Namespace, ref.Name)
		}
		if !metaConditionTrue(list.Status.Conditions, v1alpha1.ZeroTrustListConditionAccepted) || list.Status.ListID == "" {
			return result, privateInvalid("Pending", "ZeroTrustList %s/%s is not Accepted with a remote list ID", object.Namespace, ref.Name)
		}
		replacements := 0
		result.Traffic, replacements = replaceGatewayListToken(result.Traffic, ref.Name, list.Status.ListID)
		if result.Identity != nil {
			value, count := replaceGatewayListToken(*result.Identity, ref.Name, list.Status.ListID)
			result.Identity = &value
			replacements += count
		}
		if result.DevicePosture != nil {
			value, count := replaceGatewayListToken(*result.DevicePosture, ref.Name, list.Status.ListID)
			result.DevicePosture = &value
			replacements += count
		}
		if replacements == 0 {
			return result, privateInvalid("Invalid", "listRefs entry %q is not referenced as $%s in any wirefilter expression", ref.Name, ref.Name)
		}
	}
	return result, nil
}

func replaceGatewayListToken(expression, name, id string) (string, int) {
	token := "$" + name
	if expression == "" || name == "" {
		return expression, 0
	}
	var output strings.Builder
	count := 0
	for start := 0; start < len(expression); {
		index := strings.Index(expression[start:], token)
		if index < 0 {
			output.WriteString(expression[start:])
			break
		}
		index += start
		end := index + len(token)
		if end < len(expression) && gatewayListTokenCharacter(expression[end]) {
			output.WriteString(expression[start:end])
			start = end
			continue
		}
		output.WriteString(expression[start:index])
		output.WriteByte('$')
		output.WriteString(id)
		count++
		start = end
	}
	return output.String(), count
}

func gatewayListTokenCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' || value == '.'
}

func observeGatewayRule(ctx context.Context, api flarecloudflare.GatewayRuleAPI, object *v1alpha1.ZeroTrustGatewayPolicy) (flarecloudflare.GatewayRule, error) {
	id := object.Status.RuleID
	if object.Spec.ExternalRef != nil {
		id = object.Spec.ExternalRef.RuleID
	}
	if id != "" {
		remote, err := api.GetGatewayRule(ctx, id)
		if err != nil {
			return flarecloudflare.GatewayRule{}, err
		}
		if !object.Status.OwnershipVerified {
			if expected := object.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
				return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule name %q does not match expectation %q", remote.Name, expected)
			}
		}
		return remote, nil
	}
	rules, err := api.ListGatewayRules(ctx)
	if err != nil {
		return flarecloudflare.GatewayRule{}, err
	}
	matches := make([]flarecloudflare.GatewayRule, 0, 1)
	for _, rule := range rules {
		if rule.Name == object.Spec.Name {
			matches = append(matches, rule)
		}
	}
	if len(matches) == 0 {
		return flarecloudflare.GatewayRule{}, privateInvalid("TargetNotFound", "Cloudflare Gateway rule %q was not found", object.Spec.Name)
	}
	if len(matches) > 1 {
		return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "multiple Cloudflare Gateway rules are named %q", object.Spec.Name)
	}
	return matches[0], nil
}

func (r *ZeroTrustGatewayPolicyReconciler) ensureManaged(ctx context.Context, api flarecloudflare.GatewayRuleAPI, object *v1alpha1.ZeroTrustGatewayPolicy, input flarecloudflare.GatewayRuleInput, ownerDescription string) (flarecloudflare.GatewayRule, error) {
	id := object.Status.RuleID
	adopting := object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID
	acquiring := adopting && !object.Status.OwnershipVerified
	if adopting {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.RuleID == "" {
			return flarecloudflare.GatewayRule{}, privateInvalid("Invalid", "AdoptById requires externalRef.ruleId")
		}
		if id != "" && id != object.Spec.ExternalRef.RuleID {
			return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "status rule ID %q does not match adoption target %q", id, object.Spec.ExternalRef.RuleID)
		}
		id = object.Spec.ExternalRef.RuleID
		remote, err := api.GetGatewayRule(ctx, id)
		if err != nil {
			return flarecloudflare.GatewayRule{}, err
		}
		if acquiring {
			expected := object.Spec.Adoption.Expect.Name
			if expected == "" {
				expected = object.Spec.Name
			}
			if remote.Name != expected {
				return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule name %q does not match adoption expectation %q", remote.Name, expected)
			}
		}
		if remote.ReadOnly {
			return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule %q is read-only", id)
		}
	} else if object.Spec.ExternalRef != nil {
		return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "Managed externalRef requires adoption.mode AdoptById")
	}
	if id == "" {
		rules, err := api.ListGatewayRules(ctx)
		if err != nil {
			return flarecloudflare.GatewayRule{}, err
		}
		for _, rule := range rules {
			if rule.Name != object.Spec.Name {
				continue
			}
			if globalOwnedDescription(rule.Description, ownerDescription) {
				id = rule.ID
				break
			}
			return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "Cloudflare Gateway rule %q exists without this object's ownership marker", object.Spec.Name)
		}
		if id == "" {
			return api.CreateGatewayRule(ctx, input)
		}
	}
	if !adopting && !object.Status.OwnershipVerified && object.Status.RuleID != "" {
		return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule ID is not verified as owned")
	}
	remote, err := api.GetGatewayRule(ctx, id)
	if err != nil {
		return flarecloudflare.GatewayRule{}, err
	}
	if remote.ReadOnly {
		return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule %q is read-only", id)
	}
	if gatewayRuleMatchesInput(remote, input) {
		return remote, nil
	}
	if !acquiring && !globalOwnedDescription(remote.Description, ownerDescription) {
		return flarecloudflare.GatewayRule{}, privateInvalid("Conflict", "remote Gateway rule %q lost its ownership marker", id)
	}
	if gatewayRuleMatchesInput(remote, input) {
		return remote, nil
	}
	return api.UpdateGatewayRule(ctx, id, input)
}

func gatewayRuleMatchesInput(remote flarecloudflare.GatewayRule, input flarecloudflare.GatewayRuleInput) bool {
	if remote.Name != input.Name || remote.Action != input.Action || remote.Traffic != input.Traffic ||
		!slices.Equal(remote.Filters, input.Filters) {
		return false
	}
	if input.Description != nil && remote.Description != *input.Description {
		return false
	}
	if input.Enabled != nil && remote.Enabled != *input.Enabled {
		return false
	}
	if input.Precedence != nil && remote.Precedence != *input.Precedence {
		return false
	}
	if input.Identity != nil && remote.Identity != *input.Identity {
		return false
	}
	if input.DevicePosture != nil && remote.DevicePosture != *input.DevicePosture {
		return false
	}
	return input.RuleSettings == nil || reflect.DeepEqual(remote.RuleSettings, *input.RuleSettings)
}

func (r *ZeroTrustGatewayPolicyReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy, accountID string) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var list v1alpha1.ZeroTrustGatewayPolicyList
	if err := reader.List(ctx, &list); err != nil {
		return err
	}
	key := client.ObjectKeyFromObject(object)
	identity := gatewayPolicyIdentity(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() ||
			effectiveGlobalManagementPolicy(other.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
			continue
		}
		preserveOwner := other.Status.OwnershipVerified && other.Status.RuleID != ""
		otherAccountID, eligible := globalContenderAccountID(ctx, reader, other.Namespace, other.Spec.AccountRef.Name, other.Status.Conditions, preserveOwner)
		if !eligible || otherAccountID != accountID {
			continue
		}
		if identity != gatewayPolicyIdentity(other) {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if globalObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, key) {
			return privateInvalid("Conflict", "ZeroTrustGatewayPolicy %s is the earlier authorized writer for Cloudflare account ID %q and the same remote rule", otherKey, accountID)
		}
	}
	return nil
}

func gatewayPolicyIdentity(object *v1alpha1.ZeroTrustGatewayPolicy) string {
	if object.Status.RuleID != "" {
		return "id:" + object.Status.RuleID
	}
	if object.Spec.ExternalRef != nil && object.Spec.ExternalRef.RuleID != "" {
		return "id:" + object.Spec.ExternalRef.RuleID
	}
	return "name:" + object.Spec.Name
}

func gatewayRuleInput(state v1alpha1.ZeroTrustGatewayPolicyDesiredState, ownerDescription string) flarecloudflare.GatewayRuleInput {
	filters := make([]flarecloudflare.GatewayRuleFilter, len(state.Filters))
	for i := range state.Filters {
		filters[i] = flarecloudflare.GatewayRuleFilter(state.Filters[i])
	}
	description := ownerDescription
	return flarecloudflare.GatewayRuleInput{Name: state.Name, Description: &description, Enabled: state.Enabled, Precedence: state.Precedence, Filters: filters, Action: string(state.Action), Traffic: state.Traffic, Identity: state.Identity, DevicePosture: state.DevicePosture, RuleSettings: gatewayRuleSettingsInput(state.RuleSettings)}
}

func gatewayRuleSettingsInput(settings *v1alpha1.ZeroTrustGatewayRuleSettings) *flarecloudflare.GatewayRuleSettings {
	if settings == nil {
		return nil
	}
	result := &flarecloudflare.GatewayRuleSettings{BlockPageEnabled: settings.BlockPageEnabled, BlockReason: settings.BlockReason, IgnoreCNAMECategoryMatches: settings.IgnoreCNAMECategoryMatches, InsecureDisableDNSSECValidation: settings.InsecureDisableDNSSECValidation, IPCategories: settings.IPCategories, IPIndicatorFeeds: settings.IPIndicatorFeeds, OverrideHost: settings.OverrideHost}
	if settings.OverrideIPs != nil {
		values := append([]string(nil), settings.OverrideIPs...)
		result.OverrideIPs = &values
	}
	if settings.AuditSSH != nil {
		result.AuditSSH = &flarecloudflare.GatewayRuleAuditSSH{CommandLogging: settings.AuditSSH.CommandLogging}
	}
	if settings.CheckSession != nil {
		result.CheckSession = &flarecloudflare.GatewayRuleCheckSession{Enforce: settings.CheckSession.Enforce, Duration: settings.CheckSession.Duration}
	}
	if settings.L4Override != nil {
		result.L4Override = &flarecloudflare.GatewayRuleL4Override{IP: settings.L4Override.IP, Port: settings.L4Override.Port}
	}
	if settings.Notification != nil {
		result.Notification = &flarecloudflare.GatewayRuleNotification{Enabled: settings.Notification.Enabled, IncludeContext: settings.Notification.IncludeContext, Message: settings.Notification.Message, SupportURL: settings.Notification.SupportURL}
	}
	return result
}

func gatewayRuleObserved(remote flarecloudflare.GatewayRule) v1alpha1.ZeroTrustGatewayPolicyDesiredState {
	filters := make([]v1alpha1.ZeroTrustGatewayFilter, len(remote.Filters))
	for i := range remote.Filters {
		filters[i] = v1alpha1.ZeroTrustGatewayFilter(remote.Filters[i])
	}
	description := globalUserDescription(remote.Description)
	enabled := remote.Enabled
	precedence := remote.Precedence
	identity := remote.Identity
	posture := remote.DevicePosture
	return v1alpha1.ZeroTrustGatewayPolicyDesiredState{Name: remote.Name, Description: &description, Enabled: &enabled, Precedence: &precedence, Filters: filters, Action: v1alpha1.ZeroTrustGatewayAction(remote.Action), Traffic: remote.Traffic, Identity: &identity, DevicePosture: &posture, RuleSettings: gatewayRuleSettingsObserved(remote.RuleSettings)}
}

func gatewayPolicyWouldApply(desired, observed v1alpha1.ZeroTrustGatewayPolicyDesiredState) *v1alpha1.ZeroTrustGatewayPolicyDesiredState {
	changed := desired.Name != observed.Name ||
		!slices.Equal(desired.Filters, observed.Filters) ||
		desired.Action != observed.Action ||
		desired.Traffic != observed.Traffic
	if desired.Description != nil && (observed.Description == nil || *desired.Description != *observed.Description) {
		changed = true
	}
	if desired.Enabled != nil && (observed.Enabled == nil || *desired.Enabled != *observed.Enabled) {
		changed = true
	}
	if desired.Precedence != nil && (observed.Precedence == nil || *desired.Precedence != *observed.Precedence) {
		changed = true
	}
	if desired.Identity != nil && (observed.Identity == nil || *desired.Identity != *observed.Identity) {
		changed = true
	}
	if desired.DevicePosture != nil && (observed.DevicePosture == nil || *desired.DevicePosture != *observed.DevicePosture) {
		changed = true
	}
	if desired.RuleSettings != nil && !reflect.DeepEqual(desired.RuleSettings, observed.RuleSettings) {
		changed = true
	}
	if !changed {
		return nil
	}
	result := desired
	return &result
}

func gatewayRuleSettingsObserved(settings flarecloudflare.GatewayRuleSettings) *v1alpha1.ZeroTrustGatewayRuleSettings {
	result := &v1alpha1.ZeroTrustGatewayRuleSettings{BlockPageEnabled: settings.BlockPageEnabled, BlockReason: settings.BlockReason, IgnoreCNAMECategoryMatches: settings.IgnoreCNAMECategoryMatches, InsecureDisableDNSSECValidation: settings.InsecureDisableDNSSECValidation, IPCategories: settings.IPCategories, IPIndicatorFeeds: settings.IPIndicatorFeeds, OverrideHost: settings.OverrideHost}
	if settings.OverrideIPs != nil {
		result.OverrideIPs = append([]string(nil), (*settings.OverrideIPs)...)
	}
	if settings.AuditSSH != nil {
		result.AuditSSH = &v1alpha1.ZeroTrustGatewayAuditSSH{CommandLogging: settings.AuditSSH.CommandLogging}
	}
	if settings.CheckSession != nil {
		result.CheckSession = &v1alpha1.ZeroTrustGatewayCheckSession{Enforce: settings.CheckSession.Enforce, Duration: settings.CheckSession.Duration}
	}
	if settings.L4Override != nil {
		result.L4Override = &v1alpha1.ZeroTrustGatewayL4Override{IP: settings.L4Override.IP, Port: settings.L4Override.Port}
	}
	if settings.Notification != nil {
		result.Notification = &v1alpha1.ZeroTrustGatewayNotification{Enabled: settings.Notification.Enabled, IncludeContext: settings.Notification.IncludeContext, Message: settings.Notification.Message, SupportURL: settings.Notification.SupportURL}
	}
	if reflect.DeepEqual(result, &v1alpha1.ZeroTrustGatewayRuleSettings{}) {
		return nil
	}
	return result
}
func (r *ZeroTrustGatewayPolicyReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustGatewayPolicyFinalizer) {
		return ctrl.Result{}, nil
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged &&
		effectiveGlobalDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete &&
		object.Status.RuleID != "" && object.Status.OwnershipVerified {
		account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
		if r.NewCloudflareClient == nil {
			return ctrl.Result{}, fmt.Errorf("cloudflare Gateway client factory is required")
		}
		api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
		if err != nil {
			return ctrl.Result{}, err
		}
		remote, err := api.GetGatewayRule(ctx, object.Status.RuleID)
		if err != nil {
			if ignoreRemoteNotFound(err) != nil {
				return ctrl.Result{}, err
			}
		} else {
			ownerDescription, ownerErr := globalOwnerDescription(ctx, r.Client, object, valueOrEmpty(object.Spec.Description))
			if ownerErr != nil {
				return ctrl.Result{}, ownerErr
			}
			if remote.ReadOnly {
				message := fmt.Sprintf("remote Gateway rule %q is read-only; refusing deletion", object.Status.RuleID)
				if patchErr := r.patchCleanupBlocked(ctx, object, "ReadOnly", message); patchErr != nil {
					return ctrl.Result{}, patchErr
				}
				return ctrl.Result{RequeueAfter: globalRequeue}, nil
			}
			if !globalOwnedDescription(remote.Description, ownerDescription) {
				message := fmt.Sprintf("remote Gateway rule %q no longer carries this object's ownership marker; refusing deletion", object.Status.RuleID)
				if patchErr := r.patchCleanupBlocked(ctx, object, "OwnershipLost", message); patchErr != nil {
					return ctrl.Result{}, patchErr
				}
				return ctrl.Result{RequeueAfter: globalRequeue}, nil
			}
			if err = api.DeleteGatewayRule(ctx, object.Status.RuleID); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ZeroTrustGatewayPolicyFinalizer)
	if err := r.Patch(ctx, object, base); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ZeroTrustGatewayPolicyReconciler) patchCleanupBlocked(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		accessCondition(object.Generation, "CleanupBlocked", metav1.ConditionTrue, reason, message),
		accessCondition(object.Generation, v1alpha1.ZeroTrustGatewayPolicyConditionReady, metav1.ConditionFalse, "CleanupBlocked", message),
	)
	return r.Status().Patch(ctx, object, base)
}

func (r *ZeroTrustGatewayPolicyReconciler) finishError(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.GatewayRule{ID: object.Status.RuleID}, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if privateIsValidationError(err) {
		if privateErrorReason(err) == "Pending" {
			return ctrl.Result{RequeueAfter: globalRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustGatewayPolicyReconciler) finishRemoteOrValidationError(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy, err error) (ctrl.Result, error) {
	if privateIsValidationError(err) {
		return r.finishError(ctx, object, err)
	}
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.GatewayRule{ID: object.Status.RuleID}, object.Status.OwnershipVerified, nil, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustGatewayPolicyReconciler) patchStatus(ctx context.Context, object *v1alpha1.ZeroTrustGatewayPolicy, remote flarecloudflare.GatewayRule, owned bool, wouldApply *v1alpha1.ZeroTrustGatewayPolicyDesiredState, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if remote.ID != "" {
		object.Status.RuleID = remote.ID
	}
	if status == metav1.ConditionTrue {
		observed := gatewayRuleObserved(remote)
		object.Status.Observed = &observed
		object.Status.OwnershipVerified = owned
		object.Status.WouldApply = wouldApply
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = globalConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *ZeroTrustGatewayPolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ZeroTrustGatewayPolicy controller and dependency watches.
func (r *ZeroTrustGatewayPolicyReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ZeroTrustGatewayPolicy{}, gatewayPolicyAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ZeroTrustGatewayPolicy).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ZeroTrustGatewayPolicy accountRef: %w", err)
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ZeroTrustGatewayPolicy{}, gatewayPolicyListIndex, func(object client.Object) []string {
		policy := object.(*v1alpha1.ZeroTrustGatewayPolicy)
		result := make([]string, len(policy.Spec.ListRefs))
		for i := range policy.Spec.ListRefs {
			result[i] = policy.Namespace + "/" + policy.Spec.ListRefs[i].Name
		}
		return result
	}); err != nil {
		return fmt.Errorf("index ZeroTrustGatewayPolicy listRefs: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.ZeroTrustGatewayPolicy{}).Watches(&v1alpha1.ZeroTrustGatewayPolicy{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.forAccount)).Watches(&v1alpha1.ZeroTrustList{}, handler.EnqueueRequestsFromMapFunc(r.forList)).Complete(observedReconciler("zero-trust-gateway-policy", r))
}

func (r *ZeroTrustGatewayPolicyReconciler) forWriterChange(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustGatewayPolicyList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func (r *ZeroTrustGatewayPolicyReconciler) forAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustGatewayPolicyList
	if err := r.List(ctx, &list, client.MatchingFields{gatewayPolicyAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}
func (r *ZeroTrustGatewayPolicyReconciler) forList(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustGatewayPolicyList
	if err := r.List(ctx, &list, client.MatchingFields{gatewayPolicyListIndex: object.GetNamespace() + "/" + object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
