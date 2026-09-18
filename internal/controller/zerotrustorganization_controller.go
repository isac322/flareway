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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

const organizationStatusListLimit = 1000

// ZeroTrustOrganizationReconciler owns one account- or zone-scoped organization singleton.
type ZeroTrustOrganizationReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	APIReader           client.Reader
	NewCloudflareClient NewOrganizationCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations;cloudflareaccounts;servicetokens;accesscustompages,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=zerotrustorganizations/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges the ZeroTrustOrganization singleton with Cloudflare.
func (r *ZeroTrustOrganizationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ZeroTrustOrganization)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add ZeroTrustOrganization finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	scope, err := organizationScope(account, object.Spec.Zone)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		if err := r.checkSingleWriter(ctx, object, account.Spec.AccountID, scope); err != nil {
			return r.finishError(ctx, object, err)
		}
	}
	if r.NewCloudflareClient == nil {
		return r.finishError(ctx, object, fmt.Errorf("cloudflare organization client factory is required"))
	}
	api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	input, err := r.resolveOrganizationInput(ctx, object, account, api)
	if err != nil {
		return r.finishError(ctx, object, err)
	}

	observed, err := api.GetAccessOrganization(ctx, scope)
	absent := isRemoteNotFound(err)
	if err != nil && !absent {
		return r.finishRemoteError(ctx, object, err)
	}
	if absent && effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		if object.Spec.AuthDomain == nil || *object.Spec.AuthDomain == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "spec.authDomain is required to create an absent Zero Trust organization"))
		}
		if object.Spec.Name == nil || *object.Spec.Name == "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "spec.name is required to create an absent Zero Trust organization"))
		}
		observed, err = api.CreateAccessOrganization(ctx, scope, flarecloudflare.OrganizationCreateInput{AuthDomain: *object.Spec.AuthDomain, OrganizationInput: input})
		if err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
		absent = false
	}

	var observedDOH *flarecloudflare.OrganizationDOHSettings
	var desiredDOH *flarecloudflare.OrganizationDOHInput
	if object.Spec.DOH != nil {
		if scope.ZoneID != "" {
			return r.finishError(ctx, object, privateInvalid("Invalid", "spec.doh is account-scoped and cannot be used with spec.zone"))
		}
		serviceTokenID, resolveErr := r.resolveOrganizationServiceTokenID(ctx, object, account, api, object.Spec.DOH.ServiceTokenRef)
		if resolveErr != nil {
			return r.finishError(ctx, object, resolveErr)
		}
		desiredDOH = &flarecloudflare.OrganizationDOHInput{ServiceTokenID: serviceTokenID, JWTDuration: object.Spec.DOH.JWTDuration}
		remoteDOH, getErr := api.GetAccessOrganizationDOH(ctx)
		if getErr != nil && !isRemoteNotFound(getErr) {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if getErr == nil {
			observedDOH = &remoteDOH
		}
	}

	organizationWouldApply := organizationDiff(input, observed)
	dohWouldApply := organizationDOHDiff(desiredDOH, observedDOH)
	wouldApply := mergeOrganizationDiff(organizationWouldApply, dohWouldApply)
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if absent {
			observed = flarecloudflare.Organization{}
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, observed, observedDOH, wouldApply, object.Status.ObservedUserRevocationRequest, metav1.ConditionTrue, "Observed", "Zero Trust organization is observed without mutation")
	}

	if organizationWouldApply != nil {
		observed, err = api.UpdateAccessOrganization(ctx, scope, input)
		if err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
	}
	if dohWouldApply != nil {
		updatedDOH, updateErr := api.UpdateAccessOrganizationDOH(ctx, *desiredDOH)
		if updateErr != nil {
			return r.finishRemoteError(ctx, object, updateErr)
		}
		observedDOH = &updatedDOH
	}

	observedRevocation := copyOrganizationTime(object.Status.ObservedUserRevocationRequest)
	if revocation := object.Spec.UserRevocation; organizationUserRevocationRequested(revocation, observedRevocation) {
		// The informer cache can lag the status patch that recorded a previous
		// revocation; re-read status directly so a queued reconcile cannot revoke twice.
		if reader := r.APIReader; reader != nil {
			fresh := new(v1alpha1.ZeroTrustOrganization)
			if err := reader.Get(ctx, request.NamespacedName, fresh); err != nil {
				if apierrors.IsNotFound(err) {
					return ctrl.Result{}, nil
				}
				return r.finishError(ctx, object, err)
			}
			if fresh.UID != object.UID {
				return ctrl.Result{}, nil
			}
			if latest := fresh.Status.ObservedUserRevocationRequest; latest != nil &&
				(observedRevocation == nil || latest.After(observedRevocation.Time)) {
				observedRevocation = copyOrganizationTime(latest)
			}
		}
		if organizationUserRevocationRequested(revocation, observedRevocation) {
			_, revokeErr := api.RevokeAccessOrganizationUser(ctx, scope, flarecloudflare.OrganizationUserRevocationInput{
				Email: revocation.Email, UserUID: revocation.UserUID, Devices: revocation.Devices, WARPSessionReauth: revocation.WARPSessionReauth,
			})
			if revokeErr != nil {
				return r.finishRemoteError(ctx, object, revokeErr)
			}
			observedRevocation = revocation.RequestedAt.DeepCopy()
		}
	}

	if err := r.patchStatus(ctx, object, observed, observedDOH, nil, observedRevocation, metav1.ConditionTrue, "Ready", "Zero Trust organization is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: globalRequeue}, nil
}

func organizationUserRevocationRequested(request *v1alpha1.ZeroTrustOrganizationUserRevocation, observed *metav1.Time) bool {
	return request != nil && request.RequestedAt != nil &&
		(observed == nil || request.RequestedAt.After(observed.Time))
}

func (r *ZeroTrustOrganizationReconciler) resolveOrganizationInput(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, account *v1alpha1.CloudflareAccount, api flarecloudflare.OrganizationAPI) (flarecloudflare.OrganizationInput, error) {
	input := organizationInput(object.Spec)
	if object.Spec.CustomPages == nil {
		return input, nil
	}
	input.CustomPages = &flarecloudflare.OrganizationCustomPagesInput{}
	if ref := object.Spec.CustomPages.Forbidden; ref != nil {
		id, err := r.resolveOrganizationCustomPageID(ctx, object, account, api, *ref)
		if err != nil {
			return flarecloudflare.OrganizationInput{}, fmt.Errorf("resolve forbidden custom page: %w", err)
		}
		input.CustomPages.Forbidden = stringPointerValue(id)
	}
	if ref := object.Spec.CustomPages.IdentityDenied; ref != nil {
		id, err := r.resolveOrganizationCustomPageID(ctx, object, account, api, *ref)
		if err != nil {
			return flarecloudflare.OrganizationInput{}, fmt.Errorf("resolve identity-denied custom page: %w", err)
		}
		input.CustomPages.IdentityDenied = stringPointerValue(id)
	}
	return input, nil
}

func (r *ZeroTrustOrganizationReconciler) resolveOrganizationCustomPageID(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, account *v1alpha1.CloudflareAccount, api flarecloudflare.OrganizationAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetAccessCustomPage(ctx, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external AccessCustomPage: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(object.Namespace, ref)
	if err := authorizeAccessReference(ctx, r.Client, object.Namespace, targetNamespace, account); err != nil {
		return "", err
	}
	var page v1alpha1.AccessCustomPage
	if err := r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &page); err != nil {
		return "", err
	}
	if err := validateAccessReference(object.Namespace, targetNamespace, "AccessCustomPage", account.Name, page.DeletionTimestamp, page.Status.Conditions, page.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if page.Status.CustomPageID == "" {
		return "", fmt.Errorf("referenced AccessCustomPage is not ready")
	}
	return page.Status.CustomPageID, nil
}

func (r *ZeroTrustOrganizationReconciler) resolveOrganizationServiceTokenID(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, account *v1alpha1.CloudflareAccount, api flarecloudflare.OrganizationAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetServiceToken(ctx, flarecloudflare.AccessScope{}, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external ServiceToken: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(object.Namespace, ref)
	if err := authorizeAccessReference(ctx, r.Client, object.Namespace, targetNamespace, account); err != nil {
		return "", err
	}
	var token v1alpha1.ServiceToken
	if err := r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &token); err != nil {
		return "", err
	}
	if err := validateAccessReference(object.Namespace, targetNamespace, "ServiceToken", account.Name, token.DeletionTimestamp, token.Status.Conditions, token.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if token.Spec.Zone != "" {
		return "", privateInvalid("Invalid", "referenced ServiceToken %s/%s is zone-scoped; organization DoH requires an account-scoped token", targetNamespace, token.Name)
	}
	if token.Status.TokenID == "" {
		return "", fmt.Errorf("referenced ServiceToken is not ready")
	}
	return token.Status.TokenID, nil
}

func organizationScope(account *v1alpha1.CloudflareAccount, zoneName string) (flarecloudflare.AccessScope, error) {
	if zoneName == "" {
		return flarecloudflare.AccessScope{}, nil
	}
	for _, zone := range account.Status.Verified.Zones {
		if strings.EqualFold(strings.TrimSuffix(zone.Name, "."), strings.TrimSuffix(zoneName, ".")) {
			if zone.ID == "" {
				return flarecloudflare.AccessScope{}, privateInvalid("Pending", "the Cloudflare zone %q has no verified ID", zoneName)
			}
			return flarecloudflare.AccessScope{ZoneID: zone.ID}, nil
		}
	}
	return flarecloudflare.AccessScope{}, privateInvalid("Invalid", "spec.zone %q is not present in CloudflareAccount %q status.verified.zones", zoneName, account.Name)
}

func (r *ZeroTrustOrganizationReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, accountID string, scope flarecloudflare.AccessScope) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var list v1alpha1.ZeroTrustOrganizationList
	if err := reader.List(ctx, &list); err != nil {
		return err
	}
	key := client.ObjectKeyFromObject(object)
	target := organizationScopeKey(accountID, scope)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() || effectiveGlobalManagementPolicy(other.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
			continue
		}
		otherAccount, eligible, err := globalContenderAccount(ctx, reader, other.Namespace, other.Spec.AccountRef.Name)
		if err != nil {
			return err
		}
		if !eligible || otherAccount.Spec.AccountID != accountID {
			continue
		}
		otherScope, err := organizationScope(otherAccount, other.Spec.Zone)
		if err != nil || organizationScopeKey(accountID, otherScope) != target {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if globalObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, key) {
			return privateInvalid("Conflict", "the ZeroTrustOrganization %s is the earlier authorized writer for Cloudflare scope %q", otherKey, target)
		}
	}
	return nil
}

func organizationScopeKey(accountID string, scope flarecloudflare.AccessScope) string {
	if scope.ZoneID != "" {
		return accountID + "/zones/" + scope.ZoneID
	}
	return accountID + "/account"
}

func organizationInput(spec v1alpha1.ZeroTrustOrganizationSpec) flarecloudflare.OrganizationInput {
	input := flarecloudflare.OrganizationInput{
		Name: spec.Name, SessionDuration: spec.SessionDuration, WARPAuthSessionDuration: spec.WARPAuthSessionDuration,
		AllowAuthenticateViaWARP: spec.AllowAuthenticateViaWARP, AutoRedirectToIdentity: spec.AutoRedirectToIdentity,
		IsUIReadOnly: spec.IsUIReadOnly, UIReadOnlyToggleReason: spec.UIReadOnlyToggleReason,
		DenyUnmatchedRequests: spec.DenyUnmatchedRequests, DenyUnmatchedRequestsExemptedZoneNames: cloneStringSlicePointer(spec.DenyUnmatchedRequestsExemptedZoneNames),
		WARPAuthNonBrowser401: spec.WARPAuthNonBrowser401, UserSeatExpirationInactiveTime: spec.UserSeatExpirationInactiveTime,
		MFARequiredForAllApps: spec.MFARequiredForAllApps,
	}
	if spec.LoginDesign != nil {
		input.LoginDesign = &flarecloudflare.OrganizationLoginDesignInput{
			BackgroundColor: spec.LoginDesign.BackgroundColor, FooterText: spec.LoginDesign.FooterText,
			HeaderText: spec.LoginDesign.HeaderText, LogoPath: spec.LoginDesign.LogoPath, TextColor: spec.LoginDesign.TextColor,
		}
	}
	if spec.MFAConfig != nil {
		input.MFAConfig = &flarecloudflare.OrganizationMFAConfigInput{
			AllowedAuthenticators:      organizationMFAAuthenticatorsInput(spec.MFAConfig.AllowedAuthenticators),
			AMRMatchingSessionDuration: spec.MFAConfig.AMRMatchingSessionDuration, RequiredAAGUIDs: spec.MFAConfig.RequiredAAGUIDs,
			SessionDuration: spec.MFAConfig.SessionDuration,
		}
	}
	if spec.MFAPIVKeyRequirements != nil {
		input.MFAPIVKeyRequirements = &flarecloudflare.OrganizationMFAPIVKeyRequirementsInput{
			PinPolicy:         organizationPIVPinPolicyInput(spec.MFAPIVKeyRequirements.PinPolicy),
			RequireFIPSDevice: spec.MFAPIVKeyRequirements.RequireFIPSDevice,
			SSHKeySizes:       cloneInt64SlicePointer(spec.MFAPIVKeyRequirements.SSHKeySizes),
			SSHKeyTypes:       organizationPIVSSHKeyTypesInput(spec.MFAPIVKeyRequirements.SSHKeyTypes),
			TouchPolicy:       organizationPIVTouchPolicyInput(spec.MFAPIVKeyRequirements.TouchPolicy),
		}
	}
	return input
}

func organizationObserved(remote flarecloudflare.Organization, doh *flarecloudflare.OrganizationDOHSettings) v1alpha1.ZeroTrustOrganizationValues {
	exempted := canonicalLimitedStrings(remote.DenyUnmatchedRequestsExemptedZoneNames, organizationStatusListLimit)
	authenticators := make([]v1alpha1.ZeroTrustOrganizationMFAAuthenticator, len(remote.MFAConfig.AllowedAuthenticators))
	for i, item := range remote.MFAConfig.AllowedAuthenticators {
		authenticators[i] = v1alpha1.ZeroTrustOrganizationMFAAuthenticator(item)
	}
	authenticators = canonicalLimitedOrganizationAuthenticators(authenticators, 5)
	keySizes := canonicalLimitedInt64s(remote.MFAPIVKeyRequirements.SSHKeySizes, 6)
	keyTypes := make([]v1alpha1.ZeroTrustOrganizationPIVSSHKeyType, len(remote.MFAPIVKeyRequirements.SSHKeyTypes))
	for i, item := range remote.MFAPIVKeyRequirements.SSHKeyTypes {
		keyTypes[i] = v1alpha1.ZeroTrustOrganizationPIVSSHKeyType(item)
	}
	keyTypes = canonicalLimitedOrganizationKeyTypes(keyTypes, 3)
	values := v1alpha1.ZeroTrustOrganizationValues{
		Name: stringPointerValue(remote.Name), SessionDuration: stringPointerValue(remote.SessionDuration),
		WARPAuthSessionDuration:  stringPointerValue(remote.WARPAuthSessionDuration),
		AllowAuthenticateViaWARP: boolPointerValue(remote.AllowAuthenticateViaWARP), AutoRedirectToIdentity: boolPointerValue(remote.AutoRedirectToIdentity),
		IsUIReadOnly: boolPointerValue(remote.IsUIReadOnly), UIReadOnlyToggleReason: stringPointerValue(remote.UIReadOnlyToggleReason),
		DenyUnmatchedRequests: boolPointerValue(remote.DenyUnmatchedRequests), DenyUnmatchedRequestsExemptedZoneNames: &exempted,
		WARPAuthNonBrowser401: boolPointerValue(remote.WARPAuthNonBrowser401), UserSeatExpirationInactiveTime: stringPointerValue(remote.UserSeatExpirationInactiveTime),
		CustomPages: &v1alpha1.ZeroTrustOrganizationCustomPageValues{Forbidden: stringPointerValue(remote.CustomPages.Forbidden), IdentityDenied: stringPointerValue(remote.CustomPages.IdentityDenied)},
		LoginDesign: &v1alpha1.ZeroTrustOrganizationLoginDesign{
			BackgroundColor: stringPointerValue(remote.LoginDesign.BackgroundColor), FooterText: stringPointerValue(remote.LoginDesign.FooterText),
			HeaderText: stringPointerValue(remote.LoginDesign.HeaderText), LogoPath: stringPointerValue(remote.LoginDesign.LogoPath), TextColor: stringPointerValue(remote.LoginDesign.TextColor),
		},
		MFAConfig: &v1alpha1.ZeroTrustOrganizationMFAConfig{
			AllowedAuthenticators: &authenticators, AMRMatchingSessionDuration: stringPointerValue(remote.MFAConfig.AMRMatchingSessionDuration),
			RequiredAAGUIDs: stringPointerValue(remote.MFAConfig.RequiredAAGUIDs), SessionDuration: stringPointerValue(remote.MFAConfig.SessionDuration),
		},
		MFAPIVKeyRequirements: &v1alpha1.ZeroTrustOrganizationMFAPIVKeyRequirements{
			PinPolicy: organizationPIVPinPolicyObserved(remote.MFAPIVKeyRequirements.PinPolicy), RequireFIPSDevice: boolPointerValue(remote.MFAPIVKeyRequirements.RequireFIPSDevice),
			SSHKeySizes: &keySizes, SSHKeyTypes: &keyTypes, TouchPolicy: organizationPIVTouchPolicyObserved(remote.MFAPIVKeyRequirements.TouchPolicy),
		},
		MFARequiredForAllApps: boolPointerValue(remote.MFARequiredForAllApps),
	}
	if doh != nil {
		values.DOH = &v1alpha1.ZeroTrustOrganizationDOHValues{ServiceTokenID: stringPointerValue(doh.ServiceTokenID), JWTDuration: stringPointerValue(doh.JWTDuration)}
	}
	return values
}

func organizationDiff(input flarecloudflare.OrganizationInput, remote flarecloudflare.Organization) *v1alpha1.ZeroTrustOrganizationValues {
	diff := &v1alpha1.ZeroTrustOrganizationValues{}
	if differingString(input.Name, remote.Name) {
		diff.Name = input.Name
	}
	if differingString(input.SessionDuration, remote.SessionDuration) {
		diff.SessionDuration = input.SessionDuration
	}
	if differingString(input.WARPAuthSessionDuration, remote.WARPAuthSessionDuration) {
		diff.WARPAuthSessionDuration = input.WARPAuthSessionDuration
	}
	if differingBool(input.AllowAuthenticateViaWARP, remote.AllowAuthenticateViaWARP) {
		diff.AllowAuthenticateViaWARP = input.AllowAuthenticateViaWARP
	}
	if differingBool(input.AutoRedirectToIdentity, remote.AutoRedirectToIdentity) {
		diff.AutoRedirectToIdentity = input.AutoRedirectToIdentity
	}
	if differingBool(input.IsUIReadOnly, remote.IsUIReadOnly) {
		diff.IsUIReadOnly = input.IsUIReadOnly
	}
	if differingString(input.UIReadOnlyToggleReason, remote.UIReadOnlyToggleReason) {
		diff.UIReadOnlyToggleReason = input.UIReadOnlyToggleReason
	}
	if differingBool(input.DenyUnmatchedRequests, remote.DenyUnmatchedRequests) {
		diff.DenyUnmatchedRequests = input.DenyUnmatchedRequests
	}
	if input.DenyUnmatchedRequestsExemptedZoneNames != nil {
		desired := canonicalStrings(*input.DenyUnmatchedRequestsExemptedZoneNames)
		observed := canonicalStrings(remote.DenyUnmatchedRequestsExemptedZoneNames)
		if !slices.Equal(desired, observed) {
			diff.DenyUnmatchedRequestsExemptedZoneNames = &desired
		}
	}
	if differingBool(input.WARPAuthNonBrowser401, remote.WARPAuthNonBrowser401) {
		diff.WARPAuthNonBrowser401 = input.WARPAuthNonBrowser401
	}
	if differingString(input.UserSeatExpirationInactiveTime, remote.UserSeatExpirationInactiveTime) {
		diff.UserSeatExpirationInactiveTime = input.UserSeatExpirationInactiveTime
	}
	if differingBool(input.MFARequiredForAllApps, remote.MFARequiredForAllApps) {
		diff.MFARequiredForAllApps = input.MFARequiredForAllApps
	}
	diff.CustomPages = organizationCustomPagesDiff(input.CustomPages, remote.CustomPages)
	diff.LoginDesign = organizationLoginDesignDiff(input.LoginDesign, remote.LoginDesign)
	diff.MFAConfig = organizationMFAConfigDiff(input.MFAConfig, remote.MFAConfig)
	diff.MFAPIVKeyRequirements = organizationPIVRequirementsDiff(input.MFAPIVKeyRequirements, remote.MFAPIVKeyRequirements)
	if reflect.DeepEqual(diff, &v1alpha1.ZeroTrustOrganizationValues{}) {
		return nil
	}
	return diff
}

func organizationDOHDiff(input *flarecloudflare.OrganizationDOHInput, remote *flarecloudflare.OrganizationDOHSettings) *v1alpha1.ZeroTrustOrganizationDOHValues {
	if input == nil {
		return nil
	}
	result := &v1alpha1.ZeroTrustOrganizationDOHValues{}
	if remote == nil || input.ServiceTokenID != remote.ServiceTokenID {
		result.ServiceTokenID = stringPointerValue(input.ServiceTokenID)
	}
	if input.JWTDuration != nil && (remote == nil || *input.JWTDuration != remote.JWTDuration) {
		result.JWTDuration = input.JWTDuration
	}
	if result.ServiceTokenID == nil && result.JWTDuration == nil {
		return nil
	}
	return result
}

func mergeOrganizationDiff(settings *v1alpha1.ZeroTrustOrganizationValues, doh *v1alpha1.ZeroTrustOrganizationDOHValues) *v1alpha1.ZeroTrustOrganizationValues {
	if settings == nil && doh == nil {
		return nil
	}
	if settings == nil {
		settings = &v1alpha1.ZeroTrustOrganizationValues{}
	}
	settings.DOH = doh
	return settings
}

func organizationCustomPagesDiff(input *flarecloudflare.OrganizationCustomPagesInput, remote flarecloudflare.OrganizationCustomPages) *v1alpha1.ZeroTrustOrganizationCustomPageValues {
	if input == nil {
		return nil
	}
	result := &v1alpha1.ZeroTrustOrganizationCustomPageValues{}
	if desiredString(input.Forbidden) != remote.Forbidden {
		result.Forbidden = stringPointerValue(desiredString(input.Forbidden))
	}
	if desiredString(input.IdentityDenied) != remote.IdentityDenied {
		result.IdentityDenied = stringPointerValue(desiredString(input.IdentityDenied))
	}
	if result.Forbidden == nil && result.IdentityDenied == nil {
		return nil
	}
	return result
}

func organizationLoginDesignDiff(input *flarecloudflare.OrganizationLoginDesignInput, remote flarecloudflare.OrganizationLoginDesign) *v1alpha1.ZeroTrustOrganizationLoginDesign {
	if input == nil {
		return nil
	}
	result := &v1alpha1.ZeroTrustOrganizationLoginDesign{}
	if differingString(input.BackgroundColor, remote.BackgroundColor) {
		result.BackgroundColor = input.BackgroundColor
	}
	if differingString(input.FooterText, remote.FooterText) {
		result.FooterText = input.FooterText
	}
	if differingString(input.HeaderText, remote.HeaderText) {
		result.HeaderText = input.HeaderText
	}
	if differingString(input.LogoPath, remote.LogoPath) {
		result.LogoPath = input.LogoPath
	}
	if differingString(input.TextColor, remote.TextColor) {
		result.TextColor = input.TextColor
	}
	if reflect.DeepEqual(result, &v1alpha1.ZeroTrustOrganizationLoginDesign{}) {
		return nil
	}
	return result
}

func organizationMFAConfigDiff(input *flarecloudflare.OrganizationMFAConfigInput, remote flarecloudflare.OrganizationMFAConfig) *v1alpha1.ZeroTrustOrganizationMFAConfig {
	if input == nil {
		return nil
	}
	result := &v1alpha1.ZeroTrustOrganizationMFAConfig{}
	if input.AllowedAuthenticators != nil {
		desiredAuthenticators := organizationMFAAuthenticatorsObserved(input.AllowedAuthenticators)
		remoteAuthenticators := organizationMFAAuthenticatorsObserved(&remote.AllowedAuthenticators)
		if !slices.Equal(canonicalLimitedOrganizationAuthenticators(desiredAuthenticators, 5), canonicalLimitedOrganizationAuthenticators(remoteAuthenticators, 5)) {
			result.AllowedAuthenticators = &desiredAuthenticators
		}
	}
	if differingString(input.AMRMatchingSessionDuration, remote.AMRMatchingSessionDuration) {
		result.AMRMatchingSessionDuration = input.AMRMatchingSessionDuration
	}
	if differingString(input.RequiredAAGUIDs, remote.RequiredAAGUIDs) {
		result.RequiredAAGUIDs = input.RequiredAAGUIDs
	}
	if differingString(input.SessionDuration, remote.SessionDuration) {
		result.SessionDuration = input.SessionDuration
	}
	if reflect.DeepEqual(result, &v1alpha1.ZeroTrustOrganizationMFAConfig{}) {
		return nil
	}
	return result
}

func organizationPIVRequirementsDiff(input *flarecloudflare.OrganizationMFAPIVKeyRequirementsInput, remote flarecloudflare.OrganizationMFAPIVKeyRequirements) *v1alpha1.ZeroTrustOrganizationMFAPIVKeyRequirements {
	if input == nil {
		return nil
	}
	result := &v1alpha1.ZeroTrustOrganizationMFAPIVKeyRequirements{}
	if input.PinPolicy != nil && *input.PinPolicy != remote.PinPolicy {
		value := v1alpha1.ZeroTrustOrganizationPIVPinPolicy(*input.PinPolicy)
		result.PinPolicy = &value
	}
	if input.RequireFIPSDevice != nil && *input.RequireFIPSDevice != remote.RequireFIPSDevice {
		result.RequireFIPSDevice = boolPointerValue(*input.RequireFIPSDevice)
	}
	if input.SSHKeySizes != nil {
		desiredSizes := canonicalLimitedInt64s(*input.SSHKeySizes, 6)
		if !slices.Equal(desiredSizes, canonicalLimitedInt64s(remote.SSHKeySizes, 6)) {
			result.SSHKeySizes = &desiredSizes
		}
	}
	if input.SSHKeyTypes != nil {
		desiredTypes := organizationPIVSSHKeyTypesObserved(input.SSHKeyTypes)
		remoteTypes := make([]v1alpha1.ZeroTrustOrganizationPIVSSHKeyType, len(remote.SSHKeyTypes))
		for i, item := range remote.SSHKeyTypes {
			remoteTypes[i] = v1alpha1.ZeroTrustOrganizationPIVSSHKeyType(item)
		}
		if !slices.Equal(canonicalLimitedOrganizationKeyTypes(desiredTypes, 3), canonicalLimitedOrganizationKeyTypes(remoteTypes, 3)) {
			result.SSHKeyTypes = &desiredTypes
		}
	}
	if input.TouchPolicy != nil && *input.TouchPolicy != remote.TouchPolicy {
		value := v1alpha1.ZeroTrustOrganizationPIVTouchPolicy(*input.TouchPolicy)
		result.TouchPolicy = &value
	}
	if reflect.DeepEqual(result, &v1alpha1.ZeroTrustOrganizationMFAPIVKeyRequirements{}) {
		return nil
	}
	return result
}

func (r *ZeroTrustOrganizationReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ZeroTrustOrganization) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ZeroTrustOrganizationFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *ZeroTrustOrganizationReconciler) finishError(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.Organization{}, nil, nil, object.Status.ObservedUserRevocationRequest, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
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

func (r *ZeroTrustOrganizationReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.Organization{}, nil, nil, object.Status.ObservedUserRevocationRequest, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *ZeroTrustOrganizationReconciler) patchStatus(ctx context.Context, object *v1alpha1.ZeroTrustOrganization, remote flarecloudflare.Organization, doh *flarecloudflare.OrganizationDOHSettings, wouldApply *v1alpha1.ZeroTrustOrganizationValues, observedRevocation *metav1.Time, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.AuthDomain = remote.AuthDomain
		object.Status.Observed = organizationObserved(remote, doh)
		object.Status.WouldApply = wouldApply
		object.Status.ObservedUserRevocationRequest = copyOrganizationTime(observedRevocation)
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = globalConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *ZeroTrustOrganizationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ZeroTrustOrganization controller and dependency watches.
func (r *ZeroTrustOrganizationReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ZeroTrustOrganization{}, organizationAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ZeroTrustOrganization).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ZeroTrustOrganization accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.ZeroTrustOrganization{}).
		Watches(&v1alpha1.ZeroTrustOrganization{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.forAccount)).
		Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.forOrganizationDependency)).
		Watches(&v1alpha1.AccessCustomPage{}, handler.EnqueueRequestsFromMapFunc(r.forOrganizationDependency)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).
		Complete(observedReconciler("zero-trust-organization", r))
}

func (r *ZeroTrustOrganizationReconciler) forWriterChange(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.allOrganizationRequests(ctx)
}

func (r *ZeroTrustOrganizationReconciler) forOrganizationDependency(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.allOrganizationRequests(ctx)
}

func (r *ZeroTrustOrganizationReconciler) allOrganizationRequests(ctx context.Context) []reconcile.Request {
	var list v1alpha1.ZeroTrustOrganizationList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func (r *ZeroTrustOrganizationReconciler) forAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ZeroTrustOrganizationList
	if err := r.List(ctx, &list, client.MatchingFields{organizationAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func differingString(desired *string, observed string) bool {
	return desired != nil && *desired != observed
}
func differingBool(desired *bool, observed bool) bool { return desired != nil && *desired != observed }
func desiredString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func stringPointerValue(value string) *string { result := value; return &result }
func cloneStringSlicePointer(value *[]string) *[]string {
	if value == nil {
		return nil
	}
	result := slices.Clone(*value)
	return &result
}
func cloneInt64SlicePointer(value *[]int64) *[]int64 {
	if value == nil {
		return nil
	}
	result := slices.Clone(*value)
	return &result
}

func canonicalLimitedStrings(values []string, limit int) []string {
	result := canonicalStrings(values)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
func canonicalLimitedInt64s(values []int64, limit int) []int64 {
	result := slices.Clone(values)
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
func canonicalLimitedOrganizationAuthenticators(values []v1alpha1.ZeroTrustOrganizationMFAAuthenticator, limit int) []v1alpha1.ZeroTrustOrganizationMFAAuthenticator {
	result := slices.Clone(values)
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
func canonicalLimitedOrganizationKeyTypes(values []v1alpha1.ZeroTrustOrganizationPIVSSHKeyType, limit int) []v1alpha1.ZeroTrustOrganizationPIVSSHKeyType {
	result := slices.Clone(values)
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func copyOrganizationTime(value *metav1.Time) *metav1.Time {
	if value == nil {
		return nil
	}
	return value.DeepCopy()
}

func organizationMFAAuthenticatorsInput(values *[]v1alpha1.ZeroTrustOrganizationMFAAuthenticator) *[]flarecloudflare.OrganizationMFAAuthenticator {
	if values == nil {
		return nil
	}
	result := make([]flarecloudflare.OrganizationMFAAuthenticator, len(*values))
	for i, item := range *values {
		result[i] = flarecloudflare.OrganizationMFAAuthenticator(item)
	}
	return &result
}
func organizationMFAAuthenticatorsObserved(values *[]flarecloudflare.OrganizationMFAAuthenticator) []v1alpha1.ZeroTrustOrganizationMFAAuthenticator {
	if values == nil {
		return nil
	}
	result := make([]v1alpha1.ZeroTrustOrganizationMFAAuthenticator, len(*values))
	for i, item := range *values {
		result[i] = v1alpha1.ZeroTrustOrganizationMFAAuthenticator(item)
	}
	return result
}
func organizationPIVPinPolicyInput(value *v1alpha1.ZeroTrustOrganizationPIVPinPolicy) *flarecloudflare.OrganizationPIVPinPolicy {
	if value == nil {
		return nil
	}
	result := flarecloudflare.OrganizationPIVPinPolicy(*value)
	return &result
}
func organizationPIVPinPolicyObserved(value flarecloudflare.OrganizationPIVPinPolicy) *v1alpha1.ZeroTrustOrganizationPIVPinPolicy {
	if value == "" {
		return nil
	}
	result := v1alpha1.ZeroTrustOrganizationPIVPinPolicy(value)
	return &result
}
func organizationPIVSSHKeyTypesInput(values *[]v1alpha1.ZeroTrustOrganizationPIVSSHKeyType) *[]flarecloudflare.OrganizationPIVSSHKeyType {
	if values == nil {
		return nil
	}
	result := make([]flarecloudflare.OrganizationPIVSSHKeyType, len(*values))
	for i, item := range *values {
		result[i] = flarecloudflare.OrganizationPIVSSHKeyType(item)
	}
	return &result
}
func organizationPIVSSHKeyTypesObserved(values *[]flarecloudflare.OrganizationPIVSSHKeyType) []v1alpha1.ZeroTrustOrganizationPIVSSHKeyType {
	if values == nil {
		return nil
	}
	result := make([]v1alpha1.ZeroTrustOrganizationPIVSSHKeyType, len(*values))
	for i, item := range *values {
		result[i] = v1alpha1.ZeroTrustOrganizationPIVSSHKeyType(item)
	}
	return result
}
func organizationPIVTouchPolicyInput(value *v1alpha1.ZeroTrustOrganizationPIVTouchPolicy) *flarecloudflare.OrganizationPIVTouchPolicy {
	if value == nil {
		return nil
	}
	result := flarecloudflare.OrganizationPIVTouchPolicy(*value)
	return &result
}
func organizationPIVTouchPolicyObserved(value flarecloudflare.OrganizationPIVTouchPolicy) *v1alpha1.ZeroTrustOrganizationPIVTouchPolicy {
	if value == "" {
		return nil
	}
	result := v1alpha1.ZeroTrustOrganizationPIVTouchPolicy(value)
	return &result
}
