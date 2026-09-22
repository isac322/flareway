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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
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
	accessStandaloneApplicationAccountIndex = accessAccountIndex + ".standaloneApplication"
	accessStandaloneApplicationPolicyIndex  = ".spec.policies.standaloneApplication"
	accessStandaloneApplicationSecretID     = "flareway.bhyoo.com/access-standalone-application-id"
	accessStandaloneApplicationRequeue      = 2 * time.Second
)

// AccessStandaloneApplicationReconciler manages non-Gateway Cloudflare Access applications.
type AccessStandaloneApplicationReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent

	pendingUpdateMu          sync.Mutex
	pendingUpdateGenerations map[types.UID]standaloneApplicationUpdate
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessstandaloneapplications;accesspolicies;identityproviders;accesscustompages;servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessstandaloneapplications,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessstandaloneapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessstandaloneapplications/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch;create;update;patch;delete

// Reconcile converges one standalone Access application without exposing one-time credentials.
func (r *AccessStandaloneApplicationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.AccessStandaloneApplication)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	r.observeStandaloneApplicationGeneration(object)
	if !object.DeletionTimestamp.IsZero() {
		r.forgetStandaloneApplicationUpdate(object)
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessStandaloneApplicationFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.AccessStandaloneApplicationFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add AccessStandaloneApplication finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	operation := authz.Request{Zone: object.Spec.Zone, PlatformObject: true}
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, operation, r.NewCloudflareClient)
	if err != nil {
		return r.finishError(ctx, object, privateErrorReason(err), err)
	}
	scope, err := accessStandaloneScope(account, object.Spec.Zone)
	if err != nil {
		return r.finishError(ctx, object, "Invalid", err)
	}
	input, err := r.applicationInput(ctx, object, account, api)
	if err != nil {
		var validation accessValidationError
		if errors.As(err, &validation) || standaloneApplicationIsValidationError(err) {
			return r.finishError(ctx, object, accessValidationReason(err), err)
		}
		return r.finishRemoteError(ctx, object, err)
	}

	if effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.ApplicationID == "" {
			return r.finishError(ctx, object, "Invalid", errors.New("management policy ObserveOnly requires externalRef.applicationId"))
		}
		remote, getErr := api.GetAccessApplication(ctx, scope, object.Spec.ExternalRef.ApplicationID)
		if getErr != nil {
			return r.finishRemoteError(ctx, object, getErr)
		}
		if expectationErr := verifyAccessApplicationExpectation(remote, object.Spec.Adoption.Expect); expectationErr != nil {
			return r.finishObserved(ctx, object, remote, scope, metav1.ConditionFalse, "Conflict", expectationErr.Error())
		}
		if !flarecloudflare.AccessApplicationMatchesInput(remote, input) {
			return r.finishObserved(ctx, object, remote, scope, metav1.ConditionFalse, "Drifted", "Standalone Access application differs from the desired state")
		}
		return r.finishObserved(ctx, object, remote, scope, metav1.ConditionTrue, "Observed", "Standalone Access application is observed without mutation")
	}

	// T1 gate: the managed path below reads the remote application before
	// any write. ObserveOnly above stays ungated (safety condition 9).
	// Adoption reads inside ensureManaged are T0 by construction: the gate
	// only opens once status.applicationId is bound and the applied hash
	// matches.
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "AccessStandaloneApplication", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.ApplicationID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}

	remote, secretRef, err := r.ensureManaged(ctx, api, scope, object, input)
	if err != nil {
		if standaloneApplicationIsValidationError(err) {
			return r.finishError(ctx, object, standaloneApplicationErrorReason(err), err)
		}
		return r.finishRemoteError(ctx, object, err)
	}
	if !flarecloudflare.AccessApplicationMatchesInput(remote, input) {
		return ctrl.Result{RequeueAfter: accessStandaloneApplicationRequeue}, r.patchStatus(ctx, object, remote, scope, true, secretRef, metav1.ConditionTrue, metav1.ConditionFalse, "Updating", "Waiting for the updated standalone Access application to be observed", object.Status.AppliedHash, object.Status.AppliedAt)
	}
	if err := r.patchStatus(ctx, object, remote, scope, true, secretRef, metav1.ConditionTrue, metav1.ConditionTrue, "Ready", "Standalone Access application is synchronized", object.Status.AppliedHash, object.Status.AppliedAt); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "AccessStandaloneApplication", request.NamespacedName)
	return ctrl.Result{RequeueAfter: convergedRequeue(r.Freshness, freshness.GradeAuthz, accessStandaloneApplicationRequeue)}, nil
}

func accessStandaloneScope(account *v1alpha1.CloudflareAccount, zoneName string) (flarecloudflare.AccessScope, error) {
	if zoneName == "" {
		return flarecloudflare.AccessScope{}, nil
	}
	wanted := strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, zone := range account.Status.Verified.Zones {
		if strings.ToLower(strings.TrimSuffix(zone.Name, ".")) == wanted {
			return flarecloudflare.AccessScope{ZoneID: zone.ID}, nil
		}
	}
	return flarecloudflare.AccessScope{}, fmt.Errorf("zone %q is not verified for CloudflareAccount %q", zoneName, account.Name)
}

func (r *AccessStandaloneApplicationReconciler) ensureManaged(ctx context.Context, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, object *v1alpha1.AccessStandaloneApplication, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplication, *corev1.LocalObjectReference, error) {
	id := object.Status.ApplicationID
	secretRef, err := r.existingSaaSSecretRef(ctx, object)
	if err != nil {
		return flarecloudflare.AccessApplication{}, nil, err
	}
	if object.Status.SaaS != nil && object.Status.SaaS.ClientSecretRef != nil && secretRef == nil {
		return flarecloudflare.AccessApplication{}, nil, standaloneApplicationInvalid("SecretMissing", "the SaaS client Secret %q is missing; Cloudflare does not return this one-time secret again", object.Status.SaaS.ClientSecretRef.Name)
	}
	if id == "" && secretRef != nil {
		secretID, err := r.recoverApplicationID(ctx, object)
		if err != nil {
			return flarecloudflare.AccessApplication{}, secretRef, err
		}
		id = secretID
	}
	var remote flarecloudflare.AccessApplication
	if id == "" {
		switch {
		case object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID:
			if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.ApplicationID == "" {
				return remote, secretRef, standaloneApplicationInvalid("Invalid", "adoption mode AdoptById requires externalRef.applicationId")
			}
			id = object.Spec.ExternalRef.ApplicationID
			observed, err := api.GetAccessApplication(ctx, scope, id)
			if err != nil {
				return remote, secretRef, err
			}
			if expectationErr := verifyAccessApplicationExpectation(observed, object.Spec.Adoption.Expect); expectationErr != nil {
				return remote, secretRef, standaloneApplicationInvalid("Conflict", "%s", expectationErr)
			}
			remote = observed
		case object.Spec.ExternalRef != nil:
			return remote, secretRef, standaloneApplicationInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
		default:
			if len(input.Tags) != 0 {
				if err := ensureAccessTags(ctx, api, input.Tags...); err != nil {
					return remote, secretRef, err
				}
			}
			created, err := api.CreateAccessApplication(ctx, scope, input)
			if err != nil {
				return remote, secretRef, err
			}
			remote = created.Application
			if remote.ID == "" {
				return remote, secretRef, errors.New("create Access application returned an empty application ID")
			}
			if created.SaaSClientSecret != "" {
				secretRef, err = r.writeSaaSSecret(ctx, object, remote.ID, created.SaaSClientSecret)
				if err != nil {
					return remote, nil, err
				}
			}
			return remote, secretRef, nil
		}
	} else {
		if !object.Status.OwnershipVerified && object.Status.ApplicationID != "" {
			return remote, secretRef, standaloneApplicationInvalid("Conflict", "remote application ID is not verified as owned or adopted")
		}
		observed, err := api.GetAccessApplication(ctx, scope, id)
		if err != nil {
			return remote, secretRef, err
		}
		remote = observed
	}
	if remote.Type != input.Type {
		return remote, secretRef, standaloneApplicationInvalid("Conflict", "remote application type %q does not match immutable desired type %q", remote.Type, input.Type)
	}
	if flarecloudflare.AccessApplicationMatchesInput(remote, input) {
		r.clearStandaloneApplicationUpdate(object)
		return remote, secretRef, nil
	}
	if standaloneApplicationStatusUpdatePending(object) || r.standaloneApplicationGenerationUpdatePending(object) {
		return remote, secretRef, nil
	}
	if len(input.Tags) != 0 {
		if err := ensureAccessTags(ctx, api, input.Tags...); err != nil {
			return remote, secretRef, err
		}
	}
	if _, err := api.UpdateAccessApplication(ctx, scope, id, input); err != nil {
		return remote, secretRef, err
	}
	r.markStandaloneApplicationUpdate(object)
	return remote, secretRef, nil
}

type standaloneApplicationUpdate struct {
	generation          int64
	awaitingObservation bool
}

func standaloneApplicationStatusUpdatePending(_ *v1alpha1.AccessStandaloneApplication) bool {
	return false
}

func (r *AccessStandaloneApplicationReconciler) observeStandaloneApplicationGeneration(object *v1alpha1.AccessStandaloneApplication) {
	if object.UID == "" {
		return
	}
	r.pendingUpdateMu.Lock()
	defer r.pendingUpdateMu.Unlock()
	if pending, found := r.pendingUpdateGenerations[object.UID]; found && pending.generation < object.Generation {
		r.deleteStandaloneApplicationUpdateLocked(object.UID)
	}
}

func (r *AccessStandaloneApplicationReconciler) standaloneApplicationGenerationUpdatePending(object *v1alpha1.AccessStandaloneApplication) bool {
	if object.UID == "" {
		return false
	}
	r.pendingUpdateMu.Lock()
	defer r.pendingUpdateMu.Unlock()
	pending, found := r.pendingUpdateGenerations[object.UID]
	if !found || pending.generation != object.Generation {
		return false
	}
	if pending.awaitingObservation {
		pending.awaitingObservation = false
		r.pendingUpdateGenerations[object.UID] = pending
		return true
	}
	return false
}

func (r *AccessStandaloneApplicationReconciler) markStandaloneApplicationUpdate(object *v1alpha1.AccessStandaloneApplication) {
	if object.UID == "" {
		return
	}
	r.pendingUpdateMu.Lock()
	defer r.pendingUpdateMu.Unlock()
	if r.pendingUpdateGenerations == nil {
		r.pendingUpdateGenerations = make(map[types.UID]standaloneApplicationUpdate)
	}
	r.pendingUpdateGenerations[object.UID] = standaloneApplicationUpdate{
		generation:          object.Generation,
		awaitingObservation: true,
	}
}

func (r *AccessStandaloneApplicationReconciler) clearStandaloneApplicationUpdate(object *v1alpha1.AccessStandaloneApplication) {
	if object.UID == "" {
		return
	}
	r.pendingUpdateMu.Lock()
	defer r.pendingUpdateMu.Unlock()
	if pending, found := r.pendingUpdateGenerations[object.UID]; found && pending.generation <= object.Generation {
		r.deleteStandaloneApplicationUpdateLocked(object.UID)
	}
}

func (r *AccessStandaloneApplicationReconciler) forgetStandaloneApplicationUpdate(object *v1alpha1.AccessStandaloneApplication) {
	if object.UID == "" {
		return
	}
	r.pendingUpdateMu.Lock()
	defer r.pendingUpdateMu.Unlock()
	r.deleteStandaloneApplicationUpdateLocked(object.UID)
}

func (r *AccessStandaloneApplicationReconciler) deleteStandaloneApplicationUpdateLocked(uid types.UID) {
	delete(r.pendingUpdateGenerations, uid)
	if len(r.pendingUpdateGenerations) == 0 {
		r.pendingUpdateGenerations = nil
	}
}

func (r *AccessStandaloneApplicationReconciler) applicationInput(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI) (flarecloudflare.AccessApplicationInput, error) {
	settings := object.Spec.Application
	tags, err := desiredStandaloneAccessTags(object.Spec.Type, settings.Tags)
	if err != nil {
		return flarecloudflare.AccessApplicationInput{}, err
	}
	if object.Spec.Type == v1alpha1.AccessStandaloneApplicationTypeWARP && settings.Name != "" {
		return flarecloudflare.AccessApplicationInput{}, accessValidationError{
			reason:  "UnsupportedField",
			message: "WARP application.name is unsupported; use adoption.expect.name to identify an existing enrollment",
		}
	}
	if object.Spec.Type == v1alpha1.AccessStandaloneApplicationTypeWARP &&
		(effectiveManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly ||
			object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID) &&
		object.Spec.Adoption.Expect.Name == "" {
		return flarecloudflare.AccessApplicationInput{}, accessValidationError{
			reason:  "Invalid",
			message: "WARP ObserveOnly and AdoptById require adoption.expect.name to identify the existing enrollment",
		}
	}
	name := ""
	if object.Spec.Type != v1alpha1.AccessStandaloneApplicationTypeWARP {
		name = settings.Name
		if name == "" {
			generated, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Name)
			if err != nil {
				return flarecloudflare.AccessApplicationInput{}, err
			}
			name = generated
		}
	}
	input := flarecloudflare.AccessApplicationInput{
		Type: flarecloudflare.AccessApplicationType(object.Spec.Type), Name: name,
		SessionDuration: settings.SessionDuration, AllowAuthenticateViaWARP: settings.AllowAuthenticateViaWARP,
		AllowIframe: settings.AllowIframe, SkipInterstitial: settings.SkipInterstitial,
		AutoRedirectToIdentity: settings.AutoRedirectToIdentity, AppLauncherVisible: settings.AppLauncherVisible,
		ServiceAuth401Redirect: settings.ServiceAuth401Redirect, EnableBindingCookie: settings.EnableBindingCookie,
		EagerRedirectCookieSetting: settings.EagerRedirectCookieSetting, HTTPOnlyCookieAttribute: settings.HTTPOnlyCookieAttribute,
		SameSiteCookieAttribute: settings.SameSiteCookieAttribute, PathCookieAttribute: settings.PathCookieAttribute,
		OptionsPreflightBypass: settings.OptionsPreflightBypass, CORSHeaders: settings.CORSHeaders,
		ReadServiceTokensFromHeader: settings.ReadServiceTokensFromHeader, CustomDenyMessage: settings.CustomDenyMessage,
		CustomDenyURL: settings.CustomDenyURL, CustomNonIdentityDenyURL: settings.CustomNonIdentityDenyURL,
		Tags: tags, LogoURL: settings.LogoURL,
		UseClientlessIsolationAppLauncherURL: settings.UseClientlessIsolationAppLauncherURL,
		MFAConfig:                            standaloneMFAConfig(settings.MFAConfig), OAuthConfiguration: standaloneOAuthConfig(settings.OAuthConfiguration),
	}
	input.Policies, err = r.resolveStandalonePolicies(ctx, object, account, api)
	if err != nil {
		return input, err
	}
	input.AllowedIDPs, err = r.resolveStandaloneIDPs(ctx, object.Namespace, account, api, settings.AllowedIDPRefs)
	if err != nil {
		return input, err
	}
	input.CustomPages, err = r.resolveStandaloneCustomPages(ctx, object.Namespace, account, api, settings.CustomPageRefs)
	if err != nil {
		return input, err
	}
	input.SCIMConfig, err = r.resolveStandaloneSCIM(ctx, object.Namespace, account, api, settings.SCIMConfig)
	if err != nil {
		return input, err
	}
	if err := r.applyStandaloneVariant(ctx, object, account, api, &input); err != nil {
		return input, err
	}
	return input, nil
}

func (r *AccessStandaloneApplicationReconciler) applyStandaloneVariant(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, input *flarecloudflare.AccessApplicationInput) error {
	switch object.Spec.Type {
	case v1alpha1.AccessStandaloneApplicationTypeSaaS:
		saas, err := r.saaSInput(ctx, object.Namespace, account, api, object.Spec.SaaS)
		if err != nil {
			return err
		}
		if saas == nil {
			return accessValidationError{reason: "Invalid", message: "saas configuration is required"}
		}
		input.SaaSApp = saas
	case v1alpha1.AccessStandaloneApplicationTypeBookmark:
		input.Domain = object.Spec.Bookmark.URL
		input.LogoURL = object.Spec.Bookmark.LogoURL
	case v1alpha1.AccessStandaloneApplicationTypeInfrastructure:
		input.TargetCriteria = standaloneTargetCriteria(object.Spec.Infrastructure.TargetCriteria)
		policies, err := r.resolveInfrastructurePolicies(ctx, object, account, api)
		if err != nil {
			return err
		}
		input.InfrastructurePolicies = policies
		if object.Spec.Infrastructure.MFAConfig != nil {
			input.MFAConfig = standaloneInfrastructureMFAConfig(object.Spec.Infrastructure.MFAConfig)
		}
	case v1alpha1.AccessStandaloneApplicationTypeAppLauncher:
		input.AppLauncherLogoURL = object.Spec.AppLauncher.AppLauncherLogoURL
		input.BackgroundColor = object.Spec.AppLauncher.BackgroundColor
		input.HeaderBackgroundColor = object.Spec.AppLauncher.HeaderBackgroundColor
		input.SkipAppLauncherLoginPage = object.Spec.AppLauncher.SkipAppLauncherLoginPage
		for _, link := range object.Spec.AppLauncher.FooterLinks {
			input.FooterLinks = append(input.FooterLinks, flarecloudflare.AccessApplicationFooterLink{Name: link.Name, URL: link.URL})
		}
		if design := object.Spec.AppLauncher.LandingPageDesign; design != nil {
			input.LandingPageDesign = &flarecloudflare.AccessApplicationLandingPageDesign{ButtonColor: design.ButtonColor, ButtonTextColor: design.ButtonTextColor, ImageURL: design.ImageURL, Message: design.Message, Title: design.Title}
		}
	case v1alpha1.AccessStandaloneApplicationTypeDashSSO:
		input.Domain = object.Spec.DashSSO.Domain
	case v1alpha1.AccessStandaloneApplicationTypeMCPPortal:
		input.Domain = object.Spec.MCPPortal.Domain
		for _, destination := range object.Spec.MCPPortal.Destinations {
			resolved, err := standaloneDestination(destination)
			if err != nil {
				return err
			}
			input.Destinations = append(input.Destinations, resolved)
		}
	case v1alpha1.AccessStandaloneApplicationTypeWARP, v1alpha1.AccessStandaloneApplicationTypeBISO:
		// These account-level application variants have no required target or Gateway attachment.
	default:
		return accessValidationError{reason: "UnsupportedValue", message: fmt.Sprintf("unsupported standalone application type %q", object.Spec.Type)}
	}
	return nil
}

func standaloneDestination(value v1alpha1.AccessApplicationDestinationSpec) (flarecloudflare.AccessApplicationDestination, error) {
	result := flarecloudflare.AccessApplicationDestination{Type: flarecloudflare.AccessApplicationDestinationType(value.Type)}
	switch value.Type {
	case v1alpha1.AccessApplicationDestinationPublic:
		result.URI = value.Public.URI
	case v1alpha1.AccessApplicationDestinationViaMCPServerPortal:
		result.MCPServerID = value.ViaMCPServerPortal.MCPServerID
	case v1alpha1.AccessApplicationDestinationWorker:
		result.WorkerID = value.Worker.WorkerID
	case v1alpha1.AccessApplicationDestinationPreviewWorker:
		result.WorkerID = value.PreviewWorker.WorkerID
	case v1alpha1.AccessApplicationDestinationAllWorkers, v1alpha1.AccessApplicationDestinationAllPreviewWorkers:
	default:
		return result, accessValidationError{reason: "UnsupportedValue", message: fmt.Sprintf("unsupported MCP portal destination type %q", value.Type)}
	}
	return result, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandalonePolicies(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI) ([]flarecloudflare.AccessApplicationPolicyAttachment, error) {
	result := make([]flarecloudflare.AccessApplicationPolicyAttachment, 0, len(object.Spec.Policies))
	for index, reference := range object.Spec.Policies {
		id, err := r.resolveStandalonePolicy(ctx, object.Namespace, account, api, reference)
		if err != nil {
			return nil, fmt.Errorf("resolve policy %d: %w", index, err)
		}
		result = append(result, flarecloudflare.AccessApplicationPolicyAttachment{ID: id, Precedence: int64(index + 1)})
	}
	return result, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandalonePolicy(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, reference v1alpha1.AccessApplicationPolicyReference) (string, error) {
	if reference.ExternalRef != nil {
		policy, err := api.GetAccessPolicy(ctx, reference.ExternalRef.PolicyID)
		if err != nil {
			if flarecloudflare.IsNotFound(err) {
				return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external AccessPolicy %q was not found: %v", reference.ExternalRef.PolicyID, err)}
			}
			return "", err
		}
		return policy.ID, nil
	}
	if reference.PolicyRef == nil {
		return "", accessValidationError{reason: "Invalid", message: "policy reference is empty"}
	}
	targetNamespace := reference.PolicyRef.Namespace
	if targetNamespace == "" {
		targetNamespace = namespace
	}
	if err := authorizeAccessReference(ctx, r.Client, namespace, targetNamespace, account, "AccessPolicy"); err != nil {
		return "", err
	}
	var policy v1alpha1.AccessPolicy
	if err := r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: reference.PolicyRef.Name}, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("get AccessPolicy %s/%s: %v", targetNamespace, reference.PolicyRef.Name, err)}
		}
		return "", err
	}
	if err := validateAccessReference(namespace, targetNamespace, "AccessPolicy", account.Name, policy.DeletionTimestamp, policy.Status.Conditions, policy.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if policy.Status.PolicyID == "" {
		return "", accessValidationError{reason: "Pending", message: fmt.Sprintf("the AccessPolicy %s/%s is not ready", targetNamespace, policy.Name)}
	}
	return policy.Status.PolicyID, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandaloneIDPs(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, references []v1alpha1.AccessIdentityProviderReference) ([]string, error) {
	result := make([]string, 0, len(references))
	for _, reference := range references {
		id, err := r.resolveStandaloneIDP(ctx, namespace, account, api, reference)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandaloneIDP(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, reference v1alpha1.AccessIdentityProviderReference) (string, error) {
	if reference.ExternalID != "" {
		provider, err := api.GetIdentityProvider(ctx, reference.ExternalID)
		if err != nil {
			if flarecloudflare.IsNotFound(err) {
				return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external IdentityProvider %q was not found: %v", reference.ExternalID, err)}
			}
			return "", err
		}
		return provider.ID, nil
	}
	var provider v1alpha1.IdentityProvider
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, &provider); err != nil {
		if apierrors.IsNotFound(err) {
			return "", accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("get IdentityProvider %s/%s: %v", namespace, reference.Name, err)}
		}
		return "", err
	}
	if err := validateAccessReference(namespace, namespace, "IdentityProvider", account.Name, provider.DeletionTimestamp, provider.Status.Conditions, provider.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if provider.Status.IDPID == "" {
		return "", accessValidationError{reason: "Pending", message: fmt.Sprintf("the IdentityProvider %s/%s is not ready", namespace, provider.Name)}
	}
	return provider.Status.IDPID, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandaloneCustomPages(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, references []v1alpha1.AccessCustomPageReference) ([]string, error) {
	result := make([]string, 0, len(references))
	for _, reference := range references {
		if reference.ExternalID != "" {
			if _, err := api.GetAccessCustomPage(ctx, reference.ExternalID); err != nil {
				if flarecloudflare.IsNotFound(err) {
					return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external AccessCustomPage %q was not found: %v", reference.ExternalID, err)}
				}
				return nil, err
			}
			result = append(result, reference.ExternalID)
			continue
		}
		if reference.ObjectRef == nil {
			return nil, accessValidationError{reason: "Invalid", message: "custom page reference is empty"}
		}
		targetNamespace := reference.ObjectRef.Namespace
		if targetNamespace == "" {
			targetNamespace = namespace
		}
		if err := authorizeAccessReference(ctx, r.Client, namespace, targetNamespace, account, "AccessCustomPage"); err != nil {
			return nil, err
		}
		var page v1alpha1.AccessCustomPage
		if err := r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: reference.ObjectRef.Name}, &page); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("get AccessCustomPage %s/%s: %v", targetNamespace, reference.ObjectRef.Name, err)}
			}
			return nil, err
		}
		if page.Status.CustomPageID == "" {
			return nil, accessValidationError{reason: "Pending", message: fmt.Sprintf("the AccessCustomPage %s/%s is not ready", targetNamespace, page.Name)}
		}
		result = append(result, page.Status.CustomPageID)
	}
	return result, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveInfrastructurePolicies(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI) ([]flarecloudflare.AccessInfrastructurePolicyInput, error) {
	result := make([]flarecloudflare.AccessInfrastructurePolicyInput, 0, len(object.Spec.Infrastructure.Policies))
	for _, policy := range object.Spec.Infrastructure.Policies {
		include, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, policy.Include)
		if err != nil {
			return nil, err
		}
		require, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, policy.Require)
		if err != nil {
			return nil, err
		}
		exclude, err := resolveAccessRules(ctx, r.Client, object.Namespace, account, api, policy.Exclude)
		if err != nil {
			return nil, err
		}
		item := flarecloudflare.AccessInfrastructurePolicyInput{Name: policy.Name, Decision: flarecloudflare.AccessApplicationPolicyDecision(policy.Decision), Include: include, Require: require, Exclude: exclude, MFAConfig: standaloneInfrastructureMFAConfig(policy.MFAConfig)}
		if rules := policy.ConnectionRules; rules != nil && rules.SSH != nil {
			item.ConnectionRules = &flarecloudflare.AccessInfrastructureConnectionRules{SSH: &flarecloudflare.AccessInfrastructureSSHConnectionRules{Usernames: slices.Clone(rules.SSH.Usernames), AllowEmailAlias: rules.SSH.AllowEmailAlias}}
		}
		result = append(result, item)
	}
	return result, nil
}

func standaloneTargetCriteria(values []v1alpha1.AccessTargetCriterion) []flarecloudflare.AccessApplicationTargetCriterion {
	result := make([]flarecloudflare.AccessApplicationTargetCriterion, len(values))
	for i, value := range values {
		result[i] = flarecloudflare.AccessApplicationTargetCriterion{Port: int64(value.Port), Protocol: flarecloudflare.AccessApplicationTargetProtocol(value.Protocol), TargetAttributes: value.TargetAttributes}
	}
	return result
}

func standaloneMFAConfig(value *v1alpha1.AccessApplicationMFAConfig) *flarecloudflare.AccessApplicationMFAConfig {
	if value == nil {
		return nil
	}
	result := &flarecloudflare.AccessApplicationMFAConfig{Disabled: value.MFADisabled, SessionDuration: value.SessionDuration}
	for _, item := range value.AllowedAuthenticators {
		result.AllowedAuthenticators = append(result.AllowedAuthenticators, flarecloudflare.AccessApplicationMFAAuthenticator(item))
	}
	return result
}

func standaloneInfrastructureMFAConfig(value *v1alpha1.AccessInfrastructureMFAConfig) *flarecloudflare.AccessApplicationMFAConfig {
	if value == nil {
		return nil
	}
	result := &flarecloudflare.AccessApplicationMFAConfig{Disabled: value.MFADisabled, SessionDuration: value.SessionDuration}
	for _, item := range value.AllowedAuthenticators {
		result.AllowedAuthenticators = append(result.AllowedAuthenticators, flarecloudflare.AccessApplicationMFAAuthenticator(item))
	}
	return result
}

func standaloneOAuthConfig(value *v1alpha1.AccessApplicationOAuthConfiguration) *flarecloudflare.AccessApplicationOAuthConfiguration {
	if value == nil {
		return nil
	}
	result := &flarecloudflare.AccessApplicationOAuthConfiguration{Enabled: value.Enabled}
	if value.DynamicClientRegistration != nil {
		result.DynamicClientRegistration = &flarecloudflare.AccessApplicationOAuthDynamicClientRegistration{Enabled: value.DynamicClientRegistration.Enabled, AllowAnyOnLocalhost: value.DynamicClientRegistration.AllowAnyOnLocalhost, AllowAnyOnLoopback: value.DynamicClientRegistration.AllowAnyOnLoopback, AllowedURIs: slices.Clone(value.DynamicClientRegistration.AllowedURIs)}
	}
	if value.Grant != nil {
		result.Grant = &flarecloudflare.AccessApplicationOAuthGrant{AccessTokenLifetime: value.Grant.AccessTokenLifetime, SessionDuration: value.Grant.SessionDuration}
	}
	return result
}

func (r *AccessStandaloneApplicationReconciler) saaSInput(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, value *v1alpha1.AccessSaaSApplicationSpec) (*flarecloudflare.AccessSaaSApplicationInput, error) {
	if value == nil {
		return nil, nil
	}
	result := &flarecloudflare.AccessSaaSApplicationInput{AuthType: flarecloudflare.AccessSaaSAuthenticationType(value.AuthType)}
	if oidc := value.OIDC; oidc != nil {
		result.AccessTokenLifetime = oidc.AccessTokenLifetime
		result.AllowPKCEWithoutClientSecret = oidc.AllowPKCEWithoutClientSecret
		result.AppLauncherURL = oidc.AppLauncherURL
		result.GroupFilterRegex = oidc.GroupFilterRegex
		result.PublicKey = oidc.PublicKey
		result.RedirectURIs = slices.Clone(oidc.RedirectURIs)
		for _, grant := range oidc.GrantTypes {
			result.GrantTypes = append(result.GrantTypes, flarecloudflare.AccessSaaSOIDCGrantType(grant))
		}
		for _, scope := range oidc.Scopes {
			result.Scopes = append(result.Scopes, flarecloudflare.AccessSaaSOIDCScope(scope))
		}
		if oidc.HybridAndImplicitOptions != nil {
			result.HybridAndImplicitOptions = &flarecloudflare.AccessSaaSOIDCHybridAndImplicitOptions{ReturnAccessTokenFromAuthorizationEndpoint: oidc.HybridAndImplicitOptions.ReturnAccessTokenFromAuthorizationEndpoint, ReturnIDTokenFromAuthorizationEndpoint: oidc.HybridAndImplicitOptions.ReturnIDTokenFromAuthorizationEndpoint}
		}
		if oidc.RefreshTokenOptions != nil {
			result.RefreshTokenOptions = &flarecloudflare.AccessSaaSOIDCRefreshTokenOptions{Lifetime: oidc.RefreshTokenOptions.Lifetime}
		}
		for _, claim := range oidc.CustomClaims {
			source := &flarecloudflare.AccessSaaSOIDCCustomSource{Name: claim.Source.Name}
			if len(claim.Source.NameByIDP) > 0 {
				source.NameByIDP = map[string]string{}
				for _, mapping := range claim.Source.NameByIDP {
					id, err := r.resolveStandaloneIDP(ctx, namespace, account, api, mapping.IDPRef)
					if err != nil {
						return nil, err
					}
					source.NameByIDP[id] = mapping.SourceName
				}
			}
			result.CustomClaims = append(result.CustomClaims, flarecloudflare.AccessSaaSOIDCCustomClaim{Name: claim.Name, Required: claim.Required, Scope: flarecloudflare.AccessSaaSOIDCScope(claim.Scope), Source: source})
		}
	}
	if saml := value.SAML; saml != nil {
		result.ConsumerServiceURL = saml.ConsumerServiceURL
		result.DefaultRelayState = saml.DefaultRelayState
		result.IdentityProviderEntityID = saml.IDPEntityID
		result.NameIDFormat = flarecloudflare.AccessSaaSNameIDFormat(saml.NameIDFormat)
		result.NameIDTransformJSONata = saml.NameIDTransformJSONata
		result.PublicKey = saml.PublicKey
		result.SAMLAttributeTransformJSONata = saml.SAMLAttributeTransformJSONata
		result.ServiceProviderEntityID = saml.SPEntityID
		result.SSOEndpoint = saml.SSOEndpoint
		for _, attribute := range saml.CustomAttributes {
			source := &flarecloudflare.AccessSaaSSAMLCustomSource{Name: attribute.Source.Name}
			for _, mapping := range attribute.Source.NameByIDP {
				id, err := r.resolveStandaloneIDP(ctx, namespace, account, api, mapping.IDPRef)
				if err != nil {
					return nil, err
				}
				source.NameByIDP = append(source.NameByIDP, flarecloudflare.AccessSaaSSAMLCustomSourceMapping{IdentityProviderID: id, SourceName: mapping.SourceName})
			}
			result.CustomAttributes = append(result.CustomAttributes, flarecloudflare.AccessSaaSSAMLCustomAttribute{FriendlyName: attribute.FriendlyName, Name: attribute.Name, NameFormat: flarecloudflare.AccessSaaSAttributeNameFormat(attribute.NameFormat), Required: attribute.Required, Source: source})
		}
	}
	return result, nil
}

func (r *AccessStandaloneApplicationReconciler) resolveStandaloneSCIM(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, value *v1alpha1.AccessApplicationSCIMConfig) (*flarecloudflare.AccessSCIMConfigInput, error) {
	if value == nil {
		return nil, nil
	}
	idpID, err := r.resolveStandaloneIDP(ctx, namespace, account, api, value.IDPRef)
	if err != nil {
		return nil, err
	}
	result := &flarecloudflare.AccessSCIMConfigInput{IdentityProviderUID: idpID, RemoteURI: value.RemoteURI, DeactivateOnDelete: value.DeactivateOnDelete, Enabled: value.Enabled}
	for _, mapping := range value.Mappings {
		item := flarecloudflare.AccessSCIMMapping{Schema: mapping.Schema, Enabled: mapping.Enabled, Filter: mapping.Filter, Strictness: flarecloudflare.AccessSCIMMappingStrictness(mapping.Strictness), TransformJSONata: mapping.TransformJSONata}
		if mapping.Operations != nil {
			item.Operations = &flarecloudflare.AccessSCIMMappingOperations{Create: mapping.Operations.Create, Update: mapping.Operations.Update, Delete: mapping.Operations.Delete}
		}
		result.Mappings = append(result.Mappings, item)
	}
	if value.Authentication != nil {
		methods := standaloneSCIMMethods(value.Authentication)
		for _, method := range methods {
			resolved, err := r.resolveSCIMMethod(ctx, namespace, account, api, method)
			if err != nil {
				return nil, err
			}
			result.Authentication = append(result.Authentication, resolved)
		}
	}
	return result, nil
}

func standaloneSCIMMethods(value *v1alpha1.AccessSCIMAuthentication) []v1alpha1.AccessSCIMAuthenticationMethod {
	if len(value.Multiple) > 0 {
		return slices.Clone(value.Multiple)
	}
	return []v1alpha1.AccessSCIMAuthenticationMethod{{HTTPBasic: value.HTTPBasic, OAuthBearerToken: value.OAuthBearerToken, OAuth2: value.OAuth2, AccessServiceToken: value.AccessServiceToken}}
}

func (r *AccessStandaloneApplicationReconciler) resolveSCIMMethod(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, method v1alpha1.AccessSCIMAuthenticationMethod) (flarecloudflare.AccessSCIMAuthenticationInput, error) {
	result := flarecloudflare.AccessSCIMAuthenticationInput{}
	switch {
	case method.HTTPBasic != nil:
		result.Scheme, result.User = flarecloudflare.AccessSCIMAuthenticationSchemeHTTPBasic, method.HTTPBasic.User
		value, err := r.readApplicationSecret(ctx, namespace, method.HTTPBasic.PasswordSecretRef)
		result.Password = value
		return result, err
	case method.OAuthBearerToken != nil:
		result.Scheme = flarecloudflare.AccessSCIMAuthenticationSchemeOAuthBearerToken
		value, err := r.readApplicationSecret(ctx, namespace, method.OAuthBearerToken.TokenSecretRef)
		result.Token = value
		return result, err
	case method.OAuth2 != nil:
		result.Scheme, result.AuthorizationURL, result.ClientID, result.TokenURL, result.Scopes = flarecloudflare.AccessSCIMAuthenticationSchemeOAuth2, method.OAuth2.AuthorizationURL, method.OAuth2.ClientID, method.OAuth2.TokenURL, slices.Clone(method.OAuth2.Scopes)
		value, err := r.readApplicationSecret(ctx, namespace, method.OAuth2.ClientSecretRef)
		result.ClientSecret = value
		return result, err
	case method.AccessServiceToken != nil:
		result.Scheme = flarecloudflare.AccessSCIMAuthenticationSchemeAccessServiceToken
		id, err := resolveServiceTokenID(ctx, r.Client, namespace, account, api, v1alpha1.AccessObjectReference{Name: method.AccessServiceToken.ServiceTokenRef.Name, Namespace: method.AccessServiceToken.ServiceTokenRef.Namespace})
		result.Token = id
		return result, err
	default:
		return result, errors.New("the SCIM authentication method is empty")
	}
}

func (r *AccessStandaloneApplicationReconciler) readApplicationSecret(ctx context.Context, namespace string, reference v1alpha1.AccessApplicationSecretKeyReference) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, &secret); err != nil {
		return "", err
	}
	value := trimSecret(secret.Data[reference.Key])
	if value == "" {
		return "", fmt.Errorf("the Secret %s/%s has no non-empty %q key", namespace, reference.Name, reference.Key)
	}
	return value, nil
}

func standaloneSaaSSecretName(object *v1alpha1.AccessStandaloneApplication) string {
	return "saas-client-" + string(object.UID)
}

func (r *AccessStandaloneApplicationReconciler) writeSaaSSecret(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, applicationID, secretValue string) (*corev1.LocalObjectReference, error) {
	name := standaloneSaaSSecretName(object)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: object.Namespace}}
	if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
		return nil, err
	}
	secret.Type = corev1.SecretTypeOpaque
	secret.Annotations = map[string]string{accessStandaloneApplicationSecretID: applicationID}
	secret.Data = map[string][]byte{v1alpha1.AccessStandaloneApplicationClientSecretKey: []byte(secretValue)}
	if err := r.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		var existing corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: name}, &existing); err != nil {
			return nil, err
		}
		if !metav1.IsControlledBy(&existing, object) || existing.Annotations[accessStandaloneApplicationSecretID] != applicationID {
			return nil, fmt.Errorf("the SaaS client Secret %s/%s already exists and is not owned by this application", object.Namespace, name)
		}
	}
	return &corev1.LocalObjectReference{Name: name}, nil
}

func (r *AccessStandaloneApplicationReconciler) existingSaaSSecretRef(ctx context.Context, object *v1alpha1.AccessStandaloneApplication) (*corev1.LocalObjectReference, error) {
	name := standaloneSaaSSecretName(object)
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: name}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return nil, standaloneApplicationInvalid("Conflict", "the SaaS client Secret %s/%s is not controlled by this application", object.Namespace, name)
	}
	return &corev1.LocalObjectReference{Name: name}, nil
}

func (r *AccessStandaloneApplicationReconciler) recoverApplicationID(ctx context.Context, object *v1alpha1.AccessStandaloneApplication) (string, error) {
	var secret corev1.Secret
	name := standaloneSaaSSecretName(object)
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: name}, &secret); err != nil {
		return "", err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return "", errors.New("the SaaS client Secret is not controlled by the application")
	}
	return secret.Annotations[accessStandaloneApplicationSecretID], nil
}

func (r *AccessStandaloneApplicationReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.AccessStandaloneApplication) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.AccessStandaloneApplicationFinalizer) {
		return nil
	}
	if effectiveManagementPolicy(object.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly && effectiveStandaloneDeletionPolicy(object.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete && object.Status.ApplicationID != "" && object.Status.OwnershipVerified {
		api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{Zone: object.Spec.Zone, PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		scope, err := accessStandaloneScope(account, object.Spec.Zone)
		if err != nil {
			return err
		}
		if err := ignoreRemoteNotFound(api.RevokeAccessApplicationTokens(ctx, scope, object.Status.ApplicationID)); err != nil {
			return err
		}
		if err := ignoreRemoteNotFound(api.DeleteAccessApplication(ctx, scope, object.Status.ApplicationID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.AccessStandaloneApplicationFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *AccessStandaloneApplicationReconciler) finishError(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, reason string, err error) (ctrl.Result, error) {
	var validation accessValidationError
	terminal := errors.As(err, &validation) || standaloneApplicationIsValidationError(err)
	if terminal {
		r.clearStandaloneApplicationUpdate(object)
	}
	remote := standaloneApplicationFromStatus(object.Status)
	if patchErr := r.patchStatus(ctx, object, remote, flarecloudflare.AccessScope{ZoneID: object.Status.ZoneID}, object.Status.OwnershipVerified, standaloneStatusSecretRef(object.Status), metav1.ConditionFalse, metav1.ConditionFalse, reason, err.Error(), object.Status.AppliedHash, object.Status.AppliedAt); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if terminal {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *AccessStandaloneApplicationReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, standaloneApplicationFromStatus(object.Status), flarecloudflare.AccessScope{ZoneID: object.Status.ZoneID}, object.Status.OwnershipVerified, standaloneStatusSecretRef(object.Status), metav1.ConditionFalse, metav1.ConditionFalse, "CloudflareError", err.Error(), object.Status.AppliedHash, object.Status.AppliedAt); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *AccessStandaloneApplicationReconciler) finishObserved(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, remote flarecloudflare.AccessApplication, scope flarecloudflare.AccessScope, ready metav1.ConditionStatus, reason, message string) (ctrl.Result, error) {
	owned := object.Status.OwnershipVerified && object.Status.ApplicationID == remote.ID
	return ctrl.Result{}, r.patchStatus(ctx, object, remote, scope, owned, standaloneStatusSecretRef(object.Status), metav1.ConditionTrue, ready, reason, message, object.Status.AppliedHash, object.Status.AppliedAt)
}

func (r *AccessStandaloneApplicationReconciler) patchStatus(ctx context.Context, object *v1alpha1.AccessStandaloneApplication, remote flarecloudflare.AccessApplication, scope flarecloudflare.AccessScope, owned bool, secretRef *corev1.LocalObjectReference, accepted, ready metav1.ConditionStatus, reason, message, appliedHash string, appliedAt *metav1.Time) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.AppliedHash = appliedHash
	object.Status.AppliedAt = appliedAt
	if remote.ID != "" {
		object.Status.ApplicationID = remote.ID
	}
	if remote.Name != "" {
		object.Status.Type = v1alpha1.AccessStandaloneApplicationType(remote.Type)
		object.Status.Name = remote.Name
		object.Status.Domain = remote.Domain
		object.Status.ZoneID = scope.ZoneID
		object.Status.OwnershipVerified = owned
		object.Status.Tags = slices.Clone(remote.Tags)
		object.Status.SaaS, object.Status.Bookmark, object.Status.Infrastructure, object.Status.AppLauncher, object.Status.DashSSO, object.Status.MCPPortal = standaloneVariantStatus(object, remote, secretRef)
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		accessCondition(object.Generation, "Accepted", accepted, reason, message),
		accessCondition(object.Generation, "Ready", ready, reason, message),
	)
	return r.Status().Patch(ctx, object, base)
}

func standaloneVariantStatus(_ *v1alpha1.AccessStandaloneApplication, remote flarecloudflare.AccessApplication, secretRef *corev1.LocalObjectReference) (*v1alpha1.AccessSaaSApplicationStatus, *v1alpha1.AccessBookmarkApplicationStatus, *v1alpha1.AccessInfrastructureApplicationStatus, *v1alpha1.AccessAppLauncherApplicationStatus, *v1alpha1.AccessDashSSOApplicationStatus, *v1alpha1.AccessMCPPortalApplicationStatus) {
	var saas *v1alpha1.AccessSaaSApplicationStatus
	if remote.SaaSApp != nil {
		saas = standaloneSaaSStatus(remote.SaaSApp)
		saas.ClientSecretRef = secretRef
	}
	var bookmark *v1alpha1.AccessBookmarkApplicationStatus
	if remote.Type == flarecloudflare.AccessApplicationTypeBookmark {
		bookmark = &v1alpha1.AccessBookmarkApplicationStatus{URL: remote.Domain, LogoURL: remote.LogoURL}
	}
	var infrastructure *v1alpha1.AccessInfrastructureApplicationStatus
	if remote.Type == flarecloudflare.AccessApplicationTypeInfrastructure {
		infrastructure = &v1alpha1.AccessInfrastructureApplicationStatus{}
		for _, value := range remote.TargetCriteria {
			infrastructure.TargetCriteria = append(infrastructure.TargetCriteria, v1alpha1.AccessTargetCriterionStatus{Port: int32(value.Port), Protocol: string(value.Protocol), TargetAttributes: value.TargetAttributes})
		}
		if remote.MFAConfig != nil {
			infrastructure.MFAConfig = &v1alpha1.AccessInfrastructureMFAStatus{MFADisabled: boolValue(remote.MFAConfig.Disabled), SessionDuration: remote.MFAConfig.SessionDuration}
			for _, authenticator := range remote.MFAConfig.AllowedAuthenticators {
				infrastructure.MFAConfig.AllowedAuthenticators = append(infrastructure.MFAConfig.AllowedAuthenticators, string(authenticator))
			}
		}
	}
	var launcher *v1alpha1.AccessAppLauncherApplicationStatus
	if remote.Type == flarecloudflare.AccessApplicationTypeAppLauncher {
		launcher = &v1alpha1.AccessAppLauncherApplicationStatus{AppLauncherLogoURL: remote.AppLauncherLogoURL, BackgroundColor: remote.BackgroundColor, HeaderBackgroundColor: remote.HeaderBackgroundColor, SkipAppLauncherLoginPage: boolValue(remote.SkipAppLauncherLoginPage)}
		for _, link := range remote.FooterLinks {
			launcher.FooterLinks = append(launcher.FooterLinks, v1alpha1.AccessAppLauncherFooterLinkStatus{Name: link.Name, URL: link.URL})
		}
		if remote.LandingPageDesign != nil {
			launcher.LandingPageDesign = &v1alpha1.AccessAppLauncherLandingPageDesignStatus{ButtonColor: remote.LandingPageDesign.ButtonColor, ButtonTextColor: remote.LandingPageDesign.ButtonTextColor, ImageURL: remote.LandingPageDesign.ImageURL, Message: remote.LandingPageDesign.Message, Title: remote.LandingPageDesign.Title}
		}
	}
	var dash *v1alpha1.AccessDashSSOApplicationStatus
	if remote.Type == flarecloudflare.AccessApplicationTypeDashSSO {
		dash = &v1alpha1.AccessDashSSOApplicationStatus{Domain: remote.Domain}
	}
	var portal *v1alpha1.AccessMCPPortalApplicationStatus
	if remote.Type == flarecloudflare.AccessApplicationTypeMCPPortal {
		portal = &v1alpha1.AccessMCPPortalApplicationStatus{Domain: remote.Domain}
		for _, destination := range remote.Destinations {
			status := v1alpha1.AccessApplicationDestinationStatus{Type: v1alpha1.AccessApplicationDestinationType(destination.Type), URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR, PortRange: destination.PortRange, VNetID: destination.VNetID, MCPServerID: destination.MCPServerID, WorkerID: destination.WorkerID}
			if destination.L4Protocol != "" {
				protocol := v1alpha1.AccessL4Protocol(destination.L4Protocol)
				status.L4Protocol = &protocol
			}
			portal.Destinations = append(portal.Destinations, status)
		}
	}
	return saas, bookmark, infrastructure, launcher, dash, portal
}

func standaloneStatusSecretRef(status v1alpha1.AccessStandaloneApplicationStatus) *corev1.LocalObjectReference {
	if status.SaaS == nil {
		return nil
	}
	return status.SaaS.ClientSecretRef
}

func standaloneSaaSStatus(remote *flarecloudflare.AccessSaaSApplication) *v1alpha1.AccessSaaSApplicationStatus {
	status := &v1alpha1.AccessSaaSApplicationStatus{AuthType: string(remote.AuthType), ClientID: remote.ClientID}
	if remote.AuthType == flarecloudflare.AccessSaaSAuthenticationTypeOIDC {
		oidc := &v1alpha1.AccessSaaSOIDCStatus{
			AccessTokenLifetime:          remote.AccessTokenLifetime,
			AllowPKCEWithoutClientSecret: boolValue(remote.AllowPKCEWithoutClientSecret),
			AppLauncherURL:               remote.AppLauncherURL,
			GroupFilterRegex:             remote.GroupFilterRegex,
			PublicKey:                    remote.PublicKey,
			RedirectURIs:                 slices.Clone(remote.RedirectURIs),
		}
		for _, grant := range remote.GrantTypes {
			oidc.GrantTypes = append(oidc.GrantTypes, string(grant))
		}
		for _, scope := range remote.Scopes {
			oidc.Scopes = append(oidc.Scopes, string(scope))
		}
		if remote.HybridAndImplicitOptions != nil {
			oidc.ReturnAccessTokenFromAuthorizationEndpoint = boolValue(remote.HybridAndImplicitOptions.ReturnAccessTokenFromAuthorizationEndpoint)
			oidc.ReturnIDTokenFromAuthorizationEndpoint = boolValue(remote.HybridAndImplicitOptions.ReturnIDTokenFromAuthorizationEndpoint)
		}
		if remote.RefreshTokenOptions != nil {
			oidc.RefreshTokenLifetime = remote.RefreshTokenOptions.Lifetime
		}
		for _, claim := range remote.CustomClaims {
			item := v1alpha1.AccessSaaSOIDCCustomClaimStatus{Name: claim.Name, Required: boolValue(claim.Required), Scope: string(claim.Scope)}
			if claim.Source != nil {
				item.Source.Name = claim.Source.Name
				item.Source.NameByIDP = cloneStringMap(claim.Source.NameByIDP)
			}
			oidc.CustomClaims = append(oidc.CustomClaims, item)
		}
		status.OIDC = oidc
	}
	if remote.AuthType == flarecloudflare.AccessSaaSAuthenticationTypeSAML {
		saml := &v1alpha1.AccessSaaSSAMLStatus{
			ConsumerServiceURL:            remote.ConsumerServiceURL,
			DefaultRelayState:             remote.DefaultRelayState,
			IDPEntityID:                   remote.IdentityProviderEntityID,
			NameIDFormat:                  string(remote.NameIDFormat),
			NameIDTransformJSONata:        remote.NameIDTransformJSONata,
			PublicKey:                     remote.PublicKey,
			SAMLAttributeTransformJSONata: remote.SAMLAttributeTransformJSONata,
			SPEntityID:                    remote.ServiceProviderEntityID,
			SSOEndpoint:                   remote.SSOEndpoint,
		}
		for _, attribute := range remote.CustomAttributes {
			item := v1alpha1.AccessSaaSSAMLCustomAttributeStatus{FriendlyName: attribute.FriendlyName, Name: attribute.Name, NameFormat: string(attribute.NameFormat), Required: boolValue(attribute.Required)}
			if attribute.Source != nil {
				item.Source.Name = attribute.Source.Name
				item.Source.NameByIDP = make(map[string]string, len(attribute.Source.NameByIDP))
				for _, mapping := range attribute.Source.NameByIDP {
					item.Source.NameByIDP[mapping.IdentityProviderID] = mapping.SourceName
				}
			}
			saml.CustomAttributes = append(saml.CustomAttributes, item)
		}
		status.SAML = saml
	}
	return status
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func standaloneApplicationFromStatus(status v1alpha1.AccessStandaloneApplicationStatus) flarecloudflare.AccessApplication {
	return flarecloudflare.AccessApplication{ID: status.ApplicationID}
}

type standaloneApplicationValidationError struct{ reason, message string }

func (err standaloneApplicationValidationError) Error() string { return err.message }
func standaloneApplicationInvalid(reason, format string, args ...any) error {
	return standaloneApplicationValidationError{reason: reason, message: fmt.Sprintf(format, args...)}
}
func standaloneApplicationIsValidationError(err error) bool {
	var target standaloneApplicationValidationError
	return errors.As(err, &target)
}
func standaloneApplicationErrorReason(err error) string {
	var target standaloneApplicationValidationError
	if errors.As(err, &target) {
		return target.reason
	}
	return "Pending"
}
func effectiveStandaloneDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}
func (r *AccessStandaloneApplicationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers dependency indexes and watches.
func (r *AccessStandaloneApplicationReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.AccessStandaloneApplication{}, accessStandaloneApplicationAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessStandaloneApplication).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessStandaloneApplication accountRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.AccessStandaloneApplication{}, accessStandaloneApplicationPolicyIndex, func(object client.Object) []string {
		application := object.(*v1alpha1.AccessStandaloneApplication)
		keys := make([]string, 0, len(application.Spec.Policies))
		for _, reference := range application.Spec.Policies {
			if reference.PolicyRef != nil {
				namespace := reference.PolicyRef.Namespace
				if namespace == "" {
					namespace = application.Namespace
				}
				keys = append(keys, types.NamespacedName{Namespace: namespace, Name: reference.PolicyRef.Name}.String())
			}
		}
		return keys
	}); err != nil {
		return fmt.Errorf("index AccessStandaloneApplication policy refs: %w", err)
	}
	appBuilder := ctrl.NewControllerManagedBy(manager).For(&v1alpha1.AccessStandaloneApplication{}).Owns(&corev1.Secret{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.standaloneApplicationsForAccount)).Watches(&v1alpha1.AccessPolicy{}, handler.EnqueueRequestsFromMapFunc(r.standaloneApplicationsForPolicy)).Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.allStandaloneApplications)).Watches(&v1alpha1.AccessCustomPage{}, handler.EnqueueRequestsFromMapFunc(r.allStandaloneApplications)).Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.allStandaloneApplications)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allStandaloneApplications))
	if r.SweepEvents != nil {
		appBuilder = appBuilder.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return appBuilder.Complete(observedReconciler("access-standalone-application", r))
}

func (r *AccessStandaloneApplicationReconciler) standaloneApplicationsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listStandaloneApplicationRequests(ctx, client.MatchingFields{accessStandaloneApplicationAccountIndex: object.GetName()})
}
func (r *AccessStandaloneApplicationReconciler) standaloneApplicationsForPolicy(ctx context.Context, object client.Object) []reconcile.Request {
	return r.listStandaloneApplicationRequests(ctx, client.MatchingFields{accessStandaloneApplicationPolicyIndex: client.ObjectKeyFromObject(object).String()})
}
func (r *AccessStandaloneApplicationReconciler) allStandaloneApplications(ctx context.Context, _ client.Object) []reconcile.Request {
	return r.listStandaloneApplicationRequests(ctx)
}
func (r *AccessStandaloneApplicationReconciler) listStandaloneApplicationRequests(ctx context.Context, options ...client.ListOption) []reconcile.Request {
	var list v1alpha1.AccessStandaloneApplicationList
	if err := r.List(ctx, &list, options...); err != nil {
		return nil
	}
	result := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		result = append(result, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return result
}
