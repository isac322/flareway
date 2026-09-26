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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	accessApplicationFieldManager = "flareway-accessapplication"
	accessApplicationRequeue      = 2 * time.Second
	accessApplicationCleanupLimit = 2 * time.Minute

	accessApplicationTargetIndex          = "flareway.accessApplication.target"
	accessApplicationPolicyIndex          = "flareway.accessApplication.policy"
	accessApplicationAccountIndex         = "flareway.accessApplication.account"
	accessApplicationAUDNamespace         = "flareway-system"
	accessApplicationRevocationAnnotation = "flareway.bhyoo.com/access-revocation"
	accessRevocationPublisherUnavailable  = "RevocationPublisherUnavailable"
	accessApplicationPrivateTunnelsLabel  = "flareway.bhyoo.com/private-tunnels-for"
	accessApplicationPrivateTunnelsKey    = "tunnels"
	accessApplicationAUDReadyKey          = "ready"

	accessApplicationConditionAccepted       = "Accepted"
	accessApplicationConditionProgrammed     = "Programmed"
	accessApplicationConditionCleanupBlocked = "CleanupBlocked"
)

// AccessApplicationCloudflareClient provides the Access application operations used by the reconciler.
type AccessApplicationCloudflareClient interface {
	flarecloudflare.AccessApplicationAPI
	flarecloudflare.AccessTagAPI
	flarecloudflare.AccessCustomPageAPI
	GetAccessPolicy(context.Context, string) (flarecloudflare.AccessPolicy, error)
	GetIdentityProvider(context.Context, string) (flarecloudflare.IdentityProvider, error)
}

// NewAccessApplicationCloudflareClient creates one account-scoped remote client.
type NewAccessApplicationCloudflareClient = NewAccessCloudflareClient

// AccessApplicationClientFromFactory adapts the shared production Cloudflare factory.
func AccessApplicationClientFromFactory(factory flarecloudflare.ClientFactory) NewAccessApplicationCloudflareClient {
	return AccessClientFromFactory(factory)
}

// AccessApplicationReconciler owns Access application identity, the private AUD
// handoff Secret, bypass children, policy status, and fail-closed deletion.
type AccessApplicationReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessApplicationCloudflareClient
	OperatorNamespace   string
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accesspolicies;identityproviders;accesscustompages;servicetokens;cloudflareaccounts;cloudflaretunnels,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes;hostnameroutes;virtualnetworks;gatewayclassconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;gatewayclasses;httproutes;referencegrants;backendtlspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces;secrets;services;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch

// Reconcile converges one AccessApplication without exposing its AUD through status or logs.
func (r *AccessApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var application v1alpha1.AccessApplication
	if err := r.Get(ctx, req.NamespacedName, &application); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !application.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &application)
	}
	if !controllerutil.ContainsFinalizer(&application, v1alpha1.AccessApplicationFinalizer) {
		before := application.DeepCopy()
		controllerutil.AddFinalizer(&application, v1alpha1.AccessApplicationFinalizer)
		if err := r.Patch(ctx, &application, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add AccessApplication finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}
	return r.reconcileActive(ctx, &application)
}

type accessApplicationContext struct {
	account     *v1alpha1.CloudflareAccount
	scope       flarecloudflare.AccessScope
	compilation gatewayapi.AccessApplicationCompilation
	gateways    []types.NamespacedName
}

func (r *AccessApplicationReconciler) reconcileActive(ctx context.Context, application *v1alpha1.AccessApplication) (ctrl.Result, error) {
	resolved, err := r.resolveApplication(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !resolved.compilation.Accepted {
		return r.reconcileInvalidation(ctx, application, resolved.compilation)
	}
	if invalid := validateBypassDeclarations(application, resolved.compilation); invalid != nil {
		return r.reconcileInvalidation(ctx, application, *invalid)
	}
	if application.Spec.Application.CORSHeaders != nil {
		conflict, err := r.targetUsesHTTPCORS(ctx, application)
		if err != nil {
			return ctrl.Result{}, err
		}
		if conflict {
			return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Invalid", "Access application corsHeaders conflicts with HTTPRoute CORS filters"))
		}
	}

	remote, err := r.cloudflareClient(ctx, application.Namespace, resolved.account)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "RefNotPermitted", "Cloudflare Access client is unavailable: "+err.Error()))
	}
	policyIDs, err := r.resolvePolicies(ctx, application, resolved.account, remote)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, accessValidationReason(err), err.Error()))
	}
	idpIDs, err := r.resolveIdentityProviders(ctx, application, resolved.account, remote)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, accessValidationReason(err), err.Error()))
	}
	customPageIDs, err := r.resolveCustomPages(ctx, application, resolved.account, remote)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, accessValidationReason(err), err.Error()))
	}
	scimConfig, err := r.resolveApplicationSCIMConfig(ctx, application, resolved.account, remote)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, accessValidationReason(err), err.Error()))
	}

	if _, latched := application.Annotations[accessApplicationRevocationAnnotation]; latched {
		acknowledged, message, reason, err := r.revocationAcknowledged(ctx, application)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !acknowledged {
			status := r.desiredStatus(application, resolved.compilation, application.Status.ApplicationID, application.Status.BypassApplications, false)
			if reason == "" {
				reason = "RevocationPending"
			}
			setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, reason, message, r.now())
			return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
		}
		if err := r.revokeApplicationTokensWithClient(ctx, remote, resolved.scope, application); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.clearRevocationLatch(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	handoffReady, err := r.audHandoffsPresent(ctx, application, resolved.gateways)
	if err != nil {
		return ctrl.Result{}, err
	}
	if applicationProgrammed(application) && !handoffReady {
		if err := r.latchRevocation(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.deleteAUDSecrets(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		status := r.desiredStatus(application, resolved.compilation, application.Status.ApplicationID, application.Status.BypassApplications, false)
		setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, "RevocationPending", "AUD handoff disappeared; waiting for a fresh blocked data-plane version", r.now())
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
	}
	desiredPrivateTunnels, err := r.preparePrivateTunnelLedger(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}

	ownerTag, clusterID, err := r.accessIdentity(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := remoteApplicationInput(application, resolved.compilation.Destinations, policyIDs, idpIDs, customPageIDs, scimConfig, ownerTag)

	// T1 gate: reconcileRemoteApplication reads the remote application
	// before any write. The gate opens only when every precondition holds:
	// status.applicationID is bound, status.appliedHash equals the desired
	// hash computed here, status.appliedAt is inside the Authz TTL, and no
	// sweep invalidation is latched. An unbound or unconverged object —
	// first create, pending adoption, or a spec change — always reads
	// fresh, so adoption and ownership scans inside
	// reconcileRemoteApplication stay T0. Collision precedence between
	// AccessApplications is decided locally in resolveApplication before
	// this point, so the gate can never hide it. ObserveOnly is excluded:
	// observation is the feature (safety condition 9).
	var desiredHash string
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyObserveOnly {
		decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
			Kind: "AccessApplication", Namespace: application.Namespace, Name: application.Name,
			UID: application.UID, RemoteID: application.Status.ApplicationID,
			AccountID: resolved.account.Spec.AccountID, ClusterID: clusterID,
			Spec: struct {
				Spec  any `json:"spec"`
				Input any `json:"input"`
			}{Spec: application.Spec, Input: input},
		}, application.Status.AppliedHash, application.Status.AppliedAt, r.now())
		if decision.Open {
			return ctrl.Result{RequeueAfter: decision.Requeue}, nil
		}
		desiredHash = decision.DesiredHash
	}
	observed, err := r.reconcileRemoteApplication(ctx, remote, resolved.scope, application, input, ownerTag)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Pending", "Remote Access application reconciliation failed: "+err.Error()))
	}
	if application.Status.ApplicationID != observed.ID {
		if err := r.persistParentID(ctx, application, observed.ID); err != nil {
			return ctrl.Result{}, err
		}
		application.Status.ApplicationID = observed.ID
	}
	children, err := r.reconcileBypassApplications(ctx, remote, resolved.scope, application, resolved.compilation.Bypass, ownerTag, clusterID)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Pending", "Remote bypass application reconciliation failed: "+err.Error()))
	}
	if err := r.commitPrivateTunnelLedger(ctx, application, desiredPrivateTunnels); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureAUDSecrets(ctx, application, observed, resolved.gateways); err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Pending", "Access handoff publication failed: "+err.Error()))
	}
	programmed, err := r.forwardingApplied(ctx, application, resolved.compilation)
	if err != nil {
		return ctrl.Result{}, err
	}
	_, ownerTags, _ := r.accessOwnerTags(ctx, application, ownerTag)
	status := r.desiredStatus(application, resolved.compilation, observed.ID, children, programmed)
	applyObservedApplicationStatus(&status, application, resolved.scope, observed, ownerTags)
	if programmed {
		status.AppliedHash = desiredHash
		appliedAt := metav1.NewTime(r.now())
		status.AppliedAt = &appliedAt
		clearGate(r.Invalidator, "AccessApplication", client.ObjectKeyFromObject(application))
	}
	if err := r.patchStatus(ctx, application, status); err != nil {
		return ctrl.Result{}, err
	}
	if !programmed {
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeAuthz)}, nil
}

func (r *AccessApplicationReconciler) reconcileInvalidation(ctx context.Context, application *v1alpha1.AccessApplication, invalid gatewayapi.AccessApplicationCompilation) (ctrl.Result, error) {
	retained := invalid
	if application.Status.ApplicationID != "" || len(application.Status.DataPlanes) > 0 || len(application.Status.Destinations) > 0 {
		retained = statusCompilation(application, invalid)
	}
	if application.Status.ApplicationID == "" && len(application.Status.BypassApplications) == 0 && !applicationProgrammed(application) {
		if err := r.deleteAUDSecrets(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, r.desiredStatus(application, retained, "", nil, false))
	}
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		if err := r.latchRevocation(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.deleteAUDSecrets(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		status := r.desiredStatus(application, retained, application.Status.ApplicationID, application.Status.BypassApplications, false)
		setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, invalid.Reason, invalid.Message, r.now())
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
	}
	if err := r.deleteAUDSecrets(ctx, application); err != nil {
		return ctrl.Result{}, err
	}
	acknowledged, message, reason, err := r.revocationAcknowledged(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}
	status := r.desiredStatus(application, retained, application.Status.ApplicationID, application.Status.BypassApplications, false)
	setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, invalid.Reason, invalid.Message, r.now())
	if !acknowledged {
		cleanupStatus := metav1.ConditionFalse
		if reason != accessRevocationPublisherUnavailable {
			reason = "RevocationPending"
		} else {
			cleanupStatus = metav1.ConditionTrue
		}
		setApplicationStatusCondition(&status, application, accessApplicationConditionCleanupBlocked, cleanupStatus, reason, message, r.now())
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
	}
	if err := r.revokeApplicationTokensAfterHandoff(ctx, application); err != nil {
		return ctrl.Result{}, err
	}
	if targetInfrastructureUnavailable(invalid) &&
		effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged &&
		effectiveDeletionPolicy(application.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete {
		if err := r.deleteManagedRemoteApplications(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.deletePrivateTunnelLedger(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		status.ApplicationID = ""
		status.BypassApplications = nil
		status.Type = ""
		status.OwnershipVerified = false
		status.Domain = ""
		status.ZoneID = ""
		status.Tags = nil
		if err := r.clearRevocationLatch(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
}

// targetInfrastructureUnavailable reports whether the rejection was caused by a
// lost platform target object rather than a configuration or authorization
// problem. Only target loss may delete a managed remote application; every
// other rejection only blocks it.
func targetInfrastructureUnavailable(compilation gatewayapi.AccessApplicationCompilation) bool {
	return compilation.TargetLoss != gatewayapi.AccessTargetLossNone
}

func rejectedFrom(compilation gatewayapi.AccessApplicationCompilation, reason, message string) gatewayapi.AccessApplicationCompilation {
	compilation.Accepted = false
	compilation.Reason = reason
	compilation.Message = message
	return compilation
}

func statusCompilation(application *v1alpha1.AccessApplication, invalid gatewayapi.AccessApplicationCompilation) gatewayapi.AccessApplicationCompilation {
	compilation := gatewayapi.AccessApplicationCompilation{
		Accepted: false, Reason: invalid.Reason, Message: invalid.Message, TargetLoss: invalid.TargetLoss,
		OriginJWTEnforced: application.Spec.OriginJWT.Mode != v1alpha1.AccessOriginJWTModeDisabled,
	}
	for _, destination := range application.Status.Destinations {
		compilation.Destinations = append(compilation.Destinations, gatewayapi.AccessDestination{
			Type: destination.Type, URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR,
			PortRange: destination.PortRange, L4Protocol: cloneAccessL4Protocol(destination.L4Protocol),
			VNetID: destination.VNetID, MCPServerID: destination.MCPServerID, WorkerID: destination.WorkerID,
		})
	}
	for _, dataPlane := range application.Status.DataPlanes {
		compilation.DataPlanes = append(compilation.DataPlanes, gatewayapi.AccessDataPlane{
			Tunnel: dataPlane.Tunnel, Listener: string(dataPlane.Listener),
			ProtectionDomain: dataPlane.ProtectionDomain, EnvoyPort: dataPlane.EnvoyPort,
		})
	}
	for _, ancestor := range application.Status.Ancestors {
		group := ""
		if ancestor.AncestorRef.Group != nil {
			group = string(*ancestor.AncestorRef.Group)
		}
		kind := ""
		if ancestor.AncestorRef.Kind != nil {
			kind = string(*ancestor.AncestorRef.Kind)
		}
		namespace := application.Namespace
		if ancestor.AncestorRef.Namespace != nil {
			namespace = string(*ancestor.AncestorRef.Namespace)
		}
		compilation.Ancestors = append(compilation.Ancestors, gatewayapi.AccessAncestor{
			Group: group, Kind: kind, Namespace: namespace, Name: string(ancestor.AncestorRef.Name),
		})
	}
	return compilation
}

func applicationProgrammed(application *v1alpha1.AccessApplication) bool {
	return gatewaystatus.ConditionTrue(application.Status.Conditions, accessApplicationConditionProgrammed)
}

func setApplicationStatusCondition(status *v1alpha1.AccessApplicationStatus, application *v1alpha1.AccessApplication, conditionType string, conditionStatus metav1.ConditionStatus, reason, message string, now time.Time) {
	transition := metav1.NewTime(now)
	status.Conditions = gatewaystatus.SetCondition(status.Conditions, transition, gatewaystatus.NewCondition(
		conditionType, conditionStatus, reason, message, application.Generation, transition,
	))
}
func (r *AccessApplicationReconciler) resolveApplication(ctx context.Context, application *v1alpha1.AccessApplication) (accessApplicationContext, error) {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(application.Namespace)); err != nil {
		return accessApplicationContext{}, fmt.Errorf("list AccessApplications: %w", err)
	}

	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: application.Spec.AccountRef.Name}, &account); err != nil {
		if apierrors.IsNotFound(err) {
			return accessApplicationContext{
				compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("CloudflareAccount %q was not found", application.Spec.AccountRef.Name)),
			}, nil
		}
		return accessApplicationContext{}, fmt.Errorf("get CloudflareAccount %q: %w", application.Spec.AccountRef.Name, err)
	}
	if !gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
		!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return accessApplicationContext{
			account:     &account,
			compilation: rejectedCompilation("RefNotPermitted", fmt.Sprintf("CloudflareAccount %q is not accepted with valid credentials", account.Name)),
		}, nil
	}
	// The namespace grant is checked before targets are compiled so a denied
	// tenant sees the denial, not a TargetNotFound derived from listeners the
	// same denial rejected.
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, &namespace); err != nil {
		return accessApplicationContext{}, fmt.Errorf("get AccessApplication namespace %q: %w", application.Namespace, err)
	}
	if decision := authz.Evaluate(&account, &namespace, authz.Request{}); !decision.Allowed {
		return accessApplicationContext{
			account:     &account,
			compilation: rejectedCompilation(decision.Reason, decision.Message),
		}, nil
	}
	scope, err := accessApplicationScope(application, &account)
	if err != nil {
		return accessApplicationContext{
			account:     &account,
			compilation: rejectedCompilation("RefNotPermitted", err.Error()),
		}, nil
	}

	gatewayKeys, err := r.targetGatewayKeys(ctx, application)
	if err != nil {
		return accessApplicationContext{
			account: &account, scope: scope,
			compilation: rejectedCompilation("TargetNotFound", err.Error()),
		}, nil
	}
	result := accessApplicationContext{
		account: &account,
		scope:   scope,
		compilation: gatewayapi.AccessApplicationCompilation{
			Accepted: true, Reason: "Accepted", Message: "Access application targets are valid",
		},
		gateways: gatewayKeys,
	}

	privateInputs := gatewayapi.Inputs{CloudflareAccount: &account}
	if len(accessApplicationPrivateDestinations(application)) > 0 {
		privateInputs, err = r.privateAccessInputs(ctx, application, &account)
		if err != nil {
			return accessApplicationContext{}, err
		}
	}
	if len(gatewayKeys) == 0 {
		compiled := gatewayapi.CompileAccessApplication(privateInputs, application)
		result.compilation = compiled
		return result, nil
	}

	for _, gatewayKey := range gatewayKeys {
		var gateway gatewayv1.Gateway
		if err := r.Get(ctx, gatewayKey, &gateway); err != nil {
			if apierrors.IsNotFound(err) {
				result.compilation = rejectedCompilationLoss(fmt.Sprintf("Gateway %s was not found", gatewayKey), gatewayapi.AccessTargetLossGateway)
				return result, nil
			}
			return accessApplicationContext{}, fmt.Errorf("get target Gateway %s: %w", gatewayKey, err)
		}
		if !gateway.DeletionTimestamp.IsZero() {
			result.compilation = rejectedCompilationLoss(fmt.Sprintf("Gateway %s is deleting", gatewayKey), gatewayapi.AccessTargetLossGateway)
			return result, nil
		}
		var gatewayClass gatewayv1.GatewayClass
		if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, &gatewayClass); err != nil {
			if apierrors.IsNotFound(err) {
				result.compilation = rejectedCompilationLoss(fmt.Sprintf("GatewayClass %q was not found", gateway.Spec.GatewayClassName), gatewayapi.AccessTargetLossGatewayClass)
				return result, nil
			}
			return accessApplicationContext{}, fmt.Errorf("get GatewayClass: %w", err)
		}
		if gatewayClass.Spec.ControllerName != gatewayapi.ControllerName {
			result.compilation = rejectedCompilationLoss(fmt.Sprintf("Gateway %s is not managed by Flareway", gatewayKey), gatewayapi.AccessTargetLossGatewayClass)
			return result, nil
		}
		collector := &GatewayReconciler{Client: r.Client, Now: r.Now}
		config, err := collector.loadGatewayClassConfig(ctx, &gatewayClass)
		if err != nil {
			if isGatewayClassConfigInvalid(err) {
				result.compilation = rejectedCompilation("InvalidParameters", err.Error())
				return result, nil
			}
			return accessApplicationContext{}, err
		}
		inputs, _, err := collector.collectInputs(ctx, &gateway, &gatewayClass, config)
		if err != nil {
			return accessApplicationContext{}, err
		}
		tunnel, err := r.gatewayTunnel(ctx, &gateway)
		if err != nil {
			return accessApplicationContext{}, err
		}
		if tunnel == nil {
			result.compilation = rejectedCompilationLoss(fmt.Sprintf("CloudflareTunnel for Gateway %s was not found", gatewayKey), gatewayapi.AccessTargetLossTunnel)
			return result, nil
		}
		if !tunnel.DeletionTimestamp.IsZero() {
			result.compilation = rejectedCompilationLoss(fmt.Sprintf("CloudflareTunnel %s/%s is deleting", tunnel.Namespace, tunnel.Name), gatewayapi.AccessTargetLossTunnel)
			return result, nil
		}
		if tunnel.Spec.AccountRef.Name != account.Name {
			result.compilation = rejectedCompilation("RefNotPermitted", fmt.Sprintf("AccessApplication accountRef %q does not match target account %q", account.Name, tunnel.Spec.AccountRef.Name))
			return result, nil
		}
		inputs.CloudflareTunnel = tunnel
		inputs.CloudflareAccount = &account
		inputs.AccessApplications = slices.Clone(applications.Items)
		inputs.AUDSecrets, err = r.loadAUDSecrets(ctx, applications.Items, gatewayKey)
		if err != nil {
			return accessApplicationContext{}, err
		}
		if err := collector.applyAUDRevocationLatches(ctx, &gateway, tunnel, &inputs); err != nil {
			return accessApplicationContext{}, err
		}
		_, statuses := gatewayapi.Translate(inputs)
		compiled, found := statuses.AccessApplications[client.ObjectKeyFromObject(application)]
		if !found {
			continue
		}
		mergeAccessCompilation(&result.compilation, compiled)
		if !compiled.Accepted {
			result.compilation = compiled
			break
		}
	}
	if len(result.compilation.Destinations) == 0 && result.compilation.Accepted {
		result.compilation = rejectedCompilation("TargetNotFound", "no targetRef or destination resolves to an Access destination")
	}
	return result, nil
}

func (r *AccessApplicationReconciler) privateAccessInputs(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount) (gatewayapi.Inputs, error) {
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return gatewayapi.Inputs{}, fmt.Errorf("list Namespaces for private destinations: %w", err)
	}
	var networkRoutes v1alpha1.NetworkRouteList
	if err := r.List(ctx, &networkRoutes, client.InNamespace(application.Namespace)); err != nil {
		return gatewayapi.Inputs{}, fmt.Errorf("list NetworkRoutes for private destinations: %w", err)
	}
	var hostnameRoutes v1alpha1.HostnameRouteList
	if err := r.List(ctx, &hostnameRoutes, client.InNamespace(application.Namespace)); err != nil {
		return gatewayapi.Inputs{}, fmt.Errorf("list HostnameRoutes for private destinations: %w", err)
	}
	return gatewayapi.Inputs{
		CloudflareAccount: account,
		Namespaces:        namespaces.Items,
		NetworkRoutes:     networkRoutes.Items,
		HostnameRoutes:    hostnameRoutes.Items,
	}, nil
}

func accessApplicationScope(application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount) (flarecloudflare.AccessScope, error) {
	if application.Spec.Zone == "" {
		return flarecloudflare.AccessScope{}, nil
	}
	zoneName := strings.ToLower(strings.TrimSuffix(application.Spec.Zone, "."))
	for _, zone := range account.Status.Verified.Zones {
		if strings.ToLower(strings.TrimSuffix(zone.Name, ".")) == zoneName {
			if zone.ID == "" {
				break
			}
			return flarecloudflare.AccessScope{ZoneID: zone.ID}, nil
		}
	}
	return flarecloudflare.AccessScope{}, fmt.Errorf("zone %q is not verified for CloudflareAccount %q", application.Spec.Zone, account.Name)
}

func accessApplicationScopeForDeletion(application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount) (flarecloudflare.AccessScope, error) {
	if application.Status.ZoneID != "" {
		return flarecloudflare.AccessScope{ZoneID: application.Status.ZoneID}, nil
	}
	return accessApplicationScope(application, account)
}

func accessApplicationPrivateDestinations(application *v1alpha1.AccessApplication) []v1alpha1.AccessPrivateDestinationSpec {
	result := make([]v1alpha1.AccessPrivateDestinationSpec, 0)
	for _, destination := range application.Spec.Destinations {
		if destination.Type == v1alpha1.AccessApplicationDestinationPrivate && destination.Private != nil {
			result = append(result, *destination.Private)
		}
	}
	return result
}

func (r *AccessApplicationReconciler) preparePrivateTunnelLedger(ctx context.Context, application *v1alpha1.AccessApplication) ([]string, error) {
	desired, err := r.currentPrivateTunnelKeys(ctx, application)
	if err != nil {
		return nil, err
	}
	existing, err := r.privateTunnelLedger(ctx, application)
	if err != nil {
		return nil, err
	}
	union := append(slices.Clone(existing), desired...)
	slices.Sort(union)
	union = slices.Compact(union)
	if err := r.setPrivateTunnelLedger(ctx, application, union); err != nil {
		return nil, err
	}
	return desired, nil
}

func (r *AccessApplicationReconciler) commitPrivateTunnelLedger(ctx context.Context, application *v1alpha1.AccessApplication, desired []string) error {
	return r.setPrivateTunnelLedger(ctx, application, desired)
}
func (r *AccessApplicationReconciler) deletePrivateTunnelLedger(ctx context.Context, application *v1alpha1.AccessApplication) error {
	return r.setPrivateTunnelLedger(ctx, application, nil)
}

func (r *AccessApplicationReconciler) currentPrivateTunnelKeys(ctx context.Context, application *v1alpha1.AccessApplication) ([]string, error) {
	privateDestinations := accessApplicationPrivateDestinations(application)
	keys := make([]string, 0, len(privateDestinations))
	for _, destination := range privateDestinations {
		if destination.NetworkRouteRef != nil {
			var route v1alpha1.NetworkRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: destination.NetworkRouteRef.Name}, &route); err != nil {
				return nil, fmt.Errorf("get NetworkRoute for private tunnel ledger: %w", err)
			}
			if key, ok := privateRouteTunnelKey(route.Namespace, route.Spec.TunnelRef); ok {
				keys = append(keys, key)
			}
		}
		if destination.HostnameRouteRef != nil {
			var route v1alpha1.HostnameRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: destination.HostnameRouteRef.Name}, &route); err != nil {
				return nil, fmt.Errorf("get HostnameRoute for private tunnel ledger: %w", err)
			}
			if key, ok := privateRouteTunnelKey(route.Namespace, route.Spec.TunnelRef); ok {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func privateRouteTunnelKey(routeNamespace string, reference v1alpha1.TunnelReference) (string, bool) {
	if reference.Kind != "" && reference.Kind != v1alpha1.TunnelReferenceKindCloudflareTunnel {
		return "", false
	}
	namespace := reference.Namespace
	if namespace == "" {
		namespace = routeNamespace
	}
	return namespace + "/" + reference.Name, true
}

func (r *AccessApplicationReconciler) privateTunnelLedger(ctx context.Context, application *v1alpha1.AccessApplication) ([]string, error) {
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: r.operatorNamespace(), Name: privateTunnelLedgerSecretName(application.UID)}, &secret)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get private tunnel ledger Secret: %w", err)
	}
	if secret.Labels[accessApplicationPrivateTunnelsLabel] != application.Namespace+"--"+application.Name {
		return nil, errors.New("private tunnel ledger Secret has an invalid application label")
	}
	return parsePrivateTunnelKeys(secret.Data[accessApplicationPrivateTunnelsKey])
}

func parsePrivateTunnelKeys(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("private tunnel ledger is empty")
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("decode private tunnel ledger: %w", err)
	}
	for _, key := range keys {
		namespace, name, found := strings.Cut(key, "/")
		if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("private tunnel ledger contains invalid key %q", key)
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func privateTunnelLedgerSecretName(uid types.UID) string {
	return "private-tunnels-" + string(uid)
}

func (r *AccessApplicationReconciler) setPrivateTunnelLedger(ctx context.Context, application *v1alpha1.AccessApplication, keys []string) error {
	slices.Sort(keys)
	keys = slices.Compact(keys)
	current, err := r.privateTunnelLedger(ctx, application)
	if err != nil && !strings.Contains(err.Error(), "ledger is empty") {
		return err
	}
	if slices.Equal(current, keys) {
		return nil
	}
	key := types.NamespacedName{Namespace: r.operatorNamespace(), Name: privateTunnelLedgerSecretName(application.UID)}
	var secret corev1.Secret
	getErr := r.Get(ctx, key, &secret)
	if len(keys) == 0 {
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			return fmt.Errorf("get private tunnel ledger Secret for deletion: %w", getErr)
		}
		if err := r.Delete(ctx, &secret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete private tunnel ledger Secret: %w", err)
		}
		return nil
	}
	payload, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("encode private tunnel ledger: %w", err)
	}
	labels := map[string]string{accessApplicationPrivateTunnelsLabel: application.Namespace + "--" + application.Name}
	if apierrors.IsNotFound(getErr) {
		secret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, Labels: labels},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{accessApplicationPrivateTunnelsKey: payload},
		}
		if err := r.Create(ctx, &secret); err != nil {
			return fmt.Errorf("create private tunnel ledger Secret: %w", err)
		}
		return nil
	}
	if getErr != nil {
		return fmt.Errorf("get private tunnel ledger Secret: %w", getErr)
	}
	before := secret.DeepCopy()
	secret.Labels = labels
	secret.Type = corev1.SecretTypeOpaque
	secret.Data = map[string][]byte{accessApplicationPrivateTunnelsKey: payload}
	if err := r.Patch(ctx, &secret, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("update private tunnel ledger Secret: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) targetGatewayKeys(ctx context.Context, application *v1alpha1.AccessApplication) ([]types.NamespacedName, error) {
	keys := make(map[types.NamespacedName]struct{})
	for _, target := range application.Spec.TargetRefs {
		group := string(target.Group)
		if group == "" {
			group = "gateway.networking.k8s.io"
		}
		kind := string(target.Kind)
		if kind == "" {
			kind = "Gateway"
		}
		if group != "gateway.networking.k8s.io" {
			return nil, fmt.Errorf("unsupported targetRef group %q", group)
		}
		switch kind {
		case "Gateway":
			keys[types.NamespacedName{Namespace: application.Namespace, Name: string(target.Name)}] = struct{}{}
		case "HTTPRoute":
			var route gatewayv1.HTTPRoute
			key := types.NamespacedName{Namespace: application.Namespace, Name: string(target.Name)}
			if err := r.Get(ctx, key, &route); err != nil {
				return nil, fmt.Errorf("the HTTPRoute %s was not found", key)
			}
			for _, parent := range route.Spec.ParentRefs {
				parentGroup := "gateway.networking.k8s.io"
				if parent.Group != nil && *parent.Group != "" {
					parentGroup = string(*parent.Group)
				}
				parentKind := "Gateway"
				if parent.Kind != nil && *parent.Kind != "" {
					parentKind = string(*parent.Kind)
				}
				parentNamespace := route.Namespace
				if parent.Namespace != nil {
					parentNamespace = string(*parent.Namespace)
				}
				if parentGroup == "gateway.networking.k8s.io" && parentKind == "Gateway" && parentNamespace == application.Namespace {
					keys[types.NamespacedName{Namespace: parentNamespace, Name: string(parent.Name)}] = struct{}{}
				}
			}
		default:
			return nil, fmt.Errorf("unsupported targetRef kind %q", kind)
		}
	}
	result := make([]types.NamespacedName, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	slices.SortFunc(result, func(left, right types.NamespacedName) int { return strings.Compare(left.String(), right.String()) })
	return result, nil
}

func (r *AccessApplicationReconciler) gatewayTunnel(ctx context.Context, gateway *gatewayv1.Gateway) (*v1alpha1.CloudflareTunnel, error) {
	name := gateway.Name
	if gateway.Spec.Infrastructure != nil && gateway.Spec.Infrastructure.ParametersRef != nil {
		ref := gateway.Spec.Infrastructure.ParametersRef
		if string(ref.Group) == v1alpha1.Group && string(ref.Kind) == "CloudflareTunnel" {
			name = string(ref.Name)
		}
	}
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: name}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get CloudflareTunnel: %w", err)
	}
	return &tunnel, nil
}

func (r *AccessApplicationReconciler) targetUsesHTTPCORS(ctx context.Context, application *v1alpha1.AccessApplication) (bool, error) {
	for _, target := range application.Spec.TargetRefs {
		group := string(target.Group)
		if group == "" {
			group = "gateway.networking.k8s.io"
		}
		kind := string(target.Kind)
		if kind == "" {
			kind = "Gateway"
		}
		if group != "gateway.networking.k8s.io" {
			continue
		}
		switch kind {
		case "HTTPRoute":
			var route gatewayv1.HTTPRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: string(target.Name)}, &route); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return false, fmt.Errorf("get HTTPRoute for CORS validation: %w", err)
			}
			if routeRulesUseCORS(&route, target.SectionName) {
				return true, nil
			}
		case "Gateway":
			var routes gatewayv1.HTTPRouteList
			if err := r.List(ctx, &routes, client.InNamespace(application.Namespace)); err != nil {
				return false, fmt.Errorf("list HTTPRoutes for Gateway CORS validation: %w", err)
			}
			for index := range routes.Items {
				if routeParentUsesSection(&routes.Items[index], string(target.Name), target.SectionName) && routeRulesUseCORS(&routes.Items[index], nil) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func routeRulesUseCORS(route *gatewayv1.HTTPRoute, section *gatewayv1.SectionName) bool {
	for ruleIndex := range route.Spec.Rules {
		rule := &route.Spec.Rules[ruleIndex]
		if section != nil && (rule.Name == nil || *rule.Name != *section) {
			continue
		}
		for _, filter := range rule.Filters {
			if filter.Type == gatewayv1.HTTPRouteFilterCORS {
				return true
			}
		}
	}
	return false
}

func routeParentUsesSection(route *gatewayv1.HTTPRoute, gatewayName string, section *gatewayv1.SectionName) bool {
	for _, parent := range route.Spec.ParentRefs {
		group := "gateway.networking.k8s.io"
		if parent.Group != nil && *parent.Group != "" {
			group = string(*parent.Group)
		}
		kind := "Gateway"
		if parent.Kind != nil && *parent.Kind != "" {
			kind = string(*parent.Kind)
		}
		namespace := route.Namespace
		if parent.Namespace != nil {
			namespace = string(*parent.Namespace)
		}
		if group != "gateway.networking.k8s.io" || kind != "Gateway" || namespace != route.Namespace || string(parent.Name) != gatewayName {
			continue
		}
		if section == nil || parent.SectionName == nil || *parent.SectionName == *section {
			return true
		}
	}
	return false
}

func (r *AccessApplicationReconciler) loadAUDSecrets(ctx context.Context, applications []v1alpha1.AccessApplication, gatewayKey types.NamespacedName) (map[types.NamespacedName]gatewayapi.AUDSecret, error) {
	var gateway gatewayv1.Gateway
	if err := r.Get(ctx, gatewayKey, &gateway); err != nil {
		return nil, fmt.Errorf("get Gateway %s for Access AUD Secrets: %w", gatewayKey, err)
	}
	secrets, err := listAUDSecretsForGateway(ctx, r.Client, r.operatorNamespace(), &gateway)
	if err != nil {
		return nil, fmt.Errorf("list Access AUD Secrets for Gateway %s: %w", gatewayKey, err)
	}
	if err := migrateLegacyAUDSecrets(ctx, r.Client, secrets, applications, &gateway); err != nil {
		return nil, fmt.Errorf("migrate Access AUD Secrets for Gateway %s: %w", gatewayKey, err)
	}
	return verifiedAUDSecrets(secrets, applications, &gateway), nil
}

func (r *AccessApplicationReconciler) cloudflareClient(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount) (AccessApplicationCloudflareClient, error) {
	if account == nil {
		return nil, errors.New("the AccessApplication has no resolved CloudflareAccount")
	}
	remote, _, err := accessClientForAccount(ctx, r.Client, namespace, account.Name, authz.Request{}, r.NewCloudflareClient)
	if err != nil {
		return nil, err
	}
	return remote, nil
}

func (r *AccessApplicationReconciler) ensureAUDSecrets(ctx context.Context, application *v1alpha1.AccessApplication, remote flarecloudflare.AccessApplication, gatewayKeys []types.NamespacedName) error {
	if len(gatewayKeys) > 0 && application.Spec.OriginJWT.Mode != v1alpha1.AccessOriginJWTModeDisabled && remote.AUD == "" {
		return errors.New("cloudflare Access application response did not include an AUD")
	}
	if len(gatewayKeys) > 0 && (application.UID == "" || remote.ID == "") {
		return errors.New("cannot publish Access AUD Secrets without application UID and application ID")
	}
	gateways := make([]gatewayv1.Gateway, len(gatewayKeys))
	desiredNames := make(map[string]struct{}, len(gatewayKeys))
	for index, gatewayKey := range gatewayKeys {
		if err := r.Get(ctx, gatewayKey, &gateways[index]); err != nil {
			return fmt.Errorf("get Gateway %s for Access AUD Secret: %w", gatewayKey, err)
		}
		if gateways[index].UID == "" {
			return fmt.Errorf("cannot publish Access AUD Secret for Gateway %s without a UID", gatewayKey)
		}
		desiredNames[accessAUDSecretName(application, gatewayKey)] = struct{}{}
	}
	existing, err := r.listApplicationAUDSecrets(ctx, application)
	if err != nil {
		return fmt.Errorf("list existing Access AUD Secrets: %w", err)
	}
	for index := range existing {
		secret := &existing[index]
		if !audSecretOwnedByApplication(secret, application) {
			continue
		}
		if _, retained := desiredNames[secret.Name]; retained {
			continue
		}
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale Access AUD Secret %s: %w", secret.Name, err)
		}
	}
	applicationKey := client.ObjectKeyFromObject(application)
	for index := range gateways {
		gateway := &gateways[index]
		gatewayKey := client.ObjectKeyFromObject(gateway)
		labels := map[string]string{
			v1alpha1.AccessApplicationAUDSecretLabel:  applicationAUDIdentityLabel(application),
			v1alpha1.AccessApplicationGatewayAUDLabel: gatewayAUDIdentityLabel(gateway),
		}
		secretKey := accessAUDSecretKey(r.operatorNamespace(), application, gatewayKey)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace, Labels: labels},
			Type:       corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				v1alpha1.AccessApplicationAUDSecretKey:                   []byte(remote.AUD),
				v1alpha1.AccessApplicationIDSecretKey:                    []byte(remote.ID),
				v1alpha1.AccessApplicationNamespacedNameSecretKey:        []byte(applicationKey.String()),
				v1alpha1.AccessApplicationUIDSecretKey:                   []byte(application.UID),
				v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey: []byte(gatewayKey.String()),
				v1alpha1.AccessApplicationGatewayUIDSecretKey:            []byte(gateway.UID),
				accessApplicationAUDReadyKey:                             []byte("true"),
			},
		}
		var current corev1.Secret
		key := client.ObjectKeyFromObject(secret)
		if err := r.Get(ctx, key, &current); err != nil {
			if apierrors.IsNotFound(err) {
				if err := r.Create(ctx, secret); err != nil {
					return fmt.Errorf("create Access AUD Secret for Gateway %s: %w", gatewayKey, err)
				}
				continue
			}
			return fmt.Errorf("get Access AUD Secret for Gateway %s: %w", gatewayKey, err)
		}
		if !audSecretOwnedByApplication(&current, application) {
			return fmt.Errorf("access AUD Secret %s is not owned by AccessApplication %s", key, applicationKey)
		}
		before := current.DeepCopy()
		current.Labels = labels
		current.Type = secret.Type
		current.Data = secret.Data
		if err := r.Patch(ctx, &current, client.MergeFrom(before)); err != nil {
			return fmt.Errorf("update Access AUD Secret for Gateway %s: %w", gatewayKey, err)
		}
	}
	return nil
}

func accessAUDSecretName(application *v1alpha1.AccessApplication, gateway types.NamespacedName) string {
	sum := sha256.Sum256([]byte(gateway.String()))
	return fmt.Sprintf("aud-%s-%x", application.UID, sum[:6])
}

func accessAUDSecretKey(operatorNamespace string, application *v1alpha1.AccessApplication, gateway types.NamespacedName) types.NamespacedName {
	return types.NamespacedName{
		Namespace: operatorNamespace,
		Name:      accessAUDSecretName(application, gateway),
	}
}

func (r *AccessApplicationReconciler) listApplicationAUDSecrets(ctx context.Context, application *v1alpha1.AccessApplication) ([]corev1.Secret, error) {
	labelValues := []string{applicationAUDIdentityLabel(application)}
	legacyLabel := application.Namespace + "--" + application.Name
	if len(legacyLabel) <= 63 {
		labelValues = append(labelValues, legacyLabel)
	}
	secrets := make([]corev1.Secret, 0)
	seen := make(map[types.NamespacedName]struct{})
	for _, labelValue := range labelValues {
		var listed corev1.SecretList
		if err := r.List(ctx, &listed,
			client.InNamespace(r.operatorNamespace()),
			client.MatchingLabels{v1alpha1.AccessApplicationAUDSecretLabel: labelValue},
		); err != nil {
			return nil, err
		}
		for index := range listed.Items {
			key := client.ObjectKeyFromObject(&listed.Items[index])
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			secrets = append(secrets, listed.Items[index])
		}
	}
	return secrets, nil
}

func audSecretOwnedByApplication(secret *corev1.Secret, application *v1alpha1.AccessApplication) bool {
	if secret == nil || application == nil || application.UID == "" ||
		!strings.HasPrefix(secret.Name, "aud-"+string(application.UID)+"-") {
		return false
	}
	label := secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]
	if label != applicationAUDIdentityLabel(application) && label != application.Namespace+"--"+application.Name {
		return false
	}
	applicationKey := client.ObjectKeyFromObject(application).String()
	if boundKey := string(secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey]); boundKey != "" && boundKey != applicationKey {
		return false
	}
	if boundUID := string(secret.Data[v1alpha1.AccessApplicationUIDSecretKey]); boundUID != "" && boundUID != string(application.UID) {
		return false
	}
	return true
}

func (r *AccessApplicationReconciler) audHandoffsPresent(ctx context.Context, application *v1alpha1.AccessApplication, gatewayKeys []types.NamespacedName) (bool, error) {
	for _, gatewayKey := range gatewayKeys {
		var gateway gatewayv1.Gateway
		if err := r.Get(ctx, gatewayKey, &gateway); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("get Gateway %s for Access AUD handoff: %w", gatewayKey, err)
		}
		var secret corev1.Secret
		key := accessAUDSecretKey(r.operatorNamespace(), application, gatewayKey)
		if err := r.Get(ctx, key, &secret); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("get Access AUD handoff %s: %w", key, err)
		}
		secrets := []corev1.Secret{secret}
		if err := migrateLegacyAUDSecrets(ctx, r.Client, secrets, []v1alpha1.AccessApplication{*application}, &gateway); err != nil {
			return false, fmt.Errorf("migrate Access AUD handoff %s: %w", key, err)
		}
		if !audSecretIdentityMatches(&secrets[0], application, &gateway) ||
			string(secrets[0].Data[accessApplicationAUDReadyKey]) != "true" {
			return false, nil
		}
	}
	return true, nil
}

func (r *AccessApplicationReconciler) deleteAUDSecrets(ctx context.Context, application *v1alpha1.AccessApplication) error {
	secrets, err := r.listApplicationAUDSecrets(ctx, application)
	if err != nil {
		return fmt.Errorf("list Access AUD Secrets for deletion: %w", err)
	}
	for index := range secrets {
		if !audSecretOwnedByApplication(&secrets[index], application) {
			continue
		}
		if err := r.Delete(ctx, &secrets[index]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Access AUD Secret %s: %w", secrets[index].Name, err)
		}
	}
	return nil
}

type accessRevocationLatch struct {
	Claims        []accessRevocationClaim `json:"claims"`
	TokensRevoked bool                    `json:"tokensRevoked,omitempty"`
}

type accessRevocationClaim struct {
	Tunnel           string `json:"tunnel"`
	ProtectionDomain string `json:"protectionDomain"`
	Hostname         string `json:"hostname"`
	BaselineVersion  int64  `json:"baselineVersion"`
}

func (r *AccessApplicationReconciler) latchRevocation(ctx context.Context, application *v1alpha1.AccessApplication) error {
	if application.Annotations[accessApplicationRevocationAnnotation] != "" {
		return nil
	}
	applicationKey := application.Namespace + "/" + application.Name
	claims := make([]accessRevocationClaim, 0)
	hostnames := accessStatusHostnames(application.Status.Destinations)
	for _, dataPlane := range application.Status.DataPlanes {
		if dataPlane.Tunnel == "" || dataPlane.ProtectionDomain == "" {
			continue
		}
		var tunnel v1alpha1.CloudflareTunnel
		err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: dataPlane.Tunnel}, &tunnel)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get CloudflareTunnel while latching Access revocation: %w", err)
		}
		matched := false
		if err == nil {
			for _, status := range tunnel.Status.Hostnames {
				if status.ProtectionDomain != dataPlane.ProtectionDomain || status.AccessApplication != applicationKey {
					continue
				}
				baseline := revocationBaseline(status, &tunnel)
				claims = append(claims, accessRevocationClaim{
					Tunnel: dataPlane.Tunnel, ProtectionDomain: dataPlane.ProtectionDomain,
					Hostname: strings.ToLower(strings.TrimSuffix(status.Hostname, ".")), BaselineVersion: baseline,
				})
				matched = true
			}
		}
		if !matched {
			for _, hostname := range hostnames {
				claims = append(claims, accessRevocationClaim{
					Tunnel: dataPlane.Tunnel, ProtectionDomain: dataPlane.ProtectionDomain, Hostname: hostname,
				})
			}
		}
	}
	slices.SortFunc(claims, func(left, right accessRevocationClaim) int {
		return strings.Compare(
			fmt.Sprintf("%s\x00%s\x00%s\x00%d", left.Tunnel, left.ProtectionDomain, left.Hostname, left.BaselineVersion),
			fmt.Sprintf("%s\x00%s\x00%s\x00%d", right.Tunnel, right.ProtectionDomain, right.Hostname, right.BaselineVersion),
		)
	})
	claims = slices.Compact(claims)
	payload, err := json.Marshal(accessRevocationLatch{Claims: claims})
	if err != nil {
		return fmt.Errorf("encode Access revocation latch: %w", err)
	}
	before := application.DeepCopy()
	if application.Annotations == nil {
		application.Annotations = make(map[string]string)
	}
	application.Annotations[accessApplicationRevocationAnnotation] = string(payload)
	if err := r.Patch(ctx, application, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("persist Access revocation latch: %w", err)
	}
	return nil
}

func revocationBaseline(status v1alpha1.CloudflareTunnelHostnameStatus, tunnel *v1alpha1.CloudflareTunnel) int64 {
	if status.Guard == v1alpha1.HostnameGuardBlocked &&
		status.AppliedVersion > 0 &&
		status.AppliedVersion == tunnel.Status.ConfigVersion.Applied &&
		tunnel.Status.ConfigVersion.Desired == tunnel.Status.ConfigVersion.Applied {
		return status.AppliedVersion - 1
	}
	return status.AppliedVersion
}

func (r *AccessApplicationReconciler) revocationAcknowledged(ctx context.Context, application *v1alpha1.AccessApplication) (bool, string, string, error) {
	raw := application.Annotations[accessApplicationRevocationAnnotation]
	if raw == "" {
		return false, "Access revocation is not latched", "", nil
	}
	var latch accessRevocationLatch
	if err := json.Unmarshal([]byte(raw), &latch); err != nil {
		return false, "", "", fmt.Errorf("decode Access revocation latch: %w", err)
	}
	handoffs, err := r.listApplicationAUDSecrets(ctx, application)
	if err != nil {
		return false, "", "", fmt.Errorf("list Access handoffs while waiting for revocation: %w", err)
	}
	for index := range handoffs {
		if audSecretOwnedByApplication(&handoffs[index], application) &&
			string(handoffs[index].Data[accessApplicationAUDReadyKey]) == "true" {
			return false, "Waiting for the Access AUD handoff to remain absent", "", nil
		}
	}
	applicationKey := application.Namespace + "/" + application.Name
	tunnels := make(map[string]*v1alpha1.CloudflareTunnel)
	for _, claim := range latch.Claims {
		tunnel, found := tunnels[claim.Tunnel]
		if !found {
			current := &v1alpha1.CloudflareTunnel{}
			err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: claim.Tunnel}, current)
			if apierrors.IsNotFound(err) {
				tunnels[claim.Tunnel] = nil
				continue
			}
			if err != nil {
				return false, "", "", fmt.Errorf("get CloudflareTunnel while waiting for Access revocation: %w", err)
			}
			tunnel = current
			tunnels[claim.Tunnel] = tunnel
		}
		if tunnel == nil {
			continue
		}
		acknowledged := false
		for _, status := range tunnel.Status.Hostnames {
			if strings.EqualFold(strings.TrimSuffix(status.Hostname, "."), claim.Hostname) &&
				status.ProtectionDomain == claim.ProtectionDomain &&
				status.AccessApplication == applicationKey &&
				status.Guard == v1alpha1.HostnameGuardBlocked &&
				versionAcknowledged(status, tunnel, claim) &&
				status.AppliedVersion == tunnel.Status.ConfigVersion.Applied &&
				tunnel.Status.ConfigVersion.Desired == tunnel.Status.ConfigVersion.Applied {
				acknowledged = true
				break
			}
		}
		if !acknowledged {
			publisherAvailable, err := accessRevocationPublisherAvailable(ctx, r.Client, tunnel)
			if err != nil {
				return false, "", "", err
			}
			if !publisherAvailable {
				return false, fmt.Sprintf("Recorded Gateway for CloudflareTunnel %s is unavailable to publish revocation; preserving Access resources and finalizer", claim.Tunnel), accessRevocationPublisherUnavailable, nil
			}
			return false, fmt.Sprintf("Waiting for %s/%s on CloudflareTunnel %s to acknowledge Blocked after version %d", claim.Hostname, claim.ProtectionDomain, claim.Tunnel, claim.BaselineVersion), "", nil
		}
	}
	return true, "Every Access protection domain acknowledged a fresh Blocked version", "", nil
}

// versionAcknowledged reports whether the tunnel has published the Blocked
// transition. A public protection domain appears in the remote tunnel
// configuration, so revocation requires a version newer than the latched
// baseline. A private protection domain is deliberately absent from that
// configuration: the block is enforced by the data plane on loopback, and the
// remote version can never advance for it, so a settled version at or above
// the baseline is the strongest evidence that exists.
func versionAcknowledged(
	status v1alpha1.CloudflareTunnelHostnameStatus,
	tunnel *v1alpha1.CloudflareTunnel,
	claim accessRevocationClaim,
) bool {
	if status.AppliedVersion > claim.BaselineVersion {
		return true
	}
	return status.AppliedVersion == claim.BaselineVersion &&
		protectionDomainExposure(tunnel, claim.ProtectionDomain) == v1alpha1.ExposurePrivate
}

// protectionDomainExposure reports the listener exposure that owns the
// protection domain, or the empty exposure when the tunnel no longer records
// it.
func protectionDomainExposure(tunnel *v1alpha1.CloudflareTunnel, domain string) v1alpha1.Exposure {
	if tunnel == nil {
		return ""
	}
	for _, listener := range tunnel.Status.Listeners {
		for _, protectionDomain := range listener.ProtectionDomains {
			if protectionDomain.Name == domain {
				return listener.Exposure
			}
		}
	}
	return ""
}

func accessRevocationPublisherAvailable(ctx context.Context, reader client.Reader, tunnel *v1alpha1.CloudflareTunnel) (bool, error) {
	if tunnel == nil || tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" || tunnel.Status.GatewayUID == "" {
		return false, nil
	}
	var gateway gatewayv1.Gateway
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: tunnel.Status.GatewayRef.Name}
	if err := reader.Get(ctx, key, &gateway); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get recorded Gateway %s while waiting for Access revocation: %w", key, err)
	}
	if gateway.UID != tunnel.Status.GatewayUID || !gatewayClaimsTunnel(&gateway, tunnel) {
		return false, nil
	}
	// A deleting Gateway is still the recorded publisher; keep polling so its
	// normal drain/recovery path can acknowledge the claim.
	return true, nil
}

func revokeAccessApplicationTokens(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
) error {
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		return nil
	}
	ids := make(map[string]struct{}, len(application.Status.BypassApplications)+1)
	if application.Status.ApplicationID != "" {
		ids[application.Status.ApplicationID] = struct{}{}
	}
	for _, child := range application.Status.BypassApplications {
		if child.ApplicationID != "" {
			ids[child.ApplicationID] = struct{}{}
		}
	}
	for _, id := range sortedStringKeys(ids) {
		if err := remote.RevokeAccessApplicationTokens(ctx, scope, id); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("revoke Access application %s tokens: %w", id, err)
		}
	}
	return nil
}

func (r *AccessApplicationReconciler) revokeApplicationTokensAfterHandoff(ctx context.Context, application *v1alpha1.AccessApplication) error {
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		return nil
	}
	revoked, err := revocationTokensAlreadyRevoked(application)
	if err != nil || revoked {
		return err
	}
	account, err := r.accountForDeletion(ctx, application)
	if err != nil {
		return err
	}
	scope, err := accessApplicationScopeForDeletion(application, account)
	if err != nil {
		return err
	}
	remote, err := r.cloudflareClient(ctx, application.Namespace, account)
	if err != nil {
		return err
	}
	return r.revokeApplicationTokensWithClient(ctx, remote, scope, application)
}

func (r *AccessApplicationReconciler) revokeApplicationTokensWithClient(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
) error {
	revoked, err := revocationTokensAlreadyRevoked(application)
	if err != nil || revoked {
		return err
	}
	if err := revokeAccessApplicationTokens(ctx, remote, scope, application); err != nil {
		return err
	}
	return r.markRevocationTokensRevoked(ctx, application)
}

func revocationTokensAlreadyRevoked(application *v1alpha1.AccessApplication) (bool, error) {
	raw := application.Annotations[accessApplicationRevocationAnnotation]
	if raw == "" {
		return false, nil
	}
	var latch accessRevocationLatch
	if err := json.Unmarshal([]byte(raw), &latch); err != nil {
		return false, fmt.Errorf("decode Access revocation latch: %w", err)
	}
	return latch.TokensRevoked, nil
}

func (r *AccessApplicationReconciler) markRevocationTokensRevoked(ctx context.Context, application *v1alpha1.AccessApplication) error {
	raw := application.Annotations[accessApplicationRevocationAnnotation]
	if raw == "" {
		return errors.New("cannot mark Access tokens revoked without a revocation latch")
	}
	var latch accessRevocationLatch
	if err := json.Unmarshal([]byte(raw), &latch); err != nil {
		return fmt.Errorf("decode Access revocation latch: %w", err)
	}
	if latch.TokensRevoked {
		return nil
	}
	latch.TokensRevoked = true
	payload, err := json.Marshal(latch)
	if err != nil {
		return fmt.Errorf("encode Access revocation latch: %w", err)
	}
	before := application.DeepCopy()
	application.Annotations[accessApplicationRevocationAnnotation] = string(payload)
	if err := r.Patch(ctx, application, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("persist Access token revocation: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) clearRevocationLatch(ctx context.Context, application *v1alpha1.AccessApplication) error {
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		return nil
	}
	before := application.DeepCopy()
	delete(application.Annotations, accessApplicationRevocationAnnotation)
	if err := r.Patch(ctx, application, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("clear Access revocation latch: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) reconcileDelete(ctx context.Context, application *v1alpha1.AccessApplication) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(application, v1alpha1.AccessApplicationFinalizer) {
		return ctrl.Result{}, nil
	}
	programmed := meta.FindStatusCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.ObservedGeneration != application.Generation {
		status := *application.Status.DeepCopy()
		setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, "Pending", "Access application deletion is pending", r.now())
		if err := r.patchStatus(ctx, application, status); err != nil {
			return ctrl.Result{}, err
		}
		application.Status = status
	}
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		if err := r.latchRevocation(ctx, application); err != nil {
			return r.finishDeleteError(ctx, application, err)
		}
		if err := r.deleteAUDSecrets(ctx, application); err != nil {
			return r.finishDeleteError(ctx, application, err)
		}
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	if err := r.deleteAUDSecrets(ctx, application); err != nil {
		return r.finishDeleteError(ctx, application, err)
	}
	blocked, message, reason, err := r.revocationAcknowledged(ctx, application)
	if err != nil {
		return r.finishDeleteError(ctx, application, err)
	}
	if !blocked {
		status := *application.Status.DeepCopy()
		conditionStatus := metav1.ConditionFalse
		if reason == accessRevocationPublisherUnavailable {
			conditionStatus = metav1.ConditionTrue
		} else {
			reason = "Pending"
			if r.now().Sub(application.DeletionTimestamp.Time) >= accessApplicationCleanupLimit {
				conditionStatus = metav1.ConditionTrue
				reason = "CleanupTimedOut"
			}
		}
		setApplicationStatusCondition(&status, application, accessApplicationConditionCleanupBlocked, conditionStatus, reason, message, r.now())
		if err := r.patchStatus(ctx, application, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	if err := r.revokeApplicationTokensAfterHandoff(ctx, application); err != nil {
		return r.finishDeleteError(ctx, application, err)
	}
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged &&
		effectiveDeletionPolicy(application.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete {
		if err := r.deleteManagedRemoteApplications(ctx, application); err != nil {
			return r.finishDeleteError(ctx, application, err)
		}
	}
	if err := r.deletePrivateTunnelLedger(ctx, application); err != nil {
		return r.finishDeleteError(ctx, application, err)
	}
	before := application.DeepCopy()
	controllerutil.RemoveFinalizer(application, v1alpha1.AccessApplicationFinalizer)
	if err := r.Patch(ctx, application, client.MergeFrom(before)); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove AccessApplication finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *AccessApplicationReconciler) finishDeleteError(ctx context.Context, application *v1alpha1.AccessApplication, cause error) (ctrl.Result, error) {
	status := *application.Status.DeepCopy()
	now := r.now()
	setApplicationStatusCondition(&status, application, accessApplicationConditionCleanupBlocked, metav1.ConditionTrue, "RemoteError", cause.Error(), now)
	setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, "CleanupBlocked", "Access application deletion is blocked", now)
	return ctrl.Result{}, errors.Join(cause, r.patchStatus(ctx, application, status))
}

func accessStatusHostnames(destinations []v1alpha1.AccessApplicationDestinationStatus) []string {
	seen := make(map[string]struct{})
	for _, destination := range destinations {
		if destination.Type != v1alpha1.AccessApplicationDestinationPublic {
			continue
		}
		hostname := destination.URI
		if index := strings.IndexByte(hostname, '/'); index >= 0 {
			hostname = hostname[:index]
		}
		hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
		if hostname != "" {
			seen[hostname] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for hostname := range seen {
		result = append(result, hostname)
	}
	slices.Sort(result)
	return result
}

func (r *AccessApplicationReconciler) deleteManagedRemoteApplications(ctx context.Context, application *v1alpha1.AccessApplication) error {
	account, err := r.accountForDeletion(ctx, application)
	if err != nil {
		return err
	}
	remote, err := r.cloudflareClient(ctx, application.Namespace, account)
	if err != nil {
		return err
	}
	ownerTag, _, err := r.accessIdentity(ctx, application)
	if err != nil {
		return err
	}
	key, signedTag := r.accessSigningIdentity(ctx, application)
	ownerTags := []string{ownerTag}
	if signedTag == "" {
		log.FromContext(ctx).Info("ownership signing key unavailable; deleting only legacy ownership markers", "application", client.ObjectKeyFromObject(application))
	} else if signedTag != ownerTag {
		ownerTags = append(ownerTags, signedTag)
	}
	scope, err := accessApplicationScopeForDeletion(application, account)
	if err != nil {
		return err
	}
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return fmt.Errorf("list Access applications for deletion recovery: %w", err)
	}
	parentIDs, childIDs, bypassTags, err := accessApplicationDeletionTargets(application, ownerTags, key, applications)
	if err != nil {
		return err
	}
	if application.Spec.Type == v1alpha1.AccessApplicationTypeProxyEndpoint {
		clear(parentIDs)
	}
	statusByID := make(map[string]v1alpha1.AccessBypassApplicationStatus, len(application.Status.BypassApplications))
	for _, status := range application.Status.BypassApplications {
		statusByID[status.ApplicationID] = status
	}
	for _, id := range sortedStringKeys(childIDs) {
		if status, found := statusByID[id]; found && effectiveBypassDeletionPolicy(status.DeletionPolicy) == v1alpha1.DeletionPolicyOrphan {
			child, err := remote.GetAccessApplication(ctx, scope, id)
			if isRemoteNotFound(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("get bypass Access application %s for orphaning: %w", id, err)
			}
			childName := status.Name
			if childName == "" {
				childName = bypassChildApplicationName(accessApplicationRemoteName(application), status.Hostname, status.Path)
			}
			input := accessApplicationInputFromObserved(child)
			input.Tags = removeAccessTags(input.Tags, append(append([]string{accessManagedTag}, ownerTags...), accessBypassMarkersForOwners(key, ownerTags, childName)...)...)
			if !accessApplicationMatchesInput(child, input) {
				if _, err := remote.UpdateAccessApplication(ctx, scope, id, input); err != nil {
					return fmt.Errorf("orphan bypass Access application %s: %w", id, err)
				}
			}
			continue
		}
		if err := remote.DeleteAccessApplication(ctx, scope, id); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete bypass Access application %s: %w", id, err)
		}
	}
	if application.Spec.Type == v1alpha1.AccessApplicationTypeProxyEndpoint {
		if err := r.deleteManagedProxyEndpointApplication(ctx, remote, scope, application); err != nil {
			return err
		}
	}
	for _, id := range sortedStringKeys(parentIDs) {
		if err := remote.DeleteAccessApplication(ctx, scope, id); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete Access application %s: %w", id, err)
		}
	}
	for _, tagName := range sortedStringKeys(bypassTags) {
		if err := remote.DeleteAccessTag(ctx, tagName); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete bypass Access tag %q: %w", tagName, err)
		}
	}
	for _, tag := range ownerTags {
		if err := remote.DeleteAccessTag(ctx, tag); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete owner Access tag %q: %w", tag, err)
		}
	}
	return nil
}

func sortedStringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func (r *AccessApplicationReconciler) forwardingApplied(ctx context.Context, application *v1alpha1.AccessApplication, compilation gatewayapi.AccessApplicationCompilation) (bool, error) {
	if len(compilation.DataPlanes) == 0 {
		return len(compilation.Destinations) > 0, nil
	}
	applicationKey := application.Namespace + "/" + application.Name
	tunnels := make(map[string]*v1alpha1.CloudflareTunnel)
	for _, dataPlane := range compilation.DataPlanes {
		tunnel, found := tunnels[dataPlane.Tunnel]
		if !found {
			current := &v1alpha1.CloudflareTunnel{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: dataPlane.Tunnel}, current); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, fmt.Errorf("get CloudflareTunnel programming status: %w", err)
			}
			tunnel = current
			tunnels[dataPlane.Tunnel] = tunnel
		}
		acknowledged := false
		for _, status := range tunnel.Status.Hostnames {
			if status.ProtectionDomain == dataPlane.ProtectionDomain &&
				status.AccessApplication == applicationKey &&
				status.Guard == v1alpha1.HostnameGuardForwarding &&
				status.AppliedVersion > 0 &&
				status.AppliedVersion == tunnel.Status.ConfigVersion.Applied {
				acknowledged = true
				break
			}
		}
		if !acknowledged {
			return false, nil
		}
	}
	return true, nil
}

func (r *AccessApplicationReconciler) accountForDeletion(ctx context.Context, application *v1alpha1.AccessApplication) (*v1alpha1.CloudflareAccount, error) {
	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: application.Spec.AccountRef.Name}, &account); err != nil {
		return nil, fmt.Errorf("get CloudflareAccount %q for Access deletion: %w", application.Spec.AccountRef.Name, err)
	}
	return &account, nil
}

func (r *AccessApplicationReconciler) desiredStatus(application *v1alpha1.AccessApplication, compilation gatewayapi.AccessApplicationCompilation, applicationID string, children []v1alpha1.AccessBypassApplicationStatus, programmed bool) v1alpha1.AccessApplicationStatus {
	now := metav1.NewTime(r.now())
	status := *application.Status.DeepCopy()
	status.ApplicationID = applicationID
	if applicationID == "" {
		status.Type = ""
		status.OwnershipVerified = false
		status.Domain = ""
		status.ZoneID = ""
		status.Tags = nil
	}
	status.ObservedGeneration = application.Generation
	status.Destinations = accessDestinationStatuses(compilation.Destinations)
	status.DataPlanes = make([]v1alpha1.AccessApplicationDataPlaneStatus, 0, len(compilation.DataPlanes))
	for _, dataPlane := range compilation.DataPlanes {
		status.DataPlanes = append(status.DataPlanes, v1alpha1.AccessApplicationDataPlaneStatus{
			Tunnel: dataPlane.Tunnel, Listener: gatewayv1.SectionName(dataPlane.Listener),
			ProtectionDomain: dataPlane.ProtectionDomain, EnvoyPort: dataPlane.EnvoyPort,
		})
	}
	status.BypassApplications = slices.Clone(children)
	acceptedStatus := metav1.ConditionFalse
	programmedStatus := metav1.ConditionFalse
	originStatus := metav1.ConditionFalse
	acceptedReason := compilation.Reason
	programmedReason := compilation.Reason
	if programmedReason == "" {
		programmedReason = "Pending"
	}
	originReason := programmedReason
	message := compilation.Message
	if compilation.Accepted {
		acceptedStatus = metav1.ConditionTrue
		acceptedReason = "Accepted"
		if applicationID != "" && programmed {
			programmedStatus = metav1.ConditionTrue
			programmedReason = "Programmed"
		} else {
			programmedReason = "Pending"
		}
		switch {
		case compilation.OriginJWTEnforced && programmed:
			originStatus = metav1.ConditionTrue
			originReason = "Enforced"
		case !compilation.OriginJWTEnforced:
			originReason = "NotApplicable"
		default:
			originReason = "Pending"
		}
	}
	conditions := []metav1.Condition{
		gatewaystatus.NewCondition(accessApplicationConditionAccepted, acceptedStatus, acceptedReason, message, application.Generation, now),
		gatewaystatus.NewCondition(accessApplicationConditionProgrammed, programmedStatus, programmedReason, message, application.Generation, now),
		gatewaystatus.NewCondition(v1alpha1.AccessApplicationConditionOriginJWTEnforced, originStatus, originReason, originConditionMessage(compilation), application.Generation, now),
		gatewaystatus.NewCondition(accessApplicationConditionCleanupBlocked, metav1.ConditionFalse, "NotBlocked", "No cleanup is pending", application.Generation, now),
	}
	status.Conditions = gatewaystatus.MergeConditions(status.Conditions, now, conditions...)
	ancestors := make([]gatewayv1.PolicyAncestorStatus, 0, len(compilation.Ancestors))
	for _, ancestor := range compilation.Ancestors {
		group := gatewayv1.Group(ancestor.Group)
		kind := gatewayv1.Kind(ancestor.Kind)
		namespace := gatewayv1.Namespace(ancestor.Namespace)
		ancestors = append(ancestors, gatewayv1.PolicyAncestorStatus{
			AncestorRef:    gatewayv1.ParentReference{Group: &group, Kind: &kind, Namespace: &namespace, Name: gatewayv1.ObjectName(ancestor.Name)},
			ControllerName: gatewayapi.ControllerName,
			Conditions:     slices.Clone(conditions[:3]),
		})
	}
	status.Ancestors = gatewaystatus.ReplacePolicyAncestorStatuses(status.Ancestors, gatewayapi.ControllerName, now, ancestors...)
	return status
}

func applyObservedApplicationStatus(
	status *v1alpha1.AccessApplicationStatus,
	application *v1alpha1.AccessApplication,
	scope flarecloudflare.AccessScope,
	observed flarecloudflare.AccessApplication,
	ownerTags []string,
) {
	status.Type = v1alpha1.AccessApplicationType(observed.Type)
	status.Domain = observed.Domain
	status.ZoneID = scope.ZoneID
	status.OwnershipVerified = effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly ||
		observed.Type == flarecloudflare.AccessApplicationTypeProxyEndpoint ||
		hasAccessTag(observed.Tags, accessManagedTag) && hasAnyAccessTag(observed.Tags, ownerTags)
	status.Tags = canonicalStrings(observed.Tags)
	status.ObservedGeneration = application.Generation
}

func originConditionMessage(compilation gatewayapi.AccessApplicationCompilation) string {
	if !compilation.Accepted {
		return compilation.Message
	}
	if compilation.OriginJWTEnforced {
		return "Cloudflare Access JWT is required at the origin"
	}
	return "Origin JWT enforcement is not applicable or explicitly disabled by platform policy"
}

func rejectedCompilation(reason, message string) gatewayapi.AccessApplicationCompilation {
	return gatewayapi.AccessApplicationCompilation{Accepted: false, Reason: reason, Message: message}
}

// rejectedCompilationLoss rejects because a platform target object is gone or
// permanently unusable; the structured TargetLoss discriminator, not the
// message text, decides delete-vs-block handling downstream.
func rejectedCompilationLoss(message string, loss gatewayapi.AccessTargetLoss) gatewayapi.AccessApplicationCompilation {
	return gatewayapi.AccessApplicationCompilation{Accepted: false, Reason: "TargetNotFound", Message: message, TargetLoss: loss}
}

func (r *AccessApplicationReconciler) patchStatus(ctx context.Context, application *v1alpha1.AccessApplication, status v1alpha1.AccessApplicationStatus) error {
	current := &v1alpha1.AccessApplication{}
	key := client.ObjectKeyFromObject(application)
	if err := r.Get(ctx, key, current); err != nil {
		return client.IgnoreNotFound(err)
	}
	before := current.DeepCopy()
	current.Status = status
	if err := r.Status().Patch(ctx, current, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("patch AccessApplication status: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) operatorNamespace() string {
	if r.OperatorNamespace != "" {
		return r.OperatorNamespace
	}
	return accessApplicationAUDNamespace
}

func (r *AccessApplicationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers all indexes and watches that can change Access application compilation or cleanup.
func (r *AccessApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessApplication{}, accessApplicationTargetIndex, func(object client.Object) []string {
		return accessApplicationIndexTargetKeys(object.(*v1alpha1.AccessApplication))
	}); err != nil {
		return fmt.Errorf("index AccessApplication targetRefs: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessApplication{}, accessApplicationPolicyIndex, func(object client.Object) []string {
		return accessApplicationPolicyKeys(object.(*v1alpha1.AccessApplication))
	}); err != nil {
		return fmt.Errorf("index AccessApplication policyRefs: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessApplication{}, accessApplicationAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.AccessApplication).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessApplication accountRef: %w", err)
	}
	b := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AccessApplication{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&gatewayv1.GatewayClass{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayClassToApplications)).
		Watches(&v1alpha1.GatewayClassConfig{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayClassConfigToApplications)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&v1alpha1.AccessPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapPolicyToApplications)).
		Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.mapIdentityProviderToApplications)).
		Watches(&v1alpha1.AccessCustomPage{}, handler.EnqueueRequestsFromMapFunc(r.mapCustomPageToApplications)).
		Watches(&v1alpha1.ServiceToken{}, handler.EnqueueRequestsFromMapFunc(r.mapServiceTokenToApplications)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.mapTunnelToApplications)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.mapAccountToApplications)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapNamespaceToApplications)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapAUDSecretToApplication)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1})
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("access-application", r))
}

func accessApplicationIndexTargetKeys(application *v1alpha1.AccessApplication) []string {
	privateDestinations := accessApplicationPrivateDestinations(application)
	keys := make([]string, 0, len(application.Spec.TargetRefs)+len(privateDestinations))
	for _, target := range application.Spec.TargetRefs {
		group := string(target.Group)
		if group == "" {
			group = "gateway.networking.k8s.io"
		}
		kind := string(target.Kind)
		if kind == "" {
			kind = "Gateway"
		}
		keys = append(keys, strings.Join([]string{group, kind, application.Namespace, string(target.Name)}, "/"))
	}
	for _, destination := range privateDestinations {
		if destination.NetworkRouteRef != nil {
			keys = append(keys, strings.Join([]string{v1alpha1.Group, "NetworkRoute", application.Namespace, destination.NetworkRouteRef.Name}, "/"))
		}
		if destination.HostnameRouteRef != nil {
			keys = append(keys, strings.Join([]string{v1alpha1.Group, "HostnameRoute", application.Namespace, destination.HostnameRouteRef.Name}, "/"))
		}
	}
	return uniqueStrings(keys)
}

func accessApplicationPolicyKeys(application *v1alpha1.AccessApplication) []string {
	keys := make([]string, 0, len(application.Spec.Policies)+len(application.Spec.Bypass.Children))
	appendReference := func(reference *v1alpha1.AccessApplicationPolicyReference) {
		if reference == nil || reference.PolicyRef == nil {
			return
		}
		namespace := reference.PolicyRef.Namespace
		if namespace == "" {
			namespace = application.Namespace
		}
		keys = append(keys, namespace+"/"+reference.PolicyRef.Name)
	}
	for index := range application.Spec.Policies {
		appendReference(&application.Spec.Policies[index])
	}
	for index := range application.Spec.Bypass.Children {
		appendReference(application.Spec.Bypass.Children[index].PolicyRef)
	}
	return uniqueStrings(keys)
}

func (r *AccessApplicationReconciler) mapTargetToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	group := "gateway.networking.k8s.io"
	kind := "Gateway"
	switch object.(type) {
	case *gatewayv1.HTTPRoute:
		kind = "HTTPRoute"
	case *v1alpha1.NetworkRoute:
		group, kind = v1alpha1.Group, "NetworkRoute"
	case *v1alpha1.HostnameRoute:
		group, kind = v1alpha1.Group, "HostnameRoute"
	}
	key := strings.Join([]string{group, kind, object.GetNamespace(), object.GetName()}, "/")
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.MatchingFields{accessApplicationTargetIndex: key}); err != nil {
		log.FromContext(ctx).Error(err, "list AccessApplications for target", "target", key)
		return nil
	}
	requests := accessApplicationRequests(applications.Items)
	if kind == "Gateway" {
		var routes gatewayv1.HTTPRouteList
		if err := r.List(ctx, &routes, client.InNamespace(object.GetNamespace())); err != nil {
			log.FromContext(ctx).Error(err, "list HTTPRoutes for AccessApplication Gateway target", "gateway", client.ObjectKeyFromObject(object))
			return requests
		}
		gatewayKey := client.ObjectKeyFromObject(object).String()
		for index := range routes.Items {
			if slices.Contains(httpRouteParentGatewayKeys(&routes.Items[index]), gatewayKey) {
				requests = append(requests, r.mapTargetToApplications(ctx, &routes.Items[index])...)
			}
		}
	}
	return compactReconcileRequests(requests)
}

// mapGatewayClassToApplications enqueues every AccessApplication whose target
// Gateways use the changed GatewayClass. The GatewayReconciler owns the
// shared gatewayClassNameIndex field index.
func (r *AccessApplicationReconciler) mapGatewayClassToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways, client.MatchingFields{gatewayClassNameIndex: object.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "list Gateways for AccessApplication GatewayClass", "gatewayClass", object.GetName())
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range gateways.Items {
		requests = append(requests, r.mapTargetToApplications(ctx, &gateways.Items[index])...)
	}
	return compactReconcileRequests(requests)
}

// mapGatewayClassConfigToApplications enqueues every AccessApplication whose
// target Gateways use a GatewayClass that references the changed
// GatewayClassConfig. The GatewayReconciler owns the shared
// gatewayClassConfigIndex field index.
func (r *AccessApplicationReconciler) mapGatewayClassConfigToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var classes gatewayv1.GatewayClassList
	if err := r.List(ctx, &classes, client.MatchingFields{gatewayClassConfigIndex: object.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "list GatewayClasses for AccessApplication GatewayClassConfig", "gatewayClassConfig", object.GetName())
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range classes.Items {
		requests = append(requests, r.mapGatewayClassToApplications(ctx, &classes.Items[index])...)
	}
	return compactReconcileRequests(requests)
}

func (r *AccessApplicationReconciler) mapPolicyToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.MatchingFields{accessApplicationPolicyIndex: client.ObjectKeyFromObject(object).String()}); err != nil {
		log.FromContext(ctx).Error(err, "list AccessApplications for policy", "policy", client.ObjectKeyFromObject(object))
		return nil
	}
	return accessApplicationRequests(applications.Items)
}

func (r *AccessApplicationReconciler) mapIdentityProviderToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	result := make([]v1alpha1.AccessApplication, 0)
	for index := range applications.Items {
		application := &applications.Items[index]
		matches := false
		for _, reference := range application.Spec.Application.AllowedIDPRefs {
			matches = matches || reference.Name == object.GetName()
		}
		if application.Spec.Application.SCIMConfig != nil {
			matches = matches || application.Spec.Application.SCIMConfig.IDPRef.Name == object.GetName()
		}
		if matches {
			result = append(result, *application)
		}
	}
	return accessApplicationRequests(result)
}

func (r *AccessApplicationReconciler) mapCustomPageToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications); err != nil {
		return nil
	}
	result := make([]v1alpha1.AccessApplication, 0)
	for index := range applications.Items {
		application := &applications.Items[index]
		for _, reference := range application.Spec.Application.CustomPageRefs {
			if reference.ObjectRef == nil {
				continue
			}
			namespace := reference.ObjectRef.Namespace
			if namespace == "" {
				namespace = application.Namespace
			}
			if namespace == object.GetNamespace() && reference.ObjectRef.Name == object.GetName() {
				result = append(result, *application)
				break
			}
		}
	}
	return accessApplicationRequests(result)
}

func (r *AccessApplicationReconciler) mapServiceTokenToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications); err != nil {
		return nil
	}
	result := make([]v1alpha1.AccessApplication, 0)
	for index := range applications.Items {
		application := &applications.Items[index]
		config := application.Spec.Application.SCIMConfig
		if config == nil || config.Authentication == nil {
			continue
		}
		if scimAuthenticationReferencesServiceToken(config.Authentication, application.Namespace, object.GetNamespace(), object.GetName()) {
			result = append(result, *application)
		}
	}
	return accessApplicationRequests(result)
}

func scimAuthenticationReferencesServiceToken(authentication *v1alpha1.AccessSCIMAuthentication, defaultNamespace, namespace, name string) bool {
	references := make([]*v1alpha1.AccessSCIMAccessServiceTokenAuthentication, 0, len(authentication.Multiple)+1)
	references = append(references, authentication.AccessServiceToken)
	for index := range authentication.Multiple {
		references = append(references, authentication.Multiple[index].AccessServiceToken)
	}
	for _, reference := range references {
		if reference == nil || reference.ServiceTokenRef.Name != name {
			continue
		}
		referenceNamespace := reference.ServiceTokenRef.Namespace
		if referenceNamespace == "" {
			referenceNamespace = defaultNamespace
		}
		if referenceNamespace == namespace {
			return true
		}
	}
	return false
}

func (r *AccessApplicationReconciler) mapTunnelToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	result := make([]v1alpha1.AccessApplication, 0)
	for i := range applications.Items {
		matches := len(applications.Items[i].Spec.TargetRefs) > 0
		for _, dataPlane := range applications.Items[i].Status.DataPlanes {
			matches = matches || dataPlane.Tunnel == object.GetName()
		}
		if matches {
			result = append(result, applications.Items[i])
		}
	}
	return accessApplicationRequests(result)
}

func (r *AccessApplicationReconciler) mapAccountToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.MatchingFields{accessApplicationAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return accessApplicationRequests(applications.Items)
}

func (r *AccessApplicationReconciler) mapNamespaceToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return accessApplicationRequests(applications.Items)
}

func (r *AccessApplicationReconciler) mapAUDSecretToApplication(ctx context.Context, object client.Object) []reconcile.Request {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}
	_, application, trusted := liveAUDSecretBinding(ctx, r.Client, r.operatorNamespace(), secret)
	if !trusted {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(application)}}
}

func accessApplicationRequests(applications []v1alpha1.AccessApplication) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(applications))
	for index := range applications {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&applications[index])})
	}
	return requests
}

func compactReconcileRequests(requests []reconcile.Request) []reconcile.Request {
	slices.SortFunc(requests, func(left, right reconcile.Request) int {
		return strings.Compare(left.String(), right.String())
	})
	return slices.Compact(requests)
}

var _ reconcile.Reconciler = (*AccessApplicationReconciler)(nil)
