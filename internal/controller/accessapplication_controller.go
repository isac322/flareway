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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
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
	accessApplicationPrivateTunnelsLabel  = "flareway.bhyoo.com/private-tunnels-for"
	accessApplicationPrivateTunnelsKey    = "tunnels"
	accessApplicationAUDReadyKey          = "ready"

	accessTagNameMaxLength = 35
	accessManagedTag       = "flareway-managed"
	accessOwnerTagPrefix   = "flareway-owner-"
	accessBypassTagPrefix  = "flareway-bypass-"

	accessApplicationConditionAccepted       = "Accepted"
	accessApplicationConditionProgrammed     = "Programmed"
	accessApplicationConditionCleanupBlocked = "CleanupBlocked"
)

// AccessApplicationCloudflareClient provides the Access application operations used by the reconciler.
type AccessApplicationCloudflareClient interface {
	flarecloudflare.AccessApplicationAPI
	flarecloudflare.AccessTagAPI
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
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications;accesspolicies;identityproviders;cloudflareaccounts;cloudflaretunnels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes;hostnameroutes;virtualnetworks,verbs=get;list;watch
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
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly && len(resolved.compilation.Bypass) > 0 {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Invalid", "ObserveOnly AccessApplication cannot own mixed-hostname bypass applications"))
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

	if _, latched := application.Annotations[accessApplicationRevocationAnnotation]; latched {
		acknowledged, message, err := r.revocationAcknowledged(ctx, application)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !acknowledged {
			status := r.desiredStatus(application, resolved.compilation, application.Status.ApplicationID, application.Status.BypassApplications, false)
			setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, "RevocationPending", message, r.now())
			return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
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
	input := remoteApplicationInput(application, resolved.compilation.Destinations, policyIDs, idpIDs, ownerTag)
	observed, err := r.reconcileRemoteApplication(ctx, remote, application, input, ownerTag)
	if err != nil {
		return r.reconcileInvalidation(ctx, application, rejectedFrom(resolved.compilation, "Pending", "Remote Access application reconciliation failed: "+err.Error()))
	}
	if application.Status.ApplicationID != observed.ID {
		if err := r.persistParentID(ctx, application, observed.ID); err != nil {
			return ctrl.Result{}, err
		}
		application.Status.ApplicationID = observed.ID
	}
	children, err := r.reconcileBypassApplications(ctx, remote, application, resolved.compilation.Bypass, ownerTag, clusterID)
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
	status := r.desiredStatus(application, resolved.compilation, observed.ID, children, programmed)
	if err := r.patchStatus(ctx, application, status); err != nil {
		return ctrl.Result{}, err
	}
	if !programmed {
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AccessApplicationReconciler) reconcileInvalidation(ctx context.Context, application *v1alpha1.AccessApplication, invalid gatewayapi.AccessApplicationCompilation) (ctrl.Result, error) {
	retained := invalid
	if application.Status.ApplicationID != "" || len(application.Status.DataPlanes) > 0 || len(application.Status.Destinations) > 0 {
		retained = statusCompilation(application, invalid.Reason, invalid.Message)
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
	acknowledged, message, err := r.revocationAcknowledged(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}
	status := r.desiredStatus(application, retained, application.Status.ApplicationID, application.Status.BypassApplications, false)
	setApplicationStatusCondition(&status, application, accessApplicationConditionProgrammed, metav1.ConditionFalse, invalid.Reason, invalid.Message, r.now())
	if !acknowledged {
		setApplicationStatusCondition(&status, application, accessApplicationConditionCleanupBlocked, metav1.ConditionFalse, "RevocationPending", message, r.now())
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
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
		if err := r.clearRevocationLatch(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: accessApplicationRequeue}, r.patchStatus(ctx, application, status)
}
func targetInfrastructureUnavailable(compilation gatewayapi.AccessApplicationCompilation) bool {
	if compilation.Reason != "TargetNotFound" {
		return false
	}
	return strings.Contains(compilation.Message, "Gateway ") ||
		strings.Contains(compilation.Message, "GatewayClass ") ||
		strings.Contains(compilation.Message, "CloudflareTunnel ") ||
		strings.Contains(compilation.Message, "NetworkRoute ") ||
		strings.Contains(compilation.Message, "HostnameRoute ")
}

func rejectedFrom(compilation gatewayapi.AccessApplicationCompilation, reason, message string) gatewayapi.AccessApplicationCompilation {
	compilation.Accepted = false
	compilation.Reason = reason
	compilation.Message = message
	return compilation
}

func statusCompilation(application *v1alpha1.AccessApplication, reason, message string) gatewayapi.AccessApplicationCompilation {
	compilation := gatewayapi.AccessApplicationCompilation{
		Accepted: false, Reason: reason, Message: message,
		OriginJWTEnforced: application.Spec.OriginJWT.Mode != v1alpha1.AccessOriginJWTModeDisabled,
	}
	for _, destination := range application.Status.Destinations {
		compilation.Destinations = append(compilation.Destinations, gatewayapi.AccessDestination{
			Type: destination.Type, URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR,
			PortRange: destination.PortRange, L4Protocol: string(destination.L4Protocol), VNetID: destination.VNetID,
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

	gatewayKeys, err := r.targetGatewayKeys(ctx, application)
	if err != nil {
		return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", err.Error())}, nil
	}
	result := accessApplicationContext{
		compilation: gatewayapi.AccessApplicationCompilation{Accepted: true, Reason: "Accepted", Message: "Access application targets are valid"},
		gateways:    gatewayKeys,
	}
	accountNames := make(map[string]struct{})
	if len(application.Spec.PrivateDestinations) > 0 {
		inputs, account, err := r.privateAccessInputs(ctx, application)
		if err != nil {
			return accessApplicationContext{}, err
		}
		if invalid := validatePrivateRouteLifecycle(inputs, application); invalid != nil {
			return accessApplicationContext{account: account, compilation: *invalid, gateways: gatewayKeys}, nil
		}
		if account != nil &&
			(!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
				!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)) {
			return accessApplicationContext{
				account:     account,
				compilation: rejectedCompilation("RefNotPermitted", fmt.Sprintf("CloudflareAccount %q is not accepted with valid credentials", account.Name)),
				gateways:    gatewayKeys,
			}, nil
		}
		compiled := gatewayapi.CompilePrivateDestinations(inputs, application)
		if !compiled.Accepted {
			return accessApplicationContext{account: account, compilation: compiled, gateways: gatewayKeys}, nil
		}
		result.account = account
		accountNames[account.Name] = struct{}{}
		mergeAccessCompilation(&result.compilation, compiled)
	}
	if len(gatewayKeys) == 0 {
		if len(application.Spec.PrivateDestinations) == 0 {
			return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", "no targetRef resolves to a Gateway")}, nil
		}
		return result, nil
	}

	for _, gatewayKey := range gatewayKeys {
		var gateway gatewayv1.Gateway
		if err := r.Get(ctx, gatewayKey, &gateway); err != nil {
			if apierrors.IsNotFound(err) {
				return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("Gateway %s was not found", gatewayKey))}, nil
			}
			return accessApplicationContext{}, fmt.Errorf("get target Gateway %s: %w", gatewayKey, err)
		}
		if !gateway.DeletionTimestamp.IsZero() {
			return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("Gateway %s is deleting", gatewayKey))}, nil
		}
		var gatewayClass gatewayv1.GatewayClass
		if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, &gatewayClass); err != nil {
			if apierrors.IsNotFound(err) {
				return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("GatewayClass %q was not found", gateway.Spec.GatewayClassName))}, nil
			}
			return accessApplicationContext{}, fmt.Errorf("get GatewayClass: %w", err)
		}
		if gatewayClass.Spec.ControllerName != gatewayapi.ControllerName {
			return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("Gateway %s is not managed by Flareway", gatewayKey))}, nil
		}
		collector := &GatewayReconciler{Client: r.Client, Now: r.Now}
		config, err := collector.loadGatewayClassConfig(ctx, &gatewayClass)
		if err != nil {
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
			return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("CloudflareTunnel for Gateway %s was not found", gatewayKey))}, nil
		}
		if !tunnel.DeletionTimestamp.IsZero() {
			return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("CloudflareTunnel %s/%s is deleting", tunnel.Namespace, tunnel.Name))}, nil
		}
		var account v1alpha1.CloudflareAccount
		if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
			if apierrors.IsNotFound(err) {
				return accessApplicationContext{compilation: rejectedCompilation("TargetNotFound", fmt.Sprintf("CloudflareAccount %q was not found", tunnel.Spec.AccountRef.Name))}, nil
			}
			return accessApplicationContext{}, fmt.Errorf("get CloudflareAccount: %w", err)
		}
		if !gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
			!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
			return accessApplicationContext{compilation: rejectedCompilation("RefNotPermitted", fmt.Sprintf("CloudflareAccount %q is not accepted with valid credentials", account.Name))}, nil
		}
		if application.Spec.AccountRef != nil && application.Spec.AccountRef.Name != account.Name {
			return accessApplicationContext{compilation: rejectedCompilation("RefNotPermitted", fmt.Sprintf("AccessApplication accountRef %q does not match target account %q", application.Spec.AccountRef.Name, account.Name))}, nil
		}
		accountNames[account.Name] = struct{}{}
		if len(accountNames) > 1 {
			return accessApplicationContext{compilation: rejectedCompilation("RefNotPermitted", "all AccessApplication targets must use the same CloudflareAccount")}, nil
		}
		result.account = account.DeepCopy()
		inputs.CloudflareTunnel = tunnel
		inputs.CloudflareAccount = &account
		inputs.AccessApplications = slices.Clone(applications.Items)
		inputs.AUDSecrets, err = r.loadAUDSecrets(ctx, applications.Items, gatewayKey)
		if err != nil {
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
		result.compilation = rejectedCompilation("TargetNotFound", "no targetRef or private route resolves to an Access destination")
	}
	return result, nil
}

func (r *AccessApplicationReconciler) privateAccessInputs(ctx context.Context, application *v1alpha1.AccessApplication) (gatewayapi.Inputs, *v1alpha1.CloudflareAccount, error) {
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list Namespaces for private destinations: %w", err)
	}
	var networkRoutes v1alpha1.NetworkRouteList
	if err := r.List(ctx, &networkRoutes, client.InNamespace(application.Namespace)); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list NetworkRoutes for private destinations: %w", err)
	}
	var hostnameRoutes v1alpha1.HostnameRouteList
	if err := r.List(ctx, &hostnameRoutes, client.InNamespace(application.Namespace)); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list HostnameRoutes for private destinations: %w", err)
	}
	accountName := ""
	if application.Spec.AccountRef != nil {
		accountName = application.Spec.AccountRef.Name
	}
	for _, private := range application.Spec.PrivateDestinations {
		routeAccount := ""
		if private.NetworkRouteRef != nil {
			for index := range networkRoutes.Items {
				if networkRoutes.Items[index].Name == private.NetworkRouteRef.Name {
					routeAccount = networkRoutes.Items[index].Spec.AccountRef.Name
					break
				}
			}
		}
		if private.HostnameRouteRef != nil {
			for index := range hostnameRoutes.Items {
				if hostnameRoutes.Items[index].Name == private.HostnameRouteRef.Name {
					routeAccount = hostnameRoutes.Items[index].Spec.AccountRef.Name
					break
				}
			}
		}
		if routeAccount == "" {
			continue
		}
		if accountName == "" {
			accountName = routeAccount
		}
	}
	if accountName == "" {
		return gatewayapi.Inputs{Namespaces: namespaces.Items, NetworkRoutes: networkRoutes.Items, HostnameRoutes: hostnameRoutes.Items}, nil, nil
	}
	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: accountName}, &account); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("get CloudflareAccount %q for private destinations: %w", accountName, err)
	}
	return gatewayapi.Inputs{
		CloudflareAccount: &account, Namespaces: namespaces.Items,
		NetworkRoutes: networkRoutes.Items, HostnameRoutes: hostnameRoutes.Items,
	}, &account, nil
}

func validatePrivateRouteLifecycle(inputs gatewayapi.Inputs, application *v1alpha1.AccessApplication) *gatewayapi.AccessApplicationCompilation {
	for _, destination := range application.Spec.PrivateDestinations {
		if destination.NetworkRouteRef != nil {
			var route *v1alpha1.NetworkRoute
			for index := range inputs.NetworkRoutes {
				if inputs.NetworkRoutes[index].Namespace == application.Namespace && inputs.NetworkRoutes[index].Name == destination.NetworkRouteRef.Name {
					route = &inputs.NetworkRoutes[index]
					break
				}
			}
			if route == nil {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("NetworkRoute %s/%s was not found", application.Namespace, destination.NetworkRouteRef.Name))
				return &failure
			}
			if !route.DeletionTimestamp.IsZero() {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("NetworkRoute %s/%s is deleting", route.Namespace, route.Name))
				return &failure
			}
			if route.Status.ObservedGeneration != route.Generation ||
				!gatewaystatus.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("NetworkRoute %s/%s is not valid for its current generation", route.Namespace, route.Name))
				return &failure
			}
		}
		if destination.HostnameRouteRef != nil {
			var route *v1alpha1.HostnameRoute
			for index := range inputs.HostnameRoutes {
				if inputs.HostnameRoutes[index].Namespace == application.Namespace && inputs.HostnameRoutes[index].Name == destination.HostnameRouteRef.Name {
					route = &inputs.HostnameRoutes[index]
					break
				}
			}
			if route == nil {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("HostnameRoute %s/%s was not found", application.Namespace, destination.HostnameRouteRef.Name))
				return &failure
			}
			if !route.DeletionTimestamp.IsZero() {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("HostnameRoute %s/%s is deleting", route.Namespace, route.Name))
				return &failure

			}
			if route.Status.ObservedGeneration != route.Generation ||
				!gatewaystatus.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) {
				failure := rejectedCompilation("TargetNotFound", fmt.Sprintf("HostnameRoute %s/%s is not valid for its current generation", route.Namespace, route.Name))
				return &failure
			}
		}
	}
	return nil
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
	keys := make([]string, 0, len(application.Spec.PrivateDestinations))
	for _, destination := range application.Spec.PrivateDestinations {
		if destination.NetworkRouteRef != nil {
			var route v1alpha1.NetworkRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: destination.NetworkRouteRef.Name}, &route); err != nil {
				return nil, fmt.Errorf("get NetworkRoute for private tunnel ledger: %w", err)
			}
			keys = append(keys, privateRouteTunnelKey(route.Namespace, route.Spec.TunnelRef))
		}
		if destination.HostnameRouteRef != nil {
			var route v1alpha1.HostnameRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: destination.HostnameRouteRef.Name}, &route); err != nil {
				return nil, fmt.Errorf("get HostnameRoute for private tunnel ledger: %w", err)
			}
			keys = append(keys, privateRouteTunnelKey(route.Namespace, route.Spec.TunnelRef))
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func privateRouteTunnelKey(routeNamespace string, reference v1alpha1.NamespacedObjectReference) string {
	namespace := reference.Namespace
	if namespace == "" {
		namespace = routeNamespace
	}
	return namespace + "/" + reference.Name
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
				return nil, fmt.Errorf("HTTPRoute %s was not found", key)
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

func (r *AccessApplicationReconciler) loadAUDSecrets(ctx context.Context, applications []v1alpha1.AccessApplication, gateway types.NamespacedName) (map[types.NamespacedName]gatewayapi.AUDSecret, error) {
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets,
		client.InNamespace(r.operatorNamespace()),
		client.MatchingLabels{v1alpha1.AccessApplicationGatewayAUDLabel: gateway.Namespace + "--" + gateway.Name},
	); err != nil {
		return nil, fmt.Errorf("list Access AUD Secrets for Gateway %s: %w", gateway, err)
	}
	applicationByLabel := make(map[string]types.NamespacedName, len(applications))
	for index := range applications {
		application := &applications[index]
		applicationByLabel[application.Namespace+"--"+application.Name] = client.ObjectKeyFromObject(application)
	}
	result := make(map[types.NamespacedName]gatewayapi.AUDSecret)
	for index := range secrets.Items {
		secret := &secrets.Items[index]
		key, found := applicationByLabel[secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]]
		if !found {
			continue
		}
		result[key] = gatewayapi.AUDSecret{
			AUD:           string(secret.Data[v1alpha1.AccessApplicationAUDSecretKey]),
			ApplicationID: string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]),
			Ready:         string(secret.Data[accessApplicationAUDReadyKey]) == "true",
		}
	}
	return result, nil
}

func (r *AccessApplicationReconciler) resolvePolicies(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount, remote AccessApplicationCloudflareClient) ([]string, error) {
	ids := make([]string, 0, len(application.Spec.Policies))
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, &namespace); err != nil {
		return nil, fmt.Errorf("get AccessApplication namespace: %w", err)
	}
	for _, reference := range application.Spec.Policies {
		if reference.ExternalRef != nil {
			policy, err := remote.GetAccessPolicy(ctx, reference.ExternalRef.PolicyID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external Access policy %q could not be resolved: %v", reference.ExternalRef.PolicyID, err)}
			}
			if policy.Decision == "bypass" {
				return nil, accessValidationError{reason: "Invalid", message: "bypass policies are operator-managed; make the route rule public instead"}
			}
			ids = append(ids, policy.ID)
			continue
		}
		if reference.PolicyRef == nil {
			return nil, accessValidationError{reason: "Invalid", message: "policy reference is empty"}
		}
		policyNamespace := reference.PolicyRef.Namespace
		if policyNamespace == "" {
			policyNamespace = application.Namespace
		}
		var policy v1alpha1.AccessPolicy
		if err := r.Get(ctx, types.NamespacedName{Namespace: policyNamespace, Name: reference.PolicyRef.Name}, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("AccessPolicy %s/%s was not found", policyNamespace, reference.PolicyRef.Name)}
			}
			return nil, fmt.Errorf("get AccessPolicy %s/%s: %w", policyNamespace, reference.PolicyRef.Name, err)
		}
		if policy.Spec.Decision == v1alpha1.AccessPolicyDecisionBypass {
			return nil, accessValidationError{reason: "Invalid", message: "bypass policies are operator-managed; make the route rule public instead"}
		}
		if policy.Spec.AccountRef.Name != account.Name {
			return nil, fmt.Errorf("AccessPolicy %s/%s uses CloudflareAccount %q, want %q", policyNamespace, policy.Name, policy.Spec.AccountRef.Name, account.Name)
		}
		if policyNamespace != application.Namespace {
			allowed := false
			for _, grant := range account.Spec.Grants {
				selector, err := metav1.LabelSelectorAsSelector(&grant.NamespaceSelector)
				if err == nil && selector.Matches(labels.Set(namespace.Labels)) && grant.AccessPolicyRefs == v1alpha1.GrantPermissionAllowed {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("AccessPolicy %s/%s is not permitted by CloudflareAccount grants", policyNamespace, policy.Name)
			}
		}
		if policy.Status.PolicyID == "" || !gatewaystatus.ConditionTrue(policy.Status.Conditions, accessApplicationConditionAccepted) || !policy.DeletionTimestamp.IsZero() {
			return nil, fmt.Errorf("AccessPolicy %s/%s is not accepted", policyNamespace, policy.Name)
		}
		policyID := policy.Status.PolicyID
		if effectiveManagementPolicy(policy.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
			observed, err := remote.GetAccessPolicy(ctx, policyID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("AccessPolicy %s/%s remote policy could not be resolved: %v", policyNamespace, policy.Name, err)}
			}
			if observed.Decision == "bypass" {
				return nil, accessValidationError{reason: "Invalid", message: "bypass policies are operator-managed; make the route rule public instead"}
			}
			policyID = observed.ID
		}
		ids = append(ids, policyID)
	}
	return ids, nil
}
func (r *AccessApplicationReconciler) resolveIdentityProviders(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount, remote AccessApplicationCloudflareClient) ([]string, error) {
	ids := make([]string, 0, len(application.Spec.Application.AllowedIDPRefs))
	for _, reference := range application.Spec.Application.AllowedIDPRefs {
		if reference.ExternalID != "" {
			provider, err := remote.GetIdentityProvider(ctx, reference.ExternalID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external IdentityProvider %q could not be resolved: %v", reference.ExternalID, err)}
			}
			ids = append(ids, provider.ID)
			continue
		}
		var provider v1alpha1.IdentityProvider
		if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: reference.Name}, &provider); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("IdentityProvider %s/%s was not found", application.Namespace, reference.Name)}
			}
			return nil, fmt.Errorf("get IdentityProvider %s/%s: %w", application.Namespace, reference.Name, err)
		}
		if !provider.DeletionTimestamp.IsZero() {
			return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("IdentityProvider %s/%s is deleting", application.Namespace, provider.Name)}
		}
		if provider.Spec.AccountRef.Name != account.Name {
			return nil, fmt.Errorf("IdentityProvider %s/%s uses CloudflareAccount %q, want %q", application.Namespace, provider.Name, provider.Spec.AccountRef.Name, account.Name)
		}
		if provider.Status.IDPID == "" || !gatewaystatus.ConditionTrue(provider.Status.Conditions, accessApplicationConditionAccepted) {
			return nil, fmt.Errorf("IdentityProvider %s/%s is not accepted", application.Namespace, provider.Name)
		}
		providerID := provider.Status.IDPID
		if effectiveManagementPolicy(provider.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
			observed, err := remote.GetIdentityProvider(ctx, providerID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("IdentityProvider %s/%s remote provider could not be resolved: %v", application.Namespace, provider.Name, err)}
			}
			providerID = observed.ID
		}
		ids = append(ids, providerID)
	}
	return ids, nil
}

type accessValidationError struct {
	reason  string
	message string
}

func (err accessValidationError) Error() string { return err.message }

func accessValidationReason(err error) string {
	var validation accessValidationError
	if errors.As(err, &validation) {
		return validation.reason
	}
	return "RefNotPermitted"
}

func remoteApplicationInput(application *v1alpha1.AccessApplication, destinations []gatewayapi.AccessDestination, policyIDs, idpIDs []string, ownerTag string) flarecloudflare.AccessApplicationInput {
	remoteDestinations := make([]flarecloudflare.AccessApplicationDestination, 0, len(destinations))
	domain := ""
	for _, destination := range destinations {
		remoteDestinations = append(remoteDestinations, flarecloudflare.AccessApplicationDestination{
			Type: destination.Type, URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR,
			PortRange: destination.PortRange, L4Protocol: destination.L4Protocol, VNetID: destination.VNetID,
		})
		if domain == "" && destination.Type == "public" {
			domain = destination.URI
			if index := strings.IndexByte(domain, '/'); index >= 0 {
				domain = domain[:index]
			}
		}
	}
	policies := make([]flarecloudflare.AccessApplicationPolicyAttachment, len(policyIDs))
	for index, id := range policyIDs {
		policies[index] = flarecloudflare.AccessApplicationPolicyAttachment{ID: id, Precedence: int64(index + 1)}
	}
	name := accessApplicationRemoteName(application)
	tags := append([]string(nil), application.Spec.Application.Tags...)
	tags = append(tags, ownerTag, accessManagedTag)
	slices.Sort(tags)
	tags = slices.Compact(tags)
	settings := application.Spec.Application
	return flarecloudflare.AccessApplicationInput{
		Domain: domain, Name: name, Destinations: remoteDestinations, Policies: policies, AllowedIDPs: slices.Clone(idpIDs),
		SessionDuration: settings.SessionDuration, AllowAuthenticateViaWARP: settings.AllowAuthenticateViaWARP,
		SkipInterstitial: settings.SkipInterstitial, AutoRedirectToIdentity: settings.AutoRedirectToIdentity,
		AppLauncherVisible: settings.AppLauncherVisible, ServiceAuth401Redirect: settings.ServiceAuth401Redirect,
		EnableBindingCookie: settings.EnableBindingCookie, HTTPOnlyCookieAttribute: settings.HTTPOnlyCookieAttribute,
		SameSiteCookieAttribute: settings.SameSiteCookieAttribute, PathCookieAttribute: settings.PathCookieAttribute,
		OptionsPreflightBypass: settings.OptionsPreflightBypass, CORSHeaders: settings.CORSHeaders,
		ReadServiceTokensFromHeader: settings.ReadServiceTokensFromHeader,
		CustomDenyMessage:           settings.CustomDenyMessage,
		CustomDenyURL:               settings.CustomDenyURL, CustomNonIdentityDenyURL: settings.CustomNonIdentityDenyURL,
		CustomPages: slices.Clone(settings.CustomPages), Tags: tags,
	}
}

func (r *AccessApplicationReconciler) reconcileRemoteApplication(ctx context.Context, remote AccessApplicationCloudflareClient, application *v1alpha1.AccessApplication, input flarecloudflare.AccessApplicationInput, ownerTag string) (flarecloudflare.AccessApplication, error) {
	policy := effectiveManagementPolicy(application.Spec.ManagementPolicy)
	if policy == v1alpha1.ManagementPolicyObserveOnly {
		if application.Spec.ExternalRef == nil {
			return flarecloudflare.AccessApplication{}, errors.New("ObserveOnly AccessApplication requires externalRef")
		}
		return remote.GetAccessApplication(ctx, application.Spec.ExternalRef.ApplicationID)
	}
	internalTags := []string{accessManagedTag, ownerTag}
	if application.Status.ApplicationID != "" {
		current, err := remote.GetAccessApplication(ctx, application.Status.ApplicationID)
		if err == nil {
			if !hasAccessTag(current.Tags, ownerTag) || !hasAccessTag(current.Tags, accessManagedTag) {
				return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: Access application %q is not owned by this resource", application.Status.ApplicationID)
			}
			if err := ensureAccessTags(ctx, remote, internalTags...); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
			return remote.UpdateAccessApplication(ctx, current.ID, input)
		}
		if !isRemoteNotFound(err) {
			return flarecloudflare.AccessApplication{}, err
		}
	}
	if application.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
		if application.Spec.ExternalRef == nil {
			return flarecloudflare.AccessApplication{}, errors.New("AdoptById AccessApplication requires externalRef")
		}
		observed, err := remote.GetAccessApplication(ctx, application.Spec.ExternalRef.ApplicationID)
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		managedRecovery := observed.Name == input.Name &&
			hasAccessTag(observed.Tags, accessManagedTag) &&
			hasAccessTag(observed.Tags, ownerTag)
		if !managedRecovery {
			if expected := application.Spec.Adoption.Expect.Name; expected != "" && observed.Name != expected {
				return flarecloudflare.AccessApplication{}, fmt.Errorf("adoption conflict: Access application name %q does not match expected %q", observed.Name, expected)
			}
		}
		if err := ensureAccessTags(ctx, remote, internalTags...); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return remote.UpdateAccessApplication(ctx, observed.ID, input)
	}
	if application.Spec.ExternalRef != nil {
		return flarecloudflare.AccessApplication{}, errors.New("managed AccessApplication externalRef requires adoption.mode AdoptById")
	}
	recovered, found, err := findOwnedParentApplication(ctx, remote, ownerTag, input.Name)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if found {
		if err := ensureAccessTags(ctx, remote, internalTags...); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return remote.UpdateAccessApplication(ctx, recovered.ID, input)
	}
	if err := ensureAccessTags(ctx, remote, internalTags...); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	created, createErr := remote.CreateAccessApplication(ctx, input)
	if createErr == nil {
		return created, nil
	}
	recovered, found, recoveryErr := findOwnedParentApplication(ctx, remote, ownerTag, input.Name)
	if recoveryErr != nil {
		return flarecloudflare.AccessApplication{}, errors.Join(createErr, recoveryErr)
	}
	if found {
		return recovered, nil
	}
	return flarecloudflare.AccessApplication{}, createErr
}

func findOwnedParentApplication(ctx context.Context, remote AccessApplicationCloudflareClient, ownerTag, name string) (flarecloudflare.AccessApplication, bool, error) {
	applications, err := remote.ListAccessApplications(ctx)
	if err != nil {
		return flarecloudflare.AccessApplication{}, false, fmt.Errorf("list Access applications for ownership recovery: %w", err)
	}
	var found flarecloudflare.AccessApplication
	for _, application := range applications {
		if !hasAccessTag(application.Tags, ownerTag) ||
			!hasAccessTag(application.Tags, accessManagedTag) ||
			application.Name != name {
			continue
		}
		if found.ID != "" && found.ID != application.ID {
			return flarecloudflare.AccessApplication{}, false, fmt.Errorf("multiple Access applications carry owner tag %q and name %q", ownerTag, name)
		}
		found = application
	}
	return found, found.ID != "", nil
}

func ensureAccessTags(ctx context.Context, remote AccessApplicationCloudflareClient, names ...string) error {
	for _, name := range names {
		tag, err := remote.GetAccessTag(ctx, name)
		if err == nil {
			if tag.Name != name {
				return fmt.Errorf("get Access tag %q returned name %q", name, tag.Name)
			}
			continue
		}
		if !isRemoteNotFound(err) {
			return fmt.Errorf("get Access tag %q: %w", name, err)
		}
		created, createErr := remote.CreateAccessTag(ctx, name)
		if createErr == nil {
			if created.Name != name {
				return fmt.Errorf("create Access tag %q returned name %q", name, created.Name)
			}
			continue
		}
		if !flarecloudflare.IsConflict(createErr) {
			return fmt.Errorf("create Access tag %q: %w", name, createErr)
		}
		confirmed, getErr := remote.GetAccessTag(ctx, name)
		if getErr != nil {
			return errors.Join(
				fmt.Errorf("create Access tag %q raced: %w", name, createErr),
				fmt.Errorf("confirm Access tag %q after conflict: %w", name, getErr),
			)
		}
		if confirmed.Name != name {
			return fmt.Errorf("confirm Access tag %q after conflict returned name %q", name, confirmed.Name)
		}
	}
	return nil
}

func hasAccessTag(tags []string, expected string) bool {
	return slices.Contains(tags, expected)
}

func accessApplicationRemoteName(application *v1alpha1.AccessApplication) string {
	if application.Spec.Application.Name != "" {
		return application.Spec.Application.Name
	}
	return application.Namespace + "/" + application.Name
}

func (r *AccessApplicationReconciler) reconcileBypassApplications(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	application *v1alpha1.AccessApplication,
	bypasses []gatewayapi.AccessBypass,
	ownerTag string,
	clusterID string,
) ([]v1alpha1.AccessBypassApplicationStatus, error) {
	parentName := accessApplicationRemoteName(application)
	ownedRemote, err := listOwnedBypassApplications(ctx, remote, ownerTag, parentName)
	if err != nil {
		return nil, err
	}
	existing := make(map[string]string, len(application.Status.BypassApplications))
	for _, child := range application.Status.BypassApplications {
		existing[bypassStatusKey(child.Hostname, child.Path)] = child.ApplicationID
	}
	var bypassPolicy flarecloudflare.AccessPolicy
	if len(bypasses) > 0 {
		bypassPolicy, err = remote.EnsureBypassPolicy(ctx, "flareway/"+clusterID+"/bypass-everyone")
		if err != nil {
			return nil, fmt.Errorf("ensure account bypass policy: %w", err)
		}
	}
	falseValue := false
	result := make([]v1alpha1.AccessBypassApplicationStatus, 0, len(bypasses))
	desiredKeys := make(map[string]struct{}, len(bypasses))
	desiredTags := make(map[string]struct{}, len(bypasses))
	for _, bypass := range bypasses {
		key := bypassStatusKey(bypass.Hostname, bypass.Path)
		desiredKeys[key] = struct{}{}
		childName := bypassChildApplicationName(parentName, bypass.Hostname, bypass.Path)
		tagName := accessBypassTag(ownerTag, childName)
		desiredTags[tagName] = struct{}{}
		uri := strings.TrimSuffix(bypass.Hostname, "/") + bypass.Path
		tags := []string{accessManagedTag, ownerTag, tagName}
		slices.Sort(tags)
		input := flarecloudflare.AccessApplicationInput{
			Domain:                 bypass.Hostname,
			Name:                   childName,
			Destinations:           []flarecloudflare.AccessApplicationDestination{{Type: "public", URI: uri}},
			Policies:               []flarecloudflare.AccessApplicationPolicyAttachment{{ID: bypassPolicy.ID, Precedence: 1}},
			SessionDuration:        "0s",
			AppLauncherVisible:     &falseValue,
			AutoRedirectToIdentity: &falseValue,
			AllowedIDPs:            []string{},
			Tags:                   tags,
		}
		if err := ensureAccessTags(ctx, remote, accessManagedTag, ownerTag, tagName); err != nil {
			return nil, fmt.Errorf("ensure bypass Access tags for %s%s: %w", bypass.Hostname, bypass.Path, err)
		}
		var child flarecloudflare.AccessApplication
		if id := existing[key]; id != "" {
			child, err = remote.UpdateAccessApplication(ctx, id, input)
		} else if recovered, found := ownedRemote[tagName]; found {
			if recovered.Name != childName {
				return nil, fmt.Errorf("ownership conflict: bypass tag %q belongs to Access application name %q, want %q", tagName, recovered.Name, childName)
			}
			child, err = remote.UpdateAccessApplication(ctx, recovered.ID, input)
		} else {
			child, err = remote.CreateAccessApplication(ctx, input)
			if err != nil {
				createErr := err
				recovered, found, recoveryErr := findOwnedBypassApplication(ctx, remote, ownerTag, tagName, childName)
				switch {
				case recoveryErr != nil:
					err = errors.Join(createErr, recoveryErr)
				case found:
					child = recovered
					err = nil
				default:
					err = createErr
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("reconcile bypass Access application for %s%s: %w", bypass.Hostname, bypass.Path, err)
		}
		status := v1alpha1.AccessBypassApplicationStatus{Hostname: bypass.Hostname, Path: bypass.Path, ApplicationID: child.ID}
		if existing[key] != child.ID {
			if err := r.persistChildID(ctx, application, status); err != nil {
				return nil, err
			}
			upsertLocalBypassStatus(application, status)
			existing[key] = child.ID
		}
		result = append(result, status)
	}
	deleteIDs := make(map[string]struct{})
	deleteTags := make(map[string]struct{})
	for tagName, child := range ownedRemote {
		if _, retained := desiredTags[tagName]; retained {
			continue
		}
		deleteIDs[child.ID] = struct{}{}
		deleteTags[tagName] = struct{}{}
	}
	for _, child := range application.Status.BypassApplications {
		if _, retained := desiredKeys[bypassStatusKey(child.Hostname, child.Path)]; retained {
			continue
		}
		childName := bypassChildApplicationName(parentName, child.Hostname, child.Path)
		tagName := accessBypassTag(ownerTag, childName)
		if child.ApplicationID != "" {
			deleteIDs[child.ApplicationID] = struct{}{}
		}
		deleteTags[tagName] = struct{}{}
	}
	for _, id := range sortedStringKeys(deleteIDs) {
		if err := remote.DeleteAccessApplication(ctx, id); err != nil && !isRemoteNotFound(err) {
			return nil, fmt.Errorf("delete obsolete bypass Access application %s: %w", id, err)
		}
	}
	for _, tagName := range sortedStringKeys(deleteTags) {
		if err := remote.DeleteAccessTag(ctx, tagName); err != nil && !isRemoteNotFound(err) {
			return nil, fmt.Errorf("delete obsolete bypass Access tag %q: %w", tagName, err)
		}
	}
	slices.SortFunc(result, func(left, right v1alpha1.AccessBypassApplicationStatus) int {
		return strings.Compare(bypassStatusKey(left.Hostname, left.Path), bypassStatusKey(right.Hostname, right.Path))
	})
	return result, nil
}

func listOwnedBypassApplications(ctx context.Context, remote AccessApplicationCloudflareClient, ownerTag, parentName string) (map[string]flarecloudflare.AccessApplication, error) {
	applications, err := remote.ListAccessApplications(ctx)
	if err != nil {
		return nil, fmt.Errorf("list bypass Access applications for ownership recovery: %w", err)
	}
	result := make(map[string]flarecloudflare.AccessApplication)
	for _, application := range applications {
		tagName, owned := ownedBypassApplicationTag(application, ownerTag, parentName)
		if !owned {
			continue
		}
		if existing, found := result[tagName]; found && existing.ID != application.ID {
			return nil, fmt.Errorf("multiple Access applications carry bypass tag %q", tagName)
		}
		result[tagName] = application
	}
	return result, nil
}

func findOwnedBypassApplication(ctx context.Context, remote AccessApplicationCloudflareClient, ownerTag, bypassTag, expectedName string) (flarecloudflare.AccessApplication, bool, error) {
	applications, err := remote.ListAccessApplications(ctx)
	if err != nil {
		return flarecloudflare.AccessApplication{}, false, fmt.Errorf("list bypass Access applications for ownership recovery: %w", err)
	}
	var found flarecloudflare.AccessApplication
	for _, application := range applications {
		if application.Name != expectedName ||
			!hasAccessTag(application.Tags, accessManagedTag) ||
			!hasAccessTag(application.Tags, ownerTag) ||
			!hasAccessTag(application.Tags, bypassTag) {
			continue
		}
		if found.ID != "" && found.ID != application.ID {
			return flarecloudflare.AccessApplication{}, false, fmt.Errorf("multiple Access applications carry bypass tag %q and name %q", bypassTag, expectedName)
		}
		found = application
	}
	return found, found.ID != "", nil
}

func ownedBypassApplicationTag(application flarecloudflare.AccessApplication, ownerTag, parentName string) (string, bool) {
	if !hasAccessTag(application.Tags, accessManagedTag) ||
		!hasAccessTag(application.Tags, ownerTag) ||
		!strings.HasPrefix(application.Name, parentName+"/bypass/") {
		return "", false
	}
	tagName := accessBypassTag(ownerTag, application.Name)
	return tagName, hasAccessTag(application.Tags, tagName)
}

func upsertLocalBypassStatus(application *v1alpha1.AccessApplication, child v1alpha1.AccessBypassApplicationStatus) {
	key := bypassStatusKey(child.Hostname, child.Path)
	for index := range application.Status.BypassApplications {
		if bypassStatusKey(application.Status.BypassApplications[index].Hostname, application.Status.BypassApplications[index].Path) == key {
			application.Status.BypassApplications[index] = child
			return
		}
	}
	application.Status.BypassApplications = append(application.Status.BypassApplications, child)
}

func bypassStatusKey(hostname, path string) string {
	return strings.ToLower(strings.TrimSuffix(hostname, ".")) + "\x00" + path
}

func accessBypassTag(ownerTag, childName string) string {
	return accessDigestTag(accessBypassTagPrefix, ownerTag+"\x00"+childName)
}

func accessDigestTag(prefix, identity string) string {
	digest := sha256.Sum256([]byte(identity))
	hexDigest := fmt.Sprintf("%x", digest)
	return prefix + hexDigest[:accessTagNameMaxLength-len(prefix)]
}

func validInternalDigestTag(tag, prefix string) bool {
	if len(tag) != accessTagNameMaxLength || !strings.HasPrefix(tag, prefix) {
		return false
	}
	for index := len(prefix); index < len(tag); index++ {
		if !strings.ContainsRune("0123456789abcdef", rune(tag[index])) {
			return false
		}
	}
	return true
}

func bypassChildApplicationName(parentName, hostname, path string) string {
	pathName := strings.Trim(strings.ReplaceAll(path, "/", "-"), "-")
	if pathName == "" {
		pathName = "root"
	}
	hostName := strings.NewReplacer(".", "-", "*", "wildcard").Replace(hostname)
	identity := sha256.Sum256([]byte(bypassStatusKey(hostname, path)))
	return fmt.Sprintf("%s/bypass/%s-%s-%x", parentName, hostName, pathName, identity[:6])
}

func (r *AccessApplicationReconciler) persistParentID(ctx context.Context, application *v1alpha1.AccessApplication, id string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current v1alpha1.AccessApplication
		if err := r.Get(ctx, client.ObjectKeyFromObject(application), &current); err != nil {
			return err
		}
		before := current.DeepCopy()
		current.Status.ApplicationID = id
		return r.Status().Patch(ctx, &current, client.MergeFrom(before))
	})
}

func (r *AccessApplicationReconciler) persistChildID(ctx context.Context, application *v1alpha1.AccessApplication, child v1alpha1.AccessBypassApplicationStatus) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current v1alpha1.AccessApplication
		if err := r.Get(ctx, client.ObjectKeyFromObject(application), &current); err != nil {
			return err
		}
		before := current.DeepCopy()
		key := bypassStatusKey(child.Hostname, child.Path)
		replaced := false
		for index := range current.Status.BypassApplications {
			if bypassStatusKey(current.Status.BypassApplications[index].Hostname, current.Status.BypassApplications[index].Path) == key {
				current.Status.BypassApplications[index] = child
				replaced = true
				break
			}
		}
		if !replaced {
			current.Status.BypassApplications = append(current.Status.BypassApplications, child)
		}
		return r.Status().Patch(ctx, &current, client.MergeFrom(before))
	})
}

func (r *AccessApplicationReconciler) cloudflareClient(ctx context.Context, namespace string, account *v1alpha1.CloudflareAccount) (AccessApplicationCloudflareClient, error) {
	if account == nil {
		return nil, errors.New("AccessApplication has no resolved CloudflareAccount")
	}
	remote, _, err := accessClientForAccount(ctx, r.Client, namespace, account.Name, authz.Request{}, r.NewCloudflareClient)
	if err != nil {
		return nil, err
	}
	return remote, nil
}

func (r *AccessApplicationReconciler) accessIdentity(ctx context.Context, application *v1alpha1.AccessApplication) (string, string, error) {
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: "kube-system"}, &namespace); err != nil {
		return "", "", fmt.Errorf("get kube-system namespace: %w", err)
	}
	clusterID := string(namespace.UID)
	identity := flarecloudflare.OwnerTag(clusterID, application.Namespace, application.Name, application.UID)
	return accessDigestTag(accessOwnerTagPrefix, identity), clusterID, nil
}

func (r *AccessApplicationReconciler) ensureAUDSecrets(ctx context.Context, application *v1alpha1.AccessApplication, remote flarecloudflare.AccessApplication, gateways []types.NamespacedName) error {
	if len(gateways) > 0 && application.Spec.OriginJWT.Mode != v1alpha1.AccessOriginJWTModeDisabled && remote.AUD == "" {
		return errors.New("cloudflare Access application response did not include an AUD")
	}
	desiredRecipients := make(map[string]struct{}, len(gateways))
	for _, gateway := range gateways {
		desiredRecipients[gateway.Namespace+"--"+gateway.Name] = struct{}{}
	}
	var existing corev1.SecretList
	if err := r.List(ctx, &existing, client.InNamespace(r.operatorNamespace()), client.MatchingLabels{
		v1alpha1.AccessApplicationAUDSecretLabel: application.Namespace + "--" + application.Name,
	}); err != nil {
		return fmt.Errorf("list existing Access AUD Secrets: %w", err)
	}
	for index := range existing.Items {
		if _, retained := desiredRecipients[existing.Items[index].Labels[v1alpha1.AccessApplicationGatewayAUDLabel]]; retained {
			continue
		}
		if err := r.Delete(ctx, &existing.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale Access AUD Secret %s: %w", existing.Items[index].Name, err)
		}
	}
	for _, gateway := range gateways {
		labels := map[string]string{
			v1alpha1.AccessApplicationAUDSecretLabel:  application.Namespace + "--" + application.Name,
			v1alpha1.AccessApplicationGatewayAUDLabel: gateway.Namespace + "--" + gateway.Name,
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: accessAUDSecretName(application, gateway), Namespace: r.operatorNamespace(), Labels: labels},
			Type:       corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				v1alpha1.AccessApplicationAUDSecretKey: []byte(remote.AUD),
				v1alpha1.AccessApplicationIDSecretKey:  []byte(remote.ID),
				accessApplicationAUDReadyKey:           []byte("true"),
			},
		}
		var current corev1.Secret
		key := client.ObjectKeyFromObject(secret)
		if err := r.Get(ctx, key, &current); err != nil {
			if apierrors.IsNotFound(err) {
				if err := r.Create(ctx, secret); err != nil {
					return fmt.Errorf("create Access AUD Secret for Gateway %s: %w", gateway, err)
				}
				continue
			}
			return fmt.Errorf("get Access AUD Secret for Gateway %s: %w", gateway, err)
		}
		before := current.DeepCopy()
		current.Labels = labels
		current.Type = secret.Type
		current.Data = secret.Data
		if err := r.Patch(ctx, &current, client.MergeFrom(before)); err != nil {
			return fmt.Errorf("update Access AUD Secret for Gateway %s: %w", gateway, err)
		}
	}
	return nil
}

func accessAUDSecretName(application *v1alpha1.AccessApplication, gateway types.NamespacedName) string {
	sum := sha256.Sum256([]byte(gateway.String()))
	return fmt.Sprintf("aud-%s-%x", application.UID, sum[:6])
}

func (r *AccessApplicationReconciler) audHandoffsPresent(ctx context.Context, application *v1alpha1.AccessApplication, gateways []types.NamespacedName) (bool, error) {
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, client.InNamespace(r.operatorNamespace()), client.MatchingLabels{
		v1alpha1.AccessApplicationAUDSecretLabel: application.Namespace + "--" + application.Name,
	}); err != nil {
		return false, fmt.Errorf("list Access AUD handoffs: %w", err)
	}
	ready := make(map[string]bool, len(secrets.Items))
	for index := range secrets.Items {
		secret := &secrets.Items[index]
		ready[secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel]] =
			string(secret.Data[accessApplicationAUDReadyKey]) == "true" &&
				string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]) == application.Status.ApplicationID
	}
	for _, gateway := range gateways {
		if !ready[gateway.Namespace+"--"+gateway.Name] {
			return false, nil
		}
	}
	return true, nil
}

func (r *AccessApplicationReconciler) deleteAUDSecrets(ctx context.Context, application *v1alpha1.AccessApplication) error {
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, client.InNamespace(r.operatorNamespace()), client.MatchingLabels{
		v1alpha1.AccessApplicationAUDSecretLabel: application.Namespace + "--" + application.Name,
	}); err != nil {
		return fmt.Errorf("list Access AUD Secrets for deletion: %w", err)
	}
	for index := range secrets.Items {
		if err := r.Delete(ctx, &secrets.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Access AUD Secret %s: %w", secrets.Items[index].Name, err)
		}
	}
	return nil
}

type accessRevocationLatch struct {
	Claims []accessRevocationClaim `json:"claims"`
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

func (r *AccessApplicationReconciler) revocationAcknowledged(ctx context.Context, application *v1alpha1.AccessApplication) (bool, string, error) {
	raw := application.Annotations[accessApplicationRevocationAnnotation]
	if raw == "" {
		return false, "Access revocation is not latched", nil
	}
	var latch accessRevocationLatch
	if err := json.Unmarshal([]byte(raw), &latch); err != nil {
		return false, "", fmt.Errorf("decode Access revocation latch: %w", err)
	}
	var handoffs corev1.SecretList
	if err := r.List(ctx, &handoffs, client.InNamespace(r.operatorNamespace()), client.MatchingLabels{
		v1alpha1.AccessApplicationAUDSecretLabel: application.Namespace + "--" + application.Name,
	}); err != nil {
		return false, "", fmt.Errorf("list Access handoffs while waiting for revocation: %w", err)
	}
	for index := range handoffs.Items {
		if string(handoffs.Items[index].Data[accessApplicationAUDReadyKey]) == "true" {
			return false, "Waiting for the Access AUD handoff to remain absent", nil
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
				return false, "", fmt.Errorf("get CloudflareTunnel while waiting for Access revocation: %w", err)
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
				status.AppliedVersion > claim.BaselineVersion &&
				status.AppliedVersion == tunnel.Status.ConfigVersion.Applied &&
				tunnel.Status.ConfigVersion.Desired == tunnel.Status.ConfigVersion.Applied {
				acknowledged = true
				break
			}
		}
		if !acknowledged {
			return false, fmt.Sprintf("Waiting for %s/%s on CloudflareTunnel %s to acknowledge Blocked after version %d", claim.Hostname, claim.ProtectionDomain, claim.Tunnel, claim.BaselineVersion), nil
		}
	}
	return true, "Every Access protection domain acknowledged a fresh Blocked version", nil
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
	if application.Annotations[accessApplicationRevocationAnnotation] == "" {
		if err := r.latchRevocation(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.deleteAUDSecrets(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	if err := r.deleteAUDSecrets(ctx, application); err != nil {
		return ctrl.Result{}, err
	}
	blocked, message, err := r.revocationAcknowledged(ctx, application)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !blocked {
		status := *application.Status.DeepCopy()
		conditionStatus := metav1.ConditionFalse
		reason := "Pending"
		if r.now().Sub(application.DeletionTimestamp.Time) >= accessApplicationCleanupLimit {
			conditionStatus = metav1.ConditionTrue
			reason = "CleanupTimedOut"
		}
		setApplicationStatusCondition(&status, application, accessApplicationConditionCleanupBlocked, conditionStatus, reason, message, r.now())
		if err := r.patchStatus(ctx, application, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: accessApplicationRequeue}, nil
	}
	if effectiveManagementPolicy(application.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged &&
		effectiveDeletionPolicy(application.Spec.DeletionPolicy) == v1alpha1.DeletionPolicyDelete {
		if err := r.deleteManagedRemoteApplications(ctx, application); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.deletePrivateTunnelLedger(ctx, application); err != nil {
		return ctrl.Result{}, err
	}
	before := application.DeepCopy()
	controllerutil.RemoveFinalizer(application, v1alpha1.AccessApplicationFinalizer)
	if err := r.Patch(ctx, application, client.MergeFrom(before)); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove AccessApplication finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func accessStatusHostnames(destinations []v1alpha1.AccessApplicationDestinationStatus) []string {
	seen := make(map[string]struct{})
	for _, destination := range destinations {
		if destination.Type != "public" {
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
	applications, err := remote.ListAccessApplications(ctx)
	if err != nil {
		return fmt.Errorf("list Access applications for deletion recovery: %w", err)
	}
	parentIDs, childIDs, bypassTags, err := accessApplicationDeletionTargets(application, ownerTag, applications)
	if err != nil {
		return err
	}
	for _, id := range sortedStringKeys(childIDs) {
		if err := remote.DeleteAccessApplication(ctx, id); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete bypass Access application %s: %w", id, err)
		}
	}
	for _, id := range sortedStringKeys(parentIDs) {
		if err := remote.DeleteAccessApplication(ctx, id); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete Access application %s: %w", id, err)
		}
	}
	for _, tagName := range sortedStringKeys(bypassTags) {
		if err := remote.DeleteAccessTag(ctx, tagName); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete bypass Access tag %q: %w", tagName, err)
		}
	}
	if err := remote.DeleteAccessTag(ctx, ownerTag); err != nil && !isRemoteNotFound(err) {
		return fmt.Errorf("delete owner Access tag %q: %w", ownerTag, err)
	}
	return nil
}

func accessApplicationDeletionTargets(
	application *v1alpha1.AccessApplication,
	ownerTag string,
	applications []flarecloudflare.AccessApplication,
) (map[string]struct{}, map[string]struct{}, map[string]struct{}, error) {
	parentIDs := make(map[string]struct{})
	childIDs := make(map[string]struct{})
	bypassTags := make(map[string]struct{})
	if application.Status.ApplicationID != "" {
		parentIDs[application.Status.ApplicationID] = struct{}{}
	}
	for _, child := range application.Status.BypassApplications {
		if child.ApplicationID != "" {
			childIDs[child.ApplicationID] = struct{}{}
		}
	}
	parentName := accessApplicationRemoteName(application)
	for _, candidate := range applications {
		_, knownParent := parentIDs[candidate.ID]
		_, knownChild := childIDs[candidate.ID]
		if knownParent && knownChild {
			return nil, nil, nil, fmt.Errorf("access application %s is recorded as both parent and bypass child", candidate.ID)
		}
		if !hasAccessTag(candidate.Tags, accessManagedTag) || !hasAccessTag(candidate.Tags, ownerTag) {
			continue
		}
		if knownParent || candidate.Name == parentName {
			parentIDs[candidate.ID] = struct{}{}
			continue
		}
		tagName, ownedBypass := ownedBypassApplicationTag(candidate, ownerTag, parentName)
		if knownChild || ownedBypass {
			childIDs[candidate.ID] = struct{}{}
			if ownedBypass {
				bypassTags[tagName] = struct{}{}
			}
		}
	}
	for _, child := range application.Status.BypassApplications {
		childName := bypassChildApplicationName(parentName, child.Hostname, child.Path)
		bypassTags[accessBypassTag(ownerTag, childName)] = struct{}{}
	}
	return parentIDs, childIDs, bypassTags, nil
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
		for _, destination := range compilation.Destinations {
			if destination.Type != "private" {
				return false, nil
			}
		}
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
	name := ""
	if application.Spec.AccountRef != nil {
		name = application.Spec.AccountRef.Name
	}
	if name == "" {
		for _, dataPlane := range application.Status.DataPlanes {
			if dataPlane.Tunnel == "" {
				continue
			}
			var tunnel v1alpha1.CloudflareTunnel
			if err := r.Get(ctx, types.NamespacedName{Namespace: application.Namespace, Name: dataPlane.Tunnel}, &tunnel); err == nil {
				if name != "" && name != tunnel.Spec.AccountRef.Name {
					return nil, errors.New("AccessApplication data planes reference multiple CloudflareAccounts")
				}
				name = tunnel.Spec.AccountRef.Name
			} else if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("get target CloudflareTunnel for account: %w", err)
			}
		}
	}
	if name == "" {
		var namespace corev1.Namespace
		if err := r.Get(ctx, types.NamespacedName{Name: application.Namespace}, &namespace); err != nil {
			return nil, fmt.Errorf("get AccessApplication namespace for account resolution: %w", err)
		}
		var accounts v1alpha1.CloudflareAccountList
		if err := r.List(ctx, &accounts); err != nil {
			return nil, fmt.Errorf("list CloudflareAccounts for Access deletion: %w", err)
		}
		for index := range accounts.Items {
			account := &accounts.Items[index]
			for _, grant := range account.Spec.Grants {
				selector, err := metav1.LabelSelectorAsSelector(&grant.NamespaceSelector)
				if err == nil && selector.Matches(labels.Set(namespace.Labels)) {
					if name != "" && name != account.Name {
						return nil, errors.New("cannot uniquely resolve CloudflareAccount for Access application deletion")
					}
					name = account.Name
					break
				}
			}
		}
		if name == "" {
			return nil, errors.New("cannot resolve CloudflareAccount for Access application deletion")
		}
	}
	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &account); err != nil {
		return nil, fmt.Errorf("get CloudflareAccount for Access deletion: %w", err)
	}
	return &account, nil
}

func (r *AccessApplicationReconciler) desiredStatus(application *v1alpha1.AccessApplication, compilation gatewayapi.AccessApplicationCompilation, applicationID string, children []v1alpha1.AccessBypassApplicationStatus, programmed bool) v1alpha1.AccessApplicationStatus {
	now := metav1.NewTime(r.now())
	status := *application.Status.DeepCopy()
	status.ApplicationID = applicationID
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
		}
		if compilation.OriginJWTEnforced && programmed {
			originStatus = metav1.ConditionTrue
			originReason = "Enforced"
		} else if !compilation.OriginJWTEnforced {
			originReason = "NotApplicable"
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

func accessDestinationStatuses(destinations []gatewayapi.AccessDestination) []v1alpha1.AccessApplicationDestinationStatus {
	result := make([]v1alpha1.AccessApplicationDestinationStatus, 0, len(destinations))
	for _, destination := range destinations {
		result = append(result, v1alpha1.AccessApplicationDestinationStatus{Type: destination.Type, URI: destination.URI, Hostname: destination.Hostname, CIDR: destination.CIDR, PortRange: destination.PortRange, L4Protocol: v1alpha1.AccessL4Protocol(destination.L4Protocol), VNetID: destination.VNetID})
	}
	return result
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

func mergeAccessCompilation(target *gatewayapi.AccessApplicationCompilation, source gatewayapi.AccessApplicationCompilation) {
	target.Destinations = append(target.Destinations, source.Destinations...)
	target.DataPlanes = append(target.DataPlanes, source.DataPlanes...)
	target.Bypass = append(target.Bypass, source.Bypass...)
	target.Ancestors = append(target.Ancestors, source.Ancestors...)
	target.OriginJWTEnforced = target.OriginJWTEnforced || source.OriginJWTEnforced
	if !source.Accepted {
		target.Accepted = false
		target.Reason = source.Reason
		target.Message = source.Message
	}
	dedupeAccessCompilation(target)
}

func dedupeAccessCompilation(compilation *gatewayapi.AccessApplicationCompilation) {
	slices.SortFunc(compilation.Destinations, func(left, right gatewayapi.AccessDestination) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", left.Type, left.URI, left.Hostname, left.CIDR, left.PortRange, left.L4Protocol, left.VNetID), fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", right.Type, right.URI, right.Hostname, right.CIDR, right.PortRange, right.L4Protocol, right.VNetID))
	})
	compilation.Destinations = slices.Compact(compilation.Destinations)
	slices.SortFunc(compilation.DataPlanes, func(left, right gatewayapi.AccessDataPlane) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%s\x00%d", left.Tunnel, left.Listener, left.ProtectionDomain, left.EnvoyPort), fmt.Sprintf("%s\x00%s\x00%s\x00%d", right.Tunnel, right.Listener, right.ProtectionDomain, right.EnvoyPort))
	})
	compilation.DataPlanes = slices.Compact(compilation.DataPlanes)
	slices.SortFunc(compilation.Bypass, func(left, right gatewayapi.AccessBypass) int {
		return strings.Compare(left.Hostname+"\x00"+left.Path, right.Hostname+"\x00"+right.Path)
	})
	compilation.Bypass = slices.Compact(compilation.Bypass)
	slices.SortFunc(compilation.Ancestors, func(left, right gatewayapi.AccessAncestor) int {
		return strings.Compare(strings.Join([]string{left.Group, left.Kind, left.Namespace, left.Name}, "\x00"), strings.Join([]string{right.Group, right.Kind, right.Namespace, right.Name}, "\x00"))
	})
	compilation.Ancestors = slices.Compact(compilation.Ancestors)
}

func effectiveManagementPolicy(policy v1alpha1.ManagementPolicy) v1alpha1.ManagementPolicy {
	if policy == "" {
		return v1alpha1.ManagementPolicyManaged
	}
	return policy
}

func effectiveDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyDelete
	}
	return policy
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
		if object.(*v1alpha1.AccessApplication).Spec.AccountRef == nil {
			return nil
		}
		return []string{object.(*v1alpha1.AccessApplication).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index AccessApplication accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AccessApplication{}).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToApplications)).
		Watches(&v1alpha1.AccessPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapPolicyToApplications)).
		Watches(&v1alpha1.IdentityProvider{}, handler.EnqueueRequestsFromMapFunc(r.mapIdentityProviderToApplications)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.mapTunnelToApplications)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.mapAccountToApplications)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapNamespaceToApplications)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapAUDSecretToApplication)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(observedReconciler("access-application", r))
}

func accessApplicationIndexTargetKeys(application *v1alpha1.AccessApplication) []string {
	keys := make([]string, 0, len(application.Spec.TargetRefs)+len(application.Spec.PrivateDestinations))
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
	for _, destination := range application.Spec.PrivateDestinations {
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
	keys := make([]string, 0, len(application.Spec.Policies))
	for _, policy := range application.Spec.Policies {
		if policy.PolicyRef == nil {
			continue
		}
		namespace := policy.PolicyRef.Namespace
		if namespace == "" {
			namespace = application.Namespace
		}
		keys = append(keys, namespace+"/"+policy.PolicyRef.Name)
	}
	return keys
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
	for i := range applications.Items {
		for _, ref := range applications.Items[i].Spec.Application.AllowedIDPRefs {
			if ref.Name == object.GetName() {
				result = append(result, applications.Items[i])
				break
			}
		}
	}
	return accessApplicationRequests(result)
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
	var explicit v1alpha1.AccessApplicationList
	if err := r.List(ctx, &explicit, client.MatchingFields{accessApplicationAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	var all v1alpha1.AccessApplicationList
	if err := r.List(ctx, &all); err != nil {
		return accessApplicationRequests(explicit.Items)
	}
	requests := accessApplicationRequests(explicit.Items)
	for index := range all.Items {
		if len(all.Items[index].Spec.PrivateDestinations) > 0 {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&all.Items[index])})
		}
	}
	return compactReconcileRequests(requests)
}

func (r *AccessApplicationReconciler) mapNamespaceToApplications(ctx context.Context, object client.Object) []reconcile.Request {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return accessApplicationRequests(applications.Items)
}

func (r *AccessApplicationReconciler) mapAUDSecretToApplication(_ context.Context, object client.Object) []reconcile.Request {
	value := object.GetLabels()[v1alpha1.AccessApplicationAUDSecretLabel]
	namespace, name, found := strings.Cut(value, "--")
	if !found || namespace == "" || name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}}
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
