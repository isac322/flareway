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
	"maps"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
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
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/freshness"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
	"github.com/isac322/flareway/internal/ir"
)

const (
	tunnelFieldManager     = "flareway-tunnel"
	tunnelRequeue          = 2 * time.Second
	tunnelObservationLimit = int64(16)
	dnsRecordStateReady    = "Ready"
	dnsRecordStateConflict = "Conflict"

	gatewayTunnelIndex     = "flareway.gateway.cloudflareTunnel"
	tunnelAccountIndex     = "flareway.cloudflareTunnel.account"
	accountCredentialIndex = "flareway.cloudflareAccount.credentialSecret"
	dataplaneGatewayLabel  = "flareway.bhyoo.com/gateway"
)

// RemoteTunnel aliases the Cloudflare tunnel representation used by the controller contract.
type RemoteTunnel = flarecloudflare.Tunnel

// RemoteDNSRecord aliases the Cloudflare DNS record representation used by the controller contract.
type RemoteDNSRecord = flarecloudflare.DNSRecord

// RemoteDNSRecordInput aliases the Cloudflare DNS record input used by the controller contract.
type RemoteDNSRecordInput = flarecloudflare.DNSRecordInput

// TunnelCloudflareClient is the narrow Cloudflare contract used by the tunnel controller.
// Production uses internal/cloudflare.API; envtest uses a deterministic fake.
type TunnelCloudflareClient interface {
	flarecloudflare.TunnelAPI
	flarecloudflare.DNSAPI
}

// NewTunnelCloudflareClient constructs an account-scoped Cloudflare client.
type NewTunnelCloudflareClient func(token, accountID string) (TunnelCloudflareClient, error)

// TunnelClientFromFactory adapts the shared production Cloudflare factory.
func TunnelClientFromFactory(factory flarecloudflare.ClientFactory) NewTunnelCloudflareClient {
	return func(token, accountID string) (TunnelCloudflareClient, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

// CloudflareTunnelReconciler owns remote Tunnel identity, connector token, DNS,
// teardown sequencing, and the tunnel-owned portion of CloudflareTunnel status.
type CloudflareTunnelReconciler struct {
	client.Client
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewTunnelCloudflareClient
	Now                 func() time.Time
	// OperatorNamespace hosts the cluster ownership-key Secret. Empty falls
	// back to dataplane.DefaultOperatorNamespace.
	OperatorNamespace string
	Freshness         freshness.Policy
	Invalidator       *freshness.Latch
	// SweepEvents carries drift wakeups from the sweep worker. When nil no
	// raw source is registered in SetupWithManager.
	SweepEvents <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=accessapplications;hostnameroutes;networkroutes,verbs=get;list;watch

// Reconcile converges one CloudflareTunnel without ever writing gateway-owned status fields.
func (r *CloudflareTunnelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, req.NamespacedName, &tunnel); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !tunnel.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tunnel)
	}
	if !controllerutil.ContainsFinalizer(&tunnel, v1alpha1.CloudflareTunnelFinalizer) {
		before := tunnel.DeepCopy()
		controllerutil.AddFinalizer(&tunnel, v1alpha1.CloudflareTunnelFinalizer)
		if err := r.Patch(ctx, &tunnel, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add CloudflareTunnel finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	return r.reconcileActive(ctx, &tunnel)
}

func (r *CloudflareTunnelReconciler) reconcileActive(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) (ctrl.Result, error) {
	if _, present := tunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation]; present {
		before := tunnel.DeepCopy()
		delete(tunnel.Annotations, v1alpha1.CloudflareTunnelTeardownAnnotation)
		if len(tunnel.Annotations) == 0 {
			tunnel.Annotations = nil
		}
		if err := r.Patch(ctx, tunnel, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove teardown annotation from active CloudflareTunnel: %w", err)
		}
		return ctrl.Result{}, nil
	}

	now := r.now()
	mode := tunnelConfigurationMode(tunnel)
	// clearIntent records explicit revocation intent for protected status
	// fields; patchOwnedStatus restores any other protected field a stale
	// cache omitted.
	clearIntent := tunnelStatusClear{}
	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		tunnel.Status.OwnershipVerified = false
		clearIntent.Ownership = true
	}
	ownedConditions := tunnelOwnedConditions(tunnel)
	set := func(condition metav1.Condition) {
		ownedConditions = gatewaystatus.SetCondition(ownedConditions, now, condition)
	}
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "NotBlocked", "No cleanup is pending", tunnel.Generation, now))
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionFalse, "NoConflict", "No ownership conflict was detected", tunnel.Generation, now))
	if mode == v1alpha1.CloudflareTunnelConfigurationModeDirect &&
		tunnel.Status.GatewayRef != nil && tunnel.Status.GatewayRef.Name != "" {
		drained, err := r.scaleDownRecordedGatewayDataplane(ctx, tunnel)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !drained {
			message := "Waiting for the previous Gateway UID connector dataplane to terminate before entering Direct mode"
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			status := tunnelOwnedStatus(tunnel, tunnel.Status.GatewayRef, tunnel.Status.GatewayUID, ownedConditions)
			r.setReadyForMode(&status, tunnel, mode, now)
			return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
		}
		// The recorded Gateway dataplane has drained; the binding is now
		// authoritatively unbound and may be cleared.
		clearIntent.GatewayBinding = true
	}
	if mode == v1alpha1.CloudflareTunnelConfigurationModeDirect &&
		(tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "") {
		// Direct mode never had a recorded Gateway binding.
		clearIntent.GatewayBinding = true
	}

	var gateway *gatewayv1.Gateway
	var gatewayRef *corev1.LocalObjectReference
	var gatewayUID types.UID
	dnsOwnerName := tunnel.Name
	if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		var extraOwners []string
		var waitingForDrain bool
		var err error
		gateway, extraOwners, waitingForDrain, err = selectLiveTunnelGateway(ctx, r.Client, tunnel)
		if err != nil {
			return ctrl.Result{}, err
		}
		if waitingForDrain {
			if _, err := r.scaleDownRecordedGatewayDataplane(ctx, tunnel); err != nil {
				return ctrl.Result{}, err
			}
			message := "Waiting for the prior Gateway UID dataplane to scale to zero before selecting a successor"
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "WaitingForOwnerDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "WaitingForOwnerDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "WaitingForOwnerDrain", message, tunnel.Generation, now))
			status := tunnelOwnedStatus(tunnel, tunnel.Status.GatewayRef, tunnel.Status.GatewayUID, ownedConditions)
			r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
			return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
		}
		if gateway == nil {
			// No Gateway claims this Tunnel: the binding is authoritatively
			// unbound, so clearing gatewayRef/gatewayUid is explicit intent.
			clearIntent.GatewayBinding = true
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "TargetNotFound", "No Gateway references this CloudflareTunnel", tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", "Waiting for an owning Gateway", tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for an owning Gateway", tunnel.Generation, now))
			status := tunnelOwnedStatus(tunnel, nil, "", ownedConditions)
			if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
				// Gateway-absent ObserveOnly cleanup explicitly revokes the
				// recorded credential references.
				status.ConnectorTokenSecretRef = nil
				status.ManagementTokenSecretRef = nil
				clearIntent.Credentials = true
			}
			r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
			return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
		}
		gatewayRef = &corev1.LocalObjectReference{Name: gateway.Name}
		gatewayUID = gateway.UID
		dnsOwnerName = gateway.Name
		if len(extraOwners) > 0 {
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "MultipleGateways", fmt.Sprintf("Gateway %s is the owner; references from %s are rejected", gateway.Name, strings.Join(extraOwners, ", ")), tunnel.Generation, now))
		}
		if !tunnelGatewayStatusIdentityMatches(tunnel, gateway) {
			message := fmt.Sprintf("Recorded Gateway %s/%s UID %s as the Tunnel owner", gateway.Namespace, gateway.Name, gateway.UID)
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "OwnershipCheckpoint", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "OwnershipCheckpoint", "Waiting for the exact Gateway UID ownership checkpoint", tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "OwnershipCheckpoint", "Waiting for the exact Gateway UID ownership checkpoint", tunnel.Generation, now))
			status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
			r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
			return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
		}
	}
	if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway &&
		!tunnel.Status.OwnershipVerified &&
		tunnel.Status.ConnectorTokenSecretRef != nil {
		drained, err := r.scaleDownRecordedGatewayDataplane(ctx, tunnel)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !drained {
			message := "Waiting for an unverified connector-bearing Gateway dataplane to terminate"
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
			status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
			r.setReadyForMode(&status, tunnel, mode, now)
			return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
		}
	}
	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway {
			drained, err := r.scaleDownRecordedGatewayDataplane(ctx, tunnel)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !drained {
				message := "ObserveOnly is waiting for the connector-bearing Gateway dataplane to terminate"
				set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
				set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "WaitingForDrain", message, tunnel.Generation, now))
				set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "ObserveOnly", "ObserveOnly does not manage DNS records", tunnel.Generation, now))
				status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
				status.OwnershipVerified = false
				r.setReadyForMode(&status, tunnel, mode, now)
				return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
			}
		}
		tunnel.Status.OwnershipVerified = false
		// ObserveOnly transition explicitly revokes recorded credential refs.
		tunnel.Status.ConnectorTokenSecretRef = nil
		tunnel.Status.ManagementTokenSecretRef = nil
		clearIntent.Credentials = true
	}

	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
		message := fmt.Sprintf("CloudflareAccount %q was not found", tunnel.Spec.AccountRef.Name)
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("get CloudflareAccount: %w", err)
		}
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "InvalidAccountRef", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
	}
	if !gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
		!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		message := fmt.Sprintf("CloudflareAccount %q is not accepted with valid credentials", account.Name)
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "InvalidAccountRef", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
	}

	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Namespace}, namespace); err != nil {
		return ctrl.Result{}, fmt.Errorf("get Tunnel namespace: %w", err)
	}
	var publicHosts []publicHostname
	var allBindings []listenerBinding
	var bindingErr error
	if mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		publicHosts, allBindings, bindingErr = directTunnelBindings(tunnel, account.Status.Verified.Zones)
	} else {
		publicHosts, allBindings, bindingErr = tunnelGatewayBindings(tunnel, gateway, account.Status.Verified.Zones)
	}
	if bindingErr != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "Invalid", bindingErr.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", bindingErr.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Invalid", bindingErr.Error(), tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
	}
	if decision := authorizeBindings(&account, namespace, allBindings, mode == v1alpha1.CloudflareTunnelConfigurationModeDirect); !decision.Allowed {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, decision.Reason, decision.Message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", decision.Message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", decision.Message, tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
	}
	acceptedMessage := fmt.Sprintf("Direct configuration is authorized for CloudflareAccount %s", account.Name)
	if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		acceptedMessage = fmt.Sprintf("Gateway %s UID %s is authorized for CloudflareAccount %s", gateway.Name, gateway.UID, account.Name)
	}
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", acceptedMessage, tunnel.Generation, now))

	cf, err := r.cloudflareClient(ctx, &account)
	if err != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "CredentialsInvalid", err.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for valid Cloudflare credentials", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}

	clusterID := ""
	if tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly {
		clusterID, err = r.clusterID(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// T2 gate: a converged Tunnel skips the remote identity, DNS, and
	// configuration reads below. ObserveOnly tunnels are never gated —
	// remote observation is the feature (safety condition 9). The reads
	// this gate suppresses are T0 fresh reads by contract: the adoption
	// and ownership checks inside ensureRemoteTunnel, the per-hostname
	// ListDNSRecords inside ensureDNS (a fresh read before destructive
	// writes), and the read-modify-write inside WithTunnelLock. They only
	// execute while the gate is closed; the sweep re-opens them early via
	// the invalidation latch when it detects drift.
	if tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && tunnelConvergedForGate(tunnel, &account, publicHosts) {
		gate := evaluateGateWithHash(r.Freshness, r.Invalidator, freshness.GradeTraffic, "CloudflareTunnel",
			client.ObjectKeyFromObject(tunnel), tunnel.Status.ConfigVersion.DesiredHash, tunnel.Status.ConfigVersion.DesiredHash,
			tunnel.Status.ConfigVersion.AppliedAt, now.Time)
		if gate.Open {
			// QA-001 residual: ListTunnelConnections is the T4 display read
			// that keeps status.clients fresh; the token-secret ensures
			// self-heal a deleted Secret without remote calls in the steady
			// state. The status apply is skipped when the projection is
			// unchanged so an open pass costs zero etcd writes (QA-030).
			connectorSecretRef, err := r.ensureTokenSecret(ctx, cf, tunnel, tunnel.Status.TunnelID)
			if err != nil {
				return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "TokenUnavailable", err)
			}
			managementSecretRef, err := r.ensureManagementTokenSecret(ctx, cf, tunnel, tunnel.Status.TunnelID)
			if err != nil {
				return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "TokenUnavailable", err)
			}
			clients, _, err := cf.ListTunnelConnections(ctx, tunnel.Status.TunnelID, tunnelObservationLimit)
			if err != nil {
				return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "ConnectionsUnavailable", err)
			}
			status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
			status.ConnectorTokenSecretRef = connectorSecretRef
			status.ManagementTokenSecretRef = managementSecretRef
			status.Clients = tunnelClientStatuses(clients)
			status.Addresses = tunnelAddresses(tunnel.Status.TunnelID, len(publicHosts) > 0)
			r.setReadyForMode(&status, tunnel, mode, now)
			if tunnelGateStatusUnchanged(tunnel.Status, status) {
				return ctrl.Result{RequeueAfter: gate.Requeue}, nil
			}
			openClear := clearIntent
			openClear.Clients = true
			openClear.Addresses = true
			return ctrl.Result{RequeueAfter: gate.Requeue}, r.patchOwnedStatus(ctx, tunnel, status, openClear)
		}
	}
	remote, conflictReason, err := r.ensureRemoteTunnel(ctx, cf, tunnel, clusterID, account.Spec.AccountID)
	if err != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "CloudflareError", err.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for the remote Tunnel", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}
	if conflictReason != "" {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "Conflict", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "AdoptionMismatch", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Conflict", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Tunnel ownership did not complete", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		preserveVerifiedOwnership := tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly &&
			tunnel.Status.OwnershipVerified &&
			remote.ID != "" &&
			remote.ID == tunnel.Status.TunnelID &&
			validateRemoteTunnel(remote, account.Spec.AccountID) == nil
		// Ownership conflict revokes verified ownership; credential refs are
		// revoked only once the recorded dataplane has drained (or immediately
		// in Direct mode, which has no connector dataplane to drain).
		conflictClear := clearIntent
		conflictClear.Ownership = true
		if remote.ID != "" && (tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly || remote.ID == tunnel.Status.TunnelID) {
			projectRemoteTunnelStatus(&status, remote, tunnel.Generation)
			conflictClear.DeletedAt = true
		}
		status.OwnershipVerified = preserveVerifiedOwnership
		if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway {
			drained, drainErr := r.scaleDownRecordedGatewayDataplane(ctx, tunnel)
			if drainErr != nil {
				return ctrl.Result{}, drainErr
			}
			if drained {
				status.ConnectorTokenSecretRef = nil
				status.ManagementTokenSecretRef = nil
				conflictClear.Credentials = true
			}
		} else {
			status.ConnectorTokenSecretRef = nil
			status.ManagementTokenSecretRef = nil
			conflictClear.Credentials = true
		}
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, conflictClear)
	}

	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		clients, _, err := cf.ListTunnelConnections(ctx, remote.ID, tunnelObservationLimit)
		if err != nil {
			status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
			projectRemoteTunnelStatus(&status, remote, tunnel.Generation)
			status.OwnershipVerified = false
			status.ConnectorTokenSecretRef = nil
			status.ManagementTokenSecretRef = nil
			observeClear := clearIntent
			observeClear.DNSRecords = true
			observeClear.DeletedAt = true
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "ConnectionsUnavailable", err.Error(), tunnel.Generation, now), now)
			r.setReadyForMode(&status, tunnel, mode, now)
			if patchErr := r.patchOwnedStatus(ctx, tunnel, status, observeClear); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{}, err
		}
		status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
		projectRemoteTunnelStatus(&status, remote, tunnel.Generation)
		status.OwnershipVerified = false
		status.ConnectorTokenSecretRef = nil
		status.ManagementTokenSecretRef = nil
		status.Clients = tunnelClientStatuses(clients)
		status.Addresses = tunnelAddresses(remote.ID, len(publicHosts) > 0)
		status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{}
		// ObserveOnly DNS withdrawal plus the fresh client/address projection
		// are authoritative empties.
		observeClear := clearIntent
		observeClear.DNSRecords = true
		observeClear.Clients = true
		observeClear.Addresses = true
		observeClear.DeletedAt = true
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Observed", fmt.Sprintf("Observed Cloudflare Tunnel %s without adopting it", remote.ID), tunnel.Generation, now), now)
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "ObserveOnly", "ObserveOnly does not manage DNS records", tunnel.Generation, now), now)
		r.setReadyForMode(&status, tunnel, mode, now)
		return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status, observeClear)
	}

	checkpoint := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
	projectRemoteTunnelStatus(&checkpoint, remote, tunnel.Generation)
	if !remoteProjectionEqual(tunnel.Status, checkpoint) {
		checkpointClear := clearIntent
		checkpointClear.DeletedAt = true
		if err := r.patchOwnedStatus(ctx, tunnel, checkpoint, checkpointClear); err != nil {
			return ctrl.Result{}, fmt.Errorf("checkpoint remote Tunnel identity: %w", err)
		}
		tunnel.Status = mergeTunnelOwnedStatus(tunnel.Status, checkpoint)
	}

	connectorSecretRef, err := r.ensureTokenSecret(ctx, cf, tunnel, remote.ID)
	if err != nil {
		return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "TokenUnavailable", err)
	}
	managementSecretRef, err := r.ensureManagementTokenSecret(ctx, cf, tunnel, remote.ID)
	if err != nil {
		return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "TokenUnavailable", err)
	}

	clients, _, err := cf.ListTunnelConnections(ctx, remote.ID, tunnelObservationLimit)
	if err != nil {
		return r.activeFailure(ctx, tunnel, gatewayRef, gatewayUID, ownedConditions, "ConnectionsUnavailable", err)
	}
	status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, ownedConditions)
	projectRemoteTunnelStatus(&status, remote, tunnel.Generation)
	status.ConnectorTokenSecretRef = connectorSecretRef
	status.ManagementTokenSecretRef = managementSecretRef
	status.Clients = tunnelClientStatuses(clients)
	status.Addresses = tunnelAddresses(remote.ID, len(publicHosts) > 0)
	clearIntent.Clients = true
	clearIntent.Addresses = true
	clearIntent.DeletedAt = true

	if err := r.reconcileConfiguration(ctx, cf, tunnel, &account, mode, &status, now); err != nil {
		if mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "ConfigurationError", err.Error(), tunnel.Generation, now), now)
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "ConfigurationError", err.Error(), tunnel.Generation, now), now)
		r.setReadyForMode(&status, tunnel, mode, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}
	setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", fmt.Sprintf("Cloudflare Tunnel %s exists", remote.ID), tunnel.Generation, now), now)

	switch {
	case tunnel.Spec.DNS.Mode == v1alpha1.DNSModeExternal:
		remainingRecords, cleanupConflict, err := removeDNSRecords(ctx, cf, dnsOwnershipMarkers(tunnel, clusterID, dnsOwnerName), dnsRecordTargets(tunnel, remote.ID), tunnel.Status.DNSRecords)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.DNSRecords = remainingRecords
		if cleanupConflict != "" {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Conflict", cleanupConflict, tunnel.Generation, now), now)
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "DNSOwnership", cleanupConflict, tunnel.Generation, now), now)
			break
		}
		reason, message := "External", "DNS records are managed externally"
		if len(publicHosts) == 0 {
			reason, message = "NotApplicable", "The Tunnel configuration has no public hostnames"
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, reason, message, tunnel.Generation, now), now)
	case len(publicHosts) == 0:
		remainingRecords, cleanupConflict, err := removeDNSRecords(ctx, cf, dnsOwnershipMarkers(tunnel, clusterID, dnsOwnerName), dnsRecordTargets(tunnel, remote.ID), tunnel.Status.DNSRecords)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.DNSRecords = remainingRecords
		if cleanupConflict != "" {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Conflict", cleanupConflict, tunnel.Generation, now), now)
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "DNSOwnership", cleanupConflict, tunnel.Generation, now), now)
			break
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "NotApplicable", "The Tunnel configuration has no public hostnames", tunnel.Generation, now), now)
	default:
		dnsRecords, dnsConflict, dnsErr := r.ensureDNS(ctx, cf, tunnel, dnsOwnerName, clusterID, remote.ID, publicHosts)
		if dnsErr != nil {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "CloudflareError", dnsErr.Error(), tunnel.Generation, now), now)
			r.setReadyForMode(&status, tunnel, mode, now)
			if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
				return ctrl.Result{}, patchErr
			}
			return ctrl.Result{}, dnsErr
		}
		status.DNSRecords = dnsRecords
		if dnsConflict != "" {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Conflict", dnsConflict, tunnel.Generation, now), now)
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "DNSOwnership", dnsConflict, tunnel.Generation, now), now)
		} else {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "Ready", "All managed DNS records exist and are owned by Flareway", tunnel.Generation, now), now)
		}
	}

	r.setReadyForMode(&status, tunnel, mode, now)
	clearIntent.DNSRecords = true
	clearGate(r.Invalidator, "CloudflareTunnel", client.ObjectKeyFromObject(tunnel))
	// A disabled gate (zero TTL) preserves the pre-gate polling cadence:
	// without gate expiry or a sweep, the periodic remote read is the only
	// drift-detection path left.
	requeue := r.Freshness.TTL(freshness.GradeTraffic)
	if requeue <= 0 {
		requeue = tunnelRequeue
	}
	return ctrl.Result{RequeueAfter: requeue}, r.patchOwnedStatus(ctx, tunnel, status, clearIntent)
}

func (r *CloudflareTunnelReconciler) reconcileDelete(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(tunnel, v1alpha1.CloudflareTunnelFinalizer) {
		return ctrl.Result{}, nil
	}
	now := r.now()
	if tunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] != "true" {
		before := tunnel.DeepCopy()
		if tunnel.Annotations == nil {
			tunnel.Annotations = map[string]string{}
		}
		tunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] = "true"
		if err := r.Patch(ctx, tunnel, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("mark Tunnel teardown: %w", err)
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	owner, err := liveRecordedTunnelGateway(ctx, r.Client, tunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	dependencyTunnel := tunnel.DeepCopy()
	// Delete-path applies get the same stale-cache protection; only the
	// authoritative DNS removal and connection listing below may empty fields.
	clearIntent := tunnelStatusClear{}
	status := tunnelOwnedStatus(tunnel, tunnel.Status.GatewayRef, tunnel.Status.GatewayUID, tunnelOwnedConditions(tunnel))
	if owner != nil && tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly &&
		tunnel.Status.OwnershipVerified && !allHostnamesBlocked(tunnel.Status.Hostnames) {
		message := "Waiting for the exact recorded Gateway UID to block every hostname"
		if now.Sub(tunnel.DeletionTimestamp.Time) >= 30*time.Second {
			message = "The recorded Gateway UID did not block every hostname within 30s; teardown remains fail-closed"
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForBlock", message, tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	verifiedManagement := tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && tunnel.Status.OwnershipVerified
	needsRemote := verifiedManagement && tunnel.Spec.DeletionPolicy != v1alpha1.DeletionPolicyOrphan
	manageDNS := verifiedManagement
	var cf TunnelCloudflareClient
	accountID := ""
	if manageDNS && len(tunnel.Status.DNSRecords) > 0 || needsRemote {
		var account v1alpha1.CloudflareAccount
		if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
			return r.cleanupFailure(ctx, tunnel, status, clearIntent, "CredentialsUnavailable", fmt.Errorf("get CloudflareAccount for cleanup: %w", err))
		}
		accountID = account.Spec.AccountID
		cf, err = r.cloudflareClient(ctx, &account)
		if err != nil {
			return r.cleanupFailure(ctx, tunnel, status, clearIntent, "CredentialsUnavailable", err)
		}
	}

	if manageDNS && len(tunnel.Status.DNSRecords) > 0 {
		var expectedComments []string
		if tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeDirect || owner != nil {
			clusterID, err := r.clusterID(ctx)
			if err != nil {
				return r.cleanupFailure(ctx, tunnel, status, clearIntent, "DNSOwnershipUnavailable", err)
			}
			dnsOwnerName := tunnel.Name
			if owner != nil {
				dnsOwnerName = owner.Name
			}
			expectedComments = dnsOwnershipMarkers(tunnel, clusterID, dnsOwnerName)
		}
		remainingRecords, cleanupConflict, err := removeDNSRecords(ctx, cf, expectedComments, dnsRecordTargets(tunnel, ""), tunnel.Status.DNSRecords)
		if err != nil {
			return r.cleanupFailure(ctx, tunnel, status, clearIntent, "DNSDeleteFailed", err)
		}
		status.DNSRecords = remainingRecords
		clearIntent.DNSRecords = true
		if cleanupConflict != "" {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Conflict", cleanupConflict, tunnel.Generation, now), now)
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "DNSOwnership", cleanupConflict, tunnel.Generation, now), now)
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "DNSOwnership", cleanupConflict, tunnel.Generation, now), now)
			if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Deleted", "Managed DNS records were removed", tunnel.Generation, now), now)
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "Draining", "DNS is removed; waiting for connector drain", tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	drained, err := r.scaleDownRecordedGatewayDataplane(ctx, dependencyTunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !drained {
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForDrain", "Waiting for the recorded Gateway UID dataplane to scale to zero and terminate its Pods", tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	accessPending, err := r.pendingAccessApplications(ctx, dependencyTunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(accessPending) > 0 {
		message := "Waiting for AccessApplication cleanup: " + strings.Join(accessPending, ", ")
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForAccessCleanup", message, tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	dependencies, err := r.tunnelDependencies(ctx, tunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(dependencies) > 0 {
		message := "Remove dependent routes before deleting the Tunnel: " + strings.Join(dependencies, ", ")
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "DependenciesRemain", message, tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	if !needsRemote {
		status.OrphanedTunnelID = tunnel.Status.TunnelID
		reason := "Orphaned"
		message := "Remote Tunnel is intentionally retained"
		if tunnel.Status.TunnelID != "" && !tunnel.Status.OwnershipVerified {
			reason = "UnverifiedRemotePreserved"
			message = "Remote Tunnel identity was observed without verified ownership and was not deleted"
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, reason, message, tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
			return ctrl.Result{}, err
		}
	} else if tunnel.Status.TunnelID != "" {
		remote, err := cf.GetTunnel(ctx, tunnel.Status.TunnelID)
		if err != nil && !isRemoteNotFound(err) {
			return r.cleanupFailure(ctx, tunnel, status, clearIntent, "TunnelObserveFailed", fmt.Errorf("get Cloudflare Tunnel before deletion: %w", err))
		}
		if err == nil {
			if validationErr := validateRemoteTunnel(remote, accountID); validationErr != nil {
				return r.cleanupFailure(ctx, tunnel, status, clearIntent, "OwnershipMismatch", validationErr)
			}
			if err := cf.EvictTunnelConnections(ctx, tunnel.Status.TunnelID, nil); err != nil && !isRemoteNotFound(err) {
				return r.cleanupFailure(ctx, tunnel, status, clearIntent, "ConnectionEvictionFailed", err)
			}
			clients, _, err := cf.ListTunnelConnections(ctx, tunnel.Status.TunnelID, tunnelObservationLimit)
			if err != nil && !isRemoteNotFound(err) {
				return r.cleanupFailure(ctx, tunnel, status, clearIntent, "ConnectionObservationFailed", err)
			}
			status.Clients = tunnelClientStatuses(clients)
			clearIntent.Clients = true
			if tunnelClientsHaveConnections(clients) {
				setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForConnectionEviction", "Cloudflare Tunnel connections were evicted; waiting for the edge to report zero connections", tunnel.Generation, now), now)
				if err := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
			}
			if err := cf.DeleteTunnel(ctx, tunnel.Status.TunnelID, true); err != nil && !isRemoteNotFound(err) {
				return r.cleanupFailure(ctx, tunnel, status, clearIntent, "TunnelDeleteFailed", fmt.Errorf("delete Cloudflare Tunnel: %w", err))
			}
		}
	}

	return ctrl.Result{}, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current v1alpha1.CloudflareTunnel
		if err := r.Get(ctx, client.ObjectKeyFromObject(tunnel), &current); err != nil {
			return client.IgnoreNotFound(err)
		}
		before := current.DeepCopy()
		controllerutil.RemoveFinalizer(&current, v1alpha1.CloudflareTunnelFinalizer)
		return r.Patch(ctx, &current, client.MergeFrom(before))
	})
}

func (r *CloudflareTunnelReconciler) cleanupFailure(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, status v1alpha1.CloudflareTunnelStatus, clearIntent tunnelStatusClear, reason string, err error) (ctrl.Result, error) {
	now := r.now()
	setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, reason, err.Error(), tunnel.Generation, now), now)
	if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func isRemoteNotFound(err error) bool {
	return flarecloudflare.IsNotFound(err)
}

func (r *CloudflareTunnelReconciler) ensureRemoteTunnel(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, clusterID, accountID string) (RemoteTunnel, string, error) {
	// T0: the remote reads below are fresh reads by contract. The T2 gate in
	// reconcileActive decides whether this function runs at all; once it
	// runs, ObserveOnly observation, adoption claims, and ownership
	// validation must see the live remote — a stale snapshot would let an
	// adoption or a destructive update proceed on outdated ownership
	// evidence.
	policy := tunnel.Spec.ManagementPolicy
	if policy == "" {
		policy = v1alpha1.ManagementPolicyManaged
	}
	desiredName := desiredTunnelName(tunnel, clusterID)
	validate := func(remote RemoteTunnel) (RemoteTunnel, string, error) {
		if remote.Deleted() {
			return remote, fmt.Sprintf("remote Tunnel %s is deleted", remote.ID), nil
		}
		if err := validateRemoteTunnel(remote, accountID); err != nil {
			return remote, err.Error(), nil
		}
		return remote, "", nil
	}

	if policy == v1alpha1.ManagementPolicyObserveOnly {
		if tunnel.Spec.Tunnel.ExternalRef == nil || tunnel.Spec.Tunnel.ExternalRef.TunnelID == "" {
			return RemoteTunnel{}, "", errors.New("management policy ObserveOnly requires tunnel.externalRef.tunnelId")
		}
		remote, err := cf.GetTunnel(ctx, tunnel.Spec.Tunnel.ExternalRef.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("observe Cloudflare Tunnel: %w", err)
		}
		remote, conflict, err := validate(remote)
		if conflict != "" || err != nil {
			return remote, conflict, err
		}
		if expected := tunnel.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
			return remote, fmt.Sprintf("remote Tunnel name %q does not match expected name %q", remote.Name, expected), nil
		}
		return remote, "", nil
	}

	explicitAdoption := tunnel.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID &&
		tunnel.Spec.Tunnel.ExternalRef != nil &&
		tunnel.Spec.Tunnel.ExternalRef.TunnelID != "" &&
		tunnel.Spec.Adoption.Expect.Name != ""
	if tunnel.Status.TunnelID != "" && !tunnel.Status.OwnershipVerified {
		if !explicitAdoption {
			return RemoteTunnel{}, "status.tunnelId was observed without ownership; Managed requires explicit AdoptById with matching externalRef and adoption.expect.name", nil
		}
		if tunnel.Spec.Tunnel.ExternalRef.TunnelID != tunnel.Status.TunnelID {
			return RemoteTunnel{}, fmt.Sprintf("adoption externalRef %q does not match unverified observed status.tunnelId %q", tunnel.Spec.Tunnel.ExternalRef.TunnelID, tunnel.Status.TunnelID), nil
		}
	}

	var remote RemoteTunnel
	adopting := false
	switch {
	case tunnel.Status.TunnelID != "" && tunnel.Status.OwnershipVerified:
		observed, err := cf.GetTunnel(ctx, tunnel.Status.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("get managed Cloudflare Tunnel: %w", err)
		}
		remote = observed
	case tunnel.Spec.Tunnel.ExternalRef != nil:
		if !explicitAdoption {
			return RemoteTunnel{}, "a Managed externalRef requires adoption.mode AdoptById and adoption.expect.name", nil
		}
		observed, err := cf.GetTunnel(ctx, tunnel.Spec.Tunnel.ExternalRef.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("get Tunnel for adoption: %w", err)
		}
		remote = observed
		adopting = true
	default:
		created, err := cf.CreateTunnel(ctx, desiredName)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("create Cloudflare Tunnel: %w", err)
		}
		remote = created
	}

	remote, conflict, err := validate(remote)
	if conflict != "" || err != nil {
		return remote, conflict, err
	}
	if adopting && remote.Name != tunnel.Spec.Adoption.Expect.Name {
		return remote, fmt.Sprintf("remote Tunnel name %q does not match expected name %q", remote.Name, tunnel.Spec.Adoption.Expect.Name), nil
	}
	if remote.Name != desiredName {
		updated, err := cf.UpdateTunnelName(ctx, remote.ID, desiredName)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("reconcile Cloudflare Tunnel name: %w", err)
		}
		remote, conflict, err = validate(updated)
		if conflict != "" || err != nil {
			return remote, conflict, err
		}
	}
	return remote, "", nil
}

func desiredTunnelName(tunnel *v1alpha1.CloudflareTunnel, clusterID string) string {
	if tunnel.Spec.Tunnel.Name != "" {
		return tunnel.Spec.Tunnel.Name
	}
	return strings.Join([]string{clusterID, tunnel.Namespace, tunnel.Name}, "-")
}

func validateRemoteTunnel(remote RemoteTunnel, accountID string) error {
	if remote.Type != flarecloudflare.TunnelTypeCloudflared {
		return fmt.Errorf("remote Tunnel %s has type %s; expected CloudflareTunnel", remote.ID, remote.Type)
	}
	if remote.ConfigSource != flarecloudflare.TunnelConfigSourceCloudflare {
		return fmt.Errorf("remote Tunnel %s uses %s configuration; expected Cloudflare", remote.ID, remote.ConfigSource)
	}
	if accountID != "" && remote.AccountTag != accountID {
		return fmt.Errorf("remote Tunnel %s belongs to account %s; expected %s", remote.ID, remote.AccountTag, accountID)
	}
	return nil
}

func (r *CloudflareTunnelReconciler) ensureTokenSecret(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, tunnelID string) (*corev1.LocalObjectReference, error) {
	name := "flareway-tunnel-" + tunnel.Name
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: name}
	var existing corev1.Secret
	if err := r.Get(ctx, key, &existing); err == nil {
		if !metav1.IsControlledBy(&existing, tunnel) {
			return nil, fmt.Errorf("the Tunnel token Secret %s is not owned by this CloudflareTunnel", key)
		}
		if len(existing.Data[v1alpha1.CloudflareTunnelConnectorTokenSecretKey]) > 0 {
			return &corev1.LocalObjectReference{Name: name}, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get Tunnel token Secret %s: %w", key, err)
	}
	token, err := cf.GetTunnelToken(ctx, tunnelID)
	if err != nil {
		return nil, fmt.Errorf("get Tunnel token: %w", err)
	}
	if err := r.reconcileOwnedTokenSecret(ctx, tunnel, name, v1alpha1.CloudflareTunnelConnectorTokenSecretKey, token); err != nil {
		return nil, fmt.Errorf("reconcile Tunnel token Secret %s/%s: %w", tunnel.Namespace, name, err)
	}
	return &corev1.LocalObjectReference{Name: name}, nil
}

func (r *CloudflareTunnelReconciler) ensureManagementTokenSecret(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, tunnelID string) (*corev1.LocalObjectReference, error) {
	name := "flareway-tunnel-" + tunnel.Name + "-management"
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: name}
	if tunnel.Spec.ManagementToken == nil {
		var existing corev1.Secret
		if err := r.Get(ctx, key, &existing); err == nil && metav1.IsControlledBy(&existing, tunnel) {
			if err := r.Delete(ctx, &existing); err != nil && !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("delete obsolete Tunnel management token Secret %s: %w", key, err)
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("get Tunnel management token Secret %s: %w", key, err)
		}
		return nil, nil
	}

	var existing corev1.Secret
	if err := r.Get(ctx, key, &existing); err == nil {
		if !metav1.IsControlledBy(&existing, tunnel) {
			return nil, fmt.Errorf("the Tunnel management token Secret %s is not owned by this CloudflareTunnel", key)
		}
		if len(existing.Data[v1alpha1.CloudflareTunnelManagementTokenSecretKey]) > 0 {
			return &corev1.LocalObjectReference{Name: name}, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get Tunnel management token Secret %s: %w", key, err)
	}

	resources := make([]flarecloudflare.TunnelManagementResource, len(tunnel.Spec.ManagementToken.Resources))
	for index, resource := range tunnel.Spec.ManagementToken.Resources {
		switch resource {
		case v1alpha1.CloudflareTunnelManagementResourceLogs:
			resources[index] = flarecloudflare.TunnelManagementResourceLogs
		default:
			return nil, fmt.Errorf("unsupported Tunnel management token resource %q", resource)
		}
	}
	token, err := cf.IssueTunnelManagementToken(ctx, tunnelID, resources)
	if err != nil {
		return nil, fmt.Errorf("issue Tunnel management token: %w", err)
	}
	if err := r.reconcileOwnedTokenSecret(ctx, tunnel, name, v1alpha1.CloudflareTunnelManagementTokenSecretKey, token); err != nil {
		return nil, fmt.Errorf("reconcile Tunnel management token Secret %s: %w", key, err)
	}
	return &corev1.LocalObjectReference{Name: name}, nil
}

func (r *CloudflareTunnelReconciler) reconcileOwnedTokenSecret(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, name, dataKey, token string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tunnel.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.UID != "" && !metav1.IsControlledBy(secret, tunnel) {
			return fmt.Errorf("secret %s/%s is not owned by this CloudflareTunnel", secret.Namespace, secret.Name)
		}
		if err := controllerutil.SetControllerReference(tunnel, secret, r.Scheme); err != nil {
			return err
		}
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{dataKey: []byte(token)}
		return nil
	})
	return err
}

func (r *CloudflareTunnelReconciler) ensureDNS(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, gatewayName, clusterID, tunnelID string, hosts []publicHostname) ([]v1alpha1.CloudflareTunnelDNSRecordStatus, string, error) {
	// T0: every ListDNSRecords below is a fresh read before a destructive
	// write (create/update/delete of the record for that hostname). The T2
	// gate in reconcileActive decides whether ensureDNS runs at all; while
	// it runs, ownership and content must be re-verified live so a stale
	// checkpoint cannot delete or overwrite a record that changed hands
	// (safety condition 1).
	result := make([]v1alpha1.CloudflareTunnelDNSRecordStatus, 0, len(hosts))
	previousByHostname := make(map[string]v1alpha1.CloudflareTunnelDNSRecordStatus, len(tunnel.Status.DNSRecords))
	desiredHostnames := make(map[string]bool, len(hosts))
	ownershipComment := dnsOwnershipComment(tunnel, clusterID, gatewayName)
	ownershipMarkers := dnsOwnershipMarkers(tunnel, clusterID, gatewayName)
	expectedTargets := dnsRecordTargets(tunnel, tunnelID)
	for _, previous := range tunnel.Status.DNSRecords {
		normalized, err := flarecloudflare.NormalizeDNSHostname(previous.Hostname)
		if err != nil {
			return nil, "", fmt.Errorf("normalize previous DNS hostname %q: %w", previous.Hostname, err)
		}
		previousByHostname[normalized] = previous
	}
	for index := range hosts {
		normalized, err := flarecloudflare.NormalizeDNSHostname(hosts[index].Hostname)
		if err != nil {
			return nil, "", fmt.Errorf("normalize desired DNS hostname %q: %w", hosts[index].Hostname, err)
		}
		hosts[index].Hostname = normalized
		desiredHostnames[normalized] = true
	}
	conflicts := make([]string, 0)
	for _, previous := range tunnel.Status.DNSRecords {
		normalized, err := flarecloudflare.NormalizeDNSHostname(previous.Hostname)
		if err != nil {
			return nil, "", fmt.Errorf("normalize stale DNS hostname %q: %w", previous.Hostname, err)
		}
		if desiredHostnames[normalized] {
			continue
		}
		deleted, conflict, err := deleteDNSRecordIfOwned(ctx, cf, ownershipMarkers, expectedTargets, previous)
		if err != nil {
			return nil, "", fmt.Errorf("delete stale DNS record %s: %w", previous.Hostname, err)
		}
		if !deleted {
			result = append(result, previous)
			conflicts = append(conflicts, conflict)
		}
	}

	proxied := true
	if tunnel.Spec.DNS.Proxied != nil {
		proxied = *tunnel.Spec.DNS.Proxied
	}
	ttl := int64(1)
	if tunnel.Spec.DNS.TTL != nil {
		ttl = *tunnel.Spec.DNS.TTL
	}
	for _, host := range hosts {
		comment := ownershipComment
		desired := RemoteDNSRecordInput{
			Name: host.Hostname, Content: tunnelCNAMETarget(tunnelID), Comment: comment,
			Proxied: &proxied, TTL: &ttl, Settings: dnsSettingsInput(tunnel.Spec.DNS.Settings),
		}
		records, err := cf.ListDNSRecords(ctx, host.ZoneID, host.Hostname)
		if err != nil {
			return nil, "", fmt.Errorf("list DNS record %s: %w", host.Hostname, err)
		}
		if len(records) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("multiple DNS records already exist for %s", host.Hostname))
			if previous, ok := previousByHostname[host.Hostname]; ok {
				previous.State = dnsRecordStateConflict
				result = append(result, previous)
			}
			continue
		}

		var record RemoteDNSRecord
		if len(records) == 0 {
			record, err = cf.CreateCNAME(ctx, host.ZoneID, desired)
			if err != nil {
				return nil, "", fmt.Errorf("create DNS record %s: %w", host.Hostname, err)
			}
		} else {
			record = records[0]
			owned, reason := dnsRecordOwnedByGateway(record, ownershipMarkers)
			if !owned {
				conflicts = append(conflicts, fmt.Sprintf("DNS record %s is not owned by this Tunnel configuration (%s)", host.Hostname, reason))
				if previous, ok := previousByHostname[host.Hostname]; ok {
					previous.State = dnsRecordStateConflict
					result = append(result, previous)
				}
				continue
			}
			if !dnsRecordMatches(record, desired) {
				record, err = cf.UpdateCNAME(ctx, host.ZoneID, record.ID, desired)
				if err != nil {
					return nil, "", fmt.Errorf("update DNS record %s: %w", host.Hostname, err)
				}
			}
		}
		result = append(result, dnsRecordStatus(host.ZoneID, record))
	}
	slices.SortFunc(result, func(a, b v1alpha1.CloudflareTunnelDNSRecordStatus) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return result, strings.Join(conflicts, "; "), nil
}

func dnsRecordMatches(record RemoteDNSRecord, desired RemoteDNSRecordInput) bool {
	return flarecloudflare.DNSHostnamesEqual(record.Name, desired.Name) &&
		record.Comment == desired.Comment &&
		strings.EqualFold(record.Type, "CNAME") &&
		flarecloudflare.DNSHostnamesEqual(record.Content, desired.Content) &&
		desired.Proxied != nil && record.Proxied == *desired.Proxied &&
		desired.TTL != nil && record.TTL == *desired.TTL &&
		dnsSettingsEqual(record.Settings, desired.Settings)
}

func dnsSettingsInput(settings *v1alpha1.DNSRecordSettings) *flarecloudflare.DNSRecordSettings {
	if settings == nil {
		return nil
	}
	return &flarecloudflare.DNSRecordSettings{IPv4Only: settings.IPv4Only, IPv6Only: settings.IPv6Only}
}

func dnsSettingsEqual(observed, desired *flarecloudflare.DNSRecordSettings) bool {
	if desired == nil {
		return true
	}
	if observed == nil {
		return desired.IPv4Only == nil && desired.IPv6Only == nil
	}
	return optionalDesiredBoolEqual(observed.IPv4Only, desired.IPv4Only) &&
		optionalDesiredBoolEqual(observed.IPv6Only, desired.IPv6Only)
}

func optionalDesiredBoolEqual(observed, desired *bool) bool {
	return desired == nil || observed != nil && *observed == *desired
}

func dnsRecordStatus(zoneID string, record RemoteDNSRecord) v1alpha1.CloudflareTunnelDNSRecordStatus {
	proxied := record.Proxied
	proxiable := record.Proxiable
	return v1alpha1.CloudflareTunnelDNSRecordStatus{
		Hostname: record.Name, RecordID: record.ID, ZoneID: zoneID,
		OwnershipComment: record.Comment, State: dnsRecordStateReady,
		TTL: record.TTL, Proxied: &proxied, Proxiable: &proxiable,
		Settings:  dnsStatusSettings(record.Settings),
		CreatedOn: timeStatus(record.CreatedOn), ModifiedOn: timeStatus(record.ModifiedOn),
		CommentModifiedOn: timeStatus(record.CommentModifiedOn),
	}
}

func dnsStatusSettings(settings *flarecloudflare.DNSRecordSettings) *v1alpha1.DNSRecordSettings {
	if settings == nil {
		return nil
	}
	return &v1alpha1.DNSRecordSettings{IPv4Only: settings.IPv4Only, IPv6Only: settings.IPv6Only}
}

func timeStatus(value time.Time) *metav1.Time {
	if value.IsZero() {
		return nil
	}
	result := metav1.NewTime(value)
	return &result
}

func optionalTimeStatus(value *time.Time) *metav1.Time {
	if value == nil {
		return nil
	}
	result := metav1.NewTime(*value)
	return &result
}

func projectRemoteTunnelStatus(status *v1alpha1.CloudflareTunnelStatus, remote RemoteTunnel, generation int64) {
	status.TunnelID = remote.ID
	status.AccountID = remote.AccountTag
	status.Name = remote.Name
	status.TunnelType = tunnelRemoteTypeStatus(remote.Type)
	status.ConfigSource = tunnelConfigSourceStatus(remote.ConfigSource)
	status.ConnectorState = connectorState(remote.Status)
	status.CreatedAt = timeStatus(remote.CreatedAt)
	status.DeletedAt = optionalTimeStatus(remote.DeletedAt)
	status.ConnectionsActiveAt = optionalTimeStatus(remote.ConnectionsActiveAt)
	status.ConnectionsInactiveAt = optionalTimeStatus(remote.ConnectionsInactiveAt)
	status.OwnershipVerified = true
	status.ObservedGeneration = generation
}

func tunnelRemoteTypeStatus(value flarecloudflare.TunnelType) v1alpha1.TunnelRemoteType {
	switch value {
	case flarecloudflare.TunnelTypeCloudflared:
		return v1alpha1.TunnelRemoteTypeCloudflareTunnel
	case flarecloudflare.TunnelTypeWARPConnector:
		return v1alpha1.TunnelRemoteTypeWARPConnector
	case flarecloudflare.TunnelTypeWARP:
		return v1alpha1.TunnelRemoteTypeWARP
	case flarecloudflare.TunnelTypeMagic:
		return v1alpha1.TunnelRemoteTypeMagic
	case flarecloudflare.TunnelTypeIPSec:
		return v1alpha1.TunnelRemoteTypeIPSec
	case flarecloudflare.TunnelTypeGRE:
		return v1alpha1.TunnelRemoteTypeGRE
	case flarecloudflare.TunnelTypeCNI:
		return v1alpha1.TunnelRemoteTypeCNI
	default:
		return ""
	}
}

func tunnelConfigSourceStatus(value flarecloudflare.TunnelConfigSource) v1alpha1.TunnelConfigSource {
	switch value {
	case flarecloudflare.TunnelConfigSourceCloudflare:
		return v1alpha1.TunnelConfigSourceCloudflare
	case flarecloudflare.TunnelConfigSourceLocal:
		return v1alpha1.TunnelConfigSourceLocal
	default:
		return ""
	}
}

func tunnelClientStatuses(clients []flarecloudflare.TunnelConnector) []v1alpha1.CloudflareTunnelClientStatus {
	result := make([]v1alpha1.CloudflareTunnelClientStatus, 0, min(len(clients), int(tunnelObservationLimit)))
	for _, observed := range clients {
		if len(result) == int(tunnelObservationLimit) {
			break
		}
		features := slices.Clone(observed.Features)
		if len(features) > int(tunnelObservationLimit) {
			features = features[:tunnelObservationLimit]
		}
		status := v1alpha1.CloudflareTunnelClientStatus{
			ID: observed.ID, Arch: observed.Architecture, ConfigVersion: observed.ConfigVersion,
			Features: features, RunAt: timeStatus(observed.RunAt), Version: observed.Version,
		}
		for _, connection := range observed.Connections {
			if len(status.Connections) == int(tunnelObservationLimit) {
				break
			}
			status.Connections = append(status.Connections, v1alpha1.CloudflareTunnelConnectionStatus{
				ID: connection.ID, ClientID: connection.ClientID, ClientVersion: connection.ClientVersion,
				ColoName: connection.ColoName, OpenedAt: timeStatus(connection.OpenedAt),
				OriginIP: connection.OriginIP, UUID: connection.UUID,
			})
		}
		result = append(result, status)
	}
	slices.SortFunc(result, func(a, b v1alpha1.CloudflareTunnelClientStatus) int { return strings.Compare(a.ID, b.ID) })
	return result
}

func tunnelClientsHaveConnections(clients []flarecloudflare.TunnelConnector) bool {
	for _, client := range clients {
		if len(client.Connections) > 0 || client.ConnectionsTruncated {
			return true
		}
	}
	return false
}

func directTunnelConfiguration(spec *v1alpha1.CloudflareTunnelDirectConfiguration) (ir.TunnelConfiguration, error) {
	if spec == nil {
		return ir.TunnelConfiguration{}, errors.New("configuration mode Direct requires spec.configuration.direct")
	}
	result := ir.TunnelConfiguration{
		Ingress:       make([]ir.TunnelIngress, 0, len(spec.Ingress)),
		OriginRequest: directOriginRequest(spec.OriginRequest),
	}
	if spec.WARPRouting != nil {
		result.WARPRouting = &ir.WARPRouting{
			Enabled: spec.WARPRouting.Enabled, ConnectTimeout: spec.WARPRouting.ConnectTimeout,
			TCPKeepAlive: spec.WARPRouting.TCPKeepAlive, MaxActiveFlows: spec.WARPRouting.MaxActiveFlows,
		}
	}
	for _, ingress := range spec.Ingress {
		hostname := ingress.Hostname
		if hostname != "" && hostname != "*" {
			normalized, err := flarecloudflare.NormalizeDNSHostname(hostname)
			if err != nil {
				return ir.TunnelConfiguration{}, fmt.Errorf("normalize Direct ingress hostname %q: %w", hostname, err)
			}
			hostname = normalized
		}
		result.Ingress = append(result.Ingress, ir.TunnelIngress{
			Hostname: hostname, Path: ingress.Path,
			Service:       directIngressService(ingress.Service),
			OriginRequest: directOriginRequest(ingress.OriginRequest),
		})
	}
	return result, nil
}

func directIngressService(service v1alpha1.CloudflareTunnelIngressService) ir.TunnelIngressService {
	result := ir.TunnelIngressService{}
	if service.HTTP != nil {
		result.HTTP = &ir.TunnelAddressService{Address: service.HTTP.Address}
	}
	if service.HTTPS != nil {
		result.HTTPS = &ir.TunnelAddressService{Address: service.HTTPS.Address}
	}
	if service.TCP != nil {
		result.TCP = &ir.TunnelAddressService{Address: service.TCP.Address}
	}
	if service.SSH != nil {
		result.SSH = &ir.TunnelAddressService{Address: service.SSH.Address}
	}
	if service.RDP != nil {
		result.RDP = &ir.TunnelAddressService{Address: service.RDP.Address}
	}
	if service.SMB != nil {
		result.SMB = &ir.TunnelAddressService{Address: service.SMB.Address}
	}
	if service.Unix != nil {
		result.Unix = &ir.TunnelUnixService{Path: service.Unix.Path}
	}
	if service.UnixTLS != nil {
		result.UnixTLS = &ir.TunnelUnixService{Path: service.UnixTLS.Path}
	}
	if service.HelloWorld != nil {
		result.HelloWorld = &ir.TunnelBuiltinService{}
	}
	if service.HTTPStatus != nil {
		result.HTTPStatus = &ir.TunnelHTTPStatusService{Code: service.HTTPStatus.Code}
	}
	if service.Bastion != nil {
		result.Bastion = &ir.TunnelBuiltinService{}
	}
	return result
}

func directOriginRequest(origin *v1alpha1.CloudflareTunnelOriginRequest) *ir.OriginRequest {
	if origin == nil {
		return nil
	}
	result := &ir.OriginRequest{
		CAPool: origin.CAPool, ConnectTimeout: origin.ConnectTimeout,
		DisableChunkedEncoding: origin.DisableChunkedEncoding, HTTP2Origin: origin.HTTP2Origin,
		HTTPHostHeader: origin.HTTPHostHeader, KeepAliveConnections: origin.KeepAliveConnections,
		KeepAliveTimeout: origin.KeepAliveTimeout, MatchSNIToHost: origin.MatchSNIToHost,
		NoHappyEyeballs: origin.NoHappyEyeballs, NoTLSVerify: origin.NoTLSVerify,
		OriginServerName: origin.OriginServerName, TCPKeepAlive: origin.TCPKeepAlive,
		TLSTimeout: origin.TLSTimeout,
	}
	if origin.ProxyType != nil {
		proxyType := ir.OriginProxyType(*origin.ProxyType)
		result.ProxyType = &proxyType
	}
	if origin.Access != nil {
		result.Access = &ir.OriginAccess{
			AUDTags: slices.Clone(origin.Access.AUDTags), TeamName: origin.Access.TeamName,
			Required: origin.Access.Required,
		}
	}
	for _, rule := range origin.IPRules {
		result.IPRules = append(result.IPRules, ir.OriginIPRule{
			Prefix: rule.Prefix, Ports: slices.Clone(rule.Ports), Allow: rule.Allow,
		})
	}
	return result
}

func validateRemoteConfiguration(configuration flarecloudflare.TunnelConfiguration, accountID, tunnelID string) error {
	if configuration.Source != flarecloudflare.TunnelConfigSourceCloudflare {
		return fmt.Errorf("remote Tunnel %s configuration source is %s; expected Cloudflare", tunnelID, configuration.Source)
	}
	if configuration.AccountID != accountID {
		return fmt.Errorf("remote Tunnel %s configuration belongs to account %s; expected %s", tunnelID, configuration.AccountID, accountID)
	}
	if configuration.TunnelID != tunnelID {
		return fmt.Errorf("the Cloudflare service returned configuration for Tunnel %s while reconciling %s", configuration.TunnelID, tunnelID)
	}
	return nil
}

func (r *CloudflareTunnelReconciler) reconcileConfiguration(
	ctx context.Context,
	cf TunnelCloudflareClient,
	tunnel *v1alpha1.CloudflareTunnel,
	account *v1alpha1.CloudflareAccount,
	mode v1alpha1.CloudflareTunnelConfigurationMode,
	status *v1alpha1.CloudflareTunnelStatus,
	now metav1.Time,
) error {
	if mode == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		// G4: Gateway mode configuration is owned and observed exclusively by
		// GatewayReconciler, which also publishes status.configVersion. The
		// Tunnel reconciler performs no remote configuration calls here and
		// carries the existing status forward unchanged.
		status.ConfigVersion = tunnel.Status.ConfigVersion
		return nil
	}

	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		configuration, err := cf.GetTunnelConfiguration(ctx, status.TunnelID)
		if err != nil {
			return fmt.Errorf("observe Tunnel configuration: %w", err)
		}
		if err := validateRemoteConfiguration(configuration, account.Spec.AccountID, status.TunnelID); err != nil {
			return err
		}
		status.ConfigVersion.Remote = configuration.Version
		status.ConfigVersion.CreatedAt = timeStatus(configuration.CreatedAt)
		setStatusCondition(status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "ObserveOnly", "ObserveOnly does not write Tunnel configuration", tunnel.Generation, now), now)
		return nil
	}

	configuration, err := directTunnelConfiguration(tunnel.Spec.Configuration.Direct)
	if err != nil {
		return err
	}
	params, hash, err := cloudflaredconfig.CompileDirect(account.Spec.AccountID, configuration)
	if err != nil {
		return err
	}
	var applied flarecloudflare.TunnelConfiguration
	err = cf.WithTunnelLock(ctx, status.TunnelID, func() error {
		// T0: reads inside this closure are never gate-served. The lock
		// protects a read-modify-write; a stale snapshot here would let a
		// concurrent writer's change be silently overwritten (safety
		// condition 4).
		remote, getErr := cf.GetTunnelConfiguration(ctx, status.TunnelID)
		if getErr == nil {
			if err := validateRemoteConfiguration(remote, account.Spec.AccountID, status.TunnelID); err != nil {
				return err
			}
			if tunnel.Status.ConfigVersion.DesiredHash == hash &&
				tunnel.Status.ConfigVersion.Desired > 0 &&
				remote.Version == tunnel.Status.ConfigVersion.Desired {
				applied = remote
				return nil
			}
			if tunnel.Status.ConfigVersion.Applied > 0 && remote.Version != tunnel.Status.ConfigVersion.Applied {
				setStatusCondition(status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "ConfigurationChanged", fmt.Sprintf("Cloudflare configuration version is %d, expected applied version %d; restoring Direct configuration", remote.Version, tunnel.Status.ConfigVersion.Applied), tunnel.Generation, now), now)
			}
		} else if !isRemoteNotFound(getErr) {
			return getErr
		}
		updated, updateErr := cf.UpdateTunnelConfiguration(ctx, status.TunnelID, params)
		if updateErr != nil {
			return updateErr
		}
		if err := validateRemoteConfiguration(updated, account.Spec.AccountID, status.TunnelID); err != nil {
			return err
		}
		applied = updated
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile Direct Tunnel configuration: %w", err)
	}
	status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
		Desired: applied.Version, DesiredHash: hash, Applied: applied.Version,
		Remote: applied.Version, CreatedAt: timeStatus(applied.CreatedAt),
		AppliedAt: &now,
	}
	setStatusCondition(status, tunnelCondition(v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", fmt.Sprintf("Direct Tunnel configuration version %d is applied", applied.Version), tunnel.Generation, now), now)
	return nil
}

// tunnelConvergedForGate reports whether the Tunnel is in the steady state the
// desired-hash gate may shorten. Every check is a local read: a bound and
// verified remote identity on the expected account, a Ready condition that
// observed the current generation, and a checkpointed DNS record set that
// exactly matches the desired bindings. Any doubt closes the gate and the
// reconcile pays the normal remote reads.
func tunnelConvergedForGate(tunnel *v1alpha1.CloudflareTunnel, account *v1alpha1.CloudflareAccount, hosts []publicHostname) bool {
	if tunnel.Status.TunnelID == "" || !tunnel.Status.OwnershipVerified {
		return false
	}
	if tunnel.Status.AccountID != account.Spec.AccountID {
		return false
	}
	ready := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || ready.ObservedGeneration != tunnel.Generation {
		return false
	}
	desired := make(map[string]string, len(hosts))
	for _, host := range hosts {
		normalized, err := flarecloudflare.NormalizeDNSHostname(host.Hostname)
		if err != nil {
			return false
		}
		desired[normalized] = host.ZoneID
	}
	checkpointed := make(map[string]string, len(tunnel.Status.DNSRecords))
	for _, record := range tunnel.Status.DNSRecords {
		if record.State != dnsRecordStateReady {
			return false
		}
		normalized, err := flarecloudflare.NormalizeDNSHostname(record.Hostname)
		if err != nil {
			return false
		}
		checkpointed[normalized] = record.ZoneID
	}
	return maps.Equal(desired, checkpointed)
}

// tunnelGateStatusUnchanged reports whether the fields an open-gate pass can
// mutate are already equal to the persisted status, so the pass can skip the
// status apply entirely (QA-030: an open pass costs zero etcd writes).
func tunnelGateStatusUnchanged(current, projected v1alpha1.CloudflareTunnelStatus) bool {
	return localObjectRefEqual(current.ConnectorTokenSecretRef, projected.ConnectorTokenSecretRef) &&
		localObjectRefEqual(current.ManagementTokenSecretRef, projected.ManagementTokenSecretRef) &&
		slices.Equal(current.Addresses, projected.Addresses) &&
		slices.EqualFunc(current.Clients, projected.Clients, tunnelClientStatusEqual)
}

func localObjectRefEqual(left, right *corev1.LocalObjectReference) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Name == right.Name
}

func tunnelClientStatusEqual(left, right v1alpha1.CloudflareTunnelClientStatus) bool {
	return left.ID == right.ID && left.Arch == right.Arch &&
		left.ConfigVersion == right.ConfigVersion && left.Version == right.Version &&
		slices.Equal(left.Features, right.Features) &&
		timeStatusEqual(left.RunAt, right.RunAt) &&
		slices.EqualFunc(left.Connections, right.Connections, tunnelConnectionStatusEqual)
}

func tunnelConnectionStatusEqual(left, right v1alpha1.CloudflareTunnelConnectionStatus) bool {
	return left.ID == right.ID && left.ClientID == right.ClientID &&
		left.ClientVersion == right.ClientVersion && left.ColoName == right.ColoName &&
		left.OriginIP == right.OriginIP && left.UUID == right.UUID &&
		timeStatusEqual(left.OpenedAt, right.OpenedAt)
}

// removeDNSRecords revalidates each status identity before deletion. An empty
// expectedComments uses the per-record checkpoint and is reserved for
// Gateway-absent teardown, where the current owner identity is unavailable.
// expectedTargets lists the CNAME targets this Tunnel may legitimately point
// at; a record whose content no longer matches any of them is preserved.
func removeDNSRecords(
	ctx context.Context,
	cf TunnelCloudflareClient,
	expectedComments []string,
	expectedTargets []string,
	records []v1alpha1.CloudflareTunnelDNSRecordStatus,
) ([]v1alpha1.CloudflareTunnelDNSRecordStatus, string, error) {
	remaining := make([]v1alpha1.CloudflareTunnelDNSRecordStatus, 0)
	conflicts := make([]string, 0)
	for _, record := range records {
		deleted, conflict, err := deleteDNSRecordIfOwned(ctx, cf, expectedComments, expectedTargets, record)
		if err != nil {
			return nil, "", fmt.Errorf("delete managed DNS record %s: %w", record.Hostname, err)
		}
		if !deleted {
			remaining = append(remaining, record)
			conflicts = append(conflicts, conflict)
		}
	}
	return remaining, strings.Join(conflicts, "; "), nil
}

func (r *CloudflareTunnelReconciler) cloudflareClient(ctx context.Context, account *v1alpha1.CloudflareAccount) (TunnelCloudflareClient, error) {
	if r.NewCloudflareClient == nil {
		return nil, errors.New("the CloudflareTunnel reconciler requires NewCloudflareClient")
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	key := ref.Key
	if key == "" {
		key = "token"
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &secret); err != nil {
		return nil, fmt.Errorf("get Cloudflare API token Secret: %w", err)
	}
	token := secret.Data[key]
	if len(token) == 0 {
		return nil, fmt.Errorf("cloudflare API token Secret %s/%s has no %q key", ref.Namespace, ref.Name, key)
	}
	cf, err := r.NewCloudflareClient(string(token), account.Spec.AccountID)
	if err != nil {
		return nil, fmt.Errorf("construct Cloudflare client: %w", err)
	}
	return cf, nil
}

// selectLiveTunnelGateway is the shared ownership authority for Tunnel and
// Gateway reconciliation. It deliberately returns the full Gateway identity so
// writers can authorize namespace, name, and UID rather than trusting status.
func selectLiveTunnelGateway(ctx context.Context, reader client.Reader, tunnel *v1alpha1.CloudflareTunnel) (*gatewayv1.Gateway, []string, bool, error) {
	if tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		return nil, nil, false, nil
	}
	var gateways gatewayv1.GatewayList
	if err := reader.List(ctx, &gateways, client.InNamespace(tunnel.Namespace)); err != nil {
		return nil, nil, false, fmt.Errorf("list Gateways: %w", err)
	}
	owners := make([]gatewayv1.Gateway, 0)
	for i := range gateways.Items {
		gateway := &gateways.Items[i]
		if !gateway.DeletionTimestamp.IsZero() {
			continue
		}
		if gatewayClaimsTunnel(gateway, tunnel) {
			owners = append(owners, *gateway)
		}
	}
	slices.SortFunc(owners, func(a, b gatewayv1.Gateway) int {
		if cmp := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Name, b.Name)
	})

	if tunnel.Status.GatewayRef != nil && tunnel.Status.GatewayRef.Name != "" && tunnel.Status.GatewayUID != "" {
		for i := range owners {
			if owners[i].Name == tunnel.Status.GatewayRef.Name && owners[i].UID == tunnel.Status.GatewayUID {
				extra := make([]string, 0, len(owners)-1)
				for j := range owners {
					if j != i {
						extra = append(extra, owners[j].Name)
					}
				}
				return owners[i].DeepCopy(), extra, false, nil
			}
		}
	}

	if tunnel.Status.GatewayRef != nil && tunnel.Status.GatewayRef.Name != "" {
		drained, err := tunnelGatewayDataplaneDrained(ctx, reader, tunnel)
		if err != nil {
			return nil, nil, false, err
		}
		if !drained {
			extra := make([]string, 0, len(owners))
			for i := range owners {
				extra = append(extra, owners[i].Name)
			}
			return nil, extra, true, nil
		}
	}
	if len(owners) == 0 {
		return nil, nil, false, nil
	}
	extra := make([]string, 0, len(owners)-1)
	for i := 1; i < len(owners); i++ {
		extra = append(extra, owners[i].Name)
	}
	return owners[0].DeepCopy(), extra, false, nil
}

func tunnelGatewayStatusIdentityMatches(tunnel *v1alpha1.CloudflareTunnel, gateway *gatewayv1.Gateway) bool {
	return tunnel != nil && gateway != nil &&
		tunnel.Status.GatewayRef != nil &&
		tunnel.Status.GatewayRef.Name == gateway.Name &&
		tunnel.Status.GatewayUID != "" &&
		tunnel.Status.GatewayUID == gateway.UID
}

func liveRecordedTunnelGateway(ctx context.Context, reader client.Reader, tunnel *v1alpha1.CloudflareTunnel) (*gatewayv1.Gateway, error) {
	if tunnel == nil || tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" || tunnel.Status.GatewayUID == "" {
		return nil, nil
	}
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: tunnel.Status.GatewayRef.Name}
	var gateway gatewayv1.Gateway
	if err := reader.Get(ctx, key, &gateway); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get recorded Gateway %s: %w", key, err)
	}
	if gateway.UID != tunnel.Status.GatewayUID || !gateway.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	if !gatewayClaimsTunnel(&gateway, tunnel) {
		return nil, nil
	}
	return &gateway, nil
}

func gatewayClaimsTunnel(gateway *gatewayv1.Gateway, tunnel *v1alpha1.CloudflareTunnel) bool {
	if gateway == nil || tunnel == nil {
		return false
	}
	if gatewayReferencesTunnel(gateway, tunnel.Name) {
		return true
	}
	return (gateway.Spec.Infrastructure == nil || gateway.Spec.Infrastructure.ParametersRef == nil) &&
		gateway.Name == tunnel.Name &&
		metav1.IsControlledBy(tunnel, gateway)
}

func gatewayReferencesTunnel(gateway *gatewayv1.Gateway, tunnelName string) bool {
	if gateway.Spec.Infrastructure == nil || gateway.Spec.Infrastructure.ParametersRef == nil {
		return false
	}
	ref := gateway.Spec.Infrastructure.ParametersRef
	return string(ref.Group) == v1alpha1.Group && string(ref.Kind) == "CloudflareTunnel" && string(ref.Name) == tunnelName
}

type publicHostname struct {
	Hostname string
	ZoneID   string
	ZoneName string
}

type listenerBinding struct {
	Hostname    string
	Zone        string
	Exposure    v1alpha1.Exposure
	Unprotected bool
}

func tunnelGatewayBindings(tunnel *v1alpha1.CloudflareTunnel, gateway *gatewayv1.Gateway, zones []v1alpha1.CloudflareVerifiedZone) ([]publicHostname, []listenerBinding, error) {
	exposures := make(map[gatewayv1.SectionName]v1alpha1.Exposure, len(tunnel.Spec.Listeners))
	for _, listener := range tunnel.Spec.Listeners {
		exposure := listener.Exposure
		if exposure == "" {
			exposure = v1alpha1.ExposurePublic
		}
		exposures[listener.Name] = exposure
	}
	public := make([]publicHostname, 0)
	bindings := make([]listenerBinding, 0, len(gateway.Spec.Listeners))
	seen := map[string]v1alpha1.Exposure{}
	for _, listener := range gateway.Spec.Listeners {
		if listener.Hostname == nil || *listener.Hostname == "" {
			return nil, nil, fmt.Errorf("gateway listener %s must have a hostname in Cloudflare mode", listener.Name)
		}
		hostname := strings.ToLower(string(*listener.Hostname))
		exposure := exposures[listener.Name]
		if exposure == "" {
			exposure = v1alpha1.ExposurePublic
		}
		previous, duplicate := seen[hostname]
		if duplicate && previous != exposure {
			return nil, nil, fmt.Errorf("hostname exposure must be unique per Gateway: %s", hostname)
		}
		seen[hostname] = exposure
		binding := listenerBinding{Hostname: hostname, Exposure: exposure}
		if exposure == v1alpha1.ExposurePublic {
			zone, ok := zoneForHostname(hostname, zones)
			if !ok {
				return nil, nil, fmt.Errorf("zone not found for hostname %s", hostname)
			}
			binding.Zone = zone.Name
			if !duplicate {
				public = append(public, publicHostname{Hostname: hostname, ZoneID: zone.ID, ZoneName: zone.Name})
			}
		}
		bindings = append(bindings, binding)
	}
	slices.SortFunc(public, func(a, b publicHostname) int { return strings.Compare(a.Hostname, b.Hostname) })
	return public, bindings, nil
}

func tunnelConfigurationMode(tunnel *v1alpha1.CloudflareTunnel) v1alpha1.CloudflareTunnelConfigurationMode {
	if tunnel.Spec.Configuration.Mode == "" {
		return v1alpha1.CloudflareTunnelConfigurationModeGateway
	}
	return tunnel.Spec.Configuration.Mode
}

func directTunnelBindings(tunnel *v1alpha1.CloudflareTunnel, zones []v1alpha1.CloudflareVerifiedZone) ([]publicHostname, []listenerBinding, error) {
	direct := tunnel.Spec.Configuration.Direct
	if direct == nil {
		return nil, nil, errors.New("configuration mode Direct requires spec.configuration.direct")
	}
	public := make([]publicHostname, 0, len(direct.Ingress))
	bindings := make([]listenerBinding, 0, len(direct.Ingress))
	bindingByHostname := make(map[string]int, len(direct.Ingress))
	for _, ingress := range direct.Ingress {
		if ingress.Hostname == "" || ingress.Hostname == "*" {
			continue
		}
		hostname, err := flarecloudflare.NormalizeDNSHostname(ingress.Hostname)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid Direct ingress hostname %q: %w", ingress.Hostname, err)
		}
		unprotected := !directIngressOriginAccessEffective(direct.OriginRequest, ingress.OriginRequest)
		if index, duplicate := bindingByHostname[hostname]; duplicate {
			bindings[index].Unprotected = bindings[index].Unprotected || unprotected
			continue
		}
		zone, ok := zoneForHostname(hostname, zones)
		if !ok {
			return nil, nil, fmt.Errorf("zone not found for hostname %s", hostname)
		}
		bindingByHostname[hostname] = len(bindings)
		public = append(public, publicHostname{Hostname: hostname, ZoneID: zone.ID, ZoneName: zone.Name})
		bindings = append(bindings, listenerBinding{
			Hostname: hostname, Zone: zone.Name, Exposure: v1alpha1.ExposurePublic, Unprotected: unprotected,
		})
	}
	slices.SortFunc(public, func(a, b publicHostname) int { return strings.Compare(a.Hostname, b.Hostname) })
	slices.SortFunc(bindings, func(a, b listenerBinding) int { return strings.Compare(a.Hostname, b.Hostname) })
	return public, bindings, nil
}
func directIngressOriginAccessEffective(global, ingress *v1alpha1.CloudflareTunnelOriginRequest) bool {
	var access *v1alpha1.CloudflareTunnelOriginAccess
	if ingress != nil {
		access = ingress.Access
	} else if global != nil {
		access = global.Access
	}
	return access != nil && access.Required != nil && *access.Required
}

func zoneForHostname(hostname string, zones []v1alpha1.CloudflareVerifiedZone) (v1alpha1.CloudflareVerifiedZone, bool) {
	hostname = strings.TrimPrefix(strings.ToLower(hostname), "*.")
	var best v1alpha1.CloudflareVerifiedZone
	for _, zone := range zones {
		name := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		if hostname != name && !strings.HasSuffix(hostname, "."+name) {
			continue
		}
		if len(name) > len(best.Name) {
			best = zone
		}
	}
	return best, best.ID != ""
}

func authorizeBindings(
	account *v1alpha1.CloudflareAccount,
	namespace *corev1.Namespace,
	bindings []listenerBinding,
	platformObject bool,
) authz.Decision {
	if len(bindings) == 0 {
		return authz.Evaluate(account, namespace, authz.Request{PlatformObject: platformObject})
	}
	for _, binding := range bindings {
		decision := authz.Evaluate(account, namespace, authz.Request{
			Hostname:       binding.Hostname,
			Zone:           binding.Zone,
			Exposure:       binding.Exposure,
			Unprotected:    binding.Unprotected,
			PlatformObject: platformObject,
		})
		if !decision.Allowed {
			return decision
		}
	}
	return authz.Decision{Allowed: true, Reason: authz.ReasonAllowed, Message: "all Tunnel bindings are granted"}
}

func connectorState(status flarecloudflare.TunnelStatus) v1alpha1.ConnectorState {
	switch status {
	case flarecloudflare.TunnelStatusHealthy:
		return v1alpha1.ConnectorStateHealthy
	case flarecloudflare.TunnelStatusDegraded:
		return v1alpha1.ConnectorStateDegraded
	case flarecloudflare.TunnelStatusDown:
		return v1alpha1.ConnectorStateDown
	default:
		return v1alpha1.ConnectorStateInactive
	}
}

// tunnelCNAMETarget is the CNAME content a managed DNS record must point at.
func tunnelCNAMETarget(tunnelID string) string {
	return tunnelID + ".cfargotunnel.com"
}

func tunnelAddresses(tunnelID string, public bool) []gatewayv1.GatewayStatusAddress {
	if !public || tunnelID == "" {
		return nil
	}
	addressType := gatewayv1.HostnameAddressType
	return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: tunnelCNAMETarget(tunnelID)}}
}

func deleteDNSRecordIfOwned(
	ctx context.Context,
	cf TunnelCloudflareClient,
	expectedComments []string,
	expectedTargets []string,
	expected v1alpha1.CloudflareTunnelDNSRecordStatus,
) (bool, string, error) {
	expectedName, err := flarecloudflare.NormalizeDNSHostname(expected.Hostname)
	if err != nil {
		return false, "", fmt.Errorf("normalize managed DNS hostname %q: %w", expected.Hostname, err)
	}
	records, err := cf.ListDNSRecords(ctx, expected.ZoneID, expectedName)
	if err != nil {
		return false, "", fmt.Errorf("re-read managed DNS record %s: %w", expected.Hostname, err)
	}
	if len(records) == 0 {
		return true, "", nil
	}
	comments := expectedComments
	if len(comments) == 0 {
		comments = []string{expected.OwnershipComment}
	}
	for _, current := range records {
		if current.ID != expected.RecordID {
			continue
		}
		currentName, err := flarecloudflare.NormalizeDNSHostname(current.Name)
		if err != nil {
			return false, "", fmt.Errorf("normalize current DNS hostname %q: %w", current.Name, err)
		}
		matched := ""
		for _, comment := range comments {
			if comment != "" && current.Comment == comment {
				matched = comment
				break
			}
		}
		if matched == "" {
			if len(comments) == 1 && comments[0] == "" {
				return false, fmt.Sprintf(
					"DNS record %s (%s) has no checkpointed ownership comment",
					expected.Hostname, expected.RecordID,
				), nil
			}
			return false, fmt.Sprintf(
				"DNS record %s (%s) no longer has the exact name and ownership comment managed by this Tunnel",
				expected.Hostname, expected.RecordID,
			), nil
		}
		if currentName != expectedName {
			return false, fmt.Sprintf(
				"DNS record %s (%s) no longer has the exact name and ownership comment managed by this Tunnel",
				expected.Hostname, expected.RecordID,
			), nil
		}
		// D8: the marker alone never authorizes a destructive write. The
		// record must also still point at a tunnel target this controller
		// manages; when no target is known the record is preserved.
		owned := false
		for _, target := range expectedTargets {
			if flarecloudflare.IsOwnedDNSRecordStrict(flarecloudflare.OwnedDNSRecordCheck{
				Record: current, ExpectedComment: matched, ExpectedTarget: target,
			}) {
				owned = true
				break
			}
		}
		if !owned {
			return false, fmt.Sprintf(
				"DNS record %s (%s) no longer points at a Tunnel target managed by this Tunnel",
				expected.Hostname, expected.RecordID,
			), nil
		}
		if err := cf.DeleteDNSRecord(ctx, expected.ZoneID, expected.RecordID); err != nil && !isRemoteNotFound(err) {
			return false, "", err
		}
		return true, "", nil
	}
	return true, "", nil
}

// dnsOwnershipComment returns the comment written on DNS records managed by
// this Tunnel: the plaintext ownership marker plus the operator's optional
// user-facing text.
//
// D14: DNS markers are deliberately NOT HMAC-signed, unlike Access tags.
// Two reasons. First, the destructive DNS path already requires the record
// content to match a managed tunnel target (D12), so a forged marker cannot
// make this operator delete a foreign record; adoption is convergent and
// harmless. Second, the comment is what an operator reads in the Cloudflare
// dashboard to find the owning cluster and Gateway, and an opaque digest
// would destroy that. Signing would also force one UpdateCNAME per managed
// record at upgrade purely to rewrite the marker.
func dnsOwnershipComment(tunnel *v1alpha1.CloudflareTunnel, clusterID, gatewayName string) string {
	return flarecloudflare.DNSRecordCommentWithText(clusterID, tunnel.Namespace, gatewayName, tunnel.Spec.DNS.RecordComment)
}

// dnsOwnershipMarkers returns the ownership markers that may legitimately
// appear on a DNS record managed by this Tunnel.
//
// This is the bare ownership marker, never the comment with the operator's
// user-facing text appended. A record's stored comment is either exactly the
// marker or the marker followed by that text, and IsOwnedDNSRecordStrict
// accepts both shapes. Passing the text-bearing comment here would make a
// record written before spec.dns.recordComment changed look unowned.
func dnsOwnershipMarkers(tunnel *v1alpha1.CloudflareTunnel, clusterID, gatewayName string) []string {
	return []string{flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName)}
}

// dnsRecordTargets returns the CNAME targets this Tunnel may legitimately
// point at: the current tunnel plus the checkpointed previous tunnel.
func dnsRecordTargets(tunnel *v1alpha1.CloudflareTunnel, currentTunnelID string) []string {
	targets := make([]string, 0, 2)
	if currentTunnelID != "" {
		targets = append(targets, tunnelCNAMETarget(currentTunnelID))
	}
	if tunnel.Status.TunnelID != "" && tunnel.Status.TunnelID != currentTunnelID {
		targets = append(targets, tunnelCNAMETarget(tunnel.Status.TunnelID))
	}
	return targets
}

// dnsRecordOwnedByGateway judges whether an existing record at a desired
// hostname belongs to this Tunnel. Ownership is asymmetric (D12): reclaiming
// a marker-carrying record is convergence, not a destructive write, so the
// marker alone authorizes the update. A forged marker can only redirect the
// record back at this Tunnel's own target. The marker check still blocks
// foreign records, and a non-CNAME record keeps the existing conflict path.
// Destructive paths (deleteDNSRecordIfOwned) additionally require the record
// content to match a managed tunnel target. The second return value explains
// a denial for the conflict status.
func dnsRecordOwnedByGateway(record RemoteDNSRecord, markers []string) (bool, string) {
	owned := false
	for _, marker := range markers {
		if flarecloudflare.IsOwnedDNSRecordStrict(flarecloudflare.OwnedDNSRecordCheck{
			Record: record, ExpectedComment: marker,
		}) {
			owned = true
			break
		}
	}
	if !owned {
		return false, fmt.Sprintf("missing Flareway ownership marker (comment %q)", record.Comment)
	}
	if !strings.EqualFold(record.Type, "CNAME") {
		return false, fmt.Sprintf("record type %s is not a managed CNAME", record.Type)
	}
	return true, ""
}

func (r *CloudflareTunnelReconciler) clusterID(ctx context.Context) (string, error) {
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: "kube-system"}, &namespace); err != nil {
		return "", fmt.Errorf("read cluster ID from kube-system Namespace UID: %w", err)
	}
	if namespace.UID == "" {
		return "", errors.New("kube-system Namespace has no UID")
	}
	return string(namespace.UID), nil
}

func (r *CloudflareTunnelReconciler) scaleDownRecordedGatewayDataplane(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) (bool, error) {
	if tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" {
		return true, nil
	}
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: "flareway-gw-" + tunnel.Status.GatewayRef.Name}
	var deployment appsv1.Deployment
	if err := r.Get(ctx, key, &deployment); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("get recorded Gateway dataplane Deployment %s: %w", key, err)
		}
	} else if deploymentBelongsToRecordedTunnelOwner(&deployment, tunnel) &&
		(deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0) {
		before := deployment.DeepCopy()
		zero := int32(0)
		deployment.Spec.Replicas = &zero
		if err := r.Patch(ctx, &deployment, client.MergeFrom(before)); err != nil {
			return false, fmt.Errorf("scale recorded Gateway dataplane Deployment %s to zero: %w", key, err)
		}
	}
	return tunnelGatewayDataplaneDrained(ctx, r.Client, tunnel)
}

func tunnelGatewayDataplaneDrained(ctx context.Context, reader client.Reader, tunnel *v1alpha1.CloudflareTunnel) (bool, error) {
	if tunnel == nil || tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" {
		return true, nil
	}
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: "flareway-gw-" + tunnel.Status.GatewayRef.Name}
	var deployment appsv1.Deployment
	deploymentRelevant := false
	if err := reader.Get(ctx, key, &deployment); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("get dataplane Deployment %s: %w", key, err)
		}
	} else {
		deploymentRelevant = deploymentBelongsToRecordedTunnelOwner(&deployment, tunnel)
		if deploymentRelevant && (deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0) {
			return false, nil
		}
	}

	var pods corev1.PodList
	label := tunnel.Namespace + "--" + tunnel.Status.GatewayRef.Name
	if err := reader.List(ctx, &pods, client.InNamespace(tunnel.Namespace), client.MatchingLabels{dataplaneGatewayLabel: label}); err != nil {
		return false, fmt.Errorf("list dataplane Pods: %w", err)
	}
	tokenSecretName := ""
	if tunnel.Status.ConnectorTokenSecretRef != nil {
		tokenSecretName = tunnel.Status.ConnectorTokenSecretRef.Name
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if tokenSecretName != "" && podUsesTunnelTokenSecret(pod, tokenSecretName) ||
			tokenSecretName == "" && deploymentRelevant {
			return false, nil
		}
	}
	return true, nil
}

func deploymentBelongsToRecordedTunnelOwner(deployment *appsv1.Deployment, tunnel *v1alpha1.CloudflareTunnel) bool {
	if deployment == nil || tunnel == nil {
		return false
	}
	owner := metav1.GetControllerOf(deployment)
	if tunnel.Status.GatewayUID != "" && owner != nil &&
		owner.APIVersion == gatewayv1.GroupVersion.String() &&
		owner.Kind == "Gateway" &&
		owner.UID == tunnel.Status.GatewayUID {
		return true
	}
	if tunnel.Status.ConnectorTokenSecretRef == nil || tunnel.Status.ConnectorTokenSecretRef.Name == "" {
		return false
	}
	return podSpecUsesTunnelTokenSecret(&deployment.Spec.Template.Spec, tunnel.Status.ConnectorTokenSecretRef.Name)
}

func podUsesTunnelTokenSecret(pod *corev1.Pod, secretName string) bool {
	return pod != nil && podSpecUsesTunnelTokenSecret(&pod.Spec, secretName)
}

func podSpecUsesTunnelTokenSecret(spec *corev1.PodSpec, secretName string) bool {
	if spec == nil {
		return false
	}
	for i := range spec.Containers {
		if spec.Containers[i].Name != "cloudflared" {
			continue
		}
		if secretName == "" {
			return true
		}
		for j := range spec.Containers[i].Env {
			ref := spec.Containers[i].Env[j].ValueFrom
			if spec.Containers[i].Env[j].Name == "TUNNEL_TOKEN" && ref != nil && ref.SecretKeyRef != nil && ref.SecretKeyRef.Name == secretName {
				return true
			}
		}
	}
	return false
}

func (r *CloudflareTunnelReconciler) pendingAccessApplications(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) ([]string, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: v1alpha1.Group, Version: v1alpha1.GroupVersion.Version, Kind: "AccessApplicationList"})
	if err := reader.List(ctx, list); err != nil {
		if optionalResourceUnavailable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list AccessApplication dependencies: %w", err)
	}

	gatewayName := ""
	if tunnel.Status.GatewayRef != nil {
		gatewayName = tunnel.Status.GatewayRef.Name
	}
	routeTargets := map[string]bool{}
	var routes gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routes, client.InNamespace(tunnel.Namespace)); err != nil {
		return nil, fmt.Errorf("list HTTPRoutes for AccessApplication cleanup: %w", err)
	}
	if gatewayName != "" {
		for i := range routes.Items {
			for _, parent := range routes.Items[i].Spec.ParentRefs {
				namespace := tunnel.Namespace
				if parent.Namespace != nil {
					namespace = string(*parent.Namespace)
				}
				if namespace == tunnel.Namespace && string(parent.Name) == gatewayName {
					routeTargets[routes.Items[i].Name] = true
				}
			}
		}
	}
	networkRouteTargets := map[string]bool{}
	var networkRoutes v1alpha1.NetworkRouteList
	if err := reader.List(ctx, &networkRoutes); err != nil {
		if !optionalResourceUnavailable(err) {
			return nil, fmt.Errorf("list NetworkRoutes for AccessApplication cleanup: %w", err)
		}
	} else {
		for i := range networkRoutes.Items {
			route := &networkRoutes.Items[i]
			if namespacedReferenceMatches(route.Namespace, route.Spec.TunnelRef, tunnel.Namespace, tunnel.Name) {
				networkRouteTargets[route.Namespace+"/"+route.Name] = true
			}
		}
	}
	hostnameRouteTargets := map[string]bool{}
	var hostnameRoutes v1alpha1.HostnameRouteList
	if err := reader.List(ctx, &hostnameRoutes); err != nil {
		if !optionalResourceUnavailable(err) {
			return nil, fmt.Errorf("list HostnameRoutes for AccessApplication cleanup: %w", err)
		}
	} else {
		for i := range hostnameRoutes.Items {
			route := &hostnameRoutes.Items[i]
			if namespacedReferenceMatches(route.Namespace, route.Spec.TunnelRef, tunnel.Namespace, tunnel.Name) {
				hostnameRouteTargets[route.Namespace+"/"+route.Name] = true
			}
		}
	}

	var pending []string
	for i := range list.Items {
		application := &list.Items[i]
		privateTunnelKeys, err := r.privateTunnelLedgerForApplication(ctx, application)
		if err != nil {
			return nil, fmt.Errorf("read AccessApplication %s private tunnel ledger: %w", application.GetName(), err)
		}
		targetsGateway, err := accessApplicationTargets(application, privateTunnelKeys, tunnel.Namespace+"/"+tunnel.Name, tunnel.Namespace, gatewayName, routeTargets, networkRouteTargets, hostnameRouteTargets)
		if err != nil {
			return nil, fmt.Errorf("read AccessApplication %s targets: %w", application.GetName(), err)
		}
		if !targetsGateway {
			continue
		}
		if !application.GetDeletionTimestamp().IsZero() ||
			!hasTargetNotFoundProgrammedCondition(application.Object) ||
			!accessApplicationCleanupComplete(application.Object) {
			pending = append(pending, application.GetNamespace()+"/"+application.GetName())
		}
	}
	slices.Sort(pending)
	return pending, nil
}

func (r *CloudflareTunnelReconciler) privateTunnelLedgerForApplication(ctx context.Context, application *unstructured.Unstructured) ([]string, error) {
	if application.GetUID() == "" {
		return nil, nil
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{
		Namespace: accessApplicationAUDNamespace,
		Name:      privateTunnelLedgerSecretName(application.GetUID()),
	}, &secret)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if secret.Labels[accessApplicationPrivateTunnelsLabel] != application.GetNamespace()+"--"+application.GetName() {
		return nil, errors.New("private tunnel ledger Secret has an invalid application label")
	}
	return parsePrivateTunnelKeys(secret.Data[accessApplicationPrivateTunnelsKey])
}

func accessApplicationTargets(
	application *unstructured.Unstructured,
	privateTunnelKeys []string,
	tunnelKey, gatewayNamespace, gatewayName string,
	routeTargets, networkRouteTargets, hostnameRouteTargets map[string]bool,
) (bool, error) {
	for _, key := range privateTunnelKeys {
		if key == tunnelKey {
			return true, nil
		}
	}
	targets, found, err := unstructured.NestedSlice(application.Object, "spec", "targetRefs")
	if err != nil {
		return false, err
	}
	if found && application.GetNamespace() == gatewayNamespace {
		for _, target := range targets {
			ref, ok := target.(map[string]any)
			if !ok {
				continue
			}
			kind, _, _ := unstructured.NestedString(ref, "kind")
			name, _, _ := unstructured.NestedString(ref, "name")
			if (kind == "Gateway" && name == gatewayName) || (kind == "HTTPRoute" && routeTargets[name]) {
				return true, nil
			}
		}
	}
	destinations, found, err := unstructured.NestedSlice(application.Object, "spec", "privateDestinations")
	if err != nil || !found {
		return false, err
	}
	for _, destination := range destinations {
		value, ok := destination.(map[string]any)
		if !ok {
			continue
		}
		if ref, found, _ := unstructured.NestedMap(value, "networkRouteRef"); found {
			name, _, _ := unstructured.NestedString(ref, "name")
			if networkRouteTargets[application.GetNamespace()+"/"+name] {
				return true, nil
			}
		}
		if ref, found, _ := unstructured.NestedMap(value, "hostnameRouteRef"); found {
			name, _, _ := unstructured.NestedString(ref, "name")
			if hostnameRouteTargets[application.GetNamespace()+"/"+name] {
				return true, nil
			}
		}
	}
	return false, nil
}

func accessApplicationCleanupComplete(object map[string]any) bool {
	management, _, _ := unstructured.NestedString(object, "spec", "managementPolicy")
	if management == "" {
		management = string(v1alpha1.ManagementPolicyManaged)
	}
	deletion, _, _ := unstructured.NestedString(object, "spec", "deletionPolicy")
	if deletion == "" {
		deletion = string(v1alpha1.DeletionPolicyDelete)
	}
	if management != string(v1alpha1.ManagementPolicyManaged) || deletion != string(v1alpha1.DeletionPolicyDelete) {
		return true
	}
	applicationID, _, _ := unstructured.NestedString(object, "status", "applicationId")
	if applicationID != "" {
		return false
	}
	children, found, _ := unstructured.NestedSlice(object, "status", "bypassApplications")
	return !found || len(children) == 0
}

func hasTargetNotFoundProgrammedCondition(object map[string]any) bool {
	if conditions, found, _ := unstructured.NestedSlice(object, "status", "conditions"); found && conditionSliceHasTargetNotFound(conditions) {
		return true
	}
	ancestors, found, _ := unstructured.NestedSlice(object, "status", "ancestors")
	if !found {
		return false
	}
	for _, ancestor := range ancestors {
		value, ok := ancestor.(map[string]any)
		if !ok {
			continue
		}
		if conditions, found, _ := unstructured.NestedSlice(value, "conditions"); found && conditionSliceHasTargetNotFound(conditions) {
			return true
		}
	}
	return false
}

func conditionSliceHasTargetNotFound(conditions []any) bool {
	for _, condition := range conditions {
		value, ok := condition.(map[string]any)
		if !ok {
			continue
		}
		if value["type"] == "Programmed" && value["status"] == "False" && value["reason"] == "TargetNotFound" {
			return true
		}
	}
	return false
}

func (r *CloudflareTunnelReconciler) tunnelDependencies(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) ([]string, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	dependencies := make([]string, 0)

	var hostnameRoutes v1alpha1.HostnameRouteList
	if err := reader.List(ctx, &hostnameRoutes); err != nil {
		if !optionalResourceUnavailable(err) {
			return nil, fmt.Errorf("list HostnameRoute dependencies: %w", err)
		}
	} else {
		for i := range hostnameRoutes.Items {
			route := &hostnameRoutes.Items[i]
			if namespacedReferenceMatches(route.Namespace, route.Spec.TunnelRef, tunnel.Namespace, tunnel.Name) {
				dependencies = append(dependencies, "HostnameRoute/"+route.Namespace+"/"+route.Name)
			}
		}
	}

	var networkRoutes v1alpha1.NetworkRouteList
	if err := reader.List(ctx, &networkRoutes); err != nil {
		if !optionalResourceUnavailable(err) {
			return nil, fmt.Errorf("list NetworkRoute dependencies: %w", err)
		}
	} else {
		for i := range networkRoutes.Items {
			route := &networkRoutes.Items[i]
			if namespacedReferenceMatches(route.Namespace, route.Spec.TunnelRef, tunnel.Namespace, tunnel.Name) {
				dependencies = append(dependencies, "NetworkRoute/"+route.Namespace+"/"+route.Name)
			}
		}
	}

	slices.Sort(dependencies)
	return dependencies, nil
}

func namespacedReferenceMatches(
	objectNamespace string,
	ref v1alpha1.TunnelReference,
	targetNamespace, targetName string,
) bool {
	kind := ref.Kind
	if kind == "" {
		kind = v1alpha1.TunnelReferenceKindCloudflareTunnel
	}
	if kind != v1alpha1.TunnelReferenceKindCloudflareTunnel {
		return false
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = objectNamespace
	}
	return namespace == targetNamespace && ref.Name == targetName
}
func optionalResourceUnavailable(err error) bool {
	return runtime.IsNotRegisteredError(err) ||
		strings.Contains(err.Error(), "no matches for kind") ||
		strings.Contains(err.Error(), "could not find the requested resource")
}

func allHostnamesBlocked(hostnames []v1alpha1.CloudflareTunnelHostnameStatus) bool {
	for _, hostname := range hostnames {
		if hostname.Guard != v1alpha1.HostnameGuardBlocked {
			return false
		}
	}
	return true
}

func tunnelOwnedStatus(tunnel *v1alpha1.CloudflareTunnel, gatewayRef *corev1.LocalObjectReference, gatewayUID types.UID, conditions []metav1.Condition) v1alpha1.CloudflareTunnelStatus {
	return v1alpha1.CloudflareTunnelStatus{
		TunnelID: tunnel.Status.TunnelID, AccountID: tunnel.Status.AccountID, Name: tunnel.Status.Name,
		TunnelType: tunnel.Status.TunnelType, ConfigSource: tunnel.Status.ConfigSource,
		ConnectorState: tunnel.Status.ConnectorState, CreatedAt: tunnel.Status.CreatedAt,
		DeletedAt: tunnel.Status.DeletedAt, ConnectionsActiveAt: tunnel.Status.ConnectionsActiveAt,
		ConnectionsInactiveAt: tunnel.Status.ConnectionsInactiveAt,
		OrphanedTunnelID:      tunnel.Status.OrphanedTunnelID,
		OwnershipVerified:     tunnel.Status.OwnershipVerified, ObservedGeneration: tunnel.Status.ObservedGeneration,
		ConnectorTokenSecretRef:  tunnel.Status.ConnectorTokenSecretRef,
		ManagementTokenSecretRef: tunnel.Status.ManagementTokenSecretRef,
		Clients:                  append([]v1alpha1.CloudflareTunnelClientStatus(nil), tunnel.Status.Clients...),
		Addresses:                append([]gatewayv1.GatewayStatusAddress(nil), tunnel.Status.Addresses...),
		DNSRecords:               append([]v1alpha1.CloudflareTunnelDNSRecordStatus(nil), tunnel.Status.DNSRecords...),
		GatewayRef:               gatewayRef, GatewayUID: gatewayUID,
		ConfigVersion: tunnel.Status.ConfigVersion, Conditions: conditions,
	}
}

func tunnelOwnedConditions(tunnel *v1alpha1.CloudflareTunnel) []metav1.Condition {
	owned := map[string]bool{
		v1alpha1.CloudflareTunnelConditionAccepted:       true,
		v1alpha1.CloudflareTunnelConditionTunnelReady:    true,
		v1alpha1.CloudflareTunnelConditionDNSReady:       true,
		v1alpha1.CloudflareTunnelConditionReady:          true,
		v1alpha1.CloudflareTunnelConditionCleanupBlocked: true,
		v1alpha1.CloudflareTunnelConditionConflict:       true,
	}
	if tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		owned[v1alpha1.CloudflareTunnelConditionConfigApplied] = true
	}
	result := make([]metav1.Condition, 0, len(owned))
	for _, condition := range tunnel.Status.Conditions {
		if owned[condition.Type] {
			result = append(result, condition)
		}
	}
	return result
}

func tunnelCondition(conditionType string, status metav1.ConditionStatus, reason, message string, generation int64, now metav1.Time) metav1.Condition {
	return gatewaystatus.NewCondition(conditionType, status, reason, message, generation, now)
}

func setStatusCondition(status *v1alpha1.CloudflareTunnelStatus, condition metav1.Condition, now metav1.Time) {
	status.Conditions = gatewaystatus.SetCondition(status.Conditions, now, condition)
}

func (r *CloudflareTunnelReconciler) setReady(status *v1alpha1.CloudflareTunnelStatus, gatewayConditions []metav1.Condition, generation int64, now metav1.Time) {
	ready := gatewaystatus.ConditionTrue(status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady) &&
		gatewaystatus.ConditionTrue(gatewayConditions, v1alpha1.CloudflareTunnelConditionConfigApplied) &&
		gatewaystatus.ConditionTrue(status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
	conditionStatus := metav1.ConditionFalse
	reason := "Pending"
	message := "TunnelReady, ConfigApplied, and DNSReady must all be True"
	if ready {
		conditionStatus = metav1.ConditionTrue
		reason = "Ready"
		message = "Tunnel, data-plane configuration, and DNS are ready"
	}
	setStatusCondition(status, tunnelCondition(v1alpha1.CloudflareTunnelConditionReady, conditionStatus, reason, message, generation, now), now)
}

func (r *CloudflareTunnelReconciler) setReadyForMode(status *v1alpha1.CloudflareTunnelStatus, tunnel *v1alpha1.CloudflareTunnel, mode v1alpha1.CloudflareTunnelConfigurationMode, now metav1.Time) {
	configurationConditions := tunnel.Status.Conditions
	if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		setStatusCondition(status, tunnelCondition(
			v1alpha1.CloudflareTunnelConditionReady,
			metav1.ConditionFalse,
			"ObserveOnly",
			"ObserveOnly reports remote state but does not authorize a managed connector dataplane",
			tunnel.Generation,
			now,
		), now)
		return
	}
	if mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		configurationConditions = status.Conditions
	}
	r.setReady(status, configurationConditions, tunnel.Generation, now)
}

func (r *CloudflareTunnelReconciler) activeFailure(
	ctx context.Context,
	tunnel *v1alpha1.CloudflareTunnel,
	gatewayRef *corev1.LocalObjectReference,
	gatewayUID types.UID,
	conditions []metav1.Condition,
	reason string,
	err error,
) (ctrl.Result, error) {
	now := r.now()
	status := tunnelOwnedStatus(tunnel, gatewayRef, gatewayUID, conditions)
	setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, reason, err.Error(), tunnel.Generation, now), now)
	r.setReadyForMode(&status, tunnel, tunnelConfigurationMode(tunnel), now)
	// Direct mode never has a valid Gateway binding; Gateway mode keeps the
	// selected owner identity authoritative.
	clearIntent := tunnelStatusClear{GatewayBinding: tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeDirect}
	if patchErr := r.patchOwnedStatus(ctx, tunnel, status, clearIntent); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func remoteProjectionEqual(current, projected v1alpha1.CloudflareTunnelStatus) bool {
	return current.TunnelID == projected.TunnelID &&
		current.AccountID == projected.AccountID &&
		current.Name == projected.Name &&
		current.TunnelType == projected.TunnelType &&
		current.ConfigSource == projected.ConfigSource &&
		current.ConnectorState == projected.ConnectorState &&
		timeStatusEqual(current.CreatedAt, projected.CreatedAt) &&
		timeStatusEqual(current.DeletedAt, projected.DeletedAt) &&
		timeStatusEqual(current.ConnectionsActiveAt, projected.ConnectionsActiveAt) &&
		timeStatusEqual(current.ConnectionsInactiveAt, projected.ConnectionsInactiveAt) &&
		current.OwnershipVerified == projected.OwnershipVerified &&
		current.ObservedGeneration == projected.ObservedGeneration
}

func timeStatusEqual(left, right *metav1.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(right)
}

func mergeTunnelOwnedStatus(current, owned v1alpha1.CloudflareTunnelStatus) v1alpha1.CloudflareTunnelStatus {
	owned.ConfigVersion = current.ConfigVersion
	owned.Hostnames = current.Hostnames
	owned.Listeners = current.Listeners
	owned.Conditions = gatewaystatus.MergeConditions(current.Conditions, metav1.Now(), owned.Conditions...)
	return owned
}

// tunnelStatusClear declares which protected tunnel-owned status fields an
// apply is allowed to empty. Server-side apply deletes any field the
// flareway-tunnel manager owns when the apply document omits it, so a status
// built from a stale cached object would silently erase live remote identity,
// credential references, and observed collections. Callers must set the
// matching flag only on the explicit revocation paths: ObserveOnly transition
// and drained ownership conflict may clear credential refs and ownership, and
// ObserveOnly DNS withdrawal may clear DNS records. Fresh remote observations
// (clients, addresses, dnsRecords) are authoritative lists, not clears.
type tunnelStatusClear struct {
	// Credentials allows connectorTokenSecretRef and managementTokenSecretRef
	// to be emptied: ObserveOnly transition and drained ownership conflict.
	Credentials bool
	// Ownership allows ownershipVerified to be emptied: ObserveOnly
	// transition and ownership conflict.
	Ownership bool
	// GatewayBinding allows gatewayRef and gatewayUid to be emptied: only
	// when the current reconcile authoritatively computes an unbound Tunnel —
	// Gateway mode with no owning Gateway, and Direct mode where no Gateway
	// binding is valid. Drain, delete, and stale paths must preserve them.
	GatewayBinding bool
	// DeletedAt allows deletedAt to be emptied: only applies carrying a fresh
	// remote projection may rewrite it; a stale apply must never erase a
	// recorded remote deletion because deletedAt gates fail-closed handling
	// in the Gateway dataplane paths.
	DeletedAt bool
	// DNSRecords allows dnsRecords to be emptied: ObserveOnly DNS withdrawal
	// and the authoritative results of ensureDNS/removeDNSRecords.
	DNSRecords bool
	// Clients allows clients to be emptied by a fresh connection listing.
	Clients bool
	// Addresses allows addresses to be emptied by a fresh projection.
	Addresses bool
}

// patchOwnedStatus applies the tunnel-owned status under the flareway-tunnel
// field manager. Because SSA deletes owned fields omitted from the document,
// an apply built from a stale cached object must not empty protected fields
// that exist live unless the caller declared clear intent. When the document
// would empty a protected field without intent, the live object is read once
// through APIReader and the live values are restored into the document. The
// live read only happens on a potential regression — a converged apply that
// carries its protected fields never reads — so the steady-state loop does
// not pay a quorum read. The controller is the sole writer of these fields
// and runs with MaxConcurrentReconciles=1, so the read-to-apply window cannot
// observe a newer tunnel write; only an external actor could interpose, which
// is the bounded TOCTOU tradeoff accepted here.
func (r *CloudflareTunnelReconciler) patchOwnedStatus(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, status v1alpha1.CloudflareTunnelStatus, clearIntent tunnelStatusClear) error {
	statusMap, err := tunnelOwnedStatusMap(tunnel, status)
	if err != nil {
		return err
	}
	if err := r.preserveTunnelStatusFields(ctx, tunnel, statusMap, clearIntent); err != nil {
		return err
	}
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "CloudflareTunnel",
		"metadata": map[string]any{
			"name": tunnel.Name, "namespace": tunnel.Namespace,
		},
		"status": statusMap,
	}}
	if err := r.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(tunnelFieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply tunnel-owned status for %s/%s: %w", tunnel.Namespace, tunnel.Name, err)
	}
	return nil
}

// tunnelOwnedStatusMap converts the tunnel-owned status into the apply
// document: gateway-owned fields are dropped, and in Gateway mode the
// configVersion object is omitted entirely because GatewayReconciler owns it.
func tunnelOwnedStatusMap(tunnel *v1alpha1.CloudflareTunnel, status v1alpha1.CloudflareTunnelStatus) (map[string]any, error) {
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	if err != nil {
		return nil, fmt.Errorf("convert CloudflareTunnel status: %w", err)
	}
	delete(statusMap, "hostnames")
	delete(statusMap, "listeners")
	if tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		delete(statusMap, "configVersion")
	}
	// Empty owned lists are explicit so teardown can signal DNS completion.
	// Optional scalars remain omitted when empty; applying JSON null to their
	// non-nullable CRD schema would reject the complete status patch.
	statusMap["addresses"] = sliceOrEmpty(statusMap["addresses"])
	statusMap["dnsRecords"] = sliceOrEmpty(statusMap["dnsRecords"])
	statusMap["clients"] = sliceOrEmpty(statusMap["clients"])
	return statusMap, nil
}

// preserveTunnelStatusFields restores protected fields into the outgoing apply
// document from the live object when the document would empty them without
// declared clear intent. It performs at most one APIReader read, and only when
// some protected field is absent or empty in the document while it could exist
// live. Fields that can never exist live for this spec (managementTokenSecretRef
// without spec.managementToken, orphanedTunnelId outside deletion) are skipped
// so legitimately absent fields do not force a read. The observational
// connectionsActiveAt and connectionsInactiveAt are deliberately unprotected:
// they are legitimately empty on live tunnels and are authoritatively
// rewritten by each fresh remote projection.
func (r *CloudflareTunnelReconciler) preserveTunnelStatusFields(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, statusMap map[string]any, clearIntent tunnelStatusClear) error {
	protected := []string{
		"tunnelId", "accountId", "name", "tunnelType", "configSource",
		"connectorState", "createdAt", "observedGeneration",
	}
	if !clearIntent.Credentials {
		protected = append(protected, "connectorTokenSecretRef")
		if tunnel.Spec.ManagementToken != nil {
			protected = append(protected, "managementTokenSecretRef")
		}
	}
	if !tunnel.DeletionTimestamp.IsZero() {
		protected = append(protected, "orphanedTunnelId")
	}
	if !clearIntent.Ownership {
		protected = append(protected, "ownershipVerified")
	}
	if !clearIntent.DeletedAt {
		protected = append(protected, "deletedAt")
	}
	if !clearIntent.GatewayBinding {
		protected = append(protected, "gatewayRef", "gatewayUid")
	}
	if !clearIntent.DNSRecords {
		protected = append(protected, "dnsRecords")
	}
	if !clearIntent.Clients {
		protected = append(protected, "clients")
	}
	if !clearIntent.Addresses {
		protected = append(protected, "addresses")
	}
	// ownershipVerified=false and deletedAt=nil are the legitimate state of a
	// tunnel that was never adopted; only treat them as possible regressions
	// when the cached object shows a prior adoption. A fully stale cache still
	// triggers the read through the absent identity fields above.
	priorAdoption := tunnel.Status.TunnelID != "" || tunnel.Status.ObservedGeneration != 0
	needsLive := false
	for _, field := range protected {
		if (field == "ownershipVerified" || field == "deletedAt") && !priorAdoption {
			continue
		}
		if statusFieldEmpty(statusMap[field]) {
			needsLive = true
			break
		}
	}
	if !needsLive && tunnelConfigVersionRegresses(tunnel, statusMap) {
		needsLive = true
	}
	if !needsLive {
		return nil
	}
	reader := r.APIReader
	if reader == nil {
		return errors.New("CloudflareTunnelReconciler APIReader is required for status preservation")
	}
	var live v1alpha1.CloudflareTunnel
	if err := reader.Get(ctx, client.ObjectKeyFromObject(tunnel), &live); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("read live CloudflareTunnel %s/%s for status preservation: %w", tunnel.Namespace, tunnel.Name, err)
	}
	liveMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&live.Status)
	if err != nil {
		return fmt.Errorf("convert live CloudflareTunnel status: %w", err)
	}
	for _, field := range protected {
		if statusFieldEmpty(statusMap[field]) && !statusFieldEmpty(liveMap[field]) {
			statusMap[field] = liveMap[field]
		}
	}
	restoreTunnelConfigVersion(tunnel, statusMap, liveMap)
	return nil
}

// statusFieldEmpty reports whether an unstructured status field is absent or
// holds an empty value; an empty applied value deletes the live field under SSA.
func statusFieldEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	case int64:
		return typed == 0
	case bool:
		return !typed
	}
	return false
}

// tunnelConfigVersionKeys lists the configVersion subfields owned by this
// manager. In Gateway mode the GatewayReconciler owns the whole object, so the
// tunnel owns none; in Direct mode the tunnel owns the whole object.
func tunnelConfigVersionKeys(tunnel *v1alpha1.CloudflareTunnel) []string {
	if tunnelConfigurationMode(tunnel) == v1alpha1.CloudflareTunnelConfigurationModeGateway {
		return nil
	}
	return []string{"desired", "desiredHash", "applied", "remote", "createdAt", "appliedAt"}
}

// tunnelConfigVersionRegresses reports whether the outgoing document drops
// tunnel-owned configVersion subfields while evidence shows a version was
// previously published: either the document carries a partial configVersion,
// or the cached status still records one. A tunnel that never published a
// configuration has no evidence and must not force a live read.
func tunnelConfigVersionRegresses(tunnel *v1alpha1.CloudflareTunnel, statusMap map[string]any) bool {
	applied, _ := statusMap["configVersion"].(map[string]any)
	if len(applied) == 0 && tunnel.Status.ConfigVersion == (v1alpha1.CloudflareTunnelConfigVersion{}) {
		return false
	}
	for _, key := range tunnelConfigVersionKeys(tunnel) {
		if statusFieldEmpty(applied[key]) {
			return true
		}
	}
	return false
}

func restoreTunnelConfigVersion(tunnel *v1alpha1.CloudflareTunnel, statusMap, liveMap map[string]any) {
	liveVersion, _ := liveMap["configVersion"].(map[string]any)
	if len(liveVersion) == 0 {
		return
	}
	applied, _ := statusMap["configVersion"].(map[string]any)
	restored := false
	for _, key := range tunnelConfigVersionKeys(tunnel) {
		if statusFieldEmpty(applied[key]) && !statusFieldEmpty(liveVersion[key]) {
			if applied == nil {
				applied = map[string]any{}
			}
			applied[key] = liveVersion[key]
			restored = true
		}
	}
	if restored {
		statusMap["configVersion"] = applied
	}
}

func sliceOrEmpty(value any) any {
	if value == nil {
		return []any{}
	}
	return value
}

func (r *CloudflareTunnelReconciler) now() metav1.Time {
	if r.Now != nil {
		return metav1.NewTime(r.Now())
	}
	return metav1.Now()
}

// SetupWithManager registers relation indexes and all Kubernetes dependencies
// that can change Tunnel ownership, authorization, credentials, DNS inputs, or drain state.
func (r *CloudflareTunnelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	indexer := mgr.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &gatewayv1.Gateway{}, gatewayTunnelIndex, func(object client.Object) []string {
		gateway := object.(*gatewayv1.Gateway)
		if gateway.Spec.Infrastructure == nil || gateway.Spec.Infrastructure.ParametersRef == nil {
			return nil
		}
		ref := gateway.Spec.Infrastructure.ParametersRef
		if string(ref.Group) != v1alpha1.Group || string(ref.Kind) != "CloudflareTunnel" {
			return nil
		}
		return []string{gateway.Namespace + "/" + string(ref.Name)}
	}); err != nil {
		return fmt.Errorf("index Gateway CloudflareTunnel reference: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.CloudflareTunnel{}, tunnelAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.CloudflareTunnel).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index CloudflareTunnel accountRef: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.CloudflareAccount{}, accountCredentialIndex, func(object client.Object) []string {
		ref := object.(*v1alpha1.CloudflareAccount).Spec.Credentials.APITokenSecretRef
		return []string{ref.Namespace + "/" + ref.Name}
	}); err != nil {
		return fmt.Errorf("index CloudflareAccount credential Secret: %w", err)
	}

	b := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.CloudflareTunnel{}).
		Owns(&corev1.Secret{}).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToTunnel)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.mapAccountToTunnels)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapSecretToTunnels)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapNamespaceToTunnels)).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestsFromMapFunc(r.mapDataplaneToTunnel)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapDataplaneToTunnel)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapPrivateRouteToTunnel)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapPrivateRouteToTunnel)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1})
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("cloudflare-tunnel", r))
}

func (r *CloudflareTunnelReconciler) mapGatewayToTunnel(ctx context.Context, object client.Object) []reconcile.Request {
	gateway, ok := object.(*gatewayv1.Gateway)
	if !ok {
		return nil
	}
	key := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
	if gateway.Spec.Infrastructure != nil && gateway.Spec.Infrastructure.ParametersRef != nil {
		ref := gateway.Spec.Infrastructure.ParametersRef
		if string(ref.Group) == v1alpha1.Group && string(ref.Kind) == "CloudflareTunnel" {
			key.Name = string(ref.Name)
		}
	}
	if r.Client != nil {
		var tunnel v1alpha1.CloudflareTunnel
		if err := r.Get(ctx, key, &tunnel); err == nil &&
			tunnelConfigurationMode(&tunnel) == v1alpha1.CloudflareTunnelConfigurationModeDirect {
			return nil
		}
	}
	return []reconcile.Request{{NamespacedName: key}}
}

func (r *CloudflareTunnelReconciler) mapPrivateRouteToTunnel(_ context.Context, object client.Object) []reconcile.Request {
	var ref v1alpha1.TunnelReference
	switch route := object.(type) {
	case *v1alpha1.HostnameRoute:
		ref = route.Spec.TunnelRef
	case *v1alpha1.NetworkRoute:
		ref = route.Spec.TunnelRef
	default:
		return nil
	}
	kind := ref.Kind
	if kind == "" {
		kind = v1alpha1.TunnelReferenceKindCloudflareTunnel
	}
	if kind != v1alpha1.TunnelReferenceKindCloudflareTunnel {
		return nil
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = object.GetNamespace()
	}
	if namespace == "" || ref.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: namespace, Name: ref.Name}}}
}

func (r *CloudflareTunnelReconciler) mapAccountToTunnels(ctx context.Context, object client.Object) []reconcile.Request {
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels, client.MatchingFields{tunnelAccountIndex: object.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "list CloudflareTunnels for account", "account", object.GetName())
		return nil
	}
	return tunnelRequests(tunnels.Items)
}

func (r *CloudflareTunnelReconciler) mapSecretToTunnels(ctx context.Context, object client.Object) []reconcile.Request {
	key := client.ObjectKeyFromObject(object).String()
	var accounts v1alpha1.CloudflareAccountList
	if err := r.List(ctx, &accounts, client.MatchingFields{accountCredentialIndex: key}); err != nil {
		log.FromContext(ctx).Error(err, "list CloudflareAccounts for credential Secret", "secret", key)
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range accounts.Items {
		requests = append(requests, r.mapAccountToTunnels(ctx, &accounts.Items[i])...)
	}
	return requests
}

func (r *CloudflareTunnelReconciler) mapNamespaceToTunnels(ctx context.Context, object client.Object) []reconcile.Request {
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels, client.InNamespace(object.GetName())); err != nil {
		log.FromContext(ctx).Error(err, "list CloudflareTunnels for Namespace", "namespace", object.GetName())
		return nil
	}
	return tunnelRequests(tunnels.Items)
}

func (r *CloudflareTunnelReconciler) mapDataplaneToTunnel(ctx context.Context, object client.Object) []reconcile.Request {
	label := object.GetLabels()[dataplaneGatewayLabel]
	parts := strings.SplitN(label, "--", 2)
	if len(parts) != 2 {
		return nil
	}
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels, client.InNamespace(parts[0])); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, 1)
	for i := range tunnels.Items {
		if tunnels.Items[i].Status.GatewayRef != nil && tunnels.Items[i].Status.GatewayRef.Name == parts[1] {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&tunnels.Items[i])})
		}
	}
	return requests
}

func tunnelRequests(tunnels []v1alpha1.CloudflareTunnel) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(tunnels))
	for i := range tunnels {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&tunnels[i])})
	}
	return requests
}

var _ reconcile.Reconciler = (*CloudflareTunnelReconciler)(nil)
