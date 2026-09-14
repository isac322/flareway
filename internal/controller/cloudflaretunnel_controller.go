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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	tunnelFieldManager = "flareway-tunnel"
	tunnelRequeue      = 2 * time.Second

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
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch
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
	ownedConditions := tunnelOwnedConditions(tunnel.Status.Conditions)
	set := func(condition metav1.Condition) {
		ownedConditions = gatewaystatus.SetCondition(ownedConditions, now, condition)
	}
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "NotBlocked", "No cleanup is pending", tunnel.Generation, now))
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionFalse, "NoConflict", "No ownership conflict was detected", tunnel.Generation, now))

	gateway, extraOwners, err := r.owningGateway(ctx, tunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if gateway == nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "TargetNotFound", "No Gateway references this CloudflareTunnel", tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", "Waiting for an owning Gateway", tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for an owning Gateway", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, nil, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
	}
	gatewayRef := &corev1.LocalObjectReference{Name: gateway.Name}
	if len(extraOwners) > 0 {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "MultipleGateways", fmt.Sprintf("Gateway %s is the owner; later references from %s are rejected", gateway.Name, strings.Join(extraOwners, ", ")), tunnel.Generation, now))
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
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
	}
	if !gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
		!gatewaystatus.ConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		message := fmt.Sprintf("CloudflareAccount %q is not accepted with valid credentials", account.Name)
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "InvalidAccountRef", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", message, tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{RequeueAfter: tunnelRequeue}, r.patchOwnedStatus(ctx, tunnel, status)
	}

	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Namespace}, namespace); err != nil {
		return ctrl.Result{}, fmt.Errorf("get Tunnel namespace: %w", err)
	}
	publicHosts, allBindings, bindingErr := tunnelGatewayBindings(tunnel, gateway, account.Status.Verified.Zones)
	if bindingErr != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "Invalid", bindingErr.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", bindingErr.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Invalid", bindingErr.Error(), tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
	}
	if decision := authorizeBindings(&account, namespace, allBindings); !decision.Allowed {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, decision.Reason, decision.Message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Pending", decision.Message, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", decision.Message, tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
	}
	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionTrue, "Accepted", fmt.Sprintf("Gateway %s is authorized for CloudflareAccount %s", gateway.Name, account.Name), tunnel.Generation, now))

	cf, err := r.cloudflareClient(ctx, &account)
	if err != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "CredentialsInvalid", err.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for valid Cloudflare credentials", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}

	clusterID, err := r.clusterID(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	remote, conflictReason, err := r.ensureRemoteTunnel(ctx, cf, tunnel, clusterID)
	if err != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "CloudflareError", err.Error(), tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Waiting for the remote Tunnel", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}
	if conflictReason != "" {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionAccepted, metav1.ConditionFalse, "Conflict", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "AdoptionMismatch", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "Conflict", conflictReason, tunnel.Generation, now))
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Pending", "Tunnel adoption did not complete", tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
	}
	connectorState := connectorState(remote.Status)
	checkpointRequired := tunnel.Status.TunnelID == "" &&
		tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	if checkpointRequired {
		checkpoint := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		checkpoint.TunnelID = remote.ID
		checkpoint.ConnectorState = connectorState
		if err := r.patchOwnedStatus(ctx, tunnel, checkpoint); err != nil {
			return ctrl.Result{}, fmt.Errorf("checkpoint remote Tunnel identity: %w", err)
		}
		tunnel.Status.TunnelID = checkpoint.TunnelID
		tunnel.Status.ConnectorState = checkpoint.ConnectorState
	}

	set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionTrue, "Ready", fmt.Sprintf("Cloudflare Tunnel %s exists", remote.ID), tunnel.Generation, now))
	if err := r.ensureTokenSecret(ctx, cf, tunnel, remote.ID); err != nil {
		set(tunnelCondition(v1alpha1.CloudflareTunnelConditionTunnelReady, metav1.ConditionFalse, "TokenUnavailable", err.Error(), tunnel.Generation, now))
		status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
		status.TunnelID = remote.ID
		status.ConnectorState = connectorState
		r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
		if patchErr := r.patchOwnedStatus(ctx, tunnel, status); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}

	if tunnel.Status.ConfigVersion.Applied > 0 && tunnel.Status.ConfigVersion.Desired == tunnel.Status.ConfigVersion.Applied {
		version, versionErr := cf.GetTunnelConfigurationVersion(ctx, remote.ID)
		if versionErr != nil && !isRemoteNotFound(versionErr) {
			return ctrl.Result{}, fmt.Errorf("get Tunnel configuration version: %w", versionErr)
		}
		if versionErr == nil && version != tunnel.Status.ConfigVersion.Applied {
			set(tunnelCondition(v1alpha1.CloudflareTunnelConditionConflict, metav1.ConditionTrue, "ConfigurationChanged", fmt.Sprintf("Cloudflare configuration version is %d, expected applied version %d", version, tunnel.Status.ConfigVersion.Applied), tunnel.Generation, now))
		}
	}

	status := tunnelOwnedStatus(tunnel, gatewayRef, ownedConditions)
	status.TunnelID = remote.ID
	status.ConnectorState = connectorState
	status.Addresses = tunnelAddresses(remote.ID, len(publicHosts) > 0)

	switch {
	case tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly:
		status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "ObserveOnly", "ObserveOnly does not manage DNS records", tunnel.Generation, now), now)
	case tunnel.Spec.DNS.Mode == v1alpha1.DNSModeExternal:
		if err := removeDNSRecords(ctx, cf, tunnel.Status.DNSRecords); err != nil {
			return ctrl.Result{}, err
		}
		status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{}
		reason := "External"
		message := "DNS records are managed externally"
		if len(publicHosts) == 0 {
			reason = "NotApplicable"
			message = "The Tunnel has no public listeners"
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, reason, message, tunnel.Generation, now), now)
	case len(publicHosts) == 0:
		if err := removeDNSRecords(ctx, cf, tunnel.Status.DNSRecords); err != nil {
			return ctrl.Result{}, err
		}
		status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionTrue, "NotApplicable", "The Tunnel has no public listeners", tunnel.Generation, now), now)
	default:
		dnsRecords, dnsConflict, dnsErr := r.ensureDNS(ctx, cf, tunnel, gateway.Name, clusterID, remote.ID, publicHosts)
		if dnsErr != nil {
			setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "CloudflareError", dnsErr.Error(), tunnel.Generation, now), now)
			r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
			if patchErr := r.patchOwnedStatus(ctx, tunnel, status); patchErr != nil {
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

	r.setReady(&status, tunnel.Status.Conditions, tunnel.Generation, now)
	return ctrl.Result{}, r.patchOwnedStatus(ctx, tunnel, status)
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

	owner, _, err := r.owningGateway(ctx, tunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	dependencyTunnel := tunnel.DeepCopy()
	var trustedGatewayRef *corev1.LocalObjectReference
	if owner != nil {
		trustedGatewayRef = &corev1.LocalObjectReference{Name: owner.Name}
	}
	dependencyTunnel.Status.GatewayRef = trustedGatewayRef
	status := tunnelOwnedStatus(tunnel, trustedGatewayRef, tunnelOwnedConditions(tunnel.Status.Conditions))
	if owner != nil && !allHostnamesBlocked(tunnel.Status.Hostnames) {
		message := "Waiting for the Gateway controller to block every hostname"
		if now.Sub(tunnel.DeletionTimestamp.Time) >= 30*time.Second {
			message = "Gateway did not block every hostname within 30s; teardown remains fail-closed"
		}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForBlock", message, tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	needsRemote := tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && tunnel.Spec.DeletionPolicy != v1alpha1.DeletionPolicyOrphan
	manageDNS := tunnel.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
	var cf TunnelCloudflareClient
	if (manageDNS && len(tunnel.Status.DNSRecords) > 0) || needsRemote {
		var account v1alpha1.CloudflareAccount
		if err := r.Get(ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &account); err != nil {
			return r.cleanupFailure(ctx, tunnel, status, "CredentialsUnavailable", fmt.Errorf("get CloudflareAccount for cleanup: %w", err))
		}
		var err error
		cf, err = r.cloudflareClient(ctx, &account)
		if err != nil {
			return r.cleanupFailure(ctx, tunnel, status, "CredentialsUnavailable", err)
		}
	}

	if manageDNS && len(tunnel.Status.DNSRecords) > 0 {
		for _, record := range tunnel.Status.DNSRecords {
			if err := cf.DeleteDNSRecord(ctx, record.ZoneID, record.RecordID); err != nil && !isRemoteNotFound(err) {
				return r.cleanupFailure(ctx, tunnel, status, "DNSDeleteFailed", fmt.Errorf("delete DNS record %s: %w", record.Hostname, err))
			}
		}
		status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{}
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionDNSReady, metav1.ConditionFalse, "Deleted", "Managed DNS records were removed", tunnel.Generation, now), now)
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "Draining", "DNS is removed; waiting for connector drain", tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	drained, err := r.dataplaneDrained(ctx, dependencyTunnel)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !drained {
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, "WaitingForDrain", "Waiting for the Gateway controller to scale the dataplane to zero and terminate its Pods", tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
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
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
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
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: tunnelRequeue}, nil
	}

	if !needsRemote {
		status.OrphanedTunnelID = tunnel.Status.TunnelID
		setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionFalse, "Orphaned", "Remote Tunnel is intentionally retained", tunnel.Generation, now), now)
		if err := r.patchOwnedStatus(ctx, tunnel, status); err != nil {
			return ctrl.Result{}, err
		}
	} else if tunnel.Status.TunnelID != "" {
		if err := cf.DeleteTunnel(ctx, tunnel.Status.TunnelID, true); err != nil && !isRemoteNotFound(err) {
			return r.cleanupFailure(ctx, tunnel, status, "TunnelDeleteFailed", fmt.Errorf("delete Cloudflare Tunnel: %w", err))
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

func (r *CloudflareTunnelReconciler) cleanupFailure(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, status v1alpha1.CloudflareTunnelStatus, reason string, err error) (ctrl.Result, error) {
	now := r.now()
	setStatusCondition(&status, tunnelCondition(v1alpha1.CloudflareTunnelConditionCleanupBlocked, metav1.ConditionTrue, reason, err.Error(), tunnel.Generation, now), now)
	if patchErr := r.patchOwnedStatus(ctx, tunnel, status); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func isRemoteNotFound(err error) bool {
	return flarecloudflare.IsNotFound(err)
}

func (r *CloudflareTunnelReconciler) ensureRemoteTunnel(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, clusterID string) (RemoteTunnel, string, error) {
	policy := tunnel.Spec.ManagementPolicy
	if policy == "" {
		policy = v1alpha1.ManagementPolicyManaged
	}
	if policy == v1alpha1.ManagementPolicyObserveOnly {
		if tunnel.Spec.Tunnel.ExternalRef == nil || tunnel.Spec.Tunnel.ExternalRef.TunnelID == "" {
			return RemoteTunnel{}, "", errors.New("ObserveOnly requires tunnel.externalRef.tunnelId")
		}
		remote, err := cf.GetTunnel(ctx, tunnel.Spec.Tunnel.ExternalRef.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("observe Cloudflare Tunnel: %w", err)
		}
		if remote.Deleted() {
			return RemoteTunnel{}, fmt.Sprintf("remote Tunnel %s is deleted", remote.ID), nil
		}
		if expected := tunnel.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
			return RemoteTunnel{}, fmt.Sprintf("remote Tunnel name %q does not match expected name %q", remote.Name, expected), nil
		}
		return remote, "", nil
	}

	if tunnel.Status.TunnelID != "" {
		remote, err := cf.GetTunnel(ctx, tunnel.Status.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("get managed Cloudflare Tunnel: %w", err)
		}
		if remote.Deleted() {
			return RemoteTunnel{}, "", fmt.Errorf("managed Cloudflare Tunnel %s is deleted", remote.ID)
		}
		return remote, "", nil
	}
	if tunnel.Spec.Tunnel.ExternalRef != nil {
		if tunnel.Spec.Adoption.Mode != v1alpha1.AdoptionModeAdoptByID {
			return RemoteTunnel{}, "a Managed externalRef requires adoption.mode AdoptById", nil
		}
		remote, err := cf.GetTunnel(ctx, tunnel.Spec.Tunnel.ExternalRef.TunnelID)
		if err != nil {
			return RemoteTunnel{}, "", fmt.Errorf("get Tunnel for adoption: %w", err)
		}
		if remote.Deleted() {
			return RemoteTunnel{}, fmt.Sprintf("remote Tunnel %s selected for adoption is deleted", remote.ID), nil
		}
		if expected := tunnel.Spec.Adoption.Expect.Name; expected != "" && remote.Name != expected {
			return RemoteTunnel{}, fmt.Sprintf("remote Tunnel name %q does not match expected name %q", remote.Name, expected), nil
		}
		return remote, "", nil
	}
	name := tunnel.Spec.Tunnel.Name
	if name == "" {
		name = strings.Join([]string{clusterID, tunnel.Namespace, tunnel.Name}, "-")
	}
	remote, err := cf.CreateTunnel(ctx, name)
	if err != nil {
		return RemoteTunnel{}, "", fmt.Errorf("create Cloudflare Tunnel: %w", err)
	}
	return remote, "", nil
}

func (r *CloudflareTunnelReconciler) ensureTokenSecret(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, tunnelID string) error {
	token, err := cf.GetTunnelToken(ctx, tunnelID)
	if err != nil {
		return fmt.Errorf("get Tunnel token: %w", err)
	}
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: "flareway-tunnel-" + tunnel.Name}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(tunnel, secret, r.Scheme); err != nil {
			return err
		}
		secret.Type = corev1.SecretTypeOpaque
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data["token"] = []byte(token)
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile Tunnel token Secret %s: %w", key, err)
	}
	return nil
}

func (r *CloudflareTunnelReconciler) ensureDNS(ctx context.Context, cf TunnelCloudflareClient, tunnel *v1alpha1.CloudflareTunnel, gatewayName, clusterID, tunnelID string, hosts []publicHostname) ([]v1alpha1.CloudflareTunnelDNSRecordStatus, string, error) {
	result := make([]v1alpha1.CloudflareTunnelDNSRecordStatus, 0, len(hosts))
	previousByHostname := make(map[string]v1alpha1.CloudflareTunnelDNSRecordStatus, len(tunnel.Status.DNSRecords))
	desiredHostnames := make(map[string]bool, len(hosts))
	for _, previous := range tunnel.Status.DNSRecords {
		previousByHostname[previous.Hostname] = previous
	}
	for _, host := range hosts {
		desiredHostnames[host.Hostname] = true
	}
	for _, previous := range tunnel.Status.DNSRecords {
		if desiredHostnames[previous.Hostname] {
			continue
		}
		if err := cf.DeleteDNSRecord(ctx, previous.ZoneID, previous.RecordID); err != nil && !isRemoteNotFound(err) {
			return nil, "", fmt.Errorf("delete stale DNS record %s: %w", previous.Hostname, err)
		}
	}

	conflicts := make([]string, 0)
	for _, host := range hosts {
		comment := dnsOwnershipComment(tunnel, clusterID, gatewayName)
		desired := RemoteDNSRecordInput{
			Name: host.Hostname, Content: tunnelID + ".cfargotunnel.com", Comment: comment,
			Proxied: true,
		}
		records, err := cf.ListDNSRecords(ctx, host.ZoneID, host.Hostname)
		if err != nil {
			return nil, "", fmt.Errorf("list DNS record %s: %w", host.Hostname, err)
		}
		if len(records) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("multiple DNS records already exist for %s", host.Hostname))
			if previous, ok := previousByHostname[host.Hostname]; ok {
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
			if !dnsRecordOwnedByGateway(record.Comment, tunnel, clusterID, gatewayName) {
				conflicts = append(conflicts, fmt.Sprintf("DNS record %s is not owned by this Gateway (comment %q)", host.Hostname, record.Comment))
				if previous, ok := previousByHostname[host.Hostname]; ok {
					result = append(result, previous)
				}
				continue
			}
			if record.Comment != desired.Comment || !strings.EqualFold(record.Type, "CNAME") || record.Content != desired.Content || !record.Proxied {
				record, err = cf.UpdateCNAME(ctx, host.ZoneID, record.ID, desired)
				if err != nil {
					return nil, "", fmt.Errorf("update DNS record %s: %w", host.Hostname, err)
				}
			}
		}
		result = append(result, v1alpha1.CloudflareTunnelDNSRecordStatus{Hostname: host.Hostname, RecordID: record.ID, ZoneID: host.ZoneID, State: "Ready"})
	}
	slices.SortFunc(result, func(a, b v1alpha1.CloudflareTunnelDNSRecordStatus) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return result, strings.Join(conflicts, "; "), nil
}

func removeDNSRecords(ctx context.Context, cf TunnelCloudflareClient, records []v1alpha1.CloudflareTunnelDNSRecordStatus) error {
	for _, record := range records {
		if err := cf.DeleteDNSRecord(ctx, record.ZoneID, record.RecordID); err != nil && !isRemoteNotFound(err) {
			return fmt.Errorf("delete managed DNS record %s: %w", record.Hostname, err)
		}
	}
	return nil
}

func (r *CloudflareTunnelReconciler) cloudflareClient(ctx context.Context, account *v1alpha1.CloudflareAccount) (TunnelCloudflareClient, error) {
	if r.NewCloudflareClient == nil {
		return nil, errors.New("CloudflareTunnel reconciler requires NewCloudflareClient")
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

func (r *CloudflareTunnelReconciler) owningGateway(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) (*gatewayv1.Gateway, []string, error) {
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways, client.InNamespace(tunnel.Namespace)); err != nil {
		return nil, nil, fmt.Errorf("list Gateways: %w", err)
	}
	owners := make([]gatewayv1.Gateway, 0)
	for i := range gateways.Items {
		gateway := &gateways.Items[i]
		if !gateway.DeletionTimestamp.IsZero() {
			continue
		}
		if gatewayReferencesTunnel(gateway, tunnel.Name) || metav1.IsControlledBy(tunnel, gateway) {
			owners = append(owners, *gateway)
		}
	}
	if len(owners) == 0 {
		return nil, nil, nil
	}
	slices.SortFunc(owners, func(a, b gatewayv1.Gateway) int {
		if cmp := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Name, b.Name)
	})
	extra := make([]string, 0, len(owners)-1)
	for i := 1; i < len(owners); i++ {
		extra = append(extra, owners[i].Name)
	}
	return owners[0].DeepCopy(), extra, nil
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
	Hostname string
	Zone     string
	Exposure v1alpha1.Exposure
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

func authorizeBindings(account *v1alpha1.CloudflareAccount, namespace *corev1.Namespace, bindings []listenerBinding) authz.Decision {
	for _, binding := range bindings {
		decision := authz.Evaluate(account, namespace, authz.Request{
			Hostname: binding.Hostname,
			Zone:     binding.Zone,
			Exposure: binding.Exposure,
		})
		if !decision.Allowed {
			return decision
		}
	}
	return authz.Decision{Allowed: true, Reason: authz.ReasonAllowed, Message: "all Gateway listeners are granted"}
}

func connectorState(status string) v1alpha1.ConnectorState {
	switch strings.ToLower(status) {
	case string(v1alpha1.ConnectorStateHealthy):
		return v1alpha1.ConnectorStateHealthy
	case string(v1alpha1.ConnectorStateDegraded):
		return v1alpha1.ConnectorStateDegraded
	case string(v1alpha1.ConnectorStateDown):
		return v1alpha1.ConnectorStateDown
	default:
		return v1alpha1.ConnectorStateInactive
	}
}

func tunnelAddresses(tunnelID string, public bool) []gatewayv1.GatewayStatusAddress {
	if !public || tunnelID == "" {
		return []gatewayv1.GatewayStatusAddress{}
	}
	addressType := gatewayv1.HostnameAddressType
	return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: tunnelID + ".cfargotunnel.com"}}
}

func dnsOwnershipComment(tunnel *v1alpha1.CloudflareTunnel, clusterID, gatewayName string) string {
	return flarecloudflare.DNSRecordCommentWithText(clusterID, tunnel.Namespace, gatewayName, tunnel.Spec.DNS.RecordComment)
}

func dnsRecordOwnedByGateway(comment string, tunnel *v1alpha1.CloudflareTunnel, clusterID, gatewayName string) bool {
	return flarecloudflare.IsOwnedDNSRecord(
		RemoteDNSRecord{Comment: comment},
		flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName),
	)
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

func (r *CloudflareTunnelReconciler) dataplaneDrained(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel) (bool, error) {
	if tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" {
		return true, nil
	}
	key := types.NamespacedName{Namespace: tunnel.Namespace, Name: "flareway-gw-" + tunnel.Status.GatewayRef.Name}
	var deployment appsv1.Deployment
	if err := r.Get(ctx, key, &deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, fmt.Errorf("get dataplane Deployment: %w", err)
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
		return false, nil
	}
	var pods corev1.PodList
	label := tunnel.Namespace + "--" + tunnel.Status.GatewayRef.Name
	if err := r.List(ctx, &pods, client.InNamespace(tunnel.Namespace), client.MatchingLabels{dataplaneGatewayLabel: label}); err != nil {
		return false, fmt.Errorf("list dataplane Pods: %w", err)
	}
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp.IsZero() && pods.Items[i].Status.Phase != corev1.PodSucceeded && pods.Items[i].Status.Phase != corev1.PodFailed {
			return false, nil
		}
	}
	return true, nil
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
	ref v1alpha1.NamespacedObjectReference,
	targetNamespace, targetName string,
) bool {
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

func tunnelOwnedStatus(tunnel *v1alpha1.CloudflareTunnel, gatewayRef *corev1.LocalObjectReference, conditions []metav1.Condition) v1alpha1.CloudflareTunnelStatus {
	return v1alpha1.CloudflareTunnelStatus{
		TunnelID: tunnel.Status.TunnelID, ConnectorState: tunnel.Status.ConnectorState,
		OrphanedTunnelID: tunnel.Status.OrphanedTunnelID,
		Addresses:        append([]gatewayv1.GatewayStatusAddress(nil), tunnel.Status.Addresses...),
		DNSRecords:       append([]v1alpha1.CloudflareTunnelDNSRecordStatus(nil), tunnel.Status.DNSRecords...),
		GatewayRef:       gatewayRef, Conditions: conditions,
	}
}

func tunnelOwnedConditions(conditions []metav1.Condition) []metav1.Condition {
	owned := map[string]bool{
		v1alpha1.CloudflareTunnelConditionAccepted:       true,
		v1alpha1.CloudflareTunnelConditionTunnelReady:    true,
		v1alpha1.CloudflareTunnelConditionDNSReady:       true,
		v1alpha1.CloudflareTunnelConditionReady:          true,
		v1alpha1.CloudflareTunnelConditionCleanupBlocked: true,
		v1alpha1.CloudflareTunnelConditionConflict:       true,
	}
	result := make([]metav1.Condition, 0, len(owned))
	for _, condition := range conditions {
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

func (r *CloudflareTunnelReconciler) patchOwnedStatus(ctx context.Context, tunnel *v1alpha1.CloudflareTunnel, status v1alpha1.CloudflareTunnelStatus) error {
	statusMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	if err != nil {
		return fmt.Errorf("convert CloudflareTunnel status: %w", err)
	}
	for _, field := range []string{"configVersion", "hostnames", "listeners"} {
		delete(statusMap, field)
	}
	// Empty owned lists are explicit so teardown can signal DNS completion.
	// Optional scalars remain omitted when empty; applying JSON null to their
	// non-nullable CRD schema would reject the complete status patch.
	statusMap["addresses"] = sliceOrEmpty(statusMap["addresses"])
	statusMap["dnsRecords"] = sliceOrEmpty(statusMap["dnsRecords"])
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

	return ctrl.NewControllerManagedBy(mgr).
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
		Complete(observedReconciler("cloudflare-tunnel", r))
}

func (r *CloudflareTunnelReconciler) mapGatewayToTunnel(_ context.Context, object client.Object) []reconcile.Request {
	gateway, ok := object.(*gatewayv1.Gateway)
	if !ok {
		return nil
	}
	if gateway.Spec.Infrastructure != nil && gateway.Spec.Infrastructure.ParametersRef != nil {
		ref := gateway.Spec.Infrastructure.ParametersRef
		if string(ref.Group) == v1alpha1.Group && string(ref.Kind) == "CloudflareTunnel" {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: gateway.Namespace, Name: string(ref.Name)}}}
		}
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}}}
}

func (r *CloudflareTunnelReconciler) mapPrivateRouteToTunnel(_ context.Context, object client.Object) []reconcile.Request {
	var ref v1alpha1.NamespacedObjectReference
	switch route := object.(type) {
	case *v1alpha1.HostnameRoute:
		ref = route.Spec.TunnelRef
	case *v1alpha1.NetworkRoute:
		ref = route.Spec.TunnelRef
	default:
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
