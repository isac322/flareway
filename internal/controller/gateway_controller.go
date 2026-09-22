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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"golang.org/x/time/rate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/internal/xds/pki"
	"github.com/isac322/flareway/internal/xds/translator"
)

const (
	gatewayFieldManager           = "flareway-gateway"
	programmedRequeue             = 2 * time.Second
	gatewayReasonUnsupportedValue = "UnsupportedValue"

	httpRouteParentGatewayIndex           = "flareway.httpRoute.parentGateway"
	httpRouteBackendServiceIndex          = "flareway.httpRoute.backendService"
	gatewayListenerSecretIndex            = "flareway.gateway.listenerSecret"
	gatewayClassNameIndex                 = "flareway.gateway.gatewayClass"
	backendTLSPolicyTargetServiceIndex    = "flareway.backendTLSPolicy.targetService"
	backendTLSPolicyCAConfigMapIndex      = "flareway.backendTLSPolicy.caConfigMap"
	gatewayClassConfigIndex               = "flareway.gatewayClass.parametersRef"
	accessApplicationTargetGatewayIndex   = "flareway.accessApplication.targetGateway"
	accessApplicationTargetHTTPRouteIndex = "flareway.accessApplication.targetHTTPRoute"
)

// SnapshotPublisher is the narrow xDS contract needed by the Gateway
// reconciler. Production uses the xDS server; envtest uses an explicitly
// ACK-controlled implementation.
type SnapshotPublisher interface {
	SetSnapshot(context.Context, string, *cachev3.Snapshot) error
	ClearSnapshot(key string)
	IsACKed(key, version string) bool
	LastNACK(key string) (version, detail string, ok bool)
}

// SnapshotBuilder converts the translated gateway IR into an xDS snapshot.
type SnapshotBuilder func(*ir.Gateway, *v1alpha1.GatewayClassConfig) (*cachev3.Snapshot, error)

// GatewayReconciler compiles Gateway API resources into Envoy and Kubernetes
// dataplane resources.
type GatewayReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Snapshots         SnapshotPublisher
	BuildSnapshot     SnapshotBuilder
	OperatorNamespace string
	Now               func() time.Time
	CloudflareFactory flarecloudflare.ClientFactory
	Prober            dataplane.Prober
	Recorder          recorder.EventRecorder
	// DriftPolicy controls how out-of-band Cloudflare configuration drift is
	// handled. Empty or DriftPolicyOverwrite keeps the default overwrite
	// behavior; DriftPolicyHold exposes the drift without writing.
	DriftPolicy DriftPolicy
	// Freshness is the desired-hash gate policy (D1). A zero Policy keeps
	// every gate closed, which preserves the pre-gate behavior of reading
	// the remote on every pass.
	Freshness freshness.Policy
	// Invalidator is the sweep drift latch consulted by the desired-hash
	// gate. Nil means no invalidation source.
	Invalidator *freshness.Latch
	// SweepEvents carries drift wakeups from the sweep worker. When nil no
	// raw source is registered in SetupWithManager.
	SweepEvents <-chan event.GenericEvent
}

func (r *GatewayReconciler) operatorNamespace() string {
	if r.OperatorNamespace != "" {
		return r.OperatorNamespace
	}
	return dataplane.DefaultOperatorNamespace
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;gatewayclasses;httproutes;referencegrants;backendtlspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways/status;httproutes/status;backendtlspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=gatewayclassconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services;configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels;accessapplications,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflaretunnels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=virtualnetworks;networkroutes;hostnameroutes,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicesettings,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile builds and publishes the complete desired state for one Gateway.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var gateway gatewayv1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gateway); err != nil {
		if apierrors.IsNotFound(err) {
			r.clearSnapshot(req.NamespacedName)
			if err := r.clearAUDRevocationsForGateway(ctx, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var gatewayClass gatewayv1.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, &gatewayClass); err != nil {
		if apierrors.IsNotFound(err) {
			r.clearSnapshot(req.NamespacedName)
			if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if gatewayClass.Spec.ControllerName != gatewayapi.ControllerName {
		r.clearSnapshot(req.NamespacedName)
		if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if r.Snapshots == nil {
		return ctrl.Result{}, errors.New("gateway reconciler requires a snapshot publisher")
	}

	cfg, err := r.loadGatewayClassConfig(ctx, &gatewayClass)
	if err != nil {
		if isGatewayClassConfigInvalid(err) {
			r.clearSnapshot(req.NamespacedName)
			if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.rejectGatewayAdmission(ctx, &gateway, string(gatewayv1.GatewayReasonInvalidParameters), err.Error(), "GatewayClass parametersRef cannot be resolved"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	rejected, err := r.rejectDirectTunnelAttachment(ctx, &gateway, cfg)
	if err != nil {
		return ctrl.Result{}, err
	}
	if rejected {
		return ctrl.Result{}, nil
	}
	tunnel, account, effectiveConfig, created, err := r.resolveCloudflareContext(ctx, &gateway, cfg)
	accountMissing := false
	if err != nil {
		var missingTunnel *missingExplicitTunnelError
		var missingAccount *missingCloudflareAccountError
		switch {
		case errors.As(err, &missingTunnel):
			r.clearSnapshot(req.NamespacedName)
			if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.rejectGatewayAdmission(ctx, &gateway, string(gatewayv1.GatewayReasonInvalidParameters), err.Error(), "Gateway configuration references a CloudflareTunnel that does not exist"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		case errors.As(err, &missingAccount):
			accountMissing = true
		default:
			return ctrl.Result{}, err
		}
	}
	if tunnel != nil && tunnel.Spec.Configuration.Mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		reason, acceptedMessage, programmedMessage := directTunnelRejection(client.ObjectKeyFromObject(tunnel))
		r.clearSnapshot(req.NamespacedName)
		if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.rejectGatewayAdmission(ctx, &gateway, reason, acceptedMessage, programmedMessage); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if created {
		return ctrl.Result{RequeueAfter: programmedRequeue}, nil
	}
	cfg = effectiveConfig
	inputs, routes, err := r.collectInputs(ctx, &gateway, &gatewayClass, cfg)
	if err != nil {
		return ctrl.Result{}, err
	}
	inputs.CloudflareTunnel = tunnel
	inputs.CloudflareAccount = account
	if err := r.applyAUDRevocationLatches(ctx, &gateway, tunnel, &inputs); err != nil {
		return ctrl.Result{}, err
	}

	compiled, statuses := gatewayapi.Translate(inputs)
	if compiled == nil {
		return ctrl.Result{}, errors.New("gateway API translator returned a nil Gateway")
	}
	retainAccessRevocationDomains(compiled, tunnel, inputs.AccessApplications)
	compiled, _, err = accessBlockFirstGateway(compiled, tunnel)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("prepare Access block-first transition: %w", err)
	}
	privateState := privatePrerequisiteResult{}
	if !compiled.ConformanceMode {
		privateState, err = r.reconcilePrivatePrerequisites(ctx, compiled, tunnel, account, privateInputsView(
			inputs.Namespaces, inputs.VirtualNetworks, inputs.NetworkRoutes, inputs.HostnameRoutes, inputs.AccessApplications,
		))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("reconcile private listener prerequisites: %w", err)
		}
	}

	r.prepareGatewayStatus(&statuses.Gateway, &gateway)
	if accepted := meta.FindStatusCondition(statuses.Gateway.Conditions, string(gatewayv1.GatewayConditionAccepted)); accepted != nil && accepted.Status == metav1.ConditionFalse {
		// A Gateway the translator rejected can never be programmed: retract
		// the published snapshot and the owned dataplane in every mode —
		// including conformance mode — and record the rejection without
		// publishing a new snapshot. AUD revocation latches and owned child
		// resources are deliberately retained.
		r.clearSnapshot(req.NamespacedName)
		statuses.Gateway.Addresses = nil
		now := metav1.Now()
		if r.Now != nil {
			now = metav1.NewTime(r.Now())
		}
		meta.SetStatusCondition(&statuses.Gateway.Conditions, metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: gateway.Generation,
			Reason:             string(gatewayv1.GatewayReasonInvalid),
			Message:            "Gateway configuration is invalid",
			LastTransitionTime: now,
		})
		for index := range statuses.Gateway.Listeners {
			meta.SetStatusCondition(&statuses.Gateway.Listeners[index].Conditions, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionProgrammed),
				Status:             metav1.ConditionFalse,
				ObservedGeneration: gateway.Generation,
				Reason:             string(gatewayv1.ListenerReasonInvalid),
				Message:            "Listener configuration is invalid",
				LastTransitionTime: now,
			})
		}
		if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchGatewayStatus(ctx, req.NamespacedName, statuses.Gateway); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchHTTPRouteStatuses(ctx, routes, statuses.HTTPRoutes, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchBackendTLSPolicyStatuses(ctx, inputs.BackendTLSPolicies, statuses.BackendTLSPolicies, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if err := r.patchGatewayStatus(ctx, req.NamespacedName, statuses.Gateway); err != nil {
		return ctrl.Result{}, err
	}

	snapshotBuilder := r.BuildSnapshot
	if snapshotBuilder == nil {
		snapshotBuilder = translator.Build
	}
	snapshot, err := snapshotBuilder(compiled, cfg)
	if err != nil {
		return ctrl.Result{}, r.handleSnapshotBuildFailure(ctx, req.NamespacedName, &gateway, routes, inputs.BackendTLSPolicies, &statuses, fmt.Errorf("build xDS snapshot: %w", err))
	}
	version, err := translator.SnapshotVersion(snapshot)
	if err != nil {
		return ctrl.Result{}, r.handleSnapshotBuildFailure(ctx, req.NamespacedName, &gateway, routes, inputs.BackendTLSPolicies, &statuses, fmt.Errorf("read xDS snapshot version: %w", err))
	}

	if !compiled.ConformanceMode && (tunnel == nil || account == nil || compiled.Cloudflare == nil) {
		r.clearSnapshot(req.NamespacedName)
		statuses.Gateway.Addresses = nil
		r.setCloudflareProgrammedStatus(&statuses.Gateway, &gateway, false, "CloudflareTunnel and CloudflareAccount are required")
		if err := r.retractGatewayDataplane(ctx, &gateway); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchGatewayStatus(ctx, req.NamespacedName, statuses.Gateway); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchHTTPRouteStatuses(ctx, routes, statuses.HTTPRoutes, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchBackendTLSPolicyStatuses(ctx, inputs.BackendTLSPolicies, statuses.BackendTLSPolicies, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		if accountMissing {
			// The referenced CloudflareAccount is confirmed absent: stop
			// polling and rely on the CloudflareAccount watch to re-enqueue
			// this Gateway when the account is recreated.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: programmedRequeue}, nil
	}

	if !compiled.ConformanceMode {
		currentTunnel, err := r.validateGatewayTunnelWriter(ctx, compiled, tunnel)
		if err != nil {
			return ctrl.Result{}, err
		}
		tunnel = currentTunnel
	}

	if err := r.ensureXDSClientCertificate(ctx, &gateway); err != nil {
		return ctrl.Result{}, err
	}
	key := req.Namespace + "/" + req.Name
	if err := r.Snapshots.SetSnapshot(ctx, key, snapshot); err != nil {
		return ctrl.Result{}, fmt.Errorf("publish xDS snapshot for %s: %w", key, err)
	}
	resources, err := r.desiredResources(compiled, cfg)
	if err != nil {
		return ctrl.Result{}, err
	}
	if tunnel != nil && shouldScaleDownTunnel(tunnel) {
		scaleDesiredDeploymentToZero(resources)
	}
	for _, object := range resources {
		if err := reconcileGatewayOwnedObject(ctx, r.Client, r.Scheme, &gateway, object); err != nil {
			return ctrl.Result{}, fmt.Errorf("reconcile %T %s/%s: %w", object, object.GetNamespace(), object.GetName(), err)
		}
	}

	var cloudflareResult cloudflareConfigResult
	if !compiled.ConformanceMode {
		cloudflareResult, err = r.reconcileCloudflaredConfiguration(ctx, compiled, tunnel, account)
		if err != nil {
			return ctrl.Result{}, err
		}
		if cloudflareResult.drift && r.Recorder != nil {
			r.Recorder.Eventf(&gateway, nil, corev1.EventTypeWarning, observability.EventReasonOutOfBandChange, "ReconcileGateway", "%s", cloudflareResult.message)
			if tunnel != nil {
				r.Recorder.Eventf(tunnel, nil, corev1.EventTypeWarning, observability.EventReasonOutOfBandChange, "ReconcileTunnel", "%s", cloudflareResult.message)
			}
		}
		now := metav1.Now()
		if r.Now != nil {
			now = metav1.NewTime(r.Now())
		}
		config := tunnel.Status.ConfigVersion
		if cloudflareResult.version > 0 {
			config.Desired = cloudflareResult.version
			config.DesiredHash = cloudflareResult.hash
		}
		if cloudflareResult.appliedAt != nil {
			config.AppliedAt = cloudflareResult.appliedAt
		}
		config.Remote = cloudflareResult.remoteVersion
		config.CreatedAt = cloudflareResult.remoteCreatedAt
		reason := "Pending"
		message := cloudflareResult.pending
		switch {
		case cloudflareResult.held:
			reason = "DriftHold"
			message = cloudflareResult.message
		case cloudflareResult.drift:
			reason = "OutOfBandChange"
			message = cloudflareResult.message
		case message == "":
			message = fmt.Sprintf("Waiting for cloudflared configuration version %d", config.Desired)
		}
		driftCondition := gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionDriftDetected, metav1.ConditionFalse, "Synchronized", "Cloudflare Tunnel configuration matches the applied state", now)
		if cloudflareResult.drift {
			driftCondition = gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionDriftDetected, metav1.ConditionTrue, "OutOfBandChangeDetected", cloudflareResult.message, now)
		}
		if err := r.patchTunnelGatewayStatus(
			ctx,
			compiled,
			tunnel,
			config,
			tunnel.Status.Hostnames,
			desiredTunnelListeners(compiled),
			gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, reason, message, now),
			privateListenerCondition(compiled, privateState, now),
			driftCondition,
		); err != nil {
			return ctrl.Result{}, err
		}
		statuses.Gateway.Addresses = tunnelGatewayAddresses(compiled, tunnel)
		observability.Default.SetConfigVersions(req.String(), config.Desired, config.Applied)
		if cloudflareResult.pending != "" || cloudflareResult.drift || cloudflareResult.held {
			r.setCloudflareProgrammedStatus(&statuses.Gateway, &gateway, false, message)
			if err := r.patchGatewayStatus(ctx, req.NamespacedName, statuses.Gateway); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.patchHTTPRouteStatuses(ctx, routes, statuses.HTTPRoutes, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.patchBackendTLSPolicyStatuses(ctx, inputs.BackendTLSPolicies, statuses.BackendTLSPolicies, req.NamespacedName); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: programmedRequeue}, nil
		}
	}

	pending := false
	if compiled.ConformanceMode {
		addresses, addressReady, addressMessage, err := r.serviceAddresses(ctx, compiled)
		if err != nil {
			return ctrl.Result{}, err
		}
		deploymentReady, err := r.deploymentAvailable(ctx, compiled)
		if err != nil {
			return ctrl.Result{}, err
		}
		acked := r.Snapshots.IsACKed(key, version)
		statuses.Gateway.Addresses = addresses
		pending = r.setProgrammedStatus(&statuses.Gateway, &gateway, key, version, acked, deploymentReady, addressReady, addressMessage)
	} else {
		statuses.Gateway.Addresses = tunnelGatewayAddresses(compiled, tunnel)
		ready, lagging, _, err := r.cloudflareGate(ctx, compiled, tunnel, fmt.Sprint(cloudflareResult.version), version)
		if err != nil {
			return ctrl.Result{}, err
		}
		if privateState.Pending != "" {
			ready = false
			lagging = append(lagging, privateState.Pending)
		}
		message := "Gateway configuration is acknowledged by Envoy, active in every cloudflared Pod, and present in DNS"
		if !ready {
			message = "Waiting for Cloudflare programming gate: " + strings.Join(lagging, ", ")
			if condition := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied); condition != nil && r.gatewayNow().Sub(condition.LastTransitionTime.Time) >= cloudflareConvergenceTimeout {
				message = "Timed out after 30s waiting for Cloudflare programming gate: " + strings.Join(lagging, ", ")
			}
			pending = true
		}
		r.setCloudflareProgrammedStatus(&statuses.Gateway, &gateway, ready, message)
		config := tunnel.Status.ConfigVersion
		if cloudflareResult.version > 0 {
			config.Desired = cloudflareResult.version
			config.DesiredHash = cloudflareResult.hash
		}
		if cloudflareResult.appliedAt != nil {
			config.AppliedAt = cloudflareResult.appliedAt
		}
		config.Remote = cloudflareResult.remoteVersion
		config.CreatedAt = cloudflareResult.remoteCreatedAt
		hostnames := tunnel.Status.Hostnames
		conditionStatus := metav1.ConditionFalse
		reason := "Pending"
		denySnapshotApplied := compiled.Cloudflare != nil && compiled.Cloudflare.Teardown && r.Snapshots.IsACKed(key, version)
		if ready || denySnapshotApplied {
			config.Applied = cloudflareResult.version
			hostnames = desiredTunnelHostnames(compiled, cloudflareResult.version)
			conditionStatus = metav1.ConditionTrue
			reason = "Applied"
			if denySnapshotApplied && !ready {
				reason = "TeardownBlocked"
			}
		}
		now := metav1.NewTime(r.gatewayNow())
		driftCondition := gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionDriftDetected, metav1.ConditionFalse, "Synchronized", "Cloudflare Tunnel configuration matches the applied state", now)
		if cloudflareResult.drift {
			driftCondition = gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionDriftDetected, metav1.ConditionTrue, "OutOfBandChangeDetected", cloudflareResult.message, now)
		}
		if err := r.patchTunnelGatewayStatus(
			ctx, compiled, tunnel, config, hostnames, desiredTunnelListeners(compiled),
			gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionConfigApplied, conditionStatus, reason, message, now),
			privateListenerCondition(compiled, privateState, now),
			driftCondition,
		); err != nil {
			return ctrl.Result{}, err
		}
		observability.Default.SetConfigVersions(req.String(), config.Desired, config.Applied)
	}

	if err := r.patchGatewayStatus(ctx, req.NamespacedName, statuses.Gateway); err != nil {
		return ctrl.Result{}, err
	}
	if compiled.ConformanceMode {
		observability.Default.SetConfigVersions(req.String(), 0, 0)
	}
	if err := r.patchHTTPRouteStatuses(ctx, routes, statuses.HTTPRoutes, req.NamespacedName); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.patchBackendTLSPolicyStatuses(ctx, inputs.BackendTLSPolicies, statuses.BackendTLSPolicies, req.NamespacedName); err != nil {
		return ctrl.Result{}, err
	}

	if pending {
		return ctrl.Result{RequeueAfter: programmedRequeue}, nil
	}
	return ctrl.Result{RequeueAfter: cloudflareResult.requeue}, nil
}

func (r *GatewayReconciler) rejectDirectTunnelAttachment(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	cfg *v1alpha1.GatewayClassConfig,
) (bool, error) {
	tunnelName, explicit, supported := referencedTunnelName(gateway)
	if !supported || (cfg.Spec.ConformanceMode && !explicit) {
		return false, nil
	}
	if tunnelName == "" {
		tunnelName = gateway.Name
	}
	tunnelKey := types.NamespacedName{Namespace: gateway.Namespace, Name: tunnelName}
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, tunnelKey, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get CloudflareTunnel %s for Gateway admission: %w", tunnelKey, err)
	}
	if tunnel.Spec.Configuration.Mode != v1alpha1.CloudflareTunnelConfigurationModeDirect {
		return false, nil
	}
	r.clearSnapshot(client.ObjectKeyFromObject(gateway))
	if err := r.retractGatewayDataplane(ctx, gateway); err != nil {
		return false, err
	}
	reason, acceptedMessage, programmedMessage := directTunnelRejection(tunnelKey)
	if err := r.rejectGatewayAdmission(ctx, gateway, reason, acceptedMessage, programmedMessage); err != nil {
		return false, err
	}
	return true, nil
}

// directTunnelRejection returns the single source for the Accepted reason and
// the Accepted/Programmed messages recorded when a Gateway references a
// Direct-mode CloudflareTunnel. Both the pre-resolution admission check and
// the post-resolution guard must emit identical status text.
func directTunnelRejection(tunnelKey types.NamespacedName) (reason, acceptedMessage, programmedMessage string) {
	return gatewayReasonUnsupportedValue,
		fmt.Sprintf("CloudflareTunnel %s uses Direct configuration mode and cannot be attached to a Gateway", tunnelKey),
		"Gateway configuration references a Direct-mode CloudflareTunnel"
}

// rejectGatewayAdmission terminally rejects a Gateway whose referenced
// parameters cannot be resolved or programmed: it retracts addresses and
// listener status and records the rejection on the Accepted and Programmed
// conditions. Callers clear the published snapshot and retract the owned
// dataplane first; AUD revocation latches and owned child resources are
// deliberately retained.
func (r *GatewayReconciler) rejectGatewayAdmission(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	acceptedReason, acceptedMessage, programmedMessage string,
) error {
	desired := gateway.DeepCopy().Status
	desired.Addresses = nil
	desired.Listeners = nil
	now := metav1.Now()
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}
	meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionAccepted),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gateway.Generation,
		Reason:             acceptedReason,
		Message:            acceptedMessage,
		LastTransitionTime: now,
	})
	meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gateway.Generation,
		Reason:             string(gatewayv1.GatewayReasonInvalid),
		Message:            programmedMessage,
		LastTransitionTime: now,
	})
	return r.patchGatewayStatus(ctx, client.ObjectKeyFromObject(gateway), desired)
}

// invalidGatewayClassConfigError marks a GatewayClass parametersRef that can
// never resolve: either an unsupported group/kind or a GatewayClassConfig that
// is confirmed missing. Transient API failures stay plain wrapped errors so
// callers keep retrying them.
type invalidGatewayClassConfigError struct {
	message string
}

func (e *invalidGatewayClassConfigError) Error() string { return e.message }

// isGatewayClassConfigInvalid reports whether err is a confirmed unresolvable
// GatewayClass parametersRef rather than a transient lookup failure.
func isGatewayClassConfigInvalid(err error) bool {
	var invalid *invalidGatewayClassConfigError
	return errors.As(err, &invalid)
}

func (r *GatewayReconciler) loadGatewayClassConfig(ctx context.Context, gatewayClass *gatewayv1.GatewayClass) (*v1alpha1.GatewayClassConfig, error) {
	ref := gatewayClass.Spec.ParametersRef
	if ref == nil {
		return defaultGatewayClassConfig(), nil
	}
	if string(ref.Group) != v1alpha1.Group || string(ref.Kind) != "GatewayClassConfig" {
		return nil, &invalidGatewayClassConfigError{message: fmt.Sprintf("the GatewayClass %q has unsupported parametersRef %s/%s", gatewayClass.Name, ref.Group, ref.Kind)}
	}

	var cfg v1alpha1.GatewayClassConfig
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &invalidGatewayClassConfigError{message: fmt.Sprintf("the GatewayClassConfig %q referenced by GatewayClass %q was not found", ref.Name, gatewayClass.Name)}
		}
		return nil, fmt.Errorf("get GatewayClassConfig %q: %w", ref.Name, err)
	}
	return &cfg, nil
}

func defaultGatewayClassConfig() *v1alpha1.GatewayClassConfig {
	replicas := int32(2)
	concurrency := int32(1)
	return &v1alpha1.GatewayClassConfig{
		TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "GatewayClassConfig"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			Connector: v1alpha1.ConnectorSpec{
				Image:       v1alpha1.DefaultConnectorImage,
				Replicas:    &replicas,
				Protocol:    v1alpha1.ConnectorProtocolAuto,
				GracePeriod: metav1.Duration{Duration: 60 * time.Second},
			},
			Proxy: v1alpha1.ProxySpec{
				Image:             v1alpha1.DefaultProxyImage,
				StreamIdleTimeout: metav1.Duration{Duration: time.Hour},
				Concurrency:       &concurrency,
			},
			PrivateDNS:  v1alpha1.PrivateDNSSpec{Image: v1alpha1.DefaultPrivateDNSImage},
			DNS:         v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeManaged},
			OriginJWT:   v1alpha1.GatewayClassOriginJWTConfig{Mode: v1alpha1.OriginJWTModeRequired},
			Conformance: v1alpha1.ConformanceSpec{ServiceType: corev1.ServiceTypeLoadBalancer},
		},
	}
}

func (r *GatewayReconciler) collectInputs(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	gatewayClass *gatewayv1.GatewayClass,
	cfg *v1alpha1.GatewayClassConfig,
) (gatewayapi.Inputs, []gatewayv1.HTTPRoute, error) {
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list Namespaces: %w", err)
	}
	var routes gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routes); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list HTTPRoutes: %w", err)
	}
	translationRoutes := make([]gatewayv1.HTTPRoute, 0)
	gatewayKey := client.ObjectKeyFromObject(gateway)
	for index := range routes.Items {
		route := &routes.Items[index]
		if stringSliceContains(httpRouteParentGatewayKeys(route), gatewayKey.String()) ||
			hasControllerParentForGateway(route.Status.Parents, route.Namespace, gatewayKey) {
			translationRoutes = append(translationRoutes, *route.DeepCopy())
		}
	}
	var grants gatewayv1.ReferenceGrantList
	if err := r.List(ctx, &grants); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list ReferenceGrants: %w", err)
	}
	var backendPolicies gatewayv1.BackendTLSPolicyList
	if err := r.List(ctx, &backendPolicies); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list BackendTLSPolicies: %w", err)
	}

	services, endpointSlices, err := r.collectBackends(ctx, translationRoutes)
	if err != nil {
		return gatewayapi.Inputs{}, nil, err
	}
	secrets, err := r.collectListenerSecrets(ctx, gateway)
	if err != nil {
		return gatewayapi.Inputs{}, nil, err
	}
	configMaps, err := r.collectBackendTLSConfigMaps(ctx, backendPolicies.Items)
	if err != nil {
		return gatewayapi.Inputs{}, nil, err
	}
	accessApplications, audSecrets, err := r.collectAccessInputs(ctx, gateway)
	if err != nil {
		return gatewayapi.Inputs{}, nil, err
	}
	var virtualNetworks v1alpha1.VirtualNetworkList
	if err := r.List(ctx, &virtualNetworks); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list VirtualNetworks: %w", err)
	}
	var networkRoutes v1alpha1.NetworkRouteList
	if err := r.List(ctx, &networkRoutes); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list NetworkRoutes: %w", err)
	}
	var hostnameRoutes v1alpha1.HostnameRouteList
	if err := r.List(ctx, &hostnameRoutes); err != nil {
		return gatewayapi.Inputs{}, nil, fmt.Errorf("list HostnameRoutes: %w", err)
	}

	now := metav1.NewTime(time.Now())
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}
	inputs := gatewayapi.Inputs{
		Gateway:            gateway.DeepCopy(),
		GatewayClass:       gatewayClass.DeepCopy(),
		GatewayClassConfig: cfg.DeepCopy(),
		AccessApplications: accessApplications,
		AUDSecrets:         audSecrets,
		VirtualNetworks:    virtualNetworks.Items,
		NetworkRoutes:      networkRoutes.Items,
		HostnameRoutes:     hostnameRoutes.Items,
		Namespaces:         namespaces.Items,
		HTTPRoutes:         translationRoutes,
		ReferenceGrants:    grants.Items,
		BackendTLSPolicies: backendPolicies.Items,
		Services:           services,
		EndpointSlices:     endpointSlices,
		Secrets:            secrets,
		ConfigMaps:         configMaps,
		Now:                now,
	}
	return inputs, routes.Items, nil
}

func (r *GatewayReconciler) collectAccessInputs(ctx context.Context, gateway *gatewayv1.Gateway) ([]v1alpha1.AccessApplication, map[types.NamespacedName]gatewayapi.AUDSecret, error) {
	var applications v1alpha1.AccessApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(gateway.Namespace)); err != nil {
		return nil, nil, fmt.Errorf("list AccessApplications: %w", err)
	}

	operatorNamespace := r.operatorNamespace()
	secrets, err := listAUDSecretsForGateway(ctx, r.Client, operatorNamespace, gateway)
	if err != nil {
		return nil, nil, fmt.Errorf("list AccessApplication AUD Secrets: %w", err)
	}
	if err := migrateLegacyAUDSecrets(ctx, r.Client, secrets, applications.Items, gateway); err != nil {
		return nil, nil, fmt.Errorf("migrate AccessApplication AUD Secrets: %w", err)
	}
	return applications.Items, verifiedAUDSecrets(secrets, applications.Items, gateway), nil
}

func audIdentityLabel(key types.NamespacedName, uid types.UID) string {
	sum := sha256.Sum256([]byte(key.Namespace + "\x00" + key.Name + "\x00" + string(uid)))
	return hex.EncodeToString(sum[:])[:63]
}

func applicationAUDIdentityLabel(application *v1alpha1.AccessApplication) string {
	return audIdentityLabel(client.ObjectKeyFromObject(application), application.UID)
}

func gatewayAUDIdentityLabel(gateway *gatewayv1.Gateway) string {
	return audIdentityLabel(client.ObjectKeyFromObject(gateway), gateway.UID)
}

func listAUDSecretsForGateway(
	ctx context.Context,
	reader client.Reader,
	operatorNamespace string,
	gateway *gatewayv1.Gateway,
) ([]corev1.Secret, error) {
	labelValues := []string{gatewayAUDIdentityLabel(gateway)}
	legacyLabel := gateway.Namespace + "--" + gateway.Name
	if len(legacyLabel) <= 63 {
		labelValues = append(labelValues, legacyLabel)
	}
	secrets := make([]corev1.Secret, 0)
	seen := make(map[types.NamespacedName]struct{})
	for _, labelValue := range labelValues {
		var listed corev1.SecretList
		if err := reader.List(ctx, &listed,
			client.InNamespace(operatorNamespace),
			client.MatchingLabels{v1alpha1.AccessApplicationGatewayAUDLabel: labelValue},
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

func migrateLegacyAUDSecrets(
	ctx context.Context,
	kube client.Client,
	secrets []corev1.Secret,
	applications []v1alpha1.AccessApplication,
	gateway *gatewayv1.Gateway,
) error {
	secretByName := make(map[string]int, len(secrets))
	for index := range secrets {
		secretByName[secrets[index].Name] = index
	}
	gatewayKey := client.ObjectKeyFromObject(gateway)
	for appIndex := range applications {
		application := &applications[appIndex]
		secretIndex, found := secretByName[accessAUDSecretName(application, gatewayKey)]
		if !found {
			continue
		}
		secret := &secrets[secretIndex]
		if audSecretIdentityMatches(secret, application, gateway) {
			continue
		}
		if secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel] != application.Namespace+"--"+application.Name ||
			secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel] != gateway.Namespace+"--"+gateway.Name ||
			string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]) == "" ||
			string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]) != application.Status.ApplicationID {
			continue
		}
		before := secret.DeepCopy()
		if secret.Labels == nil {
			secret.Labels = make(map[string]string, 2)
		}
		secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel] = applicationAUDIdentityLabel(application)
		secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel] = gatewayAUDIdentityLabel(gateway)
		if secret.Data == nil {
			secret.Data = make(map[string][]byte, 6)
		}
		secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey] = []byte(client.ObjectKeyFromObject(application).String())
		secret.Data[v1alpha1.AccessApplicationUIDSecretKey] = []byte(application.UID)
		secret.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey] = []byte(gatewayKey.String())
		secret.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey] = []byte(gateway.UID)
		base := client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})
		if err := kube.Patch(ctx, secret, base); err != nil {
			return err
		}
	}
	return nil
}

func verifiedAUDSecrets(
	secrets []corev1.Secret,
	applications []v1alpha1.AccessApplication,
	gateway *gatewayv1.Gateway,
) map[types.NamespacedName]gatewayapi.AUDSecret {
	applicationsByLabel := make(map[string]*v1alpha1.AccessApplication, len(applications))
	for index := range applications {
		application := &applications[index]
		label := applicationAUDIdentityLabel(application)
		if _, duplicate := applicationsByLabel[label]; duplicate {
			applicationsByLabel[label] = nil
			continue
		}
		applicationsByLabel[label] = application
	}
	result := make(map[types.NamespacedName]gatewayapi.AUDSecret)
	conflicted := make(map[types.NamespacedName]struct{})
	for index := range secrets {
		secret := &secrets[index]
		application := applicationsByLabel[secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]]
		if application == nil || !audSecretIdentityMatches(secret, application, gateway) {
			continue
		}
		key := client.ObjectKeyFromObject(application)
		if _, duplicate := result[key]; duplicate {
			delete(result, key)
			conflicted[key] = struct{}{}
			continue
		}
		if _, rejected := conflicted[key]; rejected {
			continue
		}
		result[key] = gatewayapi.AUDSecret{
			AUD:           string(secret.Data[v1alpha1.AccessApplicationAUDSecretKey]),
			ApplicationID: string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]),
			Ready:         string(secret.Data[accessApplicationAUDReadyKey]) == "true",
		}
	}
	return result
}

func audSecretIdentityMatches(
	secret *corev1.Secret,
	application *v1alpha1.AccessApplication,
	gateway *gatewayv1.Gateway,
) bool {
	applicationKey := client.ObjectKeyFromObject(application)
	gatewayKey := client.ObjectKeyFromObject(gateway)
	applicationID := string(secret.Data[v1alpha1.AccessApplicationIDSecretKey])
	return applicationID != "" &&
		applicationID == application.Status.ApplicationID &&
		secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel] == applicationAUDIdentityLabel(application) &&
		secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel] == gatewayAUDIdentityLabel(gateway) &&
		string(secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey]) == applicationKey.String() &&
		string(secret.Data[v1alpha1.AccessApplicationUIDSecretKey]) == string(application.UID) &&
		string(secret.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey]) == gatewayKey.String() &&
		string(secret.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey]) == string(gateway.UID)
}

func (r *GatewayReconciler) collectBackends(ctx context.Context, routes []gatewayv1.HTTPRoute) ([]corev1.Service, []discoveryv1.EndpointSlice, error) {
	keys := make(map[types.NamespacedName]struct{})
	for index := range routes {
		for _, value := range httpRouteBackendServiceKeys(&routes[index]) {
			namespace, name, ok := strings.Cut(value, "/")
			if ok {
				keys[types.NamespacedName{Namespace: namespace, Name: name}] = struct{}{}
			}
		}
	}

	ordered := make([]types.NamespacedName, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Namespace != ordered[j].Namespace {
			return ordered[i].Namespace < ordered[j].Namespace
		}
		return ordered[i].Name < ordered[j].Name
	})

	services := make([]corev1.Service, 0, len(ordered))
	endpointSlices := make([]discoveryv1.EndpointSlice, 0)
	for _, key := range ordered {
		var service corev1.Service
		if err := r.Get(ctx, key, &service); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, fmt.Errorf("get backend Service %s: %w", key, err)
		}
		services = append(services, service)

		var slices discoveryv1.EndpointSliceList
		if err := r.List(ctx, &slices, client.InNamespace(key.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: key.Name}); err != nil {
			return nil, nil, fmt.Errorf("list EndpointSlices for Service %s: %w", key, err)
		}
		endpointSlices = append(endpointSlices, slices.Items...)
	}
	return services, endpointSlices, nil
}

func (r *GatewayReconciler) collectBackendTLSConfigMaps(ctx context.Context, policies []gatewayv1.BackendTLSPolicy) ([]corev1.ConfigMap, error) {
	keys := make(map[types.NamespacedName]struct{})
	for _, policy := range policies {
		for _, ref := range policy.Spec.Validation.CACertificateRefs {
			if string(ref.Group) == "" && string(ref.Kind) == "ConfigMap" {
				keys[types.NamespacedName{Namespace: policy.Namespace, Name: string(ref.Name)}] = struct{}{}
			}
		}
	}
	ordered := make([]types.NamespacedName, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Namespace != ordered[j].Namespace {
			return ordered[i].Namespace < ordered[j].Namespace
		}
		return ordered[i].Name < ordered[j].Name
	})
	configMaps := make([]corev1.ConfigMap, 0, len(ordered))
	for _, key := range ordered {
		var configMap corev1.ConfigMap
		if err := r.Get(ctx, key, &configMap); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get BackendTLSPolicy CA ConfigMap %s: %w", key, err)
		}
		configMaps = append(configMaps, configMap)
	}
	return configMaps, nil
}

func (r *GatewayReconciler) collectListenerSecrets(ctx context.Context, gateway *gatewayv1.Gateway) ([]corev1.Secret, error) {
	keys := gatewayListenerSecretKeys(gateway)
	secrets := make([]corev1.Secret, 0, len(keys))
	for _, value := range keys {
		namespace, name, ok := strings.Cut(value, "/")
		if !ok {
			continue
		}
		var secret corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get listener Secret %s: %w", value, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (r *GatewayReconciler) ensureXDSClientCertificate(ctx context.Context, gateway *gatewayv1.Gateway) error {
	owner := metav1.NewControllerRef(gateway, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway"))
	if _, err := pki.EnsureClientCert(ctx, r.Client, client.ObjectKeyFromObject(gateway), *owner); err != nil {
		return fmt.Errorf("ensure xDS client certificate: %w", err)
	}
	return nil
}

func (r *GatewayReconciler) desiredResources(gateway *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) ([]client.Object, error) {
	bootstrap, err := dataplane.BuildBootstrapConfigMap(gateway, cfg)
	if err != nil {
		return nil, fmt.Errorf("build Envoy bootstrap ConfigMap: %w", err)
	}
	hash, err := bootstrapConfigHash(bootstrap)
	if err != nil {
		return nil, err
	}
	deployment := dataplane.BuildDeployment(gateway, cfg, bootstrap.Name, hash)
	service := dataplane.BuildService(gateway, cfg)
	pdb := dataplane.BuildPDB(gateway, cfg)
	networkPolicy := dataplane.BuildNetworkPolicy(gateway, cfg, r.OperatorNamespace)
	resources := []client.Object{bootstrap, deployment, service, pdb, networkPolicy}
	if privateDNS := dataplane.BuildPrivateDNSConfigMap(gateway); privateDNS != nil {
		resources = append(resources, privateDNS)
	}
	return resources, nil
}

func bootstrapConfigHash(configMap *corev1.ConfigMap) (string, error) {
	payload, err := json.Marshal(struct {
		Data       map[string]string `json:"data,omitempty"`
		BinaryData map[string][]byte `json:"binaryData,omitempty"`
	}{Data: configMap.Data, BinaryData: configMap.BinaryData})
	if err != nil {
		return "", fmt.Errorf("marshal Envoy bootstrap ConfigMap for hashing: %w", err)
	}
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("%x", digest[:]), nil
}

func (r *GatewayReconciler) clearSnapshot(key types.NamespacedName) {
	if r.Snapshots != nil {
		r.Snapshots.ClearSnapshot(key.String())
	}
	observability.Default.DeleteGateway(key.String())
}

// retractGatewayDataplane scales the dataplane Deployment of a retracted
// Gateway to zero so a cleared snapshot cannot keep serving traffic through
// full replicas. A missing Deployment is success. A Deployment controlled by
// a different owner — including a recreated Gateway with a different UID — is
// left untouched and surfaced through the log and a Warning event; the
// rejection still completes because mutating foreign workloads is never safe.
// Transient API failures are returned so the caller retries.
func (r *GatewayReconciler) retractGatewayDataplane(ctx context.Context, gateway *gatewayv1.Gateway) error {
	if gateway == nil || gateway.UID == "" {
		// Only an exact, non-empty Gateway UID may authorize scaling: without
		// one there is no ownership to prove, so the dataplane stays untouched.
		return nil
	}
	key := types.NamespacedName{
		Namespace: gateway.Namespace,
		Name:      dataplane.ResourceName(&ir.Gateway{Key: client.ObjectKeyFromObject(gateway)}),
	}
	var deployment appsv1.Deployment
	if err := r.Get(ctx, key, &deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get dataplane Deployment %s: %w", key, err)
	}
	expected := metav1.NewControllerRef(gateway, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway"))
	if !sameControllerIdentity(metav1.GetControllerOf(&deployment), expected) {
		ctrl.LoggerFrom(ctx).Info(
			"Leaving dataplane Deployment untouched during Gateway retraction: not controlled by this Gateway UID",
			"gateway", client.ObjectKeyFromObject(gateway), "gatewayUID", gateway.UID, "deployment", key,
		)
		if r.Recorder != nil {
			r.Recorder.Eventf(gateway, nil, corev1.EventTypeWarning, "ForeignDataplane", "RetractGateway",
				"Dataplane Deployment %s is not controlled by Gateway UID %s and was left running", key, gateway.UID)
		}
		return nil
	}
	if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 0 {
		return nil
	}
	before := deployment.DeepCopy()
	zero := int32(0)
	deployment.Spec.Replicas = &zero
	if err := r.Patch(ctx, &deployment, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("scale dataplane Deployment %s to zero: %w", key, err)
	}
	return nil
}

func (r *GatewayReconciler) serviceAddresses(ctx context.Context, gateway *ir.Gateway) ([]gatewayv1.GatewayStatusAddress, bool, string, error) {
	var service corev1.Service
	key := types.NamespacedName{Namespace: gateway.Key.Namespace, Name: dataplane.ResourceName(gateway)}
	if err := r.Get(ctx, key, &service); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, "Waiting for the dataplane Service to be created", nil
		}
		return nil, false, "", fmt.Errorf("get dataplane Service %s: %w", key, err)
	}
	addresses, ready, message := serviceAddress(&service)
	return addresses, ready, message, nil
}

func (r *GatewayReconciler) deploymentAvailable(ctx context.Context, gateway *ir.Gateway) (bool, error) {
	var deployment appsv1.Deployment
	key := types.NamespacedName{Namespace: gateway.Key.Namespace, Name: dataplane.ResourceName(gateway)}
	if err := r.Get(ctx, key, &deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get dataplane Deployment %s: %w", key, err)
	}
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentAvailable && condition.Status == corev1.ConditionTrue {
			return true, nil
		}
	}
	return false, nil
}

func (r *GatewayReconciler) handleSnapshotBuildFailure(
	ctx context.Context,
	key types.NamespacedName,
	gateway *gatewayv1.Gateway,
	routes []gatewayv1.HTTPRoute,
	policies []gatewayv1.BackendTLSPolicy,
	statuses *gatewayapi.Statuses,
	buildErr error,
) error {
	statuses.Gateway.Addresses = nil
	now := metav1.Now()
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}
	meta.SetStatusCondition(&statuses.Gateway.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gateway.Generation,
		Reason:             string(gatewayv1.GatewayReasonInvalid),
		Message:            "Gateway configuration could not be compiled",
		LastTransitionTime: now,
	})
	for index := range statuses.Gateway.Listeners {
		meta.SetStatusCondition(&statuses.Gateway.Listeners[index].Conditions, metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: gateway.Generation,
			Reason:             string(gatewayv1.ListenerReasonInvalid),
			Message:            "Listener configuration could not be compiled",
			LastTransitionTime: now,
		})
	}
	if err := r.patchGatewayStatus(ctx, key, statuses.Gateway); err != nil {
		return errors.Join(buildErr, err)
	}
	if err := r.patchHTTPRouteStatuses(ctx, routes, statuses.HTTPRoutes, key); err != nil {
		return errors.Join(buildErr, err)
	}
	if err := r.patchBackendTLSPolicyStatuses(ctx, policies, statuses.BackendTLSPolicies, key); err != nil {
		return errors.Join(buildErr, err)
	}
	return buildErr
}

func (r *GatewayReconciler) setProgrammedStatus(status *gatewayv1.GatewayStatus, gateway *gatewayv1.Gateway, key, version string, acked, deploymentReady, addressReady bool, addressMessage string) bool {
	conditionStatus := metav1.ConditionTrue
	reason := string(gatewayv1.GatewayReasonProgrammed)
	message := "Gateway configuration is published, acknowledged, available, and addressable"
	pending := false

	accepted := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	switch {
	case accepted != nil && accepted.Status == metav1.ConditionFalse:
		conditionStatus = metav1.ConditionFalse
		reason = string(gatewayv1.GatewayReasonInvalid)
		message = "Gateway configuration is invalid"
	case !addressReady:
		conditionStatus = metav1.ConditionFalse
		reason = string(gatewayv1.GatewayReasonAddressNotAssigned)
		message = addressMessage
		pending = true
	case !deploymentReady:
		conditionStatus = metav1.ConditionFalse
		reason = string(gatewayv1.GatewayReasonPending)
		message = "Waiting for the dataplane Deployment to become available"
		pending = true
	case !acked:
		conditionStatus = metav1.ConditionFalse
		reason = string(gatewayv1.GatewayReasonPending)
		message = "Waiting for Envoy to acknowledge xDS snapshot " + version
		if nackVersion, detail, ok := r.Snapshots.LastNACK(key); ok && (nackVersion == "" || nackVersion == version) {
			message = "Envoy rejected xDS snapshot " + version + ": " + detail
		}
		pending = true
	}

	now := metav1.Now()
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}

	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		Status:             conditionStatus,
		ObservedGeneration: gateway.Generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
	for index := range status.Listeners {
		listener := &status.Listeners[index]
		listenerAccepted := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionAccepted))
		listenerStatus := conditionStatus
		listenerReason := reason
		listenerMessage := message
		switch {
		case listenerAccepted != nil && listenerAccepted.Status == metav1.ConditionFalse:
			listenerStatus = metav1.ConditionFalse
			listenerReason = string(gatewayv1.ListenerReasonInvalid)
			listenerMessage = "Listener configuration is invalid"
		case conditionStatus == metav1.ConditionTrue:
			listenerReason = string(gatewayv1.ListenerReasonProgrammed)
		case reason != string(gatewayv1.GatewayReasonInvalid):
			listenerReason = string(gatewayv1.ListenerReasonPending)
		}
		meta.SetStatusCondition(&listener.Conditions, metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             listenerStatus,
			ObservedGeneration: gateway.Generation,
			Reason:             listenerReason,
			Message:            listenerMessage,
			LastTransitionTime: now,
		})
	}
	return pending
}
func (r *GatewayReconciler) prepareGatewayStatus(status *gatewayv1.GatewayStatus, gateway *gatewayv1.Gateway) {
	now := metav1.Now()
	if r.Now != nil {
		now = metav1.NewTime(r.Now())
	}
	status.Conditions = prepareConditions(
		status.Conditions,
		gateway.Generation,
		now,
		map[string]struct{}{
			string(gatewayv1.GatewayConditionAccepted):   {},
			string(gatewayv1.GatewayConditionProgrammed): {},
		},
		string(gatewayv1.GatewayConditionProgrammed),
		string(gatewayv1.GatewayReasonPending),
		"Reconciling Gateway configuration",
	)
	for index := range status.Listeners {
		listener := &status.Listeners[index]
		listener.Conditions = prepareConditions(
			listener.Conditions,
			gateway.Generation,
			now,
			map[string]struct{}{
				string(gatewayv1.ListenerConditionAccepted):     {},
				string(gatewayv1.ListenerConditionResolvedRefs): {},
				string(gatewayv1.ListenerConditionConflicted):   {},
				string(gatewayv1.ListenerConditionProgrammed):   {},
			},
			string(gatewayv1.ListenerConditionProgrammed),
			string(gatewayv1.ListenerReasonPending),
			"Reconciling listener configuration",
		)
	}
}

func prepareConditions(
	conditions []metav1.Condition,
	generation int64,
	now metav1.Time,
	owned map[string]struct{},
	programmedType, pendingReason, pendingMessage string,
) []metav1.Condition {
	result := make([]metav1.Condition, len(conditions))
	copy(result, conditions)
	programmedFound := false
	for index := range result {
		condition := &result[index]
		if _, ok := owned[condition.Type]; !ok {
			continue
		}
		if condition.Type == programmedType {
			programmedFound = true
			if condition.ObservedGeneration != generation && condition.Status == metav1.ConditionTrue {
				condition.Status = metav1.ConditionUnknown
				condition.Reason = pendingReason
				condition.Message = pendingMessage
				condition.LastTransitionTime = now
			}
		}
		condition.ObservedGeneration = generation
	}
	if !programmedFound {
		result = append(result, metav1.Condition{
			Type:               programmedType,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: generation,
			Reason:             pendingReason,
			Message:            pendingMessage,
			LastTransitionTime: now,
		})
	}
	return result
}

func (r *GatewayReconciler) patchGatewayStatus(ctx context.Context, key types.NamespacedName, desired gatewayv1.GatewayStatus) error {
	deleted := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current gatewayv1.Gateway
		if err := r.Get(ctx, key, &current); err != nil {
			if apierrors.IsNotFound(err) {
				deleted = true
				return nil
			}
			return err
		}
		if reflect.DeepEqual(current.Status, desired) {
			return nil
		}
		before := current.DeepCopy()
		current.Status = desired
		if err := r.Status().Patch(ctx, &current, client.MergeFrom(before)); err != nil {
			if apierrors.IsNotFound(err) {
				deleted = true
				return nil
			}
			return fmt.Errorf("patch Gateway %s status: %w", key, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if deleted {
		observability.Default.DeleteGateway(key.String())
		return nil
	}
	condition := meta.FindStatusCondition(desired.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	observability.Default.SetGatewayProgrammed(key.String(), condition != nil && condition.Status == metav1.ConditionTrue)
	return nil
}

func (r *GatewayReconciler) patchHTTPRouteStatuses(
	ctx context.Context,
	routes []gatewayv1.HTTPRoute,
	desired map[types.NamespacedName]gatewayv1.HTTPRouteStatus,
	gatewayKey types.NamespacedName,
) error {
	for index := range routes {
		route := &routes[index]
		key := client.ObjectKeyFromObject(route)
		desiredStatus, hasDesired := desired[key]
		if !hasDesired && !hasControllerParentForGateway(route.Status.Parents, route.Namespace, gatewayKey) {
			continue
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var current gatewayv1.HTTPRoute
			if err := r.Get(ctx, key, &current); err != nil {
				return client.IgnoreNotFound(err)
			}
			parents := make([]gatewayv1.RouteParentStatus, 0, len(current.Status.Parents)+len(desiredStatus.Parents))
			for _, parent := range current.Status.Parents {
				if parent.ControllerName != gatewayapi.ControllerName || !parentRefTargetsGateway(parent.ParentRef, route.Namespace, gatewayKey) {
					parents = append(parents, parent)
				}
			}
			for _, parent := range desiredStatus.Parents {
				if parent.ControllerName == gatewayapi.ControllerName && parentRefTargetsGateway(parent.ParentRef, route.Namespace, gatewayKey) {
					parents = append(parents, parent)
				}
			}
			if reflect.DeepEqual(current.Status.Parents, parents) {
				return nil
			}
			before := current.DeepCopy()
			current.Status.Parents = parents
			if err := r.Status().Patch(ctx, &current, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return fmt.Errorf("patch HTTPRoute %s status: %w", key, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *GatewayReconciler) patchBackendTLSPolicyStatuses(
	ctx context.Context,
	policies []gatewayv1.BackendTLSPolicy,
	desired map[types.NamespacedName]gatewayv1.PolicyStatus,
	gatewayKey types.NamespacedName,
) error {
	for index := range policies {
		policy := &policies[index]
		key := client.ObjectKeyFromObject(policy)
		desiredStatus, hasDesired := desired[key]
		if !hasDesired && !hasControllerAncestorForGateway(policy.Status.Ancestors, policy.Namespace, gatewayKey) {
			continue
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var current gatewayv1.BackendTLSPolicy
			if err := r.Get(ctx, key, &current); err != nil {
				return client.IgnoreNotFound(err)
			}
			ancestors := make([]gatewayv1.PolicyAncestorStatus, 0, len(current.Status.Ancestors)+len(desiredStatus.Ancestors))
			for _, ancestor := range current.Status.Ancestors {
				if ancestor.ControllerName != gatewayapi.ControllerName || !parentRefTargetsGateway(ancestor.AncestorRef, policy.Namespace, gatewayKey) {
					ancestors = append(ancestors, ancestor)
				}
			}
			for _, ancestor := range desiredStatus.Ancestors {
				if ancestor.ControllerName == gatewayapi.ControllerName && parentRefTargetsGateway(ancestor.AncestorRef, policy.Namespace, gatewayKey) {
					ancestors = append(ancestors, ancestor)
				}
			}
			if reflect.DeepEqual(current.Status.Ancestors, ancestors) {
				return nil
			}
			before := current.DeepCopy()
			current.Status.Ancestors = ancestors
			if err := r.Status().Patch(ctx, &current, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return fmt.Errorf("patch BackendTLSPolicy %s status: %w", key, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func reconcileGatewayOwnedObject(
	ctx context.Context,
	kube client.Client,
	scheme *runtime.Scheme,
	gateway *gatewayv1.Gateway,
	desired client.Object,
) error {
	if gateway.UID == "" {
		return fmt.Errorf("gateway %s/%s has no UID", gateway.Namespace, gateway.Name)
	}
	if err := controllerutil.SetControllerReference(gateway, desired, scheme); err != nil {
		return fmt.Errorf("set Gateway owner on %T: %w", desired, err)
	}
	expectedOwner := metav1.GetControllerOf(desired)
	if expectedOwner == nil {
		return fmt.Errorf("resolve expected Gateway controller reference for %T", desired)
	}

	gvk, err := apiutil.GVKForObject(desired, scheme)
	if err != nil {
		return fmt.Errorf("resolve GVK for %T: %w", desired, err)
	}
	currentRuntime, err := scheme.New(gvk)
	if err != nil {
		return fmt.Errorf("create current %s object: %w", gvk, err)
	}
	current, ok := currentRuntime.(client.Object)
	if !ok {
		return fmt.Errorf("current %s object does not implement client.Object", gvk)
	}

	key := client.ObjectKeyFromObject(desired)
	err = kube.Get(ctx, key, current)
	if apierrors.IsNotFound(err) {
		if err := kube.Create(ctx, desired, client.FieldOwner(gatewayFieldManager)); err == nil {
			return nil
		} else if !apierrors.IsAlreadyExists(err) {
			return err
		}
		if err := kube.Get(ctx, key, current); err != nil {
			return fmt.Errorf("read %T after create collision: %w", desired, err)
		}
	} else if err != nil {
		return err
	}

	if controller := metav1.GetControllerOf(current); !sameControllerIdentity(controller, expectedOwner) {
		return fmt.Errorf(
			"%T %s/%s is not controlled by expected Gateway %s/%s UID %q",
			desired,
			key.Namespace,
			key.Name,
			gateway.Namespace,
			gateway.Name,
			gateway.UID,
		)
	}

	if currentService, ok := current.(*corev1.Service); ok {
		desiredService, desiredOK := desired.(*corev1.Service)
		if !desiredOK {
			return fmt.Errorf("desired %s object is not a Service", gvk)
		}
		changed, err := replaceGatewayServicePorts(ctx, kube, currentService, desiredService)
		if err != nil {
			return err
		}
		if changed {
			if err := kube.Get(ctx, key, current); err != nil {
				return fmt.Errorf("re-read Service %s after replacing listener ports: %w", key, err)
			}
			if controller := metav1.GetControllerOf(current); !sameControllerIdentity(controller, expectedOwner) {
				return fmt.Errorf(
					"service %s is no longer controlled by expected Gateway %s/%s UID %q",
					key,
					gateway.Namespace,
					gateway.Name,
					gateway.UID,
				)
			}
		}
	}

	resourceVersion := current.GetResourceVersion()
	if resourceVersion == "" {
		return fmt.Errorf("%T %s/%s has no resourceVersion", desired, key.Namespace, key.Name)
	}
	desired.SetResourceVersion(resourceVersion)
	return applyObject(ctx, kube, scheme, desired, client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func replaceGatewayServicePorts(
	ctx context.Context,
	kube client.Client,
	current *corev1.Service,
	desired *corev1.Service,
) (bool, error) {
	ports := append([]corev1.ServicePort(nil), desired.Spec.Ports...)
	for index := range ports {
		if ports[index].NodePort != 0 {
			continue
		}
		for _, existing := range current.Spec.Ports {
			if existing.Port == ports[index].Port && existing.Protocol == ports[index].Protocol {
				ports[index].NodePort = existing.NodePort
				break
			}
		}
	}
	if reflect.DeepEqual(current.Spec.Ports, ports) {
		return false, nil
	}
	before := current.DeepCopy()
	current.Spec.Ports = ports
	if err := kube.Patch(ctx, current, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return false, fmt.Errorf("replace Service %s listener ports: %w", client.ObjectKeyFromObject(current), err)
	}
	return true, nil
}

func sameControllerIdentity(actual, expected *metav1.OwnerReference) bool {
	return actual != nil &&
		expected != nil &&
		actual.APIVersion == expected.APIVersion &&
		actual.Kind == expected.Kind &&
		actual.Name == expected.Name &&
		actual.UID != "" &&
		expected.UID != "" &&
		actual.UID == expected.UID &&
		actual.Controller != nil &&
		*actual.Controller
}

func applyObject(ctx context.Context, kube client.Client, scheme *runtime.Scheme, object client.Object, options ...client.ApplyOption) error {
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return fmt.Errorf("convert %T for server-side apply: %w", object, err)
	}
	apply := &unstructured.Unstructured{Object: raw}
	gvk, err := apiutil.GVKForObject(object, scheme)
	if err != nil {
		return fmt.Errorf("resolve GVK for %T: %w", object, err)
	}
	apply.SetGroupVersionKind(gvk)
	return kube.Apply(ctx, client.ApplyConfigurationFromUnstructured(apply), options...)
}

// SetupWithManager registers the Gateway API and Cloudflare-mode cache watches.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.OperatorNamespace == "" {
		r.OperatorNamespace = dataplane.DefaultOperatorNamespace
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("flareway-gateway")
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, httpRouteParentGatewayIndex, func(object client.Object) []string {
		return httpRouteParentGatewayKeys(object.(*gatewayv1.HTTPRoute))
	}); err != nil {
		return fmt.Errorf("index HTTPRoute parent Gateways: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, httpRouteBackendServiceIndex, func(object client.Object) []string {
		return httpRouteBackendServiceKeys(object.(*gatewayv1.HTTPRoute))
	}); err != nil {
		return fmt.Errorf("index HTTPRoute backend Services: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, gatewayListenerSecretIndex, func(object client.Object) []string {
		return gatewayListenerSecretKeys(object.(*gatewayv1.Gateway))
	}); err != nil {
		return fmt.Errorf("index Gateway listener Secrets: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, gatewayClassNameIndex, func(object client.Object) []string {
		return []string{string(object.(*gatewayv1.Gateway).Spec.GatewayClassName)}
	}); err != nil {
		return fmt.Errorf("index Gateway GatewayClass: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GatewayClass{}, gatewayClassConfigIndex, func(object client.Object) []string {
		return gatewayClassConfigKeys(object.(*gatewayv1.GatewayClass))
	}); err != nil {
		return fmt.Errorf("index GatewayClass parametersRef: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.BackendTLSPolicy{}, backendTLSPolicyTargetServiceIndex, func(object client.Object) []string {
		return backendTLSPolicyTargetServiceKeys(object.(*gatewayv1.BackendTLSPolicy))
	}); err != nil {
		return fmt.Errorf("index BackendTLSPolicy target Services: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.BackendTLSPolicy{}, backendTLSPolicyCAConfigMapIndex, func(object client.Object) []string {
		return backendTLSPolicyCAConfigMapKeys(object.(*gatewayv1.BackendTLSPolicy))
	}); err != nil {
		return fmt.Errorf("index BackendTLSPolicy CA ConfigMaps: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessApplication{}, accessApplicationTargetGatewayIndex, func(object client.Object) []string {
		return accessApplicationTargetKeys(object.(*v1alpha1.AccessApplication), "Gateway")
	}); err != nil {
		return fmt.Errorf("index AccessApplication target Gateways: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.AccessApplication{}, accessApplicationTargetHTTPRouteIndex, func(object client.Object) []string {
		return accessApplicationTargetKeys(object.(*v1alpha1.AccessApplication), "HTTPRoute")
	}); err != nil {
		return fmt.Errorf("index AccessApplication target HTTPRoutes: %w", err)
	}

	blder := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapHTTPRouteToGateways)).
		Watches(&gatewayv1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.mapReferenceGrantToGateways)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.mapServiceToGateways)).
		Watches(&gatewayv1.BackendTLSPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapBackendTLSPolicyToGateways)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapBackendTLSConfigMapToGateways)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.mapEndpointSliceToGateways)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapNamespaceToGateways)).
		Watches(&corev1.Secret{}, r.secretEventHandler()).
		Watches(&gatewayv1.GatewayClass{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayClassToGateways)).
		Watches(&v1alpha1.GatewayClassConfig{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayClassConfigToGateways)).
		Watches(&v1alpha1.CloudflareTunnel{}, handler.EnqueueRequestsFromMapFunc(r.mapTunnelToGateways)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.mapAccountToGateways)).
		Watches(&v1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapPrivateRouteToGateways)).
		Watches(&v1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapPrivateRouteToGateways)).
		Watches(&v1alpha1.VirtualNetwork{}, handler.EnqueueRequestsFromMapFunc(r.mapVirtualNetworkToGateways)).
		Watches(&v1alpha1.DeviceSettings{}, handler.EnqueueRequestsFromMapFunc(r.mapDeviceSettingsToGateways)).
		Watches(&v1alpha1.AccessApplication{}, handler.EnqueueRequestsFromMapFunc(r.mapAccessApplicationToGateways)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToGateway)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RateLimiter: workqueue.NewTypedMaxOfRateLimiter(
				workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](500*time.Millisecond, 1000*time.Second),
				&workqueue.TypedBucketRateLimiter[reconcile.Request]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
			),
		})
	if r.SweepEvents != nil {
		// The sweep latch is the source of truth; this channel is only a fast
		// wakeup so a drifted object reconciles before its TTL expires (C10).
		// Events carry the drifted CloudflareTunnel, so they map through the
		// same tunnel→Gateway lookup as the regular Tunnel watch.
		blder = blder.WatchesRawSource(source.Channel(r.SweepEvents, handler.EnqueueRequestsFromMapFunc(r.mapTunnelToGateways)))
	}
	return blder.Complete(observedReconciler("gateway", r))
}

func (r *GatewayReconciler) mapHTTPRouteToGateways(_ context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	return requestsFromKeys(httpRouteParentGatewayKeys(route))
}

func (r *GatewayReconciler) mapNamespaceToGateways(ctx context.Context, _ client.Object) []reconcile.Request {
	var classes gatewayv1.GatewayClassList
	if err := r.List(ctx, &classes); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list GatewayClasses for Namespace change")
		return nil
	}
	managedClasses := make(map[gatewayv1.ObjectName]struct{})
	for index := range classes.Items {
		if classes.Items[index].Spec.ControllerName == gatewayapi.ControllerName {
			managedClasses[gatewayv1.ObjectName(classes.Items[index].Name)] = struct{}{}
		}
	}
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for Namespace change")
		return nil
	}
	selected := make([]gatewayv1.Gateway, 0)
	for index := range gateways.Items {
		gateway := &gateways.Items[index]
		if _, managed := managedClasses[gateway.Spec.GatewayClassName]; managed && gatewayUsesNamespaceSelector(gateway) {
			selected = append(selected, *gateway)
		}
	}
	return requestsFromGateways(selected)
}

func gatewayUsesNamespaceSelector(gateway *gatewayv1.Gateway) bool {
	for _, listener := range gateway.Spec.Listeners {
		if listener.AllowedRoutes != nil &&
			listener.AllowedRoutes.Namespaces != nil &&
			listener.AllowedRoutes.Namespaces.From != nil &&
			*listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
			return true
		}
	}
	return false
}

func (r *GatewayReconciler) mapServiceToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	return r.requestsForBackendService(ctx, client.ObjectKeyFromObject(object).String())
}

func (r *GatewayReconciler) mapEndpointSliceToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	slice, ok := object.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil
	}
	serviceName := slice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return nil
	}
	return r.requestsForBackendService(ctx, slice.Namespace+"/"+serviceName)
}

func (r *GatewayReconciler) requestsForBackendService(ctx context.Context, serviceKey string) []reconcile.Request {
	var routes gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routes, client.MatchingFields{httpRouteBackendServiceIndex: serviceKey}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list HTTPRoutes for backend Service", "service", serviceKey)
		return nil
	}
	keys := make([]string, 0)
	for index := range routes.Items {
		keys = append(keys, httpRouteParentGatewayKeys(&routes.Items[index])...)
	}
	return requestsFromKeys(keys)
}

func (r *GatewayReconciler) secretEventHandler() handler.EventHandler {
	enqueue := func(ctx context.Context, object client.Object, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		for _, request := range r.mapSecretToGateways(ctx, object) {
			queue.Add(request)
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, event event.CreateEvent, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, event.Object, queue)
		},
		UpdateFunc: func(ctx context.Context, event event.UpdateEvent, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldSecret, oldOK := event.ObjectOld.(*corev1.Secret)
			newSecret, newOK := event.ObjectNew.(*corev1.Secret)
			if oldOK && newOK && audSecretRevoked(oldSecret, newSecret) {
				if err := r.latchAUDRevocation(ctx, oldSecret); err != nil {
					ctrl.LoggerFrom(ctx).Error(err, "Unable to persist AUD revocation latch", "secret", client.ObjectKeyFromObject(oldSecret))
				}
			}
			enqueue(ctx, event.ObjectOld, queue)
			enqueue(ctx, event.ObjectNew, queue)
		},
		DeleteFunc: func(ctx context.Context, event event.DeleteEvent, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if secret, ok := event.Object.(*corev1.Secret); ok {
				if err := r.latchAUDRevocation(ctx, secret); err != nil {
					ctrl.LoggerFrom(ctx).Error(err, "Unable to persist AUD revocation latch", "secret", client.ObjectKeyFromObject(secret))
				}
			}
			enqueue(ctx, event.Object, queue)
		},
		GenericFunc: func(ctx context.Context, event event.GenericEvent, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, event.Object, queue)
		},
	}
}

func audSecretRevoked(oldSecret, newSecret *corev1.Secret) bool {
	if audRevocationKey(oldSecret) == "" {
		return false
	}
	if audRevocationKey(oldSecret) != audRevocationKey(newSecret) {
		return true
	}
	return string(oldSecret.Data["ready"]) == "true" &&
		(string(newSecret.Data["ready"]) != "true" ||
			string(oldSecret.Data[v1alpha1.AccessApplicationAUDSecretKey]) != string(newSecret.Data[v1alpha1.AccessApplicationAUDSecretKey]) ||
			string(oldSecret.Data[v1alpha1.AccessApplicationIDSecretKey]) != string(newSecret.Data[v1alpha1.AccessApplicationIDSecretKey]))
}

func audRevocationKey(secret *corev1.Secret) string {
	if secret == nil {
		return ""
	}
	application := string(secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey])
	applicationUID := string(secret.Data[v1alpha1.AccessApplicationUIDSecretKey])
	gateway := string(secret.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey])
	gatewayUID := string(secret.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey])
	applicationID := string(secret.Data[v1alpha1.AccessApplicationIDSecretKey])
	if application == "" || applicationUID == "" || gateway == "" || gatewayUID == "" || applicationID == "" {
		return ""
	}
	return gateway + "\x00" + gatewayUID + "\x00" + application + "\x00" + applicationUID
}

// latchAUDRevocation persists a revocation latch on the CloudflareTunnel bound
// to the Secret's Gateway. The latch survives process restarts so a revoked
// AUD can never be re-admitted after a controller bounce (G3).
func (r *GatewayReconciler) latchAUDRevocation(ctx context.Context, secret *corev1.Secret) error {
	gateway, application, trusted := liveAUDSecretBinding(ctx, r.Client, r.operatorNamespace(), secret)
	if !trusted {
		return nil
	}
	tunnel, err := r.gatewayTunnel(ctx, gateway)
	if err != nil {
		return err
	}
	if tunnel == nil {
		// Without a Tunnel no dataplane can admit the revoked AUD; there is
		// nothing to latch.
		return nil
	}
	applicationKey := client.ObjectKeyFromObject(application).String()
	return r.updateAUDRevocations(ctx, client.ObjectKeyFromObject(tunnel), func(current *v1alpha1.CloudflareTunnel) {
		current.Status.AUDRevocationSequence++
		token := current.Status.AUDRevocationSequence
		for index := range current.Status.AUDRevocations {
			entry := &current.Status.AUDRevocations[index]
			if entry.Application != applicationKey {
				continue
			}
			entry.ApplicationUID = application.UID
			entry.Token = token
			entry.LatchedAt = metav1.NewTime(r.gatewayNow())
			return
		}
		current.Status.AUDRevocations = append(current.Status.AUDRevocations, v1alpha1.CloudflareAUDRevocationLatch{
			Application:    applicationKey,
			ApplicationUID: application.UID,
			Token:          token,
			LatchedAt:      metav1.NewTime(r.gatewayNow()),
		})
	})
}

// gatewayTunnel resolves the CloudflareTunnel bound to gateway, returning nil
// when the referenced Tunnel does not exist.
func (r *GatewayReconciler) gatewayTunnel(ctx context.Context, gateway *gatewayv1.Gateway) (*v1alpha1.CloudflareTunnel, error) {
	name, _, supported := referencedTunnelName(gateway)
	if !supported {
		return nil, nil
	}
	if name == "" {
		name = gateway.Name
	}
	var tunnel v1alpha1.CloudflareTunnel
	if err := r.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: name}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get CloudflareTunnel for Gateway %s: %w", client.ObjectKeyFromObject(gateway), err)
	}
	return &tunnel, nil
}

// updateAUDRevocations applies mutate to the persisted AUD revocation latches
// of one CloudflareTunnel, retrying the whole read-modify-write on
// resourceVersion conflicts so a latch is never silently lost (G3).
func (r *GatewayReconciler) updateAUDRevocations(ctx context.Context, key types.NamespacedName, mutate func(*v1alpha1.CloudflareTunnel)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current v1alpha1.CloudflareTunnel
		if err := r.Get(ctx, key, &current); err != nil {
			return err
		}
		mutate(&current)
		return r.Status().Update(ctx, &current)
	})
}

func liveAUDSecretBinding(
	ctx context.Context,
	reader client.Reader,
	operatorNamespace string,
	secret *corev1.Secret,
) (*gatewayv1.Gateway, *v1alpha1.AccessApplication, bool) {
	if reader == nil || secret == nil || secret.Namespace != operatorNamespace {
		return nil, nil, false
	}
	gatewayNamespace, gatewayName, found := strings.Cut(
		string(secret.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey]), "/",
	)
	if !found || gatewayNamespace == "" || gatewayName == "" {
		return nil, nil, false
	}
	gatewayKey := types.NamespacedName{Namespace: gatewayNamespace, Name: gatewayName}
	var gateway gatewayv1.Gateway
	if err := reader.Get(ctx, gatewayKey, &gateway); err != nil {
		return nil, nil, false
	}
	applicationNamespace, applicationName, found := strings.Cut(
		string(secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey]), "/",
	)
	if !found || applicationNamespace == "" || applicationName == "" {
		return nil, nil, false
	}
	applicationKey := types.NamespacedName{Namespace: applicationNamespace, Name: applicationName}
	var application v1alpha1.AccessApplication
	if err := reader.Get(ctx, applicationKey, &application); err != nil {
		return nil, nil, false
	}
	if client.ObjectKeyFromObject(secret) != accessAUDSecretKey(operatorNamespace, &application, gatewayKey) ||
		!audSecretIdentityMatches(secret, &application, &gateway) {
		return nil, nil, false
	}
	return &gateway, &application, true
}

// applyAUDRevocationLatches enforces persisted AUD revocation latches on the
// translated inputs, then releases latches whose blocked state converged and
// prunes latches for applications no longer bound to this Gateway.
func (r *GatewayReconciler) applyAUDRevocationLatches(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	tunnel *v1alpha1.CloudflareTunnel,
	inputs *gatewayapi.Inputs,
) error {
	if gateway == nil || tunnel == nil || inputs == nil {
		return nil
	}
	// Latches recorded after this snapshot was read carry a token above the
	// ceiling and are never released or pruned by this pass.
	ceiling := tunnel.Status.AUDRevocationSequence

	latchesByApp := make(map[string]v1alpha1.CloudflareAUDRevocationLatch, len(tunnel.Status.AUDRevocations))
	for _, latch := range tunnel.Status.AUDRevocations {
		latchesByApp[latch.Application] = latch
	}

	active := make(map[string]struct{}, len(inputs.AccessApplications))
	activeUIDs := make(map[string]types.UID, len(inputs.AccessApplications))
	toRelease := make(map[string]int64)
	for index := range inputs.AccessApplications {
		application := &inputs.AccessApplications[index]
		appKey := client.ObjectKeyFromObject(application).String()
		active[appKey] = struct{}{}
		activeUIDs[appKey] = application.UID
		latch, latched := latchesByApp[appKey]
		if !latched || latch.ApplicationUID != application.UID {
			continue
		}
		if audRevocationApplied(tunnel, appKey) {
			toRelease[appKey] = latch.Token
			continue
		}
		namespacedName := types.NamespacedName{Namespace: application.Namespace, Name: application.Name}
		handoff := inputs.AUDSecrets[namespacedName]
		handoff.Ready = false
		inputs.AUDSecrets[namespacedName] = handoff
	}

	toPrune := make(map[string]int64)
	for _, latch := range tunnel.Status.AUDRevocations {
		if latch.Token > ceiling {
			continue
		}
		if _, isActive := active[latch.Application]; !isActive {
			toPrune[latch.Application] = latch.Token
			continue
		}
		// A latch bound to a previous incarnation of an active application can
		// never converge or release; prune it so latches cannot accumulate.
		if activeUIDs[latch.Application] != latch.ApplicationUID {
			toPrune[latch.Application] = latch.Token
		}
	}

	if len(toRelease) == 0 && len(toPrune) == 0 {
		return nil
	}

	// CAS on the persisted token: a latch re-created after this snapshot was
	// read carries a different token and is kept, so a concurrent revocation
	// can never be released or pruned by a stale pass.
	return r.updateAUDRevocations(ctx, client.ObjectKeyFromObject(tunnel), func(current *v1alpha1.CloudflareTunnel) {
		filtered := current.Status.AUDRevocations[:0]
		for _, entry := range current.Status.AUDRevocations {
			if token, release := toRelease[entry.Application]; release && entry.Token == token {
				continue
			}
			if token, prune := toPrune[entry.Application]; prune && entry.Token == token {
				continue
			}
			filtered = append(filtered, entry)
		}
		current.Status.AUDRevocations = filtered
	})
}

// clearAUDRevocationsForGateway removes the persisted AUD revocation latches
// of every CloudflareTunnel bound to a deleted Gateway. Tunnels bound to a
// different Gateway keep their latches.
func (r *GatewayReconciler) clearAUDRevocationsForGateway(ctx context.Context, key types.NamespacedName) error {
	var tunnels v1alpha1.CloudflareTunnelList
	if err := r.List(ctx, &tunnels, client.InNamespace(key.Namespace)); err != nil {
		return fmt.Errorf("list CloudflareTunnels for AUD revocation cleanup: %w", err)
	}
	for index := range tunnels.Items {
		tunnel := &tunnels.Items[index]
		bound := tunnel.Name == key.Name
		if tunnel.Status.GatewayRef != nil {
			bound = tunnel.Status.GatewayRef.Name == key.Name
		}
		if !bound || len(tunnel.Status.AUDRevocations) == 0 {
			continue
		}
		if err := r.updateAUDRevocations(ctx, client.ObjectKeyFromObject(tunnel), func(current *v1alpha1.CloudflareTunnel) {
			current.Status.AUDRevocations = nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func audRevocationApplied(tunnel *v1alpha1.CloudflareTunnel, application string) bool {
	if tunnel == nil || tunnel.Status.ConfigVersion.Applied <= 0 {
		return false
	}
	found := false
	for _, hostname := range tunnel.Status.Hostnames {
		if hostname.AccessApplication != application {
			continue
		}
		found = true
		if hostname.Guard != v1alpha1.HostnameGuardBlocked ||
			hostname.AppliedVersion != tunnel.Status.ConfigVersion.Applied {
			return false
		}
	}
	return found
}

func (r *GatewayReconciler) mapSecretToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	requests := make([]reconcile.Request, 0)
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways, client.MatchingFields{gatewayListenerSecretIndex: client.ObjectKeyFromObject(object).String()}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for listener Secret", "secret", client.ObjectKeyFromObject(object))
	} else {
		requests = append(requests, requestsFromGateways(gateways.Items)...)
	}
	secret, isSecret := object.(*corev1.Secret)
	if !isSecret {
		return deduplicateRequests(requests)
	}
	if gateway, _, trusted := liveAUDSecretBinding(ctx, r.Client, r.operatorNamespace(), secret); trusted {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gateway)})
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapAccessApplicationToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	application, ok := object.(*v1alpha1.AccessApplication)
	if !ok {
		return nil
	}
	requests := requestsFromKeys(accessApplicationTargetKeys(application, "Gateway"))
	for _, routeKey := range accessApplicationTargetKeys(application, "HTTPRoute") {
		namespace, name, ok := strings.Cut(routeKey, "/")
		if !ok {
			continue
		}
		var route gatewayv1.HTTPRoute
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &route); err != nil {
			if !apierrors.IsNotFound(err) {
				ctrl.LoggerFrom(ctx).Error(err, "Unable to get AccessApplication target HTTPRoute", "route", routeKey)
			}
			continue
		}
		requests = append(requests, requestsFromKeys(httpRouteParentGatewayKeys(&route))...)
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapBackendTLSPolicyToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	policy, ok := object.(*gatewayv1.BackendTLSPolicy)
	if !ok {
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for _, serviceKey := range backendTLSPolicyTargetServiceKeys(policy) {
		requests = append(requests, r.requestsForBackendService(ctx, serviceKey)...)
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapBackendTLSConfigMapToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	var policies gatewayv1.BackendTLSPolicyList
	if err := r.List(ctx, &policies, client.MatchingFields{backendTLSPolicyCAConfigMapIndex: client.ObjectKeyFromObject(object).String()}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list BackendTLSPolicies for CA ConfigMap", "configMap", client.ObjectKeyFromObject(object))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range policies.Items {
		requests = append(requests, r.mapBackendTLSPolicyToGateways(ctx, &policies.Items[index])...)
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapGatewayClassToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways, client.MatchingFields{gatewayClassNameIndex: object.GetName()}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for GatewayClass", "gatewayClass", object.GetName())
		return nil
	}
	return requestsFromGateways(gateways.Items)
}

func (r *GatewayReconciler) mapGatewayClassConfigToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	var classes gatewayv1.GatewayClassList
	if err := r.List(ctx, &classes, client.MatchingFields{gatewayClassConfigIndex: object.GetName()}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list GatewayClasses for GatewayClassConfig", "config", object.GetName())
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range classes.Items {
		requests = append(requests, r.mapGatewayClassToGateways(ctx, &classes.Items[index])...)
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapDeviceSettingsToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	settings, ok := object.(*v1alpha1.DeviceSettings)
	if !ok {
		return nil
	}
	if settings.Name != "default" || !settings.DeletionTimestamp.IsZero() ||
		effectivePrivateManagementPolicy(settings.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged ||
		settings.Status.ObservedGeneration != settings.Generation ||
		!conditionTrueForGeneration(settings.Status.Conditions, v1alpha1.DeviceSettingsConditionAccepted, settings.Generation) {
		return nil
	}
	var account v1alpha1.CloudflareAccount
	if err := r.Get(ctx, types.NamespacedName{Name: settings.Spec.AccountRef.Name}, &account); err != nil {
		return nil
	}
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: settings.Namespace}, &namespace); err != nil ||
		!authz.Evaluate(&account, &namespace, authz.Request{PlatformObject: true}).Allowed {
		return nil
	}
	var configs v1alpha1.GatewayClassConfigList
	if err := r.List(ctx, &configs); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list GatewayClassConfigs for DeviceSettings", "settings", client.ObjectKeyFromObject(settings))
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range configs.Items {
		config := &configs.Items[index]
		if config.Spec.AccountRef == nil || config.Spec.AccountRef.Name != settings.Spec.AccountRef.Name {
			continue
		}
		requests = append(requests, r.mapGatewayClassConfigToGateways(ctx, config)...)
	}
	return deduplicateRequests(requests)
}

func (r *GatewayReconciler) mapReferenceGrantToGateways(ctx context.Context, object client.Object) []reconcile.Request {
	grant, ok := object.(*gatewayv1.ReferenceGrant)
	if !ok {
		return nil
	}
	var routes gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routes); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list HTTPRoutes for ReferenceGrant", "namespace", grant.Namespace)
		return nil
	}
	keys := make([]string, 0)
	for index := range routes.Items {
		if routeReferencesNamespace(&routes.Items[index], grant.Namespace) {
			keys = append(keys, httpRouteParentGatewayKeys(&routes.Items[index])...)
		}
	}
	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for ReferenceGrant", "namespace", grant.Namespace)
		return requestsFromKeys(keys)
	}
	for index := range gateways.Items {
		for _, secret := range gatewayListenerSecretKeys(&gateways.Items[index]) {
			if strings.HasPrefix(secret, grant.Namespace+"/") {
				keys = append(keys, gateways.Items[index].Namespace+"/"+gateways.Items[index].Name)
				break
			}
		}
	}
	return requestsFromKeys(keys)
}

func httpRouteParentGatewayKeys(route *gatewayv1.HTTPRoute) []string {
	keys := make([]string, 0, len(route.Spec.ParentRefs))
	for _, ref := range route.Spec.ParentRefs {
		group := gatewayv1.GroupName
		if ref.Group != nil {
			group = string(*ref.Group)
		}
		kind := "Gateway"
		if ref.Kind != nil {
			kind = string(*ref.Kind)
		}
		if group != gatewayv1.GroupName || kind != "Gateway" {
			continue
		}
		namespace := route.Namespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}
		keys = append(keys, namespace+"/"+string(ref.Name))
	}
	return uniqueStrings(keys)
}

func accessApplicationTargetKeys(application *v1alpha1.AccessApplication, targetKind string) []string {
	keys := make([]string, 0, len(application.Spec.TargetRefs))
	for _, ref := range application.Spec.TargetRefs {
		group := string(ref.Group)
		if group == "" {
			group = gatewayv1.GroupName
		}
		kind := string(ref.Kind)
		if kind == "" {
			kind = targetKind
		}
		if group != gatewayv1.GroupName || kind != targetKind {
			continue
		}
		keys = append(keys, application.Namespace+"/"+string(ref.Name))
	}
	return uniqueStrings(keys)
}

func httpRouteBackendServiceKeys(route *gatewayv1.HTTPRoute) []string {
	keys := make([]string, 0)
	appendRef := func(ref gatewayv1.BackendObjectReference) {
		group := ""
		if ref.Group != nil {
			group = string(*ref.Group)
		}
		kind := "Service"
		if ref.Kind != nil {
			kind = string(*ref.Kind)
		}
		if group != "" || kind != "Service" {
			return
		}
		namespace := route.Namespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}
		keys = append(keys, namespace+"/"+string(ref.Name))
	}
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			appendRef(backend.BackendObjectReference)
		}
		for _, filter := range rule.Filters {
			if filter.RequestMirror != nil {
				appendRef(filter.RequestMirror.BackendRef)
			}
		}
	}
	return uniqueStrings(keys)
}

func gatewayListenerSecretKeys(gateway *gatewayv1.Gateway) []string {
	keys := make([]string, 0)
	for _, listener := range gateway.Spec.Listeners {
		if listener.TLS == nil {
			continue
		}
		for _, ref := range listener.TLS.CertificateRefs {
			group := ""
			if ref.Group != nil {
				group = string(*ref.Group)
			}
			kind := "Secret"
			if ref.Kind != nil {
				kind = string(*ref.Kind)
			}
			if group != "" || kind != "Secret" {
				continue
			}
			namespace := gateway.Namespace
			if ref.Namespace != nil {
				namespace = string(*ref.Namespace)
			}
			keys = append(keys, namespace+"/"+string(ref.Name))
		}
	}
	return uniqueStrings(keys)
}

func gatewayClassConfigKeys(gatewayClass *gatewayv1.GatewayClass) []string {
	ref := gatewayClass.Spec.ParametersRef
	if ref == nil || string(ref.Group) != v1alpha1.Group || string(ref.Kind) != "GatewayClassConfig" {
		return nil
	}
	return []string{ref.Name}
}

func backendTLSPolicyTargetServiceKeys(policy *gatewayv1.BackendTLSPolicy) []string {
	keys := make([]string, 0, len(policy.Spec.TargetRefs))
	for _, ref := range policy.Spec.TargetRefs {
		if string(ref.Group) == "" && string(ref.Kind) == "Service" {
			keys = append(keys, policy.Namespace+"/"+string(ref.Name))
		}
	}
	return uniqueStrings(keys)
}

func backendTLSPolicyCAConfigMapKeys(policy *gatewayv1.BackendTLSPolicy) []string {
	keys := make([]string, 0, len(policy.Spec.Validation.CACertificateRefs))
	for _, ref := range policy.Spec.Validation.CACertificateRefs {
		if string(ref.Group) == "" && string(ref.Kind) == "ConfigMap" {
			keys = append(keys, policy.Namespace+"/"+string(ref.Name))
		}
	}
	return uniqueStrings(keys)
}

func routeReferencesNamespace(route *gatewayv1.HTTPRoute, namespace string) bool {
	for _, key := range httpRouteBackendServiceKeys(route) {
		if strings.HasPrefix(key, namespace+"/") {
			return true
		}
	}
	return false
}

func hasControllerParentForGateway(parents []gatewayv1.RouteParentStatus, ownerNamespace string, key types.NamespacedName) bool {
	for _, parent := range parents {
		if parent.ControllerName == gatewayapi.ControllerName && parentRefTargetsGateway(parent.ParentRef, ownerNamespace, key) {
			return true
		}
	}
	return false
}

func hasControllerAncestorForGateway(ancestors []gatewayv1.PolicyAncestorStatus, ownerNamespace string, key types.NamespacedName) bool {
	for _, ancestor := range ancestors {
		if ancestor.ControllerName == gatewayapi.ControllerName && parentRefTargetsGateway(ancestor.AncestorRef, ownerNamespace, key) {
			return true
		}
	}
	return false
}

func parentRefTargetsGateway(ref gatewayv1.ParentReference, ownerNamespace string, key types.NamespacedName) bool {
	group := gatewayv1.GroupName
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := "Gateway"
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}
	namespace := ownerNamespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}
	return group == gatewayv1.GroupName && kind == "Gateway" && namespace == key.Namespace && string(ref.Name) == key.Name
}

func requestsFromGateways(gateways []gatewayv1.Gateway) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(gateways))
	for index := range gateways {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&gateways[index])})
	}
	return deduplicateRequests(requests)
}

func requestsFromKeys(keys []string) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(keys))
	for _, value := range uniqueStrings(keys) {
		namespace, name, ok := strings.Cut(value, "/")
		if ok && namespace != "" && name != "" {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
		}
	}
	return requests
}

func deduplicateRequests(requests []reconcile.Request) []reconcile.Request {
	byKey := make(map[types.NamespacedName]struct{}, len(requests))
	for _, request := range requests {
		byKey[request.NamespacedName] = struct{}{}
	}
	keys := make([]types.NamespacedName, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})
	result := make([]reconcile.Request, 0, len(keys))
	for _, key := range keys {
		result = append(result, reconcile.Request{NamespacedName: key})
	}
	return result
}

func uniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringSliceContains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func serviceAddress(service *corev1.Service) ([]gatewayv1.GatewayStatusAddress, bool, string) {
	if service.Spec.Type == corev1.ServiceTypeClusterIP {
		if service.Spec.ClusterIP == "" || service.Spec.ClusterIP == corev1.ClusterIPNone {
			return nil, false, "Waiting for the dataplane Service to receive a ClusterIP"
		}
		if _, err := netip.ParseAddr(service.Spec.ClusterIP); err != nil {
			return nil, false, "The dataplane Service has an invalid ClusterIP"
		}
		addressType := gatewayv1.IPAddressType
		return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: service.Spec.ClusterIP}}, true, ""
	}
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			if _, err := netip.ParseAddr(ingress.IP); err == nil {
				addressType := gatewayv1.IPAddressType
				return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: ingress.IP}}, true, ""
			}
		}
		if ingress.Hostname != "" {
			addressType := gatewayv1.HostnameAddressType
			return []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: ingress.Hostname}}, true, ""
		}
	}
	return nil, false, "Waiting for the dataplane LoadBalancer Service to receive an address"
}
