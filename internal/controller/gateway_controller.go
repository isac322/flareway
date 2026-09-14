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
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/internal/xds/pki"
	"github.com/isac322/flareway/internal/xds/translator"
)

const (
	gatewayFieldManager = "flareway-gateway"
	programmedRequeue   = 2 * time.Second

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

	audRevocationMu sync.Mutex
	audRevocations  map[string]struct{}
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
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var gatewayClass gatewayv1.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, &gatewayClass); err != nil {
		if apierrors.IsNotFound(err) {
			r.clearSnapshot(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if gatewayClass.Spec.ControllerName != gatewayapi.ControllerName {
		r.clearSnapshot(req.NamespacedName)
		return ctrl.Result{}, nil
	}
	if r.Snapshots == nil {
		return ctrl.Result{}, errors.New("gateway reconciler requires a snapshot publisher")
	}

	cfg, err := r.loadGatewayClassConfig(ctx, &gatewayClass)
	if err != nil {
		return ctrl.Result{}, err
	}
	tunnel, account, effectiveConfig, created, err := r.resolveCloudflareContext(ctx, &gateway, cfg)
	if err != nil {
		return ctrl.Result{}, err
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
	r.applyAUDRevocationLatches(&gateway, tunnel, &inputs)

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
		if err := controllerutil.SetControllerReference(&gateway, object, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("set Gateway owner on %T: %w", object, err)
		}
		if err := applyObject(ctx, r.Client, r.Scheme, object, client.FieldOwner(gatewayFieldManager), client.ForceOwnership); err != nil {
			return ctrl.Result{}, fmt.Errorf("apply %T %s/%s: %w", object, object.GetNamespace(), object.GetName(), err)
		}
	}

	var cloudflareResult cloudflareConfigResult
	if !compiled.ConformanceMode {
		if tunnel == nil || account == nil || compiled.Cloudflare == nil {
			r.setCloudflareProgrammedStatus(&statuses.Gateway, &gateway, false, "CloudflareTunnel and CloudflareAccount are required")
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
		cloudflareResult, err = r.reconcileCloudflaredConfiguration(ctx, compiled, tunnel, account)
		if err != nil {
			return ctrl.Result{}, err
		}
		if cloudflareResult.drift && r.Recorder != nil {
			r.Recorder.Eventf(&gateway, nil, corev1.EventTypeWarning, "OutOfBandChange", "ReconcileGateway", "%s", cloudflareResult.message)
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
		reason := "Pending"
		message := cloudflareResult.pending
		if cloudflareResult.drift {
			reason = "OutOfBandChange"
			message = cloudflareResult.message
		} else if message == "" {
			message = fmt.Sprintf("Waiting for cloudflared configuration version %d", config.Desired)
		}
		if err := r.patchTunnelGatewayStatus(
			ctx,
			tunnel,
			config,
			tunnel.Status.Hostnames,
			desiredTunnelListeners(compiled),
			gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, reason, message, now),
			privateListenerCondition(compiled, privateState, now),
		); err != nil {
			return ctrl.Result{}, err
		}
		observability.Default.SetConfigVersions(req.String(), config.Desired, config.Applied)
		if cloudflareResult.pending != "" || cloudflareResult.drift {
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
		config.Desired = cloudflareResult.version
		config.DesiredHash = cloudflareResult.hash
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
		if err := r.patchTunnelGatewayStatus(
			ctx, tunnel, config, hostnames, desiredTunnelListeners(compiled),
			gatewayTunnelCondition(tunnel, v1alpha1.CloudflareTunnelConditionConfigApplied, conditionStatus, reason, message, now),
			privateListenerCondition(compiled, privateState, now),
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
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) loadGatewayClassConfig(ctx context.Context, gatewayClass *gatewayv1.GatewayClass) (*v1alpha1.GatewayClassConfig, error) {
	ref := gatewayClass.Spec.ParametersRef
	if ref == nil {
		return defaultGatewayClassConfig(), nil
	}
	if string(ref.Group) != v1alpha1.Group || string(ref.Kind) != "GatewayClassConfig" {
		return nil, fmt.Errorf("GatewayClass %q has unsupported parametersRef %s/%s", gatewayClass.Name, ref.Group, ref.Kind)
	}

	var cfg v1alpha1.GatewayClassConfig
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &cfg); err != nil {
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

	operatorNamespace := r.OperatorNamespace
	if operatorNamespace == "" {
		operatorNamespace = dataplane.DefaultOperatorNamespace
	}
	var secrets corev1.SecretList
	gatewayLabel := gateway.Namespace + "--" + gateway.Name
	if err := r.List(ctx, &secrets,
		client.InNamespace(operatorNamespace),
		client.MatchingLabels{v1alpha1.AccessApplicationGatewayAUDLabel: gatewayLabel},
	); err != nil {
		return nil, nil, fmt.Errorf("list AccessApplication AUD Secrets: %w", err)
	}
	audSecrets := make(map[types.NamespacedName]gatewayapi.AUDSecret)
	for index := range secrets.Items {
		secret := &secrets.Items[index]
		applicationLabel := secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]
		for appIndex := range applications.Items {
			application := &applications.Items[appIndex]
			key := types.NamespacedName{Namespace: application.Namespace, Name: application.Name}
			if applicationLabel != application.Namespace+"--"+application.Name {
				continue
			}
			audSecrets[key] = gatewayapi.AUDSecret{
				AUD:           string(secret.Data[v1alpha1.AccessApplicationAUDSecretKey]),
				ApplicationID: string(secret.Data[v1alpha1.AccessApplicationIDSecretKey]),
				Ready:         string(secret.Data["ready"]) == "true",
			}
			break
		}
	}
	return applications.Items, audSecrets, nil
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
	secret, err := pki.EnsureClientCert(ctx, r.Client, client.ObjectKeyFromObject(gateway))
	if err != nil {
		return fmt.Errorf("ensure xDS client certificate: %w", err)
	}
	before := secret.DeepCopy()
	if err := controllerutil.SetControllerReference(gateway, secret, r.Scheme); err != nil {
		return fmt.Errorf("set Gateway owner on xDS client certificate Secret: %w", err)
	}
	if len(before.OwnerReferences) == len(secret.OwnerReferences) {
		return nil
	}
	if err := r.Patch(ctx, secret, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("patch xDS client certificate Secret owner: %w", err)
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
			if err := r.Status().Patch(ctx, &current, client.MergeFrom(before)); err != nil {
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
			if err := r.Status().Patch(ctx, &current, client.MergeFrom(before)); err != nil {
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
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
		}).
		Complete(observedReconciler("gateway", r))
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
				r.latchAUDRevocation(oldSecret)
			}
			enqueue(ctx, event.ObjectOld, queue)
			enqueue(ctx, event.ObjectNew, queue)
		},
		DeleteFunc: func(ctx context.Context, event event.DeleteEvent, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if secret, ok := event.Object.(*corev1.Secret); ok {
				r.latchAUDRevocation(secret)
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
	gateway := secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel]
	application := secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]
	if gateway == "" || application == "" {
		return ""
	}
	return gateway + "\x00" + application
}

func (r *GatewayReconciler) latchAUDRevocation(secret *corev1.Secret) {
	key := audRevocationKey(secret)
	if key == "" {
		return
	}
	r.audRevocationMu.Lock()
	defer r.audRevocationMu.Unlock()
	if r.audRevocations == nil {
		r.audRevocations = make(map[string]struct{})
	}
	r.audRevocations[key] = struct{}{}
}

func (r *GatewayReconciler) applyAUDRevocationLatches(gateway *gatewayv1.Gateway, tunnel *v1alpha1.CloudflareTunnel, inputs *gatewayapi.Inputs) {
	if gateway == nil || inputs == nil {
		return
	}
	gatewayLabel := gateway.Namespace + "--" + gateway.Name
	for index := range inputs.AccessApplications {
		application := &inputs.AccessApplications[index]
		key := gatewayLabel + "\x00" + application.Namespace + "--" + application.Name
		r.audRevocationMu.Lock()
		_, latched := r.audRevocations[key]
		r.audRevocationMu.Unlock()
		if !latched {
			continue
		}
		applicationKey := application.Namespace + "/" + application.Name
		if audRevocationApplied(tunnel, applicationKey) {
			r.audRevocationMu.Lock()
			delete(r.audRevocations, key)
			r.audRevocationMu.Unlock()
			continue
		}
		namespacedName := types.NamespacedName{Namespace: application.Namespace, Name: application.Name}
		handoff := inputs.AUDSecrets[namespacedName]
		handoff.Ready = false
		inputs.AUDSecrets[namespacedName] = handoff
	}
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
	if gatewayLabel := object.GetLabels()[v1alpha1.AccessApplicationGatewayAUDLabel]; gatewayLabel != "" {
		var all gatewayv1.GatewayList
		if err := r.List(ctx, &all); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Unable to list Gateways for AUD Secret")
		} else {
			for index := range all.Items {
				gateway := &all.Items[index]
				if gateway.Namespace+"--"+gateway.Name == gatewayLabel {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gateway)})
				}
			}
		}
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
