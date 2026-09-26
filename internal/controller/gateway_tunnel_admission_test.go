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
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
)

// tunnelAdmissionFixture is a Cloudflare-mode Gateway whose tunnel cannot be
// programmed yet. Each test adjusts the tunnel and grants to one scenario.
type tunnelAdmissionFixture struct {
	namespace *corev1.Namespace
	account   *v1alpha1.CloudflareAccount
	config    *v1alpha1.GatewayClassConfig
	class     *gatewayv1.GatewayClass
	gateway   *gatewayv1.Gateway
	tunnel    *v1alpha1.CloudflareTunnel
	route     *gatewayv1.HTTPRoute
	extra     []client.Object
}

func newTunnelAdmissionFixture(granted bool) *tunnelAdmissionFixture {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", Labels: map[string]string{"tenant": "demo"}}}
	grantedTenant := "other"
	if granted {
		grantedTenant = "demo"
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": grantedTenant}},
			Hostnames:         []string{"*"},
			Zones:             []string{"*"},
			Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		}}},
	}
	config := defaultGatewayClassConfig()
	config.Name = "config"
	config.Spec.AccountRef = &corev1.LocalObjectReference{Name: account.Name}
	class := gatewayClass("class", config.Name)
	gatewayKey := types.NamespacedName{Namespace: namespace.Name, Name: "gw"}
	gateway := httpGateway(gatewayKey, class.Name)
	gateway.UID = "gw-uid"
	gateway.Generation = 2
	hostname := gatewayv1.Hostname("app.example.com")
	gateway.Spec.Listeners[0].Hostname = &hostname
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: gateway.Name, Namespace: namespace.Name, UID: "tunnel-uid", Generation: 1},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			GatewayRef: &corev1.LocalObjectReference{Name: gateway.Name},
			GatewayUID: gateway.UID,
		},
	}
	route := httpRoute(types.NamespacedName{Namespace: namespace.Name, Name: "route"}, gatewayKey, "backend")
	return &tunnelAdmissionFixture{
		namespace: namespace, account: account, config: config, class: class,
		gateway: gateway, tunnel: tunnel, route: route,
	}
}

func (f *tunnelAdmissionFixture) referenceTunnelExplicitly() {
	f.gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
		Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: f.tunnel.Name,
	}}
}

func (f *tunnelAdmissionFixture) rejectTunnel(reason, message string) {
	f.tunnel.Status.Conditions = []metav1.Condition{{
		Type: v1alpha1.CloudflareTunnelConditionAccepted, Status: metav1.ConditionFalse,
		Reason: reason, Message: message, ObservedGeneration: f.tunnel.Generation,
		LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	}}
}

type tunnelAdmissionRun struct {
	kube      client.Client
	snapshots *fakeSnapshotPublisher
	result    ctrl.Result
	err       error
}

func (f *tunnelAdmissionFixture) reconcile(t *testing.T, withTunnel bool) tunnelAdmissionRun {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{f.namespace, f.account, f.config, f.class, f.gateway, f.route}
	if withTunnel {
		objects = append(objects, f.tunnel)
	}
	objects = append(objects, f.extra...)
	kube := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.HTTPRoute{}, &v1alpha1.CloudflareTunnel{}).
		WithObjects(objects...).
		Build()
	snapshots := newFakeSnapshotPublisher()
	snapshots.versions[client.ObjectKeyFromObject(f.gateway).String()] = "stale"
	reconciler := &GatewayReconciler{Client: kube, Scheme: scheme, Snapshots: snapshots}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.gateway)})
	return tunnelAdmissionRun{kube: kube, snapshots: snapshots, result: result, err: err}
}

func (run tunnelAdmissionRun) gateway(t *testing.T, f *tunnelAdmissionFixture) gatewayv1.Gateway {
	t.Helper()
	if run.err != nil {
		t.Fatalf("reconcile error: %v", run.err)
	}
	var observed gatewayv1.Gateway
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed); err != nil {
		t.Fatal(err)
	}
	return observed
}

func requireCondition(t *testing.T, conditions []metav1.Condition, conditionType string, generation int64) metav1.Condition {
	t.Helper()
	condition := meta.FindStatusCondition(conditions, conditionType)
	if condition == nil {
		t.Fatalf("condition %s is missing from %#v", conditionType, conditions)
	}
	if condition.ObservedGeneration != generation {
		t.Fatalf("condition %s observedGeneration = %d, want %d", conditionType, condition.ObservedGeneration, generation)
	}
	return *condition
}

func requireRouteParent(t *testing.T, run tunnelAdmissionRun, f *tunnelAdmissionFixture) gatewayv1.RouteParentStatus {
	t.Helper()
	var route gatewayv1.HTTPRoute
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(f.route), &route); err != nil {
		t.Fatal(err)
	}
	for _, parent := range route.Status.Parents {
		if parent.ControllerName == gatewayapi.ControllerName && string(parent.ParentRef.Name) == f.gateway.Name {
			return parent
		}
	}
	t.Fatalf("HTTPRoute has no status.parents entry for Gateway %s: %#v", f.gateway.Name, route.Status.Parents)
	return gatewayv1.RouteParentStatus{}
}

func requireTunnelStatusUnchanged(t *testing.T, run tunnelAdmissionRun, f *tunnelAdmissionFixture) {
	t.Helper()
	var observed v1alpha1.CloudflareTunnel
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(f.tunnel), &observed); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(observed.Status, f.tunnel.Status) {
		t.Fatalf("Gateway reconcile wrote the unprogrammable tunnel's status:\n got %#v\nwant %#v", observed.Status, f.tunnel.Status)
	}
}

// A Gateway whose explicit tunnel is denied by tenant authorization still gets
// a deterministic admission verdict: the listener grant check rejects it with
// the denial message, the attached route learns its parent is not accepted,
// and Programmed carries the tunnel's own reason instead of a pending
// ownership message. This is the state v0.3.0 left behind (only Programmed).
func TestGatewayReportsAdmissionForAuthorizationDeniedTunnel(t *testing.T) {
	f := newTunnelAdmissionFixture(false)
	f.tunnel.Name = "denied"
	f.referenceTunnelExplicitly()
	denial := `namespace "demo" is not granted by CloudflareAccount "account"`
	f.rejectTunnel("RefNotPermitted", denial)
	f.gateway.Status = gatewayv1.GatewayStatus{Conditions: []metav1.Condition{{
		Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionFalse,
		Reason: string(gatewayv1.GatewayReasonPending), Message: "CloudflareTunnel demo/denied has not verified remote ownership",
		ObservedGeneration: f.gateway.Generation, LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	}}}
	replicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flareway-gw-" + f.gateway.Name, Namespace: f.gateway.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(f.gateway, gatewayControllerGVK())},
		},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas},
	}
	f.extra = append(f.extra, deployment)

	run := f.reconcile(t, true)
	observed := run.gateway(t, f)

	if run.result != (ctrl.Result{}) {
		t.Fatalf("terminal tunnel denial result = %#v, want no requeue", run.result)
	}
	if run.snapshots.Version(client.ObjectKeyFromObject(f.gateway).String()) != "" {
		t.Fatal("denied tunnel kept the published xDS snapshot")
	}
	accepted := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), f.gateway.Generation)
	if accepted.Status != metav1.ConditionFalse || accepted.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
		t.Fatalf("Accepted = %#v, want False/ListenersNotValid", accepted)
	}
	if len(observed.Status.Listeners) != 1 {
		t.Fatalf("status.listeners = %#v, want one entry", observed.Status.Listeners)
	}
	listenerAccepted := requireCondition(t, observed.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionAccepted), f.gateway.Generation)
	if listenerAccepted.Status != metav1.ConditionFalse || !strings.Contains(listenerAccepted.Message, denial) {
		t.Fatalf("listener Accepted = %#v, want False carrying %q", listenerAccepted, denial)
	}
	programmed := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), f.gateway.Generation)
	if programmed.Status != metav1.ConditionFalse || !strings.Contains(programmed.Message, "RefNotPermitted") ||
		!strings.Contains(programmed.Message, denial) {
		t.Fatalf("Programmed = %#v, want False carrying the tunnel denial", programmed)
	}
	if len(observed.Status.Addresses) != 0 {
		t.Fatalf("denied tunnel kept Gateway addresses: %#v", observed.Status.Addresses)
	}
	parent := requireRouteParent(t, run, f)
	if routeAccepted := meta.FindStatusCondition(parent.Conditions, string(gatewayv1.RouteConditionAccepted)); routeAccepted == nil ||
		routeAccepted.Status != metav1.ConditionFalse {
		t.Fatalf("route parent Accepted = %#v, want False", routeAccepted)
	}
	var scaled appsv1.Deployment
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &scaled); err != nil {
		t.Fatal(err)
	}
	if scaled.Spec.Replicas == nil || *scaled.Spec.Replicas != 0 {
		t.Fatalf("denied tunnel dataplane replicas = %v, want 0", scaled.Spec.Replicas)
	}
	requireTunnelStatusUnchanged(t, run, f)
}

// An auto-created tunnel rejected for its spec leaves the Gateway itself
// valid: the Gateway and route are Accepted, and Programmed explains which
// tunnel verdict blocks programming.
func TestGatewayReportsAdmissionForSpecInvalidDefaultTunnel(t *testing.T) {
	f := newTunnelAdmissionFixture(true)
	f.tunnel.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(f.gateway, gatewayControllerGVK())}
	invalid := "zone not found for hostname app.example.com"
	f.rejectTunnel("Invalid", invalid)

	run := f.reconcile(t, true)
	observed := run.gateway(t, f)

	if run.result != (ctrl.Result{}) {
		t.Fatalf("terminal tunnel rejection result = %#v, want no requeue", run.result)
	}
	accepted := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), f.gateway.Generation)
	if accepted.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted = %#v, want True", accepted)
	}
	if len(observed.Status.Listeners) != 1 {
		t.Fatalf("status.listeners = %#v, want one entry", observed.Status.Listeners)
	}
	listenerProgrammed := requireCondition(t, observed.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed), f.gateway.Generation)
	if listenerProgrammed.Status != metav1.ConditionFalse || listenerProgrammed.Reason != string(gatewayv1.ListenerReasonPending) {
		t.Fatalf("listener Programmed = %#v, want False/Pending", listenerProgrammed)
	}
	programmed := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), f.gateway.Generation)
	if programmed.Status != metav1.ConditionFalse || !strings.Contains(programmed.Message, "Invalid") ||
		!strings.Contains(programmed.Message, invalid) {
		t.Fatalf("Programmed = %#v, want False carrying the tunnel rejection", programmed)
	}
	parent := requireRouteParent(t, run, f)
	if routeAccepted := meta.FindStatusCondition(parent.Conditions, string(gatewayv1.RouteConditionAccepted)); routeAccepted == nil ||
		routeAccepted.Status != metav1.ConditionTrue {
		t.Fatalf("route parent Accepted = %#v, want True", routeAccepted)
	}
	requireTunnelStatusUnchanged(t, run, f)
}

// A tunnel owned by another live Gateway must not be written on behalf of the
// non-owner: no AUD latch release/prune, no generated HostnameRoute rebinding,
// no dataplane objects, no snapshot. Admission is still reported and the
// reconcile keeps polling because ownership can change without a spec edit.
func TestGatewayReportsAdmissionWithoutWritingForeignTunnel(t *testing.T) {
	f := newTunnelAdmissionFixture(true)
	f.tunnel.Name = "shared"
	f.referenceTunnelExplicitly()
	owner := httpGateway(types.NamespacedName{Namespace: f.gateway.Namespace, Name: "owner"}, f.class.Name)
	owner.UID = "owner-uid"
	owner.CreationTimestamp = metav1.NewTime(time.Unix(50, 0))
	owner.Spec.Infrastructure = f.gateway.Spec.Infrastructure.DeepCopy()
	f.gateway.CreationTimestamp = metav1.NewTime(time.Unix(60, 0))
	f.tunnel.Status = v1alpha1.CloudflareTunnelStatus{
		TunnelID:                "remote-id",
		OwnershipVerified:       true,
		ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "connector-token"},
		GatewayRef:              &corev1.LocalObjectReference{Name: owner.Name},
		GatewayUID:              owner.UID,
		AUDRevocationSequence:   3,
		AUDRevocations: []v1alpha1.CloudflareAUDRevocationLatch{{
			Application: "demo/removed", ApplicationUID: "removed-uid", Token: 2,
			LatchedAt: metav1.NewTime(time.Unix(100, 0)),
		}},
	}
	generated := &v1alpha1.HostnameRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dataplane.DefaultOperatorNamespace,
			Name:      privateHostnameRouteName(f.tunnel.Namespace, f.tunnel.Name, "private"),
			Labels: map[string]string{
				generatedPlatformObjectLabel:  "true",
				generatedSourceNamespaceLabel: f.tunnel.Namespace,
				generatedGatewayLabel:         f.tunnel.Namespace + "--" + f.tunnel.Name,
			},
			Annotations: map[string]string{sourceGatewayUIDAnnotation: string(owner.UID)},
		},
		Spec: v1alpha1.HostnameRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: f.account.Name},
			TunnelRef: v1alpha1.TunnelReference{
				Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: f.tunnel.Name, Namespace: f.tunnel.Namespace,
			},
		},
	}
	f.extra = append(f.extra, owner, generated)

	run := f.reconcile(t, true)
	observed := run.gateway(t, f)

	if run.result != (ctrl.Result{RequeueAfter: programmedRequeue}) {
		t.Fatalf("foreign-owned tunnel result = %#v, want programmedRequeue", run.result)
	}
	if run.snapshots.Version(client.ObjectKeyFromObject(f.gateway).String()) != "" {
		t.Fatal("non-owner Gateway kept the published xDS snapshot")
	}
	accepted := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), f.gateway.Generation)
	if accepted.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted = %#v, want True", accepted)
	}
	programmed := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), f.gateway.Generation)
	if programmed.Status != metav1.ConditionFalse || !strings.Contains(programmed.Message, "owned by Gateway") {
		t.Fatalf("Programmed = %#v, want False naming the owner", programmed)
	}
	requireRouteParent(t, run, f)
	requireTunnelStatusUnchanged(t, run, f)

	var observedRoute v1alpha1.HostnameRoute
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(generated), &observedRoute); err != nil {
		t.Fatalf("non-owner Gateway deleted the owner's generated HostnameRoute: %v", err)
	}
	if observedRoute.Annotations[sourceGatewayUIDAnnotation] != string(owner.UID) {
		t.Fatalf("non-owner Gateway rebound the owner's generated HostnameRoute: %#v", observedRoute.Annotations)
	}
	var deployments appsv1.DeploymentList
	if err := run.kube.List(context.Background(), &deployments, client.InNamespace(f.gateway.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(deployments.Items) != 0 {
		t.Fatalf("non-owner Gateway created dataplane Deployments: %#v", deployments.Items)
	}
}

// The first reconcile of a Gateway without parametersRef creates its default
// tunnel and reports admission in the same pass instead of leaving the
// Gateway with no status until a later reconcile.
func TestGatewayReportsAdmissionWhenCreatingDefaultTunnel(t *testing.T) {
	f := newTunnelAdmissionFixture(true)

	run := f.reconcile(t, false)
	observed := run.gateway(t, f)

	if run.result != (ctrl.Result{RequeueAfter: programmedRequeue}) {
		t.Fatalf("default tunnel creation result = %#v, want programmedRequeue", run.result)
	}
	var created v1alpha1.CloudflareTunnel
	if err := run.kube.Get(context.Background(), client.ObjectKeyFromObject(f.tunnel), &created); err != nil {
		t.Fatalf("default tunnel was not created: %v", err)
	}
	if owner := metav1.GetControllerOf(&created); owner == nil || owner.UID != f.gateway.UID {
		t.Fatalf("default tunnel controller owner = %#v, want Gateway UID %s", owner, f.gateway.UID)
	}
	accepted := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), f.gateway.Generation)
	if accepted.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted = %#v, want True", accepted)
	}
	if len(observed.Status.Listeners) != 1 {
		t.Fatalf("status.listeners = %#v, want one entry", observed.Status.Listeners)
	}
	programmed := requireCondition(t, observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), f.gateway.Generation)
	if programmed.Status != metav1.ConditionFalse {
		t.Fatalf("Programmed = %#v, want False", programmed)
	}
	requireRouteParent(t, run, f)
}
