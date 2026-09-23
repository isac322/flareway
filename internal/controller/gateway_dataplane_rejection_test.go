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
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/observability"
)

// These specs drive the real Gateway Reconcile against a stateful fake API
// seeded with a healthy, same-generation Programmed=True Gateway, and inject
// typed API failures at the owned-object boundary. They pin the observable
// contract of docs/qa-gateway-dataplane-rejection.md (Q4-Q9, Q11): which
// failures demote Programmed, which Events are emitted, what the caller can
// still discover from the returned error, and what is left untouched.

const rejectionUnitGatewayUID = types.UID("rejection-unit-gateway-uid")

var errRejectionUnitStatusWrite = errors.New("injected Gateway status write failure")

// ownedMutationFaultClient intercepts client calls so a spec can fail one
// boundary operation with a typed API error while every other call reaches the
// backing fake API.
type ownedMutationFaultClient struct {
	client.Client
	get         func(key types.NamespacedName, object client.Object) error
	create      func(object client.Object) error
	apply       func(object client.Object) error
	patch       func(object client.Object) error
	statusPatch func(object client.Object) error
}

func (c *ownedMutationFaultClient) Get(ctx context.Context, key types.NamespacedName, object client.Object, options ...client.GetOption) error {
	if c.get != nil {
		if err := c.get(key, object); err != nil {
			return err
		}
	}
	return c.Client.Get(ctx, key, object, options...)
}

func (c *ownedMutationFaultClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	if c.create != nil {
		if err := c.create(object); err != nil {
			return err
		}
	}
	return c.Client.Create(ctx, object, options...)
}

func (c *ownedMutationFaultClient) Apply(ctx context.Context, config runtime.ApplyConfiguration, options ...client.ApplyOption) error {
	if c.apply != nil {
		object, ok := config.(client.Object)
		gomega.Expect(ok).To(gomega.BeTrue(), "apply configuration %T does not expose object identity", config)
		if err := c.apply(object); err != nil {
			return err
		}
	}
	return c.Client.Apply(ctx, config, options...)
}

func (c *ownedMutationFaultClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if c.patch != nil {
		if err := c.patch(object); err != nil {
			return err
		}
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

func (c *ownedMutationFaultClient) Status() client.SubResourceWriter {
	return &ownedMutationStatusWriter{SubResourceWriter: c.Client.Status(), client: c}
}

type ownedMutationStatusWriter struct {
	client.SubResourceWriter
	client *ownedMutationFaultClient
}

func (w *ownedMutationStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	if w.client.statusPatch != nil {
		if err := w.client.statusPatch(object); err != nil {
			return err
		}
	}
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
}

type capturedGatewayEvent struct {
	regarding runtime.Object
	eventType string
	reason    string
	note      string
}

// capturingEventRecorder keeps the regarding object so specs can prove which
// object an Event is attached to, which a string-only fake recorder cannot.
type capturingEventRecorder struct {
	mu     sync.Mutex
	events []capturedGatewayEvent
}

var _ recorder.EventRecorder = (*capturingEventRecorder)(nil)

func (r *capturingEventRecorder) Eventf(regarding runtime.Object, _ runtime.Object, eventType, reason, _, note string, args ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, capturedGatewayEvent{
		regarding: regarding,
		eventType: eventType,
		reason:    reason,
		note:      fmt.Sprintf(note, args...),
	})
}

func (r *capturingEventRecorder) AnnotatedEventf(regarding runtime.Object, related runtime.Object, _ map[string]string, eventType, reason, action, note string, args ...interface{}) {
	r.Eventf(regarding, related, eventType, reason, action, note, args...)
}

func (r *capturingEventRecorder) recorded() []capturedGatewayEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]capturedGatewayEvent(nil), r.events...)
}

func (r *capturingEventRecorder) rejections() []capturedGatewayEvent {
	var rejections []capturedGatewayEvent
	for _, event := range r.recorded() {
		if event.reason == observability.EventReasonDataplaneApplyRejected {
			rejections = append(rejections, event)
		}
	}
	return rejections
}

type rejectionUnitFixture struct {
	backing     client.Client
	fault       *ownedMutationFaultClient
	events      *capturingEventRecorder
	reconciler  *GatewayReconciler
	gatewayKey  types.NamespacedName
	dataplane   types.NamespacedName
	generation  int64
	seededAt    time.Time
	seededRV    string
	seededPorts []corev1.ServicePort
}

// newRejectionUnitFixture seeds a Programmed=True Gateway (and listener) whose
// conditions match its current generation, plus a healthy owned Deployment and
// Service. mutate may adjust the seeded owned objects before the fake API is
// built.
func newRejectionUnitFixture(mutate func(deployment *appsv1.Deployment, service *corev1.Service)) *rejectionUnitFixture {
	scheme := runtime.NewScheme()
	gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
	gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
	gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

	const namespace = "tenant"
	gatewayKey := types.NamespacedName{Namespace: namespace, Name: "gateway"}
	dataplaneKey := types.NamespacedName{
		Namespace: namespace,
		Name:      dataplane.ResourceName(&ir.Gateway{Key: gatewayKey}),
	}
	seededAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	generation := int64(3)

	config := conformanceConfig("rejection-unit-config", corev1.ServiceTypeClusterIP)
	class := gatewayClass("rejection-unit-class", config.Name)
	gateway := httpGateway(gatewayKey, class.Name)
	gateway.UID = rejectionUnitGatewayUID
	gateway.Generation = generation
	gateway.Status = gatewayv1.GatewayStatus{
		Conditions: []metav1.Condition{
			{
				Type: string(gatewayv1.GatewayConditionAccepted), Status: metav1.ConditionTrue,
				Reason: string(gatewayv1.GatewayReasonAccepted), Message: "Gateway accepted",
				ObservedGeneration: generation, LastTransitionTime: metav1.NewTime(seededAt),
			},
			{
				Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue,
				Reason: string(gatewayv1.GatewayReasonProgrammed), Message: "Gateway configuration is published, acknowledged, available, and addressable",
				ObservedGeneration: generation, LastTransitionTime: metav1.NewTime(seededAt),
			},
		},
		Listeners: []gatewayv1.ListenerStatus{{
			Name:           "http",
			SupportedKinds: []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}},
			Conditions: []metav1.Condition{
				{
					Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted), Message: "Listener accepted",
					ObservedGeneration: generation, LastTransitionTime: metav1.NewTime(seededAt),
				},
				{
					Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonProgrammed), Message: "Listener programmed",
					ObservedGeneration: generation, LastTransitionTime: metav1.NewTime(seededAt),
				},
			},
		}},
	}

	owner := *metav1.NewControllerRef(gateway, gatewayControllerGVK())
	replicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dataplaneKey.Namespace, Name: dataplaneKey.Name,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dataplane"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "dataplane"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
			},
		},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			Replicas:           2,
			AvailableReplicas:  2,
			Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue,
			}},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dataplaneKey.Namespace, Name: dataplaneKey.Name,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{"app": "dataplane"},
		},
	}
	if mutate != nil {
		mutate(deployment, service)
	}

	backing := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithReturnManagedFields().
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithObjects(config, class, gateway, deployment, service).
		Build()
	fault := &ownedMutationFaultClient{Client: backing}
	events := &capturingEventRecorder{}
	var tick atomic.Int64
	reconciler := &GatewayReconciler{
		Client:            fault,
		Scheme:            scheme,
		Snapshots:         newFakeSnapshotPublisher(),
		BuildSnapshot:     controlledSnapshotBuild,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Recorder:          events,
		// A strictly advancing clock makes any rewritten transition time
		// observable.
		Now: func() time.Time { return seededAt.Add(time.Duration(tick.Add(1)) * time.Minute) },
	}

	var seededDeployment appsv1.Deployment
	gomega.Expect(backing.Get(context.Background(), dataplaneKey, &seededDeployment)).To(gomega.Succeed())
	var seededService corev1.Service
	gomega.Expect(backing.Get(context.Background(), dataplaneKey, &seededService)).To(gomega.Succeed())

	return &rejectionUnitFixture{
		backing:     backing,
		fault:       fault,
		events:      events,
		reconciler:  reconciler,
		gatewayKey:  gatewayKey,
		dataplane:   dataplaneKey,
		generation:  generation,
		seededAt:    seededAt,
		seededRV:    seededDeployment.ResourceVersion,
		seededPorts: seededService.Spec.Ports,
	}
}

func (f *rejectionUnitFixture) reconcile() error {
	_, err := f.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.gatewayKey})
	return err
}

func (f *rejectionUnitFixture) gateway() *gatewayv1.Gateway {
	var gateway gatewayv1.Gateway
	gomega.ExpectWithOffset(1, f.backing.Get(context.Background(), f.gatewayKey, &gateway)).To(gomega.Succeed())
	return &gateway
}

// programmedConditions returns the Gateway Programmed condition followed by
// every listener Programmed condition.
func (f *rejectionUnitFixture) programmedConditions() []metav1.Condition {
	gateway := f.gateway()
	gomega.ExpectWithOffset(1, gateway.Generation).To(gomega.Equal(f.generation), "status handling must never change the Gateway generation")
	conditions := make([]metav1.Condition, 0, 1+len(gateway.Status.Listeners))
	condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil())
	conditions = append(conditions, *condition)
	gomega.ExpectWithOffset(1, gateway.Status.Listeners).NotTo(gomega.BeEmpty())
	for _, listener := range gateway.Status.Listeners {
		condition := findCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed))
		gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil(), "listener %s has no Programmed condition", listener.Name)
		conditions = append(conditions, *condition)
	}
	return conditions
}

// expectStillProgrammed proves the prior healthy verdict survived untouched,
// including its transition time.
func (f *rejectionUnitFixture) expectStillProgrammed() {
	for _, condition := range f.programmedConditions() {
		gomega.ExpectWithOffset(1, condition.Status).To(gomega.Equal(metav1.ConditionTrue), "condition %#v", condition)
		gomega.ExpectWithOffset(1, condition.ObservedGeneration).To(gomega.Equal(f.generation))
		gomega.ExpectWithOffset(1, condition.LastTransitionTime.Time).To(gomega.BeTemporally("==", f.seededAt))
	}
}

// expectRejected proves Gateway and listeners report Programmed=False/Invalid
// for the current generation with a safe message naming the rejected object
// and API reason. It returns the Gateway Programmed condition.
func (f *rejectionUnitFixture) expectRejected(kind string, apiReason metav1.StatusReason, sensitive ...string) metav1.Condition {
	conditions := f.programmedConditions()
	for _, condition := range conditions {
		gomega.ExpectWithOffset(1, condition.Status).To(gomega.Equal(metav1.ConditionFalse), "condition %#v", condition)
		gomega.ExpectWithOffset(1, condition.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalid)))
		gomega.ExpectWithOffset(1, condition.ObservedGeneration).To(gomega.Equal(f.generation))
		gomega.ExpectWithOffset(1, condition.Message).To(gomega.ContainSubstring(kind))
		gomega.ExpectWithOffset(1, condition.Message).To(gomega.ContainSubstring(f.dataplane.String()))
		gomega.ExpectWithOffset(1, condition.Message).To(gomega.ContainSubstring(string(apiReason)))
		for _, secret := range sensitive {
			gomega.ExpectWithOffset(1, condition.Message).NotTo(gomega.ContainSubstring(secret))
		}
	}
	accepted := findCondition(f.gateway().Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	gomega.ExpectWithOffset(1, accepted).NotTo(gomega.BeNil())
	gomega.ExpectWithOffset(1, accepted.Status).To(gomega.Equal(metav1.ConditionTrue), "rejection must not revoke acceptance")
	return conditions[0]
}

// expectRejectionEvents proves exactly want rejection Events were emitted, all
// Warnings attached to this Gateway, and returns the most recent one.
func (f *rejectionUnitFixture) expectRejectionEvents(want int) capturedGatewayEvent {
	rejections := f.events.rejections()
	gomega.ExpectWithOffset(1, rejections).To(gomega.HaveLen(want))
	for _, event := range rejections {
		gomega.ExpectWithOffset(1, event.eventType).To(gomega.Equal(corev1.EventTypeWarning))
		regarding, ok := event.regarding.(*gatewayv1.Gateway)
		gomega.ExpectWithOffset(1, ok).To(gomega.BeTrue(), "rejection Event regards %T, want the Gateway", event.regarding)
		gomega.ExpectWithOffset(1, regarding.UID).To(gomega.Equal(rejectionUnitGatewayUID))
		gomega.ExpectWithOffset(1, client.ObjectKeyFromObject(regarding)).To(gomega.Equal(f.gatewayKey))
	}
	if want == 0 {
		return capturedGatewayEvent{}
	}
	return rejections[len(rejections)-1]
}

// expectWorkloadPreserved proves a rejection neither deleted nor scaled down
// the healthy Deployment and kept the existing Service.
func (f *rejectionUnitFixture) expectWorkloadPreserved() {
	var deployment appsv1.Deployment
	gomega.ExpectWithOffset(1, f.backing.Get(context.Background(), f.dataplane, &deployment)).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, deployment.DeletionTimestamp).To(gomega.BeNil())
	gomega.ExpectWithOffset(1, deployment.Spec.Replicas).NotTo(gomega.BeNil())
	gomega.ExpectWithOffset(1, *deployment.Spec.Replicas).To(gomega.Equal(int32(2)))
	gomega.ExpectWithOffset(1, deployment.Status.AvailableReplicas).To(gomega.Equal(int32(2)))
	var service corev1.Service
	gomega.ExpectWithOffset(1, f.backing.Get(context.Background(), f.dataplane, &service)).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, service.DeletionTimestamp).To(gomega.BeNil())
}

func (f *rejectionUnitFixture) isDataplane(object client.Object, kind string) bool {
	if client.ObjectKeyFromObject(object) != f.dataplane {
		return false
	}
	switch typed := object.(type) {
	case *appsv1.Deployment:
		return kind == "Deployment"
	case *corev1.Service:
		return kind == "Service"
	default:
		return typed.GetObjectKind().GroupVersionKind().Kind == kind
	}
}

var _ = ginkgo.Describe("Gateway dataplane mutation rejection", func() {
	const sensitiveDetail = "token=super-secret-admission-payload"
	deploymentsResource := schema.GroupResource{Group: appsv1.GroupName, Resource: "deployments"}
	// forgedStatus builds an API error whose HTTP code alone satisfies the
	// matching apierrors predicate while its Reason is an arbitrary,
	// sensitive payload string. Status and Events must report only the
	// canonical reason; the raw Reason must never be copied out.
	forgedStatus := func(code int32) error {
		return &apierrors.StatusError{ErrStatus: metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    code,
			Reason:  metav1.StatusReason("ForgedAdmission:" + sensitiveDetail),
			Message: "admission denied: " + sensitiveDetail,
		}}
	}

	ginkgo.DescribeTable("reports persistent owned-object apply rejections (Q4)",
		func(rejection error, isReason func(error) bool, apiReason metav1.StatusReason) {
			f := newRejectionUnitFixture(nil)
			f.fault.apply = func(object client.Object) error {
				if f.isDataplane(object, "Deployment") {
					return rejection
				}
				return nil
			}

			err := f.reconcile()

			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(isReason(err)).To(gomega.BeTrue(), "the original API rejection must stay discoverable, got %v", err)
			gomega.Expect(err.Error()).To(gomega.ContainSubstring(sensitiveDetail), "the returned error keeps the full API diagnosis")
			f.expectRejected("Deployment", apiReason, sensitiveDetail)
			event := f.expectRejectionEvents(1)
			gomega.Expect(event.note).To(gomega.ContainSubstring("Deployment"))
			gomega.Expect(event.note).To(gomega.ContainSubstring(f.dataplane.String()))
			gomega.Expect(event.note).To(gomega.ContainSubstring(string(apiReason)))
			gomega.Expect(event.note).NotTo(gomega.ContainSubstring(sensitiveDetail))
			f.expectWorkloadPreserved()
		},
		ginkgo.Entry("Invalid",
			apierrors.NewInvalid(schema.GroupKind{Group: appsv1.GroupName, Kind: "Deployment"}, "flareway-gw-gateway",
				field.ErrorList{field.Invalid(field.NewPath("spec", "template", "spec", "nodeSelector"), sensitiveDetail, "invalid label key")}),
			apierrors.IsInvalid, metav1.StatusReasonInvalid),
		ginkgo.Entry("Forbidden",
			apierrors.NewForbidden(deploymentsResource, "flareway-gw-gateway", errors.New("admission webhook denied: "+sensitiveDetail)),
			apierrors.IsForbidden, metav1.StatusReasonForbidden),
		ginkgo.Entry("BadRequest",
			apierrors.NewBadRequest("malformed apply body: "+sensitiveDetail),
			apierrors.IsBadRequest, metav1.StatusReasonBadRequest),
		ginkgo.Entry("403 with an arbitrary sensitive reason",
			forgedStatus(http.StatusForbidden), apierrors.IsForbidden, metav1.StatusReasonForbidden),
		ginkgo.Entry("422 with an arbitrary sensitive reason",
			forgedStatus(http.StatusUnprocessableEntity), apierrors.IsInvalid, metav1.StatusReasonInvalid),
		ginkgo.Entry("400 with an arbitrary sensitive reason",
			forgedStatus(http.StatusBadRequest), apierrors.IsBadRequest, metav1.StatusReasonBadRequest),
	)

	ginkgo.It("reports a rejected initial create instead of leaving the Gateway programmed (Q4)", func() {
		f := newRejectionUnitFixture(nil)
		gomega.Expect(f.backing.Delete(context.Background(), &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: f.dataplane.Namespace, Name: f.dataplane.Name,
		}})).To(gomega.Succeed())
		f.fault.create = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewForbidden(deploymentsResource, f.dataplane.Name, errors.New("exceeded quota: "+sensitiveDetail))
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsForbidden(err)).To(gomega.BeTrue(), "got %v", err)
		f.expectRejected("Deployment", metav1.StatusReasonForbidden, sensitiveDetail)
		f.expectRejectionEvents(1)
		var deployment appsv1.Deployment
		gomega.Expect(apierrors.IsNotFound(f.backing.Get(context.Background(), f.dataplane, &deployment))).To(gomega.BeTrue())
	})

	ginkgo.DescribeTable("keeps transient mutation failures retry-only (Q5)",
		func(transient error, isReason func(error) bool) {
			f := newRejectionUnitFixture(nil)
			f.fault.apply = func(object client.Object) error {
				if f.isDataplane(object, "Deployment") {
					return transient
				}
				return nil
			}

			err := f.reconcile()

			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(isReason(err)).To(gomega.BeTrue(), "got %v", err)
			f.expectStillProgrammed()
			gomega.Expect(f.events.recorded()).To(gomega.BeEmpty())
		},
		ginkgo.Entry("Conflict", apierrors.NewConflict(deploymentsResource, "flareway-gw-gateway", errors.New("object was modified")), apierrors.IsConflict),
		ginkgo.Entry("Timeout", apierrors.NewTimeoutError("request timed out", 1), apierrors.IsTimeout),
		ginkgo.Entry("ServerTimeout", apierrors.NewServerTimeout(deploymentsResource, "apply", 1), apierrors.IsServerTimeout),
		ginkgo.Entry("TooManyRequests", apierrors.NewTooManyRequestsError("slow down"), apierrors.IsTooManyRequests),
		ginkgo.Entry("ServiceUnavailable", apierrors.NewServiceUnavailable("apiserver draining"), apierrors.IsServiceUnavailable),
		ginkgo.Entry("non-API", errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), func(err error) bool {
			return strings.Contains(err.Error(), "connection refused") && apierrors.ReasonForError(err) == metav1.StatusReasonUnknown
		}),
	)

	ginkgo.It("keeps a Forbidden observation GET retry-only (Q6)", func() {
		f := newRejectionUnitFixture(nil)
		f.fault.get = func(key types.NamespacedName, object client.Object) error {
			if _, ok := object.(*appsv1.Deployment); ok && key == f.dataplane {
				return apierrors.NewForbidden(deploymentsResource, key.Name, errors.New("RBAC: get denied"))
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsForbidden(err)).To(gomega.BeTrue(), "got %v", err)
		f.expectStillProgrammed()
		gomega.Expect(f.events.recorded()).To(gomega.BeEmpty())
	})

	ginkgo.It("keeps a foreign-owned collision retry-only and never mutates it (Q6)", func() {
		f := newRejectionUnitFixture(func(deployment *appsv1.Deployment, _ *corev1.Service) {
			foreign := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "gateway", UID: "previous-gateway-uid"}}
			deployment.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(foreign, gatewayControllerGVK())}
		})
		mutated := false
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				mutated = true
			}
			return nil
		}
		f.fault.patch = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				mutated = true
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))
		gomega.Expect(apierrors.IsForbidden(err) || apierrors.IsInvalid(err) || apierrors.IsBadRequest(err)).To(gomega.BeFalse())
		gomega.Expect(mutated).To(gomega.BeFalse(), "a foreign-owned Deployment must never be mutated")
		f.expectStillProgrammed()
		gomega.Expect(f.events.recorded()).To(gomega.BeEmpty())
		var deployment appsv1.Deployment
		gomega.Expect(f.backing.Get(context.Background(), f.dataplane, &deployment)).To(gomega.Succeed())
		gomega.Expect(deployment.ResourceVersion).To(gomega.Equal(f.seededRV))
		gomega.Expect(metav1.GetControllerOf(&deployment).UID).To(gomega.Equal(types.UID("previous-gateway-uid")))
	})

	ginkgo.It("reports a rejected blocking managed-field migration (Q7)", func() {
		f := newRejectionUnitFixture(func(deployment *appsv1.Deployment, _ *corev1.Service) {
			deployment.ManagedFields = []metav1.ManagedFieldsEntry{{
				Manager:    gatewayFieldManager,
				Operation:  metav1.ManagedFieldsOperationUpdate,
				APIVersion: "apps/v1",
				FieldsType: "FieldsV1",
				FieldsV1:   metav1.NewFieldsV1(`{"f:spec":{"f:replicas":{}}}`),
			}}
		})
		applied := false
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				applied = true
			}
			return nil
		}
		f.fault.patch = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewInvalid(schema.GroupKind{Group: appsv1.GroupName, Kind: "Deployment"}, f.dataplane.Name,
					field.ErrorList{field.Invalid(field.NewPath("metadata", "managedFields"), sensitiveDetail, "rejected")})
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "got %v", err)
		gomega.Expect(applied).To(gomega.BeFalse(), "apply must not run after its blocking migration was rejected")
		f.expectRejected("Deployment", metav1.StatusReasonInvalid, sensitiveDetail)
		f.expectRejectionEvents(1)
		f.expectWorkloadPreserved()
	})

	ginkgo.It("keeps a Forbidden re-read during a blocking managed-field migration retry-only (Q7)", func() {
		f := newRejectionUnitFixture(func(deployment *appsv1.Deployment, _ *corev1.Service) {
			deployment.ManagedFields = []metav1.ManagedFieldsEntry{{
				Manager:    gatewayFieldManager,
				Operation:  metav1.ManagedFieldsOperationUpdate,
				APIVersion: "apps/v1",
				FieldsType: "FieldsV1",
				FieldsV1:   metav1.NewFieldsV1(`{"f:spec":{"f:replicas":{}}}`),
			}}
		})
		applied := false
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				applied = true
			}
			return nil
		}
		// A moved managedFields entry forces the migration to re-read; the
		// re-read (the second Deployment GET) is an observation and fails
		// Forbidden, which must not masquerade as an admission rejection.
		f.fault.patch = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewConflict(deploymentsResource, f.dataplane.Name, errors.New("managedFields entry moved"))
			}
			return nil
		}
		deploymentGets := 0
		f.fault.get = func(key types.NamespacedName, object client.Object) error {
			if _, ok := object.(*appsv1.Deployment); ok && key == f.dataplane {
				deploymentGets++
				if deploymentGets == 2 {
					return apierrors.NewForbidden(deploymentsResource, key.Name, errors.New("RBAC: get denied "+sensitiveDetail))
				}
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsForbidden(err)).To(gomega.BeTrue(), "got %v", err)
		gomega.Expect(deploymentGets).To(gomega.Equal(2), "the failure must hit the migration re-read")
		gomega.Expect(applied).To(gomega.BeFalse(), "apply must not run after the migration could not re-read")
		f.expectStillProgrammed()
		gomega.Expect(f.events.recorded()).To(gomega.BeEmpty())
		f.expectWorkloadPreserved()
	})

	ginkgo.It("keeps a failed best-effort migration after a successful create non-blocking (Q7)", func() {
		f := newRejectionUnitFixture(nil)
		gomega.Expect(f.backing.Delete(context.Background(), &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: f.dataplane.Namespace, Name: f.dataplane.Name,
		}})).To(gomega.Succeed())
		f.fault.create = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				// Mirror the API server Create response, which records the
				// Create-time Update entry the migration converts.
				object.SetManagedFields([]metav1.ManagedFieldsEntry{{
					Manager:    gatewayFieldManager,
					Operation:  metav1.ManagedFieldsOperationUpdate,
					APIVersion: "apps/v1",
					FieldsType: "FieldsV1",
					FieldsV1:   metav1.NewFieldsV1(`{"f:spec":{"f:replicas":{}}}`),
				}})
			}
			return nil
		}
		migrationPatches := 0
		f.fault.patch = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				migrationPatches++
				return apierrors.NewForbidden(deploymentsResource, f.dataplane.Name, errors.New("admission webhook denied: "+sensitiveDetail))
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "a best-effort migration failure after create must not block reconcile")
		gomega.Expect(migrationPatches).To(gomega.Equal(3), "the post-create migration must exhaust its bounded retries")
		for _, condition := range f.programmedConditions() {
			gomega.Expect(condition.Reason).NotTo(gomega.Equal(string(gatewayv1.GatewayReasonInvalid)), "condition %#v", condition)
			gomega.Expect(condition.Message).NotTo(gomega.ContainSubstring(sensitiveDetail))
		}
		f.expectRejectionEvents(0)
		var deployment appsv1.Deployment
		gomega.Expect(f.backing.Get(context.Background(), f.dataplane, &deployment)).To(gomega.Succeed())
		gomega.Expect(metav1.GetControllerOf(&deployment).UID).To(gomega.Equal(rejectionUnitGatewayUID))
	})

	ginkgo.It("reports a rejected Service listener-port replacement (Q7)", func() {
		f := newRejectionUnitFixture(func(_ *appsv1.Deployment, service *corev1.Service) {
			service.Spec.Ports = []corev1.ServicePort{{Name: "stale", Protocol: corev1.ProtocolTCP, Port: 81}}
		})
		f.fault.patch = func(object client.Object) error {
			if f.isDataplane(object, "Service") {
				return apierrors.NewInvalid(schema.GroupKind{Kind: "Service"}, f.dataplane.Name,
					field.ErrorList{field.Invalid(field.NewPath("spec", "ports"), sensitiveDetail, "port rejected")})
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "got %v", err)
		f.expectRejected("Service", metav1.StatusReasonInvalid, sensitiveDetail)
		event := f.expectRejectionEvents(1)
		gomega.Expect(event.note).To(gomega.ContainSubstring("Service"))
		var service corev1.Service
		gomega.Expect(f.backing.Get(context.Background(), f.dataplane, &service)).To(gomega.Succeed())
		gomega.Expect(service.Spec.Ports).To(gomega.Equal(f.seededPorts), "a rejected replacement leaves the existing Service intact")
	})

	ginkgo.It("keeps a Forbidden re-read after a Service port replacement retry-only (Q7)", func() {
		f := newRejectionUnitFixture(func(_ *appsv1.Deployment, service *corev1.Service) {
			service.Spec.Ports = []corev1.ServicePort{{Name: "stale", Protocol: corev1.ProtocolTCP, Port: 81}}
		})
		serviceGets := 0
		f.fault.get = func(key types.NamespacedName, object client.Object) error {
			if _, ok := object.(*corev1.Service); ok && key == f.dataplane {
				serviceGets++
				if serviceGets == 2 {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, key.Name, errors.New("RBAC: get denied "+sensitiveDetail))
				}
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(apierrors.IsForbidden(err)).To(gomega.BeTrue(), "got %v", err)
		gomega.Expect(serviceGets).To(gomega.Equal(2), "the failure must hit the post-replacement re-read")
		f.expectStillProgrammed()
		gomega.Expect(f.events.recorded()).To(gomega.BeEmpty())
	})

	ginkgo.It("emits once per rejection identity and keeps identical retries stable (Q8)", func() {
		f := newRejectionUnitFixture(nil)
		var rejection error = apierrors.NewInvalid(schema.GroupKind{Group: appsv1.GroupName, Kind: "Deployment"}, "flareway-gw-gateway",
			field.ErrorList{field.Invalid(field.NewPath("spec"), sensitiveDetail, "invalid")})
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return rejection
			}
			return nil
		}

		gomega.Expect(apierrors.IsInvalid(f.reconcile())).To(gomega.BeTrue())
		first := f.expectRejected("Deployment", metav1.StatusReasonInvalid, sensitiveDetail)
		f.expectRejectionEvents(1)

		for range 2 {
			gomega.Expect(apierrors.IsInvalid(f.reconcile())).To(gomega.BeTrue())
			retried := f.expectRejected("Deployment", metav1.StatusReasonInvalid, sensitiveDetail)
			gomega.Expect(retried.Message).To(gomega.Equal(first.Message))
			gomega.Expect(retried.LastTransitionTime.Time).To(gomega.BeTemporally("==", first.LastTransitionTime.Time),
				"an identical retry must not rewrite the transition time")
			f.expectRejectionEvents(1)
		}

		rejection = apierrors.NewForbidden(deploymentsResource, "flareway-gw-gateway", errors.New(sensitiveDetail))
		gomega.Expect(apierrors.IsForbidden(f.reconcile())).To(gomega.BeTrue())
		f.expectRejected("Deployment", metav1.StatusReasonForbidden, sensitiveDetail)
		event := f.expectRejectionEvents(2)
		gomega.Expect(event.note).To(gomega.ContainSubstring(string(metav1.StatusReasonForbidden)))

		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Service") {
				return apierrors.NewInvalid(schema.GroupKind{Kind: "Service"}, f.dataplane.Name,
					field.ErrorList{field.Invalid(field.NewPath("spec"), sensitiveDetail, "invalid")})
			}
			return nil
		}
		gomega.Expect(apierrors.IsInvalid(f.reconcile())).To(gomega.BeTrue())
		f.expectRejected("Service", metav1.StatusReasonInvalid, sensitiveDetail)
		event = f.expectRejectionEvents(3)
		gomega.Expect(event.note).To(gomega.ContainSubstring("Service"))
		gomega.Expect(event.note).NotTo(gomega.ContainSubstring(sensitiveDetail))
	})

	ginkgo.It("reports rejections without a recorder (Q8)", func() {
		f := newRejectionUnitFixture(nil)
		f.reconciler.Recorder = nil
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewBadRequest(sensitiveDetail)
			}
			return nil
		}

		var err error
		gomega.Expect(func() { err = f.reconcile() }).NotTo(gomega.Panic())

		gomega.Expect(apierrors.IsBadRequest(err)).To(gomega.BeTrue(), "got %v", err)
		f.expectRejected("Deployment", metav1.StatusReasonBadRequest, sensitiveDetail)
	})

	ginkgo.It("surfaces both errors when the rejection status write fails, then recovers on retry (Q9)", func() {
		f := newRejectionUnitFixture(nil)
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewInvalid(schema.GroupKind{Group: appsv1.GroupName, Kind: "Deployment"}, f.dataplane.Name,
					field.ErrorList{field.Invalid(field.NewPath("spec"), sensitiveDetail, "invalid")})
			}
			return nil
		}
		failedRejectionWrites := 0
		f.fault.statusPatch = func(object client.Object) error {
			gateway, ok := object.(*gatewayv1.Gateway)
			if !ok {
				return nil
			}
			// Fail only the rejection write, not the pre-apply checkpoint.
			if programmed := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed)); programmed != nil &&
				programmed.Status == metav1.ConditionFalse && programmed.Reason == string(gatewayv1.GatewayReasonInvalid) {
				failedRejectionWrites++
				return errRejectionUnitStatusWrite
			}
			return nil
		}

		err := f.reconcile()

		gomega.Expect(failedRejectionWrites).To(gomega.Equal(1))
		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "the original rejection must survive, got %v", err)
		gomega.Expect(errors.Is(err, errRejectionUnitStatusWrite)).To(gomega.BeTrue(), "the status write failure must survive, got %v", err)
		f.expectStillProgrammed()
		gomega.Expect(f.events.recorded()).To(gomega.BeEmpty(), "no Event may claim a rejection the status does not record")

		f.fault.statusPatch = nil
		err = f.reconcile()

		gomega.Expect(apierrors.IsInvalid(err)).To(gomega.BeTrue(), "got %v", err)
		gomega.Expect(errors.Is(err, errRejectionUnitStatusWrite)).To(gomega.BeFalse())
		f.expectRejected("Deployment", metav1.StatusReasonInvalid, sensitiveDetail)
		f.expectRejectionEvents(1)
	})

	ginkgo.It("preserves the existing workload, Service, and acceptance on rejection (Q11)", func() {
		f := newRejectionUnitFixture(nil)
		acceptedBefore := findCondition(f.gateway().Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(acceptedBefore).NotTo(gomega.BeNil())
		f.fault.apply = func(object client.Object) error {
			if f.isDataplane(object, "Deployment") {
				return apierrors.NewInvalid(schema.GroupKind{Group: appsv1.GroupName, Kind: "Deployment"}, f.dataplane.Name,
					field.ErrorList{field.Invalid(field.NewPath("spec"), sensitiveDetail, "invalid")})
			}
			return nil
		}

		gomega.Expect(apierrors.IsInvalid(f.reconcile())).To(gomega.BeTrue())

		f.expectRejected("Deployment", metav1.StatusReasonInvalid, sensitiveDetail)
		f.expectWorkloadPreserved()
		var deployment appsv1.Deployment
		gomega.Expect(f.backing.Get(context.Background(), f.dataplane, &deployment)).To(gomega.Succeed())
		gomega.Expect(deployment.ResourceVersion).To(gomega.Equal(f.seededRV), "a rejected apply must not rewrite the workload")
		gomega.Expect(metav1.GetControllerOf(&deployment).UID).To(gomega.Equal(rejectionUnitGatewayUID))
		accepted := findCondition(f.gateway().Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(accepted.Reason).To(gomega.Equal(acceptedBefore.Reason))
		gomega.Expect(accepted.LastTransitionTime.Time).To(gomega.BeTemporally("==", acceptedBefore.LastTransitionTime.Time))
		for _, listener := range f.gateway().Status.Listeners {
			listenerAccepted := findCondition(listener.Conditions, string(gatewayv1.ListenerConditionAccepted))
			gomega.Expect(listenerAccepted).NotTo(gomega.BeNil())
			gomega.Expect(listenerAccepted.Status).To(gomega.Equal(metav1.ConditionTrue))
		}
	})
})
