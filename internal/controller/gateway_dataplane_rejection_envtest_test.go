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
	"strings"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/test/envtesthelpers"
)

// dataplaneRejectionFixture drives a GatewayReconciler through explicit
// Reconcile calls on a dedicated control plane, so no suite manager can
// interleave status writes with a rejection observation. The recorder is a
// controlled fake; every Kubernetes mutation goes through the real API
// server, which is what makes the admission rejection genuine.
type dataplaneRejectionFixture struct {
	kube        client.Client
	reconciler  *GatewayReconciler
	snapshots   *fakeSnapshotPublisher
	recorder    *events.FakeRecorder
	request     ctrl.Request
	namespace   string
	configName  string
	gatewayKey  types.NamespacedName
	deployKey   types.NamespacedName
	snapshotKey string
}

func newDataplaneRejectionFixture(kube client.Client) *dataplaneRejectionFixture {
	fixtureID := fixtureCounter.Add(1)
	namespaceName := fmt.Sprintf("gw-reject-%d", fixtureID)
	className := fmt.Sprintf("cls-reject-%d", fixtureID)
	fixture := &dataplaneRejectionFixture{
		kube:       kube,
		namespace:  namespaceName,
		configName: fmt.Sprintf("cfg-reject-%d", fixtureID),
		snapshots:  newFakeSnapshotPublisher(),
		recorder:   events.NewFakeRecorder(32),
		gatewayKey: types.NamespacedName{Namespace: namespaceName, Name: "gateway"},
		deployKey:  types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-gateway"},
	}
	fixture.snapshotKey = fixture.gatewayKey.String()
	fixture.request = ctrl.Request{NamespacedName: fixture.gatewayKey}
	fixture.reconciler = &GatewayReconciler{
		Client:            kube,
		APIReader:         kube,
		Scheme:            kube.Scheme(),
		Snapshots:         fixture.snapshots,
		BuildSnapshot:     controlledSnapshotBuild,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Recorder:          fixture.recorder,
	}

	gomega.ExpectWithOffset(1, client.IgnoreAlreadyExists(kube.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}))).
		To(gomega.Succeed())
	gomega.ExpectWithOffset(1, kube.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fixture.namespace}})).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, kube.Create(testContext, conformanceConfig(fixture.configName, corev1.ServiceTypeClusterIP))).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, kube.Create(testContext, gatewayClass(className, fixture.configName))).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, kube.Create(testContext, httpGateway(fixture.gatewayKey, className))).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() {
		gomega.Expect(client.IgnoreNotFound(kube.Delete(context.Background(), &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.namespace, Name: fixture.gatewayKey.Name}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(kube.Delete(context.Background(), &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: className}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(kube.Delete(context.Background(), &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: fixture.configName}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(kube.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fixture.namespace}}))).To(gomega.Succeed())
	})
	return fixture
}

func (f *dataplaneRejectionFixture) reconcile() error {
	_, err := f.reconciler.Reconcile(testContext, f.request)
	return err
}

// convergeProgrammed reconciles to Programmed=True by supplying the inputs a
// healthy dataplane would report: an available Deployment and an acknowledged
// snapshot. Each gate is proven in order: a successful apply alone must not
// promote, and availability without a current ACK must not promote.
func (f *dataplaneRejectionFixture) convergeProgrammed() {
	f.withholdACK()
	gomega.ExpectWithOffset(1, f.reconcile()).To(gomega.Succeed())
	f.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonPending))
	f.promoteThroughGates()
}

// withholdACK clears any recorded Envoy ACK so the next reconcile observes an
// unacknowledged snapshot even when the republished version is unchanged.
func (f *dataplaneRejectionFixture) withholdACK() {
	f.snapshots.mu.Lock()
	defer f.snapshots.mu.Unlock()
	delete(f.snapshots.acked, f.snapshotKey)
}

// promoteThroughGates finishes convergence after the desired objects have been
// applied and proves each gate on its own: a current ACK without an available
// Deployment stays Pending on availability, an available Deployment without a
// current ACK stays Pending on the ACK, and only both report Programmed=True.
func (f *dataplaneRejectionFixture) promoteThroughGates() {
	f.markDeploymentUnavailable()
	gomega.ExpectWithOffset(1, f.snapshots.ACK(f.snapshotKey)).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, f.reconcile()).To(gomega.Succeed())
	waitingAvailability := f.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonPending))
	gomega.ExpectWithOffset(1, waitingAvailability.Message).To(gomega.Equal("Waiting for the dataplane Deployment to become available"))

	f.withholdACK()
	gomega.ExpectWithOffset(1, envtesthelpers.MarkDeploymentAvailable(testContext, f.kube, f.deployKey)).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, f.reconcile()).To(gomega.Succeed())
	waitingACK := f.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonPending))
	gomega.ExpectWithOffset(1, waitingACK.Message).To(gomega.HavePrefix("Waiting for Envoy to acknowledge xDS snapshot "))

	gomega.ExpectWithOffset(1, f.snapshots.ACK(f.snapshotKey)).To(gomega.Succeed())
	gomega.ExpectWithOffset(1, f.reconcile()).To(gomega.Succeed())
	f.expectProgrammed(metav1.ConditionTrue, string(gatewayv1.GatewayReasonProgrammed))
}

// markDeploymentUnavailable records the status a Deployment controller reports
// while the rolled-out Pods are not yet available, replacing any earlier
// Available=True so availability is observed for the current spec only.
func (f *dataplaneRejectionFixture) markDeploymentUnavailable() {
	var deployment appsv1.Deployment
	gomega.ExpectWithOffset(2, f.kube.Get(testContext, f.deployKey, &deployment)).To(gomega.Succeed())
	now := metav1.Now()
	deployment.Status = appsv1.DeploymentStatus{
		ObservedGeneration: deployment.Generation,
		Conditions: []appsv1.DeploymentCondition{{
			Type:               appsv1.DeploymentAvailable,
			Status:             corev1.ConditionFalse,
			Reason:             "MinimumReplicasUnavailable",
			Message:            "Deployment does not have minimum availability.",
			LastUpdateTime:     now,
			LastTransitionTime: now,
		}},
	}
	gomega.ExpectWithOffset(2, f.kube.Status().Update(testContext, &deployment)).To(gomega.Succeed())
}

// expectProgrammed asserts the persisted Programmed condition of the Gateway
// and every listener, pinned to the current Gateway generation.
func (f *dataplaneRejectionFixture) expectProgrammed(status metav1.ConditionStatus, reason string) *metav1.Condition {
	var gateway gatewayv1.Gateway
	gomega.ExpectWithOffset(1, f.kube.Get(testContext, f.gatewayKey, &gateway)).To(gomega.Succeed())
	condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	gomega.ExpectWithOffset(1, condition).NotTo(gomega.BeNil())
	gomega.ExpectWithOffset(1, condition.Status).To(gomega.Equal(status))
	gomega.ExpectWithOffset(1, condition.Reason).To(gomega.Equal(reason))
	gomega.ExpectWithOffset(1, condition.ObservedGeneration).To(gomega.Equal(gateway.Generation))
	gomega.ExpectWithOffset(1, gateway.Status.Listeners).NotTo(gomega.BeEmpty())
	for index := range gateway.Status.Listeners {
		listenerCondition := findCondition(gateway.Status.Listeners[index].Conditions, string(gatewayv1.ListenerConditionProgrammed))
		gomega.ExpectWithOffset(1, listenerCondition).NotTo(gomega.BeNil())
		gomega.ExpectWithOffset(1, listenerCondition.Status).To(gomega.Equal(status))
		gomega.ExpectWithOffset(1, listenerCondition.Reason).To(gomega.Equal(reason))
		gomega.ExpectWithOffset(1, listenerCondition.ObservedGeneration).To(gomega.Equal(gateway.Generation))
	}
	return condition
}

func (f *dataplaneRejectionFixture) setScheduling(scheduling v1alpha1.DataplaneSchedulingSpec) {
	var config v1alpha1.GatewayClassConfig
	gomega.ExpectWithOffset(1, f.kube.Get(testContext, types.NamespacedName{Name: f.configName}, &config)).To(gomega.Succeed())
	config.Spec.Scheduling = scheduling
	gomega.ExpectWithOffset(1, f.kube.Update(testContext, &config)).To(gomega.Succeed())
}

func (f *dataplaneRejectionFixture) drainEvents() []string {
	var drained []string
	for {
		select {
		case event := <-f.recorder.Events:
			drained = append(drained, event)
		default:
			return drained
		}
	}
}

// expectRejectionEvent asserts exactly one Warning event that identifies the
// rejected object kind, its namespace/name, and the API reason.
func (f *dataplaneRejectionFixture) expectRejectionEvent() {
	var rejectionEvents []string
	for _, event := range f.drainEvents() {
		if strings.Contains(event, "DataplaneApplyRejected") {
			rejectionEvents = append(rejectionEvents, event)
		}
	}
	gomega.ExpectWithOffset(1, rejectionEvents).To(gomega.HaveLen(1))
	gomega.ExpectWithOffset(1, rejectionEvents[0]).To(gomega.HavePrefix(string(corev1.EventTypeWarning) + " "))
	gomega.ExpectWithOffset(1, rejectionEvents[0]).To(gomega.ContainSubstring("Deployment"))
	gomega.ExpectWithOffset(1, rejectionEvents[0]).To(gomega.ContainSubstring(f.deployKey.String()))
	gomega.ExpectWithOffset(1, rejectionEvents[0]).To(gomega.ContainSubstring("Invalid"))
}

var _ = ginkgo.Describe("Gateway dataplane apply rejection", func() {
	var plane client.Client

	ginkgo.BeforeEach(func() {
		// A dedicated control plane per spec with no manager: only this spec's
		// explicit Reconcile calls write, so status and event observations are
		// exact and neither spec can observe the other's state.
		plane = startIsolatedConditionsPlane()
	})

	ginkgo.It("reports Invalid and emits a Warning when the API server rejects an owned Deployment apply", func() {
		fixture := newDataplaneRejectionFixture(plane)
		fixture.convergeProgrammed()

		var gateway gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		generation := gateway.Generation
		gomega.Expect(gateway.Status.Addresses).NotTo(gomega.BeEmpty())

		// The CRD accepts the scheduling spec, but the API server rejects the
		// resulting Deployment: prove the admission boundary with a dry-run
		// write of the same mutation the controller will attempt.
		var deployment appsv1.Deployment
		gomega.Expect(fixture.kube.Get(testContext, fixture.deployKey, &deployment)).To(gomega.Succeed())
		rejectedDeployment := deployment.DeepCopy()
		rejectedDeployment.Spec.Template.Spec.NodeSelector = map[string]string{"bad key!": "linux"}
		dryRunErr := fixture.kube.Update(testContext, rejectedDeployment, client.DryRunAll)
		gomega.Expect(apierrors.IsInvalid(dryRunErr)).To(gomega.BeTrue(), "expected the API server to reject the bad nodeSelector, got %v", dryRunErr)

		fixture.setScheduling(v1alpha1.DataplaneSchedulingSpec{NodeSelector: map[string]string{"bad key!": "linux"}})
		fixture.drainEvents()

		reconcileErr := fixture.reconcile()
		gomega.Expect(apierrors.IsInvalid(reconcileErr)).To(gomega.BeTrue(), "expected the reconcile to surface the apiserver Invalid rejection, got %v", reconcileErr)

		rejected := fixture.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonInvalid))
		var persisted gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &persisted)).To(gomega.Succeed())
		gomega.Expect(persisted.Generation).To(gomega.Equal(generation))
		gomega.Expect(persisted.Status.Addresses).To(gomega.Equal(gateway.Status.Addresses))
		accepted := findCondition(persisted.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(accepted).NotTo(gomega.BeNil())
		gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))

		fixture.expectRejectionEvent()

		// The rejected apply must not mutate the healthy workload.
		var preserved appsv1.Deployment
		gomega.Expect(fixture.kube.Get(testContext, fixture.deployKey, &preserved)).To(gomega.Succeed())
		gomega.Expect(preserved.Spec.Template.Spec.NodeSelector).NotTo(gomega.HaveKey("bad key!"))
		gomega.Expect(preserved.Generation).To(gomega.Equal(deployment.Generation))
		var service corev1.Service
		gomega.Expect(fixture.kube.Get(testContext, fixture.deployKey, &service)).To(gomega.Succeed())

		// An identical retry keeps the persisted condition and does not
		// re-emit the event.
		gomega.Expect(apierrors.IsInvalid(fixture.reconcile())).To(gomega.BeTrue())
		retried := fixture.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonInvalid))
		gomega.Expect(retried.LastTransitionTime).To(gomega.Equal(rejected.LastTransitionTime))
		gomega.Expect(fixture.drainEvents()).To(gomega.BeEmpty())

		// Correcting the config at the same Gateway generation restores
		// Programmed only through the ordinary availability and ACK gates.
		// The ACK recorded before the rejection is withheld so a successful
		// apply and a still-Available Deployment cannot promote on their own.
		fixture.setScheduling(v1alpha1.DataplaneSchedulingSpec{NodeSelector: map[string]string{"kubernetes.io/os": "linux"}})
		fixture.withholdACK()
		gomega.Expect(fixture.reconcile()).To(gomega.Succeed())
		var recovered appsv1.Deployment
		gomega.Expect(fixture.kube.Get(testContext, fixture.deployKey, &recovered)).To(gomega.Succeed())
		gomega.Expect(recovered.Spec.Template.Spec.NodeSelector).To(gomega.HaveKeyWithValue("kubernetes.io/os", "linux"))
		gomega.Expect(recovered.Generation).To(gomega.BeNumerically(">", deployment.Generation))
		fixture.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonPending))
		fixture.promoteThroughGates()
		var converged gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &converged)).To(gomega.Succeed())
		gomega.Expect(converged.Generation).To(gomega.Equal(generation))
	})

	ginkgo.It("reports Invalid instead of Unknown when the initial owned Deployment create is rejected", func() {
		fixture := newDataplaneRejectionFixture(plane)
		fixture.setScheduling(v1alpha1.DataplaneSchedulingSpec{NodeSelector: map[string]string{"bad key!": "linux"}})

		reconcileErr := fixture.reconcile()
		gomega.Expect(apierrors.IsInvalid(reconcileErr)).To(gomega.BeTrue(), "expected the reconcile to surface the apiserver Invalid rejection, got %v", reconcileErr)

		var deployment appsv1.Deployment
		err := fixture.kube.Get(testContext, fixture.deployKey, &deployment)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "the rejected Deployment must not exist, got %v", err)

		fixture.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonInvalid))
		fixture.expectRejectionEvent()

		var original gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &original)).To(gomega.Succeed())
		fixture.setScheduling(v1alpha1.DataplaneSchedulingSpec{NodeSelector: map[string]string{"kubernetes.io/os": "linux"}})
		fixture.convergeProgrammed()
		var converged gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &converged)).To(gomega.Succeed())
		gomega.Expect(converged.Generation).To(gomega.Equal(original.Generation))
	})
})
