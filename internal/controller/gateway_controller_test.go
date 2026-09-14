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
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/test/envtesthelpers"
)

var fixtureCounter atomic.Uint64

var _ = ginkgo.Describe("Gateway reconciler", ginkgo.Ordered, func() {
	var namespaceName string
	var configName string
	var className string
	var gatewayKey types.NamespacedName
	var routeKey types.NamespacedName

	ginkgo.BeforeAll(func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName = fmt.Sprintf("gateway-envtest-%d", fixtureID)
		configName = fmt.Sprintf("conformance-%d", fixtureID)
		className = fmt.Sprintf("flareway-%d", fixtureID)
		gatewayKey = types.NamespacedName{Namespace: namespaceName, Name: "gateway"}
		routeKey = types.NamespacedName{Namespace: namespaceName, Name: "route"}

		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}})).To(gomega.Or(gomega.Succeed(), gomega.MatchError(gomega.ContainSubstring("already exists"))))
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, conformanceConfig(configName, corev1.ServiceTypeLoadBalancer))).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, gatewayClass(className, configName))).To(gomega.Succeed())

		backend := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "echo", Namespace: namespaceName},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "echo"},
				Ports:    []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080)}},
			},
		}
		gomega.Expect(testClient.Create(testContext, backend)).To(gomega.Succeed())
		_, err := envtesthelpers.CreateEndpointSlice(testContext, testClient, backend, "192.0.2.20")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		route := httpRoute(routeKey, gatewayKey, "echo")
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		foreignController := gatewayv1.GatewayController("example.net/other-controller")
		foreignParent := gatewayv1.RouteParentStatus{
			ParentRef:      gatewayv1.ParentReference{Name: "unrelated-gateway"},
			ControllerName: foreignController,
			Conditions: []metav1.Condition{{
				Type:               string(gatewayv1.RouteConditionAccepted),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: route.Generation,
				Reason:             string(gatewayv1.RouteReasonAccepted),
				Message:            "owned by another controller",
				LastTransitionTime: metav1.Now(),
			}},
		}
		route.Status.Parents = []gatewayv1.RouteParentStatus{foreignParent}
		gomega.Expect(testClient.Status().Update(testContext, route)).To(gomega.Succeed())

		gomega.Expect(testClient.Create(testContext, httpGateway(gatewayKey, className))).To(gomega.Succeed())
	})

	ginkgo.AfterAll(func() {
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: className}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}}))).To(gomega.Succeed())
	})

	ginkgo.It("requires ACK, Deployment availability, and a Service address before Programmed", func() {
		dataplaneKey := types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-gateway"}
		snapshotKey := gatewayKey.String()

		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
			var service corev1.Service
			g.Expect(testClient.Get(testContext, dataplaneKey, &service)).To(gomega.Succeed())
			var configMap corev1.ConfigMap
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-gateway-envoy"}, &configMap)).To(gomega.Succeed())
			var pdb policyv1.PodDisruptionBudget
			g.Expect(testClient.Get(testContext, dataplaneKey, &pdb)).To(gomega.Succeed())
			var networkPolicy networkingv1.NetworkPolicy
			g.Expect(testClient.Get(testContext, dataplaneKey, &networkPolicy)).To(gomega.Succeed())
			var xdsSecret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: "flareway-xds-gateway"}, &xdsSecret)).To(gomega.Succeed())
			g.Expect(testSnapshots.Version(snapshotKey)).NotTo(gomega.BeEmpty())
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())

		gomega.Consistently(func(g gomega.Gomega) {
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &gateway)).To(gomega.Succeed())
			condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).NotTo(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(envtesthelpers.MarkDeploymentAvailable(testContext, testClient, dataplaneKey)).To(gomega.Succeed())

		gomega.Consistently(func(g gomega.Gomega) {
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &gateway)).To(gomega.Succeed())
			condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonAddressNotAssigned)))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testSnapshots.NACK(snapshotKey, "rejected test snapshot")).To(gomega.Succeed())
		var service corev1.Service
		gomega.Expect(testClient.Get(testContext, dataplaneKey, &service)).To(gomega.Succeed())
		before := service.DeepCopy()
		service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "gateway.example.test"}}
		gomega.Expect(testClient.Status().Patch(testContext, &service, client.MergeFrom(before))).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &gateway)).To(gomega.Succeed())
			condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonPending)))
			g.Expect(condition.Message).To(gomega.ContainSubstring("Envoy rejected xDS snapshot"), "observed condition: %#v", condition)
			g.Expect(condition.Message).To(gomega.ContainSubstring("rejected test snapshot"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testSnapshots.ACK(snapshotKey)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &gateway)).To(gomega.Succeed())
			condition := findCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(condition.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonProgrammed)))
			g.Expect(gateway.Status.Addresses).To(gomega.HaveLen(1))
			g.Expect(gateway.Status.Addresses[0].Type).NotTo(gomega.BeNil())
			g.Expect(*gateway.Status.Addresses[0].Type).To(gomega.Equal(gatewayv1.HostnameAddressType))
			g.Expect(gateway.Status.Addresses[0].Value).To(gomega.Equal("gateway.example.test"))
		}).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("advances owned condition generations without changing transition times for unchanged status", func() {
		var before gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, gatewayKey, &before)).To(gomega.Succeed())
		beforeAccepted := findCondition(before.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(beforeAccepted).NotTo(gomega.BeNil())
		beforeListener := listenerStatusByName(before.Status.Listeners, "http")
		gomega.Expect(beforeListener).NotTo(gomega.BeNil())
		transitionTimes := map[string]metav1.Time{}
		for _, condition := range beforeListener.Conditions {
			transitionTimes[condition.Type] = condition.LastTransitionTime
		}
		fromSame := gatewayv1.NamespacesFromSame
		gomega.Eventually(func() error {
			var current gatewayv1.Gateway
			if err := testClient.Get(testContext, gatewayKey, &current); err != nil {
				return err
			}
			current.Spec.Listeners[0].AllowedRoutes = &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &fromSame},
				Kinds:      []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}},
			}
			return testClient.Update(testContext, &current)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &current)).To(gomega.Succeed())
			g.Expect(current.Generation).To(gomega.BeNumerically(">", beforeAccepted.ObservedGeneration))
			for _, conditionType := range []string{
				string(gatewayv1.GatewayConditionAccepted),
				string(gatewayv1.GatewayConditionProgrammed),
			} {
				condition := findCondition(current.Status.Conditions, conditionType)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(current.Generation))
			}
			accepted := findCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
			g.Expect(accepted.LastTransitionTime).To(gomega.Equal(beforeAccepted.LastTransitionTime))
			listener := listenerStatusByName(current.Status.Listeners, "http")
			g.Expect(listener).NotTo(gomega.BeNil())
			for _, condition := range listener.Conditions {
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(current.Generation))
				if previous, ok := transitionTimes[condition.Type]; ok && condition.Type != string(gatewayv1.ListenerConditionProgrammed) {
					g.Expect(condition.LastTransitionTime).To(gomega.Equal(previous))
				}
			}
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("patches computed statuses with current generations before returning a snapshot build error", func() {
		snapshotKey := gatewayKey.String()
		previousVersion := testSnapshots.Version(snapshotKey)
		testSnapshotBuildFailures.Store(snapshotKey, errors.New("sensitive compiler detail"))
		ginkgo.DeferCleanup(func() { testSnapshotBuildFailures.Delete(snapshotKey) })

		policy := systemBackendTLSPolicy(namespaceName, "echo-tls", "echo")
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), policy))).To(gomega.Succeed())
		})

		var route gatewayv1.HTTPRoute
		gomega.Expect(testClient.Get(testContext, routeKey, &route)).To(gomega.Succeed())
		routeBefore := route.DeepCopy()
		foreignParents := make([]gatewayv1.RouteParentStatus, 0)
		for _, parent := range route.Status.Parents {
			if parent.ControllerName != gatewayapi.ControllerName {
				foreignParents = append(foreignParents, parent)
			}
		}
		route.Status.Parents = foreignParents
		gomega.Expect(testClient.Status().Patch(testContext, &route, client.MergeFrom(routeBefore))).To(gomega.Succeed())

		fromAll := gatewayv1.NamespacesFromAll
		gomega.Eventually(func() error {
			var gateway gatewayv1.Gateway
			if err := testClient.Get(testContext, gatewayKey, &gateway); err != nil {
				return err
			}
			gateway.Spec.Listeners[0].AllowedRoutes.Namespaces.From = &fromAll
			return testClient.Update(testContext, &gateway)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &current)).To(gomega.Succeed())
			for _, conditionType := range []string{
				string(gatewayv1.GatewayConditionAccepted),
				string(gatewayv1.GatewayConditionProgrammed),
			} {
				condition := findCondition(current.Status.Conditions, conditionType)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(current.Generation))
			}
			programmed := findCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalid)))
			g.Expect(programmed.Message).To(gomega.Equal("Gateway configuration could not be compiled"))
			g.Expect(programmed.Message).NotTo(gomega.ContainSubstring("sensitive compiler detail"))
			for _, listener := range current.Status.Listeners {
				for _, condition := range listener.Conditions {
					g.Expect(condition.ObservedGeneration).To(gomega.Equal(current.Generation))
				}
			}

			var currentRoute gatewayv1.HTTPRoute
			g.Expect(testClient.Get(testContext, routeKey, &currentRoute)).To(gomega.Succeed())
			g.Expect(hasControllerParentForGateway(currentRoute.Status.Parents, currentRoute.Namespace, gatewayKey)).To(gomega.BeTrue())

			var currentPolicy gatewayv1.BackendTLSPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &currentPolicy)).To(gomega.Succeed())
			g.Expect(hasControllerAncestorForGateway(currentPolicy.Status.Ancestors, currentPolicy.Namespace, gatewayKey)).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testSnapshotBuildFailures.Delete(snapshotKey)
		gomega.Eventually(func() error {
			var trigger gatewayv1.Gateway
			if err := testClient.Get(testContext, gatewayKey, &trigger); err != nil {
				return err
			}
			if trigger.Annotations == nil {
				trigger.Annotations = map[string]string{}
			}
			trigger.Annotations["example.net/reconcile"] = "after-build-failure"
			return testClient.Update(testContext, &trigger)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func() string {
			return testSnapshots.Version(snapshotKey)
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).ShouldNot(gomega.Equal(previousVersion))
		gomega.Expect(testSnapshots.ACK(snapshotKey)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &current)).To(gomega.Succeed())
			programmed := findCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("updates xDS for EndpointSlice churn without rolling the dataplane Deployment", func() {
		dataplaneKey := types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-gateway"}
		snapshotKey := gatewayKey.String()
		var deployment appsv1.Deployment
		gomega.Expect(testClient.Get(testContext, dataplaneKey, &deployment)).To(gomega.Succeed())
		originalGeneration := deployment.Generation
		originalHash := deployment.Spec.Template.Annotations[dataplane.ConfigHashKey]
		originalVersion := testSnapshots.Version(snapshotKey)

		var endpointSlice discoveryv1.EndpointSlice
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: "echo-envtest"}, &endpointSlice)).To(gomega.Succeed())
		endpointSlice.Endpoints[0].Addresses = []string{"192.0.2.21"}
		gomega.Expect(testClient.Update(testContext, &endpointSlice)).To(gomega.Succeed())

		gomega.Eventually(func() string {
			return testSnapshots.Version(snapshotKey)
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).ShouldNot(gomega.Equal(originalVersion))
		gomega.Consistently(func(g gomega.Gomega) {
			var current appsv1.Deployment
			g.Expect(testClient.Get(testContext, dataplaneKey, &current)).To(gomega.Succeed())
			g.Expect(current.Generation).To(gomega.Equal(originalGeneration))
			g.Expect(current.Spec.Template.Annotations[dataplane.ConfigHashKey]).To(gomega.Equal(originalHash))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testSnapshots.ACK(snapshotKey)).To(gomega.Succeed())
	})

	ginkgo.It("publishes its HTTPRoute parent status without replacing another controller", func() {
		gomega.Eventually(func(g gomega.Gomega) {
			var route gatewayv1.HTTPRoute
			g.Expect(testClient.Get(testContext, routeKey, &route)).To(gomega.Succeed())
			g.Expect(route.Status.Parents).To(gomega.HaveLen(2))
			controllers := map[gatewayv1.GatewayController]bool{}
			for _, parent := range route.Status.Parents {
				controllers[parent.ControllerName] = true
			}
			g.Expect(controllers[gatewayapi.ControllerName]).To(gomega.BeTrue())
			g.Expect(controllers[gatewayv1.GatewayController("example.net/other-controller")]).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("clears the published snapshot when the Gateway leaves the Flareway class", func() {
		foreignClassName := fmt.Sprintf("foreign-%d", fixtureCounter.Add(1))
		foreignClass := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: foreignClassName},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/foreign-controller"},
		}
		gomega.Expect(testClient.Create(testContext, foreignClass)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), foreignClass))).To(gomega.Succeed())
		})
		gomega.Eventually(func() error {
			var gateway gatewayv1.Gateway
			if err := testClient.Get(testContext, gatewayKey, &gateway); err != nil {
				return err
			}
			gateway.Spec.GatewayClassName = gatewayv1.ObjectName(foreignClassName)
			return testClient.Update(testContext, &gateway)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func() string {
			return testSnapshots.Version(gatewayKey.String())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeEmpty())
	})
})

var _ = ginkgo.Describe("Service address selection", func() {
	ginkgo.It("uses an IPAddress for ClusterIP Services", func() {
		service := &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.96.0.15"}}
		addresses, ready, message := serviceAddress(service)
		gomega.Expect(ready).To(gomega.BeTrue())
		gomega.Expect(message).To(gomega.BeEmpty())
		gomega.Expect(addresses).To(gomega.HaveLen(1))
		gomega.Expect(*addresses[0].Type).To(gomega.Equal(gatewayv1.IPAddressType))
		gomega.Expect(addresses[0].Value).To(gomega.Equal("10.96.0.15"))
	})

	ginkgo.It("uses an IPAddress for LoadBalancer IP ingress", func() {
		service := &corev1.Service{
			Spec:   corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "192.0.2.55"}}}},
		}
		addresses, ready, _ := serviceAddress(service)
		gomega.Expect(ready).To(gomega.BeTrue())
		gomega.Expect(*addresses[0].Type).To(gomega.Equal(gatewayv1.IPAddressType))
		gomega.Expect(addresses[0].Value).To(gomega.Equal("192.0.2.55"))
	})
})

func conformanceConfig(name string, serviceType corev1.ServiceType) *v1alpha1.GatewayClassConfig {
	return &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.GatewayClassConfigSpec{
			ConformanceMode: true,
			Conformance:     v1alpha1.ConformanceSpec{ServiceType: serviceType},
		},
	}
}

func gatewayClass(name, configName string) *gatewayv1.GatewayClass {
	return &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef: &gatewayv1.ParametersReference{
				Group: gatewayv1.Group(v1alpha1.Group),
				Kind:  gatewayv1.Kind("GatewayClassConfig"),
				Name:  configName,
			},
		},
	}
}

func httpGateway(key types.NamespacedName, className string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				Port:     80,
			}},
		},
	}
}

func systemBackendTLSPolicy(namespace, name, serviceName string) *gatewayv1.BackendTLSPolicy {
	systemCAs := gatewayv1.WellKnownCACertificatesSystem
	return &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: "",
					Kind:  "Service",
					Name:  gatewayv1.ObjectName(serviceName),
				},
			}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				WellKnownCACertificates: &systemCAs,
				Hostname:                gatewayv1.PreciseHostname(serviceName + "." + namespace + ".svc.cluster.local"),
			},
		},
	}
}

func httpRoute(key, gatewayKey types.NamespacedName, serviceName string) *gatewayv1.HTTPRoute {
	pathType := gatewayv1.PathMatchPathPrefix
	path := "/"
	port := gatewayv1.PortNumber(8080)
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{
				Name: gatewayv1.ObjectName(gatewayKey.Name),
			}}},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: gatewayv1.ObjectName(serviceName),
						Port: &port,
					},
				}}},
			}},
		},
	}
}

func listenerStatusByName(listeners []gatewayv1.ListenerStatus, name gatewayv1.SectionName) *gatewayv1.ListenerStatus {
	for index := range listeners {
		if listeners[index].Name == name {
			return &listeners[index]
		}
	}
	return nil
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}
