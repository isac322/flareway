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
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, gatewayKey, &gateway)).To(gomega.Succeed())
			expectedOwner := metav1.NewControllerRef(&gateway, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway"))
			g.Expect(xdsSecret.OwnerReferences).To(gomega.Equal([]metav1.OwnerReference{*expectedOwner}))
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
			g.Expect(gateway.Status.Addresses).To(gomega.HaveLen(1))
			g.Expect(gateway.Status.Addresses[0].Value).To(gomega.Equal("gateway.example.test"))
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

var _ = ginkgo.Describe("Gateway xDS client certificate ownership", func() {
	ginkgo.It("creates the Secret with the canonical Gateway controller reference", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
		}}
		kube := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
		reconciler := &GatewayReconciler{Client: kube, Scheme: scheme}

		gomega.Expect(reconciler.ensureXDSClientCertificate(context.Background(), gateway)).To(gomega.Succeed())

		var secret corev1.Secret
		gomega.Expect(kube.Get(
			context.Background(),
			types.NamespacedName{Namespace: gateway.Namespace, Name: "flareway-xds-" + gateway.Name},
			&secret,
		)).To(gomega.Succeed())
		expected := metav1.NewControllerRef(gateway, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway"))
		gomega.Expect(secret.OwnerReferences).To(gomega.Equal([]metav1.OwnerReference{*expected}))
	})

	ginkgo.It("rejects a Secret controlled by a different Gateway UID without modifying it", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
		}}
		foreignGateway := gateway.DeepCopy()
		foreignGateway.UID = "foreign-gateway-uid"
		collision := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gateway.Namespace,
				Name:      "flareway-xds-" + gateway.Name,
				Labels:    map[string]string{"foreign": "keep"},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(foreignGateway, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway")),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"foreign": []byte("keep"), corev1.TLSCertKey: []byte("invalid")},
		}
		kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(collision).Build()
		reconciler := &GatewayReconciler{Client: kube, Scheme: scheme}

		err := reconciler.ensureXDSClientCertificate(context.Background(), gateway)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

		var preserved corev1.Secret
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(collision), &preserved)).To(gomega.Succeed())
		gomega.Expect(preserved.Type).To(gomega.Equal(collision.Type))
		gomega.Expect(preserved.Data).To(gomega.Equal(collision.Data))
		gomega.Expect(preserved.Labels).To(gomega.Equal(collision.Labels))
		gomega.Expect(preserved.OwnerReferences).To(gomega.Equal(collision.OwnerReferences))
	})
})

var _ = ginkgo.Describe("Gateway dataplane object ownership", func() {
	var scheme *runtime.Scheme
	var gateway *gatewayv1.Gateway

	ginkgo.BeforeEach(func() {
		scheme = runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gateway = &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant",
			Name:      "gateway",
			UID:       "gateway-uid",
		}}
	})

	ginkgo.It("creates the desired object with the Gateway controller reference", func() {
		kube := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
		_, desired := configMapDataplaneObjects(gateway.Namespace, "dataplane")

		gomega.Expect(reconcileGatewayOwnedObject(context.Background(), kube, scheme, gateway, desired)).To(gomega.Succeed())

		var created corev1.ConfigMap
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(desired), &created)).To(gomega.Succeed())
		expectedOwner := metav1.NewControllerRef(gateway, gatewayControllerGVK())
		gomega.Expect(created.OwnerReferences).To(gomega.Equal([]metav1.OwnerReference{*expectedOwner}))
		gomega.Expect(created.Data).To(gomega.Equal(map[string]string{"desired": "value"}))
	})

	ginkgo.It("updates an object controlled by the exact Gateway identity", func() {
		currentObject, desired := configMapDataplaneObjects(gateway.Namespace, "dataplane")
		current := currentObject.(*corev1.ConfigMap)
		current.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(gateway, gatewayControllerGVK()),
		}
		kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build()

		gomega.Expect(reconcileGatewayOwnedObject(context.Background(), kube, scheme, gateway, desired)).To(gomega.Succeed())

		var updated corev1.ConfigMap
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(desired), &updated)).To(gomega.Succeed())
		gomega.Expect(updated.Data).To(gomega.Equal(map[string]string{"desired": "value", "foreign": "keep"}))
		gomega.Expect(metav1.GetControllerOf(&updated)).To(gomega.Equal(metav1.NewControllerRef(
			gateway,
			gatewayControllerGVK(),
		)))
	})

	ginkgo.DescribeTable("preserves ownerless and foreign same-name objects",
		func(objects dataplaneObjectFactory, foreignOwner bool) {
			current, desired := objects(gateway.Namespace, "dataplane")
			if foreignOwner {
				foreignGateway := gateway.DeepCopy()
				foreignGateway.UID = "foreign-gateway-uid"
				current.SetOwnerReferences([]metav1.OwnerReference{
					*metav1.NewControllerRef(foreignGateway, gatewayControllerGVK()),
				})
			}
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build()
			before := current.DeepCopyObject().(client.Object)
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(current), before)).To(gomega.Succeed())

			err := reconcileGatewayOwnedObject(context.Background(), kube, scheme, gateway, desired)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

			after := current.DeepCopyObject().(client.Object)
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(current), after)).To(gomega.Succeed())
			gomega.Expect(after).To(gomega.Equal(before))
		},
		ginkgo.Entry("ownerless ConfigMap", dataplaneObjectFactory(configMapDataplaneObjects), false),
		ginkgo.Entry("foreign ConfigMap", dataplaneObjectFactory(configMapDataplaneObjects), true),
		ginkgo.Entry("ownerless Deployment", dataplaneObjectFactory(deploymentDataplaneObjects), false),
		ginkgo.Entry("foreign Deployment", dataplaneObjectFactory(deploymentDataplaneObjects), true),
		ginkgo.Entry("ownerless Service", dataplaneObjectFactory(serviceDataplaneObjects), false),
		ginkgo.Entry("foreign Service", dataplaneObjectFactory(serviceDataplaneObjects), true),
		ginkgo.Entry("ownerless PodDisruptionBudget", dataplaneObjectFactory(pdbDataplaneObjects), false),
		ginkgo.Entry("foreign PodDisruptionBudget", dataplaneObjectFactory(pdbDataplaneObjects), true),
		ginkgo.Entry("ownerless NetworkPolicy", dataplaneObjectFactory(networkPolicyDataplaneObjects), false),
		ginkgo.Entry("foreign NetworkPolicy", dataplaneObjectFactory(networkPolicyDataplaneObjects), true),
	)

	ginkgo.DescribeTable("requires every field of the Gateway controller identity",
		func(mutate func(*metav1.OwnerReference)) {
			currentObject, desired := configMapDataplaneObjects(gateway.Namespace, "dataplane")
			current := currentObject.(*corev1.ConfigMap)
			owner := metav1.NewControllerRef(gateway, gatewayControllerGVK())
			mutate(owner)
			current.OwnerReferences = []metav1.OwnerReference{*owner}
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build()
			before := current.DeepCopy()
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(current), before)).To(gomega.Succeed())

			err := reconcileGatewayOwnedObject(context.Background(), kube, scheme, gateway, desired)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

			var after corev1.ConfigMap
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(current), &after)).To(gomega.Succeed())
			gomega.Expect(&after).To(gomega.Equal(before))
		},
		ginkgo.Entry("API version", func(owner *metav1.OwnerReference) { owner.APIVersion = "gateway.networking.k8s.io/v1beta1" }),
		ginkgo.Entry("kind", func(owner *metav1.OwnerReference) { owner.Kind = "GatewayClass" }),
		ginkgo.Entry("name", func(owner *metav1.OwnerReference) { owner.Name = "other-gateway" }),
		ginkgo.Entry("UID", func(owner *metav1.OwnerReference) { owner.UID = "other-gateway-uid" }),
		ginkgo.Entry("controller flag", func(owner *metav1.OwnerReference) { owner.Controller = nil }),
	)

	ginkgo.It("re-reads and rejects an ownerless object that wins the create race", func() {
		backing := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
		collision, desired := configMapDataplaneObjects(gateway.Namespace, "dataplane")
		racing := &dataplaneCreateRaceClient{Client: backing, collision: collision}

		err := reconcileGatewayOwnedObject(context.Background(), racing, scheme, gateway, desired)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

		after := collision.DeepCopyObject().(client.Object)
		gomega.Expect(backing.Get(context.Background(), client.ObjectKeyFromObject(collision), after)).To(gomega.Succeed())
		gomega.Expect(after).To(gomega.Equal(racing.created))
	})

	ginkgo.It("returns a conflict when ownership changes between validation and apply", func() {
		currentObject, desired := configMapDataplaneObjects(gateway.Namespace, "dataplane")
		current := currentObject.(*corev1.ConfigMap)
		current.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(gateway, gatewayControllerGVK()),
		}
		backing := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build()
		foreignGateway := gateway.DeepCopy()
		foreignGateway.UID = "foreign-gateway-uid"
		racing := &concurrentDataplaneOwnerClient{
			Client: backing,
			beforeApply: func(ctx context.Context) error {
				var raced corev1.ConfigMap
				if err := backing.Get(ctx, client.ObjectKeyFromObject(current), &raced); err != nil {
					return err
				}
				raced.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(foreignGateway, gatewayControllerGVK()),
				}
				return backing.Update(ctx, &raced)
			},
		}

		err := reconcileGatewayOwnedObject(context.Background(), racing, scheme, gateway, desired)
		gomega.Expect(apierrors.IsConflict(err)).To(gomega.BeTrue(), "expected conflict, got %v", err)

		var preserved corev1.ConfigMap
		gomega.Expect(backing.Get(context.Background(), client.ObjectKeyFromObject(current), &preserved)).To(gomega.Succeed())
		gomega.Expect(preserved.Data).To(gomega.Equal(map[string]string{"foreign": "keep"}))
		gomega.Expect(metav1.GetControllerOf(&preserved)).To(gomega.Equal(metav1.NewControllerRef(
			foreignGateway,
			gatewayControllerGVK(),
		)))
	})
})

var _ = ginkgo.Describe("Gateway Direct tunnel admission", func() {
	ginkgo.DescribeTable("rejects the tunnel without claiming or programming it",
		func(explicitReference bool) {
			scheme := runtime.NewScheme()
			gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
			gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
			gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

			gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
			config := &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: "config"}}
			class := gatewayClass("class", config.Name)
			gateway := httpGateway(gatewayKey, class.Name)
			gateway.UID = "gateway-uid"
			gateway.Generation = 3
			addressType := gatewayv1.HostnameAddressType
			gateway.Status = gatewayv1.GatewayStatus{
				Addresses: []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "stale.example.test"}},
				Conditions: []metav1.Condition{
					{
						Type:               string(gatewayv1.GatewayConditionAccepted),
						Status:             metav1.ConditionTrue,
						ObservedGeneration: 2,
						Reason:             string(gatewayv1.GatewayReasonAccepted),
						Message:            "previously accepted",
					},
					{
						Type:               string(gatewayv1.GatewayConditionProgrammed),
						Status:             metav1.ConditionTrue,
						ObservedGeneration: 2,
						Reason:             string(gatewayv1.GatewayReasonProgrammed),
						Message:            "previously programmed",
					},
				},
				Listeners: []gatewayv1.ListenerStatus{{Name: "http"}},
			}
			tunnelName := gateway.Name
			if explicitReference {
				tunnelName = "direct"
				gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: v1alpha1.Group,
						Kind:  "CloudflareTunnel",
						Name:  tunnelName,
					},
				}
			}
			tunnel := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: gateway.Namespace},
				Spec: v1alpha1.CloudflareTunnelSpec{
					AccountRef: corev1.LocalObjectReference{Name: "account"},
					Configuration: v1alpha1.CloudflareTunnelConfiguration{
						Mode:   v1alpha1.CloudflareTunnelConfigurationModeDirect,
						Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{},
					},
				},
				Status: v1alpha1.CloudflareTunnelStatus{
					TunnelID:      "11111111-1111-1111-1111-111111111111",
					ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, DesiredHash: "direct"},
				},
			}
			beforeTunnel := tunnel.DeepCopy()
			replicas := int32(2)
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name: "flareway-gw-" + gateway.Name, Namespace: gateway.Namespace,
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gateway, gatewayControllerGVK())},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &replicas},
			}
			snapshots := newFakeSnapshotPublisher()
			snapshots.versions[gatewayKey.String()] = "stale"
			kube := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
				WithObjects(config, class, gateway, tunnel, deployment).
				Build()
			reconciler := &GatewayReconciler{Client: kube, Scheme: scheme, Snapshots: snapshots}

			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))

			var observedGateway gatewayv1.Gateway
			gomega.Expect(kube.Get(context.Background(), gatewayKey, &observedGateway)).To(gomega.Succeed())
			accepted := findCondition(observedGateway.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
			gomega.Expect(accepted).NotTo(gomega.BeNil())
			gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			gomega.Expect(accepted.Reason).To(gomega.Equal(gatewayReasonUnsupportedValue))
			gomega.Expect(accepted.ObservedGeneration).To(gomega.Equal(gateway.Generation))
			gomega.Expect(accepted.Message).To(gomega.ContainSubstring("Direct configuration mode"))
			programmed := findCondition(observedGateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			gomega.Expect(programmed).NotTo(gomega.BeNil())
			gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			gomega.Expect(observedGateway.Status.Addresses).To(gomega.BeEmpty())
			gomega.Expect(observedGateway.Status.Listeners).To(gomega.BeEmpty())

			var observedTunnel v1alpha1.CloudflareTunnel
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &observedTunnel)).To(gomega.Succeed())
			gomega.Expect(observedTunnel.OwnerReferences).To(gomega.Equal(beforeTunnel.OwnerReferences))
			gomega.Expect(observedTunnel.Spec).To(gomega.Equal(beforeTunnel.Spec))
			gomega.Expect(observedTunnel.Status).To(gomega.Equal(beforeTunnel.Status))
			gomega.Expect(snapshots.Version(gatewayKey.String())).To(gomega.BeEmpty())

			var observedDeployment appsv1.Deployment
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &observedDeployment)).To(gomega.Succeed())
			gomega.Expect(observedDeployment.Spec.Replicas).NotTo(gomega.BeNil())
			gomega.Expect(*observedDeployment.Spec.Replicas).To(gomega.Equal(int32(0)))
			var services corev1.ServiceList
			gomega.Expect(kube.List(context.Background(), &services, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
			gomega.Expect(services.Items).To(gomega.BeEmpty())
			var configMaps corev1.ConfigMapList
			gomega.Expect(kube.List(context.Background(), &configMaps, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
			gomega.Expect(configMaps.Items).To(gomega.BeEmpty())
			var secrets corev1.SecretList
			gomega.Expect(kube.List(context.Background(), &secrets, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
			gomega.Expect(secrets.Items).To(gomega.BeEmpty())
		},
		ginkgo.Entry("for the default tunnel named after the Gateway", false),
		ginkgo.Entry("for an explicitly referenced tunnel", true),
	)
})

var _ = ginkgo.Describe("Gateway soft-deleted tunnel admission", func() {
	ginkgo.It("clears publication and cannot reverse the Tunnel controller drain", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

		gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
		config := defaultGatewayClassConfig()
		config.Name = "config"
		class := gatewayClass("class", config.Name)
		gateway := httpGateway(gatewayKey, class.Name)
		gateway.UID = "gateway-uid"
		gateway.Generation = 3
		gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			},
		}
		addressType := gatewayv1.HostnameAddressType
		gateway.Status = gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "stale.cfargotunnel.com"}},
			Conditions: []metav1.Condition{{
				Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue,
				Reason: string(gatewayv1.GatewayReasonProgrammed), ObservedGeneration: 2,
			}},
		}
		deletedAt := metav1.NewTime(time.Now().Round(0))
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: gateway.Namespace, UID: "tunnel-uid"},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
			Status: v1alpha1.CloudflareTunnelStatus{
				TunnelID:                "remote-id",
				DeletedAt:               &deletedAt,
				OwnershipVerified:       true,
				ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "connector-token"},
				GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name},
				GatewayUID:              gateway.UID,
				ConfigVersion:           v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7, DesiredHash: "preserve"},
				Hostnames:               []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardForwarding}},
				Listeners:               []v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}},
			},
		}
		beforeTunnel := tunnel.DeepCopy()
		replicas := int32(2)
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + gateway.Name, Namespace: gateway.Namespace,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gateway, gatewayControllerGVK())},
			},
			Spec: appsv1.DeploymentSpec{Replicas: &replicas},
		}
		snapshots := newFakeSnapshotPublisher()
		snapshots.versions[gatewayKey.String()] = "stale"
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
			WithObjects(config, class, gateway, tunnel, deployment).
			Build()
		reconciler := &GatewayReconciler{Client: kube, Scheme: scheme, Snapshots: snapshots}

		result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.RequeueAfter).To(gomega.Equal(programmedRequeue))
		gomega.Expect(snapshots.Version(gatewayKey.String())).To(gomega.BeEmpty())

		var observedGateway gatewayv1.Gateway
		gomega.Expect(kube.Get(context.Background(), gatewayKey, &observedGateway)).To(gomega.Succeed())
		gomega.Expect(observedGateway.Status.Addresses).To(gomega.BeEmpty())
		programmed := findCondition(observedGateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		gomega.Expect(programmed).NotTo(gomega.BeNil())
		gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(programmed.Message).To(gomega.ContainSubstring("remotely deleted"))

		var observedDeployment appsv1.Deployment
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &observedDeployment)).To(gomega.Succeed())
		gomega.Expect(observedDeployment.OwnerReferences).To(gomega.Equal(deployment.OwnerReferences))
		gomega.Expect(observedDeployment.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*observedDeployment.Spec.Replicas).To(gomega.Equal(int32(0)))

		var observedTunnel v1alpha1.CloudflareTunnel
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &observedTunnel)).To(gomega.Succeed())
		gomega.Expect(observedTunnel.Status.ConfigVersion).To(gomega.Equal(beforeTunnel.Status.ConfigVersion))
		gomega.Expect(observedTunnel.Status.Hostnames).To(gomega.Equal(beforeTunnel.Status.Hostnames))
		gomega.Expect(observedTunnel.Status.Listeners).To(gomega.Equal(beforeTunnel.Status.Listeners))

		var services corev1.ServiceList
		gomega.Expect(kube.List(context.Background(), &services, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
		gomega.Expect(services.Items).To(gomega.BeEmpty())
		var configMaps corev1.ConfigMapList
		gomega.Expect(kube.List(context.Background(), &configMaps, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
		gomega.Expect(configMaps.Items).To(gomega.BeEmpty())
		var secrets corev1.SecretList
		gomega.Expect(kube.List(context.Background(), &secrets, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
		gomega.Expect(secrets.Items).To(gomega.BeEmpty())
		var pdbs policyv1.PodDisruptionBudgetList
		gomega.Expect(kube.List(context.Background(), &pdbs, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
		gomega.Expect(pdbs.Items).To(gomega.BeEmpty())
		var networkPolicies networkingv1.NetworkPolicyList
		gomega.Expect(kube.List(context.Background(), &networkPolicies, client.InNamespace(gateway.Namespace))).To(gomega.Succeed())
		gomega.Expect(networkPolicies.Items).To(gomega.BeEmpty())
	})
})

var _ = ginkgo.Describe("Gateway dependency loss", func() {
	type dependencyFixture struct {
		gateway    *gatewayv1.Gateway
		class      *gatewayv1.GatewayClass
		config     *v1alpha1.GatewayClassConfig
		tunnel     *v1alpha1.CloudflareTunnel
		deployment *appsv1.Deployment
		extra      []client.Object
	}

	newDependencyFixture := func() *dependencyFixture {
		gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
		config := defaultGatewayClassConfig()
		config.Name = "config"
		class := gatewayClass("class", config.Name)
		gateway := httpGateway(gatewayKey, class.Name)
		gateway.UID = "gateway-uid"
		gateway.Generation = 3
		hostname := gatewayv1.Hostname("app.example.com")
		gateway.Spec.Listeners[0].Hostname = &hostname
		gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			},
		}
		addressType := gatewayv1.HostnameAddressType
		gateway.Status = gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "stale.cfargotunnel.com"}},
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.GatewayConditionAccepted),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 2,
					Reason:             string(gatewayv1.GatewayReasonAccepted),
					Message:            "previously accepted",
				},
				{
					Type:               string(gatewayv1.GatewayConditionProgrammed),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 2,
					Reason:             string(gatewayv1.GatewayReasonProgrammed),
					Message:            "previously programmed",
				},
			},
			Listeners: []gatewayv1.ListenerStatus{{Name: "http"}},
		}
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: gateway.Namespace, UID: "tunnel-uid"},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
			Status: v1alpha1.CloudflareTunnelStatus{
				TunnelID:                "remote-id",
				OwnershipVerified:       true,
				ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "connector-token"},
				GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name},
				GatewayUID:              gateway.UID,
			},
		}
		replicas := int32(2)
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + gateway.Name, Namespace: gateway.Namespace,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gateway, gatewayControllerGVK())},
			},
			Spec: appsv1.DeploymentSpec{Replicas: &replicas},
		}
		return &dependencyFixture{gateway: gateway, class: class, config: config, tunnel: tunnel, deployment: deployment}
	}

	expectTerminalRejection := func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
		gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())

		var observed gatewayv1.Gateway
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed)).To(gomega.Succeed())
		accepted := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(accepted).NotTo(gomega.BeNil())
		gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(accepted.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalidParameters)))
		gomega.Expect(accepted.ObservedGeneration).To(gomega.Equal(f.gateway.Generation))
		programmed := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		gomega.Expect(programmed).NotTo(gomega.BeNil())
		gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalid)))
		gomega.Expect(observed.Status.Addresses).To(gomega.BeEmpty())
		gomega.Expect(observed.Status.Listeners).To(gomega.BeEmpty())
	}

	expectDataplaneScaledToZero := func(kube client.Client, f *dependencyFixture) {
		var observed appsv1.Deployment
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.deployment), &observed)).To(gomega.Succeed())
		gomega.Expect(observed.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*observed.Spec.Replicas).To(gomega.Equal(int32(0)))
	}

	expectDataplanePreserved := func(kube client.Client, f *dependencyFixture) {
		var observed appsv1.Deployment
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.deployment), &observed)).To(gomega.Succeed())
		gomega.Expect(observed.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*observed.Spec.Replicas).To(gomega.Equal(*f.deployment.Spec.Replicas))
		gomega.Expect(observed.OwnerReferences).To(gomega.Equal(f.deployment.OwnerReferences))
	}
	expectPreservedProgrammed := func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
		gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.Equal("stale"))

		var observed gatewayv1.Gateway
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed)).To(gomega.Succeed())
		programmed := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		gomega.Expect(programmed).NotTo(gomega.BeNil())
		gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(observed.Status.Addresses).To(gomega.Equal(f.gateway.Status.Addresses))

		expectDataplanePreserved(kube, f)
	}
	expectWaitingUnprogrammed := func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, message string, result ctrl.Result, err error) {
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result).To(gomega.Equal(ctrl.Result{RequeueAfter: programmedRequeue}))
		gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())

		var observed gatewayv1.Gateway
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed)).To(gomega.Succeed())
		accepted := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(accepted).NotTo(gomega.BeNil())
		gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))
		programmed := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		gomega.Expect(programmed).NotTo(gomega.BeNil())
		gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonPending)))
		gomega.Expect(programmed.Message).To(gomega.ContainSubstring(message))
		gomega.Expect(observed.Status.Addresses).To(gomega.BeEmpty())
	}

	ginkgo.DescribeTable("retracts publication and reports the lost dependency",
		func(arrange func(*dependencyFixture), assert func(client.Client, *dependencyFixture, *fakeSnapshotPublisher, ctrl.Result, error)) {
			scheme := runtime.NewScheme()
			gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
			gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
			gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

			f := newDependencyFixture()
			arrange(f)
			objects := []client.Object{f.gateway}
			if f.class != nil {
				objects = append(objects, f.class)
			}
			if f.config != nil {
				objects = append(objects, f.config)
			}
			if f.tunnel != nil {
				objects = append(objects, f.tunnel)
			}
			if f.deployment != nil {
				objects = append(objects, f.deployment)
			}
			objects = append(objects, f.extra...)
			gatewayKey := client.ObjectKeyFromObject(f.gateway)
			snapshots := newFakeSnapshotPublisher()
			snapshots.versions[gatewayKey.String()] = "stale"
			kube := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
				WithObjects(objects...).
				Build()
			reconciler := &GatewayReconciler{Client: kube, Scheme: scheme, Snapshots: snapshots}

			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
			assert(kube, f, snapshots, result, err)
		},
		ginkgo.Entry("clears publication and scales the owned dataplane to zero when the GatewayClass is missing",
			func(f *dependencyFixture) { f.class = nil },
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
				gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("clears publication and scales the owned dataplane to zero when the GatewayClass belongs to a foreign controller",
			func(f *dependencyFixture) {
				f.class.Spec.ControllerName = "example.net/other-controller"
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
				gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("rejects a Gateway whose explicit CloudflareTunnel is missing and scales its owned dataplane to zero",
			func(f *dependencyFixture) { f.tunnel = nil },
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectTerminalRejection(kube, f, snapshots, result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("leaves a foreign-owned dataplane Deployment running when the explicit CloudflareTunnel is missing",
			func(f *dependencyFixture) {
				f.tunnel = nil
				foreignGateway := f.gateway.DeepCopy()
				foreignGateway.UID = "recreated-gateway-uid"
				f.deployment.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(foreignGateway, gatewayControllerGVK()),
				}
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectTerminalRejection(kube, f, snapshots, result, err)
				expectDataplanePreserved(kube, f)
			}),
		ginkgo.Entry("leaves an ownerless dataplane Deployment running when the explicit CloudflareTunnel is missing",
			func(f *dependencyFixture) {
				f.tunnel = nil
				f.deployment.OwnerReferences = nil
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectTerminalRejection(kube, f, snapshots, result, err)
				expectDataplanePreserved(kube, f)
			}),
		ginkgo.Entry("rejects a Gateway whose GatewayClassConfig is missing and scales its owned dataplane to zero",
			func(f *dependencyFixture) { f.config = nil },
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectTerminalRejection(kube, f, snapshots, result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("rejects a Gateway whose GatewayClass parametersRef is unsupported and scales its owned dataplane to zero",
			func(f *dependencyFixture) {
				f.class.Spec.ParametersRef = &gatewayv1.ParametersReference{
					Group: "example.net", Kind: "OtherConfig", Name: "other",
				}
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectTerminalRejection(kube, f, snapshots, result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("keeps a valid Gateway Accepted but unprogrammed and stops polling while its CloudflareAccount is missing",
			func(_ *dependencyFixture) {},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
				gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())

				var observed gatewayv1.Gateway
				gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed)).To(gomega.Succeed())
				accepted := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
				gomega.Expect(accepted).NotTo(gomega.BeNil())
				gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))
				programmed := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
				gomega.Expect(programmed).NotTo(gomega.BeNil())
				gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))

				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("terminally rejects a Gateway whose infrastructure parametersRef is unsupported and scales its owned dataplane to zero",
			func(f *dependencyFixture) {
				f.gateway.Spec.Infrastructure.ParametersRef = &gatewayv1.LocalParametersReference{
					Group: "example.net", Kind: "OtherTunnel", Name: "other",
				}
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
				gomega.Expect(snapshots.Version(client.ObjectKeyFromObject(f.gateway).String())).To(gomega.BeEmpty())

				var observed gatewayv1.Gateway
				gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(f.gateway), &observed)).To(gomega.Succeed())
				accepted := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
				gomega.Expect(accepted).NotTo(gomega.BeNil())
				gomega.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
				gomega.Expect(accepted.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalidParameters)))
				programmed := findCondition(observed.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
				gomega.Expect(programmed).NotTo(gomega.BeNil())
				gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
				gomega.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonInvalid)))

				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("clears publication but keeps the owned dataplane running while the verified Tunnel waits for connector credentials",
			func(f *dependencyFixture) {
				f.tunnel.Status.ConnectorTokenSecretRef = nil
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectWaitingUnprogrammed(kube, f, snapshots, "waiting for verified connector credentials", result, err)
				expectDataplanePreserved(kube, f)
			}),
		ginkgo.Entry("clears publication but keeps the owned dataplane running while the verified Tunnel waits for a remote tunnel ID",
			func(f *dependencyFixture) {
				f.tunnel.Status.TunnelID = ""
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectWaitingUnprogrammed(kube, f, snapshots, "waiting for verified connector credentials", result, err)
				expectDataplanePreserved(kube, f)
			}),
		ginkgo.Entry("clears publication and scales the owned dataplane to zero while the Tunnel has not verified remote ownership",
			func(f *dependencyFixture) {
				f.tunnel.Status.OwnershipVerified = false
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectWaitingUnprogrammed(kube, f, snapshots, "has not verified remote ownership", result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("clears publication and scales the owned dataplane to zero when the Tunnel is ObserveOnly",
			func(f *dependencyFixture) {
				f.tunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectWaitingUnprogrammed(kube, f, snapshots, "ObserveOnly", result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
		ginkgo.Entry("clears publication and scales the owned dataplane to zero when the Tunnel is owned by another Gateway",
			func(f *dependencyFixture) {
				owner := httpGateway(types.NamespacedName{Namespace: f.gateway.Namespace, Name: "owner"}, f.class.Name)
				owner.UID = "owner-uid"
				owner.Spec.Infrastructure = f.gateway.Spec.Infrastructure.DeepCopy()
				f.extra = append(f.extra, owner)
				f.tunnel.Status.GatewayRef = &corev1.LocalObjectReference{Name: owner.Name}
				f.tunnel.Status.GatewayUID = owner.UID
			},
			func(kube client.Client, f *dependencyFixture, snapshots *fakeSnapshotPublisher, result ctrl.Result, err error) {
				expectWaitingUnprogrammed(kube, f, snapshots, "owned by Gateway", result, err)
				expectDataplaneScaledToZero(kube, f)
			}),
	)

	ginkgo.DescribeTable("returns transient dependency lookup failures as errors",
		func(kind string) {
			scheme := runtime.NewScheme()
			gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
			gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
			gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

			f := newDependencyFixture()
			f.extra = append(f.extra, &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}})
			objects := []client.Object{f.gateway, f.class, f.config, f.tunnel, f.deployment}
			objects = append(objects, f.extra...)
			gatewayKey := client.ObjectKeyFromObject(f.gateway)
			snapshots := newFakeSnapshotPublisher()
			snapshots.versions[gatewayKey.String()] = "stale"
			kube := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}).
				WithObjects(objects...).
				Build()
			reconciler := &GatewayReconciler{
				Client:    &getErrorClient{Client: kube, kind: kind, err: errors.New("injected transport failure")},
				Scheme:    scheme,
				Snapshots: snapshots,
			}

			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
			expectPreservedProgrammed(kube, f, snapshots, result, err)
		},
		ginkgo.Entry("for the referenced CloudflareTunnel", "CloudflareTunnel"),
		ginkgo.Entry("for the referenced CloudflareAccount", "CloudflareAccount"),
		ginkgo.Entry("for the referenced GatewayClassConfig", "GatewayClassConfig"),
	)

	ginkgo.It("restores the configured dataplane replicas when a valid reconcile follows retraction", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

		gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
		config := conformanceConfig("config", corev1.ServiceTypeClusterIP)
		class := gatewayClass("class", config.Name)
		gateway := httpGateway(gatewayKey, class.Name)
		gateway.UID = "gateway-uid"
		gateway.Generation = 3
		replicas := int32(2)
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + gateway.Name, Namespace: gateway.Namespace,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gateway, gatewayControllerGVK())},
			},
			Spec: appsv1.DeploymentSpec{Replicas: &replicas},
		}
		snapshots := newFakeSnapshotPublisher()
		snapshots.versions[gatewayKey.String()] = "stale"
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&gatewayv1.Gateway{}).
			WithObjects(class, gateway, deployment).
			Build()
		reconciler := &GatewayReconciler{Client: kube, Scheme: scheme, Snapshots: snapshots}

		// The referenced GatewayClassConfig is confirmed missing: the Gateway is
		// terminally rejected and its owned dataplane scales to zero.
		result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result).To(gomega.Equal(ctrl.Result{}))
		var retracted appsv1.Deployment
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &retracted)).To(gomega.Succeed())
		gomega.Expect(retracted.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*retracted.Spec.Replicas).To(gomega.Equal(int32(0)))

		// Recreating the config lets the next reconcile restore the desired
		// replicas through the normal owned-object path.
		gomega.Expect(kube.Create(context.Background(), config)).To(gomega.Succeed())
		result, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: gatewayKey})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.RequeueAfter).To(gomega.Equal(programmedRequeue))
		var restored appsv1.Deployment
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &restored)).To(gomega.Succeed())
		gomega.Expect(restored.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*restored.Spec.Replicas).To(gomega.Equal(int32(2)))
	})
})

// getErrorClient fails Get calls for one object kind so tests can exercise
// transient API failures that must surface as reconcile errors.
type getErrorClient struct {
	client.Client
	kind string
	err  error
}

func (c *getErrorClient) Get(ctx context.Context, key types.NamespacedName, object client.Object, options ...client.GetOption) error {
	switch object.(type) {
	case *v1alpha1.CloudflareTunnel:
		if c.kind == "CloudflareTunnel" {
			return c.err
		}
	case *v1alpha1.CloudflareAccount:
		if c.kind == "CloudflareAccount" {
			return c.err
		}
	case *v1alpha1.GatewayClassConfig:
		if c.kind == "GatewayClassConfig" {
			return c.err
		}
	}
	return c.Client.Get(ctx, key, object, options...)
}

var _ = ginkgo.Describe("AUD handoff identity", func() {
	ginkgo.It("uses bounded injective labels for namespaced names that collided under delimiter concatenation", func() {
		left := types.NamespacedName{Namespace: "a--b", Name: "c"}
		right := types.NamespacedName{Namespace: "a", Name: "b--c"}
		gomega.Expect(left.Namespace + "--" + left.Name).To(gomega.Equal(right.Namespace + "--" + right.Name))
		gomega.Expect(audIdentityLabel(left, "same-uid")).NotTo(gomega.Equal(audIdentityLabel(right, "same-uid")))
		gomega.Expect(audIdentityLabel(left, "same-uid")).To(gomega.HaveLen(63))
	})

	ginkgo.It("accepts only exact UID and application ID bindings and rejects duplicate handoffs", func() {
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
		}}
		application := v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "application", UID: "application-uid"},
			Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "application-id"},
		}
		secret := boundAUDSecret("handoff-one", &application, gateway, "audience")
		key := client.ObjectKeyFromObject(&application)

		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{secret}, []v1alpha1.AccessApplication{application}, gateway)).
			To(gomega.HaveKeyWithValue(key, gatewayapi.AUDSecret{AUD: "audience", ApplicationID: "application-id", Ready: true}))

		wrongUID := *secret.DeepCopy()
		wrongUID.Data[v1alpha1.AccessApplicationUIDSecretKey] = []byte("other-uid")
		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{wrongUID}, []v1alpha1.AccessApplication{application}, gateway)).To(gomega.BeEmpty())

		wrongGatewayUID := *secret.DeepCopy()
		wrongGatewayUID.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey] = []byte("other-gateway-uid")
		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{wrongGatewayUID}, []v1alpha1.AccessApplication{application}, gateway)).To(gomega.BeEmpty())

		wrongNamespacedName := *secret.DeepCopy()
		wrongNamespacedName.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey] = []byte("other/application")
		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{wrongNamespacedName}, []v1alpha1.AccessApplication{application}, gateway)).To(gomega.BeEmpty())

		wrongApplicationID := *secret.DeepCopy()
		wrongApplicationID.Data[v1alpha1.AccessApplicationIDSecretKey] = []byte("other-application")
		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{wrongApplicationID}, []v1alpha1.AccessApplication{application}, gateway)).To(gomega.BeEmpty())

		duplicate := *secret.DeepCopy()
		duplicate.Name = "handoff-two"
		duplicate.Data[v1alpha1.AccessApplicationAUDSecretKey] = []byte("conflicting-audience")
		gomega.Expect(verifiedAUDSecrets([]corev1.Secret{secret, duplicate}, []v1alpha1.AccessApplication{application}, gateway)).To(gomega.BeEmpty())
	})

	ginkgo.It("trusts only the configured operator handoff while preserving cross-namespace listener Secret mapping", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "victim", UID: "gateway-uid",
		}}
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "application", UID: "application-uid"},
			Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "application-id"},
		}
		listenerGateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other-tenant", Name: "listener-gateway", UID: "listener-gateway-uid"},
			Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
				Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			}}},
		}
		tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{
			Namespace: gateway.Namespace, Name: gateway.Name,
		}}
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&v1alpha1.CloudflareTunnel{}).
			WithObjects(gateway, application, listenerGateway, tunnel).
			WithIndex(&gatewayv1.Gateway{}, gatewayListenerSecretIndex, func(object client.Object) []string {
				return gatewayListenerSecretKeys(object.(*gatewayv1.Gateway))
			}).
			Build()
		reconciler := &GatewayReconciler{
			Client: kube, OperatorNamespace: "trusted-operator",
		}
		applicationReconciler := &AccessApplicationReconciler{
			Client: kube, OperatorNamespace: reconciler.OperatorNamespace,
		}
		genuine := boundAUDSecret(
			accessAUDSecretName(application, client.ObjectKeyFromObject(gateway)),
			application,
			gateway,
			"audience",
		)
		genuine.Namespace = reconciler.OperatorNamespace

		invalid := []struct {
			name   string
			mutate func(*corev1.Secret)
		}{
			{name: "tenant namespace", mutate: func(secret *corev1.Secret) {
				secret.Namespace = gateway.Namespace
			}},
			{name: "non-deterministic name", mutate: func(secret *corev1.Secret) {
				secret.Name = "forged-handoff"
			}},
			{name: "application namespaced name", mutate: func(secret *corev1.Secret) {
				secret.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey] = []byte("tenant/other-application")
			}},
			{name: "application UID", mutate: func(secret *corev1.Secret) {
				secret.Data[v1alpha1.AccessApplicationUIDSecretKey] = []byte("other-application-uid")
			}},
			{name: "gateway namespaced name", mutate: func(secret *corev1.Secret) {
				secret.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey] = []byte("tenant/other-gateway")
			}},
			{name: "gateway UID", mutate: func(secret *corev1.Secret) {
				secret.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey] = []byte("other-gateway-uid")
			}},
			{name: "application identity label", mutate: func(secret *corev1.Secret) {
				secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel] = "other-application-label"
			}},
			{name: "gateway identity label", mutate: func(secret *corev1.Secret) {
				secret.Labels[v1alpha1.AccessApplicationGatewayAUDLabel] = "other-gateway-label"
			}},
			{name: "application ID", mutate: func(secret *corev1.Secret) {
				secret.Data[v1alpha1.AccessApplicationIDSecretKey] = []byte("other-application-id")
			}},
		}
		persistedLatches := func() []v1alpha1.CloudflareAUDRevocationLatch {
			var current v1alpha1.CloudflareTunnel
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			return current.Status.AUDRevocations
		}
		for _, test := range invalid {
			ginkgo.By("rejecting a handoff with the wrong " + test.name)
			secret := genuine.DeepCopy()
			test.mutate(secret)
			gomega.Expect(reconciler.mapSecretToGateways(context.Background(), secret)).To(gomega.BeEmpty())
			gomega.Expect(applicationReconciler.mapAUDSecretToApplication(context.Background(), secret)).To(gomega.BeEmpty())
			gomega.Expect(reconciler.latchAUDRevocation(context.Background(), secret)).To(gomega.Succeed())
			gomega.Expect(persistedLatches()).To(gomega.BeEmpty())
		}

		gomega.Expect(reconciler.mapSecretToGateways(context.Background(), &genuine)).To(gomega.ConsistOf(
			ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gateway)},
		))
		gomega.Expect(applicationReconciler.mapAUDSecretToApplication(context.Background(), &genuine)).To(gomega.ConsistOf(
			ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)},
		))
		gomega.Expect(reconciler.latchAUDRevocation(context.Background(), &genuine)).To(gomega.Succeed())
		latches := persistedLatches()
		gomega.Expect(latches).To(gomega.HaveLen(1))
		gomega.Expect(latches[0].Application).To(gomega.Equal(client.ObjectKeyFromObject(application).String()))
		gomega.Expect(latches[0].ApplicationUID).To(gomega.Equal(application.UID))
		listenerSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: listenerGateway.Namespace, Name: "listener-cert",
		}}
		gomega.Expect(reconciler.mapSecretToGateways(context.Background(), listenerSecret)).To(gomega.ConsistOf(
			ctrl.Request{NamespacedName: client.ObjectKeyFromObject(listenerGateway)},
		))
	})

	ginkgo.It("migrates an unambiguous legacy handoff before accepting it", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
		}}
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "application", UID: "application-uid"},
			Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "application-id"},
		}
		legacy := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: dataplane.DefaultOperatorNamespace,
				Name:      accessAUDSecretName(application, client.ObjectKeyFromObject(gateway)),
				Labels: map[string]string{
					v1alpha1.AccessApplicationAUDSecretLabel:  application.Namespace + "--" + application.Name,
					v1alpha1.AccessApplicationGatewayAUDLabel: gateway.Namespace + "--" + gateway.Name,
				},
			},
			Data: map[string][]byte{
				v1alpha1.AccessApplicationAUDSecretKey: []byte("audience"),
				v1alpha1.AccessApplicationIDSecretKey:  []byte(application.Status.ApplicationID),
				accessApplicationAUDReadyKey:           []byte("true"),
			},
		}
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&v1alpha1.AccessApplication{}).
			WithObjects(gateway, application, legacy).
			Build()
		reconciler := &GatewayReconciler{Client: kube}

		_, handoffs, err := reconciler.collectAccessInputs(context.Background(), gateway)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(handoffs).To(gomega.HaveKey(client.ObjectKeyFromObject(application)))

		var migrated corev1.Secret
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(legacy), &migrated)).To(gomega.Succeed())
		gomega.Expect(migrated.Labels[v1alpha1.AccessApplicationAUDSecretLabel]).To(gomega.Equal(applicationAUDIdentityLabel(application)))
		gomega.Expect(migrated.Labels[v1alpha1.AccessApplicationGatewayAUDLabel]).To(gomega.Equal(gatewayAUDIdentityLabel(gateway)))
		gomega.Expect(string(migrated.Data[v1alpha1.AccessApplicationNamespacedNameSecretKey])).To(gomega.Equal(client.ObjectKeyFromObject(application).String()))
		gomega.Expect(string(migrated.Data[v1alpha1.AccessApplicationUIDSecretKey])).To(gomega.Equal(string(application.UID)))
		gomega.Expect(string(migrated.Data[v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey])).To(gomega.Equal(client.ObjectKeyFromObject(gateway).String()))
		gomega.Expect(string(migrated.Data[v1alpha1.AccessApplicationGatewayUIDSecretKey])).To(gomega.Equal(string(gateway.UID)))
	})

	ginkgo.It("shares revocation latches across reconcilers and keeps a newer relatch", func() {
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "shared-gateway", UID: "shared-gateway-uid",
		}}
		application := v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "shared-application", UID: "shared-application-uid"},
			Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "shared-application-id"},
		}
		secret := boundAUDSecret(accessAUDSecretName(&application, client.ObjectKeyFromObject(gateway)), &application, gateway, "audience")
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "shared-gateway"},
			Status: v1alpha1.CloudflareTunnelStatus{
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Applied: 1},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					AccessApplication: client.ObjectKeyFromObject(&application).String(),
					Guard:             v1alpha1.HostnameGuardForwarding,
					AppliedVersion:    1,
				}},
			},
		}
		scheme := runtime.NewScheme()
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&v1alpha1.CloudflareTunnel{}).
			WithObjects(gateway, &application, tunnel).
			Build()
		first := &GatewayReconciler{Client: kube}
		second := &GatewayReconciler{Client: kube}
		currentTunnel := func() *v1alpha1.CloudflareTunnel {
			var current v1alpha1.CloudflareTunnel
			gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			return &current
		}
		gomega.Expect(first.latchAUDRevocation(context.Background(), &secret)).To(gomega.Succeed())
		inputs := gatewayapi.Inputs{
			AccessApplications: []v1alpha1.AccessApplication{application},
			AUDSecrets: map[types.NamespacedName]gatewayapi.AUDSecret{
				client.ObjectKeyFromObject(&application): {AUD: "audience", ApplicationID: application.Status.ApplicationID, Ready: true},
			},
		}
		gomega.Expect(second.applyAUDRevocationLatches(context.Background(), gateway, currentTunnel(), &inputs)).To(gomega.Succeed())
		gomega.Expect(inputs.AUDSecrets[client.ObjectKeyFromObject(&application)].Ready).To(gomega.BeFalse())

		// A relatch after the snapshot was read allocates a fresh token, so a
		// release computed from the stale snapshot must not remove it.
		stale := currentTunnel()
		gomega.Expect(first.latchAUDRevocation(context.Background(), &secret)).To(gomega.Succeed())
		stale.Status.ConfigVersion.Applied = 2
		stale.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
		stale.Status.Hostnames[0].AppliedVersion = 2
		gomega.Expect(second.applyAUDRevocationLatches(context.Background(), gateway, stale, &inputs)).To(gomega.Succeed())
		latches := currentTunnel().Status.AUDRevocations
		gomega.Expect(latches).To(gomega.HaveLen(1))
		gomega.Expect(latches[0].Token).To(gomega.Equal(int64(2)))

		fresh := currentTunnel()
		fresh.Status.ConfigVersion.Applied = 2
		fresh.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
		fresh.Status.Hostnames[0].AppliedVersion = 2
		gomega.Expect(second.applyAUDRevocationLatches(context.Background(), gateway, fresh, &inputs)).To(gomega.Succeed())
		gomega.Expect(currentTunnel().Status.AUDRevocations).To(gomega.BeEmpty())
	})

	ginkgo.It("prunes revocations for applications no longer attached to a Gateway", func() {
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
		}}
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "gateway"},
			Status: v1alpha1.CloudflareTunnelStatus{
				AUDRevocationSequence: 2,
				AUDRevocations: []v1alpha1.CloudflareAUDRevocationLatch{
					{Application: "tenant/removed", ApplicationUID: "removed-uid", Token: 1, LatchedAt: metav1.Now()},
					{Application: "tenant/newly-attached", ApplicationUID: "newly-attached-uid", Token: 2, LatchedAt: metav1.Now()},
				},
			},
		}
		scheme := runtime.NewScheme()
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&v1alpha1.CloudflareTunnel{}).
			WithObjects(tunnel).
			Build()
		reconciler := &GatewayReconciler{Client: kube}
		inputs := gatewayapi.Inputs{
			AccessApplications: []v1alpha1.AccessApplication{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "newly-attached", UID: "newly-attached-uid"},
			}},
			AUDSecrets: map[types.NamespacedName]gatewayapi.AUDSecret{},
		}
		gomega.Expect(reconciler.applyAUDRevocationLatches(context.Background(), gateway, tunnel, &inputs)).To(gomega.Succeed())
		var current v1alpha1.CloudflareTunnel
		gomega.Expect(kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
		gomega.Expect(current.Status.AUDRevocations).To(gomega.HaveLen(1))
		gomega.Expect(current.Status.AUDRevocations[0].Application).To(gomega.Equal("tenant/newly-attached"))
		gomega.Expect(current.Status.AUDRevocations[0].Token).To(gomega.Equal(int64(2)))
	})
})

var _ = ginkgo.Describe("Gateway status concurrency", func() {
	ginkgo.It("preserves a foreign HTTPRoute parent written between read and patch", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
		routeKey := types.NamespacedName{Namespace: "tenant", Name: "route"}
		route := httpRoute(routeKey, gatewayKey, "backend")
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&gatewayv1.HTTPRoute{}).
			WithObjects(route).
			Build()
		foreign := gatewayv1.RouteParentStatus{
			ParentRef:      gatewayv1.ParentReference{Name: "foreign"},
			ControllerName: "example.net/foreign",
		}
		writer := &concurrentStatusWriterClient{Client: kube}
		writer.beforeFirstPatch = func(ctx context.Context, object client.Object) error {
			var current gatewayv1.HTTPRoute
			if err := kube.Get(ctx, client.ObjectKeyFromObject(object), &current); err != nil {
				return err
			}
			current.Status.Parents = append(current.Status.Parents, foreign)
			return kube.Status().Update(ctx, &current)
		}
		reconciler := &GatewayReconciler{Client: writer}
		owned := gatewayv1.RouteParentStatus{
			ParentRef:      gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gatewayKey.Name)},
			ControllerName: gatewayapi.ControllerName,
		}

		err := reconciler.patchHTTPRouteStatuses(context.Background(), []gatewayv1.HTTPRoute{*route}, map[types.NamespacedName]gatewayv1.HTTPRouteStatus{
			routeKey: {Parents: []gatewayv1.RouteParentStatus{owned}},
		}, gatewayKey)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(writer.patchCalls.Load()).To(gomega.BeNumerically(">=", 2))
		var current gatewayv1.HTTPRoute
		gomega.Expect(kube.Get(context.Background(), routeKey, &current)).To(gomega.Succeed())
		gomega.Expect(current.Status.Parents).To(gomega.ConsistOf(foreign, owned))
	})

	ginkgo.It("preserves a foreign BackendTLSPolicy ancestor written between read and patch", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gatewayKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
		policy := systemBackendTLSPolicy("tenant", "policy", "backend")
		policyKey := client.ObjectKeyFromObject(policy)
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&gatewayv1.BackendTLSPolicy{}).
			WithObjects(policy).
			Build()
		foreign := gatewayv1.PolicyAncestorStatus{
			AncestorRef:    gatewayv1.ParentReference{Name: "foreign"},
			ControllerName: "example.net/foreign",
		}
		writer := &concurrentStatusWriterClient{Client: kube}
		writer.beforeFirstPatch = func(ctx context.Context, object client.Object) error {
			var current gatewayv1.BackendTLSPolicy
			if err := kube.Get(ctx, client.ObjectKeyFromObject(object), &current); err != nil {
				return err
			}
			current.Status.Ancestors = append(current.Status.Ancestors, foreign)
			return kube.Status().Update(ctx, &current)
		}
		reconciler := &GatewayReconciler{Client: writer}
		owned := gatewayv1.PolicyAncestorStatus{
			AncestorRef:    gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gatewayKey.Name)},
			ControllerName: gatewayapi.ControllerName,
		}

		err := reconciler.patchBackendTLSPolicyStatuses(context.Background(), []gatewayv1.BackendTLSPolicy{*policy}, map[types.NamespacedName]gatewayv1.PolicyStatus{
			policyKey: {Ancestors: []gatewayv1.PolicyAncestorStatus{owned}},
		}, gatewayKey)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(writer.patchCalls.Load()).To(gomega.BeNumerically(">=", 2))
		var current gatewayv1.BackendTLSPolicy
		gomega.Expect(kube.Get(context.Background(), policyKey, &current)).To(gomega.Succeed())
		gomega.Expect(current.Status.Ancestors).To(gomega.ConsistOf(foreign, owned))
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

var _ = ginkgo.Describe("Gateway CloudflareAccount watch mapping", func() {
	ginkgo.It("enqueues Gateways through CloudflareTunnels that reference the account", func() {
		scheme := runtime.NewScheme()
		gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
		gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
		gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

		explicit := httpGateway(types.NamespacedName{Namespace: "tenant", Name: "explicit"}, "class")
		explicit.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			},
		}
		implicit := httpGateway(types.NamespacedName{Namespace: "tenant", Name: "implicit"}, "class")
		unrelated := httpGateway(types.NamespacedName{Namespace: "tenant", Name: "unrelated"}, "class")
		tunnels := []client.Object{
			&v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "tenant"},
				Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
			},
			&v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "implicit", Namespace: "tenant"},
				Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
			},
			&v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "tenant"},
				Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "other-account"}},
			},
		}
		kube := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(append([]client.Object{explicit, implicit, unrelated}, tunnels...)...).
			Build()
		reconciler := &GatewayReconciler{Client: kube, Scheme: scheme}

		requests := reconciler.mapAccountToGateways(context.Background(), &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
		})
		gomega.Expect(requests).To(gomega.ConsistOf(
			reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "explicit"}},
			reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "implicit"}},
		))

		gomega.Expect(reconciler.mapAccountToGateways(context.Background(), &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "other-account"},
		})).To(gomega.BeEmpty())
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

func boundAUDSecret(name string, application *v1alpha1.AccessApplication, gateway *gatewayv1.Gateway, aud string) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dataplane.DefaultOperatorNamespace,
			Name:      name,
			Labels: map[string]string{
				v1alpha1.AccessApplicationAUDSecretLabel:  applicationAUDIdentityLabel(application),
				v1alpha1.AccessApplicationGatewayAUDLabel: gatewayAUDIdentityLabel(gateway),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			v1alpha1.AccessApplicationAUDSecretKey:                   []byte(aud),
			v1alpha1.AccessApplicationIDSecretKey:                    []byte(application.Status.ApplicationID),
			v1alpha1.AccessApplicationNamespacedNameSecretKey:        []byte(client.ObjectKeyFromObject(application).String()),
			v1alpha1.AccessApplicationUIDSecretKey:                   []byte(application.UID),
			v1alpha1.AccessApplicationGatewayNamespacedNameSecretKey: []byte(client.ObjectKeyFromObject(gateway).String()),
			v1alpha1.AccessApplicationGatewayUIDSecretKey:            []byte(gateway.UID),
			accessApplicationAUDReadyKey:                             []byte("true"),
		},
	}
}

func gatewayControllerGVK() schema.GroupVersionKind {
	return schema.GroupVersion{
		Group:   gatewayv1.GroupVersion.Group,
		Version: gatewayv1.GroupVersion.Version,
	}.WithKind("Gateway")
}

type dataplaneObjectFactory func(namespace, name string) (client.Object, client.Object)

func configMapDataplaneObjects(namespace, name string) (client.Object, client.Object) {
	return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Labels:      map[string]string{"foreign": "keep"},
				Annotations: map[string]string{"foreign": "keep"},
			},
			Data: map[string]string{"foreign": "keep"},
		}, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Data:       map[string]string{"desired": "value"},
		}
}

func deploymentDataplaneObjects(namespace, name string) (client.Object, client.Object) {
	currentReplicas := int32(3)
	desiredReplicas := int32(2)
	return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Labels:      map[string]string{"foreign": "keep"},
				Annotations: map[string]string{"foreign": "keep"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &currentReplicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foreign"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "foreign"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "foreign", Image: "example.invalid/foreign",
					}}},
				},
			},
		}, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: appsv1.DeploymentSpec{
				Replicas: &desiredReplicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "desired"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "desired"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "desired", Image: "example.invalid/desired",
					}}},
				},
			},
		}
}

func serviceDataplaneObjects(namespace, name string) (client.Object, client.Object) {
	return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Labels:      map[string]string{"foreign": "keep"},
				Annotations: map[string]string{"foreign": "keep"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "foreign"},
				Ports:    []corev1.ServicePort{{Name: "foreign", Port: 81}},
			},
		}, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "desired"},
				Ports:    []corev1.ServicePort{{Name: "desired", Port: 80}},
			},
		}
}

func pdbDataplaneObjects(namespace, name string) (client.Object, client.Object) {
	return &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Labels:      map[string]string{"foreign": "keep"},
				Annotations: map[string]string{"foreign": "keep"},
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foreign"}},
			},
		}, &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
				Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "desired"}},
			},
		}
}

func networkPolicyDataplaneObjects(namespace, name string) (client.Object, client.Object) {
	return &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Labels:      map[string]string{"foreign": "keep"},
				Annotations: map[string]string{"foreign": "keep"},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "foreign"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "desired"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}
}

type dataplaneCreateRaceClient struct {
	client.Client
	once      sync.Once
	collision client.Object
	created   client.Object
}

func (c *dataplaneCreateRaceClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	var collisionErr error
	c.once.Do(func() {
		collisionErr = c.Client.Create(ctx, c.collision)
		if collisionErr == nil {
			c.created = c.collision.DeepCopyObject().(client.Object)
		}
	})
	if collisionErr != nil {
		return collisionErr
	}
	return c.Client.Create(ctx, object, options...)
}

type concurrentDataplaneOwnerClient struct {
	client.Client
	once        sync.Once
	beforeApply func(context.Context) error
}

func (c *concurrentDataplaneOwnerClient) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.ApplyOption) error {
	var hookErr error
	c.once.Do(func() {
		if c.beforeApply != nil {
			hookErr = c.beforeApply(ctx)
		}
	})
	if hookErr != nil {
		return hookErr
	}
	return c.Client.Apply(ctx, object, options...)
}

// concurrentDeleteClient runs beforeDelete once, immediately before the first
// Delete reaches the API server, to model a writer racing the deletion.
type concurrentDeleteClient struct {
	client.Client
	once         sync.Once
	beforeDelete func(context.Context) error
}

func (c *concurrentDeleteClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	var hookErr error
	c.once.Do(func() {
		if c.beforeDelete != nil {
			hookErr = c.beforeDelete(ctx)
		}
	})
	if hookErr != nil {
		return hookErr
	}
	return c.Client.Delete(ctx, object, options...)
}

type concurrentStatusWriterClient struct {
	client.Client
	once             sync.Once
	patchCalls       atomic.Int32
	beforeFirstPatch func(context.Context, client.Object) error
}

func (c *concurrentStatusWriterClient) Status() client.SubResourceWriter {
	return &concurrentStatusWriter{SubResourceWriter: c.Client.Status(), client: c}
}

type concurrentStatusWriter struct {
	client.SubResourceWriter
	client *concurrentStatusWriterClient
}

func (w *concurrentStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	w.client.patchCalls.Add(1)
	firstPatch := false
	var hookErr error
	w.client.once.Do(func() {
		firstPatch = true
		if w.client.beforeFirstPatch != nil {
			hookErr = w.client.beforeFirstPatch(ctx, object)
		}
	})
	if hookErr != nil {
		return hookErr
	}
	if firstPatch {
		data, err := patch.Data(object)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(`"resourceVersion"`)) {
			return apierrors.NewConflict(
				schema.GroupResource{Group: gatewayv1.GroupName, Resource: "statuses"},
				object.GetName(),
				errors.New("concurrent foreign status writer"),
			)
		}
	}
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
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
