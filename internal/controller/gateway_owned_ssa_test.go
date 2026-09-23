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
	"encoding/json"
	"fmt"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
)

var _ = ginkgo.Describe("Gateway-owned object field ownership", func() {
	var namespaceName, configName, className string
	var gatewayKey, deploymentKey types.NamespacedName

	schedulingToleration := corev1.Toleration{
		Key:      "flareway.test/dedicated",
		Operator: corev1.TolerationOpEqual,
		Value:    "gateway",
		Effect:   corev1.TaintEffectNoSchedule,
	}
	const schedulingNodeLabel = "flareway.test/pool"

	ginkgo.BeforeEach(func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName = fmt.Sprintf("gateway-owned-ssa-%d", fixtureID)
		configName = fmt.Sprintf("owned-ssa-%d", fixtureID)
		className = fmt.Sprintf("owned-ssa-%d", fixtureID)
		gatewayKey = types.NamespacedName{Namespace: namespaceName, Name: "gateway"}
		deploymentKey = types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-gateway"}
		gomega.Expect(client.IgnoreAlreadyExists(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}))).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})).To(gomega.Succeed())
	})

	ginkgo.AfterEach(func() {
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: className}}))).To(gomega.Succeed())
		gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}}))).To(gomega.Succeed())
	})

	setScheduling := func(scheduling v1alpha1.DataplaneSchedulingSpec) {
		gomega.Eventually(func() error {
			var config v1alpha1.GatewayClassConfig
			if err := testClient.Get(testContext, types.NamespacedName{Name: configName}, &config); err != nil {
				return err
			}
			config.Spec.Scheduling = scheduling
			return testClient.Update(testContext, &config)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	}

	withScheduling := v1alpha1.DataplaneSchedulingSpec{
		NodeSelector: map[string]string{schedulingNodeLabel: "edge"},
		Tolerations:  []corev1.Toleration{schedulingToleration},
	}

	expectDeploymentScheduling := func(present bool) {
		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, deploymentKey, &deployment)).To(gomega.Succeed())
			pod := deployment.Spec.Template.Spec
			if present {
				g.Expect(pod.Tolerations).To(gomega.ContainElement(schedulingToleration))
				g.Expect(pod.NodeSelector).To(gomega.HaveKeyWithValue(schedulingNodeLabel, "edge"))
			} else {
				g.Expect(pod.Tolerations).NotTo(gomega.ContainElement(schedulingToleration))
				g.Expect(pod.NodeSelector).NotTo(gomega.HaveKey(schedulingNodeLabel))
			}
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())
	}

	gatewayManagerEntries := func(deployment *appsv1.Deployment, operation metav1.ManagedFieldsOperationType) []metav1.ManagedFieldsEntry {
		var entries []metav1.ManagedFieldsEntry
		for _, entry := range deployment.ManagedFields {
			if entry.Manager == gatewayFieldManager && entry.Operation == operation && entry.Subresource == "" {
				entries = append(entries, entry)
			}
		}
		return entries
	}

	createClassAndGateway := func(scheduling v1alpha1.DataplaneSchedulingSpec) {
		config := conformanceConfig(configName, corev1.ServiceTypeClusterIP)
		config.Spec.Scheduling = scheduling
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, gatewayClass(className, configName))).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, httpGateway(gatewayKey, className))).To(gomega.Succeed())
	}

	ginkgo.It("removes scheduling fields the dataplane Deployment was created with", func() {
		createClassAndGateway(withScheduling)
		expectDeploymentScheduling(true)

		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, deploymentKey, &deployment)).To(gomega.Succeed())
			g.Expect(gatewayManagerEntries(&deployment, metav1.ManagedFieldsOperationUpdate)).To(gomega.BeEmpty())
			g.Expect(gatewayManagerEntries(&deployment, metav1.ManagedFieldsOperationApply)).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())

		setScheduling(v1alpha1.DataplaneSchedulingSpec{})
		expectDeploymentScheduling(false)
	})

	ginkgo.It("keeps the ownership of objects already applied by an earlier controller", func() {
		createClassAndGateway(v1alpha1.DataplaneSchedulingSpec{})

		// Reshape the converged Deployment into what an earlier controller left
		// behind: a Create-time Update entry alongside the Apply entry.
		gomega.Eventually(func(g gomega.Gomega) {
			var deployment appsv1.Deployment
			g.Expect(testClient.Get(testContext, deploymentKey, &deployment)).To(gomega.Succeed())
			applied := gatewayManagerEntries(&deployment, metav1.ManagedFieldsOperationApply)
			g.Expect(applied).To(gomega.HaveLen(1))
			legacyUpdate := *applied[0].DeepCopy()
			legacyUpdate.Operation = metav1.ManagedFieldsOperationUpdate
			patch, err := json.Marshal([]map[string]any{
				{"op": "replace", "path": "/metadata/managedFields", "value": append(deployment.ManagedFields, legacyUpdate)},
				{"op": "replace", "path": "/metadata/resourceVersion", "value": deployment.ResourceVersion},
			})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(testClient.Patch(testContext, &deployment, client.RawPatch(types.JSONPatchType, patch))).To(gomega.Succeed())
			g.Expect(gatewayManagerEntries(&deployment, metav1.ManagedFieldsOperationUpdate)).To(gomega.HaveLen(1))
		}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(gomega.Succeed())

		setScheduling(withScheduling)
		expectDeploymentScheduling(true)
		setScheduling(v1alpha1.DataplaneSchedulingSpec{})
		expectDeploymentScheduling(false)

		var deployment appsv1.Deployment
		gomega.Expect(testClient.Get(testContext, deploymentKey, &deployment)).To(gomega.Succeed())
		gomega.Expect(gatewayManagerEntries(&deployment, metav1.ManagedFieldsOperationUpdate)).To(gomega.HaveLen(1), "earlier-controller Update entry must not be migrated")
	})
})
