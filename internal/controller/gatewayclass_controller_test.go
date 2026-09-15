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
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/isac322/flareway/internal/gatewayapi"
)

var _ = ginkgo.Describe("GatewayClass reconciler", func() {
	ginkgo.It("accepts a valid GatewayClassConfig and publishes the shared feature list", func() {
		fixtureID := fixtureCounter.Add(1)
		configName := fmt.Sprintf("class-config-%d", fixtureID)
		className := fmt.Sprintf("class-valid-%d", fixtureID)
		config := conformanceConfig(configName, "ClusterIP")
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), config))).To(gomega.Succeed())
		})
		class := gatewayClass(className, configName)
		gomega.Expect(testClient.Create(testContext, class)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), class))).To(gomega.Succeed())
		})

		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.GatewayClass
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: className}, &current)).To(gomega.Succeed())
			accepted := findCondition(current.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(accepted.Reason).To(gomega.Equal(string(gatewayv1.GatewayClassReasonAccepted)))
			actual := make([]string, len(current.Status.SupportedFeatures))
			for index, feature := range current.Status.SupportedFeatures {
				actual[index] = string(feature.Name)
			}
			expectedFeatures := gatewayapi.SupportedFeatures()
			expected := make([]string, len(expectedFeatures))
			for index, feature := range expectedFeatures {
				expected[index] = string(feature)
			}
			g.Expect(actual).To(gomega.Equal(expected))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("rejects a missing GatewayClassConfig and ignores foreign classes", func() {
		fixtureID := fixtureCounter.Add(1)
		missingClassName := fmt.Sprintf("class-missing-%d", fixtureID)
		missingConfigName := fmt.Sprintf("missing-%d", fixtureID)
		missing := gatewayClass(missingClassName, missingConfigName)
		gomega.Expect(testClient.Create(testContext, missing)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), missing))).To(gomega.Succeed())
		})

		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.GatewayClass
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: missingClassName}, &current)).To(gomega.Succeed())
			accepted := findCondition(current.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal(string(gatewayv1.GatewayClassReasonInvalidParameters)))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		foreignName := fmt.Sprintf("class-foreign-%d", fixtureID)
		foreign := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: foreignName},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/foreign-controller"},
		}
		gomega.Expect(testClient.Create(testContext, foreign)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(client.IgnoreNotFound(testClient.Delete(context.Background(), foreign))).To(gomega.Succeed())
		})
		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.GatewayClass
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: foreignName}, &current)).To(gomega.Succeed())
			g.Expect(current.Status.Conditions).To(gomega.HaveLen(1))
			g.Expect(current.Status.Conditions[0].Status).To(gomega.Equal(metav1.ConditionUnknown))
			g.Expect(current.Status.Conditions[0].Reason).To(gomega.Equal(string(gatewayv1.GatewayClassReasonPending)))
			g.Expect(current.Status.SupportedFeatures).To(gomega.BeEmpty())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})
})
