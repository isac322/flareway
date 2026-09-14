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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var privateNetworkFixtureCounter atomic.Uint64

var _ = ginkgo.Describe("Private network controllers", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func() {
		ensureSystemNamespace("kube-system")
		ensureSystemNamespace("flareway-system")
	})
	ginkgo.BeforeEach(func() {
		testPrivateNetworkCloudflare.reset()
		testTunnelCloudflare.Reset()
		testAccountCloudflare.reset()
	})

	ginkgo.It("rejects unmasked CIDRs and invalid wildcard hostnames at admission", func() {
		namespace := fmt.Sprintf("private-admission-%d", privateNetworkFixtureCounter.Add(1))
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})).To(gomega.Succeed())
		ginkgo.DeferCleanup(forceDeletePrivateNetworkNamespace, namespace)
		network := &v1alpha1.NetworkRoute{ObjectMeta: metav1.ObjectMeta{Name: "unmasked", Namespace: namespace}, Spec: v1alpha1.NetworkRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Network: "10.96.1.1/12",
			TunnelRef: v1alpha1.NamespacedObjectReference{Name: "tunnel"}, VirtualNetworkRef: corev1.LocalObjectReference{Name: "vnet"},
		}}
		gomega.Expect(testClient.Create(testContext, network)).To(gomega.MatchError(gomega.ContainSubstring("network must be masked")))
		hostname := &v1alpha1.HostnameRoute{ObjectMeta: metav1.ObjectMeta{Name: "wildcard", Namespace: namespace}, Spec: v1alpha1.HostnameRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Hostname: "*.*.private.internal",
			TunnelRef: v1alpha1.NamespacedObjectReference{Name: "tunnel"},
		}}
		gomega.Expect(testClient.Create(testContext, hostname)).To(gomega.MatchError(gomega.ContainSubstring("spec.hostname")))
	})

	ginkgo.It("synchronizes and deletes virtual network, CIDR route, and hostname route", func() {
		fixture := newPrivateNetworkFixture("lifecycle")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		cidr := fixture.networkRoute("services", "10.96.0.0/12", vnet.Name)
		hostname := fixture.hostnameRoute("admin", "*.private.internal")
		gomega.Expect(testClient.Create(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, hostname)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(cidr), cidr)).To(gomega.Succeed())
			g.Expect(cidr.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(cidr.Status.Applied.Network).To(gomega.Equal("10.96.0.0/12"))
			g.Expect(cidr.Status.Applied.ObservedGeneration).To(gomega.Equal(cidr.Generation))
			g.Expect(cidr.Status.Applied.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(cidr.Status.Applied.VirtualNetworkID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(cidr.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(hostname), hostname)).To(gomega.Succeed())
			g.Expect(hostname.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(hostname.Status.Applied.Hostname).To(gomega.Equal("*.private.internal"))
			g.Expect(hostname.Status.Applied.ObservedGeneration).To(gomega.Equal(hostname.Generation))
			g.Expect(hostname.Status.Applied.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(hostname.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		var deletingTunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &deletingTunnel)).To(gomega.Succeed())
		base := client.MergeFrom(deletingTunnel.DeepCopy())
		deletingTunnel.Finalizers = append(deletingTunnel.Finalizers, "flareway.bhyoo.com/test-hold")
		gomega.Expect(testClient.Patch(testContext, &deletingTunnel, base)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &deletingTunnel)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deletingTunnel)).To(gomega.Succeed())
			g.Expect(deletingTunnel.DeletionTimestamp.IsZero()).To(gomega.BeFalse())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, hostname)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(cidr), new(v1alpha1.NetworkRoute))) &&
				apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(hostname), new(v1alpha1.HostnameRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testClient.Delete(testContext, vnet)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), new(v1alpha1.VirtualNetwork)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())

		calls := testPrivateNetworkCloudflare.callsSnapshot()
		gomega.Expect(calls).To(gomega.ContainElements("CreateVirtualNetwork", "CreateNetworkRoute", "CreateHostnameRoute", "DeleteNetworkRoute", "DeleteHostnameRoute", "DeleteVirtualNetwork"))
	})

	ginkgo.It("rejects overlapping CIDRs in the same virtual network before a remote write", func() {
		fixture := newPrivateNetworkFixture("overlap")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		first := fixture.networkRoute("first", "10.96.0.0/12", vnet.Name)
		second := fixture.networkRoute("second", "10.100.0.0/16", vnet.Name)
		gomega.Expect(testClient.Create(testContext, first)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(first), first)).To(gomega.Succeed())
			g.Expect(first.Status.RouteID).NotTo(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, second)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(second), second)).To(gomega.Succeed())
			condition := statusutil.FindCondition(second.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("overlaps applied NetworkRoute"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateNetworkRoute")).To(gomega.Equal(1))
	})

	ginkgo.It("keeps applied network and hostname claims when an older route update would overlap a live route", func() {
		fixture := newPrivateNetworkFixture("update-overlap")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		firstNetwork := fixture.networkRoute("first-network", "10.0.0.0/16", vnet.Name)
		secondNetwork := fixture.networkRoute("second-network", "10.1.0.0/16", vnet.Name)
		firstHostname := fixture.hostnameRoute("first-hostname", "one.private.internal")
		secondHostname := fixture.hostnameRoute("second-hostname", "two.private.internal")
		for _, object := range []client.Object{firstNetwork, secondNetwork, firstHostname, secondHostname} {
			gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
		}
		gomega.Eventually(func(g gomega.Gomega) {
			for _, route := range []*v1alpha1.NetworkRoute{firstNetwork, secondNetwork} {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			}
			for _, route := range []*v1alpha1.HostnameRoute{firstHostname, secondHostname} {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			}
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		networkAppliedGeneration := firstNetwork.Status.Applied.ObservedGeneration
		hostnameAppliedGeneration := firstHostname.Status.Applied.ObservedGeneration

		firstNetwork.Spec.Network = "10.1.128.0/17"
		gomega.Expect(testClient.Update(testContext, firstNetwork)).To(gomega.Succeed())
		firstHostname.Spec.Hostname = "*.private.internal"
		gomega.Expect(testClient.Update(testContext, firstHostname)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(firstNetwork), firstNetwork)).To(gomega.Succeed())
			networkCondition := statusutil.FindCondition(firstNetwork.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(networkCondition).NotTo(gomega.BeNil())
			g.Expect(networkCondition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(networkCondition.Message).To(gomega.ContainSubstring("overlaps applied NetworkRoute"))
			g.Expect(firstNetwork.Status.Applied.Network).To(gomega.Equal("10.0.0.0/16"))
			g.Expect(firstNetwork.Status.Applied.ObservedGeneration).To(gomega.Equal(networkAppliedGeneration))
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(firstHostname), firstHostname)).To(gomega.Succeed())
			hostnameCondition := statusutil.FindCondition(firstHostname.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(hostnameCondition).NotTo(gomega.BeNil())
			g.Expect(hostnameCondition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(hostnameCondition.Message).To(gomega.ContainSubstring("overlaps applied HostnameRoute"))
			g.Expect(firstHostname.Status.Applied.Hostname).To(gomega.Equal("one.private.internal"))
			g.Expect(firstHostname.Status.Applied.ObservedGeneration).To(gomega.Equal(hostnameAppliedGeneration))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("rejects a tunnel namespace excluded by allowedNamespaces without a remote write", func() {
		fixture := newPrivateNetworkFixture("namespace")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		route := fixture.networkRoute("denied", "10.120.0.0/16", vnet.Name)
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("RefNotPermitted"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateNetworkRoute")).To(gomega.BeZero())
	})

	ginkgo.It("rejects a hostname outside the tenant account grant before a remote write", func() {
		fixture := newPrivateNetworkFixture("hostname-grant")
		fixture.create()
		var account v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
		account.Spec.Grants[1].Hostnames = []string{"allowed.private.internal"}
		gomega.Expect(testClient.Update(testContext, &account)).To(gomega.Succeed())
		route := fixture.hostnameRoute("denied-hostname", "denied.private.internal")
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("UnsupportedValue"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("hostname"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("does not let tenant-supplied generated-route labels change the authorization principal", func() {
		fixture := newPrivateNetworkFixture("forged-generated")
		fixture.create()
		route := fixture.hostnameRoute("forged", "forged.private.internal")
		route.Namespace = fixture.tenantNamespace
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame}
		route.Labels[generatedPlatformObjectLabel] = "true"
		route.Labels[generatedSourceNamespaceLabel] = fixture.tenantNamespace
		route.Annotations = map[string]string{sourceGatewayUIDAnnotation: "forged"}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("RefNotPermitted"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("authorizes an auto-created platform hostname route against its source namespace grant", func() {
		fixture := newPrivateNetworkFixture("generated")
		fixture.create()
		var account v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
		account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionDenied
		account.Spec.Grants[1].PlatformObjects = v1alpha1.GrantPermissionAllowed
		gomega.Expect(testClient.Update(testContext, &account)).To(gomega.Succeed())

		var sourceGateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &sourceGateway)).To(gomega.Succeed())
		listenerName := "private"
		routeName := privateHostnameRouteName(fixture.tunnelKey.Namespace, fixture.tunnelKey.Name, listenerName)
		route := fixture.hostnameRoute(routeName, "admin.private.internal")
		route.Namespace = "flareway-system"
		route.Labels[generatedPlatformObjectLabel] = "true"
		route.Labels[generatedSourceNamespaceLabel] = fixture.tenantNamespace
		route.Labels[generatedGatewayLabel] = fixture.tenantNamespace + "--" + fixture.tunnelKey.Name
		route.Annotations = map[string]string{sourceGatewayUIDAnnotation: string(sourceGateway.UID)}
		route.Spec.Comment = fmt.Sprintf("flareway private listener %s/%s/%s", fixture.tenantNamespace, fixture.tunnelKey.Name, listenerName)
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{
			From: v1alpha1.AllowedNamespaceFromSelector,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": fixture.tenantNamespace,
			}},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), route) })
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("accepts a generated route for an implicit same-name Gateway-owned Tunnel", func() {
		fixture := newPrivateNetworkFixture("implicit-generated")
		fixture.tunnelKey.Name = fixture.gatewayKey.Name
		fixture.create()
		var account v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
		account.Spec.Grants[1].PlatformObjects = v1alpha1.GrantPermissionAllowed
		gomega.Expect(testClient.Update(testContext, &account)).To(gomega.Succeed())
		var sourceGateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &sourceGateway)).To(gomega.Succeed())
		sourceGateway.Spec.Infrastructure = nil
		gomega.Expect(testClient.Update(testContext, &sourceGateway)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var tunnel v1alpha1.CloudflareTunnel
			if err := testClient.Get(testContext, fixture.tunnelKey, &tunnel); err != nil {
				return err
			}
			base := client.MergeFrom(tunnel.DeepCopy())
			controller := true
			tunnel.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway", Name: sourceGateway.Name,
				UID: sourceGateway.UID, Controller: &controller,
			}}
			return testClient.Patch(testContext, &tunnel, base)
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		listenerName := "private"
		route := fixture.hostnameRoute(privateHostnameRouteName(fixture.tunnelKey.Namespace, fixture.tunnelKey.Name, listenerName), "admin.private.internal")
		route.Namespace = "flareway-system"
		route.Labels[generatedPlatformObjectLabel] = "true"
		route.Labels[generatedSourceNamespaceLabel] = fixture.tenantNamespace
		route.Labels[generatedGatewayLabel] = fixture.tenantNamespace + "--" + fixture.tunnelKey.Name
		route.Annotations = map[string]string{sourceGatewayUIDAnnotation: string(sourceGateway.UID)}
		route.Spec.Comment = fmt.Sprintf("flareway private listener %s/%s/%s", fixture.tenantNamespace, fixture.tunnelKey.Name, listenerName)
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{
			From: v1alpha1.AllowedNamespaceFromSelector,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": fixture.tenantNamespace,
			}},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), route) })
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("rejects an operator-namespace generated route with a stale Gateway UID proof", func() {
		fixture := newPrivateNetworkFixture("stale-generated")
		fixture.create()
		var account v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
		account.Spec.Grants[1].PlatformObjects = v1alpha1.GrantPermissionAllowed
		gomega.Expect(testClient.Update(testContext, &account)).To(gomega.Succeed())
		listenerName := "private"
		route := fixture.hostnameRoute(privateHostnameRouteName(fixture.tunnelKey.Namespace, fixture.tunnelKey.Name, listenerName), "admin.private.internal")
		route.Namespace = "flareway-system"
		route.Labels[generatedPlatformObjectLabel] = "true"
		route.Labels[generatedSourceNamespaceLabel] = fixture.tenantNamespace
		route.Labels[generatedGatewayLabel] = fixture.tenantNamespace + "--" + fixture.tunnelKey.Name
		route.Annotations = map[string]string{sourceGatewayUIDAnnotation: "stale-uid"}
		route.Spec.Comment = fmt.Sprintf("flareway private listener %s/%s/%s", fixture.tenantNamespace, fixture.tunnelKey.Name, listenerName)
		route.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{
			From: v1alpha1.AllowedNamespaceFromSelector,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": fixture.tenantNamespace,
			}},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), route) })
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("RefNotPermitted"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("UID proof"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("observes an external hostname route without mutation", func() {
		fixture := newPrivateNetworkFixture("observe")
		fixture.create()
		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "external-hostname", Hostname: "observed.private.internal", TunnelID: fixture.tunnelID(), Comment: "terraform",
		})
		route := fixture.hostnameRoute("observed", "observed.private.internal")
		route.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		route.Spec.ExternalRef = &v1alpha1.HostnameRouteExternalReference{RouteID: "external-hostname"}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.RouteID).To(gomega.Equal("external-hostname"))
			g.Expect(route.Status.OwnershipVerified).To(gomega.BeFalse())
			g.Expect(statusutil.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("orphans a managed virtual network on deletion", func() {
		fixture := newPrivateNetworkFixture("orphan")
		fixture.create()
		vnet := fixture.virtualNetwork("orphaned")
		vnet.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
		fixture.waitVirtualNetworkReady(vnet)
		gomega.Expect(testClient.Delete(testContext, vnet)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), new(v1alpha1.VirtualNetwork)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteVirtualNetwork")).To(gomega.BeZero())
	})

	ginkgo.It("rejects adoption when the remote route target differs from resolved references", func() {
		fixture := newPrivateNetworkFixture("adoption")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{ID: "foreign-route", Network: "192.168.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID})
		route := fixture.networkRoute("adopt", "10.200.0.0/16", vnet.Name)
		route.Spec.ExternalRef = &v1alpha1.NetworkRouteExternalReference{RouteID: "foreign-route"}
		route.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match resolved target"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateNetworkRoute")).To(gomega.BeZero())
	})
})

type privateNetworkFixture struct {
	platformNamespace string
	tenantNamespace   string
	accountName       string
	credential        types.NamespacedName
	gatewayKey        types.NamespacedName
	tunnelKey         types.NamespacedName
}

func newPrivateNetworkFixture(prefix string) *privateNetworkFixture {
	id := privateNetworkFixtureCounter.Add(1)
	return &privateNetworkFixture{
		platformNamespace: fmt.Sprintf("private-platform-%s-%d", prefix, id),
		tenantNamespace:   fmt.Sprintf("private-tenant-%s-%d", prefix, id),
		accountName:       fmt.Sprintf("private-account-%d", id),
		credential:        types.NamespacedName{Namespace: fmt.Sprintf("private-platform-%s-%d", prefix, id), Name: "credentials"},
		gatewayKey:        types.NamespacedName{Namespace: fmt.Sprintf("private-tenant-%s-%d", prefix, id), Name: "gateway"},
		tunnelKey:         types.NamespacedName{Namespace: fmt.Sprintf("private-tenant-%s-%d", prefix, id), Name: "tunnel"},
	}
}

func (f *privateNetworkFixture) create() {
	platformLabels := map[string]string{"private-platform": f.platformNamespace}
	tenantLabels := map[string]string{"private-tenant": f.tenantNamespace}
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.platformNamespace, Labels: platformLabels}})).To(gomega.Succeed())
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.tenantNamespace, Labels: tenantLabels}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeletePrivateNetworkNamespace, f.platformNamespace)
	ginkgo.DeferCleanup(forceDeletePrivateNetworkNamespace, f.tenantNamespace)
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: f.credential.Name, Namespace: f.credential.Namespace}, Data: map[string][]byte{"token": []byte("api-token")}})).To(gomega.Succeed())

	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: f.accountName}, Spec: v1alpha1.CloudflareAccountSpec{
		AccountID: fmt.Sprintf("%032x", privateNetworkFixtureCounter.Load()),
		Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
			Name: f.credential.Name, Namespace: f.credential.Namespace, Key: "token",
		}},
		Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: platformLabels},
			Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
			PlatformObjects: v1alpha1.GrantPermissionAllowed,
		}, {
			NamespaceSelector: metav1.LabelSelector{MatchLabels: tenantLabels},
			Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
			PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
				NetworkRouteSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
				HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
			},
		}},
	}}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	gomega.Eventually(func(g gomega.Gomega) {
		var current v1alpha1.CloudflareAccount
		g.Expect(testClient.Get(testContext, types.NamespacedName{Name: f.accountName}, &current)).To(gomega.Succeed())
		g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
		g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
	}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

	hostname := gatewayv1.Hostname("admin.private.internal")
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: f.gatewayKey.Name, Namespace: f.gatewayKey.Namespace}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "unused-private-network-test",
		Listeners:        []gatewayv1.Listener{{Name: "private", Protocol: gatewayv1.HTTPProtocolType, Port: 443, Hostname: &hostname}},
		Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("CloudflareTunnel"), Name: f.tunnelKey.Name}},
	}}
	tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace}, Spec: v1alpha1.CloudflareTunnelSpec{
		AccountRef:       corev1.LocalObjectReference{Name: f.accountName},
		Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "private-" + f.tunnelKey.Namespace},
		ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
		DNS:       v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
		Listeners: []v1alpha1.CloudflareTunnelListener{{Name: "private", Exposure: v1alpha1.ExposurePrivate}},
	}}
	gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
	gomega.Expect(testClient.Create(testContext, tunnel)).To(gomega.Succeed())
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(testClient.Get(testContext, f.tunnelKey, tunnel)).To(gomega.Succeed())
		g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		g.Expect(statusutil.ConditionTrue(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)).To(gomega.BeTrue())
	}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func (f *privateNetworkFixture) createVirtualNetwork(name string) *v1alpha1.VirtualNetwork {
	object := f.virtualNetwork(name)
	gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
	return object
}

func (f *privateNetworkFixture) virtualNetwork(name string) *v1alpha1.VirtualNetwork {
	return &v1alpha1.VirtualNetwork{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.platformNamespace}, Spec: v1alpha1.VirtualNetworkSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.accountName}, Name: name,
		ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
	}}
}

func (f *privateNetworkFixture) waitVirtualNetworkReady(object *v1alpha1.VirtualNetwork) {
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(object), object)).To(gomega.Succeed())
		g.Expect(object.Status.VirtualNetworkID).NotTo(gomega.BeEmpty())
		g.Expect(statusutil.ConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
	}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func (f *privateNetworkFixture) networkRoute(name, network, virtualNetworkName string) *v1alpha1.NetworkRoute {
	return &v1alpha1.NetworkRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.platformNamespace, Labels: map[string]string{"private-route": "allowed"}}, Spec: v1alpha1.NetworkRouteSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.accountName}, Network: network,
		TunnelRef:         v1alpha1.NamespacedObjectReference{Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace},
		VirtualNetworkRef: corev1.LocalObjectReference{Name: virtualNetworkName},
		AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-tenant": f.tenantNamespace}}},
		ManagementPolicy:  v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
	}}
}

func (f *privateNetworkFixture) hostnameRoute(name, hostname string) *v1alpha1.HostnameRoute {
	return &v1alpha1.HostnameRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.platformNamespace, Labels: map[string]string{"private-route": "allowed"}}, Spec: v1alpha1.HostnameRouteSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.accountName}, Hostname: hostname,
		TunnelRef:         v1alpha1.NamespacedObjectReference{Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace},
		AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-tenant": f.tenantNamespace}}},
		ManagementPolicy:  v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
	}}
}

func (f *privateNetworkFixture) tunnelID() string {
	var tunnel v1alpha1.CloudflareTunnel
	gomega.Expect(testClient.Get(testContext, f.tunnelKey, &tunnel)).To(gomega.Succeed())
	return tunnel.Status.TunnelID
}

func forceDeletePrivateNetworkNamespace(namespace string) {
	ctx := context.Background()
	for _, list := range []client.ObjectList{&v1alpha1.NetworkRouteList{}, &v1alpha1.HostnameRouteList{}, &v1alpha1.VirtualNetworkList{}, &v1alpha1.CloudflareTunnelList{}} {
		if err := testClient.List(ctx, list, client.InNamespace(namespace)); err != nil {
			continue
		}
		switch objects := list.(type) {
		case *v1alpha1.NetworkRouteList:
			for i := range objects.Items {
				clearFinalizers(ctx, &objects.Items[i])
			}
		case *v1alpha1.HostnameRouteList:
			for i := range objects.Items {
				clearFinalizers(ctx, &objects.Items[i])
			}
		case *v1alpha1.VirtualNetworkList:
			for i := range objects.Items {
				clearFinalizers(ctx, &objects.Items[i])
			}
		case *v1alpha1.CloudflareTunnelList:
			for i := range objects.Items {
				clearFinalizers(ctx, &objects.Items[i])
			}
		}
	}
	_ = testClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
}

func clearFinalizers(ctx context.Context, object client.Object) {
	if len(object.GetFinalizers()) == 0 {
		return
	}
	base := client.MergeFrom(object.DeepCopyObject().(client.Object))
	object.SetFinalizers(nil)
	_ = testClient.Patch(ctx, object, base)
}

type fakePrivateNetworkCloudflare struct {
	mu              sync.Mutex
	next            int
	virtualNetworks map[string]flarecloudflare.VirtualNetwork
	networkRoutes   map[string]flarecloudflare.NetworkRoute
	hostnameRoutes  map[string]flarecloudflare.HostnameRoute
	calls           []string
}

func newFakePrivateNetworkCloudflare() *fakePrivateNetworkCloudflare {
	fake := new(fakePrivateNetworkCloudflare)
	fake.reset()
	return fake
}

func (f *fakePrivateNetworkCloudflare) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = 0
	f.virtualNetworks = map[string]flarecloudflare.VirtualNetwork{}
	f.networkRoutes = map[string]flarecloudflare.NetworkRoute{}
	f.hostnameRoutes = map[string]flarecloudflare.HostnameRoute{}
	f.calls = nil
}

func (f *fakePrivateNetworkCloudflare) Client(_, _ string) (flarecloudflare.NetworkAPI, error) {
	return f, nil
}

func (f *fakePrivateNetworkCloudflare) record(call string) { f.calls = append(f.calls, call) }
func (f *fakePrivateNetworkCloudflare) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%s-%d", prefix, f.next)
}
func (f *fakePrivateNetworkCloudflare) missing(resource, id string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "cloudflare", Resource: resource}, id)
}

func (f *fakePrivateNetworkCloudflare) CreateVirtualNetwork(_ context.Context, input flarecloudflare.VirtualNetworkInput) (flarecloudflare.VirtualNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateVirtualNetwork")
	remote := flarecloudflare.VirtualNetwork{ID: f.id("vnet"), Name: input.Name, IsDefault: input.IsDefault, Comment: input.Comment}
	f.virtualNetworks[remote.ID] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) UpdateVirtualNetwork(_ context.Context, id string, input flarecloudflare.VirtualNetworkInput) (flarecloudflare.VirtualNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("UpdateVirtualNetwork")
	if _, ok := f.virtualNetworks[id]; !ok {
		return flarecloudflare.VirtualNetwork{}, f.missing("virtualnetworks", id)
	}
	remote := flarecloudflare.VirtualNetwork{ID: id, Name: input.Name, IsDefault: input.IsDefault, Comment: input.Comment}
	f.virtualNetworks[id] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) GetVirtualNetwork(_ context.Context, id string) (flarecloudflare.VirtualNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetVirtualNetwork")
	remote, ok := f.virtualNetworks[id]
	if !ok {
		return flarecloudflare.VirtualNetwork{}, f.missing("virtualnetworks", id)
	}
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) ListVirtualNetworks(context.Context) ([]flarecloudflare.VirtualNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListVirtualNetworks")
	out := make([]flarecloudflare.VirtualNetwork, 0, len(f.virtualNetworks))
	for _, remote := range f.virtualNetworks {
		out = append(out, remote)
	}
	return out, nil
}
func (f *fakePrivateNetworkCloudflare) DeleteVirtualNetwork(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteVirtualNetwork")
	delete(f.virtualNetworks, id)
	return nil
}
func (f *fakePrivateNetworkCloudflare) CreateNetworkRoute(_ context.Context, input flarecloudflare.NetworkRouteInput) (flarecloudflare.NetworkRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateNetworkRoute")
	remote := flarecloudflare.NetworkRoute{ID: f.id("network-route"), Network: input.Network, TunnelID: input.TunnelID, VirtualNetworkID: input.VirtualNetworkID, Comment: input.Comment}
	f.networkRoutes[remote.ID] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) UpdateNetworkRoute(_ context.Context, id string, input flarecloudflare.NetworkRouteInput) (flarecloudflare.NetworkRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("UpdateNetworkRoute")
	if _, ok := f.networkRoutes[id]; !ok {
		return flarecloudflare.NetworkRoute{}, f.missing("networkroutes", id)
	}
	remote := flarecloudflare.NetworkRoute{ID: id, Network: input.Network, TunnelID: input.TunnelID, VirtualNetworkID: input.VirtualNetworkID, Comment: input.Comment}
	f.networkRoutes[id] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) GetNetworkRoute(_ context.Context, id string) (flarecloudflare.NetworkRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetNetworkRoute")
	remote, ok := f.networkRoutes[id]
	if !ok {
		return flarecloudflare.NetworkRoute{}, f.missing("networkroutes", id)
	}
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) ListNetworkRoutes(context.Context) ([]flarecloudflare.NetworkRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListNetworkRoutes")
	out := make([]flarecloudflare.NetworkRoute, 0, len(f.networkRoutes))
	for _, remote := range f.networkRoutes {
		out = append(out, remote)
	}
	return out, nil
}
func (f *fakePrivateNetworkCloudflare) DeleteNetworkRoute(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteNetworkRoute")
	delete(f.networkRoutes, id)
	return nil
}
func (f *fakePrivateNetworkCloudflare) CreateHostnameRoute(_ context.Context, input flarecloudflare.HostnameRouteInput) (flarecloudflare.HostnameRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateHostnameRoute")
	remote := flarecloudflare.HostnameRoute{ID: f.id("hostname-route"), Hostname: input.Hostname, TunnelID: input.TunnelID, Comment: input.Comment}
	f.hostnameRoutes[remote.ID] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) UpdateHostnameRoute(_ context.Context, id string, input flarecloudflare.HostnameRouteInput) (flarecloudflare.HostnameRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("UpdateHostnameRoute")
	if _, ok := f.hostnameRoutes[id]; !ok {
		return flarecloudflare.HostnameRoute{}, f.missing("hostnameroutes", id)
	}
	remote := flarecloudflare.HostnameRoute{ID: id, Hostname: input.Hostname, TunnelID: input.TunnelID, Comment: input.Comment}
	f.hostnameRoutes[id] = remote
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) GetHostnameRoute(_ context.Context, id string) (flarecloudflare.HostnameRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetHostnameRoute")
	remote, ok := f.hostnameRoutes[id]
	if !ok {
		return flarecloudflare.HostnameRoute{}, f.missing("hostnameroutes", id)
	}
	return remote, nil
}
func (f *fakePrivateNetworkCloudflare) ListHostnameRoutes(context.Context) ([]flarecloudflare.HostnameRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListHostnameRoutes")
	out := make([]flarecloudflare.HostnameRoute, 0, len(f.hostnameRoutes))
	for _, remote := range f.hostnameRoutes {
		out = append(out, remote)
	}
	return out, nil
}
func (f *fakePrivateNetworkCloudflare) DeleteHostnameRoute(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteHostnameRoute")
	delete(f.hostnameRoutes, id)
	return nil
}
func (f *fakePrivateNetworkCloudflare) GetDeviceSettings(context.Context) (flarecloudflare.DeviceSettings, error) {
	return flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}, nil
}
func (f *fakePrivateNetworkCloudflare) UpdateDeviceSettings(_ context.Context, input flarecloudflare.DeviceSettingsInput) (flarecloudflare.DeviceSettings, error) {
	return flarecloudflare.DeviceSettings{
		GatewayProxyEnabled:                pointerBoolOrZero(input.GatewayProxyEnabled),
		GatewayUDPProxyEnabled:             pointerBoolOrZero(input.GatewayUDPProxyEnabled),
		RootCertificateInstallationEnabled: pointerBoolOrZero(input.RootCertificateInstallationEnabled),
		UseZTVirtualIP:                     pointerBoolOrZero(input.UseZTVirtualIP),
		DisableForTime:                     pointerInt64OrZero(input.DisableForTime),
	}, nil
}
func pointerBoolOrZero(value *bool) bool { return value != nil && *value }
func pointerInt64OrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
func (f *fakePrivateNetworkCloudflare) putNetworkRoute(remote flarecloudflare.NetworkRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networkRoutes[remote.ID] = remote
}
func (f *fakePrivateNetworkCloudflare) putHostnameRoute(remote flarecloudflare.HostnameRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostnameRoutes[remote.ID] = remote
}
func (f *fakePrivateNetworkCloudflare) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(slices.DeleteFunc(append([]string(nil), f.calls...), func(value string) bool { return value != call }))
}
func (f *fakePrivateNetworkCloudflare) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
