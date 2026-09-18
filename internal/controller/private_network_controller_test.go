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
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			TunnelRef: v1alpha1.TunnelReference{Name: "tunnel"}, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "vnet"},
		}}
		gomega.Expect(testClient.Create(testContext, network)).To(gomega.MatchError(gomega.ContainSubstring("network must be masked")))
		hostname := &v1alpha1.HostnameRoute{ObjectMeta: metav1.ObjectMeta{Name: "wildcard", Namespace: namespace}, Spec: v1alpha1.HostnameRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Hostname: "*.*.private.internal",
			TunnelRef: v1alpha1.TunnelReference{Name: "tunnel"},
		}}
		gomega.Expect(testClient.Create(testContext, hostname)).To(gomega.MatchError(gomega.ContainSubstring("spec.hostname")))
		managedExternal := &v1alpha1.NetworkRoute{ObjectMeta: metav1.ObjectMeta{Name: "managed-external", Namespace: namespace}, Spec: v1alpha1.NetworkRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Network: "10.96.0.0/12",
			TunnelRef:   v1alpha1.TunnelReference{Name: "tunnel"},
			ExternalRef: &v1alpha1.NetworkRouteExternalReference{RouteID: "remote-route"},
		}}
		gomega.Expect(testClient.Create(testContext, managedExternal)).To(gomega.MatchError(gomega.ContainSubstring("adoption.mode AdoptById")))
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

	ginkgo.It("records network route IP lookup results", func() {
		fixture := newPrivateNetworkFixture("ip-lookup")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		route := fixture.networkRoute("services", "10.96.0.0/12", vnet.Name)
		route.Spec.IPLookup = &v1alpha1.NetworkRouteIPLookupSpec{
			IP:                "10.100.2.3",
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.IPLookup).NotTo(gomega.BeNil())
			g.Expect(route.Status.IPLookup.IP).To(gomega.Equal("10.100.2.3"))
			g.Expect(route.Status.IPLookup.ObservedGeneration).To(gomega.Equal(route.Generation))
			g.Expect(route.Status.IPLookup.VirtualNetworkID).To(gomega.Equal(vnet.Status.VirtualNetworkID))
			g.Expect(route.Status.IPLookup.Result).NotTo(gomega.BeNil())
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(route.Status.IPLookup.Result.RouteID).To(gomega.Equal(route.Status.RouteID))
			g.Expect(route.Status.IPLookup.Result.Network).To(gomega.Equal("10.96.0.0/12"))
			g.Expect(route.Status.IPLookup.Result.VirtualNetworkID).To(gomega.Equal(vnet.Status.VirtualNetworkID))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("LookupNetworkRoute")).To(gomega.BeNumerically(">=", 1))
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

	ginkgo.It("rejects adoption when the remote network route target differs from resolved references without recording its ID", func() {
		fixture := newPrivateNetworkFixture("network-adoption-mismatch")
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
			g.Expect(route.Status.RouteID).To(gomega.BeEmpty())
			g.Expect(route.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match resolved target"))
			g.Expect(condition.Message).NotTo(gomega.ContainSubstring("ID is not verified"))
			g.Expect(route.Status.RouteID).To(gomega.BeEmpty())
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateNetworkRoute")).To(gomega.BeZero())
	})

	ginkgo.It("rejects adoption when the remote hostname route target differs without recording its ID", func() {
		fixture := newPrivateNetworkFixture("hostname-adoption-mismatch")
		fixture.create()
		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{ID: "foreign-hostname-route", Hostname: "foreign.private.internal", TunnelID: fixture.tunnelID()})
		route := fixture.hostnameRoute("adopt", "wanted.private.internal")
		route.Spec.ExternalRef = &v1alpha1.HostnameRouteExternalReference{RouteID: "foreign-hostname-route"}
		route.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match resolved target"))
			g.Expect(route.Status.RouteID).To(gomega.BeEmpty())
			g.Expect(route.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match resolved target"))
			g.Expect(condition.Message).NotTo(gomega.ContainSubstring("ID is not verified"))
			g.Expect(route.Status.RouteID).To(gomega.BeEmpty())
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("rejects adoption when the remote virtual network name differs without recording its ID", func() {
		fixture := newPrivateNetworkFixture("vnet-adoption-mismatch")
		fixture.create()
		testPrivateNetworkCloudflare.putVirtualNetwork(flarecloudflare.VirtualNetwork{ID: "foreign-vnet", Name: "foreign"})
		vnet := fixture.virtualNetwork("wanted")
		vnet.Spec.ExternalRef = &v1alpha1.VirtualNetworkExternalReference{VirtualNetworkID: "foreign-vnet"}
		vnet.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), vnet)).To(gomega.Succeed())
			condition := statusutil.FindCondition(vnet.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match adoption expectation"))
			g.Expect(vnet.Status.VirtualNetworkID).To(gomega.BeEmpty())
			g.Expect(vnet.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), vnet)).To(gomega.Succeed())
			condition := statusutil.FindCondition(vnet.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match adoption expectation"))
			g.Expect(condition.Message).NotTo(gomega.ContainSubstring("ID is not verified"))
			g.Expect(vnet.Status.VirtualNetworkID).To(gomega.BeEmpty())
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateVirtualNetwork")).To(gomega.BeZero())
	})

	ginkgo.It("records identity for successful managed adoptions", func() {
		fixture := newPrivateNetworkFixture("successful-adoption")
		fixture.create()
		testPrivateNetworkCloudflare.putVirtualNetwork(flarecloudflare.VirtualNetwork{ID: "adopted-vnet", Name: "adopted"})
		vnet := fixture.virtualNetwork("adopted")
		vnet.Spec.ExternalRef = &v1alpha1.VirtualNetworkExternalReference{VirtualNetworkID: "adopted-vnet"}
		vnet.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
		fixture.waitVirtualNetworkReady(vnet)
		gomega.Expect(vnet.Status.VirtualNetworkID).To(gomega.Equal("adopted-vnet"))
		gomega.Expect(vnet.Status.OwnershipVerified).To(gomega.BeTrue())

		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "adopted-network-route", Network: "10.210.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID,
		})
		networkRoute := fixture.networkRoute("adopted-network", "10.210.0.0/16", vnet.Name)
		networkRoute.Spec.ExternalRef = &v1alpha1.NetworkRouteExternalReference{RouteID: "adopted-network-route"}
		networkRoute.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "adopted-hostname-route", Hostname: "adopted.private.internal", TunnelID: fixture.tunnelID(),
		})
		hostnameRoute := fixture.hostnameRoute("adopted-hostname", "adopted.private.internal")
		hostnameRoute.Spec.ExternalRef = &v1alpha1.HostnameRouteExternalReference{RouteID: "adopted-hostname-route"}
		hostnameRoute.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		gomega.Expect(testClient.Create(testContext, networkRoute)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, hostnameRoute)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(networkRoute), networkRoute)).To(gomega.Succeed())
			g.Expect(networkRoute.Status.RouteID).To(gomega.Equal("adopted-network-route"))
			g.Expect(networkRoute.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(networkRoute.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(hostnameRoute), hostnameRoute)).To(gomega.Succeed())
			g.Expect(hostnameRoute.Status.RouteID).To(gomega.Equal("adopted-hostname-route"))
			g.Expect(hostnameRoute.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(hostnameRoute.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateVirtualNetwork")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateNetworkRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("allows overlapping CIDRs in different virtual networks", func() {
		fixture := newPrivateNetworkFixture("vnet-isolation")
		fixture.create()
		prod := fixture.createVirtualNetwork("prod")
		dev := fixture.createVirtualNetwork("dev")
		fixture.waitVirtualNetworkReady(prod)
		fixture.waitVirtualNetworkReady(dev)
		first := fixture.networkRoute("first", "10.96.0.0/12", prod.Name)
		second := fixture.networkRoute("second", "10.100.0.0/16", dev.Name)
		gomega.Expect(testClient.Create(testContext, first)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, second)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			for _, route := range []*v1alpha1.NetworkRoute{first, second} {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
				g.Expect(statusutil.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
			}
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateNetworkRoute")).To(gomega.Equal(2))
	})

	ginkgo.It("keeps the applied claim and peer routes when an IP lookup fails after convergence", func() {
		fixture := newPrivateNetworkFixture("lookup-failure")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		peer := fixture.networkRoute("peer", "10.96.0.0/12", vnet.Name)
		route := fixture.networkRoute("lookup", "10.200.0.0/16", vnet.Name)
		gomega.Expect(testClient.Create(testContext, peer)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			for _, object := range []*v1alpha1.NetworkRoute{peer, route} {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(object), object)).To(gomega.Succeed())
				g.Expect(statusutil.ConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
			}
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		appliedGeneration := route.Status.Applied.ObservedGeneration

		route.Spec.IPLookup = &v1alpha1.NetworkRouteIPLookupSpec{
			IP:                "10.0.1.5",
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name},
		}
		gomega.Expect(testClient.Update(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.ObservedGeneration).To(gomega.Equal(route.Generation))
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(route.Status.Applied.Network).To(gomega.Equal("10.200.0.0/16"))
			g.Expect(route.Status.Applied.ObservedGeneration).To(gomega.Equal(appliedGeneration))
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(peer), peer)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(peer.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("LookupNetworkRoute")).To(gomega.BeNumerically(">=", 1))
	})

	ginkgo.It("orphans managed routes on deletion without remote deletes", func() {
		fixture := newPrivateNetworkFixture("route-orphan")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		cidr := fixture.networkRoute("orphaned-network", "10.96.0.0/12", vnet.Name)
		cidr.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		hostname := fixture.hostnameRoute("orphaned-hostname", "orphan.private.internal")
		hostname.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		gomega.Expect(testClient.Create(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, hostname)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			for _, route := range []client.Object{cidr, hostname} {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			}
			g.Expect(cidr.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(hostname.Status.RouteID).NotTo(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, hostname)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(cidr), new(v1alpha1.NetworkRoute))) &&
				apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(hostname), new(v1alpha1.HostnameRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteNetworkRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("keeps a deleting virtual network until its referencing route is gone", func() {
		fixture := newPrivateNetworkFixture("vnet-blocked")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		route := fixture.networkRoute("referencing", "10.96.0.0/12", vnet.Name)
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, vnet)).To(gomega.Succeed())
		gomega.Consistently(func() error {
			return testClient.Get(testContext, client.ObjectKeyFromObject(vnet), new(v1alpha1.VirtualNetwork))
		}).WithTimeout(2 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteVirtualNetwork")).To(gomega.BeZero())

		gomega.Expect(testClient.Delete(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), new(v1alpha1.VirtualNetwork)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteVirtualNetwork")).To(gomega.Equal(1))
	})

	ginkgo.It("reports conflicting remote targets on observed routes without mutation", func() {
		fixture := newPrivateNetworkFixture("observe-conflict")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "external-network", Network: "192.168.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID,
		})
		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "external-hostname", Hostname: "other.private.internal", TunnelID: fixture.tunnelID(),
		})
		cidr := fixture.networkRoute("observed-network", "10.96.0.0/12", vnet.Name)
		cidr.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		cidr.Spec.ExternalRef = &v1alpha1.NetworkRouteExternalReference{RouteID: "external-network"}
		hostname := fixture.hostnameRoute("observed-hostname", "observed.private.internal")
		hostname.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		hostname.Spec.ExternalRef = &v1alpha1.HostnameRouteExternalReference{RouteID: "external-hostname"}
		gomega.Expect(testClient.Create(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, hostname)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(cidr), cidr)).To(gomega.Succeed())
			networkCondition := statusutil.FindCondition(cidr.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(networkCondition).NotTo(gomega.BeNil())
			g.Expect(networkCondition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(networkCondition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(networkCondition.Message).To(gomega.ContainSubstring("does not match resolved target"))
			g.Expect(cidr.Status.RouteID).To(gomega.Equal("external-network"))
			g.Expect(cidr.Status.OwnershipVerified).To(gomega.BeFalse())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(hostname), hostname)).To(gomega.Succeed())
			hostnameCondition := statusutil.FindCondition(hostname.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(hostnameCondition).NotTo(gomega.BeNil())
			g.Expect(hostnameCondition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(hostnameCondition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(hostname.Status.RouteID).To(gomega.Equal("external-hostname"))
			g.Expect(hostname.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateNetworkRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateNetworkRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateHostnameRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateHostnameRoute")).To(gomega.BeZero())

		gomega.Expect(testClient.Delete(testContext, cidr)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, hostname)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(cidr), new(v1alpha1.NetworkRoute))) &&
				apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(hostname), new(v1alpha1.HostnameRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteNetworkRoute")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteHostnameRoute")).To(gomega.BeZero())
	})

	ginkgo.It("reports a conflicting remote name on an observed virtual network without mutation", func() {
		fixture := newPrivateNetworkFixture("vnet-observe-conflict")
		fixture.create()
		testPrivateNetworkCloudflare.putVirtualNetwork(flarecloudflare.VirtualNetwork{ID: "external-vnet", Name: "other-name"})
		vnet := fixture.virtualNetwork("wanted-name")
		vnet.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		vnet.Spec.ExternalRef = &v1alpha1.VirtualNetworkExternalReference{VirtualNetworkID: "external-vnet"}
		gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), vnet)).To(gomega.Succeed())
			condition := statusutil.FindCondition(vnet.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("does not match spec.name"))
			g.Expect(vnet.Status.VirtualNetworkID).To(gomega.Equal("external-vnet"))
			g.Expect(vnet.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("CreateVirtualNetwork")).To(gomega.BeZero())
		gomega.Expect(testPrivateNetworkCloudflare.count("UpdateVirtualNetwork")).To(gomega.BeZero())

		gomega.Expect(testClient.Delete(testContext, vnet)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(vnet), new(v1alpha1.VirtualNetwork)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteVirtualNetwork")).To(gomega.BeZero())
	})

	ginkgo.It("keeps the applied claim and isolates peers when the network route IP lookup fails", func() {
		fixture := newPrivateNetworkFixture("lookup-failure")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		failing := fixture.networkRoute("failing", "10.96.0.0/12", vnet.Name)
		failing.Spec.IPLookup = &v1alpha1.NetworkRouteIPLookupSpec{
			IP:                "192.0.2.1",
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name},
		}
		gomega.Expect(testClient.Create(testContext, failing)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(failing), failing)).To(gomega.Succeed())
			g.Expect(failing.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(failing.Status.Applied.Network).To(gomega.Equal("10.96.0.0/12"))
			g.Expect(failing.Status.Applied.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(failing.Status.Applied.VirtualNetworkID).To(gomega.Equal(vnet.Status.VirtualNetworkID))
			condition := statusutil.FindCondition(failing.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Pending"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(failing), failing)).To(gomega.Succeed())
			g.Expect(failing.Status.Applied.Network).To(gomega.Equal("10.96.0.0/12"))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		peer := fixture.networkRoute("peer", "10.200.0.0/16", vnet.Name)
		gomega.Expect(testClient.Create(testContext, peer)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(peer), peer)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(peer.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		overlapping := fixture.networkRoute("overlapping", "10.96.128.0/17", vnet.Name)
		gomega.Expect(testClient.Create(testContext, overlapping)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(overlapping), overlapping)).To(gomega.Succeed())
			condition := statusutil.FindCondition(overlapping.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("overlaps applied NetworkRoute"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("LookupNetworkRoute")).To(gomega.BeNumerically(">=", 2))
	})

	ginkgo.It("retries an IP lookup that returns a network route without an ID", func() {
		fixture := newPrivateNetworkFixture("idless-lookup")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		route := fixture.networkRoute("services", "10.96.0.0/12", vnet.Name)
		route.Spec.IPLookup = &v1alpha1.NetworkRouteIPLookupSpec{
			IP:                "10.96.1.1",
			VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name},
		}
		testPrivateNetworkCloudflare.setLookupIDLess(true)
		ginkgo.DeferCleanup(testPrivateNetworkCloudflare.setLookupIDLess, false)
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(route.Status.RouteID).NotTo(gomega.BeEmpty())
			g.Expect(route.Status.Applied.Network).To(gomega.Equal("10.96.0.0/12"))
			condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Pending"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("LookupNetworkRoute")).To(gomega.BeNumerically(">=", 1))

		testPrivateNetworkCloudflare.setLookupIDLess(false)
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(route.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
			g.Expect(route.Status.IPLookup).NotTo(gomega.BeNil())
			g.Expect(route.Status.IPLookup.Result).NotTo(gomega.BeNil())
			g.Expect(route.Status.IPLookup.Result.RouteID).To(gomega.Equal(route.Status.RouteID))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("does not record an applied claim when the managed write fails", func() {
		fixture := newPrivateNetworkFixture("failed-write")
		fixture.create()
		networkRoute := fixture.networkRoute("mismatch-network", "10.150.0.0/16", "")
		networkRoute.Spec.VirtualNetworkRef = nil
		networkOwner, err := privateOwnerComment(testContext, testClient, networkRoute, networkRoute.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "mismatch-network-remote", Network: "10.150.0.0/16", TunnelID: fixture.tunnelID(),
			TunnelType: flarecloudflare.NetworkTunnelTypeWARPConnector, Comment: networkOwner,
		})
		hostnameRoute := fixture.hostnameRoute("mismatch-hostname", "mismatch.private.internal")
		hostnameOwner, err := privateOwnerComment(testContext, testClient, hostnameRoute, hostnameRoute.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "mismatch-hostname-remote", Hostname: "mismatch.private.internal", TunnelID: fixture.tunnelID(),
			TunnelType: flarecloudflare.NetworkTunnelTypeWARPConnector, Comment: hostnameOwner,
		})
		gomega.Expect(testClient.Create(testContext, networkRoute)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, hostnameRoute)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(networkRoute), networkRoute)).To(gomega.Succeed())
			g.Expect(networkRoute.Status.RouteID).To(gomega.Equal("mismatch-network-remote"))
			g.Expect(networkRoute.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(networkRoute.Status.Applied.Network).To(gomega.BeEmpty())
			condition := statusutil.FindCondition(networkRoute.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("tunnel type"))
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(hostnameRoute), hostnameRoute)).To(gomega.Succeed())
			g.Expect(hostnameRoute.Status.RouteID).To(gomega.Equal("mismatch-hostname-remote"))
			g.Expect(hostnameRoute.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(hostnameRoute.Status.Applied.Hostname).To(gomega.BeEmpty())
			hostnameCondition := statusutil.FindCondition(hostnameRoute.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(hostnameCondition).NotTo(gomega.BeNil())
			g.Expect(hostnameCondition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(hostnameCondition.Reason).To(gomega.Equal("Conflict"))
			g.Expect(hostnameCondition.Message).To(gomega.ContainSubstring("tunnel type"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("deletes a half-persisted network route only after live ownership proof", func() {
		fixture := newPrivateNetworkFixture("legacy-half-state")
		fixture.create()
		vnet := fixture.createVirtualNetwork("prod")
		fixture.waitVirtualNetworkReady(vnet)
		seed := func(route *v1alpha1.NetworkRoute, network string) {
			ownerComment, err := privateOwnerComment(testContext, testClient, route, route.Spec.Comment)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Eventually(func(g gomega.Gomega) {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Finalizers).To(gomega.ContainElement(v1alpha1.NetworkRouteFinalizer))
				route.Status = v1alpha1.NetworkRouteStatus{
					RouteID:           "zombie-" + route.Name,
					Network:           network,
					TunnelID:          fixture.tunnelID(),
					TunnelType:        v1alpha1.TunnelRemoteTypeCloudflareTunnel,
					VirtualNetworkID:  vnet.Status.VirtualNetworkID,
					Comment:           ownerComment,
					OwnershipVerified: true,
				}
				g.Expect(testClient.Status().Update(testContext, route)).To(gomega.Succeed())
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
			gomega.Eventually(func(g gomega.Gomega) {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Status.RouteID).To(gomega.Equal("zombie-" + route.Name))
				g.Expect(route.Status.OwnershipVerified).To(gomega.BeTrue())
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}
		zombie := fixture.networkRoute("zombie", "10.96.0.0/16", vnet.Name)
		zombie.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, zombie)).To(gomega.Succeed())
		seed(zombie, "10.96.0.0/16")
		zombieOwner, err := privateOwnerComment(testContext, testClient, zombie, zombie.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		peer := fixture.networkRoute("peer", "10.200.0.0/16", vnet.Name)
		gomega.Expect(testClient.Create(testContext, peer)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(peer), peer)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(peer.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		blocked := fixture.networkRoute("blocked", "10.96.128.0/17", vnet.Name)
		gomega.Expect(testClient.Create(testContext, blocked)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(blocked), blocked)).To(gomega.Succeed())
			condition := statusutil.FindCondition(blocked.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("overlaps observed NetworkRoute"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "zombie-zombie", Network: "10.96.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID, Comment: zombieOwner,
		})
		gomega.Expect(testClient.Delete(testContext, zombie)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), new(v1alpha1.NetworkRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteNetworkRoute")).To(gomega.Equal(1))

		changed := fixture.networkRoute("changed", "10.97.0.0/16", vnet.Name)
		changed.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, changed)).To(gomega.Succeed())
		seed(changed, "10.97.0.0/16")
		changedOwner, err := privateOwnerComment(testContext, testClient, changed, changed.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "zombie-changed", Network: "10.150.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID, Comment: changedOwner,
		})
		foreign := fixture.networkRoute("foreign", "10.98.0.0/16", vnet.Name)
		foreign.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, foreign)).To(gomega.Succeed())
		seed(foreign, "10.98.0.0/16")
		testPrivateNetworkCloudflare.putNetworkRoute(flarecloudflare.NetworkRoute{
			ID: "zombie-foreign", Network: "10.98.0.0/16", TunnelID: fixture.tunnelID(), VirtualNetworkID: vnet.Status.VirtualNetworkID, Comment: "terraform",
		})
		gomega.Expect(testClient.Delete(testContext, changed)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, foreign)).To(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(changed), changed)).To(gomega.Succeed())
			g.Expect(changed.Finalizers).To(gomega.ContainElement(v1alpha1.NetworkRouteFinalizer))
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(foreign), foreign)).To(gomega.Succeed())
			g.Expect(foreign.Finalizers).To(gomega.ContainElement(v1alpha1.NetworkRouteFinalizer))
		}).WithTimeout(2 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteNetworkRoute")).To(gomega.Equal(1))

		gone := fixture.networkRoute("gone", "10.99.0.0/16", vnet.Name)
		gone.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, gone)).To(gomega.Succeed())
		seed(gone, "10.99.0.0/16")
		gomega.Expect(testClient.Delete(testContext, gone)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(gone), new(v1alpha1.NetworkRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteNetworkRoute")).To(gomega.Equal(1))
	})

	ginkgo.It("keeps a half-persisted wildcard hostname route claim and deletes it from observed identity", func() {
		fixture := newPrivateNetworkFixture("legacy-hostname")
		fixture.create()
		zombie := fixture.hostnameRoute("zombie", "*.private.internal")
		zombie.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, zombie)).To(gomega.Succeed())
		zombieOwner, err := privateOwnerComment(testContext, testClient, zombie, zombie.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			g.Expect(zombie.Finalizers).To(gomega.ContainElement(v1alpha1.HostnameRouteFinalizer))
			zombie.Status = v1alpha1.HostnameRouteStatus{
				RouteID:           "zombie-hostname-route",
				Hostname:          "private.internal",
				TunnelID:          fixture.tunnelID(),
				TunnelType:        v1alpha1.TunnelRemoteTypeCloudflareTunnel,
				Comment:           zombieOwner,
				OwnershipVerified: true,
			}
			g.Expect(testClient.Status().Update(testContext, zombie)).To(gomega.Succeed())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			g.Expect(zombie.Status.RouteID).To(gomega.Equal("zombie-hostname-route"))
			g.Expect(zombie.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		peer := fixture.hostnameRoute("peer", "other.internal")
		gomega.Expect(testClient.Create(testContext, peer)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(peer), peer)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(peer.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		blocked := fixture.hostnameRoute("blocked", "x.private.internal")
		gomega.Expect(testClient.Create(testContext, blocked)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(blocked), blocked)).To(gomega.Succeed())
			condition := statusutil.FindCondition(blocked.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("overlaps observed HostnameRoute"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "zombie-hostname-route", Hostname: "private.internal", TunnelID: fixture.tunnelID(), Comment: zombieOwner,
		})
		gomega.Expect(testClient.Delete(testContext, zombie)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), new(v1alpha1.HostnameRoute)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteHostnameRoute")).To(gomega.Equal(1))
	})

	ginkgo.It("derives hostname overlap claims from observed identity when spec and remote disagree", func() {
		fixture := newPrivateNetworkFixture("observed-claim")
		fixture.create()
		seed := func(route *v1alpha1.HostnameRoute, observed string) {
			ownerComment, err := privateOwnerComment(testContext, testClient, route, route.Spec.Comment)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Eventually(func(g gomega.Gomega) {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Finalizers).To(gomega.ContainElement(v1alpha1.HostnameRouteFinalizer))
				route.Status = v1alpha1.HostnameRouteStatus{
					RouteID:           "zombie-" + route.Name,
					Hostname:          observed,
					TunnelID:          fixture.tunnelID(),
					TunnelType:        v1alpha1.TunnelRemoteTypeCloudflareTunnel,
					Comment:           ownerComment,
					OwnershipVerified: true,
				}
				g.Expect(testClient.Status().Update(testContext, route)).To(gomega.Succeed())
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
			gomega.Eventually(func(g gomega.Gomega) {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				g.Expect(route.Status.RouteID).To(gomega.Equal("zombie-" + route.Name))
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}
		assertRejected := func(route *v1alpha1.HostnameRoute, message string) {
			gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
			gomega.Eventually(func(g gomega.Gomega) {
				g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(route), route)).To(gomega.Succeed())
				condition := statusutil.FindCondition(route.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
				g.Expect(condition.Message).To(gomega.ContainSubstring(message))
			}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}

		exact := fixture.hostnameRoute("exact", "*.private.internal")
		exact.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, exact)).To(gomega.Succeed())
		seed(exact, "exact.private.internal")
		assertRejected(fixture.hostnameRoute("exact-collision", "exact.private.internal"), "overlaps observed HostnameRoute")
		peer := fixture.hostnameRoute("peer", "x.private.internal")
		gomega.Expect(testClient.Create(testContext, peer)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(peer), peer)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(peer.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		wild := fixture.hostnameRoute("wild", "wild.private.internal")
		wild.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, wild)).To(gomega.Succeed())
		seed(wild, "wild.private.internal")
		assertRejected(fixture.hostnameRoute("wild-collision", "*.wild.private.internal"), "overlaps observed HostnameRoute")

		malformed := fixture.hostnameRoute("malformed", "ok.private.internal")
		malformed.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, malformed)).To(gomega.Succeed())
		seed(malformed, "Not A Hostname")
		assertRejected(fixture.hostnameRoute("malformed-peer", "unrelated.internal"), "invalid observed hostname")
	})

	ginkgo.It("refuses to delete a half-persisted hostname route outside the tenant grant", func() {
		fixture := newPrivateNetworkFixture("delete-grant")
		fixture.create()
		var account v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
		account.Spec.Grants[1].Hostnames = []string{"allowed.private.internal"}
		gomega.Expect(testClient.Update(testContext, &account)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.accountName}, &account)).To(gomega.Succeed())
			g.Expect(account.Spec.Grants[1].Hostnames).To(gomega.Equal([]string{"allowed.private.internal"}))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		zombie := fixture.hostnameRoute("zombie", "*.private.internal")
		zombie.Spec.TunnelRef.Name = "missing"
		gomega.Expect(testClient.Create(testContext, zombie)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			condition := meta.FindStatusCondition(zombie.Status.Conditions, v1alpha1.PrivateNetworkConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("UnsupportedValue"))
			g.Expect(condition.Message).To(gomega.ContainSubstring("hostname"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		zombieOwner, err := privateOwnerComment(testContext, testClient, zombie, zombie.Spec.Comment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			zombie.Status = v1alpha1.HostnameRouteStatus{
				RouteID:           "zombie-hostname-route",
				Hostname:          "private.internal",
				TunnelID:          fixture.tunnelID(),
				TunnelType:        v1alpha1.TunnelRemoteTypeCloudflareTunnel,
				Comment:           zombieOwner,
				OwnershipVerified: true,
			}
			g.Expect(testClient.Status().Update(testContext, zombie)).To(gomega.Succeed())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			g.Expect(zombie.Status.RouteID).To(gomega.Equal("zombie-hostname-route"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		testPrivateNetworkCloudflare.putHostnameRoute(flarecloudflare.HostnameRoute{
			ID: "zombie-hostname-route", Hostname: "private.internal", TunnelID: fixture.tunnelID(), Comment: zombieOwner,
		})
		gomega.Expect(testClient.Delete(testContext, zombie)).To(gomega.Succeed())
		gomega.Consistently(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(zombie), zombie)).To(gomega.Succeed())
			g.Expect(zombie.Finalizers).To(gomega.ContainElement(v1alpha1.HostnameRouteFinalizer))
		}).WithTimeout(2 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testPrivateNetworkCloudflare.count("DeleteHostnameRoute")).To(gomega.BeZero())
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
		TunnelRef:         v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace},
		VirtualNetworkRef: &corev1.LocalObjectReference{Name: virtualNetworkName},
		AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-tenant": f.tenantNamespace}}},
		ManagementPolicy:  v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
	}}
}

func (f *privateNetworkFixture) hostnameRoute(name, hostname string) *v1alpha1.HostnameRoute {
	return &v1alpha1.HostnameRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.platformNamespace, Labels: map[string]string{"private-route": "allowed"}}, Spec: v1alpha1.HostnameRouteSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.accountName}, Hostname: hostname,
		TunnelRef:         v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace},
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
	lookupIDLess    bool
}

var _ flarecloudflare.NetworkAPI = (*fakePrivateNetworkCloudflare)(nil)

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
	f.lookupIDLess = false
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
	return &cloudflaresdk.Error{
		StatusCode: http.StatusNotFound,
		Request:    &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/" + resource + "/" + id}},
		Response:   &http.Response{StatusCode: http.StatusNotFound},
	}
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
func (f *fakePrivateNetworkCloudflare) LookupNetworkRoute(_ context.Context, input flarecloudflare.NetworkRouteLookupInput) (flarecloudflare.NetworkRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("LookupNetworkRoute")
	ip, err := netip.ParseAddr(input.IP)
	if err != nil {
		return flarecloudflare.NetworkRoute{}, fmt.Errorf("parse lookup IP %q: %w", input.IP, err)
	}
	bestPrefixBits := -1
	var result flarecloudflare.NetworkRoute
	for _, remote := range f.networkRoutes {
		prefix, parseErr := netip.ParsePrefix(remote.Network)
		if parseErr != nil || remote.Deleted || remote.VirtualNetworkID != input.VirtualNetworkID || !prefix.Contains(ip) {
			continue
		}
		if prefix.Bits() > bestPrefixBits {
			bestPrefixBits = prefix.Bits()
			result = remote
		}
	}
	if result.ID == "" {
		return flarecloudflare.NetworkRoute{}, f.missing("networkroutes", input.IP)
	}
	if f.lookupIDLess {
		result.ID = ""
	}
	return result, nil
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
func (f *fakePrivateNetworkCloudflare) putVirtualNetwork(remote flarecloudflare.VirtualNetwork) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.virtualNetworks[remote.ID] = remote
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
func (f *fakePrivateNetworkCloudflare) setLookupIDLess(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupIDLess = value
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
