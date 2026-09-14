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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
)

var accessFixtureCounter atomic.Uint64

var _ = ginkgo.Describe("AccessApplication reconciler", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func() {
		ensureSystemNamespace("kube-system")
		ensureSystemNamespace(accessApplicationAUDNamespace)
	})

	ginkgo.BeforeEach(func() {
		testAccessCloudflare.Reset()
		testTunnelCloudflare.Reset()
		testAccountCloudflare.reset()
	})

	ginkgo.It("uses injective child names and only accepts a settled pre-applied Blocked version", func() {
		gomega.Expect(bypassChildApplicationName("parent", "a.b.example.test", "/a/b")).
			NotTo(gomega.Equal(bypassChildApplicationName("parent", "a-b.example.test", "/a-b")))
		tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, Applied: 7},
		}}
		blocked := v1alpha1.CloudflareTunnelHostnameStatus{Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 7}
		gomega.Expect(revocationBaseline(blocked, tunnel)).To(gomega.Equal(int64(6)))
		tunnel.Status.ConfigVersion.Desired = 8
		gomega.Expect(revocationBaseline(blocked, tunnel)).To(gomega.Equal(int64(7)))
	})

	ginkgo.It("bounds internal tag names to Cloudflare's 35-character limit with distinct digests", func() {
		ownerOne := accessDigestTag(accessOwnerTagPrefix, "owner-one")
		ownerTwo := accessDigestTag(accessOwnerTagPrefix, "owner-two")
		gomega.Expect(ownerOne).To(gomega.HaveLen(accessTagNameMaxLength))
		gomega.Expect(ownerTwo).To(gomega.HaveLen(accessTagNameMaxLength))
		gomega.Expect(ownerOne).NotTo(gomega.Equal(ownerTwo))
		gomega.Expect(validInternalDigestTag(ownerOne, accessOwnerTagPrefix)).To(gomega.BeTrue())

		bypassOne := accessBypassTag(ownerOne, "tenant/parent/bypass/one")
		bypassTwo := accessBypassTag(ownerOne, "tenant/parent/bypass/two")
		gomega.Expect(bypassOne).To(gomega.HaveLen(accessTagNameMaxLength))
		gomega.Expect(bypassTwo).To(gomega.HaveLen(accessTagNameMaxLength))
		gomega.Expect(bypassOne).NotTo(gomega.Equal(bypassTwo))
		gomega.Expect(validInternalDigestTag(bypassOne, accessBypassTagPrefix)).To(gomega.BeTrue())
	})

	ginkgo.It("requires the exact bypass child name for recovery and deletion", func() {
		remote := newFakeAccessApplicationCloudflare()
		ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
		parentName := "tenant/parent"
		expectedName := bypassChildApplicationName(parentName, "api.example.test", "/public")
		bypassTag := accessBypassTag(ownerTag, expectedName)
		wrongChild := flarecloudflare.AccessApplication{
			ID: "wrong-child", Name: parentName + "/bypass/wrong-name",
			Tags: []string{accessManagedTag, ownerTag, bypassTag},
		}
		remote.Put(wrongChild)

		recovered, found, err := findOwnedBypassApplication(testContext, remote, ownerTag, bypassTag, expectedName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeFalse())
		gomega.Expect(recovered.ID).To(gomega.BeEmpty())
		gomega.Expect(remote.Calls()).NotTo(gomega.ContainElement("Update:wrong-child"))

		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: "tenant"},
			Spec:       v1alpha1.AccessApplicationSpec{Application: v1alpha1.AccessApplicationSettings{Name: parentName}},
		}
		wrongParent := flarecloudflare.AccessApplication{
			ID: "wrong-parent", Name: "other/parent",
			Tags: []string{accessManagedTag, ownerTag},
		}
		parentIDs, childIDs, tagNames, err := accessApplicationDeletionTargets(application, ownerTag, []flarecloudflare.AccessApplication{wrongParent, wrongChild})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parentIDs).To(gomega.BeEmpty())
		gomega.Expect(childIDs).To(gomega.BeEmpty())
		gomega.Expect(tagNames).To(gomega.BeEmpty())
	})

	ginkgo.It("recovers a completed AdoptById rename after status loss", func() {
		remote := newFakeAccessApplicationCloudflare()
		ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
		for _, tagName := range []string{accessManagedTag, ownerTag} {
			remote.PutTag(tagName)
		}
		remote.Put(flarecloudflare.AccessApplication{
			ID: "external-adopted", Name: "tenant/desired",
			Tags: []string{accessManagedTag, ownerTag},
		})
		application := &v1alpha1.AccessApplication{
			Spec: v1alpha1.AccessApplicationSpec{
				Application: v1alpha1.AccessApplicationSettings{Name: "tenant/desired"},
				ExternalRef: &v1alpha1.AccessApplicationExternalReference{ApplicationID: "external-adopted"},
				Adoption: v1alpha1.AdoptionSpec{
					Mode:   v1alpha1.AdoptionModeAdoptByID,
					Expect: v1alpha1.AdoptionExpect{Name: "initial-name"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		observed, err := (&AccessApplicationReconciler{}).reconcileRemoteApplication(
			testContext,
			remote,
			application,
			flarecloudflare.AccessApplicationInput{
				Name: "tenant/desired",
				Tags: []string{accessManagedTag, ownerTag},
			},
			ownerTag,
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(observed.ID).To(gomega.Equal("external-adopted"))
		gomega.Expect(remote.Calls()).To(gomega.ContainElement("Update:external-adopted"))
	})

	ginkgo.It("removes an obsolete remote bypass even when its Kubernetes status was lost", func() {
		remote := newFakeAccessApplicationCloudflare()
		ownerTag := accessDigestTag(accessOwnerTagPrefix, "owner")
		parentName := "tenant/parent"
		childName := bypassChildApplicationName(parentName, "api.example.test", "/public")
		bypassTag := accessBypassTag(ownerTag, childName)
		for _, tagName := range []string{accessManagedTag, ownerTag, bypassTag} {
			remote.PutTag(tagName)
		}
		created, err := remote.CreateAccessApplication(testContext, flarecloudflare.AccessApplicationInput{
			Name: childName, Domain: "api.example.test",
			Tags: []string{accessManagedTag, ownerTag, bypassTag},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: "tenant"},
			Spec:       v1alpha1.AccessApplicationSpec{Application: v1alpha1.AccessApplicationSettings{Name: parentName}},
			Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "parent-id"},
		}
		children, err := (&AccessApplicationReconciler{}).reconcileBypassApplications(
			testContext,
			remote,
			application,
			nil,
			ownerTag,
			"cluster-id",
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(children).To(gomega.BeEmpty())
		gomega.Expect(remote.Has(created.ID)).To(gomega.BeFalse())
		gomega.Expect(remote.Tags()).To(gomega.ConsistOf(accessManagedTag, ownerTag))
		calls := remote.Calls()
		gomega.Expect(indexOfAccessCall(calls, "Delete:"+created.ID)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "DeleteTag:"+bypassTag)))
	})
	ginkgo.It("treats deleting and stale-generation private routes as TargetNotFound", func() {
		accepted := metav1.Condition{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}
		route := v1alpha1.NetworkRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "tenant", Generation: 2},
			Status:     v1alpha1.NetworkRouteStatus{ObservedGeneration: 1, Conditions: []metav1.Condition{accepted}},
		}
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant"},
			Spec: v1alpha1.AccessApplicationSpec{PrivateDestinations: []v1alpha1.AccessPrivateDestinationSpec{{
				NetworkRouteRef: &corev1.LocalObjectReference{Name: route.Name}, PortRange: "443",
			}}},
		}
		failure := validatePrivateRouteLifecycle(gatewayapi.Inputs{NetworkRoutes: []v1alpha1.NetworkRoute{route}}, application)
		gomega.Expect(failure).NotTo(gomega.BeNil())
		gomega.Expect(failure.Reason).To(gomega.Equal("TargetNotFound"))
		gomega.Expect(failure.Message).To(gomega.ContainSubstring("current generation"))

		now := metav1.Now()
		route.Status.ObservedGeneration = route.Generation
		route.DeletionTimestamp = &now
		failure = validatePrivateRouteLifecycle(gatewayapi.Inputs{NetworkRoutes: []v1alpha1.NetworkRoute{route}}, application)
		gomega.Expect(failure).NotTo(gomega.BeNil())
		gomega.Expect(failure.Message).To(gomega.ContainSubstring("deleting"))
	})

	ginkgo.It("keeps Tunnel teardown blocked by the private-tunnel ledger until Managed+Delete cleanup completes", func() {
		application := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": v1alpha1.GroupVersion.String(),
			"kind":       "AccessApplication",
			"metadata":   map[string]any{"name": "private", "namespace": "tenant"},
			"spec":       map[string]any{"managementPolicy": "Managed", "deletionPolicy": "Delete"},
			"status": map[string]any{
				"applicationId": "remote-app",
				"conditions":    []any{map[string]any{"type": "Programmed", "status": "False", "reason": "TargetNotFound"}},
			},
		}}
		targets, err := accessApplicationTargets(application, []string{"tenant/tunnel"}, "tenant/tunnel", "tenant", "", nil, nil, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(targets).To(gomega.BeTrue())
		gomega.Expect(accessApplicationCleanupComplete(application.Object)).To(gomega.BeFalse())
		gomega.Expect(unstructured.SetNestedField(application.Object, "", "status", "applicationId")).To(gomega.Succeed())
		gomega.Expect(accessApplicationCleanupComplete(application.Object)).To(gomega.BeTrue())

		application.SetAnnotations(map[string]string{"tenant-controlled": "not-json"})
		targets, err = accessApplicationTargets(application, nil, "tenant/tunnel", "tenant", "", nil, nil, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(targets).To(gomega.BeFalse())
		_, err = parsePrivateTunnelKeys([]byte("not-json"))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("decode private tunnel ledger")))
	})

	ginkgo.It("creates the remote application, private AUD Secret, and policy ancestors without exposing the AUD", func() {
		fixture := newAccessFixture("create", false, false)
		testAccessCloudflare.PutTag("customer-existing")
		fixture.application.Spec.Application.Tags = []string{"customer-existing"}
		fixture.create()

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(application.Status.Destinations).To(gomega.ContainElement(v1alpha1.AccessApplicationDestinationStatus{Type: "public", URI: fixture.hostname}))
			g.Expect(application.Status.Ancestors).To(gomega.HaveLen(1))
			g.Expect(application.Status.Ancestors[0].ControllerName).To(gomega.Equal(gatewayapi.ControllerName))
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var secret corev1.Secret
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret)).To(gomega.Succeed())
		gomega.Expect(secret.Data[v1alpha1.AccessApplicationAUDSecretKey]).To(gomega.Equal([]byte("aud-" + application.Status.ApplicationID)))
		gomega.Expect(secret.Labels[v1alpha1.AccessApplicationAUDSecretLabel]).To(gomega.Equal(fixture.namespace + "--access"))
		statusJSON, err := json.Marshal(application.Status)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(statusJSON)).NotTo(gomega.ContainSubstring("aud-"))
		parentInput := testAccessCloudflare.Input(application.Status.ApplicationID)
		gomega.Expect(parentInput.Tags).To(gomega.HaveLen(3))
		gomega.Expect(parentInput.Tags).To(gomega.ContainElements("customer-existing", accessManagedTag))
		var ownerTag string
		for _, tag := range parentInput.Tags {
			if validInternalDigestTag(tag, accessOwnerTagPrefix) {
				ownerTag = tag
			}
			gomega.Expect(tag).NotTo(gomega.ContainSubstring("="))
		}
		gomega.Expect(ownerTag).NotTo(gomega.BeEmpty())
		calls := testAccessCloudflare.Calls()
		gomega.Expect(calls).NotTo(gomega.ContainElements("GetTag:customer-existing", "CreateTag:customer-existing"))
		gomega.Expect(indexOfAccessCall(calls, "CreateTag:"+accessManagedTag)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "Create:"+fixture.remoteName())))
		gomega.Expect(indexOfAccessCall(calls, "CreateTag:"+ownerTag)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "Create:"+fixture.remoteName())))
		gomega.Expect(testAccessCloudflare.Calls()).To(gomega.ContainElement("Create:" + fixture.remoteName()))
	})

	ginkgo.It("rejects a missing policy reference before any remote write", func() {
		fixture := newAccessFixture("missing-policy", false, false)
		fixture.application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{{PolicyRef: &v1alpha1.NamespacedLocalObjectReference{Name: "missing"}}}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Message).To(gomega.ContainSubstring("AccessPolicy"))
			g.Expect(application.Status.ApplicationID).To(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElement("Create:" + fixture.remoteName()))
	})
	ginkgo.It("resolves a route-authorized private destination without publishing an AUD Secret", func() {
		fixture := newAccessFixture("private-route", false, false)
		fixture.application.Spec.TargetRefs = nil
		fixture.application.Spec.PrivateDestinations = []v1alpha1.AccessPrivateDestinationSpec{{
			NetworkRouteRef: &corev1.LocalObjectReference{Name: "private-route"},
			CIDR:            "10.96.12.34/32",
			PortRange:       "5432",
			L4Protocol:      v1alpha1.AccessL4ProtocolTCP,
		}}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var account v1alpha1.CloudflareAccount
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.account}, &account)).To(gomega.Succeed())
			before := account.DeepCopy()
			selector := metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}}
			account.Spec.Grants[0].PrivateRoutes = &v1alpha1.CloudflarePrivateRouteGrant{NetworkRouteSelector: &selector}
			account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
			account.Spec.Grants[0].Exposures = append(account.Spec.Grants[0].Exposures, v1alpha1.ExposurePrivate)
			g.Expect(testClient.Patch(testContext, &account, client.MergeFrom(before))).To(gomega.Succeed())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		vnet := &v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "private-vnet", Namespace: fixture.namespace},
			Spec: v1alpha1.VirtualNetworkSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.account},
				Name:       "private-vnet",
			},
		}
		gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
		route := &v1alpha1.NetworkRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "private-route", Namespace: fixture.namespace, Labels: map[string]string{"private-route": "allowed"}},
			Spec: v1alpha1.NetworkRouteSpec{
				AccountRef:        corev1.LocalObjectReference{Name: fixture.account},
				Network:           "10.96.0.0/16",
				TunnelRef:         v1alpha1.NamespacedObjectReference{Name: fixture.tunnelKey.Name},
				VirtualNetworkRef: corev1.LocalObjectReference{Name: vnet.Name},
				AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame},
			},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(application.Status.Destinations).To(gomega.HaveLen(1))
			g.Expect(application.Status.Destinations[0].Type).To(gomega.Equal("private"))
			g.Expect(application.Status.Destinations[0].CIDR).To(gomega.Equal("10.96.12.34/32"))
			g.Expect(application.Status.Destinations[0].PortRange).To(gomega.Equal("5432"))
			g.Expect(application.Status.Ancestors).To(gomega.HaveLen(1))
			g.Expect(application.Status.Ancestors[0].AncestorRef.Kind).NotTo(gomega.BeNil())
			g.Expect(string(*application.Status.Ancestors[0].AncestorRef.Kind)).To(gomega.Equal("NetworkRoute"))
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			programmed := findCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
			origin := findCondition(application.Status.Conditions, v1alpha1.AccessApplicationConditionOriginJWTEnforced)
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(origin.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(origin.Reason).To(gomega.Equal("NotApplicable"))
		}).WithTimeout(30 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var secrets corev1.SecretList
		gomega.Expect(testClient.List(testContext, &secrets, client.InNamespace(accessApplicationAUDNamespace), client.MatchingLabels{
			v1alpha1.AccessApplicationAUDSecretLabel: fixture.namespace + "--" + fixture.applicationKey.Name,
		})).To(gomega.Succeed())
		gomega.Expect(secrets.Items).To(gomega.BeEmpty())
		var ledger corev1.Secret
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{
			Namespace: accessApplicationAUDNamespace, Name: privateTunnelLedgerSecretName(application.UID),
		}, &ledger)).To(gomega.Succeed())
		keys, err := parsePrivateTunnelKeys(ledger.Data[accessApplicationPrivateTunnelsKey])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(keys).To(gomega.Equal([]string{fixture.tunnelKey.String()}))
	})
	ginkgo.It("cleans up a Managed+Delete Access application when its private route is deleted", func() {
		fixture := newAccessFixture("private-route-delete", false, false)
		application, route := preparePrivateNetworkRouteAccess(fixture)
		parentID := application.Status.ApplicationID
		gomega.Expect(testClient.Delete(testContext, route)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).To(gomega.BeEmpty())
			programmed := findCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Reason).To(gomega.Equal("TargetNotFound"))
			g.Expect(testAccessCloudflare.Has(parentID)).To(gomega.BeFalse())
			var ledger corev1.Secret
			err := testClient.Get(testContext, types.NamespacedName{
				Namespace: accessApplicationAUDNamespace, Name: privateTunnelLedgerSecretName(application.UID),
			}, &ledger)
			g.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue())
		}).WithTimeout(25 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("revokes but orphans the remote Access application when its private route is deleted", func() {
		fixture := newAccessFixture("private-route-orphan", false, false)
		fixture.application.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		application, route := preparePrivateNetworkRouteAccess(fixture)
		parentID := application.Status.ApplicationID
		gomega.Expect(testClient.Delete(testContext, route)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).To(gomega.Equal(parentID))
			programmed := findCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Reason).To(gomega.Equal("TargetNotFound"))
			g.Expect(testAccessCloudflare.Has(parentID)).To(gomega.BeTrue())
			var ledger corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{
				Namespace: accessApplicationAUDNamespace, Name: privateTunnelLedgerSecretName(application.UID),
			}, &ledger)).To(gomega.Succeed())
		}).WithTimeout(25 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("rejects an external bypass policy before creating the parent application", func() {
		fixture := newAccessFixture("external-bypass", false, false)
		fixture.application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{{
			ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "external-bypass"},
		}}
		testAccessCloudflare.SetPolicy(flarecloudflare.AccessPolicy{ID: "external-bypass", Name: "foreign-bypass", Decision: "bypass"})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal("Invalid"))
			g.Expect(accepted.Message).To(gomega.ContainSubstring("operator-managed"))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElement("Create:" + fixture.remoteName()))
	})

	ginkgo.It("recovers ambiguous parent and child creates by ownership tags without duplicates", func() {
		fixture := newAccessFixture("ambiguous-create", true, true)
		testAccessCloudflare.AmbiguousCreates(2)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(application.Status.BypassApplications).To(gomega.HaveLen(1))
			g.Expect(testAccessCloudflare.ApplicationCount()).To(gomega.Equal(2))
			childInput := testAccessCloudflare.Input(application.Status.BypassApplications[0].ApplicationID)
			tagName := firstTagWithPrefix(childInput.Tags, accessBypassTagPrefix)
			g.Expect(validInternalDigestTag(tagName, accessBypassTagPrefix)).To(gomega.BeTrue())
			g.Expect(tagName).To(gomega.Equal(accessBypassTag(
				firstTagWithPrefix(testAccessCloudflare.Input(application.Status.ApplicationID).Tags, accessOwnerTagPrefix),
				childInput.Name,
			)))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("confirms a racing Access tag create before creating the application", func() {
		fixture := newAccessFixture("tag-race", false, false)
		testAccessCloudflare.TagCreateConflict(accessManagedTag, 1)
		fixture.create()

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		calls := testAccessCloudflare.Calls()
		gomega.Expect(countAccessCall(calls, "GetTag:"+accessManagedTag)).To(gomega.BeNumerically(">=", 2))
		gomega.Expect(nthIndexOfAccessCall(calls, "GetTag:"+accessManagedTag, 2)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "Create:"+fixture.remoteName())))
	})

	ginkgo.It("does not accept a tag create conflict until a follow-up get confirms the tag", func() {
		fixture := newAccessFixture("tag-conflict-unconfirmed", false, false)
		testAccessCloudflare.Fail("CreateTag:"+accessManagedTag, &cloudflaresdk.Error{StatusCode: http.StatusConflict})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Message).To(gomega.ContainSubstring("confirm Access tag"))
			g.Expect(application.Status.ApplicationID).To(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElement("Create:" + fixture.remoteName()))
	})

	ginkgo.It("observes an external application without creating or updating it", func() {
		fixture := newAccessFixture("observe", false, false)
		fixture.application.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		fixture.application.Spec.ExternalRef = &v1alpha1.AccessApplicationExternalReference{ApplicationID: "external-observed"}
		testAccessCloudflare.Put(flarecloudflare.AccessApplication{ID: "external-observed", AUD: "aud-external-observed", Name: "terraform-app", Domain: fixture.hostname, Type: "self_hosted"})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).To(gomega.Equal("external-observed"))
			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret)).To(gomega.Succeed())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testAccessCloudflare.Calls()).To(gomega.ContainElement("Get:external-observed"))
		gomega.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElements("Create:"+fixture.remoteName(), "Update:external-observed"))
	})

	ginkgo.It("adopts the explicitly named remote application before managing it", func() {
		fixture := newAccessFixture("adopt", false, false)
		fixture.application.Spec.ExternalRef = &v1alpha1.AccessApplicationExternalReference{ApplicationID: "external-adopted"}
		fixture.application.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "existing-app"}}
		testAccessCloudflare.Put(flarecloudflare.AccessApplication{ID: "external-adopted", AUD: "aud-external-adopted", Name: "existing-app", Domain: fixture.hostname, Type: "self_hosted"})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).To(gomega.Equal("external-adopted"))
			g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionAccepted).Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(testAccessCloudflare.Input("external-adopted").Name).To(gomega.Equal(fixture.remoteName()))
			g.Expect(countAccessCall(testAccessCloudflare.Calls(), "Update:external-adopted")).To(gomega.BeNumerically(">=", 2))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("gives the older application collision precedence", func() {
		fixture := newAccessFixture("collision", false, false)
		fixture.create()
		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		newer := fixture.application.DeepCopy()
		newer.ResourceVersion = ""
		newer.UID = ""
		newer.Name = "access-newer"
		newer.Spec.Application.Name = fixture.remoteName() + "-newer"
		gomega.Expect(testClient.Create(testContext, newer)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var application v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(newer), &application)).To(gomega.Succeed())
			accepted := findCondition(application.Status.Conditions, accessApplicationConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal("Conflicted"))
			g.Expect(application.Status.ApplicationID).To(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElement("Create:" + newer.Spec.Application.Name))
	})
	ginkgo.It("fans the AUD handoff and data-plane status out to every target Gateway", func() {
		fixture := newAccessFixture("multi-target", false, false)
		fixture.create()
		secondGateway, secondTunnel := fixture.createAdditionalGateway("gateway-two", "tunnel-two", "multi-target-two.example.test")

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		before := application.DeepCopy()
		section := gatewayv1.SectionName("public")
		application.Spec.TargetRefs = append(application.Spec.TargetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			Group: gatewayv1.Group("gateway.networking.k8s.io"), Kind: gatewayv1.Kind("Gateway"),
			Name: gatewayv1.ObjectName(secondGateway.Name), SectionName: &section,
		})
		gomega.Expect(testClient.Patch(testContext, &application, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.DataPlanes).To(gomega.HaveLen(2))
			for _, gateway := range []types.NamespacedName{fixture.gatewayKey, client.ObjectKeyFromObject(secondGateway)} {
				var secret corev1.Secret
				g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, gateway)}, &secret)).To(gomega.Succeed())
				g.Expect(string(secret.Data[accessApplicationAUDReadyKey])).To(gomega.Equal("true"))
			}
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(secondTunnel.Name).To(gomega.Equal("tunnel-two"))
	})

	ginkgo.It("revokes and latches an invalidated policy until a fresh Blocked version, then recovers", func() {
		fixture := newAccessFixture("policy-revocation", false, false)
		fixture.create()
		var application v1alpha1.AccessApplication
		programAccessFixture(fixture, &application, 1)
		parentID := application.Status.ApplicationID

		before := application.DeepCopy()
		application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{{PolicyRef: &v1alpha1.NamespacedLocalObjectReference{Name: "missing-after-programming"}}}
		gomega.Expect(testClient.Patch(testContext, &application, client.MergeFrom(before))).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Annotations[accessApplicationRevocationAnnotation]).NotTo(gomega.BeEmpty())
			g.Expect(application.Status.DataPlanes).To(gomega.HaveLen(1))
			g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionProgrammed).Status).To(gomega.Equal(metav1.ConditionFalse))
			var secret corev1.Secret
			err := testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret)
			g.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue())
			g.Expect(testAccessCloudflare.Has(parentID)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		applyBlockedAfterLatch(fixture, &application)
		before = application.DeepCopy()
		application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}}
		gomega.Expect(testClient.Patch(testContext, &application, client.MergeFrom(before))).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Annotations[accessApplicationRevocationAnnotation]).To(gomega.BeEmpty())
			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret)).To(gomega.Succeed())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("latches a missing AUD handoff and refuses to recreate it before Blocked is acknowledged", func() {
		fixture := newAccessFixture("missing-aud", false, false)
		fixture.create()
		var application v1alpha1.AccessApplication
		programAccessFixture(fixture, &application, 1)
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey),
		}}
		gomega.Expect(testClient.Delete(testContext, secret)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Annotations[accessApplicationRevocationAnnotation]).NotTo(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(secret), &corev1.Secret{}))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		applyBlockedAfterLatch(fixture, &application)
		gomega.Eventually(func() error {
			return testClient.Get(testContext, client.ObjectKeyFromObject(secret), &corev1.Secret{})
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})
	ginkgo.It("revokes and deletes managed remote applications when the target disappears", func() {
		fixture := newAccessFixture("target-teardown", true, true)
		fixture.create()
		var application v1alpha1.AccessApplication
		programAccessFixture(fixture, &application, 1)
		parentID := application.Status.ApplicationID
		childID := application.Status.BypassApplications[0].ApplicationID
		gomega.Expect(testClient.Delete(testContext, &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: fixture.gatewayKey.Name, Namespace: fixture.namespace}})).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Annotations[accessApplicationRevocationAnnotation]).NotTo(gomega.BeEmpty())
			g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionProgrammed).Status).To(gomega.Equal(metav1.ConditionFalse))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		applyBlockedAfterLatch(fixture, &application)
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).To(gomega.BeEmpty())
			g.Expect(application.Status.BypassApplications).To(gomega.BeEmpty())
			programmed := findCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Reason).To(gomega.Equal("TargetNotFound"))
			g.Expect(testAccessCloudflare.Has(parentID)).To(gomega.BeFalse())
			g.Expect(testAccessCloudflare.Has(childID)).To(gomega.BeFalse())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("deletes the AUD first, waits for Blocked, then deletes child applications before the parent", func() {
		fixture := newAccessFixture("carveout-delete", true, true)
		testAccessCloudflare.PutTag("customer-retained")
		fixture.application.Spec.Application.Tags = []string{"customer-retained"}
		fixture.create()

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(application.Status.DataPlanes).To(gomega.HaveLen(1))
			g.Expect(application.Status.BypassApplications).To(gomega.HaveLen(1))
			g.Expect(application.Status.BypassApplications[0].Hostname).To(gomega.Equal(fixture.hostname))
			g.Expect(application.Status.BypassApplications[0].Path).To(gomega.Equal("/v1"))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		parentID := application.Status.ApplicationID
		childID := application.Status.BypassApplications[0].ApplicationID
		parentInput := testAccessCloudflare.Input(parentID)
		ownerTag := firstTagWithPrefix(parentInput.Tags, accessOwnerTagPrefix)
		gomega.Expect(validInternalDigestTag(ownerTag, accessOwnerTagPrefix)).To(gomega.BeTrue())
		childInput := testAccessCloudflare.Input(childID)
		bypassTag := firstTagWithPrefix(childInput.Tags, accessBypassTagPrefix)
		gomega.Expect(validInternalDigestTag(bypassTag, accessBypassTagPrefix)).To(gomega.BeTrue())
		gomega.Expect(bypassTag).To(gomega.Equal(accessBypassTag(ownerTag, childInput.Name)))
		gomega.Expect(childInput.Tags).To(gomega.ConsistOf(accessManagedTag, ownerTag, bypassTag))
		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
			Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
			AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
		}, 1)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionProgrammed).Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, &application)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var secret corev1.Secret
			return apierrors.IsNotFound(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Consistently(func() bool { return testAccessCloudflare.Has(parentID) }).WithTimeout(750 * time.Millisecond).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
			Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
			AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
		}, 2)).To(gomega.Succeed())

		gomega.Eventually(func() bool {
			var current v1alpha1.AccessApplication
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.applicationKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		calls := testAccessCloudflare.Calls()
		gomega.Expect(indexOfAccessCall(calls, "Delete:"+childID)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "Delete:"+parentID)))
		gomega.Expect(indexOfAccessCall(calls, "Delete:"+parentID)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "DeleteTag:"+bypassTag)))
		gomega.Expect(indexOfAccessCall(calls, "DeleteTag:"+bypassTag)).To(gomega.BeNumerically("<", indexOfAccessCall(calls, "DeleteTag:"+ownerTag)))
		gomega.Expect(testAccessCloudflare.Tags()).To(gomega.ConsistOf(accessManagedTag, "customer-retained"))
	})

	ginkgo.It("keeps the finalizer and never deletes the parent when child deletion fails", func() {
		fixture := newAccessFixture("delete-fault", true, true)
		fixture.create()

		var application v1alpha1.AccessApplication
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(application.Status.DataPlanes).To(gomega.HaveLen(1))
			g.Expect(application.Status.BypassApplications).To(gomega.HaveLen(1))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		parentID := application.Status.ApplicationID
		childID := application.Status.BypassApplications[0].ApplicationID
		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
			Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
			AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
		}, 1)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &application)).To(gomega.Succeed())
			g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionProgrammed).Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testAccessCloudflare.Fail("Delete:"+childID, errors.New("injected child delete failure"))
		gomega.Expect(testClient.Delete(testContext, &application)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var secret corev1.Secret
			return apierrors.IsNotFound(testClient.Get(testContext, types.NamespacedName{Namespace: accessApplicationAUDNamespace, Name: accessAUDSecretName(&application, fixture.gatewayKey)}, &secret))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
			Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
			AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
		}, 2)).To(gomega.Succeed())

		gomega.Consistently(func(g gomega.Gomega) {
			var current v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, fixture.applicationKey, &current)).To(gomega.Succeed())
			g.Expect(current.Finalizers).To(gomega.ContainElement(v1alpha1.AccessApplicationFinalizer))
			g.Expect(testAccessCloudflare.Has(parentID)).To(gomega.BeTrue())
			g.Expect(testAccessCloudflare.Calls()).NotTo(gomega.ContainElement("Delete:" + parentID))
		}).WithTimeout(time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		testAccessCloudflare.ClearFailure("Delete:" + childID)
		gomega.Eventually(func() bool {
			var current v1alpha1.AccessApplication
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.applicationKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
	})
})

type accessFixture struct {
	namespace      string
	account        string
	credential     types.NamespacedName
	gatewayClass   string
	config         string
	gatewayKey     types.NamespacedName
	tunnelKey      types.NamespacedName
	applicationKey types.NamespacedName
	hostname       string
	unprotected    bool
	carveout       bool
	application    *v1alpha1.AccessApplication
}

func newAccessFixture(prefix string, unprotected, carveout bool) *accessFixture {
	id := accessFixtureCounter.Add(1)
	namespace := fmt.Sprintf("access-%s-%d", prefix, id)
	hostname := fmt.Sprintf("%s-%d.example.test", prefix, id)
	fixture := &accessFixture{
		namespace: namespace, account: fmt.Sprintf("access-account-%d", id),
		credential:   types.NamespacedName{Namespace: namespace, Name: "cloudflare-token"},
		gatewayClass: fmt.Sprintf("access-class-%d", id), config: fmt.Sprintf("access-config-%d", id),
		gatewayKey:     types.NamespacedName{Namespace: namespace, Name: "gateway"},
		tunnelKey:      types.NamespacedName{Namespace: namespace, Name: "tunnel"},
		applicationKey: types.NamespacedName{Namespace: namespace, Name: "access"},
		hostname:       hostname, unprotected: unprotected, carveout: carveout,
	}
	targetKind := gatewayv1.Kind("Gateway")
	targetName := gatewayv1.ObjectName(fixture.gatewayKey.Name)
	section := gatewayv1.SectionName("public")
	if carveout {
		targetKind = gatewayv1.Kind("HTTPRoute")
		targetName = "routes"
		section = "dashboard"
	}
	fixture.application = &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: fixture.applicationKey.Name, Namespace: fixture.applicationKey.Namespace},
		Spec: v1alpha1.AccessApplicationSpec{
			TargetRefs:       []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{Group: gatewayv1.Group("gateway.networking.k8s.io"), Kind: targetKind, Name: targetName, SectionName: &section}},
			Application:      v1alpha1.AccessApplicationSettings{Name: fixture.remoteName(), SessionDuration: "1h"},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
			OriginJWT:        v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	return fixture
}

func (f *accessFixture) remoteName() string { return f.namespace + "/access" }

func (f *accessFixture) create() {
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: f.namespace, Labels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace},
	}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeleteAccessNamespace, f.namespace)
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: f.credential.Name, Namespace: f.credential.Namespace}, Data: map[string][]byte{"token": []byte("api-token")}})).To(gomega.Succeed())

	testAccountCloudflare.mu.Lock()
	testAccountCloudflare.zones = []flarecloudflare.Zone{{ID: "zone-example", Name: "example.test"}}
	testAccountCloudflare.organization = flarecloudflare.Organization{AuthDomain: "team.cloudflareaccess.com", Name: "team"}
	testAccountCloudflare.mu.Unlock()
	grant := v1alpha1.CloudflareAccountGrant{
		NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace}},
		Hostnames:         []string{"*.example.test"}, Zones: []string{"example.test"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		AccessPolicyRefs: v1alpha1.GrantPermissionAllowed,
	}
	if f.unprotected {
		grant.UnprotectedHostnames = []string{f.hostname}
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: f.account},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   fmt.Sprintf("%032x", accessFixtureCounter.Load()),
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: f.credential.Name, Namespace: f.credential.Namespace, Key: "token"}},
			Grants:      []v1alpha1.CloudflareAccountGrant{grant},
		},
	}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	gomega.Eventually(func(g gomega.Gomega) {
		var current v1alpha1.CloudflareAccount
		g.Expect(testClient.Get(testContext, types.NamespacedName{Name: f.account}, &current)).To(gomega.Succeed())
		current.Status.Verified.AuthDomain = "team.cloudflareaccess.com"
		current.Status.Verified.TeamName = "team"
		current.Status.Verified.Zones = []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}}
		current.Status.Conditions = []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now()},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now()},
		}
		g.Expect(testClient.Status().Update(testContext, &current)).To(gomega.Succeed())
	}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

	config := &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: f.config}, Spec: v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: f.account}}}
	gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), config) })
	group := gatewayv1.Group(v1alpha1.Group)
	kind := gatewayv1.Kind("GatewayClassConfig")
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: f.gatewayClass}, Spec: gatewayv1.GatewayClassSpec{
		ControllerName: gatewayapi.ControllerName,
		ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: f.config},
	}}
	gomega.Expect(testClient.Create(testContext, gatewayClass)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), gatewayClass) })

	hostname := gatewayv1.Hostname(f.hostname)
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: f.gatewayKey.Name, Namespace: f.gatewayKey.Namespace}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: gatewayv1.ObjectName(f.gatewayClass),
		Listeners:        []gatewayv1.Listener{{Name: "public", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
		Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: f.tunnelKey.Name}},
	}}
	gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
	tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: f.tunnelKey.Name, Namespace: f.tunnelKey.Namespace}, Spec: v1alpha1.CloudflareTunnelSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.account}, Tunnel: v1alpha1.CloudflareTunnelRemoteSpec{Name: "remote-" + f.namespace},
		ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete, DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
	}}
	gomega.Expect(testClient.Create(testContext, tunnel)).To(gomega.Succeed())

	if f.carveout {
		gomega.Expect(testClient.Create(testContext, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: f.namespace}, Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}, Selector: map[string]string{"app": "backend"},
		}})).To(gomega.Succeed())
		pathRoot := gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchPathPrefix), Value: new("/")}
		pathV1 := gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchPathPrefix), Value: new("/v1")}
		port := gatewayv1.PortNumber(8080)
		parentSection := gatewayv1.SectionName("public")
		backend := gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}
		route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "routes", Namespace: f.namespace}, Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &parentSection}}}, Rules: []gatewayv1.HTTPRouteRule{
			{Name: new(gatewayv1.SectionName("dashboard")), Matches: []gatewayv1.HTTPRouteMatch{{Path: &pathRoot}}, BackendRefs: []gatewayv1.HTTPBackendRef{backend}},
			{Name: new(gatewayv1.SectionName("public")), Matches: []gatewayv1.HTTPRouteMatch{{Path: &pathV1}}, BackendRefs: []gatewayv1.HTTPBackendRef{backend}},
		}}}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
	}
	gomega.Expect(testClient.Create(testContext, f.application)).To(gomega.Succeed())
}

func (f *accessFixture) createAdditionalGateway(gatewayName, tunnelName, hostnameValue string) (*gatewayv1.Gateway, *v1alpha1.CloudflareTunnel) {
	group := gatewayv1.Group(v1alpha1.Group)
	hostname := gatewayv1.Hostname(hostnameValue)
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: f.namespace}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: gatewayv1.ObjectName(f.gatewayClass),

		Listeners: []gatewayv1.Listener{{Name: "public", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
		Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: group, Kind: "CloudflareTunnel", Name: tunnelName,
		}},
	}}
	tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: f.namespace}, Spec: v1alpha1.CloudflareTunnelSpec{
		AccountRef:       corev1.LocalObjectReference{Name: f.account},
		Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "remote-" + f.namespace + "-" + tunnelName},
		ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
	}}
	gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
	gomega.Expect(testClient.Create(testContext, tunnel)).To(gomega.Succeed())
	return gateway, tunnel
}
func preparePrivateNetworkRouteAccess(fixture *accessFixture) (*v1alpha1.AccessApplication, *v1alpha1.NetworkRoute) {
	fixture.application.Spec.TargetRefs = nil
	fixture.application.Spec.PrivateDestinations = []v1alpha1.AccessPrivateDestinationSpec{{
		NetworkRouteRef: &corev1.LocalObjectReference{Name: "private-route"},
		CIDR:            "10.96.12.34/32", PortRange: "5432", L4Protocol: v1alpha1.AccessL4ProtocolTCP,
	}}
	fixture.create()
	gomega.Eventually(func(g gomega.Gomega) {
		var account v1alpha1.CloudflareAccount
		g.Expect(testClient.Get(testContext, types.NamespacedName{Name: fixture.account}, &account)).To(gomega.Succeed())
		before := account.DeepCopy()
		selector := metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}}
		account.Spec.Grants[0].PrivateRoutes = &v1alpha1.CloudflarePrivateRouteGrant{NetworkRouteSelector: &selector}
		account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
		account.Spec.Grants[0].Exposures = append(account.Spec.Grants[0].Exposures, v1alpha1.ExposurePrivate)
		g.Expect(testClient.Patch(testContext, &account, client.MergeFrom(before))).To(gomega.Succeed())
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	vnet := &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "private-vnet", Namespace: fixture.namespace},
		Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: fixture.account}, Name: "private-vnet"},
	}
	gomega.Expect(testClient.Create(testContext, vnet)).To(gomega.Succeed())
	route := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "private-route", Namespace: fixture.namespace, Labels: map[string]string{"private-route": "allowed"}},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: fixture.account}, Network: "10.96.0.0/16",
			TunnelRef:         v1alpha1.NamespacedObjectReference{Name: fixture.tunnelKey.Name},
			VirtualNetworkRef: corev1.LocalObjectReference{Name: vnet.Name},
			AllowedNamespaces: v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSame},
		},
	}
	gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
	application := new(v1alpha1.AccessApplication)
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
		g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
		g.Expect(application.Status.Destinations).To(gomega.HaveLen(1))
		g.Expect(application.Status.Destinations[0].Type).To(gomega.Equal("private"))
		g.Expect(findCondition(application.Status.Conditions, accessApplicationConditionProgrammed).Status).To(gomega.Equal(metav1.ConditionTrue))
	}).WithTimeout(30 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	return application, route
}

func programAccessFixture(fixture *accessFixture, application *v1alpha1.AccessApplication, version int64) {
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
		g.Expect(application.Status.ApplicationID).NotTo(gomega.BeEmpty())
		g.Expect(application.Status.DataPlanes).To(gomega.HaveLen(1))
	}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	var tunnel v1alpha1.CloudflareTunnel
	gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
	gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
		Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
		AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: int64(version),
	}, int64(version))).To(gomega.Succeed())
	gomega.Eventually(func(g gomega.Gomega) {
		g.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
		condition := findCondition(application.Status.Conditions, accessApplicationConditionProgrammed)
		g.Expect(condition).NotTo(gomega.BeNil())
		g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
	}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
}

func applyBlockedAfterLatch(fixture *accessFixture, application *v1alpha1.AccessApplication) {
	gomega.Expect(testClient.Get(testContext, fixture.applicationKey, application)).To(gomega.Succeed())
	var latch accessRevocationLatch
	gomega.Expect(json.Unmarshal([]byte(application.Annotations[accessApplicationRevocationAnnotation]), &latch)).To(gomega.Succeed())
	version := int64(1)
	for _, claim := range latch.Claims {
		if claim.BaselineVersion >= version {
			version = claim.BaselineVersion + 1
		}
	}
	var tunnel v1alpha1.CloudflareTunnel
	gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
	gomega.Expect(applyAccessTunnelHandshake(&tunnel, v1alpha1.CloudflareTunnelHostnameStatus{
		Hostname: fixture.hostname, ProtectionDomain: application.Status.DataPlanes[0].ProtectionDomain,
		AccessApplication: fixture.namespace + "/access", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: version,
	}, version)).To(gomega.Succeed())
}

func applyAccessTunnelHandshake(tunnel *v1alpha1.CloudflareTunnel, hostname v1alpha1.CloudflareTunnelHostnameStatus, version int64) error {
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(),
		"kind":       "CloudflareTunnel",
		"metadata":   map[string]any{"name": tunnel.Name, "namespace": tunnel.Namespace},
		"status": map[string]any{
			"configVersion": map[string]any{"desired": version, "applied": version, "desiredHash": fmt.Sprintf("access-%d", version)},
			"hostnames": []any{map[string]any{
				"hostname": hostname.Hostname, "protectionDomain": hostname.ProtectionDomain,
				"accessApplication": hostname.AccessApplication, "guard": string(hostname.Guard),
				"appliedVersion": hostname.AppliedVersion,
			}},
		},
	}}
	return testClient.Status().Apply(testContext, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func forceDeleteAccessNamespace(namespace string) {
	ctx := context.Background()
	var applications v1alpha1.AccessApplicationList
	if err := testClient.List(ctx, &applications, client.InNamespace(namespace)); err == nil {
		for i := range applications.Items {
			if len(applications.Items[i].Finalizers) == 0 {
				continue
			}
			before := applications.Items[i].DeepCopy()
			applications.Items[i].Finalizers = nil
			_ = testClient.Patch(ctx, &applications.Items[i], client.MergeFrom(before))
		}
	}
	var ledgers corev1.SecretList
	if err := testClient.List(ctx, &ledgers, client.InNamespace(accessApplicationAUDNamespace)); err == nil {
		for i := range ledgers.Items {
			if strings.HasPrefix(ledgers.Items[i].Labels[accessApplicationPrivateTunnelsLabel], namespace+"--") {
				_ = testClient.Delete(ctx, &ledgers.Items[i])
			}
		}
	}
	forceDeleteTunnelNamespace(namespace)
}

func indexOfAccessCall(calls []string, target string) int {
	for index, call := range calls {
		if call == target {
			return index
		}
	}
	return len(calls) + 1
}

func nthIndexOfAccessCall(calls []string, target string, occurrence int) int {
	for index, call := range calls {
		if call != target {
			continue
		}
		occurrence--
		if occurrence == 0 {
			return index
		}
	}
	return len(calls) + 1
}

func countAccessCall(calls []string, target string) int {
	count := 0
	for _, call := range calls {
		if call == target {
			count++
		}
	}
	return count
}

func firstTagWithPrefix(tags []string, prefix string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, prefix) {
			return tag
		}
	}
	return ""
}

type fakeAccessApplicationCloudflare struct {
	flarecloudflare.AccessAPI
	mu                 sync.Mutex
	applications       map[string]flarecloudflare.AccessApplication
	inputs             map[string]flarecloudflare.AccessApplicationInput
	policies           map[string]flarecloudflare.AccessPolicy
	providers          map[string]flarecloudflare.IdentityProvider
	tags               map[string]flarecloudflare.AccessTag
	calls              []string
	failures           map[string]error
	next               int
	ambiguousCreates   int
	tagCreateConflicts map[string]int
	bypassPolicy       flarecloudflare.AccessPolicy
}

func newFakeAccessApplicationCloudflare() *fakeAccessApplicationCloudflare {
	fake := &fakeAccessApplicationCloudflare{}
	fake.Reset()
	return fake
}

func (f *fakeAccessApplicationCloudflare) Client(_, _ string) (flarecloudflare.AccessAPI, error) {
	return f, nil
}

func (f *fakeAccessApplicationCloudflare) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applications = make(map[string]flarecloudflare.AccessApplication)
	f.inputs = make(map[string]flarecloudflare.AccessApplicationInput)
	f.policies = map[string]flarecloudflare.AccessPolicy{
		"policy-allow": {ID: "policy-allow", Name: "allow", Decision: "allow"},
	}
	f.providers = make(map[string]flarecloudflare.IdentityProvider)
	f.tags = make(map[string]flarecloudflare.AccessTag)
	f.calls = nil
	f.failures = make(map[string]error)
	f.next = 0
	f.ambiguousCreates = 0
	f.tagCreateConflicts = make(map[string]int)
	f.bypassPolicy = flarecloudflare.AccessPolicy{ID: "bypass-policy", Name: "bypass", Decision: "bypass"}
}

func (f *fakeAccessApplicationCloudflare) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeAccessApplicationCloudflare) Input(id string) flarecloudflare.AccessApplicationInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inputs[id]
}

func (f *fakeAccessApplicationCloudflare) Has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, found := f.applications[id]
	return found
}
func (f *fakeAccessApplicationCloudflare) ApplicationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applications)
}

func (f *fakeAccessApplicationCloudflare) SetPolicy(policy flarecloudflare.AccessPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[policy.ID] = policy
}

func (f *fakeAccessApplicationCloudflare) AmbiguousCreates(count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ambiguousCreates = count
}

func (f *fakeAccessApplicationCloudflare) PutTag(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[name] = flarecloudflare.AccessTag{Name: name}
}

func (f *fakeAccessApplicationCloudflare) Tags() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]string, 0, len(f.tags))
	for name := range f.tags {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

func (f *fakeAccessApplicationCloudflare) TagCreateConflict(name string, count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tagCreateConflicts[name] = count
}

func (f *fakeAccessApplicationCloudflare) Put(application flarecloudflare.AccessApplication) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applications[application.ID] = application
}

func (f *fakeAccessApplicationCloudflare) Fail(operation string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[operation] = err
}

func (f *fakeAccessApplicationCloudflare) ClearFailure(operation string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, operation)
}

func (f *fakeAccessApplicationCloudflare) record(operation string) error {
	f.calls = append(f.calls, operation)
	return f.failures[operation]
}

func (f *fakeAccessApplicationCloudflare) validateApplicationTags(input flarecloudflare.AccessApplicationInput) error {
	for _, name := range input.Tags {
		if _, found := f.tags[name]; !found {
			return fmt.Errorf("Access application tag %q does not exist", name)
		}
	}
	return nil
}

func (f *fakeAccessApplicationCloudflare) CreateAccessApplication(_ context.Context, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Create:" + input.Name); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if err := f.validateApplicationTags(input); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	f.next++
	id := fmt.Sprintf("access-app-%d", f.next)
	application := flarecloudflare.AccessApplication{ID: id, AUD: "aud-" + id, Name: input.Name, Domain: input.Domain, Type: "self_hosted", SessionDuration: input.SessionDuration, Tags: slices.Clone(input.Tags)}
	f.applications[id] = application
	f.inputs[id] = input
	if f.ambiguousCreates > 0 {
		f.ambiguousCreates--
		return flarecloudflare.AccessApplication{}, errors.New("ambiguous create result")
	}
	return application, nil
}

func (f *fakeAccessApplicationCloudflare) UpdateAccessApplication(_ context.Context, id string, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Update:" + id); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if err := f.validateApplicationTags(input); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	application, found := f.applications[id]
	if !found {
		return flarecloudflare.AccessApplication{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	application.Name = input.Name
	application.Domain = input.Domain
	application.SessionDuration = input.SessionDuration
	application.Tags = slices.Clone(input.Tags)
	f.applications[id] = application
	f.inputs[id] = input
	return application, nil
}

func (f *fakeAccessApplicationCloudflare) GetAccessApplication(_ context.Context, id string) (flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Get:" + id); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	application, found := f.applications[id]
	if !found {
		return flarecloudflare.AccessApplication{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	return application, nil
}

func (f *fakeAccessApplicationCloudflare) ListAccessApplications(_ context.Context) ([]flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("List"); err != nil {
		return nil, err
	}
	result := make([]flarecloudflare.AccessApplication, 0, len(f.applications))
	for _, application := range f.applications {
		result = append(result, application)
	}
	return result, nil
}

func (f *fakeAccessApplicationCloudflare) DeleteAccessApplication(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Delete:" + id); err != nil {
		return err
	}
	if _, found := f.applications[id]; !found {
		return &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	delete(f.applications, id)
	delete(f.inputs, id)
	return nil
}

func (f *fakeAccessApplicationCloudflare) GetAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTag:" + name); err != nil {
		return flarecloudflare.AccessTag{}, err
	}
	tag, found := f.tags[name]
	if !found {
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	return tag, nil
}

func (f *fakeAccessApplicationCloudflare) CreateAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateTag:" + name); err != nil {
		return flarecloudflare.AccessTag{}, err
	}
	if f.tagCreateConflicts[name] > 0 {
		f.tagCreateConflicts[name]--
		f.tags[name] = flarecloudflare.AccessTag{Name: name}
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusConflict}
	}
	if _, found := f.tags[name]; found {
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusConflict}
	}
	tag := flarecloudflare.AccessTag{Name: name}
	f.tags[name] = tag
	return tag, nil
}

func (f *fakeAccessApplicationCloudflare) DeleteAccessTag(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DeleteTag:" + name); err != nil {
		return err
	}
	if _, found := f.tags[name]; !found {
		return &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	for _, application := range f.applications {
		if slices.Contains(application.Tags, name) {
			return &cloudflaresdk.Error{StatusCode: http.StatusConflict}
		}
	}
	delete(f.tags, name)
	return nil
}

func (f *fakeAccessApplicationCloudflare) GetAccessPolicy(_ context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetPolicy:" + id); err != nil {
		return flarecloudflare.AccessPolicy{}, err
	}
	policy, found := f.policies[id]
	if !found {
		return flarecloudflare.AccessPolicy{}, errors.New("policy not found")
	}
	return policy, nil
}

func (f *fakeAccessApplicationCloudflare) GetIdentityProvider(_ context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	provider, found := f.providers[id]
	if !found {
		return flarecloudflare.IdentityProvider{}, errors.New("identity provider not found")
	}
	return provider, nil
}

func (f *fakeAccessApplicationCloudflare) EnsureBypassPolicy(_ context.Context, name string) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("EnsureBypassPolicy:" + name); err != nil {
		return flarecloudflare.AccessPolicy{}, err
	}
	policy := f.bypassPolicy
	policy.Name = name
	return policy, nil
}

var _ AccessApplicationCloudflareClient = (*fakeAccessApplicationCloudflare)(nil)
