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
	"testing"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestGatewayListTokenSubstitutionUsesTokenBoundaries(t *testing.T) {
	got, count := replaceGatewayListToken("net.dst.ip in $trusted or net.src.ip in $trusted-extra", "trusted", "list-123")
	want := "net.dst.ip in $list-123 or net.src.ip in $trusted-extra"
	if got != want || count != 1 {
		t.Fatalf("replaceGatewayListToken() = %q, %d; want %q, 1", got, count, want)
	}
}

func TestGatewayRuleSettingsMappingPreservesTypedL4AndDNSFields(t *testing.T) {
	enabled, enforce := true, false
	duration, reason := "8h", "restricted"
	settings := gatewayRuleSettingsInput(&v1alpha1.ZeroTrustGatewayRuleSettings{
		BlockReason:  &reason,
		CheckSession: &v1alpha1.ZeroTrustGatewayCheckSession{Enforce: &enforce, Duration: &duration},
		L4Override:   &v1alpha1.ZeroTrustGatewayL4Override{IP: "100.80.0.1", Port: 8443},
		Notification: &v1alpha1.ZeroTrustGatewayNotification{Enabled: &enabled},
		OverrideIPs:  []string{"100.80.0.2", "100.80.0.3"},
	})
	if settings == nil || settings.BlockReason == nil || *settings.BlockReason != reason || settings.CheckSession == nil || settings.CheckSession.Duration == nil || *settings.CheckSession.Duration != duration || settings.L4Override == nil || settings.L4Override.Port != 8443 || settings.Notification == nil || settings.Notification.Enabled == nil || !*settings.Notification.Enabled || settings.OverrideIPs == nil || len(*settings.OverrideIPs) != 2 {
		t.Fatalf("gatewayRuleSettingsInput() = %#v", settings)
	}
}

func TestCanonicalListItemsSortsAndDeduplicates(t *testing.T) {
	got := canonicalListItems([]string{"b.example", "a.example", "b.example"})
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("canonicalListItems() = %#v", got)
	}
}

func TestEstablishedTransientOwnerBlocksNewAdopters(t *testing.T) {
	accountID := "0123456789abcdef0123456789abcdef"
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"platform": "true"}},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue},
		}},
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "platform", Labels: map[string]string{"platform": "true"}}}
	older := metav1.NewTime(time.Now().Add(-time.Minute))
	newer := metav1.NewTime(time.Now())
	ownerList := v1alpha1.ZeroTrustList{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-list", Namespace: namespace.Name, UID: "owner-list", CreationTimestamp: older},
		Spec:       v1alpha1.ZeroTrustListSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "remote", Type: v1alpha1.ZeroTrustListTypeIP, ManagementPolicy: v1alpha1.ManagementPolicyManaged, ExternalRef: &v1alpha1.ZeroTrustListExternalReference{ListID: "list-id"}},
		Status:     v1alpha1.ZeroTrustListStatus{ListID: "list-id", OwnershipVerified: true, Conditions: []metav1.Condition{{Type: v1alpha1.ZeroTrustListConditionAccepted, Status: metav1.ConditionFalse, Reason: "CloudflareError"}}},
	}
	newList := &v1alpha1.ZeroTrustList{
		ObjectMeta: metav1.ObjectMeta{Name: "new-list", Namespace: namespace.Name, UID: "new-list", CreationTimestamp: newer},
		Spec:       v1alpha1.ZeroTrustListSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "remote", Type: v1alpha1.ZeroTrustListTypeIP, ManagementPolicy: v1alpha1.ManagementPolicyManaged, ExternalRef: &v1alpha1.ZeroTrustListExternalReference{ListID: "list-id"}, Adoption: v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}},
	}
	reader := &globalArbitrationReader{account: account, namespace: namespace, lists: []v1alpha1.ZeroTrustList{ownerList}}
	if err := (&ZeroTrustListReconciler{APIReader: reader}).checkSingleWriter(context.Background(), newList, accountID); privateErrorReason(err) != "Conflict" {
		t.Fatalf("new list adopter was not blocked by transiently failing established owner: %v", err)
	}

	ownerPolicy := v1alpha1.ZeroTrustGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-policy", Namespace: namespace.Name, UID: "owner-policy", CreationTimestamp: older},
		Spec:       v1alpha1.ZeroTrustGatewayPolicySpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "remote", ManagementPolicy: v1alpha1.ManagementPolicyManaged, ExternalRef: &v1alpha1.ZeroTrustGatewayPolicyExternalReference{RuleID: "rule-id"}},
		Status:     v1alpha1.ZeroTrustGatewayPolicyStatus{RuleID: "rule-id", OwnershipVerified: true, Conditions: []metav1.Condition{{Type: v1alpha1.ZeroTrustGatewayPolicyConditionAccepted, Status: metav1.ConditionFalse, Reason: "CloudflareError"}}},
	}
	newPolicy := &v1alpha1.ZeroTrustGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "new-policy", Namespace: namespace.Name, UID: "new-policy", CreationTimestamp: newer},
		Spec:       v1alpha1.ZeroTrustGatewayPolicySpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "remote", ManagementPolicy: v1alpha1.ManagementPolicyManaged, ExternalRef: &v1alpha1.ZeroTrustGatewayPolicyExternalReference{RuleID: "rule-id"}, Adoption: v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}},
	}
	reader.policies = []v1alpha1.ZeroTrustGatewayPolicy{ownerPolicy}
	if err := (&ZeroTrustGatewayPolicyReconciler{APIReader: reader}).checkSingleWriter(context.Background(), newPolicy, accountID); privateErrorReason(err) != "Conflict" {
		t.Fatalf("new rule adopter was not blocked by transiently failing established owner: %v", err)
	}
}

type globalArbitrationReader struct {
	account   *v1alpha1.CloudflareAccount
	namespace *corev1.Namespace
	lists     []v1alpha1.ZeroTrustList
	policies  []v1alpha1.ZeroTrustGatewayPolicy
}

func (r *globalArbitrationReader) Get(_ context.Context, key client.ObjectKey, object client.Object, _ ...client.GetOption) error {
	switch target := object.(type) {
	case *v1alpha1.CloudflareAccount:
		if r.account != nil && key.Name == r.account.Name {
			*target = *r.account.DeepCopy()
			return nil
		}
	case *corev1.Namespace:
		if r.namespace != nil && key.Name == r.namespace.Name {
			*target = *r.namespace.DeepCopy()
			return nil
		}
	}
	return apierrors.NewNotFound(schema.GroupResource{Group: "test", Resource: "objects"}, key.String())
}

func (r *globalArbitrationReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	switch target := list.(type) {
	case *v1alpha1.ZeroTrustListList:
		target.Items = append([]v1alpha1.ZeroTrustList(nil), r.lists...)
	case *v1alpha1.ZeroTrustGatewayPolicyList:
		target.Items = append([]v1alpha1.ZeroTrustGatewayPolicy(nil), r.policies...)
	default:
		return apierrors.NewNotFound(schema.GroupResource{Group: "test", Resource: "lists"}, "")
	}
	return nil
}

var _ = ginkgo.Describe("M5 global controllers", ginkgo.Ordered, func() {
	ginkgo.BeforeEach(func() {
		testGlobalDeviceCloudflare.reset(flarecloudflare.DeviceSettings{
			GatewayProxyEnabled: false, GatewayUDPProxyEnabled: false,
			RootCertificateInstallationEnabled: false, UseZTVirtualIP: false, DisableForTime: 60,
		})
		testGlobalOrganizationCloudflare.reset(flarecloudflare.Organization{
			Name: "team", AuthDomain: "team.cloudflareaccess.com", SessionDuration: "12h", WARPAuthSessionDuration: "24h",
		})
		testGlobalGatewayCloudflare.reset()
	})

	ginkgo.It("reports ObserveOnly singleton diffs without Cloudflare writes", func() {
		fixture := newDeviceProfileFixture("global-observe")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		truth := true
		disableFor := int64(900)
		settings := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: fixture.namespace},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef:          corev1.LocalObjectReference{Name: fixture.accountName},
				GatewayProxyEnabled: &truth, GatewayUDPProxyEnabled: &truth,
				DisableForTime: &disableFor, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
			},
		}
		gomega.Expect(testClient.Create(testContext, settings)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceSettings
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(settings), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.DeviceSettingsConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.WouldApply).NotTo(gomega.BeNil())
			g.Expect(current.Status.WouldApply.GatewayProxyEnabled).NotTo(gomega.BeNil())
			g.Expect(*current.Status.WouldApply.GatewayProxyEnabled).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalDeviceCloudflare.count("UpdateDeviceSettings")).To(gomega.BeZero())

		session, warp := "24h", "720h"
		organization := &v1alpha1.ZeroTrustOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustOrganizationSpec{
				AccountRef:      corev1.LocalObjectReference{Name: fixture.accountName},
				SessionDuration: &session, WARPAuthSessionDuration: &warp,
				AllowAuthenticateViaWARP: &truth, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
			},
		}
		gomega.Expect(testClient.Create(testContext, organization)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustOrganization
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(organization), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustOrganizationConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.AuthDomain).To(gomega.Equal("team.cloudflareaccess.com"))
			g.Expect(current.Status.WouldApply).NotTo(gomega.BeNil())
			g.Expect(current.Status.WouldApply.WARPAuthSessionDuration).NotTo(gomega.BeNil())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalOrganizationCloudflare.count("UpdateOrganization")).To(gomega.BeZero())
	})

	ginkgo.It("updates Managed singleton settings and records Cloudflare read-back", func() {
		fixture := newDeviceProfileFixture("global-managed")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		truth := true
		disableFor := int64(1200)
		settings := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: fixture.namespace},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef:          corev1.LocalObjectReference{Name: fixture.accountName},
				GatewayProxyEnabled: &truth, GatewayUDPProxyEnabled: &truth,
				RootCertificateInstallationEnabled: &truth, UseZTVirtualIP: &truth,
				DisableForTime: &disableFor, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		gomega.Expect(testClient.Create(testContext, settings)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceSettings
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(settings), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.DeviceSettingsConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.Observed.DisableForTime).NotTo(gomega.BeNil())
			g.Expect(*current.Status.Observed.DisableForTime).To(gomega.Equal(disableFor))
			g.Expect(current.Status.WouldApply).To(gomega.BeNil())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalDeviceCloudflare.count("UpdateDeviceSettings")).To(gomega.BeNumerically(">=", 1))

		session, warp := "36h", "720h"
		organization := &v1alpha1.ZeroTrustOrganization{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustOrganizationSpec{
				AccountRef:      corev1.LocalObjectReference{Name: fixture.accountName},
				SessionDuration: &session, WARPAuthSessionDuration: &warp,
				AllowAuthenticateViaWARP: &truth, DenyUnmatchedRequests: &truth,
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		gomega.Expect(testClient.Create(testContext, organization)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustOrganization
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(organization), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustOrganizationConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.AuthDomain).To(gomega.Equal("team.cloudflareaccess.com"))
			g.Expect(current.Status.Observed.SessionDuration).NotTo(gomega.BeNil())
			g.Expect(*current.Status.Observed.SessionDuration).To(gomega.Equal(session))
			g.Expect(current.Status.WouldApply).To(gomega.BeNil())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalOrganizationCloudflare.count("UpdateOrganization")).To(gomega.BeNumerically(">=", 1))
	})

	ginkgo.It("arbitrates singleton writers by resolved account ID and ignores ineligible contenders", func() {
		fixture := newDeviceProfileFixture("global-arbitration")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		authorizedNamespace := "aaa-global-arbitration-authorized"
		unauthorizedNamespace := "global-arbitration-unauthorized"
		authorizedAccount := createGlobalAliasAccount(authorizedNamespace, "alias-authorized", map[string]string{"writer": "authorized"}, map[string]string{"writer": "authorized"})
		unauthorizedAccount := createGlobalAliasAccount(unauthorizedNamespace, "alias-unauthorized", map[string]string{"writer": "unauthorized"}, map[string]string{"writer": "different"})
		ginkgo.DeferCleanup(func() {
			cleanupGlobalAliasAccount(authorizedNamespace, authorizedAccount)
			cleanupGlobalAliasAccount(unauthorizedNamespace, unauthorizedAccount)
		})

		truth := true
		unauthorized := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: unauthorizedNamespace},
			Spec:       v1alpha1.DeviceSettingsSpec{AccountRef: corev1.LocalObjectReference{Name: unauthorizedAccount}, GatewayProxyEnabled: &truth, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		}
		gomega.Expect(testClient.Create(testContext, unauthorized)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceSettings
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(unauthorized), &current)).To(gomega.Succeed())
			g.Expect(globalConditionFalse(current.Status.Conditions, v1alpha1.DeviceSettingsConditionAccepted)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		contender := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: authorizedNamespace},
			Spec:       v1alpha1.DeviceSettingsSpec{AccountRef: corev1.LocalObjectReference{Name: authorizedAccount}, GatewayProxyEnabled: &truth, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		}
		gomega.Expect(testClient.Create(testContext, contender)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceSettings
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(contender), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.DeviceSettingsConditionReady)).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		var contenderCurrent v1alpha1.DeviceSettings
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(contender), &contenderCurrent)).To(gomega.Succeed())
		resolvedAccountID, eligible := globalContenderAccountID(testContext, testClient, contenderCurrent.Namespace, contenderCurrent.Spec.AccountRef.Name, contenderCurrent.Status.Conditions, false)
		gomega.Expect(eligible).To(gomega.BeTrue())
		gomega.Expect(resolvedAccountID).To(gomega.Equal("0123456789abcdef0123456789abcdef"))

		currentWriter := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: fixture.namespace},
			Spec:       v1alpha1.DeviceSettingsSpec{AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, GatewayProxyEnabled: &truth, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		}
		gomega.Expect(testClient.Create(testContext, currentWriter)).To(gomega.Succeed())
		var createdCurrent v1alpha1.DeviceSettings
		gomega.Eventually(func() error {
			return testClient.Get(testContext, client.ObjectKeyFromObject(currentWriter), &createdCurrent)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(globalObjectPrecedes(contenderCurrent.CreationTimestamp, client.ObjectKeyFromObject(&contenderCurrent), createdCurrent.CreationTimestamp, client.ObjectKeyFromObject(&createdCurrent))).To(gomega.BeTrue(),
			"contender=%s/%s at %s current=%s/%s at %s", contenderCurrent.Namespace, contenderCurrent.Name, contenderCurrent.CreationTimestamp, createdCurrent.Namespace, createdCurrent.Name, createdCurrent.CreationTimestamp)
		gomega.Eventually(func() string {
			var direct v1alpha1.DeviceSettings
			if err := testClient.Get(testContext, client.ObjectKeyFromObject(currentWriter), &direct); err != nil {
				return err.Error()
			}
			err := (&DeviceSettingsReconciler{Client: testClient, APIReader: testClient}).checkSingleWriter(testContext, &direct, "0123456789abcdef0123456789abcdef")
			if err == nil {
				return "none"
			}
			return privateErrorReason(err)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Equal("Conflict"))
		var observedContender v1alpha1.DeviceSettings
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(contender), &observedContender)).To(gomega.Succeed())
		observedContender.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		gomega.Expect(testClient.Update(testContext, &observedContender)).To(gomega.Succeed())
		gomega.Eventually(func() string {
			var direct v1alpha1.DeviceSettings
			if err := testClient.Get(testContext, client.ObjectKeyFromObject(currentWriter), &direct); err != nil {
				return err.Error()
			}
			err := (&DeviceSettingsReconciler{Client: testClient, APIReader: testClient}).checkSingleWriter(testContext, &direct, "0123456789abcdef0123456789abcdef")
			if err != nil {
				return privateErrorReason(err)
			}
			return "none"
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Equal("none"))
	})

	ginkgo.It("maps a Managed list reference to the remote list ID in a typed policy", func() {
		fixture := newDeviceProfileFixture("global-policy")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		list := &v1alpha1.ZeroTrustList{
			ObjectMeta: metav1.ObjectMeta{Name: "trusted-egress", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustListSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "trusted-egress", Type: v1alpha1.ZeroTrustListTypeIP,
				Items: []string{"203.0.113.0/24", "198.51.100.0/24"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		gomega.Expect(testClient.Create(testContext, list)).To(gomega.Succeed())
		var listID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.Observed.Items).To(gomega.Equal([]string{"198.51.100.0/24", "203.0.113.0/24"}))
			listID = current.Status.ListID
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		enabled := true
		reason := "approved egress"
		policy := &v1alpha1.ZeroTrustGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-egress", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "allow-egress", Enabled: &enabled,
				Filters: []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterL4}, Action: v1alpha1.ZeroTrustGatewayAction("allow"),
				Traffic: "net.dst.ip in $trusted-egress", ListRefs: []v1alpha1.ZeroTrustGatewayListReference{{Name: "trusted-egress"}},
				RuleSettings: &v1alpha1.ZeroTrustGatewayRuleSettings{BlockReason: &reason}, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		var ruleID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			ruleID = current.Status.RuleID
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		remote, found := testGlobalGatewayCloudflare.rule(ruleID)
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(remote.Filters).To(gomega.Equal([]flarecloudflare.GatewayRuleFilter{flarecloudflare.GatewayRuleFilterL4}))
		gomega.Expect(remote.Traffic).To(gomega.Equal("net.dst.ip in $" + listID))
		gomega.Expect(remote.RuleSettings.BlockReason).NotTo(gomega.BeNil())
		gomega.Expect(*remote.RuleSettings.BlockReason).To(gomega.Equal(reason))
	})

	ginkgo.It("adopts explicitly identified Gateway lists and rules only after expectation checks", func() {
		fixture := newDeviceProfileFixture("global-adopt")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		testGlobalGatewayCloudflare.putList(flarecloudflare.GatewayList{
			ID: "adopt-list-id", Name: "adopt-list", Type: flarecloudflare.GatewayListTypeIP,
			Items: []flarecloudflare.GatewayListItem{{Value: "203.0.113.0/24"}}, Count: 1,
		})
		list := &v1alpha1.ZeroTrustList{
			ObjectMeta: metav1.ObjectMeta{Name: "adopt-list", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustListSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "adopt-list", Type: v1alpha1.ZeroTrustListTypeIP,
				Items: []string{"198.51.100.0/24"}, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				ExternalRef: &v1alpha1.ZeroTrustListExternalReference{ListID: "adopt-list-id"},
				Adoption:    v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "adopt-list"}},
			},
		}
		gomega.Expect(testClient.Create(testContext, list)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.ListID).To(gomega.Equal("adopt-list-id"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustList(list, func(current *v1alpha1.ZeroTrustList) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustList(list, func(current *v1alpha1.ZeroTrustList) {
			current.Spec.Name = "renamed-list"
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(current.Status.Observed.Name).To(gomega.Equal("renamed-list"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		renamedList, found := testGlobalGatewayCloudflare.list("adopt-list-id")
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(renamedList.Name).To(gomega.Equal("renamed-list"))
		gomega.Expect(updateZeroTrustList(list, func(current *v1alpha1.ZeroTrustList) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
			current.Spec.ExternalRef = nil
			current.Spec.Adoption = v1alpha1.AdoptionSpec{}
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(statusReason(current.Status.Conditions, v1alpha1.ZeroTrustListConditionReady)).To(gomega.Equal("Observed"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustList(list, func(current *v1alpha1.ZeroTrustList) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		adoptedList, found := testGlobalGatewayCloudflare.list("adopt-list-id")
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(adoptedList.Items).To(gomega.Equal([]flarecloudflare.GatewayListItem{{Value: "198.51.100.0/24"}}))

		testGlobalGatewayCloudflare.putRule(flarecloudflare.GatewayRule{
			ID: "adopt-rule-id", Name: "adopt-rule", Description: "created outside Flareway",
			Filters: []flarecloudflare.GatewayRuleFilter{flarecloudflare.GatewayRuleFilterDNS},
			Action:  "block", Traffic: "dns.fqdn == \"old.example\"",
		})
		policy := &v1alpha1.ZeroTrustGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "adopt-rule", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "adopt-rule",
				Filters: []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterDNS},
				Action:  v1alpha1.ZeroTrustGatewayAction("block"), Traffic: "dns.fqdn == \"new.example\"",
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				ExternalRef:      &v1alpha1.ZeroTrustGatewayPolicyExternalReference{RuleID: "adopt-rule-id"},
				Adoption:         v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "adopt-rule"}},
			},
		}
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.RuleID).To(gomega.Equal("adopt-rule-id"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustGatewayPolicy(policy, func(current *v1alpha1.ZeroTrustGatewayPolicy) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustGatewayPolicy(policy, func(current *v1alpha1.ZeroTrustGatewayPolicy) {
			current.Spec.Name = "renamed-rule"
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(current.Status.Observed.Name).To(gomega.Equal("renamed-rule"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		renamedRule, found := testGlobalGatewayCloudflare.rule("adopt-rule-id")
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(renamedRule.Name).To(gomega.Equal("renamed-rule"))
		gomega.Expect(updateZeroTrustGatewayPolicy(policy, func(current *v1alpha1.ZeroTrustGatewayPolicy) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
			current.Spec.ExternalRef = nil
			current.Spec.Adoption = v1alpha1.AdoptionSpec{}
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(statusReason(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionReady)).To(gomega.Equal("Observed"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(updateZeroTrustGatewayPolicy(policy, func(current *v1alpha1.ZeroTrustGatewayPolicy) {
			current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionReady)).To(gomega.BeTrue())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		adoptedRule, found := testGlobalGatewayCloudflare.rule("adopt-rule-id")
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(adoptedRule.Traffic).To(gomega.Equal("dns.fqdn == \"new.example\""))
		gomega.Expect(adoptedRule.Description).To(gomega.HavePrefix("flareway "))
	})

	ginkgo.It("blocks Gateway policy deletion when remote ownership is lost", func() {
		fixture := newDeviceProfileFixture("global-delete-ownership")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		policy := &v1alpha1.ZeroTrustGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-owned-rule", Namespace: fixture.namespace},
			Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "delete-owned-rule",
				Filters: []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterDNS},
				Action:  v1alpha1.ZeroTrustGatewayAction("block"), Traffic: "dns.fqdn == \"blocked.example\"",
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			var current v1alpha1.ZeroTrustGatewayPolicy
			if err := testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current); err == nil {
				clearFinalizers(testContext, &current)
				_ = testClient.Delete(testContext, &current)
			}
		})
		var ruleID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustGatewayPolicyConditionReady)).To(gomega.BeTrue())
			ruleID = current.Status.RuleID
			g.Expect(ruleID).NotTo(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		remote, found := testGlobalGatewayCloudflare.rule(ruleID)
		gomega.Expect(found).To(gomega.BeTrue())
		remote.Description = "foreign owner"
		testGlobalGatewayCloudflare.putRule(remote)

		gomega.Expect(testClient.Delete(testContext, policy)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustGatewayPolicy
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), &current)).To(gomega.Succeed())
			g.Expect(current.Finalizers).To(gomega.ContainElement(v1alpha1.ZeroTrustGatewayPolicyFinalizer))
			g.Expect(metaConditionTrue(current.Status.Conditions, "CleanupBlocked")).To(gomega.BeTrue())
			g.Expect(statusReason(current.Status.Conditions, "CleanupBlocked")).To(gomega.Equal("OwnershipLost"))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalGatewayCloudflare.count("DeleteGatewayRule")).To(gomega.BeZero())
	})

	ginkgo.It("observes existing Gateway list state without create or replacement", func() {
		fixture := newDeviceProfileFixture("global-list-observe")
		fixture.create()
		ginkgo.DeferCleanup(func() { cleanupGlobalFixture(fixture) })
		testGlobalGatewayCloudflare.putList(flarecloudflare.GatewayList{ID: "external-list", Name: "external", Type: flarecloudflare.GatewayListTypeIP, Items: []flarecloudflare.GatewayListItem{{Value: "203.0.113.0/24"}}, Count: 1})
		list := &v1alpha1.ZeroTrustList{ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: fixture.namespace}, Spec: v1alpha1.ZeroTrustListSpec{AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Name: "external", Type: v1alpha1.ZeroTrustListTypeIP, Items: []string{"198.51.100.0/24"}, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly}}
		gomega.Expect(testClient.Create(testContext, list)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ZeroTrustList
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(list), &current)).To(gomega.Succeed())
			g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.ZeroTrustListConditionAccepted)).To(gomega.BeTrue())
			g.Expect(current.Status.ListID).To(gomega.Equal("external-list"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
			g.Expect(current.Status.WouldApply).NotTo(gomega.BeNil())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testGlobalGatewayCloudflare.count("CreateGatewayList")).To(gomega.BeZero())
		gomega.Expect(testGlobalGatewayCloudflare.count("ReplaceGatewayListItems")).To(gomega.BeZero())
	})
})

func updateZeroTrustList(object *v1alpha1.ZeroTrustList, mutate func(*v1alpha1.ZeroTrustList)) error {
	var current v1alpha1.ZeroTrustList
	if err := testClient.Get(testContext, client.ObjectKeyFromObject(object), &current); err != nil {
		return err
	}
	mutate(&current)
	return testClient.Update(testContext, &current)
}

func updateZeroTrustGatewayPolicy(object *v1alpha1.ZeroTrustGatewayPolicy, mutate func(*v1alpha1.ZeroTrustGatewayPolicy)) error {
	var current v1alpha1.ZeroTrustGatewayPolicy
	if err := testClient.Get(testContext, client.ObjectKeyFromObject(object), &current); err != nil {
		return err
	}
	mutate(&current)
	return testClient.Update(testContext, &current)
}

func statusReason(conditions []metav1.Condition, conditionType string) string {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return conditions[i].Reason
		}
	}
	return ""
}

func createGlobalAliasAccount(namespace, accountName string, namespaceLabels, allowedLabels map[string]string) string {
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: namespaceLabels}})).To(gomega.Succeed())
	secretName := accountName + "-token"
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace}, Data: map[string][]byte{"token": []byte("alias-token")}})).To(gomega.Succeed())
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: secretName, Namespace: namespace, Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: allowedLabels},
				Hostnames:         []string{"*"}, Zones: []string{"*"},
				Exposures:       []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				PlatformObjects: v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	gomega.Eventually(func(g gomega.Gomega) {
		var current v1alpha1.CloudflareAccount
		g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(account), &current)).To(gomega.Succeed())
		g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
		g.Expect(metaConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
	}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	return accountName
}

func cleanupGlobalAliasAccount(namespace, accountName string) {
	var account v1alpha1.CloudflareAccount
	if err := testClient.Get(testContext, client.ObjectKey{Name: accountName}, &account); err == nil {
		clearFinalizers(testContext, &account)
		_ = testClient.Delete(testContext, &account)
	}
	var namespaceObject corev1.Namespace
	if err := testClient.Get(testContext, client.ObjectKey{Name: namespace}, &namespaceObject); err == nil {
		_ = testClient.Delete(testContext, &namespaceObject)
	}
}

func cleanupGlobalFixture(fixture deviceProfileFixture) {
	var namespace corev1.Namespace
	if err := testClient.Get(testContext, client.ObjectKey{Name: fixture.namespace}, &namespace); err == nil {
		_ = testClient.Delete(testContext, &namespace)
	}
	var account v1alpha1.CloudflareAccount
	if err := testClient.Get(testContext, client.ObjectKey{Name: fixture.accountName}, &account); err == nil {
		clearFinalizers(testContext, &account)
		_ = testClient.Delete(testContext, &account)
	} else if !apierrors.IsNotFound(err) {
		ginkgo.Fail(err.Error())
	}
}
