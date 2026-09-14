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
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var accessResourceCounter atomic.Uint64

var _ = ginkgo.Describe("Access resource controllers", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func() { ensureSystemNamespace("kube-system") })
	ginkgo.BeforeEach(func() {
		testResourceAccessCloudflare.reset()
		testAccountCloudflare.reset()
	})

	ginkgo.It("reconciles policy, group, IdP, posture, and service-token lifecycles", func() {
		suffix := accessResourceCounter.Add(1)
		namespace := fmt.Sprintf("access-resources-%d", suffix)
		accountName := fmt.Sprintf("access-account-%d", suffix)
		credential := types.NamespacedName{Namespace: namespace, Name: "credentials"}
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"access-test": namespace}}})).To(gomega.Succeed())
		ginkgo.DeferCleanup(forceDeleteAccessNamespace, namespace)
		gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: credential.Name, Namespace: credential.Namespace}, Data: map[string][]byte{"token": []byte("api-token")}})).To(gomega.Succeed())
		account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: accountName}, Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   fmt.Sprintf("%032x", suffix),
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: credential.Name, Namespace: credential.Namespace, Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"access-test": namespace}},
				Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				AccessPolicyRefs: v1alpha1.GrantPermissionAllowed, PlatformObjects: v1alpha1.GrantPermissionAllowed,
			}},
		}}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareAccount
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: accountName}, &current)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		var readyAccount v1alpha1.CloudflareAccount
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: accountName}, &readyAccount)).To(gomega.Succeed())
		testResourceAccessCloudflare.mu.Lock()
		clientCallsBeforeDenial := testResourceAccessCloudflare.clientCalls
		testResourceAccessCloudflare.mu.Unlock()
		_, _, err := accessClientForAccount(testContext, testClient, namespace, accountName, authz.Request{Hostname: "denied.example", Unprotected: true}, testResourceAccessCloudflare.Client)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("RefNotPermitted")))
		testResourceAccessCloudflare.mu.Lock()
		gomega.Expect(testResourceAccessCloudflare.clientCalls).To(gomega.Equal(clientCallsBeforeDenial))
		testResourceAccessCloudflare.mu.Unlock()

		deniedCrossNamespace := readyAccount.DeepCopy()
		deniedCrossNamespace.Spec.Grants[0].AccessPolicyRefs = v1alpha1.GrantPermissionDenied
		gomega.Expect(authorizeAccessReference(testContext, testClient, namespace, "platform-access", deniedCrossNamespace)).To(gomega.MatchError(gomega.ContainSubstring("RefNotPermitted")))
		acceptedConditions := []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}}
		gomega.Expect(validateAccessReference(namespace, namespace, "AccessGroup", accountName, nil, acceptedConditions, "other-account")).To(gomega.MatchError(gomega.ContainSubstring("want")))
		deleting := metav1.NewTime(time.Now())
		gomega.Expect(validateAccessReference(namespace, namespace, "AccessGroup", accountName, &deleting, acceptedConditions, accountName)).To(gomega.MatchError(gomega.ContainSubstring("deleting")))
		_, err = resolveAccessRule(testContext, testClient, namespace, &readyAccount, testResourceAccessCloudflare, v1alpha1.AccessRule{
			Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{ExternalID: "foreign-group-id"}},
		})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("validate external AccessGroup")))

		accountRef := corev1.LocalObjectReference{Name: accountName}
		group := &v1alpha1.AccessGroup{ObjectMeta: metav1.ObjectMeta{Name: "developers", Namespace: namespace}, Spec: v1alpha1.AccessGroupSpec{AccountRef: accountRef, Name: "developers", Include: []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}}, ManagementPolicy: v1alpha1.ManagementPolicyManaged}}
		provider := &v1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "otp", Namespace: namespace}, Spec: v1alpha1.IdentityProviderSpec{AccountRef: accountRef, Name: "otp", Type: "onetimepin", ManagementPolicy: v1alpha1.ManagementPolicyManaged}}
		posture := &v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: "warp", Namespace: namespace}, Spec: v1alpha1.DevicePostureRuleSpec{AccountRef: accountRef, Name: "warp", Type: "warp", ManagementPolicy: v1alpha1.ManagementPolicyManaged}}
		token := &v1alpha1.ServiceToken{ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: namespace}, Spec: v1alpha1.ServiceTokenSpec{AccountRef: accountRef, Name: "ci", Duration: "8760h", SecretRef: corev1.LocalObjectReference{Name: "ci-credentials"}, Rotation: v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "24h"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete}}
		for _, object := range []client.Object{group, provider, posture, token} {
			gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
		}

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(group), group)).To(gomega.Succeed())
			g.Expect(group.Status.GroupID).NotTo(gomega.BeEmpty())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(provider), provider)).To(gomega.Succeed())
			g.Expect(provider.Status.IDPID).NotTo(gomega.BeEmpty())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(posture), posture)).To(gomega.Succeed())
			g.Expect(posture.Status.RuleID).NotTo(gomega.BeEmpty())
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(token), token)).To(gomega.Succeed())
			g.Expect(token.Status.TokenID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		policy := &v1alpha1.AccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: namespace}, Spec: v1alpha1.AccessPolicySpec{AccountRef: accountRef, Name: "allow", Decision: v1alpha1.AccessPolicyDecisionAllow, Include: []v1alpha1.AccessRule{{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{Name: group.Name}}}}, Require: []v1alpha1.AccessRule{{DevicePosture: &v1alpha1.AccessDevicePostureRuleReference{RuleRef: v1alpha1.AccessObjectReference{Name: posture.Name}}}}, ManagementPolicy: v1alpha1.ManagementPolicyManaged}}
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), policy)).To(gomega.Succeed())
			g.Expect(policy.Status.PolicyID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(policy.Status.Conditions, "Ready")).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		observedRemote, err := testResourceAccessCloudflare.CreateAccessGroup(testContext, flarecloudflare.AccessGroupInput{Name: "terraform/developers", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		observed := &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: namespace},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "ignored", Include: []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				ExternalRef:      &v1alpha1.AccessGroupExternalReference{GroupID: observedRemote.ID},
			},
		}

		failedAdoption := &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "failed-adoption", Namespace: namespace},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "failed-adoption",
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				ExternalRef:      &v1alpha1.AccessGroupExternalReference{GroupID: observedRemote.ID},
				Adoption:         v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "different-name"}},
			},
		}
		gomega.Expect(testClient.Create(testContext, failedAdoption)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(failedAdoption), failedAdoption)).To(gomega.Succeed())
			g.Expect(failedAdoption.Status.GroupID).To(gomega.BeEmpty())
			g.Expect(failedAdoption.Status.OwnershipVerified).To(gomega.BeFalse())
			condition := statusutil.FindCondition(failedAdoption.Status.Conditions, "Accepted")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, observed)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(observed), observed)).To(gomega.Succeed())
			g.Expect(observed.Status.GroupID).To(gomega.Equal(observedRemote.ID))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		bypass := &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "user-bypass", Namespace: namespace},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: accountRef, Name: "user-bypass", Decision: v1alpha1.AccessPolicyDecisionBypass,
				Include: []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
			},
		}
		gomega.Expect(testClient.Create(testContext, bypass)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(bypass), bypass)).To(gomega.Succeed())
			condition := statusutil.FindCondition(bypass.Status.Conditions, "Accepted")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("Invalid"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		secretKey := types.NamespacedName{Namespace: namespace, Name: token.Spec.SecretRef.Name}
		gomega.Eventually(func(g gomega.Gomega) {
			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
			g.Expect(secret.Data[v1alpha1.ServiceTokenClientSecretKey]).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		var secret corev1.Secret
		gomega.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &secret)).To(gomega.Succeed())
		gomega.Consistently(func() int {
			testResourceAccessCloudflare.mu.Lock()
			defer testResourceAccessCloudflare.mu.Unlock()
			return testResourceAccessCloudflare.rotations
		}).WithTimeout(500 * time.Millisecond).WithPolling(50 * time.Millisecond).Should(gomega.Equal(0))
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(token), token)).To(gomega.Succeed())
			condition := statusutil.FindCondition(token.Status.Conditions, "Ready")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("SecretMissing"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		base := client.MergeFrom(token.DeepCopy())
		requested := metav1.NewTime(time.Now().UTC())
		token.Spec.Rotation.RequestedAt = &requested
		gomega.Expect(testClient.Patch(testContext, token, base)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var recreated corev1.Secret
			g.Expect(testClient.Get(testContext, secretKey, &recreated)).To(gomega.Succeed())
			g.Expect(string(recreated.Data[v1alpha1.ServiceTokenClientSecretKey])).To(gomega.HavePrefix("rotated-"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(token), token)).To(gomega.Succeed())
			g.Expect(token.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		tokenID, clientID := token.Status.TokenID, token.Status.ClientID
		testResourceAccessCloudflare.mu.Lock()
		tokenCount := len(testResourceAccessCloudflare.tokens)
		clientCallsBeforeFailure := testResourceAccessCloudflare.clientCalls
		testResourceAccessCloudflare.clientErr = fmt.Errorf("temporary client construction failure")
		testResourceAccessCloudflare.mu.Unlock()
		base = client.MergeFrom(token.DeepCopy())
		token.Spec.Duration = "8000h"
		gomega.Expect(testClient.Patch(testContext, token, base)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(token), token)).To(gomega.Succeed())
			g.Expect(token.Status.TokenID).To(gomega.Equal(tokenID))
			g.Expect(token.Status.ClientID).To(gomega.Equal(clientID))
			condition := statusutil.FindCondition(token.Status.Conditions, "Ready")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("Pending"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		testResourceAccessCloudflare.mu.Lock()
		gomega.Expect(testResourceAccessCloudflare.tokens).To(gomega.HaveLen(tokenCount))
		gomega.Expect(testResourceAccessCloudflare.clientCalls).To(gomega.BeNumerically(">", clientCallsBeforeFailure))
		testResourceAccessCloudflare.clientErr = nil
		testResourceAccessCloudflare.mu.Unlock()
	})
})
