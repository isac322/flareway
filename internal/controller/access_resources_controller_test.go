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
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
				NamespaceSelector:               metav1.LabelSelector{MatchLabels: map[string]string{"access-test": namespace}},
				Hostnames:                       []string{"*"},
				Zones:                           []string{"*"},
				Exposures:                       []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				AccessPolicyRefs:                v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs:            v1alpha1.GrantPermissionAllowed,
				DevicePostureIntegrationRefs:    v1alpha1.GrantPermissionAllowed,
				AccessStandaloneApplicationRefs: v1alpha1.GrantPermissionAllowed,
				PlatformObjects:                 v1alpha1.GrantPermissionAllowed,
			}},
		}}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareAccount
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: accountName}, &current)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
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
		collisionSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "collision-credentials",
				Namespace:   namespace,
				Annotations: map[string]string{"preserve": "annotation"},
			},
			Data: map[string][]byte{"preserve": []byte("data")},
		}
		gomega.Expect(testClient.Create(testContext, collisionSecret)).To(gomega.Succeed())
		collisionToken := &v1alpha1.ServiceToken{
			ObjectMeta: metav1.ObjectMeta{Name: "collision", Namespace: namespace},
			Spec: v1alpha1.ServiceTokenSpec{
				AccountRef: accountRef, Name: "collision", Enabled: true, Duration: "8760h",
				SecretRef:        corev1.LocalObjectReference{Name: collisionSecret.Name},
				Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "24h"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		testResourceAccessCloudflare.mu.Lock()
		tokenCreatesBeforeCollision := testResourceAccessCloudflare.tokenCreates
		testResourceAccessCloudflare.mu.Unlock()
		gomega.Expect(testClient.Create(testContext, collisionToken)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), collisionToken) })
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.ServiceToken
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(collisionToken), &current)).To(gomega.Succeed())
			accepted := statusutil.FindCondition(current.Status.Conditions, "Accepted")
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal("Conflict"))
			g.Expect(accepted.Message).To(gomega.ContainSubstring("not controlled by this ServiceToken"))
			g.Expect(current.Status.TokenID).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func() int {
			testResourceAccessCloudflare.mu.Lock()
			defer testResourceAccessCloudflare.mu.Unlock()
			return testResourceAccessCloudflare.tokenCreates
		}).WithTimeout(500 * time.Millisecond).WithPolling(50 * time.Millisecond).Should(gomega.Equal(tokenCreatesBeforeCollision))
		var preservedCollisionSecret corev1.Secret
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(collisionSecret), &preservedCollisionSecret)).To(gomega.Succeed())
		gomega.Expect(preservedCollisionSecret.Data).To(gomega.Equal(map[string][]byte{"preserve": []byte("data")}))
		gomega.Expect(preservedCollisionSecret.Annotations).To(gomega.Equal(map[string]string{"preserve": "annotation"}))
		gomega.Expect(preservedCollisionSecret.OwnerReferences).To(gomega.BeEmpty())

		group := &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "developers", Namespace: namespace},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "developers",
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		provider := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "otp", Namespace: namespace},
			Spec: v1alpha1.IdentityProviderSpec{
				AccountRef: accountRef, Name: "otp", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
				Config:           v1alpha1.IdentityProviderConfig{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		posture := &v1alpha1.DevicePostureRule{
			ObjectMeta: metav1.ObjectMeta{Name: "warp", Namespace: namespace},
			Spec: v1alpha1.DevicePostureRuleSpec{
				AccountRef: accountRef, Name: "warp", Type: v1alpha1.DevicePostureRuleTypeWARP,
				Match:            []v1alpha1.DevicePostureMatch{{Platform: v1alpha1.DevicePosturePlatformWindows}},
				Input:            v1alpha1.DevicePostureInput{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		token := &v1alpha1.ServiceToken{
			ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: namespace},
			Spec: v1alpha1.ServiceTokenSpec{
				AccountRef: accountRef, Name: "ci", Enabled: true, Duration: "8760h",
				SecretRef:        corev1.LocalObjectReference{Name: "ci-credentials"},
				Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "24h"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		for _, object := range []client.Object{group, provider, posture, token} {
			gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
		}
		var managedGroupID string

		gomega.Eventually(func(g gomega.Gomega) {
			managedGroupID = testResourceAccessCloudflare.onlyAccessGroupID()
			g.Expect(managedGroupID).NotTo(gomega.BeEmpty())
			var currentGroup v1alpha1.AccessGroup
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(group), &currentGroup)).To(gomega.Succeed())
			g.Expect(currentGroup.Status.GroupID).To(gomega.Equal(managedGroupID))
			g.Expect(statusutil.ConditionTrue(currentGroup.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(currentGroup.Status.Conditions, "Ready")).To(gomega.BeTrue())
			g.Expect(currentGroup.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(currentGroup.Status.Observed.Include).To(gomega.Equal([]v1alpha1.AccessRuleObservation{{Kind: "everyone"}}))
			*group = currentGroup

			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(provider), provider)).To(gomega.Succeed())
			g.Expect(provider.Status.IDPID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(provider.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(provider.Status.Conditions, "Ready")).To(gomega.BeTrue())

			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(posture), posture)).To(gomega.Succeed())
			g.Expect(posture.Status.RuleID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(posture.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(posture.Status.Conditions, "Ready")).To(gomega.BeTrue())
			g.Expect(posture.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(posture.Status.Observed.Type).To(gomega.Equal(v1alpha1.DevicePostureRuleTypeWARP))
			g.Expect(posture.Status.Observed.Match).To(gomega.Equal([]v1alpha1.DevicePostureMatch{{Platform: v1alpha1.DevicePosturePlatformWindows}}))

			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(token), token)).To(gomega.Succeed())
			g.Expect(token.Status.TokenID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(token.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(token.Status.Conditions, "Ready")).To(gomega.BeTrue())
			g.Expect(token.Status.ObservedEnabled).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		policy := &v1alpha1.AccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: namespace}, Spec: v1alpha1.AccessPolicySpec{AccountRef: accountRef, Name: "allow", Decision: v1alpha1.AccessPolicyDecisionAllow, Include: []v1alpha1.AccessRule{{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{Name: group.Name}}}}, Require: []v1alpha1.AccessRule{{DevicePosture: &v1alpha1.AccessDevicePostureRuleReference{RuleRef: v1alpha1.AccessObjectReference{Name: posture.Name}}}}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete}}
		gomega.Expect(testClient.Create(testContext, policy)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(policy), policy)).To(gomega.Succeed())
			g.Expect(policy.Status.PolicyID).NotTo(gomega.BeEmpty())
			g.Expect(statusutil.ConditionTrue(policy.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(policy.Status.Conditions, "Ready")).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		observedRemote, err := testResourceAccessCloudflare.CreateAccessGroup(testContext, flarecloudflare.AccessScope{}, flarecloudflare.AccessGroupInput{Name: "terraform/developers", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}})
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
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(failedAdoption), failedAdoption)).To(gomega.Succeed())
			g.Expect(failedAdoption.Status.GroupID).To(gomega.BeEmpty())
			g.Expect(failedAdoption.Status.OwnershipVerified).To(gomega.BeFalse())
			condition := statusutil.FindCondition(failedAdoption.Status.Conditions, "Accepted")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, observed)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(observed), observed)).To(gomega.Succeed())
			g.Expect(observed.Status.GroupID).To(gomega.Equal(observedRemote.ID))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		bypass := &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "user-bypass", Namespace: namespace},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: accountRef, Name: "user-bypass", Decision: v1alpha1.AccessPolicyDecisionBypass,
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		gomega.Expect(testClient.Create(testContext, bypass)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(bypass), bypass)).To(gomega.Succeed())
			g.Expect(bypass.Status.PolicyID).NotTo(gomega.BeEmpty())
			g.Expect(bypass.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(bypass.Status.Observed.Decision).To(gomega.Equal(v1alpha1.AccessPolicyDecisionBypass))
			g.Expect(statusutil.ConditionTrue(bypass.Status.Conditions, "Ready")).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		secretKey := types.NamespacedName{Namespace: namespace, Name: token.Spec.SecretRef.Name}
		gomega.Eventually(func(g gomega.Gomega) {
			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
			g.Expect(secret.Data[v1alpha1.ServiceTokenClientSecretKey]).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		var secret corev1.Secret
		gomega.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
		serializedStatus, err := json.Marshal(token.Status)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(serializedStatus)).NotTo(gomega.ContainSubstring(string(secret.Data[v1alpha1.ServiceTokenClientSecretKey])))
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
		for _, object := range []client.Object{policy, bypass, group, provider, posture, token} {
			gomega.Expect(testClient.Delete(testContext, object)).To(gomega.Succeed())
		}
		for _, object := range []client.Object{
			&v1alpha1.AccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: policy.Name, Namespace: namespace}},
			&v1alpha1.AccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: bypass.Name, Namespace: namespace}},
			&v1alpha1.AccessGroup{ObjectMeta: metav1.ObjectMeta{Name: group.Name, Namespace: namespace}},
			&v1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: provider.Name, Namespace: namespace}},
			&v1alpha1.DevicePostureRule{ObjectMeta: metav1.ObjectMeta{Name: posture.Name, Namespace: namespace}},
			&v1alpha1.ServiceToken{ObjectMeta: metav1.ObjectMeta{Name: token.Name, Namespace: namespace}},
		} {
			gomega.Eventually(func() bool {
				return apierrors.IsNotFound(testAPIReader.Get(testContext, client.ObjectKeyFromObject(object), object))
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		}
		testResourceAccessCloudflare.mu.Lock()
		policyCount := len(testResourceAccessCloudflare.policies)
		groupCount := len(testResourceAccessCloudflare.groups)
		_, managedGroupPresent := testResourceAccessCloudflare.groups[fakeAccessGroupKey(flarecloudflare.AccessScope{}, managedGroupID)]
		providerCount := len(testResourceAccessCloudflare.providers)
		postureCount := len(testResourceAccessCloudflare.posture)
		tokenCount = len(testResourceAccessCloudflare.tokens)
		secretCount := len(testResourceAccessCloudflare.secrets)
		testResourceAccessCloudflare.mu.Unlock()
		gomega.Expect(policyCount).To(gomega.BeZero())
		gomega.Expect(groupCount).To(gomega.Equal(1))
		gomega.Expect(managedGroupPresent).To(gomega.BeFalse())
		gomega.Expect(providerCount).To(gomega.BeZero())
		gomega.Expect(postureCount).To(gomega.BeZero())
		gomega.Expect(tokenCount).To(gomega.BeZero())
		gomega.Expect(secretCount).To(gomega.BeZero())
	})
})

func TestAccessPolicyRuleRoundTripCoversEveryOfficialVariant(t *testing.T) {
	rules := []flarecloudflare.ResolvedAccessRule{
		{Kind: "email", Value: "user@example.com"},
		{Kind: "emailDomain", Value: "example.com"},
		{Kind: "emailList", ID: "email-list"},
		{Kind: "everyone"},
		{Kind: "ip", Value: "192.0.2.0/24"},
		{Kind: "ipList", ID: "ip-list"},
		{Kind: "certificate"},
		{Kind: "commonName", Value: "device.example.com"},
		{Kind: "group", ID: "group"},
		{Kind: "azureAD", ID: "azure-group", IdentityProviderID: "azure-idp"},
		{Kind: "githubOrganization", Value: "example", Value2: "platform", IdentityProviderID: "github-idp"},
		{Kind: "gsuite", Value: "group@example.com", IdentityProviderID: "google-idp"},
		{Kind: "okta", Value: "engineering", IdentityProviderID: "okta-idp"},
		{Kind: "saml", Value: "role", Value2: "admin", IdentityProviderID: "saml-idp"},
		{Kind: "oidc", Value: "groups", Value2: "admin", IdentityProviderID: "oidc-idp"},
		{Kind: "serviceToken", ID: "service-token"},
		{Kind: "anyValidServiceToken"},
		{Kind: "externalEvaluation", Value: "https://example.com/evaluate", Value2: "https://example.com/keys"},
		{Kind: "geo", Value: "US"},
		{Kind: "authMethod", Value: "hwk"},
		{Kind: "devicePosture", ID: "posture", AccountID: "account"},
		{Kind: "loginMethod", IdentityProviderID: "login-idp"},
		{Kind: "authContext", Value: "context", Value2: "c1", IdentityProviderID: "azure-idp"},
		{Kind: "linkedAppToken", ID: "application"},
		{Kind: "userRiskScore", Values: []string{"Low", "Medium", "High", "Unscored"}},
		{Kind: "cloudflareAccountMember", AccountID: "account"},
	}
	params, err := flarecloudflare.AccessRulesForSDK(rules)
	if err != nil {
		t.Fatal(err)
	}
	responses := make([]zero_trust.AccessRule, len(params))
	for i := range params {
		data, marshalErr := json.Marshal(params[i])
		if marshalErr != nil {
			t.Fatalf("marshal rule %d: %v", i, marshalErr)
		}
		if unmarshalErr := json.Unmarshal(data, &responses[i]); unmarshalErr != nil {
			t.Fatalf("unmarshal rule %d: %v", i, unmarshalErr)
		}
	}
	observed, err := flarecloudflare.AccessRulesFromSDK(responses)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, rules) {
		t.Fatalf("round trip = %#v, want %#v", observed, rules)
	}
}

func TestAccessPolicyDriftComparisonAndAdoptionValidation(t *testing.T) {
	disabled := false
	required := true
	approvalRequired := true
	isolationRequired := true
	input := flarecloudflare.AccessPolicyInput{
		Name:                         "flareway/cluster/test/policy",
		Decision:                     string(v1alpha1.AccessPolicyDecisionAllow),
		Include:                      []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
		Require:                      []flarecloudflare.ResolvedAccessRule{{Kind: "userRiskScore", Values: []string{string(v1alpha1.AccessUserRiskLevelLow), string(v1alpha1.AccessUserRiskLevelHigh)}}},
		Exclude:                      []flarecloudflare.ResolvedAccessRule{},
		SessionDuration:              "8h",
		PurposeJustificationRequired: &required,
		PurposeJustificationPrompt:   "Explain why access is needed",
		ApprovalRequired:             &approvalRequired,
		ApprovalGroups:               []flarecloudflare.AccessApprovalGroup{{ApprovalsNeeded: 1, EmailAddresses: []string{"approver@example.com"}}},
		IsolationRequired:            &isolationRequired,
		MFAConfig:                    &flarecloudflare.AccessPolicyMFAConfig{AllowedAuthenticators: []string{"SecurityKey", "TOTP"}, MFADisabled: &disabled, SessionDuration: "24h"},
		ConnectionRules: &flarecloudflare.AccessPolicyConnectionRules{RDP: &flarecloudflare.AccessPolicyRDPConnectionRules{
			AllowedClipboardLocalToRemoteFormats: []string{"Text", "File"},
		}},
	}
	remote := flarecloudflare.AccessPolicy{
		ID:                           "policy",
		Name:                         input.Name,
		Decision:                     input.Decision,
		Include:                      []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
		Require:                      []flarecloudflare.ResolvedAccessRule{{Kind: "userRiskScore", Values: []string{string(v1alpha1.AccessUserRiskLevelHigh), string(v1alpha1.AccessUserRiskLevelLow)}}},
		Exclude:                      []flarecloudflare.ResolvedAccessRule{},
		SessionDuration:              "8h",
		PurposeJustificationRequired: true,
		PurposeJustificationPrompt:   "Explain why access is needed",
		ApprovalRequired:             true,
		ApprovalGroups:               []flarecloudflare.AccessApprovalGroup{{ApprovalsNeeded: 1, EmailAddresses: []string{"approver@example.com"}}},
		IsolationRequired:            true,
		MFAConfig:                    flarecloudflare.AccessPolicyMFAConfig{AllowedAuthenticators: []string{"TOTP", "SecurityKey"}, MFADisabled: &disabled, SessionDuration: "24h"},
		ConnectionRules: flarecloudflare.AccessPolicyConnectionRules{RDP: &flarecloudflare.AccessPolicyRDPConnectionRules{
			AllowedClipboardLocalToRemoteFormats: []string{"File", "Text"},
		}},
	}
	if !flarecloudflare.AccessPolicyMatchesInput(remote, input) {
		t.Fatal("equivalent policy was reported as drifted")
	}
	state, err := accessPolicyStateFromRemote(remote)
	if err != nil {
		t.Fatal(err)
	}
	if state.PurposeJustification == nil || !state.PurposeJustification.Required ||
		state.Approval == nil || !state.Approval.Required ||
		state.ConnectionRules == nil || state.ConnectionRules.RDP == nil ||
		state.MFAConfig == nil || state.MFAConfig.MFADisabled == nil ||
		state.IsolationRequired == nil || !*state.IsolationRequired {
		t.Fatalf("observed status omitted mutable state: %#v", state)
	}
	remote.Decision = string(v1alpha1.AccessPolicyDecisionDeny)
	if flarecloudflare.AccessPolicyMatchesInput(remote, input) {
		t.Fatal("decision drift was not detected")
	}
	object := &v1alpha1.AccessPolicy{Spec: v1alpha1.AccessPolicySpec{Adoption: v1alpha1.AdoptionSpec{Expect: v1alpha1.AdoptionExpect{Name: input.Name}}}}
	if err := validateAccessPolicyAdoption(object, input, remote); err == nil {
		t.Fatal("adoption accepted a mismatched decision")
	}
	remote.Decision = input.Decision
	remote.Name = "different"
	if err := validateAccessPolicyAdoption(object, input, remote); err == nil {
		t.Fatal("adoption accepted a mismatched name")
	}
}

func TestAccessPolicyReconcileSkipsPUTWithoutDriftAndObservesDrift(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "policy-test", Labels: map[string]string{"policy-test": "true"}}}
	systemNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster")}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: namespace.Name}, Data: map[string][]byte{"token": []byte("value")}}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: secret.Name, Namespace: secret.Namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: namespace.Labels},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue},
		}},
	}
	managed := &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: namespace.Name, Finalizers: []string{v1alpha1.AccessPolicyFinalizer}},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Name:             "managed",
			Decision:         v1alpha1.AccessPolicyDecisionAllow,
			Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.AccessPolicyStatus{PolicyID: "managed-id", OwnershipVerified: true},
	}
	remote := flarecloudflare.AccessPolicy{ID: "managed-id", Name: "flareway/cluster/policy-test/managed", Decision: string(v1alpha1.AccessPolicyDecisionAllow), Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}}
	api := &countingAccessPolicyAPI{policy: remote}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(managed).WithObjects(namespace, systemNamespace, secret, account, managed).Build()
	reconciler := &AccessPolicyReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil }}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(managed)}); err != nil {
		t.Fatal(err)
	}
	if api.updates != 0 {
		t.Fatalf("matching policy caused %d PUT requests", api.updates)
	}

	observeOnly := managed.DeepCopy()
	observeOnly.Name = "observed"
	observeOnly.ResourceVersion = ""
	observeOnly.UID = ""
	observeOnly.Spec.Name = "wanted"
	observeOnly.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
	observeOnly.Spec.ExternalRef = &v1alpha1.AccessPolicyExternalReference{PolicyID: "observed-id"}
	observeOnly.Status = v1alpha1.AccessPolicyStatus{}
	api.policy = flarecloudflare.AccessPolicy{ID: "observed-id", Name: "terraform-policy", Decision: string(v1alpha1.AccessPolicyDecisionDeny), Include: []flarecloudflare.ResolvedAccessRule{{Kind: "email", Value: "user@example.com"}}}
	if err := kube.Create(context.Background(), observeOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(observeOnly)}); err != nil {
		t.Fatal(err)
	}
	var observed v1alpha1.AccessPolicy
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(observeOnly), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Status.Observed == nil || observed.Status.WouldApply == nil {
		t.Fatalf("ObserveOnly status did not report observed state and drift: %#v", observed.Status)
	}
	if api.updates != 0 {
		t.Fatalf("ObserveOnly policy caused %d PUT requests", api.updates)
	}
}

type countingAccessPolicyAPI struct {
	flarecloudflare.AccessAPI
	policy  flarecloudflare.AccessPolicy
	updates int
}

func (f *countingAccessPolicyAPI) GetAccessPolicy(context.Context, string) (flarecloudflare.AccessPolicy, error) {
	return f.policy, nil
}

func (f *countingAccessPolicyAPI) UpdateAccessPolicy(_ context.Context, _ string, input flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	f.updates++
	f.policy.Name = input.Name
	f.policy.Decision = input.Decision
	f.policy.Include = input.Include
	f.policy.Require = input.Require
	f.policy.Exclude = input.Exclude
	return f.policy, nil
}
