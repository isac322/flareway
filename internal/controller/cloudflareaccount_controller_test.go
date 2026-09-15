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
	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"testing"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var _ = ginkgo.Describe("CloudflareAccount controller", func() {
	ginkgo.BeforeEach(func() {
		testAccountCloudflare.reset()
	})

	ginkgo.It("verifies credentials and publishes sorted non-secret account metadata", func() {
		testAccountCloudflare.mu.Lock()
		testAccountCloudflare.zones = []flarecloudflare.Zone{
			{ID: "zone-b", Name: "z.example", AccountID: "0123456789abcdef0123456789abcdef", AccountName: "Example Account"},
			{ID: "zone-a", Name: "a.example", AccountID: "0123456789abcdef0123456789abcdef", AccountName: "Example Account"},
			{ID: "foreign", Name: "foreign.example", AccountID: "ffffffffffffffffffffffffffffffff"},
		}
		testAccountCloudflare.organization = flarecloudflare.Organization{Name: "Example Account", AuthDomain: "TEAM.cloudflareaccess.com."}
		testAccountCloudflare.mu.Unlock()

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "account-token-success", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("sensitive-token")},
		}
		gomega.Expect(testClient.Create(testContext, secret)).To(gomega.Succeed())
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account-success"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: secret.Name, Namespace: secret.Namespace,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			observed := new(v1alpha1.CloudflareAccount)
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: account.Name}, observed)).To(gomega.Succeed())
			g.Expect(observed.Spec.Credentials.APITokenSecretRef.Key).To(gomega.Equal("token"))
			g.Expect(statusutil.ConditionTrue(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
			g.Expect(observed.Status.Verified.AccountName).To(gomega.Equal("Example Account"))
			g.Expect(observed.Status.Verified.AuthDomain).To(gomega.Equal("team.cloudflareaccess.com"))
			g.Expect(observed.Status.Verified.TeamName).To(gomega.Equal("team"))
			g.Expect(observed.Status.Verified.Zones).To(gomega.Equal([]v1alpha1.CloudflareVerifiedZone{
				{ID: "zone-a", Name: "a.example"},
				{ID: "zone-b", Name: "z.example"},
			}))
			g.Expect(observed.Status.Verified.TokenPermissions).To(gomega.BeEmpty())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

	})

	ginkgo.It("reports a missing Secret without constructing a Cloudflare client", func() {
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account-missing-secret"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: "does-not-exist", Namespace: "default", Key: "token",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			observed := new(v1alpha1.CloudflareAccount)
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: account.Name}, observed)).To(gomega.Succeed())
			accepted := statusutil.FindCondition(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)
			credentials := statusutil.FindCondition(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal("SecretNotFound"))
			g.Expect(credentials).NotTo(gomega.BeNil())
			g.Expect(credentials.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(observed.Status.Verified).To(gomega.Equal(v1alpha1.CloudflareAccountVerifiedStatus{}))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		testAccountCloudflare.mu.Lock()
		gomega.Expect(testAccountCloudflare.tokens).To(gomega.BeEmpty())
		testAccountCloudflare.mu.Unlock()

		gomega.Expect(testClient.Create(testContext, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "does-not-exist", Namespace: "default"},
			StringData: map[string]string{"token": "now-present"},
		})).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			observed := new(v1alpha1.CloudflareAccount)
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: account.Name}, observed)).To(gomega.Succeed())
			g.Expect(statusutil.ConditionTrue(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
			g.Expect(statusutil.ConditionTrue(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

	})

	ginkgo.It("marks an inactive token invalid", func() {
		testAccountCloudflare.mu.Lock()
		testAccountCloudflare.verification = flarecloudflare.TokenVerification{ID: "disabled", Status: "disabled"}
		testAccountCloudflare.mu.Unlock()
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "account-token-disabled", Namespace: "default"},
			StringData: map[string]string{"token": "disabled-token"},
		}
		gomega.Expect(testClient.Create(testContext, secret)).To(gomega.Succeed())
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account-disabled"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: secret.Name, Namespace: secret.Namespace, Key: "token",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			observed := new(v1alpha1.CloudflareAccount)
			g.Expect(testClient.Get(testContext, types.NamespacedName{Name: account.Name}, observed)).To(gomega.Succeed())
			condition := statusutil.FindCondition(observed.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal("CredentialsInvalid"))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
	})
})

func TestTeamNameFromAuthDomain(t *testing.T) {
	for _, test := range []struct {
		domain string
		team   string
		ok     bool
	}{
		{domain: "team.cloudflareaccess.com", team: "team", ok: true},
		{domain: "team.example.cloudflareaccess.com", ok: false},
		{domain: "cloudflareaccess.com", ok: false},
		{domain: "team.example.com", ok: false},
	} {
		team, ok := teamNameFromAuthDomain(test.domain)
		if team != test.team || ok != test.ok {
			t.Fatalf("teamNameFromAuthDomain(%q) = %q, %t; want %q, %t", test.domain, team, ok, test.team, test.ok)
		}
	}
}

func TestPermanentCredentialError(t *testing.T) {
	for _, test := range []struct {
		status int
		want   bool
	}{
		{status: 400, want: true},
		{status: 401, want: true},
		{status: 403, want: true},
		{status: 429, want: false},
		{status: 500, want: false},
	} {
		if got := permanentCredentialError(&cloudflaresdk.Error{StatusCode: test.status}); got != test.want {
			t.Fatalf("permanentCredentialError(status %d) = %t, want %t", test.status, got, test.want)
		}
	}
}
