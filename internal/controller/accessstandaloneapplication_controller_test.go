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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var standaloneTestCounter atomic.Int64

const fakeStandaloneWARPName = "WARP enrollment"

var _ = ginkgo.Describe("AccessStandaloneApplication Controller", func() {
	ginkgo.It("creates, updates, adopts, observes, and deletes WARP enrollment applications without sending a name", func() {
		fixture := newStandaloneControllerFixture("warp")
		fixture.createPrerequisites()

		managed := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName},
				Type:       v1alpha1.AccessStandaloneApplicationTypeWARP,
				Application: v1alpha1.AccessApplicationSettings{
					SessionDuration:          "24h",
					CustomDenyURL:            "https://deny.example.test/initial",
					CustomNonIdentityDenyURL: "https://deny.example.test/non-identity",
				},
				WARP:           &v1alpha1.AccessWARPApplicationSpec{},
				DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}
		gomega.Expect(testClient.Create(testContext, managed)).To(gomega.Succeed())
		fixture.reconcileUntil(managed, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		})
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))
		createInput := fixture.remote.lastCreate()
		gomega.Expect(createInput.Type).To(gomega.Equal(flarecloudflare.AccessApplicationTypeWARP))
		gomega.Expect(createInput.Name).To(gomega.BeEmpty())
		gomega.Expect(createInput.CustomDenyURL).To(gomega.Equal("https://deny.example.test/initial"))
		gomega.Expect(createInput.CustomNonIdentityDenyURL).To(gomega.Equal("https://deny.example.test/non-identity"))
		managedID := managed.Status.ApplicationID
		managedRemote := fixture.remote.application(managedID)
		gomega.Expect(managedRemote.AUD).NotTo(gomega.BeEmpty())
		gomega.Expect(managedRemote.Name).To(gomega.Equal(fakeStandaloneWARPName))
		gomega.Expect(managed.Status.Name).To(gomega.Equal(managedRemote.Name))
		fixture.remote.delayNextUpdateObservation()

		base := client.MergeFrom(managed.DeepCopy())
		managed.Spec.Application.SessionDuration = "12h"
		managed.Spec.Application.CustomDenyURL = "https://deny.example.test/updated"
		gomega.Expect(testClient.Patch(testContext, managed, base)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			_, reconcileErr := fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(managed)})
			g.Expect(reconcileErr).NotTo(gomega.HaveOccurred())
			updateID, updateInput := fixture.remote.lastUpdate()
			g.Expect(fixture.remote.updateCount()).To(gomega.Equal(1))
			g.Expect(updateID).To(gomega.Equal(managedID))
			g.Expect(updateInput.Type).To(gomega.Equal(flarecloudflare.AccessApplicationTypeWARP))
			g.Expect(updateInput.Name).To(gomega.BeEmpty())
			g.Expect(updateInput.SessionDuration).To(gomega.Equal("12h"))
			g.Expect(updateInput.CustomDenyURL).To(gomega.Equal("https://deny.example.test/updated"))
			g.Expect(updateInput.CustomNonIdentityDenyURL).To(gomega.Equal("https://deny.example.test/non-identity"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		fixture.reconcileUntil(managed, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.ApplicationID).To(gomega.Equal(managedID))
			remote := fixture.remote.application(current.Status.ApplicationID)
			g.Expect(remote.AUD).To(gomega.Equal(managedRemote.AUD))
			g.Expect(remote.SessionDuration).To(gomega.Equal("12h"))
			g.Expect(remote.CustomDenyURL).To(gomega.Equal("https://deny.example.test/updated"))
			g.Expect(remote.CustomNonIdentityDenyURL).To(gomega.Equal("https://deny.example.test/non-identity"))
		})

		fixture.remote.failNextUpdates(1)
		base = client.MergeFrom(managed.DeepCopy())
		managed.Spec.Application.SessionDuration = "8h"
		managed.Spec.Application.CustomNonIdentityDenyURL = "https://deny.example.test/non-identity-updated"
		gomega.Expect(testClient.Patch(testContext, managed, base)).To(gomega.Succeed())
		var failedUpdateErr error
		gomega.Eventually(func() bool {
			_, reconcileErr := fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(managed)})
			if fixture.remote.updateCallCount() != 2 {
				return false
			}
			failedUpdateErr = reconcileErr
			return true
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(failedUpdateErr).To(gomega.HaveOccurred())
		gomega.Expect(fixture.remote.updateCount()).To(gomega.Equal(1))
		gomega.Eventually(func(g gomega.Gomega) {
			_, reconcileErr := fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(managed)})
			g.Expect(reconcileErr).NotTo(gomega.HaveOccurred())
			_, updateInput := fixture.remote.lastUpdate()
			g.Expect(fixture.remote.updateCallCount()).To(gomega.Equal(3))
			g.Expect(fixture.remote.updateCount()).To(gomega.Equal(2))
			g.Expect(updateInput.Name).To(gomega.BeEmpty())
			g.Expect(updateInput.SessionDuration).To(gomega.Equal("8h"))
			g.Expect(updateInput.CustomDenyURL).To(gomega.Equal("https://deny.example.test/updated"))
			g.Expect(updateInput.CustomNonIdentityDenyURL).To(gomega.Equal("https://deny.example.test/non-identity-updated"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		fixture.reconcileUntil(managed, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			remote := fixture.remote.application(current.Status.ApplicationID)
			g.Expect(remote.SessionDuration).To(gomega.Equal("8h"))
			g.Expect(remote.CustomDenyURL).To(gomega.Equal("https://deny.example.test/updated"))
			g.Expect(remote.CustomNonIdentityDenyURL).To(gomega.Equal("https://deny.example.test/non-identity-updated"))
		})

		adoptedRemote := fixture.remote.put(flarecloudflare.AccessApplication{
			ID: "adopted-warp", Type: flarecloudflare.AccessApplicationTypeWARP,
			Name: "existing-terraform-warp", SessionDuration: "12h", CustomDenyURL: "https://deny.example.test/adopted",
		})
		adopted := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeWARP,
				Application: v1alpha1.AccessApplicationSettings{SessionDuration: "24h", CustomDenyURL: "https://deny.example.test/adopted-updated"}, WARP: &v1alpha1.AccessWARPApplicationSpec{},
				ExternalRef: &v1alpha1.AccessApplicationExternalReference{ApplicationID: adoptedRemote.ID},
				Adoption:    v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: adoptedRemote.Name}},
			},
		}
		gomega.Expect(testClient.Create(testContext, adopted)).To(gomega.Succeed())
		fixture.reconcileUntil(adopted, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.ApplicationID).To(gomega.Equal(adoptedRemote.ID))
			g.Expect(current.Status.Name).To(gomega.Equal(adoptedRemote.Name))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			remote := fixture.remote.application(current.Status.ApplicationID)
			g.Expect(remote.Name).To(gomega.Equal(adoptedRemote.Name))
			g.Expect(remote.SessionDuration).To(gomega.Equal("24h"))
			g.Expect(remote.CustomDenyURL).To(gomega.Equal("https://deny.example.test/adopted-updated"))
		})
		adoptUpdateID, adoptUpdateInput := fixture.remote.lastUpdate()
		gomega.Expect(adoptUpdateID).To(gomega.Equal(adoptedRemote.ID))
		gomega.Expect(adoptUpdateInput.Name).To(gomega.BeEmpty())
		gomega.Expect(adoptUpdateInput.CustomDenyURL).To(gomega.Equal("https://deny.example.test/adopted-updated"))

		observedRemote := fixture.remote.put(flarecloudflare.AccessApplication{
			ID: "observed-warp", Type: flarecloudflare.AccessApplicationTypeWARP,
			Name: "observed-terraform-warp", SessionDuration: "24h", CustomDenyURL: "https://deny.example.test/observed",
		})
		observed := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeWARP,
				Application: v1alpha1.AccessApplicationSettings{SessionDuration: "24h", CustomDenyURL: "https://deny.example.test/observed"}, WARP: &v1alpha1.AccessWARPApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				ExternalRef:      &v1alpha1.AccessApplicationExternalReference{ApplicationID: observedRemote.ID},
				Adoption:         v1alpha1.AdoptionSpec{Expect: v1alpha1.AdoptionExpect{Name: observedRemote.Name}},
			},
		}
		gomega.Expect(testClient.Create(testContext, observed)).To(gomega.Succeed())
		mutations := fixture.remote.mutations()
		fixture.reconcileUntil(observed, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.ApplicationID).To(gomega.Equal(observedRemote.ID))
			g.Expect(current.Status.Name).To(gomega.Equal(observedRemote.Name))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
		})
		gomega.Expect(fixture.remote.mutations()).To(gomega.Equal(mutations))

		gomega.Expect(testClient.Delete(testContext, managed)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			_, err := fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(managed)})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(fixture.remote.has(managedID)).To(gomega.BeFalse())
			g.Expect(fixture.remote.deletes).To(gomega.Equal(1))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("checks expected domains before observing or adopting standalone applications", func() {
		fixture := newStandaloneControllerFixture("expect-domain")
		fixture.createPrerequisites()

		observedRemote := fixture.remote.put(flarecloudflare.AccessApplication{
			ID: "observed-bookmark", Type: flarecloudflare.AccessApplicationTypeBookmark,
			Name: "observed-bookmark", Domain: "https://observed.example.test/",
		})
		observed := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "observed", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Application:      v1alpha1.AccessApplicationSettings{Name: observedRemote.Name},
				Bookmark:         &v1alpha1.AccessBookmarkApplicationSpec{URL: observedRemote.Domain},
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				ExternalRef:      &v1alpha1.AccessApplicationExternalReference{ApplicationID: observedRemote.ID},
				Adoption: v1alpha1.AdoptionSpec{Expect: v1alpha1.AdoptionExpect{
					Name: observedRemote.Name, Domain: "https://wrong.example.test/",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, observed)).To(gomega.Succeed())
		fixture.reconcileUntil(observed, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(gomega.Equal("Conflict"))
			g.Expect(ready.Message).To(gomega.ContainSubstring("domain"))
		})

		adoptedRemote := fixture.remote.put(flarecloudflare.AccessApplication{
			ID: "adopted-bookmark", Type: flarecloudflare.AccessApplicationTypeBookmark,
			Name: "adopted-bookmark", Domain: "https://adopted.example.test/",
		})
		adopted := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Application: v1alpha1.AccessApplicationSettings{Name: adoptedRemote.Name},
				Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: adoptedRemote.Domain},
				ExternalRef: &v1alpha1.AccessApplicationExternalReference{ApplicationID: adoptedRemote.ID},
				Adoption: v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{
					Name: adoptedRemote.Name, Domain: "https://wrong.example.test/",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, adopted)).To(gomega.Succeed())
		fixture.reconcileUntil(adopted, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(gomega.Equal("Conflict"))
			g.Expect(ready.Message).To(gomega.ContainSubstring("domain"))
		})
		gomega.Expect(fixture.remote.mutations()).To(gomega.BeZero())
	})

	ginkgo.It("creates missing supported tags before standalone application creates and updates", func() {
		fixture := newStandaloneControllerFixture("tags")
		fixture.createPrerequisites()
		fixture.remote.putTag("existing")

		application := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "bookmark", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Application: v1alpha1.AccessApplicationSettings{Name: "bookmark", Tags: []string{"new-tag", "existing"}},
				Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://bookmark.example.test/"},
			},
		}
		gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.Tags).To(gomega.ConsistOf("existing", "new-tag"))
		})
		gomega.Expect(fixture.remote.hasTag("existing")).To(gomega.BeTrue())
		gomega.Expect(fixture.remote.hasTag("new-tag")).To(gomega.BeTrue())
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))

		base := client.MergeFrom(application.DeepCopy())
		application.Spec.Application.Tags = []string{"replacement", "existing"}
		gomega.Expect(testClient.Patch(testContext, application, base)).To(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.Tags).To(gomega.ConsistOf("existing", "replacement"))
		})
		gomega.Expect(fixture.remote.hasTag("replacement")).To(gomega.BeTrue())
		gomega.Expect(fixture.remote.updateCount()).To(gomega.Equal(1))
	})

	ginkgo.It("rejects invalid tags and WARP identification fields before remote writes", func() {
		fixture := newStandaloneControllerFixture("invalid-tags")
		account := &v1alpha1.CloudflareAccount{}
		bookmark := &v1alpha1.AccessStandaloneApplication{Spec: v1alpha1.AccessStandaloneApplicationSpec{
			Type:        v1alpha1.AccessStandaloneApplicationTypeBookmark,
			Application: v1alpha1.AccessApplicationSettings{Name: "bookmark", Tags: []string{"invalid tag"}},
			Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://bookmark.example.test/"},
		}}
		_, err := fixture.reconciler.applicationInput(testContext, bookmark, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported character")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("Invalid"))

		bookmark.Spec.Application.Tags = []string{""}
		_, err = fixture.reconciler.applicationInput(testContext, bookmark, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError("access tag name is required"))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("Invalid"))

		bookmark.Spec.Application.Tags = make([]string, flarecloudflare.AccessApplicationTagLimit+1)
		for index := range bookmark.Spec.Application.Tags {
			bookmark.Spec.Application.Tags[index] = fmt.Sprintf("tag-%d", index)
		}
		_, err = fixture.reconciler.applicationInput(testContext, bookmark, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("at most 25")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("Invalid"))

		for _, applicationType := range []v1alpha1.AccessStandaloneApplicationType{
			v1alpha1.AccessStandaloneApplicationTypeSaaS,
			v1alpha1.AccessStandaloneApplicationTypeBookmark,
			v1alpha1.AccessStandaloneApplicationTypeMCPPortal,
		} {
			tags, supportedErr := desiredStandaloneAccessTags(applicationType, []string{"supported"})
			gomega.Expect(supportedErr).NotTo(gomega.HaveOccurred())
			gomega.Expect(tags).To(gomega.Equal([]string{"supported"}))
		}

		for _, applicationType := range []v1alpha1.AccessStandaloneApplicationType{
			v1alpha1.AccessStandaloneApplicationTypeInfrastructure,
			v1alpha1.AccessStandaloneApplicationTypeAppLauncher,
			v1alpha1.AccessStandaloneApplicationTypeWARP,
			v1alpha1.AccessStandaloneApplicationTypeBISO,
			v1alpha1.AccessStandaloneApplicationTypeDashSSO,
		} {
			_, err = desiredStandaloneAccessTags(applicationType, []string{"unsupported"})
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("does not support tags")))
			gomega.Expect(accessValidationReason(err)).To(gomega.Equal("UnsupportedField"))
		}

		warp := &v1alpha1.AccessStandaloneApplication{Spec: v1alpha1.AccessStandaloneApplicationSpec{
			Type:        v1alpha1.AccessStandaloneApplicationTypeWARP,
			Application: v1alpha1.AccessApplicationSettings{Tags: []string{"unsupported"}},
			WARP:        &v1alpha1.AccessWARPApplicationSpec{},
		}}
		_, err = fixture.reconciler.applicationInput(testContext, warp, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("does not support tags")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("UnsupportedField"))

		warp.Spec.Application.Tags = nil
		warp.Spec.Application.Name = "terraform-warp"
		_, err = fixture.reconciler.applicationInput(testContext, warp, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("adoption.expect.name")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("UnsupportedField"))

		warp.Spec.Application.Name = ""
		warp.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}
		_, err = fixture.reconciler.applicationInput(testContext, warp, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("require adoption.expect.name")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("Invalid"))

		warp.Spec.Adoption = v1alpha1.AdoptionSpec{}
		warp.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		_, err = fixture.reconciler.applicationInput(testContext, warp, account, fixture.remote)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("require adoption.expect.name")))
		gomega.Expect(accessValidationReason(err)).To(gomega.Equal("Invalid"))
		gomega.Expect(fixture.remote.mutations()).To(gomega.BeZero())
	})

	ginkgo.It("does not create an application when a missing tag cannot be created", func() {
		fixture := newStandaloneControllerFixture("tag-failure")
		fixture.createPrerequisites()
		fixture.remote.failTagCreate("missing-tag", errors.New("tag creation denied"))
		application := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "bookmark", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Type: v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Application: v1alpha1.AccessApplicationSettings{Name: "bookmark", Tags: []string{"missing-tag"}},
				Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://bookmark.example.test/"},
			},
		}
		gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())
		var reconcileErr error
		gomega.Eventually(func() bool {
			_, reconcileErr = fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(application)})
			return reconcileErr != nil
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(reconcileErr).To(gomega.MatchError(gomega.ContainSubstring("tag creation denied")))
		gomega.Expect(fixture.remote.hasTag("missing-tag")).To(gomega.BeFalse())
		gomega.Expect(fixture.remote.mutations()).To(gomega.BeZero())
	})

	ginkgo.It("writes the SaaS client secret once and never fabricates a replacement", func() {
		fixture := newStandaloneControllerFixture("saas")
		fixture.createPrerequisites()
		application := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "saas", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.accountName}, Zone: "example.test", Type: v1alpha1.AccessStandaloneApplicationTypeSaaS,
				Application: v1alpha1.AccessApplicationSettings{Name: "oidc-saas"},
				SaaS:        &v1alpha1.AccessSaaSApplicationSpec{AuthType: v1alpha1.AccessSaaSAuthenticationTypeOIDC, OIDC: &v1alpha1.AccessSaaSOIDCSpec{RedirectURIs: []string{"https://app.example.test/callback"}, Scopes: []v1alpha1.AccessSaaSOIDCScope{v1alpha1.AccessSaaSOIDCScopeOpenID}}},
			},
		}
		gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.SaaS).NotTo(gomega.BeNil())
			g.Expect(current.Status.SaaS.ClientSecretRef).NotTo(gomega.BeNil())
			g.Expect(current.Status.ZoneID).To(gomega.Equal("zone-example"))
		})
		gomega.Expect(fixture.remote.lastScope.ZoneID).To(gomega.Equal("zone-example"))
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))
		expectedSecretName := "saas-client-" + string(application.UID)
		gomega.Expect(standaloneSaaSSecretName(application)).To(gomega.Equal(expectedSecretName))
		gomega.Expect(application.Status.SaaS.ClientSecretRef.Name).To(gomega.Equal(expectedSecretName))
		secretKey := types.NamespacedName{Namespace: fixture.namespace, Name: expectedSecretName}
		var secret corev1.Secret
		gomega.Expect(testAPIReader.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
		gomega.Expect(string(secret.Data[v1alpha1.AccessStandaloneApplicationClientSecretKey])).To(gomega.Equal("one-time-saas-secret"))
		gomega.Expect(secret.OwnerReferences).To(gomega.HaveLen(1))
		secretUID, secretVersion := secret.UID, secret.ResourceVersion

		statusBase := client.MergeFrom(application.DeepCopy())
		application.Status.ApplicationID = ""
		application.Status.OwnershipVerified = false
		application.Status.SaaS = nil
		gomega.Expect(testClient.Status().Patch(testContext, application, statusBase)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.AccessStandaloneApplication
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(application), &current)).To(gomega.Succeed())
			g.Expect(current.Status.ApplicationID).To(gomega.BeEmpty())
			g.Expect(current.Status.SaaS).To(gomega.BeNil())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(current.Status.ApplicationID).NotTo(gomega.BeEmpty())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.SaaS).NotTo(gomega.BeNil())
			g.Expect(current.Status.SaaS.ClientSecretRef).NotTo(gomega.BeNil())
		})
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))
		var recoveredSecret corev1.Secret
		gomega.Expect(testAPIReader.Get(testContext, secretKey, &recoveredSecret)).To(gomega.Succeed())
		gomega.Expect(recoveredSecret.UID).To(gomega.Equal(secretUID))
		gomega.Expect(recoveredSecret.ResourceVersion).To(gomega.Equal(secretVersion))
		gomega.Expect(string(recoveredSecret.Data[v1alpha1.AccessStandaloneApplicationClientSecretKey])).To(gomega.Equal("one-time-saas-secret"))

		creates := fixture.remote.creates
		gomega.Expect(testClient.Delete(testContext, &recoveredSecret)).To(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			condition := statusutil.FindCondition(current.Status.Conditions, "Ready")
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("SecretMissing"))
		})
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(creates))
		gomega.Expect(testAPIReader.Get(testContext, secretKey, &corev1.Secret{})).To(gomega.HaveOccurred())
	})

	ginkgo.It("retries transient external reference lookups and treats only a genuine 404 as TargetNotFound", func() {
		fixture := newStandaloneControllerFixture("transient-ref")
		fixture.createPrerequisites()

		transient := standaloneCloudflareError(http.StatusServiceUnavailable)
		notFound := standaloneCloudflareError(http.StatusNotFound)

		cases := []struct {
			name  string
			apply func(*v1alpha1.AccessStandaloneApplication)
			fail  func(error)
		}{
			{
				name: "policy",
				apply: func(application *v1alpha1.AccessStandaloneApplication) {
					application.Spec.Policies = []v1alpha1.AccessApplicationPolicyReference{{
						ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "external-policy"},
					}}
				},
				fail: fixture.remote.failPolicyLookup,
			},
			{
				name: "identity-provider",
				apply: func(application *v1alpha1.AccessStandaloneApplication) {
					application.Spec.Application.AllowedIDPRefs = []v1alpha1.AccessIdentityProviderReference{{ExternalID: "external-idp"}}
				},
				fail: fixture.remote.failIDPLookup,
			},
			{
				name: "custom-page",
				apply: func(application *v1alpha1.AccessStandaloneApplication) {
					application.Spec.Application.CustomPageRefs = []v1alpha1.AccessCustomPageReference{{ExternalID: "external-page"}}
				},
				fail: fixture.remote.failCustomPageLookup,
			},
		}

		for _, testCase := range cases {
			application := &v1alpha1.AccessStandaloneApplication{
				ObjectMeta: metav1.ObjectMeta{Name: testCase.name, Namespace: fixture.namespace},
				Spec: v1alpha1.AccessStandaloneApplicationSpec{
					AccountRef:  corev1.LocalObjectReference{Name: fixture.accountName},
					Type:        v1alpha1.AccessStandaloneApplicationTypeBookmark,
					Application: v1alpha1.AccessApplicationSettings{Name: testCase.name},
					Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://" + testCase.name + ".example.test/"},
				},
			}
			testCase.apply(application)
			gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())

			testCase.fail(transient)
			gomega.Eventually(func() bool {
				_, reconcileErr := fixture.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(application)})
				statusCode, isCloudflareError := flarecloudflare.StatusCode(reconcileErr)
				return isCloudflareError && statusCode == http.StatusServiceUnavailable
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
			gomega.Eventually(func(g gomega.Gomega) {
				var current v1alpha1.AccessStandaloneApplication
				g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(application), &current)).To(gomega.Succeed())
				ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
				g.Expect(ready).NotTo(gomega.BeNil())
				g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(ready.Reason).To(gomega.Equal("CloudflareError"))
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

			testCase.fail(nil)
			fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
				g.Expect(statusutil.ConditionTrue(current.Status.Conditions, "Ready")).To(gomega.BeTrue())
			})

			testCase.fail(notFound)
			fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
				ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
				g.Expect(ready).NotTo(gomega.BeNil())
				g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(ready.Reason).To(gomega.Equal("TargetNotFound"))
				g.Expect(statusutil.ConditionFalse(current.Status.Conditions, "Accepted")).To(gomega.BeTrue())
			})
			testCase.fail(nil)
		}
	})

	ginkgo.It("repairs remote drift that lands inside the update confirmation window, including after a restart", func() {
		fixture := newStandaloneControllerFixture("update-window")
		fixture.createPrerequisites()

		application := &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "bookmark", Namespace: fixture.namespace},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef:  corev1.LocalObjectReference{Name: fixture.accountName},
				Type:        v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Application: v1alpha1.AccessApplicationSettings{Name: "bookmark"},
				Bookmark:    &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://bookmark.example.test/"},
			},
		}
		gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, "Ready")).To(gomega.BeTrue())
		})
		gomega.Expect(fixture.remote.updateCallCount()).To(gomega.BeZero())

		restarted := func() *AccessStandaloneApplicationReconciler {
			return &AccessStandaloneApplicationReconciler{
				Client: testClient, Scheme: testClient.Scheme(),
				NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return fixture.remote, nil },
			}
		}
		drift := func(domain string) {
			remote := fixture.remote.application(application.Status.ApplicationID)
			remote.Domain = domain
			fixture.remote.put(remote)
		}
		updatesReach := func(reconciler *AccessStandaloneApplicationReconciler, count int) {
			gomega.Eventually(func(g gomega.Gomega) {
				_, err := reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(application)})
				g.Expect(err).NotTo(gomega.HaveOccurred())
				g.Expect(fixture.remote.updateCallCount()).To(gomega.Equal(count))
			}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}

		// Drift outside the confirmation window is repaired immediately.
		drift("https://drifted.example.test/")
		updatesReach(fixture.reconciler, 1)
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, "Ready")).To(gomega.BeTrue())
		})

		// Drift inside the confirmation window is repaired on the next reconcile.
		base := client.MergeFrom(application.DeepCopy())
		application.Spec.Bookmark.URL = "https://bookmark-v2.example.test/"
		gomega.Expect(testClient.Patch(testContext, application, base)).To(gomega.Succeed())
		updatesReach(fixture.reconciler, 2)
		drift("https://window.example.test/")
		updatesReach(fixture.reconciler, 3)
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, "Ready")).To(gomega.BeTrue())
			g.Expect(fixture.remote.application(current.Status.ApplicationID).Domain).To(gomega.Equal("https://bookmark-v2.example.test/"))
		})

		// A process restart inside the confirmation window does not strand drift.
		drift("https://restart.example.test/")
		updatesReach(restarted(), 4)
		drift("https://restart-window.example.test/")
		updatesReach(restarted(), 5)
		fixture.reconcileUntil(application, func(g gomega.Gomega, current *v1alpha1.AccessStandaloneApplication) {
			g.Expect(statusutil.ConditionTrue(current.Status.Conditions, "Ready")).To(gomega.BeTrue())
			g.Expect(fixture.remote.application(current.Status.ApplicationID).Domain).To(gomega.Equal("https://bookmark-v2.example.test/"))
		})
	})
})

type standaloneControllerFixture struct {
	namespace   string
	accountName string
	remote      *fakeStandaloneCloudflare
	reconciler  *AccessStandaloneApplicationReconciler
}

func newStandaloneControllerFixture(prefix string) *standaloneControllerFixture {
	suffix := standaloneTestCounter.Add(1)
	remote := &fakeStandaloneCloudflare{
		applications:        map[string]flarecloudflare.AccessApplication{},
		pendingApplications: map[string]flarecloudflare.AccessApplication{},
		tags:                map[string]flarecloudflare.AccessTag{},
		tagCreateFailures:   map[string]error{},
	}
	return &standaloneControllerFixture{
		namespace: fmt.Sprintf("standalone-%s-%d", prefix, suffix), accountName: fmt.Sprintf("standalone-account-%d", suffix), remote: remote,
		reconciler: &AccessStandaloneApplicationReconciler{Client: testClient, Scheme: testClient.Scheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil }},
	}
}

func (f *standaloneControllerFixture) createPrerequisites() {
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.namespace, Labels: map[string]string{"standalone": f.namespace}}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeleteStandaloneNamespace, f.namespace)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: f.namespace}, Data: map[string][]byte{"token": []byte("api-token")}}
	gomega.Expect(testClient.Create(testContext, secret)).To(gomega.Succeed())
	accountID := fmt.Sprintf("%032x", standaloneTestCounter.Load())
	testAccountCloudflare.reset()
	testAccountCloudflare.mu.Lock()
	testAccountCloudflare.zones = []flarecloudflare.Zone{{ID: "zone-example", Name: "example.test", AccountID: accountID}}
	testAccountCloudflare.mu.Unlock()
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: f.accountName}, Spec: v1alpha1.CloudflareAccountSpec{
		AccountID:   accountID,
		Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: secret.Name, Namespace: secret.Namespace, Key: "token"}},
		Grants: []v1alpha1.CloudflareAccountGrant{{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"standalone": f.namespace}},
			Hostnames:         []string{"*"},
			Zones:             []string{"*"},
			Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
			PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
		}},
	}}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	gomega.Eventually(func(g gomega.Gomega) {
		var current v1alpha1.CloudflareAccount
		g.Expect(testAPIReader.Get(testContext, types.NamespacedName{Name: f.accountName}, &current)).To(gomega.Succeed())
		g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
		g.Expect(statusutil.ConditionTrue(current.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
		g.Expect(current.Status.Verified.Zones).To(gomega.ContainElement(v1alpha1.CloudflareVerifiedZone{ID: "zone-example", Name: "example.test"}))
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func (f *standaloneControllerFixture) reconcileUntil(object *v1alpha1.AccessStandaloneApplication, assertion func(gomega.Gomega, *v1alpha1.AccessStandaloneApplication)) {
	key := client.ObjectKeyFromObject(object)
	gomega.Eventually(func(g gomega.Gomega) {
		_, err := f.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: key})
		g.Expect(err).NotTo(gomega.HaveOccurred())
		var current v1alpha1.AccessStandaloneApplication
		g.Expect(testAPIReader.Get(testContext, key, &current)).To(gomega.Succeed())
		*object = current
		assertion(g, &current)
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func forceDeleteStandaloneNamespace(namespace string) {
	var applications v1alpha1.AccessStandaloneApplicationList
	if err := testClient.List(testContext, &applications, client.InNamespace(namespace)); err == nil {
		for i := range applications.Items {
			if len(applications.Items[i].Finalizers) == 0 {
				continue
			}
			base := client.MergeFrom(applications.Items[i].DeepCopy())
			applications.Items[i].Finalizers = nil
			_ = testClient.Patch(testContext, &applications.Items[i], base)
		}
	}
	forceDeleteAccessNamespace(namespace)
}

type fakeStandaloneCloudflare struct {
	flarecloudflare.AccessAPI
	mu                     sync.Mutex
	applications           map[string]flarecloudflare.AccessApplication
	pendingApplications    map[string]flarecloudflare.AccessApplication
	tags                   map[string]flarecloudflare.AccessTag
	tagCreateFailures      map[string]error
	delayUpdateObservation bool
	creates                int
	updates                int
	updateCalls            int
	deletes                int
	lastScope              flarecloudflare.AccessScope
	lastUpdateID           string
	lastUpdateInput        flarecloudflare.AccessApplicationInput
	lastCreateInput        flarecloudflare.AccessApplicationInput
	updateFailures         int
	policyLookupErr        error
	idpLookupErr           error
	customPageLookupErr    error
}

func (f *fakeStandaloneCloudflare) CreateAccessApplication(_ context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplicationCreateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastScope = scope
	f.lastCreateInput = input
	if missing := f.missingTag(input.Tags); missing != "" {
		return flarecloudflare.AccessApplicationCreateResult{}, fmt.Errorf("create Access application references missing tag %q", missing)
	}
	f.creates++
	id := fmt.Sprintf("application-%d", f.creates)
	application := fakeStandaloneApplication(id, input)
	if input.Type == flarecloudflare.AccessApplicationTypeWARP {
		application.Name = fakeStandaloneWARPName
	}
	f.applications[id] = application
	secret := ""
	if input.Type == flarecloudflare.AccessApplicationTypeSaaS {
		secret = "one-time-saas-secret"
	}
	return flarecloudflare.AccessApplicationCreateResult{Application: application, SaaSClientSecret: secret}, nil
}
func (f *fakeStandaloneCloudflare) UpdateAccessApplication(_ context.Context, _ flarecloudflare.AccessScope, id string, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if missing := f.missingTag(input.Tags); missing != "" {
		return flarecloudflare.AccessApplication{}, fmt.Errorf("update Access application references missing tag %q", missing)
	}
	f.updateCalls++
	if f.updateFailures > 0 {
		f.updateFailures--
		return flarecloudflare.AccessApplication{}, fmt.Errorf("update Access application failed")
	}
	f.updates++
	f.lastUpdateID = id
	f.lastUpdateInput = input
	application := fakeStandaloneApplication(id, input)
	if input.Type == flarecloudflare.AccessApplicationTypeWARP && input.Name == "" {
		application.Name = f.applications[id].Name
	}
	if f.delayUpdateObservation {
		f.delayUpdateObservation = false
		f.pendingApplications[id] = application
	} else {
		f.applications[id] = application
	}
	return application, nil
}
func (f *fakeStandaloneCloudflare) GetAccessApplication(_ context.Context, _ flarecloudflare.AccessScope, id string) (flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	application, ok := f.applications[id]
	if !ok {
		return application, fmt.Errorf("not found")
	}
	if pending, found := f.pendingApplications[id]; found {
		f.applications[id] = pending
		delete(f.pendingApplications, id)
	}
	return application, nil
}
func (f *fakeStandaloneCloudflare) ListAccessApplications(context.Context, flarecloudflare.AccessScope) ([]flarecloudflare.AccessApplication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]flarecloudflare.AccessApplication, 0, len(f.applications))
	for _, application := range f.applications {
		result = append(result, application)
	}
	return result, nil
}
func (f *fakeStandaloneCloudflare) DeleteAccessApplication(_ context.Context, _ flarecloudflare.AccessScope, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	delete(f.applications, id)
	return nil
}
func (f *fakeStandaloneCloudflare) RevokeAccessApplicationTokens(context.Context, flarecloudflare.AccessScope, string) error {
	return nil
}
func (f *fakeStandaloneCloudflare) GetAccessPolicy(_ context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policyLookupErr != nil {
		return flarecloudflare.AccessPolicy{}, f.policyLookupErr
	}
	return flarecloudflare.AccessPolicy{ID: id}, nil
}
func (f *fakeStandaloneCloudflare) GetIdentityProvider(_ context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idpLookupErr != nil {
		return flarecloudflare.IdentityProvider{}, f.idpLookupErr
	}
	return flarecloudflare.IdentityProvider{ID: id}, nil
}
func (f *fakeStandaloneCloudflare) GetAccessCustomPage(_ context.Context, id string) (flarecloudflare.AccessCustomPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.customPageLookupErr != nil {
		return flarecloudflare.AccessCustomPage{}, f.customPageLookupErr
	}
	return flarecloudflare.AccessCustomPage{AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{ID: id}}, nil
}
func (f *fakeStandaloneCloudflare) GetAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tag, found := f.tags[name]
	if !found {
		return flarecloudflare.AccessTag{}, fmt.Errorf("Access tag %q not found", name)
	}
	return tag, nil
}

func (f *fakeStandaloneCloudflare) ListAccessTags(context.Context) ([]flarecloudflare.AccessTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]flarecloudflare.AccessTag, 0, len(f.tags))
	for _, tag := range f.tags {
		result = append(result, tag)
	}
	return result, nil
}

func (f *fakeStandaloneCloudflare) CreateAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.tagCreateFailures[name]; err != nil {
		return flarecloudflare.AccessTag{}, err
	}
	tag := flarecloudflare.AccessTag{Name: name}
	f.tags[name] = tag
	return tag, nil
}
func (f *fakeStandaloneCloudflare) put(application flarecloudflare.AccessApplication) flarecloudflare.AccessApplication {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applications[application.ID] = application
	return application
}
func (f *fakeStandaloneCloudflare) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.applications[id]
	return ok
}
func (f *fakeStandaloneCloudflare) putTag(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[name] = flarecloudflare.AccessTag{Name: name}
}

func (f *fakeStandaloneCloudflare) hasTag(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, found := f.tags[name]
	return found
}

func (f *fakeStandaloneCloudflare) failTagCreate(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tagCreateFailures[name] = err
}

func (f *fakeStandaloneCloudflare) missingTag(names []string) string {
	for _, name := range names {
		if _, found := f.tags[name]; !found {
			return name
		}
	}
	return ""
}
func (f *fakeStandaloneCloudflare) application(id string) flarecloudflare.AccessApplication {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applications[id]
}
func (f *fakeStandaloneCloudflare) delayNextUpdateObservation() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delayUpdateObservation = true
}

func (f *fakeStandaloneCloudflare) failNextUpdates(count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateFailures = count
}

func (f *fakeStandaloneCloudflare) failPolicyLookup(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policyLookupErr = err
}

func (f *fakeStandaloneCloudflare) failIDPLookup(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idpLookupErr = err
}

func (f *fakeStandaloneCloudflare) failCustomPageLookup(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.customPageLookupErr = err
}

func (f *fakeStandaloneCloudflare) lastCreate() flarecloudflare.AccessApplicationInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCreateInput
}

func (f *fakeStandaloneCloudflare) lastUpdate() (string, flarecloudflare.AccessApplicationInput) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastUpdateID, f.lastUpdateInput
}

func (f *fakeStandaloneCloudflare) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

func (f *fakeStandaloneCloudflare) updateCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updateCalls
}

func (f *fakeStandaloneCloudflare) mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates + f.updates + f.deletes
}

func fakeStandaloneApplication(id string, input flarecloudflare.AccessApplicationInput) flarecloudflare.AccessApplication {
	application := flarecloudflare.AccessApplication{
		ID: id, AUD: "aud-" + id, Type: input.Type, Domain: input.Domain, Name: input.Name,
		Destinations: input.Destinations, AllowedIDPs: input.AllowedIDPs, SessionDuration: input.SessionDuration,
		AutoRedirectToIdentity: input.AutoRedirectToIdentity, CustomDenyURL: input.CustomDenyURL,
		CustomNonIdentityDenyURL: input.CustomNonIdentityDenyURL, CustomPages: input.CustomPages,
		Tags: input.Tags, LogoURL: input.LogoURL, TargetCriteria: input.TargetCriteria,
		AppLauncherLogoURL: input.AppLauncherLogoURL, BackgroundColor: input.BackgroundColor,
		FooterLinks: input.FooterLinks, HeaderBackgroundColor: input.HeaderBackgroundColor,
		LandingPageDesign: input.LandingPageDesign, SkipAppLauncherLoginPage: input.SkipAppLauncherLoginPage,
	}
	for _, policy := range input.Policies {
		application.Policies = append(application.Policies, flarecloudflare.AccessApplicationPolicy{ID: policy.ID, Precedence: policy.Precedence})
	}
	if input.SaaSApp != nil {
		application.SaaSApp = &flarecloudflare.AccessSaaSApplication{AuthType: input.SaaSApp.AuthType, ClientID: "saas-client-id", PublicKey: input.SaaSApp.PublicKey, RedirectURIs: input.SaaSApp.RedirectURIs, Scopes: input.SaaSApp.Scopes}
	}
	return application
}

// standaloneCloudflareError builds a Cloudflare API error whose Error() is safe
// to call: apierror.Error.Error dereferences Request and Response.
func standaloneCloudflareError(statusCode int) error {
	return &cloudflaresdk.Error{
		StatusCode: statusCode,
		Request:    httptest.NewRequest(http.MethodGet, "https://api.cloudflare.test/client/v4", nil),
		Response:   &http.Response{StatusCode: statusCode},
	}
}
