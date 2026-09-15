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

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var _ = ginkgo.Describe("DevicePostureIntegration Controller", func() {
	ginkgo.It("creates and deletes a managed integration", func() {
		const (
			namespaceName         = "device-posture-integration-test"
			accountName           = "device-posture-integration-account"
			accountID             = "0123456789abcdef0123456789abcdef"
			integrationName       = "managed-integration"
			accountSecretName     = "cloudflare-token"
			integrationSecretName = "integration-credentials"
		)

		testAccountCloudflare.reset()

		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   namespaceName,
			Labels: map[string]string{"device-posture-integration": "true"},
		}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(cleanupDevicePostureIntegrationFixture, namespaceName, accountName)

		accountSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: accountSecretName, Namespace: namespaceName},
			Data:       map[string][]byte{"token": []byte("api-token")},
		}
		gomega.Expect(testClient.Create(testContext, accountSecret)).To(gomega.Succeed())
		integrationSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: integrationSecretName, Namespace: namespaceName},
			Data:       map[string][]byte{"client-secret": []byte("kolide-client-secret")},
		}
		gomega.Expect(testClient.Create(testContext, integrationSecret)).To(gomega.Succeed())

		account := &flarewayv1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: accountName},
			Spec: flarewayv1alpha1.CloudflareAccountSpec{
				AccountID: accountID,
				Credentials: flarewayv1alpha1.CloudflareAccountCredentials{
					APITokenSecretRef: flarewayv1alpha1.NamespacedSecretKeyReference{
						Name: accountSecretName, Namespace: namespaceName, Key: "token",
					},
				},
				Grants: []flarewayv1alpha1.CloudflareAccountGrant{{
					NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"device-posture-integration": "true"}},
					Hostnames:         []string{"*"},
					Zones:             []string{"*"},
					Exposures:         []flarewayv1alpha1.Exposure{flarewayv1alpha1.ExposurePrivate},
					PlatformObjects:   flarewayv1alpha1.GrantPermissionAllowed,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
		waitForCloudflareAccountReady(testContext, accountName)

		integration := &flarewayv1alpha1.DevicePostureIntegration{
			ObjectMeta: metav1.ObjectMeta{Name: integrationName, Namespace: namespaceName},
			Spec: flarewayv1alpha1.DevicePostureIntegrationSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Type:       flarewayv1alpha1.DevicePostureIntegrationTypeKolide,
				Name:       "Managed Kolide",
				Interval:   "1h",
				Config: flarewayv1alpha1.DevicePostureIntegrationConfig{
					ClientID: "kolide-client-id",
					ClientSecretRef: &flarewayv1alpha1.DevicePostureIntegrationSecretReference{
						Name: integrationSecretName,
						Key:  "client-secret",
					},
				},
				DeletionPolicy: flarewayv1alpha1.DeletionPolicyDelete,
			},
		}
		gomega.Expect(testClient.Create(testContext, integration)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			return testClient.Get(testContext, client.ObjectKeyFromObject(integration), new(flarewayv1alpha1.DevicePostureIntegration))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		remote := &fakeDevicePostureIntegrationCloudflare{
			integrations: map[string]flarecloudflare.DevicePostureIntegration{},
		}
		reconciler := &DevicePostureIntegrationReconciler{
			Client: testClient,
			Scheme: testClient.Scheme(),
			NewCloudflareClient: func(token, accountID string) (flarecloudflare.AccessAPI, error) {
				gomega.Expect(token).To(gomega.Equal("api-token"))
				gomega.Expect(accountID).To(gomega.Equal(account.Spec.AccountID))
				return remote, nil
			},
		}
		request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(integration)}

		_, err := reconciler.Reconcile(testContext, request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		current := new(flarewayv1alpha1.DevicePostureIntegration)
		gomega.Expect(testAPIReader.Get(testContext, request.NamespacedName, current)).To(gomega.Succeed())
		gomega.Expect(current.Finalizers).To(gomega.ContainElement(flarewayv1alpha1.DevicePostureIntegrationFinalizer))

		gomega.Eventually(func(g gomega.Gomega) {
			_, reconcileErr := reconciler.Reconcile(testContext, request)
			g.Expect(reconcileErr).NotTo(gomega.HaveOccurred())
			current = new(flarewayv1alpha1.DevicePostureIntegration)
			g.Expect(testAPIReader.Get(testContext, request.NamespacedName, current)).To(gomega.Succeed())
			g.Expect(current.Status.IntegrationID).To(gomega.Equal("integration-1"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.Observed).NotTo(gomega.BeNil())
			g.Expect(current.Status.Observed.Config.ClientID).To(gomega.Equal("kolide-client-id"))
			ready := statusutil.FindCondition(current.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(ready.Reason).To(gomega.Equal("Ready"))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(remote.creates).To(gomega.Equal(1))
		gomega.Expect(remote.lastInput.Type).To(gomega.Equal(flarewayv1alpha1.DevicePostureIntegrationTypeKolide))
		gomega.Expect(remote.lastInput.Interval).To(gomega.Equal("1h"))
		gomega.Expect(remote.lastInput.Config.ClientID).To(gomega.Equal("kolide-client-id"))
		gomega.Expect(remote.lastInput.ClientSecret).To(gomega.Equal("kolide-client-secret"))

		_, err = reconciler.Reconcile(testContext, request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.creates).To(gomega.Equal(1))
		gomega.Expect(remote.updates).To(gomega.BeZero())

		gomega.Expect(testClient.Delete(testContext, current)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			_, reconcileErr := reconciler.Reconcile(testContext, request)
			g.Expect(reconcileErr).NotTo(gomega.HaveOccurred())
			g.Expect(remote.integrations).NotTo(gomega.HaveKey("integration-1"))
			g.Expect(remote.deletes).To(gomega.Equal([]string{"integration-1"}))
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func() bool {
			err = testClient.Get(testContext, request.NamespacedName, new(flarewayv1alpha1.DevicePostureIntegration))
			return apierrors.IsNotFound(err)
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
	})
})

func cleanupDevicePostureIntegrationFixture(namespaceName, accountName string) {
	ctx := context.Background()
	var integrations flarewayv1alpha1.DevicePostureIntegrationList
	if err := testClient.List(ctx, &integrations, client.InNamespace(namespaceName)); err == nil {
		for i := range integrations.Items {
			if len(integrations.Items[i].Finalizers) == 0 {
				continue
			}
			before := integrations.Items[i].DeepCopy()
			integrations.Items[i].Finalizers = nil
			_ = testClient.Patch(ctx, &integrations.Items[i], client.MergeFrom(before))
		}
	}
	_ = testClient.Delete(ctx, &flarewayv1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: accountName}})
	_ = testClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})
}

type fakeDevicePostureIntegrationCloudflare struct {
	flarecloudflare.AccessAPI
	integrations map[string]flarecloudflare.DevicePostureIntegration
	creates      int
	updates      int
	deletes      []string
	lastInput    flarecloudflare.DevicePostureIntegrationInput
}

func (f *fakeDevicePostureIntegrationCloudflare) CreateDevicePostureIntegration(_ context.Context, input flarecloudflare.DevicePostureIntegrationInput) (flarecloudflare.DevicePostureIntegration, error) {
	f.creates++
	f.lastInput = input
	integration := fakeDevicePostureIntegration(fmt.Sprintf("integration-%d", f.creates), input)
	f.integrations[integration.ID] = integration
	return integration, nil
}

func (f *fakeDevicePostureIntegrationCloudflare) UpdateDevicePostureIntegration(_ context.Context, id string, input flarecloudflare.DevicePostureIntegrationInput) (flarecloudflare.DevicePostureIntegration, error) {
	f.updates++
	f.lastInput = input
	integration := fakeDevicePostureIntegration(id, input)
	f.integrations[id] = integration
	return integration, nil
}

func (f *fakeDevicePostureIntegrationCloudflare) GetDevicePostureIntegration(_ context.Context, id string) (flarecloudflare.DevicePostureIntegration, error) {
	integration, ok := f.integrations[id]
	if !ok {
		return integration, fmt.Errorf("device posture integration %q not found", id)
	}
	return integration, nil
}

func (f *fakeDevicePostureIntegrationCloudflare) ListDevicePostureIntegrations(context.Context) ([]flarecloudflare.DevicePostureIntegration, error) {
	integrations := make([]flarecloudflare.DevicePostureIntegration, 0, len(f.integrations))
	for _, integration := range f.integrations {
		integrations = append(integrations, integration)
	}
	return integrations, nil
}

func (f *fakeDevicePostureIntegrationCloudflare) DeleteDevicePostureIntegration(_ context.Context, id string) error {
	delete(f.integrations, id)
	f.deletes = append(f.deletes, id)
	return nil
}

func fakeDevicePostureIntegration(id string, input flarecloudflare.DevicePostureIntegrationInput) flarecloudflare.DevicePostureIntegration {
	return flarecloudflare.DevicePostureIntegration{
		ID:       id,
		Name:     input.Name,
		Type:     input.Type,
		Interval: input.Interval,
		Config: flarewayv1alpha1.DevicePostureIntegrationObservedConfig{
			APIURL:     input.Config.APIURL,
			AuthURL:    input.Config.AuthURL,
			ClientID:   input.Config.ClientID,
			CustomerID: input.Config.CustomerID,
		},
	}
}
