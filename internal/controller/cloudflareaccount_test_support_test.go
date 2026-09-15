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
	"sync"
	"time"

	gomega "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var testAccountCloudflare = newFakeAccountCloudflareFactory()

type fakeAccountCloudflareFactory struct {
	mu sync.Mutex

	verification flarecloudflare.TokenVerification
	zones        []flarecloudflare.Zone
	organization flarecloudflare.Organization
	verifyErr    error
	zonesErr     error
	orgErr       error
	tokens       []string
	accountIDs   []string
}

func newFakeAccountCloudflareFactory() *fakeAccountCloudflareFactory {
	factory := new(fakeAccountCloudflareFactory)
	factory.reset()
	return factory
}

func (factory *fakeAccountCloudflareFactory) reset() {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	factory.verification = flarecloudflare.TokenVerification{ID: "test-token", Status: "active"}
	factory.zones = nil
	factory.organization = flarecloudflare.Organization{Name: "Test Account", AuthDomain: "test.cloudflareaccess.com"}
	factory.verifyErr = nil
	factory.zonesErr = nil
	factory.orgErr = nil
	factory.tokens = nil
	factory.accountIDs = nil
}

func waitForCloudflareAccountReady(ctx context.Context, name string) {
	gomega.Eventually(func(g gomega.Gomega) {
		account := new(flarewayv1alpha1.CloudflareAccount)
		g.Expect(testAPIReader.Get(ctx, types.NamespacedName{Name: name}, account)).To(gomega.Succeed())
		g.Expect(statusutil.ConditionTrue(account.Status.Conditions, flarewayv1alpha1.CloudflareAccountConditionAccepted)).To(gomega.BeTrue())
		g.Expect(statusutil.ConditionTrue(account.Status.Conditions, flarewayv1alpha1.CloudflareAccountConditionCredentialsValid)).To(gomega.BeTrue())
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func (factory *fakeAccountCloudflareFactory) AccountClient(token, accountID string) flarecloudflare.AccountAPI {
	factory.mu.Lock()
	factory.tokens = append(factory.tokens, token)
	factory.accountIDs = append(factory.accountIDs, accountID)
	factory.mu.Unlock()
	return (*fakeAccountCloudflareClient)(factory)
}

type fakeAccountCloudflareClient fakeAccountCloudflareFactory

func (client *fakeAccountCloudflareClient) VerifyToken(context.Context) (flarecloudflare.TokenVerification, error) {
	factory := (*fakeAccountCloudflareFactory)(client)
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.verification, factory.verifyErr
}

func (client *fakeAccountCloudflareClient) ListZones(context.Context) ([]flarecloudflare.Zone, error) {
	factory := (*fakeAccountCloudflareFactory)(client)
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return append([]flarecloudflare.Zone(nil), factory.zones...), factory.zonesErr
}

func (client *fakeAccountCloudflareClient) GetOrganization(context.Context) (flarecloudflare.Organization, error) {
	factory := (*fakeAccountCloudflareFactory)(client)
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.organization, factory.orgErr
}
