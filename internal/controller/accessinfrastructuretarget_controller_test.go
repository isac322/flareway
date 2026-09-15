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
	"sync"
	"sync/atomic"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

var infrastructureTargetTestCounter atomic.Int64

var _ = ginkgo.Describe("AccessInfrastructureTarget Controller", func() {
	ginkgo.It("creates, updates, adopts, observes, and safely bulk-deletes one owned target", func() {
		fixture := newInfrastructureTargetFixture()
		fixture.createPrerequisites()

		managed := fixture.target("managed", "managed.example.test")
		managed.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
		gomega.Expect(testClient.Create(testContext, managed)).To(gomega.Succeed())
		fixture.reconcileTwice(managed)
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(managed), managed)).To(gomega.Succeed())
		gomega.Expect(managed.Status.TargetID).NotTo(gomega.BeEmpty())
		gomega.Expect(managed.Status.OwnershipVerified).To(gomega.BeTrue())
		gomega.Expect(managed.Status.IP.IPV4.VirtualNetworkID).To(gomega.Equal("vnet-managed"))
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))
		fixture.reconcile(managed)
		gomega.Expect(fixture.remote.creates).To(gomega.Equal(1))
		gomega.Expect(fixture.remote.updates).To(gomega.Equal(0))

		base := client.MergeFrom(managed.DeepCopy())
		managed.Spec.Hostname = "updated.example.test"
		gomega.Expect(testClient.Patch(testContext, managed, base)).To(gomega.Succeed())
		fixture.reconcile(managed)
		gomega.Expect(fixture.remote.updates).To(gomega.Equal(1))
		gomega.Expect(fixture.remote.target(managed.Status.TargetID).Hostname).To(gomega.Equal("updated.example.test"))

		adoptedRemote := fixture.remote.put(flarecloudflare.AccessInfrastructureTarget{ID: "adopted-target", Hostname: "adopted.example.test", IPV4: &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: "192.0.2.20", VirtualNetworkID: "vnet-managed"}})
		adopted := fixture.target("adopted", adoptedRemote.Hostname)
		adopted.Spec.IP.IPV4.IPAddr = adoptedRemote.IPV4.IPAddr
		adopted.Spec.ExternalRef = &v1alpha1.AccessInfrastructureTargetExternalReference{TargetID: adoptedRemote.ID}
		adopted.Spec.Adoption = v1alpha1.AccessInfrastructureTargetAdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AccessInfrastructureTargetAdoptionExpect{Hostname: adoptedRemote.Hostname}}
		gomega.Expect(testClient.Create(testContext, adopted)).To(gomega.Succeed())
		fixture.reconcileTwice(adopted)
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(adopted), adopted)).To(gomega.Succeed())
		gomega.Expect(adopted.Status.TargetID).To(gomega.Equal(adoptedRemote.ID))
		gomega.Expect(adopted.Status.OwnershipVerified).To(gomega.BeTrue())

		observedRemote := fixture.remote.put(flarecloudflare.AccessInfrastructureTarget{ID: "observed-target", Hostname: "observed.example.test", IPV4: &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: "192.0.2.30", VirtualNetworkID: "vnet-managed"}})
		observed := fixture.target("observed", observedRemote.Hostname)
		observed.Spec.IP.IPV4.IPAddr = observedRemote.IPV4.IPAddr
		observed.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		observed.Spec.ExternalRef = &v1alpha1.AccessInfrastructureTargetExternalReference{TargetID: observedRemote.ID}
		gomega.Expect(testClient.Create(testContext, observed)).To(gomega.Succeed())
		mutations := fixture.remote.mutations()
		fixture.reconcileTwice(observed)
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(observed), observed)).To(gomega.Succeed())
		gomega.Expect(observed.Status.TargetID).To(gomega.Equal(observedRemote.ID))
		gomega.Expect(observed.Status.OwnershipVerified).To(gomega.BeFalse())
		gomega.Expect(observed.Status.WouldApply).To(gomega.BeNil())
		gomega.Expect(observed.Finalizers).To(gomega.ContainElement(v1alpha1.AccessInfrastructureTargetFinalizer))
		gomega.Expect(fixture.remote.has(observedRemote.ID)).To(gomega.BeTrue())
		gomega.Expect(fixture.remote.mutations()).To(gomega.Equal(mutations))

		managedID := managed.Status.TargetID
		gomega.Expect(testClient.Delete(testContext, managed)).To(gomega.Succeed())
		fixture.reconcile(managed)
		gomega.Expect(fixture.remote.has(managedID)).To(gomega.BeFalse())
		gomega.Expect(fixture.remote.deletes).To(gomega.BeEmpty())
		gomega.Expect(fixture.remote.bulkDeletes).To(gomega.Equal([][]string{{managedID}}))
	})

	ginkgo.It("reports ObserveOnly drift without mutating the target", func() {
		fixture := newInfrastructureTargetFixture()
		fixture.createPrerequisites()
		remote := fixture.remote.put(flarecloudflare.AccessInfrastructureTarget{ID: "drifted-target", Hostname: "remote.example.test", IPV4: &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: "192.0.2.40", VirtualNetworkID: "vnet-managed"}})
		object := fixture.target("drifted", "desired.example.test")
		object.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		object.Spec.ExternalRef = &v1alpha1.AccessInfrastructureTargetExternalReference{TargetID: remote.ID}
		gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
		fixture.reconcileTwice(object)
		fixture.reconcile(object)
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(object), object)).To(gomega.Succeed())
		condition := statusutil.FindCondition(object.Status.Conditions, "Ready")
		gomega.Expect(condition).NotTo(gomega.BeNil())
		gomega.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(condition.Reason).To(gomega.Equal("Drifted"))
		gomega.Expect(object.Status.WouldApply).NotTo(gomega.BeNil())
		gomega.Expect(object.Status.WouldApply.Hostname).To(gomega.Equal("desired.example.test"))
		gomega.Expect(object.Status.WouldApply.IP.IPV4.IPAddr).To(gomega.Equal("192.0.2.10"))
		gomega.Expect(object.Finalizers).To(gomega.ContainElement(v1alpha1.AccessInfrastructureTargetFinalizer))
		gomega.Expect(fixture.remote.target(remote.ID)).To(gomega.Equal(remote))
		gomega.Expect(fixture.remote.mutations()).To(gomega.Equal(0))
	})
})

type infrastructureTargetFixture struct {
	namespace   string
	accountName string
	accountID   string
	remote      *fakeInfrastructureTargetCloudflare
	reconciler  *AccessInfrastructureTargetReconciler
}

func newInfrastructureTargetFixture() *infrastructureTargetFixture {
	suffix := infrastructureTargetTestCounter.Add(1)
	remote := &fakeInfrastructureTargetCloudflare{targets: map[string]flarecloudflare.AccessInfrastructureTarget{}}
	fixture := &infrastructureTargetFixture{
		namespace:   fmt.Sprintf("infrastructure-target-%d", suffix),
		accountName: fmt.Sprintf("infrastructure-target-account-%d", suffix),
		accountID:   fmt.Sprintf("%032x", suffix),
		remote:      remote,
	}
	fixture.reconciler = &AccessInfrastructureTargetReconciler{
		Client:    testClient,
		APIReader: testAPIReader,
		Scheme:    testClient.Scheme(),
		NewCloudflareClient: func(token, accountID string) (flarecloudflare.AccessAPI, error) {
			gomega.Expect(token).To(gomega.Equal("api-token"))
			gomega.Expect(accountID).To(gomega.Equal(fixture.accountID))
			return remote, nil
		},
	}
	return fixture
}

func (f *infrastructureTargetFixture) createPrerequisites() {
	testAccountCloudflare.reset()
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.namespace, Labels: map[string]string{"infrastructure-target": f.namespace}}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeleteInfrastructureTargetNamespace, f.namespace)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: f.namespace}, Data: map[string][]byte{"token": []byte("api-token")}}
	gomega.Expect(testClient.Create(testContext, secret)).To(gomega.Succeed())
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: f.accountName}, Spec: v1alpha1.CloudflareAccountSpec{
		AccountID:   f.accountID,
		Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: secret.Name, Namespace: secret.Namespace, Key: "token"}},
		Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"infrastructure-target": f.namespace}}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate}, PlatformObjects: v1alpha1.GrantPermissionAllowed}},
	}}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	waitForCloudflareAccountReady(testContext, f.accountName)
}

func (f *infrastructureTargetFixture) target(name, hostname string) *v1alpha1.AccessInfrastructureTarget {
	return &v1alpha1.AccessInfrastructureTarget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.namespace}, Spec: v1alpha1.AccessInfrastructureTargetSpec{
		AccountRef: corev1.LocalObjectReference{Name: f.accountName}, Hostname: hostname,
		IP: v1alpha1.AccessInfrastructureTargetIP{IPV4: &v1alpha1.AccessInfrastructureTargetIPv4Address{IPAddr: "192.0.2.10", VirtualNetworkID: "vnet-managed"}},
	}}
}

func (f *infrastructureTargetFixture) reconcile(object client.Object) {
	_, err := f.reconciler.Reconcile(testContext, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(object)})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}
func (f *infrastructureTargetFixture) reconcileTwice(object client.Object) {
	f.reconcile(object)
	f.reconcile(object)
}

func forceDeleteInfrastructureTargetNamespace(namespace string) {
	var targets v1alpha1.AccessInfrastructureTargetList
	if err := testAPIReader.List(testContext, &targets, client.InNamespace(namespace)); err == nil {
		for i := range targets.Items {
			if len(targets.Items[i].Finalizers) == 0 {
				continue
			}
			base := client.MergeFrom(targets.Items[i].DeepCopy())
			targets.Items[i].Finalizers = nil
			_ = testClient.Patch(testContext, &targets.Items[i], base)
		}
	}
	forceDeleteAccessNamespace(namespace)
}

type fakeInfrastructureTargetCloudflare struct {
	flarecloudflare.AccessAPI
	mu          sync.Mutex
	targets     map[string]flarecloudflare.AccessInfrastructureTarget
	creates     int
	updates     int
	deletes     []string
	bulkDeletes [][]string
}

func (f *fakeInfrastructureTargetCloudflare) CreateAccessInfrastructureTarget(_ context.Context, input flarecloudflare.AccessInfrastructureTargetInput) (flarecloudflare.AccessInfrastructureTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	target := fakeInfrastructureTarget(fmt.Sprintf("target-%d", f.creates), input)
	f.targets[target.ID] = target
	return target, nil
}
func (f *fakeInfrastructureTargetCloudflare) UpdateAccessInfrastructureTarget(_ context.Context, id string, input flarecloudflare.AccessInfrastructureTargetInput) (flarecloudflare.AccessInfrastructureTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	target := fakeInfrastructureTarget(id, input)
	f.targets[id] = target
	return target, nil
}
func (f *fakeInfrastructureTargetCloudflare) GetAccessInfrastructureTarget(_ context.Context, id string) (flarecloudflare.AccessInfrastructureTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	target, ok := f.targets[id]
	if !ok {
		return target, fmt.Errorf("not found")
	}
	return target, nil
}
func (f *fakeInfrastructureTargetCloudflare) ListAccessInfrastructureTargets(context.Context) ([]flarecloudflare.AccessInfrastructureTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]flarecloudflare.AccessInfrastructureTarget, 0, len(f.targets))
	for _, target := range f.targets {
		result = append(result, target)
	}
	return result, nil
}
func (f *fakeInfrastructureTargetCloudflare) DeleteAccessInfrastructureTarget(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, id)
	delete(f.targets, id)
	return nil
}
func (f *fakeInfrastructureTargetCloudflare) BulkDeleteAccessInfrastructureTargets(_ context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := append([]string(nil), ids...)
	f.bulkDeletes = append(f.bulkDeletes, copied)
	for _, id := range ids {
		delete(f.targets, id)
	}
	return nil
}
func (f *fakeInfrastructureTargetCloudflare) put(target flarecloudflare.AccessInfrastructureTarget) flarecloudflare.AccessInfrastructureTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets[target.ID] = target
	return target
}
func (f *fakeInfrastructureTargetCloudflare) target(id string) flarecloudflare.AccessInfrastructureTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.targets[id]
}
func (f *fakeInfrastructureTargetCloudflare) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.targets[id]
	return ok
}
func (f *fakeInfrastructureTargetCloudflare) mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates + f.updates + len(f.deletes) + len(f.bulkDeletes)
}

func fakeInfrastructureTarget(id string, input flarecloudflare.AccessInfrastructureTargetInput) flarecloudflare.AccessInfrastructureTarget {
	return flarecloudflare.AccessInfrastructureTarget{ID: id, Hostname: input.Hostname, IPV4: input.IPV4, IPV6: input.IPV6}
}
