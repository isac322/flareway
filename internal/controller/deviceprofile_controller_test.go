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
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

func TestNormalizeSplitCandidatesDeterministic(t *testing.T) {
	cidr := "10.96.7.9/12"
	hostUpper := "APP.EXAMPLE.COM."
	hostLower := "app.example.com"
	input := []splitCandidate{
		{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Host: &hostUpper, Description: "derived"}, provenance: "HostnameRoute/zeta/route", priority: 1},
		{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Address: &cidr, Description: "network"}, provenance: "NetworkRoute/zeta/route", priority: 1},
		{entry: v1alpha1.DeviceProfileSplitTunnelEntry{Host: &hostLower, Description: "static"}, provenance: "spec.splitTunnel.static", priority: 0},
	}
	wantApplied, wantRemote, err := normalizeSplitCandidates(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, permutation := range [][]splitCandidate{
		{input[2], input[0], input[1]},
		{input[1], input[2], input[0]},
	} {
		gotApplied, gotRemote, err := normalizeSplitCandidates(permutation)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(wantApplied, gotApplied); diff != "" {
			t.Fatalf("applied aggregate depends on input order (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(wantRemote, gotRemote); diff != "" {
			t.Fatalf("remote payload depends on input order (-want +got):\n%s", diff)
		}
	}
	if len(wantApplied) != 2 || wantApplied[0].Entry.Address == nil || *wantApplied[0].Entry.Address != "10.96.0.0/12" {
		t.Fatalf("CIDR was not masked and sorted first: %#v", wantApplied)
	}
	if wantApplied[1].Entry.Host == nil || *wantApplied[1].Entry.Host != "app.example.com" || wantApplied[1].Entry.Description != "static" {
		t.Fatalf("hostname was not normalized with static description precedence: %#v", wantApplied[1])
	}
	wantProvenance := []string{"HostnameRoute/zeta/route", "spec.splitTunnel.static"}
	if diff := cmp.Diff(wantProvenance, wantApplied[1].Provenance); diff != "" {
		t.Fatalf("provenance mismatch (-want +got):\n%s", diff)
	}
}

func TestAggregateRejectsMoreThanOneThousandEntries(t *testing.T) {
	entries := make([]v1alpha1.DeviceProfileSplitTunnelEntry, deviceProfileEntryLimit+1)
	for index := range entries {
		host := fmt.Sprintf("host-%04d.example.com", index)
		entries[index].Host = &host
	}
	profile := &v1alpha1.DeviceProfile{Spec: v1alpha1.DeviceProfileSpec{SplitTunnel: v1alpha1.DeviceProfileSplitTunnel{Mode: v1alpha1.DeviceProfileSplitTunnelModeInclude, Static: entries}}}
	_, err := (&DeviceProfileReconciler{}).aggregate(context.Background(), profile, &v1alpha1.CloudflareAccount{}, &corev1.Namespace{})
	if err == nil || err.Error() != "split-tunnel aggregate has 1001 entries; maximum is 1000" {
		t.Fatalf("expected aggregate limit error, got %v", err)
	}
}

func TestNormalizeFallbackDomainsRejectsConflictingDuplicate(t *testing.T) {
	_, _, err := normalizeFallbackDomains([]v1alpha1.DeviceProfileFallbackDomain{
		{Suffix: "corp.example", DNSServer: []string{"10.0.0.1"}},
		{Suffix: "CORP.EXAMPLE.", DNSServer: []string{"10.0.0.2"}},
	})
	if err == nil || err.Error() != "fallback domain \"corp.example\" has conflicting definitions" {
		t.Fatalf("expected conflicting fallback error, got %v", err)
	}
}

func TestSyncDeviceProfileUsesSafeWholeListOrderAndExactPayload(t *testing.T) {
	fake := newFakeDeviceProfileCloudflare()
	ref := flarecloudflare.DeviceProfileRef{Kind: flarecloudflare.DeviceProfileKindDefault, ID: "default-id"}
	desired := aggregatedDeviceProfile{
		include:  []flarecloudflare.SplitTunnelEntry{{Host: "app.example.com", Description: "application"}, {Address: "10.96.0.0/12", Description: "cluster"}},
		fallback: []flarecloudflare.FallbackDomain{{Suffix: "corp.example", Description: "corporate", DNSServer: []string{"10.0.0.53"}}},
	}
	input := flarecloudflare.DeviceProfileInput{SwitchLocked: new(true), DNSSearchSuffixes: &[]flarecloudflare.DNSSearchSuffix{{Suffix: "example.com"}}}
	diff := v1alpha1.DeviceProfileWouldApplyStatus{ProfileFields: []string{"switchLocked"}, DNSSearchSuffixes: v1alpha1.DeviceProfileDNSSearchSuffixDiff{Add: []v1alpha1.DeviceProfileDNSSearchSuffix{{Suffix: "example.com"}}}}
	if err := syncDeviceProfile(context.Background(), fake, ref, v1alpha1.DeviceProfileSplitTunnelModeInclude, input,
		[]flarecloudflare.SplitTunnelEntry{{Host: "old.example.com"}}, []flarecloudflare.SplitTunnelEntry{{Address: "192.0.2.0/24"}}, []flarecloudflare.FallbackDomain{{Suffix: "old.example"}}, desired, diff); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"ReplaceExclude", "ReplaceInclude", "ReplaceFallback", "UpdateDefault"}
	if diff := cmp.Diff(wantCalls, fake.callsSnapshot()); diff != "" {
		t.Fatalf("unsafe update order (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(desired.include, fake.include[deviceProfileRefKey(ref)]); diff != "" {
		t.Fatalf("include whole-list payload mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]flarecloudflare.SplitTunnelEntry{}, fake.exclude[deviceProfileRefKey(ref)]); diff != "" {
		t.Fatalf("inactive exclude list was not cleared (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(desired.fallback, fake.fallback[deviceProfileRefKey(ref)]); diff != "" {
		t.Fatalf("fallback whole-list payload mismatch (-want +got):\n%s", diff)
	}
}

func TestResolveRemoteProfileRequiresExplicitAdoption(t *testing.T) {
	fake := newFakeDeviceProfileCloudflare()
	fake.custom["existing"] = flarecloudflare.DeviceProfile{PolicyID: "existing", Name: "corporate", Match: "identity.email == \"user@example.com\"", Precedence: 100}
	object := &v1alpha1.DeviceProfile{Spec: v1alpha1.DeviceProfileSpec{
		Profile:          v1alpha1.DeviceProfileTarget{Kind: v1alpha1.DeviceProfileKindCustom},
		ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		ExternalRef:      &v1alpha1.DeviceProfileExternalReference{ProfileID: "existing"},
		Adoption:         v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "corporate"}},
	}}
	remote, acquired, err := (&DeviceProfileReconciler{}).resolveRemoteProfile(context.Background(), fake, object, flarecloudflare.DeviceProfileInput{})
	if err != nil {
		t.Fatal(err)
	}
	if remote.PolicyID != "existing" || !acquired {
		t.Fatalf("explicit adoption did not acquire the selected profile: remote=%#v acquired=%v", remote, acquired)
	}
	object.Spec.Adoption.Expect.Name = "other"
	if _, _, err := (&DeviceProfileReconciler{}).resolveRemoteProfile(context.Background(), fake, object, flarecloudflare.DeviceProfileInput{}); err == nil || err.Error() != "remote custom profile name \"corporate\" does not match expected \"other\"" {
		t.Fatalf("expected adoption expectation conflict, got %v", err)
	}
}

var testDeviceProfileCloudflare = newFakeDeviceProfileCloudflare()

var _ = ginkgo.Describe("DeviceProfile controller", ginkgo.Ordered, func() {
	ginkgo.BeforeEach(func() {
		testDeviceProfileCloudflare.reset()
	})

	ginkgo.It("observes the exact diff without any Cloudflare mutation", func() {
		fixture := newDeviceProfileFixture("observe")
		fixture.create()
		profile := fixture.profile(v1alpha1.ManagementPolicyObserveOnly)
		profile.Spec.SplitTunnel.Static = []v1alpha1.DeviceProfileSplitTunnelEntry{{Host: new("app.example.com"), Description: "public app"}}
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(condition.Reason).To(gomega.Equal("Observed"))
			g.Expect(current.Status.ProfileID).To(gomega.Equal("default-profile"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
			g.Expect(current.Status.WouldApply).NotTo(gomega.BeNil())
			g.Expect(current.Status.WouldApply.Include.Add).To(gomega.Equal([]v1alpha1.DeviceProfileStatusSplitTunnelEntry{{Host: new("app.example.com"), Description: "public app"}}))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.mutationCount()).To(gomega.BeZero())
	})

	ginkgo.It("rejects competing Managed writers before any Cloudflare mutation", func() {
		fixture := newDeviceProfileFixture("conflict")
		fixture.create()
		first := fixture.profile(v1alpha1.ManagementPolicyManaged)
		first.Name = "first"
		second := fixture.profile(v1alpha1.ManagementPolicyManaged)
		second.Name = "second"
		gomega.Expect(testClient.Create(testContext, first)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, second)).To(gomega.Succeed())

		for _, key := range []types.NamespacedName{client.ObjectKeyFromObject(first), client.ObjectKeyFromObject(second)} {
			gomega.Eventually(func(g gomega.Gomega) {
				var current v1alpha1.DeviceProfile
				g.Expect(testClient.Get(testContext, key, &current)).To(gomega.Succeed())
				condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionAccepted)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
				g.Expect(current.Status.Conflicts).NotTo(gomega.BeEmpty())
			}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}
		gomega.Expect(testDeviceProfileCloudflare.mutationCount()).To(gomega.BeZero())
	})

	ginkgo.It("ignores a Managed contender whose namespace lacks platformObjects authorization", func() {
		fixture := newDeviceProfileFixture("denied-contender")
		fixture.create()
		deniedNamespace := fixture.namespace + "-denied"
		gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: deniedNamespace, Labels: map[string]string{"profile": "denied"}}})).To(gomega.Succeed())
		denied := fixture.profile(v1alpha1.ManagementPolicyManaged)
		denied.Name = "denied"
		denied.Namespace = deniedNamespace
		authorized := fixture.profile(v1alpha1.ManagementPolicyManaged)
		authorized.Name = "authorized"
		gomega.Expect(testClient.Create(testContext, denied)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, authorized)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(authorized), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.Conflicts).To(gomega.BeEmpty())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("detects competing writers through CloudflareAccount aliases with the same accountId", func() {
		fixture := newDeviceProfileFixture("account-alias")
		fixture.create()
		aliasName := fixture.accountName + "-alias"
		createReadyDeviceProfileAccount(aliasName, fixture.namespace, fixture.secretName, fixture.accountID, map[string]string{"profile": fixture.name})
		first := fixture.profile(v1alpha1.ManagementPolicyManaged)
		first.Name = "primary"
		second := fixture.profile(v1alpha1.ManagementPolicyManaged)
		second.Name = "alias"
		second.Spec.AccountRef.Name = aliasName
		gomega.Expect(testClient.Create(testContext, first)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, second)).To(gomega.Succeed())

		for _, key := range []types.NamespacedName{client.ObjectKeyFromObject(first), client.ObjectKeyFromObject(second)} {
			gomega.Eventually(func(g gomega.Gomega) {
				var current v1alpha1.DeviceProfile
				g.Expect(testClient.Get(testContext, key, &current)).To(gomega.Succeed())
				condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionAccepted)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.Reason).To(gomega.Equal("Conflict"))
			}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		}
		gomega.Expect(testDeviceProfileCloudflare.mutationCount()).To(gomega.BeZero())
	})

	ginkgo.It("explicitly adopts after ObserveOnly without rejecting the unowned observed ID", func() {
		fixture := newDeviceProfileFixture("observe-adopt")
		fixture.create()
		remote := flarecloudflare.DeviceProfile{PolicyID: "observed-custom", Name: "profile-" + fixture.name, Match: "identity.email == \"user@example.com\"", Precedence: 100, Enabled: true}
		testDeviceProfileCloudflare.addCustom(remote)
		profile := fixture.customProfile(v1alpha1.DeletionPolicyOrphan)
		profile.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		profile.Spec.ExternalRef = &v1alpha1.DeviceProfileExternalReference{ProfileID: remote.PolicyID}
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("Observed"))
			g.Expect(current.Status.ProfileID).To(gomega.Equal(remote.PolicyID))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		var current v1alpha1.DeviceProfile
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
		current.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		current.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: remote.Name}}
		gomega.Expect(testClient.Update(testContext, &current)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var adopted v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &adopted)).To(gomega.Succeed())
			condition := statusutil.FindCondition(adopted.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(condition.Reason).To(gomega.Equal("Ready"))
			g.Expect(adopted.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.callCount("CreateCustom")).To(gomega.Equal(0))
	})

	ginkgo.It("preserves ownership across Managed to ObserveOnly to Managed transitions", func() {
		fixture := newDeviceProfileFixture("managed-observe-managed")
		fixture.create()
		profile := fixture.customProfile(v1alpha1.DeletionPolicyOrphan)
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.callCount("CreateCustom")).To(gomega.Equal(1))

		var observed v1alpha1.DeviceProfile
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &observed)).To(gomega.Succeed())
		observed.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		gomega.Expect(testClient.Update(testContext, &observed)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Reason).To(gomega.Equal("Observed"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		var managed v1alpha1.DeviceProfile
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &managed)).To(gomega.Succeed())
		managed.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		gomega.Expect(testClient.Update(testContext, &managed)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(condition.Reason).To(gomega.Equal("Ready"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.callCount("CreateCustom")).To(gomega.Equal(1))
	})

	ginkgo.It("orphans an owned custom profile instead of deleting it", func() {
		fixture := newDeviceProfileFixture("orphan")
		fixture.create()
		profile := fixture.customProfile(v1alpha1.DeletionPolicyOrphan)
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		var profileID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.ProfileID).NotTo(gomega.BeEmpty())
			profileID = current.Status.ProfileID
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, profile)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(profile), new(v1alpha1.DeviceProfile)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testDeviceProfileCloudflare.hasCustom(profileID)).To(gomega.BeTrue())
		gomega.Expect(testDeviceProfileCloudflare.callsSnapshot()).NotTo(gomega.ContainElement("DeleteCustom"))
	})

	ginkgo.It("deletes only an owned custom profile with deletionPolicy Delete", func() {
		fixture := newDeviceProfileFixture("delete")
		fixture.create()
		profile := fixture.customProfile(v1alpha1.DeletionPolicyDelete)
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		var profileID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			profileID = current.Status.ProfileID
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, profile)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(profile), new(v1alpha1.DeviceProfile)))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testDeviceProfileCloudflare.hasCustom(profileID)).To(gomega.BeFalse())
		gomega.Expect(testDeviceProfileCloudflare.callsSnapshot()).To(gomega.ContainElement("DeleteCustom"))
	})

	ginkgo.It("retains the last applied lists when dependency resolution fails", func() {
		fixture := newDeviceProfileFixture("dependency-loss")
		fixture.create()
		profile := fixture.profile(v1alpha1.ManagementPolicyManaged)
		profile.Spec.SplitTunnel.Static = []v1alpha1.DeviceProfileSplitTunnelEntry{{Host: new("app.example.com"), Description: "public app"}}
		profile.Spec.FallbackDomains.Static = []v1alpha1.DeviceProfileFallbackDomain{{Suffix: "corp.example", DNSServer: []string{"10.0.0.53"}}}
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		var appliedInclude []v1alpha1.DeviceProfileAppliedSplitTunnelEntry
		var appliedFallback []v1alpha1.DeviceProfileAppliedFallbackDomain
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.AppliedInclude).NotTo(gomega.BeEmpty())
			g.Expect(current.Status.AppliedFallback).NotTo(gomega.BeEmpty())
			appliedInclude = current.Status.AppliedInclude
			appliedFallback = current.Status.AppliedFallback
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		var current v1alpha1.DeviceProfile
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
		current.Spec.Profile.Fields = &v1alpha1.DeviceProfileFields{VirtualNetworks: &v1alpha1.DeviceProfileVirtualNetworks{
			DefaultRef:  corev1.LocalObjectReference{Name: "missing-vnet"},
			AllowedRefs: []corev1.LocalObjectReference{{Name: "missing-vnet"}},
		}}
		gomega.Expect(testClient.Update(testContext, &current)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var failed v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &failed)).To(gomega.Succeed())
			for _, conditionType := range []string{v1alpha1.DeviceProfileConditionAccepted, v1alpha1.DeviceProfileConditionReady} {
				condition := statusutil.FindCondition(failed.Status.Conditions, conditionType)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(failed.Generation))
			}
			g.Expect(failed.Status.AppliedInclude).To(gomega.Equal(appliedInclude))
			g.Expect(failed.Status.AppliedFallback).To(gomega.Equal(appliedFallback))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("retains the last applied lists when remote synchronization fails", func() {
		fixture := newDeviceProfileFixture("sync-loss")
		fixture.create()
		profile := fixture.profile(v1alpha1.ManagementPolicyManaged)
		profile.Spec.SplitTunnel.Static = []v1alpha1.DeviceProfileSplitTunnelEntry{{Host: new("app.example.com"), Description: "public app"}}
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		var appliedInclude []v1alpha1.DeviceProfileAppliedSplitTunnelEntry
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			condition := statusutil.FindCondition(current.Status.Conditions, v1alpha1.DeviceProfileConditionReady)
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.AppliedInclude).NotTo(gomega.BeEmpty())
			appliedInclude = current.Status.AppliedInclude
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		testDeviceProfileCloudflare.fail("ReplaceInclude", errors.New("injected replace failure"))
		var current v1alpha1.DeviceProfile
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
		current.Spec.SplitTunnel.Static = append(current.Spec.SplitTunnel.Static, v1alpha1.DeviceProfileSplitTunnelEntry{Host: new("extra.example.com")})
		gomega.Expect(testClient.Update(testContext, &current)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var failed v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &failed)).To(gomega.Succeed())
			for _, conditionType := range []string{v1alpha1.DeviceProfileConditionAccepted, v1alpha1.DeviceProfileConditionReady} {
				condition := statusutil.FindCondition(failed.Status.Conditions, conditionType)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(failed.Generation))
			}
			g.Expect(failed.Status.AppliedInclude).To(gomega.Equal(appliedInclude))
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.includeSnapshot(flarecloudflare.DeviceProfileRef{Kind: flarecloudflare.DeviceProfileKindDefault, ID: "default-profile"})).To(gomega.Equal([]flarecloudflare.SplitTunnelEntry{{Host: "app.example.com", Description: "public app"}}))
	})
	ginkgo.It("keeps desired lists out of status when the first custom sync fails after acquisition", func() {
		fixture := newDeviceProfileFixture("first-sync-loss")
		fixture.create()
		testDeviceProfileCloudflare.fail("GetInclude", errors.New("injected include read failure"))
		profile := fixture.customProfile(v1alpha1.DeletionPolicyOrphan)
		profile.Spec.SplitTunnel.Static = []v1alpha1.DeviceProfileSplitTunnelEntry{{Host: new("app.example.com"), Description: "public app"}}
		profile.Spec.FallbackDomains.Static = []v1alpha1.DeviceProfileFallbackDomain{{Suffix: "corp.example", DNSServer: []string{"10.0.0.53"}}}
		gomega.Expect(testClient.Create(testContext, profile)).To(gomega.Succeed())

		var profileID string
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.DeviceProfile
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(profile), &current)).To(gomega.Succeed())
			for _, conditionType := range []string{v1alpha1.DeviceProfileConditionAccepted, v1alpha1.DeviceProfileConditionReady} {
				condition := statusutil.FindCondition(current.Status.Conditions, conditionType)
				g.Expect(condition).NotTo(gomega.BeNil())
				g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
				g.Expect(condition.ObservedGeneration).To(gomega.Equal(current.Generation))
			}
			g.Expect(current.Status.ProfileID).NotTo(gomega.BeEmpty())
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.AppliedInclude).To(gomega.BeEmpty())
			g.Expect(current.Status.AppliedExclude).To(gomega.BeEmpty())
			g.Expect(current.Status.AppliedFallback).To(gomega.BeEmpty())
			profileID = current.Status.ProfileID
		}).WithTimeout(15 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testDeviceProfileCloudflare.callCount("CreateCustom")).To(gomega.Equal(1))
		// The injected read failure must leave the acquired profile unconverged: no
		// successful list replacement may have landed under this profile's ref.
		ref := flarecloudflare.DeviceProfileRef{Kind: flarecloudflare.DeviceProfileKindCustom, ID: profileID}
		gomega.Expect(testDeviceProfileCloudflare.includeSnapshot(ref)).To(gomega.BeEmpty())
		gomega.Expect(testDeviceProfileCloudflare.fallbackSnapshot(ref)).To(gomega.BeEmpty())
	})
})

type deviceProfileFixture struct {
	name        string
	namespace   string
	accountName string
	accountID   string
	secretName  string
}

func newDeviceProfileFixture(name string) deviceProfileFixture {
	sum := sha256.Sum256([]byte(name))
	return deviceProfileFixture{name: name, namespace: "device-profile-" + name, accountName: "device-profile-" + name, accountID: fmt.Sprintf("%x", sum[:16]), secretName: "device-profile-token-" + name}
}

func (f deviceProfileFixture) create() {
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: f.namespace, Labels: map[string]string{"profile": f.name}}})).To(gomega.Succeed())
	testAccountCloudflare.reset()
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: f.secretName, Namespace: f.namespace}, Data: map[string][]byte{"token": []byte("profile-token")}})).To(gomega.Succeed())
	createReadyDeviceProfileAccount(f.accountName, f.namespace, f.secretName, f.accountID, map[string]string{"profile": f.name})
	testDeviceProfileCloudflare.defaultProfile = flarecloudflare.DeviceProfile{PolicyID: "default-profile", Default: true}
}

func createReadyDeviceProfileAccount(name, secretNamespace, secretName, accountID string, namespaceLabels map[string]string) {
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: secretName, Namespace: secretNamespace, Key: "token"}},
			Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: namespaceLabels}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}, PlatformObjects: v1alpha1.GrantPermissionAllowed}},
		},
	}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	gomega.Eventually(func() error {
		var current v1alpha1.CloudflareAccount
		if err := testClient.Get(testContext, client.ObjectKeyFromObject(account), &current); err != nil {
			return err
		}
		before := current.DeepCopy()
		current.Status.Conditions = []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()},
		}
		return testClient.Status().Patch(testContext, &current, client.MergeFrom(before))
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
}

func (f deviceProfileFixture) profile(policy v1alpha1.ManagementPolicy) *v1alpha1.DeviceProfile {
	return &v1alpha1.DeviceProfile{
		ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: f.namespace},
		Spec: v1alpha1.DeviceProfileSpec{
			AccountRef:       corev1.LocalObjectReference{Name: f.accountName},
			Profile:          v1alpha1.DeviceProfileTarget{Kind: v1alpha1.DeviceProfileKindDefault},
			SplitTunnel:      v1alpha1.DeviceProfileSplitTunnel{Mode: v1alpha1.DeviceProfileSplitTunnelModeInclude},
			ManagementPolicy: policy,
			DeletionPolicy:   v1alpha1.DeletionPolicyOrphan,
		},
	}
}

func (f deviceProfileFixture) customProfile(deletionPolicy v1alpha1.DeletionPolicy) *v1alpha1.DeviceProfile {
	profile := f.profile(v1alpha1.ManagementPolicyManaged)
	profile.Spec.Profile = v1alpha1.DeviceProfileTarget{
		Kind:       v1alpha1.DeviceProfileKindCustom,
		Match:      new("identity.email == \"user@example.com\""),
		Precedence: new(int64(100)),
		Fields:     &v1alpha1.DeviceProfileFields{Name: new("profile-" + f.name), Enabled: new(true)},
	}
	profile.Spec.DeletionPolicy = deletionPolicy
	return profile
}

type fakeDeviceProfileCloudflare struct {
	mu             sync.Mutex
	defaultProfile flarecloudflare.DeviceProfile
	custom         map[string]flarecloudflare.DeviceProfile
	include        map[string][]flarecloudflare.SplitTunnelEntry
	exclude        map[string][]flarecloudflare.SplitTunnelEntry
	fallback       map[string][]flarecloudflare.FallbackDomain
	failures       map[string]error
	calls          []string
	next           int
}

func newFakeDeviceProfileCloudflare() *fakeDeviceProfileCloudflare {
	fake := new(fakeDeviceProfileCloudflare)
	fake.reset()
	return fake
}

func (f *fakeDeviceProfileCloudflare) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaultProfile = flarecloudflare.DeviceProfile{PolicyID: "default-profile", Default: true}
	f.custom = map[string]flarecloudflare.DeviceProfile{}
	f.include = map[string][]flarecloudflare.SplitTunnelEntry{}
	f.exclude = map[string][]flarecloudflare.SplitTunnelEntry{}
	f.fallback = map[string][]flarecloudflare.FallbackDomain{}
	f.failures = map[string]error{}
	f.calls = nil
	f.next = 0
}

func (f *fakeDeviceProfileCloudflare) Client(string, string) (flarecloudflare.DeviceProfileAPI, error) {
	return f, nil
}

func (f *fakeDeviceProfileCloudflare) GetDefaultDeviceProfile(context.Context) (flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.defaultProfile, nil
}

func (f *fakeDeviceProfileCloudflare) UpdateDefaultDeviceProfile(_ context.Context, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateDefault")
	applyFakeProfileInput(&f.defaultProfile, input)
	return f.defaultProfile, nil
}

func (f *fakeDeviceProfileCloudflare) CreateCustomDeviceProfile(_ context.Context, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateCustom")
	f.next++
	profile := flarecloudflare.DeviceProfile{PolicyID: fmt.Sprintf("custom-%d", f.next)}
	applyFakeProfileInput(&profile, input)
	f.custom[profile.PolicyID] = profile
	return profile, nil
}

func (f *fakeDeviceProfileCloudflare) ListCustomDeviceProfiles(context.Context) ([]flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]flarecloudflare.DeviceProfile, 0, len(f.custom))
	for _, profile := range f.custom {
		result = append(result, profile)
	}
	slices.SortFunc(result, func(a, b flarecloudflare.DeviceProfile) int { return strings.Compare(a.PolicyID, b.PolicyID) })
	return result, nil
}

func (f *fakeDeviceProfileCloudflare) GetCustomDeviceProfile(_ context.Context, id string) (flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	profile, found := f.custom[id]
	if !found {
		return profile, fmt.Errorf("custom profile %s not found", id)
	}
	return profile, nil
}

func (f *fakeDeviceProfileCloudflare) UpdateCustomDeviceProfile(_ context.Context, id string, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateCustom")
	profile := f.custom[id]
	applyFakeProfileInput(&profile, input)
	f.custom[id] = profile
	return profile, nil
}

func (f *fakeDeviceProfileCloudflare) DeleteCustomDeviceProfile(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "DeleteCustom")
	delete(f.custom, id)
	return nil
}

func (f *fakeDeviceProfileCloudflare) GetDeviceProfileInclude(_ context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["GetInclude"]; err != nil {
		return nil, err
	}
	return slices.Clone(f.include[deviceProfileRefKey(ref)]), nil
}

func (f *fakeDeviceProfileCloudflare) ReplaceDeviceProfileInclude(_ context.Context, ref flarecloudflare.DeviceProfileRef, entries []flarecloudflare.SplitTunnelEntry) ([]flarecloudflare.SplitTunnelEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["ReplaceInclude"]; err != nil {
		return nil, err
	}
	f.calls = append(f.calls, "ReplaceInclude")
	f.include[deviceProfileRefKey(ref)] = slices.Clone(entries)
	return slices.Clone(entries), nil
}

func (f *fakeDeviceProfileCloudflare) GetDeviceProfileExclude(_ context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.exclude[deviceProfileRefKey(ref)]), nil
}

func (f *fakeDeviceProfileCloudflare) ReplaceDeviceProfileExclude(_ context.Context, ref flarecloudflare.DeviceProfileRef, entries []flarecloudflare.SplitTunnelEntry) ([]flarecloudflare.SplitTunnelEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ReplaceExclude")
	f.exclude[deviceProfileRefKey(ref)] = slices.Clone(entries)
	return slices.Clone(entries), nil
}

func (f *fakeDeviceProfileCloudflare) GetDeviceProfileFallbackDomains(_ context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.FallbackDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.fallback[deviceProfileRefKey(ref)]), nil
}

func (f *fakeDeviceProfileCloudflare) ReplaceDeviceProfileFallbackDomains(_ context.Context, ref flarecloudflare.DeviceProfileRef, entries []flarecloudflare.FallbackDomain) ([]flarecloudflare.FallbackDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ReplaceFallback")
	f.fallback[deviceProfileRefKey(ref)] = slices.Clone(entries)
	return slices.Clone(entries), nil
}

func (f *fakeDeviceProfileCloudflare) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeDeviceProfileCloudflare) mutationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeDeviceProfileCloudflare) hasCustom(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, found := f.custom[id]
	return found
}

func deviceProfileRefKey(ref flarecloudflare.DeviceProfileRef) string {
	return string(ref.Kind) + "/" + ref.ID
}

func (f *fakeDeviceProfileCloudflare) addCustom(profile flarecloudflare.DeviceProfile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.custom[profile.PolicyID] = profile
}

func (f *fakeDeviceProfileCloudflare) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if call == name {
			count++
		}
	}
	return count
}

func (f *fakeDeviceProfileCloudflare) fail(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[name] = err
}

func (f *fakeDeviceProfileCloudflare) fallbackSnapshot(ref flarecloudflare.DeviceProfileRef) []flarecloudflare.FallbackDomain {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.fallback[deviceProfileRefKey(ref)])
}

func (f *fakeDeviceProfileCloudflare) includeSnapshot(ref flarecloudflare.DeviceProfileRef) []flarecloudflare.SplitTunnelEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.include[deviceProfileRefKey(ref)])
}

func applyFakeProfileInput(profile *flarecloudflare.DeviceProfile, input flarecloudflare.DeviceProfileInput) {
	if input.Name != nil {
		profile.Name = *input.Name
	}

	if input.Description != nil {
		profile.Description = *input.Description
	}
	if input.Enabled != nil {
		profile.Enabled = *input.Enabled
	}
	if input.Match != nil {
		profile.Match = *input.Match
	}
	if input.Precedence != nil {
		profile.Precedence = *input.Precedence
	}
	if input.SwitchLocked != nil {
		profile.SwitchLocked = *input.SwitchLocked
	}
	if input.CaptivePortal != nil {
		profile.CaptivePortal = *input.CaptivePortal
	}
	if input.AllowModeSwitch != nil {
		profile.AllowModeSwitch = *input.AllowModeSwitch
	}
	if input.AllowUpdates != nil {
		profile.AllowUpdates = *input.AllowUpdates
	}
	if input.AllowedToLeave != nil {
		profile.AllowedToLeave = *input.AllowedToLeave
	}
	if input.AutoConnect != nil {
		profile.AutoConnect = *input.AutoConnect
	}
	if input.DisableAutoFallback != nil {
		profile.DisableAutoFallback = *input.DisableAutoFallback
	}
	if input.ExcludeOfficeIPs != nil {
		profile.ExcludeOfficeIPs = *input.ExcludeOfficeIPs
	}
	if input.ServiceModeV2 != nil {
		profile.ServiceModeV2 = *input.ServiceModeV2
	}
	if input.SupportURL != nil {
		profile.SupportURL = *input.SupportURL
	}
	if input.LANAllowMinutes != nil {
		profile.LANAllowMinutes = *input.LANAllowMinutes
	}
	if input.LANAllowSubnetSize != nil {
		profile.LANAllowSubnetSize = *input.LANAllowSubnetSize
	}
	if input.RegisterInterfaceIPWithDNS != nil {
		profile.RegisterInterfaceIPWithDNS = *input.RegisterInterfaceIPWithDNS
	}
	if input.SCCMVPNBoundarySupport != nil {
		profile.SCCMVPNBoundarySupport = *input.SCCMVPNBoundarySupport
	}
	if input.TunnelProtocol != nil {
		profile.TunnelProtocol = *input.TunnelProtocol
	}
	if input.VirtualNetworks != nil {
		profile.VirtualNetworks = *input.VirtualNetworks
	}
	if input.DNSSearchSuffixes != nil {
		profile.DNSSearchSuffixes = slices.Clone(*input.DNSSearchSuffixes)
	}
}
