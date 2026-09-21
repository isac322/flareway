//go:build e2e

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

package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
	"github.com/isac322/flareway/test/e2e/internal/names"
	"github.com/isac322/flareway/test/e2e/internal/poll"
)

var _ = Describe("Account-global device profile", Label("account-global"), func() {
	It("owns whole custom-profile lists and leaves them on Orphan deletion", func(ctx SpecContext) {
		kind := configuration.DeviceProfileKind
		if kind != "Custom" && kind != "Default" {
			Fail(fmt.Sprintf("FLAREWAY_E2E_DEVICE_PROFILE_KIND must be Custom or Default, got %q", kind))
		}
		isDefault := kind == "Default"
		if isDefault && !configuration.AllowDefaultDeviceProfile {
			Skip("default profile mutation requires explicit FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE=1")
		}

		var defaultSnapshot *cfapi.DefaultDeviceProfileSnapshot
		if isDefault {
			snapshot, err := cloudflareAPI.SnapshotDefaultDeviceProfile(ctx)
			Expect(err).NotTo(HaveOccurred(), "snapshot every mutable default device-profile field and whole list")
			defaultSnapshot = &snapshot
		}

		remoteName := names.Resource(runID, "device-profile")
		profileTarget := map[string]any{"kind": kind}
		if !isDefault {
			profileTarget["match"] = fmt.Sprintf("identity.email == \"flareway-e2e-%s@example.invalid\"", runID)
			profileTarget["precedence"] = int64(999999)
			profileTarget["fields"] = map[string]any{
				"name": remoteName, "enabled": true,
				"description": "Flareway isolated e2e profile " + names.CreatedMarkerPrefix + time.Now().UTC().Format(time.RFC3339),
			}
		}
		desiredInclude := []cfapi.SplitTunnelEntry{
			{Address: "10.240.0.0/16", Description: "flareway e2e network"},
			{Host: fmt.Sprintf("profile-%s.flareway.internal", runID), Description: "flareway e2e hostname"},
		}
		desiredFallback := []cfapi.FallbackDomain{{
			Suffix:      fmt.Sprintf("fallback-%s.flareway.internal", runID),
			Description: "flareway e2e fallback",
			DNSServer:   []string{"192.0.2.53"},
		}}
		static := make([]any, 0, len(desiredInclude))
		for _, entry := range desiredInclude {
			value := map[string]any{"description": entry.Description}
			if entry.Address != "" {
				value["address"] = entry.Address
			} else {
				value["host"] = entry.Host
			}
			static = append(static, value)
		}
		fallbackStatic := []any{map[string]any{
			"suffix": desiredFallback[0].Suffix, "description": desiredFallback[0].Description,
			"dnsServer": []any{desiredFallback[0].DNSServer[0]},
		}}
		deviceProfile := object("flareway.bhyoo.com/v1alpha1", "DeviceProfile", namespace, "account-global", map[string]any{
			"accountRef":       map[string]any{"name": accountName},
			"profile":          profileTarget,
			"splitTunnel":      map[string]any{"mode": "Include", "static": static},
			"fallbackDomains":  map[string]any{"static": fallbackStatic},
			"managementPolicy": "Managed",
			"deletionPolicy":   "Orphan",
		})

		profileID := ""
		remoteCleaned := false
		defaultRestored := false
		DeferCleanup(func(cleanupCtx SpecContext) {
			Expect(deleteAndWaitDeviceProfile(cleanupCtx, deviceProfile)).To(Succeed())
			if isDefault && defaultSnapshot != nil && !defaultRestored {
				Expect(cloudflareAPI.RestoreDefaultDeviceProfile(cleanupCtx, *defaultSnapshot)).To(Succeed())
			} else if !isDefault && profileID != "" && !remoteCleaned {
				if err := cloudflareAPI.DeleteDeviceProfile(cleanupCtx, profileID); err != nil {
					GinkgoWriter.Printf("delete isolated e2e device profile %s: %v\n", profileID, err)
				}
			}
		})
		Expect(kubeClient.Create(ctx, deviceProfile)).To(Succeed())

		readyCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		defer cancel()
		duration, err := poll.Until(readyCtx, 30*time.Second, func(checkCtx context.Context) (bool, error) {
			current := &unstructured.Unstructured{}
			current.SetAPIVersion(deviceProfile.GetAPIVersion())
			current.SetKind(deviceProfile.GetKind())
			if getErr := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(deviceProfile), current); getErr != nil {
				return false, getErr
			}
			id, _, idErr := unstructured.NestedString(current.Object, "status", "profileId")
			if idErr != nil {
				return false, idErr
			}
			if id != "" {
				profileID = id
			}
			acceptedReady, conditionErr := hasCondition(checkCtx, current, "Accepted", "True")
			if conditionErr != nil || !acceptedReady {
				return false, conditionErr
			}
			return hasCondition(checkCtx, current, "Ready", "True")
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("account-global-device-profile-ready", duration)
		if isDefault && profileID == "" {
			profileID = "default"
		}
		Expect(profileID).NotTo(BeEmpty())

		remote, err := cloudflareAPI.GetDeviceProfile(ctx, profileID, isDefault)
		Expect(err).NotTo(HaveOccurred())
		Expect(remote.Default).To(Equal(isDefault))
		assertDeviceProfileLists(ctx, profileID, isDefault, desiredInclude, desiredFallback)

		Expect(deleteAndWaitDeviceProfile(ctx, deviceProfile)).To(Succeed())

		_, err = cloudflareAPI.GetDeviceProfile(ctx, profileID, isDefault)
		Expect(err).NotTo(HaveOccurred(), "deletionPolicy=Orphan must retain the remote profile")
		assertDeviceProfileLists(ctx, profileID, isDefault, desiredInclude, desiredFallback)
		if isDefault {
			Expect(defaultSnapshot).NotTo(BeNil())
			Expect(cloudflareAPI.RestoreDefaultDeviceProfile(ctx, *defaultSnapshot)).To(Succeed())
			restored, restoreErr := cloudflareAPI.SnapshotDefaultDeviceProfile(ctx)
			Expect(restoreErr).NotTo(HaveOccurred())
			Expect(restored).To(Equal(*defaultSnapshot), "manual default-profile e2e must restore every field and whole list")
			defaultRestored = true
		} else {
			Expect(cloudflareAPI.DeleteDeviceProfile(ctx, profileID)).To(Succeed())
			remoteCleaned = true
		}
	}, NodeTimeout(18*time.Minute))
})

func deleteAndWaitDeviceProfile(ctx context.Context, profile *unstructured.Unstructured) error {
	if err := kubeClient.Delete(ctx, profile); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, err := poll.Until(waitCtx, 5*time.Second, func(checkCtx context.Context) (bool, error) {
		current := &unstructured.Unstructured{}
		current.SetAPIVersion(profile.GetAPIVersion())
		current.SetKind(profile.GetKind())
		getErr := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(profile), current)
		return apierrors.IsNotFound(getErr), client.IgnoreNotFound(getErr)
	})
	return err
}

func assertDeviceProfileLists(ctx context.Context, profileID string, isDefault bool, wantInclude []cfapi.SplitTunnelEntry, wantFallback []cfapi.FallbackDomain) {
	GinkgoHelper()
	gotInclude, err := cloudflareAPI.GetDeviceProfileIncludes(ctx, profileID, isDefault)
	Expect(err).NotTo(HaveOccurred())
	gotFallback, err := cloudflareAPI.GetDeviceProfileFallbackDomains(ctx, profileID, isDefault)
	Expect(err).NotTo(HaveOccurred())
	sortSplitTunnelEntries(gotInclude)
	sortSplitTunnelEntries(wantInclude)
	slices.SortFunc(gotFallback, compareFallbackDomain)
	slices.SortFunc(wantFallback, compareFallbackDomain)
	Expect(gotInclude).To(Equal(wantInclude))
	Expect(gotFallback).To(Equal(wantFallback))
}

func sortSplitTunnelEntries(entries []cfapi.SplitTunnelEntry) {
	slices.SortFunc(entries, func(left, right cfapi.SplitTunnelEntry) int {
		return strings.Compare(left.Address+"\x00"+left.Host+"\x00"+left.Description, right.Address+"\x00"+right.Host+"\x00"+right.Description)
	})
}

func compareFallbackDomain(left, right cfapi.FallbackDomain) int {
	return strings.Compare(left.Suffix+"\x00"+left.Description+"\x00"+strings.Join(left.DNSServer, ","), right.Suffix+"\x00"+right.Description+"\x00"+strings.Join(right.DNSServer, ","))
}
