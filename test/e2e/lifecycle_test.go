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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isac322/flareway/test/e2e/internal/names"
	"github.com/isac322/flareway/test/e2e/internal/poll"
)

var _ = Describe("Tunnel lifecycle", Label("public", "lifecycle"), func() {
	It("adopts an explicitly identified tunnel and honors Orphan deletion", func(ctx SpecContext) {
		remoteName := names.Resource(runID, "adopted")
		remote, err := cloudflareAPI.CreateTunnel(ctx, remoteName)
		Expect(err).NotTo(HaveOccurred())
		remoteDeleted := false
		DeferCleanup(func(cleanupCtx SpecContext) {
			if !remoteDeleted {
				_ = cloudflareAPI.DeleteTunnel(cleanupCtx, remote.ID)
			}
		})

		tunnel := object("flareway.bhyoo.com/v1alpha1", "CloudflareTunnel", namespace, "adoption", map[string]any{
			"accountRef": map[string]any{"name": accountName},
			"tunnel": map[string]any{
				"name": remoteName, "externalRef": map[string]any{"tunnelId": remote.ID},
			},
			"managementPolicy": "Managed",
			"adoption": map[string]any{
				"mode": "AdoptById", "expect": map[string]any{"name": remoteName},
			},
			"deletionPolicy": "Orphan",
			"dns":            map[string]any{"mode": "External"},
			"listeners":      []any{map[string]any{"name": "web", "exposure": "Public"}},
		})
		Expect(kubeClient.Create(ctx, tunnel)).To(Succeed())
		DeferCleanup(func(cleanupCtx SpecContext) { deleteObject(cleanupCtx, tunnel) })

		gateway := object("gateway.networking.k8s.io/v1", "Gateway", namespace, "adoption", map[string]any{
			"gatewayClassName": className,
			"infrastructure": map[string]any{"parametersRef": map[string]any{
				"group": "flareway.bhyoo.com", "kind": "CloudflareTunnel", "name": "adoption",
			}},
			"listeners": []any{map[string]any{
				"name": "web", "hostname": hostname, "port": int64(80), "protocol": "HTTP",
			}},
		})
		Expect(kubeClient.Create(ctx, gateway)).To(Succeed())
		DeferCleanup(func(cleanupCtx SpecContext) { deleteObject(cleanupCtx, gateway) })

		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		duration, err := poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			return hasCondition(checkCtx, tunnel, "Ready", "True")
		})
		if err != nil {
			GinkgoWriter.Printf("Dataplane diagnostics:\n%s\n", dataplaneDiagnostics())
		}
		Expect(err).NotTo(HaveOccurred(), "CloudflareTunnel conditions: %s", conditionSummary(tunnel))
		recordLatency("lifecycle-adoption-ready", duration)

		Expect(kubeClient.Delete(ctx, tunnel)).To(Succeed())
		duration, err = poll.Until(readyCtx, 2*time.Second, func(checkCtx context.Context) (bool, error) {
			current := &unstructured.Unstructured{}
			current.SetAPIVersion("flareway.bhyoo.com/v1alpha1")
			current.SetKind("CloudflareTunnel")
			getErr := kubeClient.Get(checkCtx, client.ObjectKeyFromObject(tunnel), current)
			return apierrors.IsNotFound(getErr), client.IgnoreNotFound(getErr)
		})
		Expect(err).NotTo(HaveOccurred())
		recordLatency("lifecycle-orphan-finalizer", duration)

		tunnels, err := cloudflareAPI.ListTunnels(ctx)
		Expect(err).NotTo(HaveOccurred())
		found := false
		for _, candidate := range tunnels {
			if candidate.ID == remote.ID {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "deletionPolicy=Orphan must preserve the adopted remote tunnel")
		Expect(cloudflareAPI.DeleteTunnel(ctx, remote.ID)).To(Succeed())
		remoteDeleted = true
	}, NodeTimeout(7*time.Minute))
})
