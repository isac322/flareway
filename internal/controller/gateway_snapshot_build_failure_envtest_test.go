/*
Copyright 2026 The Flareway Authors.

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
	"fmt"
	"time"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// buildWithCollidingDomain feeds the real translator a compiled Gateway in
// which one protection domain name is bound to a second Envoy port — the
// shape that previously let one route table silently replace another. The
// real translator.Build must refuse it.
func buildWithCollidingDomain(gateway *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (*cachev3.Snapshot, error) {
	gomega.ExpectWithOffset(1, gateway.Domains).NotTo(gomega.BeEmpty())
	colliding := *gateway
	duplicate := gateway.Domains[0]
	duplicate.EnvoyPort = 30999
	colliding.Domains = append(append([]ir.ProtectionDomain(nil), gateway.Domains...), duplicate)
	return translator.Build(&colliding, cfg)
}

var _ = ginkgo.Describe("Gateway snapshot build failure", func() {
	ginkgo.It("TestGatewaySnapshotBuildFailureFailsClosed: reports Programmed=False and publishes nothing when translator.Build rejects duplicate xDS names", func() {
		fixture := newDataplaneRejectionFixture(startIsolatedConditionsPlane())
		fixture.convergeProgrammed()

		fixture.snapshots.mu.RLock()
		servedSnapshot := fixture.snapshots.snapshots[fixture.snapshotKey]
		fixture.snapshots.mu.RUnlock()
		servedVersion := fixture.snapshots.Version(fixture.snapshotKey)
		gomega.Expect(servedSnapshot).NotTo(gomega.BeNil())

		fixture.reconciler.BuildSnapshot = buildWithCollidingDomain
		reconcileErr := fixture.reconcile()
		gomega.Expect(reconcileErr).To(gomega.MatchError(gomega.ContainSubstring("is used by more than one")))

		programmed := fixture.expectProgrammed(metav1.ConditionFalse, string(gatewayv1.GatewayReasonInvalid))
		gomega.Expect(programmed.Message).To(gomega.Equal("Gateway configuration could not be compiled"))
		var gateway gatewayv1.Gateway
		gomega.Expect(fixture.kube.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		gomega.Expect(gateway.Status.Addresses).To(gomega.BeEmpty())

		// No snapshot built from the rejected configuration reaches Envoy:
		// the publisher still holds exactly the last good snapshot.
		fixture.snapshots.mu.RLock()
		gomega.Expect(fixture.snapshots.snapshots[fixture.snapshotKey]).To(gomega.BeIdenticalTo(servedSnapshot))
		fixture.snapshots.mu.RUnlock()
		gomega.Expect(fixture.snapshots.Version(fixture.snapshotKey)).To(gomega.Equal(servedVersion))
	})

	ginkgo.It("enforces non-negative whole-second CEL validation on GatewayOriginRequestSpec", func() {
		startIsolatedConditionsPlane()
		invalidDurations := []metav1.Duration{
			{Duration: -1 * time.Second},
			{Duration: 500 * time.Millisecond},
			{Duration: 1500 * time.Millisecond},
			{Duration: time.Second + 500*time.Nanosecond},
		}
		for i, bad := range invalidDurations {
			d := bad
			for _, field := range []string{"connectTimeout", "keepAliveTimeout", "tcpKeepAlive"} {
				origin := v1alpha1.GatewayOriginRequestSpec{}
				switch field {
				case "connectTimeout":
					origin.ConnectTimeout = &d
				case "keepAliveTimeout":
					origin.KeepAliveTimeout = &d
				case "tcpKeepAlive":
					origin.TCPKeepAlive = &d
				}
				cfg := &v1alpha1.GatewayClassConfig{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("invalid-origin-%s-%d", field, i)},
					Spec: v1alpha1.GatewayClassConfigSpec{
						AccountRef:    &corev1.LocalObjectReference{Name: "acct"},
						OriginRequest: origin,
					},
				}
				gomega.Expect(testClient.Create(testContext, cfg)).NotTo(gomega.Succeed(), "GatewayClassConfig %s=%v should be rejected", field, d.Duration)

				tunnel := &v1alpha1.CloudflareTunnel{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("invalid-tunnel-origin-%s-%d", field, i), Namespace: "default"},
					Spec: v1alpha1.CloudflareTunnelSpec{
						AccountRef:    corev1.LocalObjectReference{Name: "acct"},
						OriginRequest: &origin,
					},
				}
				gomega.Expect(testClient.Create(testContext, tunnel)).NotTo(gomega.Succeed(), "CloudflareTunnel %s=%v should be rejected", field, d.Duration)
			}
		}

		validOrigin := v1alpha1.GatewayOriginRequestSpec{
			ConnectTimeout:   &metav1.Duration{Duration: 0},
			KeepAliveTimeout: &metav1.Duration{Duration: 90 * time.Second},
			TCPKeepAlive:     &metav1.Duration{Duration: 2 * time.Minute},
		}
		validCfg := &v1alpha1.GatewayClassConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "valid-origin-cel"},
			Spec: v1alpha1.GatewayClassConfigSpec{
				AccountRef:    &corev1.LocalObjectReference{Name: "acct"},
				OriginRequest: validOrigin,
			},
		}
		gomega.Expect(testClient.Create(testContext, validCfg)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, validCfg) })

		validTunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "valid-tunnel-origin-cel", Namespace: "default"},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:    corev1.LocalObjectReference{Name: "acct"},
				OriginRequest: &validOrigin,
			},
		}
		gomega.Expect(testClient.Create(testContext, validTunnel)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, validTunnel) })
	})
})
