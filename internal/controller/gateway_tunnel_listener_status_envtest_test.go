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

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

var _ = ginkgo.Describe("Gateway-owned CloudflareTunnel listener status", func() {
	// Every public Access-protected host is its own protection domain on its
	// own Envoy port, so one listener fronting many protected hosts reports
	// one protectionDomains entry per host. The status write must be accepted
	// by the real API server schema well past the former 64-entry bound.
	ginkgo.It("TestTunnelListenerStatusAcceptsMoreThan64ProtectionDomains: persists every per-host protection domain of one public listener", func() {
		direct := startIsolatedConditionsPlane()
		fixture := newTunnelConditionsFixture(direct, managedTunnelSpec())
		_, writerGateway := fixture.createGateway()

		const domainCount = 100
		compiled := &ir.Gateway{
			Key:       writerGateway.Key,
			UID:       writerGateway.UID,
			Listeners: []ir.Listener{{Name: "http", Hostname: "edge.example.com", Port: 80, EnvoyPort: 10080, Protocol: "HTTP", Exposure: ir.ExposurePublic}},
		}
		want := make([]v1alpha1.CloudflareProtectionDomainStatus, 0, domainCount)
		for index := range domainCount {
			domain := ir.ProtectionDomain{
				Name:         fmt.Sprintf("http-access-apps-app-%03d-%08x", index, index),
				ListenerName: "http",
				EnvoyPort:    int32(20000 + index),
				Protected:    true,
			}
			compiled.Domains = append(compiled.Domains, domain)
			want = append(want, v1alpha1.CloudflareProtectionDomainStatus{Name: domain.Name, EnvoyPort: domain.EnvoyPort, Protected: true})
		}

		writer := &GatewayReconciler{Client: direct, APIReader: direct, Scheme: direct.Scheme()}
		observed := fixture.live()
		gomega.Expect(writer.patchTunnelGatewayData(
			testContext, compiled, observed,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "hash"},
			observed.Status.Hostnames,
			desiredTunnelListeners(compiled),
		)).To(gomega.Succeed())

		persisted := fixture.live()
		gomega.Expect(persisted.Status.ConfigVersion.Desired).To(gomega.Equal(int64(1)))
		gomega.Expect(persisted.Status.Listeners).To(gomega.HaveLen(1))
		listener := persisted.Status.Listeners[0]
		gomega.Expect(listener.Name).To(gomega.Equal(gatewayv1.SectionName("http")))
		gomega.Expect(listener.Exposure).To(gomega.Equal(v1alpha1.ExposurePublic))
		gomega.Expect(listener.ProtectionDomains).To(gomega.ConsistOf(want))
	})
})
