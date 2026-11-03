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
	"encoding/json"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
)

var _ = ginkgo.Describe("Gateway listener prerequisite isolation (issue 135)", func() {
	ginkgo.It("QA-135-private-isolation checkpoints public Access while a private listener remains pending", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
			beforeProvision: func(f *qa92Fixture) {
				var account v1alpha1.CloudflareAccount
				gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: f.tunnel().Spec.AccountRef.Name}, &account)).To(gomega.Succeed())
				// The private route would otherwise be allowed to forward. Its
				// denial must come from the missing prerequisite, not a grant.
				account.Spec.Grants[0].UnprotectedHostnames = append(account.Spec.Grants[0].UnprotectedHostnames, "private.internal.example")
				gomega.Expect(f.direct.Update(f.ctx, &account)).To(gomega.Succeed())
			},
		})
		var account v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: f.tunnel().Spec.AccountRef.Name}, &account)).To(gomega.Succeed())

		backend := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: f.gatewayKey.Namespace},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, backend)).To(gomega.Succeed())
		for _, listener := range []struct{ name, hostname string }{
			{name: "http", hostname: "edge-a.example.com"},
			{name: "private", hostname: "private.internal.example"},
		} {
			section := gatewayv1.SectionName(listener.name)
			port := gatewayv1.PortNumber(8080)
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: listener.name, Namespace: f.gatewayKey.Namespace},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &section}}},
					Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(listener.hostname)},
					Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}}}},
				},
			}
			gomega.Expect(f.direct.Create(f.ctx, route)).To(gomega.Succeed())
		}
		section := gatewayv1.SectionName("http")
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "public-access", Namespace: f.gatewayKey.Namespace},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:  corev1.LocalObjectReference{Name: account.Name},
				Type:        v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:  &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs:  []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &section}},
				Application: v1alpha1.AccessApplicationSettings{Name: "public-access", SessionDuration: "1h"},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "allow-policy"}}},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, application)).To(gomega.Succeed())
		application.Status.ApplicationID = "public-application"
		gomega.Expect(f.direct.Status().Update(f.ctx, application)).To(gomega.Succeed())
		applicationReconciler := &AccessApplicationReconciler{Client: f.direct, OperatorNamespace: dataplane.DefaultOperatorNamespace}
		gomega.Expect(applicationReconciler.ensureAUDSecrets(f.ctx, application, flarecloudflare.AccessApplication{ID: application.Status.ApplicationID, AUD: "public-aud"}, []types.NamespacedName{f.gatewayKey})).To(gomega.Succeed())

		var compiled *ir.Gateway
		var published *cachev3.Snapshot
		f.reconciler.BuildSnapshot = func(gateway *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (*cachev3.Snapshot, error) {
			compiled = gateway
			snapshot, err := controlledSnapshotBuild(gateway, cfg)
			published = snapshot
			return snapshot, err
		}
		reconcile := func() {
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		reconcile()
		gomega.Expect(qa135PublicEdgeService(compiled)).To(gomega.Equal("http_status:403"))
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded).Reason).To(gomega.Equal("Pending"))

		// Neither an ACK with a stale Pod version nor a current Pod version
		// with an xDS NACK proves that the denial reached the data plane.
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		reconcile()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.BeZero())
		f.prober.version = f.remote.remoteVersion
		gomega.Expect(f.snapshots.NACK(f.gatewayKey.String(), "denial not accepted")).To(gomega.Succeed())
		reconcile()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.BeZero())

		// Once both observations agree, checkpoint the public denial even
		// though the unrelated private VirtualNetwork is still missing.
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		reconcile()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		blocked := qa135PublicHostname(f.tunnel())
		gomega.Expect(blocked.Guard).To(gomega.Equal(v1alpha1.HostnameGuardBlocked))
		gomega.Expect(blocked.AccessBinding).NotTo(gomega.BeEmpty())
		gomega.Expect(blocked.AppliedVersion).To(gomega.Equal(f.remote.remoteVersion))

		reconcile()
		gomega.Expect(qa135PublicEdgeService(compiled)).To(gomega.HavePrefix("http://127.0.0.1:"))
		qa135ExpectPrivateDenial(compiled, published)
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		f.prober.version = f.remote.remoteVersion
		reconcile()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(f.tunnel().Status.ConfigVersion.Applied).To(gomega.Equal(f.remote.remoteVersion))
		// Tunnel Ready proves the applied snapshot and DNS, including its
		// denied private rules; listener Programmed describes availability.
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(qa135PublicHostname(f.tunnel()).Guard).To(gomega.Equal(v1alpha1.HostnameGuardForwarding))
		gomega.Expect(f.gatewayProgrammed().Status).To(gomega.Equal(metav1.ConditionFalse))
		var gateway gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gateway)).To(gomega.Succeed())
		gomega.Expect(gateway.Status.Listeners).To(gomega.HaveLen(2))
		for _, listener := range gateway.Status.Listeners {
			programmed := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			gomega.Expect(programmed).NotTo(gomega.BeNil())
			if listener.Name == "http" {
				gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionTrue))
			} else {
				gomega.Expect(listener.Name).To(gomega.Equal(gatewayv1.SectionName("private")))
				gomega.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
				gomega.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.ListenerReasonPending)))
				gomega.Expect(programmed.Message).NotTo(gomega.BeEmpty())
			}
		}
		updates := f.remote.updates
		for range 2 {
			reconcile()
			gomega.Expect(qa135PublicEdgeService(compiled)).To(gomega.HavePrefix("http://127.0.0.1:"))
			qa135ExpectPrivateDenial(compiled, published)
			gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
			gomega.Expect(f.remote.updates).To(gomega.Equal(updates))
		}
	})
})

func qa135PublicHostname(tunnel *v1alpha1.CloudflareTunnel) v1alpha1.CloudflareTunnelHostnameStatus {
	for _, hostname := range tunnel.Status.Hostnames {
		if hostname.Hostname == "edge-a.example.com" {
			return hostname
		}
	}
	ginkgo.Fail("applied public hostname checkpoint is missing")
	return v1alpha1.CloudflareTunnelHostnameStatus{}
}

func qa135PublicEdgeService(gateway *ir.Gateway) string {
	request, _, err := cloudflaredconfig.Compile(gateway)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	data, err := json.Marshal(request)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	var wire struct {
		Config struct {
			Ingress []struct{ Hostname, Service string }
		}
	}
	gomega.ExpectWithOffset(1, json.Unmarshal(data, &wire)).To(gomega.Succeed())
	for _, rule := range wire.Config.Ingress {
		if rule.Hostname == "edge-a.example.com" {
			return rule.Service
		}
	}
	ginkgo.Fail("public cloudflared ingress rule is missing")
	return ""
}

func qa135ExpectPrivateDenial(gateway *ir.Gateway, snapshot *cachev3.Snapshot) {
	privateDomains := 0
	for _, domain := range gateway.Domains {
		if domain.ListenerName != "private" {
			continue
		}
		privateDomains++
		gomega.ExpectWithOffset(1, domain.Guard).To(gomega.Equal(ir.GuardBlocked))
		gomega.ExpectWithOffset(1, domain.Access).To(gomega.BeNil())
		routes, found := snapshot.GetResources(resourcev3.RouteType)[domain.Name]
		gomega.ExpectWithOffset(1, found).To(gomega.BeTrue())
		configuration, ok := routes.(*routev3.RouteConfiguration)
		gomega.ExpectWithOffset(1, ok).To(gomega.BeTrue())
		gomega.ExpectWithOffset(1, configuration.VirtualHosts).NotTo(gomega.BeEmpty())
		for _, host := range configuration.VirtualHosts {
			gomega.ExpectWithOffset(1, host.Routes).NotTo(gomega.BeEmpty())
			for _, route := range host.Routes {
				gomega.ExpectWithOffset(1, route.GetDirectResponse()).NotTo(gomega.BeNil())
				gomega.ExpectWithOffset(1, route.GetDirectResponse().Status).To(gomega.Equal(uint32(403)))
			}
		}
	}
	gomega.ExpectWithOffset(1, privateDomains).To(gomega.BeNumerically(">", 0))
}
