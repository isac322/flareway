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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

var tunnelFixtureCounter atomic.Uint64

func TestCloudflareTunnelGatewayMapper(t *testing.T) {
	g := gomega.NewWithT(t)
	reconciler := new(CloudflareTunnelReconciler)

	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
		Name: "gateway", Namespace: "tenant",
		OwnerReferences: []metav1.OwnerReference{{Name: "irrelevant-owner"}},
	}}
	g.Expect(reconciler.mapGatewayToTunnel(context.Background(), gateway)).To(gomega.Equal([]reconcile.Request{{
		NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "gateway"},
	}}))

	gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "explicit-tunnel",
		},
	}
	g.Expect(reconciler.mapGatewayToTunnel(context.Background(), gateway)).To(gomega.Equal([]reconcile.Request{{
		NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "explicit-tunnel"},
	}}))
}

func TestTunnelGatewayBindingsDeduplicateSamePublicHostname(t *testing.T) {
	g := gomega.NewWithT(t)
	httpHostname := gatewayv1.Hostname("app.example.test")
	httpsHostname := gatewayv1.Hostname("app.example.test")
	gateway := &gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
		Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &httpHostname,
	}, {
		Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443, Hostname: &httpsHostname,
	}}}}
	tunnel := &v1alpha1.CloudflareTunnel{}
	zones := []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}}

	public, bindings, err := tunnelGatewayBindings(tunnel, gateway, zones)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(public).To(gomega.Equal([]publicHostname{{
		Hostname: "app.example.test", ZoneID: "zone-example", ZoneName: "example.test",
	}}))
	g.Expect(bindings).To(gomega.HaveLen(2))

	tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
		Name: "https", Exposure: v1alpha1.ExposurePrivate,
	}}
	_, _, err = tunnelGatewayBindings(tunnel, gateway, zones)
	g.Expect(err).To(gomega.MatchError("hostname exposure must be unique per Gateway: app.example.test"))
}

var _ = ginkgo.Describe("CloudflareTunnel reconciler", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func() {
		ensureSystemNamespace("kube-system")
		ensureSystemNamespace("flareway-system")
	})

	ginkgo.BeforeEach(func() {
		testTunnelCloudflare.Reset()
		testAccountCloudflare.reset()
	})

	ginkgo.It("creates a managed Tunnel, token Secret, DNS record, and merged Ready status", func() {
		fixture := newTunnelFixture("create", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.GatewayRef).To(gomega.Equal(&corev1.LocalObjectReference{Name: fixture.gatewayKey.Name}))
			g.Expect(tunnel.Status.Addresses).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords[0].Hostname).To(gomega.Equal(fixture.hostname))
			tunnelReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(tunnelReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(tunnelReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))

			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name}, &secret)).To(gomega.Succeed())
			g.Expect(secret.Data["token"]).To(gomega.Equal([]byte("token-" + tunnel.Status.TunnelID)))
			g.Expect(secret.OwnerReferences).To(gomega.HaveLen(1))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, []metav1.Condition{{
			Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionTrue,
			Reason: "Applied", Message: "configuration converged", ObservedGeneration: tunnel.Generation,
			LastTransitionTime: metav1.Now(),
		}}, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
		}})).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			ready := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.Hostnames).To(gomega.Equal([]v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
			}}))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		calls := testTunnelCloudflare.Calls()
		gomega.Expect(calls).To(gomega.ContainElement("CreateTunnel"))
		gomega.Expect(calls).To(gomega.ContainElement("GetTunnelToken"))
		gomega.Expect(calls).To(gomega.ContainElement("CreateCNAME"))
	})
	ginkgo.It("removes a user-supplied teardown annotation from an active Tunnel", func() {
		fixture := newTunnelFixture("active-teardown-annotation", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Annotations = map[string]string{v1alpha1.CloudflareTunnelTeardownAnnotation: "true"}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Annotations).NotTo(gomega.HaveKey(v1alpha1.CloudflareTunnelTeardownAnnotation))
			g.Expect(tunnel.DeletionTimestamp.IsZero()).To(gomega.BeTrue())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("reports a conflict without adopting a Tunnel whose expected name differs", func() {
		fixture := newTunnelFixture("adopt-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "existing-tunnel"}
		fixture.tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "expected-name"}}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "existing-tunnel", Name: "foreign-name", Status: "healthy"})
		fixture.create()

		gomega.Eventually(func() error {
			var tunnel v1alpha1.CloudflareTunnel
			if err := testClient.Get(testContext, fixture.tunnelKey, &tunnel); err != nil {
				return err
			}
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			if conflict == nil || conflict.Status != metav1.ConditionTrue || conflict.Reason != "AdoptionMismatch" || tunnel.Status.TunnelID != "" {
				return fmt.Errorf("conditions=%v tunnelID=%q calls=%v", tunnel.Status.Conditions, tunnel.Status.TunnelID, testTunnelCloudflare.Calls())
			}
			return nil
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("GetTunnel"))
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("CreateTunnel", "GetTunnelToken", "CreateCNAME"))
	})

	ginkgo.It("rejects adoption of a soft-deleted Tunnel", func() {
		fixture := newTunnelFixture("adopt-deleted", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "deleted-adoption"}
		fixture.tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "deleted-name"}}
		deletedAt := time.Now()
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "deleted-adoption", Name: "deleted-name", Status: "inactive", DeletedAt: &deletedAt})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Message).To(gomega.ContainSubstring("deleted"))
			g.Expect(tunnel.Status.TunnelID).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("GetTunnelToken", "CreateCNAME"))
	})

	ginkgo.It("marks an already-managed soft-deleted Tunnel not ready", func() {
		fixture := newTunnelFixture("managed-deleted", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.MarkTunnelDeleted(tunnel.Status.TunnelID)

		var credential corev1.Secret
		gomega.Expect(testClient.Get(testContext, fixture.credential, &credential)).To(gomega.Succeed())
		before := credential.DeepCopy()
		if credential.Annotations == nil {
			credential.Annotations = map[string]string{}
		}
		credential.Annotations["flareway.bhyoo.com/test-refresh"] = time.Now().Format(time.RFC3339Nano)
		gomega.Expect(testClient.Patch(testContext, &credential, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			ready := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Message).To(gomega.ContainSubstring("deleted"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("observes an external Tunnel and writes no remote resources", func() {
		fixture := newTunnelFixture("observe", v1alpha1.ManagementPolicyObserveOnly, v1alpha1.DNSModeManaged)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-tunnel"}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "observed-tunnel", Name: "terraform-tunnel", Status: "healthy"})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal("observed-tunnel"))
			g.Expect(tunnel.Status.DNSRecords).To(gomega.BeEmpty())
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Reason).To(gomega.Equal("ObserveOnly"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		calls := testTunnelCloudflare.Calls()
		gomega.Expect(calls).To(gomega.ContainElements("GetTunnel", "GetTunnelToken"))
		gomega.Expect(calls).NotTo(gomega.ContainElements("CreateTunnel", "CreateCNAME", "UpdateCNAME", "DeleteDNSRecord", "DeleteTunnel"))
	})

	ginkgo.It("treats External DNS as ready without listing or mutating records", func() {
		fixture := newTunnelFixture("external-dns", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.BeEmpty())
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Reason).To(gomega.Equal("External"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("ListDNSRecords", "CreateCNAME", "UpdateCNAME"))
	})

	ginkgo.It("refuses to overwrite a foreign DNS record", func() {
		fixture := newTunnelFixture("dns-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "foreign-record", Name: fixture.hostname, Type: "CNAME",
			Content: "foreign.example.net", Comment: "terraform", Proxied: true,
		})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("DNSOwnership"))
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionFalse))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("UpdateCNAME", "DeleteDNSRecord"))
	})

	ginkgo.It("updates a comment-owned DNS record without requiring Cloudflare tags", func() {
		fixture := newTunnelFixture("dns-comment-owner", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.tunnel.Spec.DNS.RecordComment = "operator note"
		var systemNamespace corev1.Namespace
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: "kube-system"}, &systemNamespace)).To(gomega.Succeed())
		owner := flarecloudflare.DNSRecordComment(string(systemNamespace.UID), fixture.namespace, fixture.gatewayKey.Name)
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "owned-without-tags", Name: fixture.hostname, Type: "CNAME",
			Content: "stale.cfargotunnel.com", Comment: owner, Proxied: false,
		})
		fixture.create()

		var recordID, remoteID string
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords[0].RecordID).To(gomega.Equal("owned-without-tags"))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			recordID = tunnel.Status.DNSRecords[0].RecordID
			remoteID = tunnel.Status.TunnelID
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		record, ok := testTunnelCloudflare.DNSRecord("zone-example", recordID)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(record.Content).To(gomega.Equal(remoteID + ".cfargotunnel.com"))
		gomega.Expect(record.Comment).To(gomega.Equal(owner + " operator note"))
		gomega.Expect(record.Proxied).To(gomega.BeTrue())
		gomega.Expect(record.Tags).To(gomega.BeEmpty())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("UpdateCNAME"))
	})

	ginkgo.It("checkpoints a created Tunnel before DNS failure and reuses it on retry", func() {
		fixture := newTunnelFixture("dns-checkpoint", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		var tokenChecked, tokenCheckpointed atomic.Bool
		var dnsChecked, dnsCheckpointed atomic.Bool
		checkStatus := func(checked, checkpointed *atomic.Bool) func() {
			return func() {
				if !checked.CompareAndSwap(false, true) {
					return
				}
				var current v1alpha1.CloudflareTunnel
				err := testAPIReader.Get(testContext, fixture.tunnelKey, &current)
				checkpointed.Store(err == nil && current.Status.TunnelID != "")
			}
		}
		testTunnelCloudflare.Before("GetTunnelToken", checkStatus(&tokenChecked, &tokenCheckpointed))
		testTunnelCloudflare.Before("CreateCNAME", checkStatus(&dnsChecked, &dnsCheckpointed))
		testTunnelCloudflare.FailNext("CreateCNAME", errors.New("injected DNS creation failure"))
		fixture.create()

		var remoteID string
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.ConnectorState).To(gomega.Equal(v1alpha1.ConnectorStateHealthy))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionFalse))
			remoteID = tunnel.Status.TunnelID
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(tokenChecked.Load()).To(gomega.BeTrue())
		gomega.Expect(tokenCheckpointed.Load()).To(gomega.BeTrue(), "status.tunnelId was not persisted before GetTunnelToken")
		gomega.Expect(dnsChecked.Load()).To(gomega.BeTrue())
		gomega.Expect(dnsCheckpointed.Load()).To(gomega.BeTrue(), "status.tunnelId was not persisted before CreateCNAME")

		gomega.Eventually(func() bool {
			calls := testTunnelCloudflare.Calls()
			return slices.Contains(calls, "GetTunnel") && countCall(calls, "CreateTunnel") == 1
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasTunnel(remoteID)).To(gomega.BeTrue())

		testTunnelCloudflare.ClearFailure("CreateCNAME")
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal(remoteID))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(countCall(testTunnelCloudflare.Calls(), "CreateTunnel")).To(gomega.Equal(1))
	})

	ginkgo.It("preserves every owned DNS record when another hostname collides and deletes owned records during teardown", func() {
		fixture := newTunnelFixture("multi-host", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		ownedRecord := tunnel.Status.DNSRecords[0]

		collisionHostname := "aaa-" + fixture.hostname
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "foreign-multi-host", Name: collisionHostname, Type: "CNAME",
			Content: "foreign.example.net", Comment: "terraform", Proxied: true,
		})
		var gateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		before := gateway.DeepCopy()
		hostname := gatewayv1.Hostname(collisionHostname)
		gateway.Spec.Listeners = append(gateway.Spec.Listeners, gatewayv1.Listener{
			Name: "collision", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname,
		})
		gomega.Expect(testClient.Patch(testContext, &gateway, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("DNSOwnership"))
			g.Expect(current.Status.DNSRecords).To(gomega.ConsistOf(ownedRecord))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasDNSRecord("zone-example", ownedRecord.RecordID)).To(gomega.BeFalse())
		gomega.Expect(testTunnelCloudflare.HasDNSRecord("zone-example", "foreign-multi-host")).To(gomega.BeTrue())
	})

	ginkgo.It("reports an out-of-band configuration version conflict", func() {
		fixture := newTunnelFixture("version-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.SetConfigVersion(tunnel.Status.TunnelID, 8)
		gomega.Expect(applyGatewayTunnelVersion(&tunnel, 7, 7)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("ConfigurationChanged"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("orphans the remote Tunnel when deletionPolicy is Orphan", func() {
		fixture := newTunnelFixture("orphan", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		remoteID := tunnel.Status.TunnelID
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasTunnel(remoteID)).To(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
	})

	ginkgo.It("continues fail-closed teardown when the owning Gateway is already absent", func() {
		fixture := newTunnelFixture("owner-gone", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding,
		}})).To(gomega.Succeed())

		var gateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &gateway)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.gatewayKey, &gateway))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		replicas := int32(1)
		staleDataplane := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + fixture.gatewayKey.Name, Namespace: fixture.namespace,
				Labels: map[string]string{dataplaneGatewayLabel: fixture.namespace + "--" + fixture.gatewayKey.Name},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "stale-dataplane"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "stale-dataplane"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "placeholder", Image: "example.invalid/placeholder",
					}}},
				},
			},
		}
		gomega.Expect(testClient.Create(testContext, staleDataplane)).To(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var current v1alpha1.CloudflareTunnel
			err := testClient.Get(testContext, fixture.tunnelKey, &current)
			if apierrors.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("still deleting: gatewayRef=%v conditions=%v calls=%v", current.Status.GatewayRef, current.Status.Conditions, testTunnelCloudflare.Calls())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElements("DeleteDNSRecord", "DeleteTunnel"))
	})

	ginkgo.It("waits for dataplane drain when teardown has no hostname guards", func() {
		fixture := newTunnelFixture("empty-host-drain", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.Hostnames).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		replicas := int32(1)
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + fixture.gatewayKey.Name, Namespace: fixture.namespace,
				Labels: map[string]string{dataplaneGatewayLabel: fixture.namespace + "--" + fixture.gatewayKey.Name},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "drain-test"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "drain-test"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "placeholder", Image: "example.invalid/placeholder"}}},
				},
			},
		}
		gomega.Expect(testClient.Create(testContext, deployment)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			g.Expect(deleting.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation]).To(gomega.Equal("true"))
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Reason).To(gomega.Equal("WaitingForDrain"))
			g.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(deployment), deployment)).To(gomega.Succeed())
		before := deployment.DeepCopy()
		zero := int32(0)
		deployment.Spec.Replicas = &zero
		gomega.Expect(testClient.Patch(testContext, deployment, client.MergeFrom(before))).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
	})

	ginkgo.It("blocks teardown on a platform HostnameRoute that cross-references the tenant Tunnel", func() {
		fixture := newTunnelFixture("cross-ns-route", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		route := &v1alpha1.HostnameRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "platform-route-" + fixture.tunnelKey.Namespace, Namespace: "flareway-system"},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.account},
				Hostname:   "private." + fixture.hostname,
				TunnelRef: v1alpha1.NamespacedObjectReference{
					Name: fixture.tunnelKey.Name, Namespace: fixture.tunnelKey.Namespace,
				},
				DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.HostnameRoute
			return testClient.Get(testContext, client.ObjectKeyFromObject(route), &current) == nil
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("DependenciesRemain"))
			g.Expect(blocked.Message).To(gomega.ContainSubstring("HostnameRoute/flareway-system/" + route.Name))
			g.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.HostnameRoute
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(route), &current))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("DeleteTunnel"))
	})

	ginkgo.It("keeps the finalizer when remote Tunnel deletion fails and retries safely", func() {
		fixture := newTunnelFixture("delete-tunnel-failure", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.FailNext("DeleteTunnel", errors.New("injected Tunnel delete failure"))
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("TunnelDeleteFailed"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testTunnelCloudflare.ClearFailure("DeleteTunnel")
		gomega.Eventually(func() bool {
			var deleting v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &deleting))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
	})

	ginkgo.It("keeps the finalizer on DNS deletion failure and resumes the ordered teardown", func() {
		fixture := newTunnelFixture("delete", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding,
		}})).To(gomega.Succeed())
		testTunnelCloudflare.FailNext("DeleteDNSRecord", errors.New("injected DNS delete failure"))
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			g.Expect(deleting.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation]).To(gomega.Equal("true"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func() []string { return testTunnelCloudflare.Calls() }).WithTimeout(750 * time.Millisecond).ShouldNot(gomega.ContainElement("DeleteDNSRecord"))

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardBlocked,
		}})).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("DNSDeleteFailed"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
			g.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testTunnelCloudflare.ClearFailure("DeleteDNSRecord")
		gomega.Eventually(func() bool {
			var deleting v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &deleting))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())

		calls := testTunnelCloudflare.Calls()
		dnsDelete := slices.Index(calls, "DeleteDNSRecord")
		tunnelDelete := slices.Index(calls, "DeleteTunnel")
		gomega.Expect(dnsDelete).To(gomega.BeNumerically(">=", 0))
		gomega.Expect(tunnelDelete).To(gomega.BeNumerically(">", dnsDelete))
	})
})

type tunnelFixture struct {
	namespace  string
	account    string
	credential types.NamespacedName
	gatewayKey types.NamespacedName
	tunnelKey  types.NamespacedName
	hostname   string
	tunnel     *v1alpha1.CloudflareTunnel
}

func newTunnelFixture(prefix string, management v1alpha1.ManagementPolicy, dnsMode v1alpha1.DNSMode) *tunnelFixture {
	id := tunnelFixtureCounter.Add(1)
	namespace := fmt.Sprintf("tunnel-%s-%d", prefix, id)
	account := fmt.Sprintf("account-%d", id)
	gatewayName := "gateway"
	hostname := fmt.Sprintf("%s-%d.example.test", prefix, id)
	key := types.NamespacedName{Namespace: namespace, Name: "tunnel"}
	return &tunnelFixture{
		namespace: namespace, account: account,
		credential: types.NamespacedName{Namespace: namespace, Name: "cloudflare-token"},
		gatewayKey: types.NamespacedName{Namespace: namespace, Name: gatewayName},
		tunnelKey:  key, hostname: hostname,
		tunnel: &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: account},
				Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: fmt.Sprintf("remote-%d", id)},
				ManagementPolicy: management,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: dnsMode},
			},
		},
	}
}

func (f *tunnelFixture) create() {
	ginkgo.By("creating the namespace, credential, verified account, Gateway, and Tunnel")
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: f.namespace, Labels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace},
	}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeleteTunnelNamespace, f.namespace)
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: f.credential.Name, Namespace: f.credential.Namespace},
		Data:       map[string][]byte{"token": []byte("api-token")},
	})).To(gomega.Succeed())

	testAccountCloudflare.mu.Lock()
	testAccountCloudflare.zones = []flarecloudflare.Zone{{ID: "zone-example", Name: "example.test"}}
	testAccountCloudflare.mu.Unlock()

	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: f.account},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: fmt.Sprintf("%032x", tunnelFixtureCounter.Load()),
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: f.credential.Name, Namespace: f.credential.Namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace}},
				Hostnames:         []string{"*.example.test"}, Zones: []string{"example.test"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			}},
		},
	}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	gomega.Eventually(func() error {
		var current v1alpha1.CloudflareAccount
		if err := testClient.Get(testContext, types.NamespacedName{Name: f.account}, &current); err != nil {
			return err
		}
		current.Status.Verified.Zones = []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}}
		current.Status.Conditions = []metav1.Condition{{
			Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted",
			ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now(),
		}, {
			Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid",
			ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now(),
		}}
		return testClient.Status().Update(testContext, &current)
	}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

	hostname := gatewayv1.Hostname(f.hostname)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: f.gatewayKey.Name, Namespace: f.gatewayKey.Namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "unused-by-tunnel-controller",
			Listeners:        []gatewayv1.Listener{{Name: "public", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("CloudflareTunnel"), Name: f.tunnelKey.Name,
			}},
		},
	}
	gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
	gomega.Expect(testClient.Create(testContext, f.tunnel)).To(gomega.Succeed())
}

func ensureSystemNamespace(name string) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := testClient.Create(testContext, namespace)
	gomega.Expect(err).To(gomega.Or(gomega.Succeed(), gomega.MatchError(gomega.ContainSubstring("already exists"))))
}

func applyGatewayTunnelStatus(tunnel *v1alpha1.CloudflareTunnel, conditions []metav1.Condition, hostnames []v1alpha1.CloudflareTunnelHostnameStatus) error {
	conditionValues := make([]any, 0, len(conditions))
	for _, condition := range conditions {
		conditionValues = append(conditionValues, map[string]any{
			"type": condition.Type, "status": string(condition.Status), "reason": condition.Reason,
			"message": condition.Message, "observedGeneration": condition.ObservedGeneration,
			"lastTransitionTime": condition.LastTransitionTime.Format(time.RFC3339),
		})
	}
	hostnameValues := make([]any, 0, len(hostnames))
	for _, hostname := range hostnames {
		hostnameValues = append(hostnameValues, map[string]any{
			"hostname": hostname.Hostname, "protectionDomain": hostname.ProtectionDomain,
			"guard": string(hostname.Guard), "accessApplication": hostname.AccessApplication,
			"appliedVersion": hostname.AppliedVersion,
		})
	}
	status := map[string]any{"conditions": conditionValues, "hostnames": hostnameValues}
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(), "kind": "CloudflareTunnel",
		"metadata": map[string]any{"name": tunnel.Name, "namespace": tunnel.Namespace},
		"status":   status,
	}}
	return testClient.Status().Apply(testContext, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func applyGatewayTunnelVersion(tunnel *v1alpha1.CloudflareTunnel, desired, applied int64) error {
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(), "kind": "CloudflareTunnel",
		"metadata": map[string]any{"name": tunnel.Name, "namespace": tunnel.Namespace},
		"status": map[string]any{"configVersion": map[string]any{
			"desired": desired, "applied": applied, "desiredHash": fmt.Sprintf("version-%d", desired),
		}},
	}}
	return testClient.Status().Apply(testContext, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func forceDeleteTunnelNamespace(namespace string) {
	ctx := context.Background()
	var tunnels v1alpha1.CloudflareTunnelList
	if err := testClient.List(ctx, &tunnels, client.InNamespace(namespace)); err == nil {
		for i := range tunnels.Items {
			if len(tunnels.Items[i].Finalizers) == 0 {
				continue
			}
			before := tunnels.Items[i].DeepCopy()
			tunnels.Items[i].Finalizers = nil
			_ = testClient.Patch(ctx, &tunnels.Items[i], client.MergeFrom(before))
		}
	}
	_ = testClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
}

type fakeTunnelCloudflareFactory struct {
	mu sync.Mutex

	tunnels map[string]RemoteTunnel
	tokens  map[string]string
	configs map[string]int64
	dns     map[string]map[string]RemoteDNSRecord
	calls   []string
	fail    map[string]error
	before  map[string]func()
	next    int
}

func newFakeTunnelCloudflareFactory() *fakeTunnelCloudflareFactory {
	factory := &fakeTunnelCloudflareFactory{}
	factory.Reset()
	return factory
}

func (f *fakeTunnelCloudflareFactory) Client(_ string, _ string) (TunnelCloudflareClient, error) {
	return f, nil
}

func (f *fakeTunnelCloudflareFactory) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnels = map[string]RemoteTunnel{}
	f.tokens = map[string]string{}
	f.configs = map[string]int64{}
	f.dns = map[string]map[string]RemoteDNSRecord{}
	f.calls = nil
	f.fail = map[string]error{}
	f.before = map[string]func(){}
	f.next = 0
}

func (f *fakeTunnelCloudflareFactory) PutTunnel(tunnel RemoteTunnel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnels[tunnel.ID] = tunnel
	f.tokens[tunnel.ID] = "token-" + tunnel.ID
}

func (f *fakeTunnelCloudflareFactory) MarkTunnelDeleted(tunnelID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tunnel := f.tunnels[tunnelID]
	deletedAt := time.Now()
	tunnel.DeletedAt = &deletedAt
	tunnel.Status = "inactive"
	f.tunnels[tunnelID] = tunnel
}

func (f *fakeTunnelCloudflareFactory) SetConfigVersion(tunnelID string, version int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs[tunnelID] = version
}

func (f *fakeTunnelCloudflareFactory) HasTunnel(tunnelID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tunnels[tunnelID]
	return ok
}

func (f *fakeTunnelCloudflareFactory) HasDNSRecord(zoneID, recordID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.dns[zoneID][recordID]
	return ok
}

func (f *fakeTunnelCloudflareFactory) DNSRecord(zoneID, recordID string) (RemoteDNSRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.dns[zoneID][recordID]
	return record, ok
}

func (f *fakeTunnelCloudflareFactory) PutDNS(zone string, record RemoteDNSRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dns[zone] == nil {
		f.dns[zone] = map[string]RemoteDNSRecord{}
	}
	f.dns[zone][record.ID] = record
}

func (f *fakeTunnelCloudflareFactory) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func countCall(calls []string, operation string) int {
	count := 0
	for _, call := range calls {
		if call == operation {
			count++
		}
	}
	return count
}

func (f *fakeTunnelCloudflareFactory) FailNext(operation string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[operation] = err
}

func (f *fakeTunnelCloudflareFactory) ClearFailure(operation string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fail, operation)
}

func (f *fakeTunnelCloudflareFactory) Before(operation string, hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before[operation] = hook
}

func (f *fakeTunnelCloudflareFactory) record(operation string) error {
	f.calls = append(f.calls, operation)
	if hook := f.before[operation]; hook != nil {
		hook()
	}
	if err := f.fail[operation]; err != nil {
		return err
	}
	return nil
}

func (f *fakeTunnelCloudflareFactory) CreateTunnel(_ context.Context, name string) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateTunnel"); err != nil {
		return RemoteTunnel{}, err
	}
	f.next++
	id := fmt.Sprintf("tunnel-%d", f.next)
	tunnel := RemoteTunnel{ID: id, Name: name, Status: "healthy"}
	f.tunnels[id] = tunnel
	f.tokens[id] = "token-" + id
	return tunnel, nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnel(_ context.Context, tunnelID string) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnel"); err != nil {
		return RemoteTunnel{}, err
	}
	tunnel, ok := f.tunnels[tunnelID]
	if !ok {
		return RemoteTunnel{}, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	return tunnel, nil
}

func (f *fakeTunnelCloudflareFactory) DeleteTunnel(_ context.Context, tunnelID string, cascade bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !cascade {
		return errors.New("cascade must be true")
	}
	if err := f.record("DeleteTunnel"); err != nil {
		return err
	}
	delete(f.tunnels, tunnelID)
	delete(f.tokens, tunnelID)
	return nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnelToken(_ context.Context, tunnelID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelToken"); err != nil {
		return "", err
	}
	token, ok := f.tokens[tunnelID]
	if !ok {
		return "", fmt.Errorf("token for %s not found", tunnelID)
	}
	return token, nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnelConfigurationVersion(_ context.Context, tunnelID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelConfigurationVersion"); err != nil {
		return 0, err
	}
	return f.configs[tunnelID], nil
}

func (f *fakeTunnelCloudflareFactory) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateTunnelConfiguration"); err != nil {
		return 0, err
	}
	f.configs[tunnelID]++
	return f.configs[tunnelID], nil
}

func (f *fakeTunnelCloudflareFactory) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	return fn()
}

func (f *fakeTunnelCloudflareFactory) ListDNSRecords(_ context.Context, zoneID, name string) ([]RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListDNSRecords"); err != nil {
		return nil, err
	}
	var result []RemoteDNSRecord
	for _, record := range f.dns[zoneID] {
		if strings.EqualFold(record.Name, name) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (f *fakeTunnelCloudflareFactory) CreateCNAME(_ context.Context, zoneID string, input RemoteDNSRecordInput) (RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateCNAME"); err != nil {
		return RemoteDNSRecord{}, err
	}
	f.next++
	record := RemoteDNSRecord{ID: fmt.Sprintf("record-%d", f.next), Name: input.Name, Type: "CNAME", Content: input.Content, Comment: input.Comment, Tags: append([]string(nil), input.Tags...), Proxied: input.Proxied}
	if f.dns[zoneID] == nil {
		f.dns[zoneID] = map[string]RemoteDNSRecord{}
	}
	f.dns[zoneID][record.ID] = record
	return record, nil
}

func (f *fakeTunnelCloudflareFactory) UpdateCNAME(_ context.Context, zoneID, recordID string, input RemoteDNSRecordInput) (RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateCNAME"); err != nil {
		return RemoteDNSRecord{}, err
	}
	record := RemoteDNSRecord{ID: recordID, Name: input.Name, Type: "CNAME", Content: input.Content, Comment: input.Comment, Tags: append([]string(nil), input.Tags...), Proxied: input.Proxied}
	f.dns[zoneID][recordID] = record
	return record, nil
}

func (f *fakeTunnelCloudflareFactory) DeleteDNSRecord(_ context.Context, zoneID, recordID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DeleteDNSRecord"); err != nil {
		return err
	}
	delete(f.dns[zoneID], recordID)
	return nil
}

var _ TunnelCloudflareClient = (*fakeTunnelCloudflareFactory)(nil)
