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
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func listenerConvergenceGateway() *ir.Gateway {
	return &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners: []ir.Listener{
			{Name: "a", Hostname: "a.example.com", Exposure: ir.ExposurePublic},
			{Name: "b", Hostname: "b.example.com", Exposure: ir.ExposurePublic},
		},
		Domains: []ir.ProtectionDomain{
			{Name: "a-protected", ListenerName: "a", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding, AccessApplication: "apps/a",
				Access:       &ir.AccessGuard{AUDs: []string{"a-aud"}, TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
				VirtualHosts: []ir.VirtualHost{{Hostname: "a.example.com"}}},
			{Name: "b-protected", ListenerName: "b", EnvoyPort: 18082, Protected: true, Guard: ir.GuardForwarding, AccessApplication: "apps/b",
				Access:       &ir.AccessGuard{AUDs: []string{"b-aud"}, TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
				VirtualHosts: []ir.VirtualHost{{Hostname: "b.example.com"}}},
		},
	}
}

func persistListenerConvergence(t *testing.T, gateway *ir.Gateway) *v1alpha1.CloudflareTunnel {
	t.Helper()
	_, hash, err := cloudflaredconfig.Compile(gateway)
	if err != nil {
		t.Fatal(err)
	}
	return &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{DesiredHash: hash, Desired: 7, Applied: 7},
		Hostnames:     desiredTunnelHostnames(gateway, 7),
	}}
}

func TestAccessBindingUnrelatedRouteChangeKeepsForwarding(t *testing.T) {
	gateway := listenerConvergenceGateway()
	tunnel := persistListenerConvergence(t, gateway)
	gateway.Domains[1].IngressPaths = []ir.PathMatch{{Type: ir.PathMatchPathPrefix, Value: "/changed"}}
	prepared, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning {
		t.Fatal("route-only change entered an Access transition")
	}
	for _, host := range []string{"a.example.com", "b.example.com"} {
		if got := firstEdgeService(t, prepared, host); got == "http_status:403" {
			t.Fatalf("unchanged Access binding for %s was blocked", host)
		}
	}
}

func TestAccessBindingChangesBlockOnlyAffectedDomain(t *testing.T) {
	for _, test := range []struct {
		name    string
		private bool
		mutate  func(*ir.ProtectionDomain)
	}{
		{name: "AUD", mutate: func(domain *ir.ProtectionDomain) { domain.Access.AUDs = []string{"replacement-aud"} }},
		{name: "AuthDomain", mutate: func(domain *ir.ProtectionDomain) { domain.Access.AuthDomain = "replacement.cloudflareaccess.com" }},
		{name: "Preflight", mutate: func(domain *ir.ProtectionDomain) { domain.Access.OptionsPreflightBypass = true }},
		{name: "PrivateAUD", private: true, mutate: func(domain *ir.ProtectionDomain) { domain.Access.AUDs = []string{"replacement-aud"} }},
		{name: "DomainMove", mutate: func(domain *ir.ProtectionDomain) { domain.Name = "moved-domain" }},
		{name: "ApplicationReplacement", mutate: func(domain *ir.ProtectionDomain) { domain.AccessApplication = "apps/replacement" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := listenerConvergenceGateway()
			if test.private {
				gateway.Listeners[1].Exposure = ir.ExposurePrivate
			}
			tunnel := persistListenerConvergence(t, gateway)
			test.mutate(&gateway.Domains[1])
			prepared, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			if !transitioning || prepared.Domains[1].Guard != ir.GuardBlocked {
				t.Fatal("changed Access binding did not publish a denial first")
			}
			if got := firstEdgeService(t, prepared, "a.example.com"); got == "http_status:403" {
				t.Fatal("sibling listener's unchanged binding was blocked")
			}
			if !test.private && firstEdgeService(t, prepared, "b.example.com") != "http_status:403" {
				t.Fatal("affected public host still forwards in the cloudflared configuration")
			}
			// Checkpoint exactly the blocked configuration, then let the next
			// reconcile activate the desired binding without another denial.
			tunnel = persistListenerConvergence(t, prepared)
			released, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			if transitioning || released.Domains[1].Guard != ir.GuardForwarding {
				t.Fatal("applied denial did not release the new binding")
			}
		})
	}
}

func TestAccessBindingLegacyStatusMigratesOnce(t *testing.T) {
	gateway := listenerConvergenceGateway()
	tunnel := persistListenerConvergence(t, gateway)
	for i := range tunnel.Status.Hostnames {
		tunnel.Status.Hostnames[i].AccessBinding = ""
	}
	// An old Blocked guard also lacks proof of the intended binding.
	tunnel.Status.Hostnames[1].Guard = v1alpha1.HostnameGuardBlocked
	blocked, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || firstEdgeService(t, blocked, "a.example.com") != "http_status:403" || firstEdgeService(t, blocked, "b.example.com") != "http_status:403" {
		t.Fatal("legacy status did not undergo a one-time fail-closed migration")
	}
	tunnel = persistListenerConvergence(t, blocked)
	released, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning || firstEdgeService(t, released, "a.example.com") == "http_status:403" || firstEdgeService(t, released, "b.example.com") == "http_status:403" {
		t.Fatal("checkpointed migration denial did not release forwarding")
	}
}

func TestAccessBindingSharedPrivateDomainRemainsBuildable(t *testing.T) {
	gateway := listenerConvergenceGateway()
	gateway.Listeners = gateway.Listeners[:1]
	gateway.Listeners[0].Exposure = ir.ExposurePrivate
	gateway.Listeners[0].Port = 8443
	gateway.Domains = gateway.Domains[:1]
	tunnel := persistListenerConvergence(t, gateway)
	// Translation emits host fragments that share a private route table.
	newHost := gateway.Domains[0]
	newHost.VirtualHosts = []ir.VirtualHost{{Hostname: "new.example.com"}}
	gateway.Domains = append(gateway.Domains, newHost)
	prepared, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning {
		t.Fatal("new protected hostname did not enter a block-first transition")
	}
	if _, err := translator.Build(prepared, defaultGatewayClassConfig()); err != nil {
		t.Fatalf("prepared protection-domain denial cannot be published to Envoy: %v", err)
	}
}

func TestDisabledOriginJWTBindingCompletesHandshake(t *testing.T) {
	gateway := listenerConvergenceGateway()
	gateway.Domains[1].OriginJWTDisabled = true
	gateway.Domains[1].Access = nil
	tunnel := &v1alpha1.CloudflareTunnel{}
	blocked, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || firstEdgeService(t, blocked, "b.example.com") != "http_status:403" {
		t.Fatal("new disabled-origin binding skipped its initial denial")
	}
	tunnel = persistListenerConvergence(t, blocked)
	released, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning || firstEdgeService(t, released, "b.example.com") == "http_status:403" {
		t.Fatal("applied disabled-origin denial did not release forwarding")
	}
}

func TestManagedDNSFailureDeniesOnlyAffectedListener(t *testing.T) {
	for _, state := range []string{"missing", dnsRecordStateConflict} {
		t.Run(state, func(t *testing.T) {
			gateway := listenerConvergenceGateway()
			// Listener A is already serving when listener B is added with
			// a missing or foreign managed record, as in issue #135.
			existing := *gateway
			existing.Listeners = gateway.Listeners[:1]
			existing.Domains = gateway.Domains[:1]
			tunnel := persistListenerConvergence(t, &existing)
			tunnel.Spec.DNS.Mode = v1alpha1.DNSModeManaged
			tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "a.example.com", State: dnsRecordStateReady}}
			if state != "missing" {
				tunnel.Status.DNSRecords = append(tunnel.Status.DNSRecords, v1alpha1.CloudflareTunnelDNSRecordStatus{Hostname: "b.example.com", State: state})
			}
			prepared, _, err := accessBlockFirstGateway(gateway, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			blockDomainsForUnreadyDNS(prepared, tunnel)
			if service := firstEdgeService(t, prepared, "a.example.com"); service == "http_status:403" {
				t.Fatal("sibling listener's managed DNS failure interrupted the healthy host")
			}
			if service := firstEdgeService(t, prepared, "b.example.com"); service != "http_status:403" {
				t.Fatalf("listener without ready managed DNS still forwards: %s", service)
			}
			readiness := cloudflareListenerReadiness(prepared, tunnel, true)
			if !readiness["a"] || readiness["b"] || publicDNSReady(prepared, tunnel) {
				t.Fatalf("per-listener DNS readiness = %#v; Gateway must remain pending", readiness)
			}

			// Persist the active denial, repair DNS, and release only this host.
			tunnel.Status.Hostnames = desiredTunnelHostnames(prepared, 8)
			tunnel.Status.DNSRecords = append(tunnel.Status.DNSRecords[:1], v1alpha1.CloudflareTunnelDNSRecordStatus{Hostname: "b.example.com", State: dnsRecordStateReady})
			repaired := listenerConvergenceGateway()
			released, _, err := accessBlockFirstGateway(repaired, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			blockDomainsForUnreadyDNS(released, tunnel)
			if firstEdgeService(t, released, "b.example.com") == "http_status:403" {
				t.Fatal("DNS recovery did not release the affected host")
			}
		})
	}
}

func TestExternalDNSDoesNotRequireManagedRecords(t *testing.T) {
	gateway := listenerConvergenceGateway()
	tunnel := persistListenerConvergence(t, gateway)
	tunnel.Spec.DNS.Mode = v1alpha1.DNSModeExternal
	blockDomainsForUnreadyDNS(gateway, tunnel)
	for _, host := range []string{"a.example.com", "b.example.com"} {
		if firstEdgeService(t, gateway, host) == "http_status:403" {
			t.Fatalf("external DNS mode incorrectly blocked %s for missing managed records", host)
		}
	}
}

func TestCloudflareListenerProgrammedIndependentOfGlobalDNS(t *testing.T) {
	status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{
		{Name: "a", Conditions: []metav1.Condition{{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue}}},
		{Name: "b", Conditions: []metav1.Condition{{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue}}},
	}}
	reconciler := &GatewayReconciler{}
	compiled := listenerConvergenceGateway()
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{DNSRecords: []v1alpha1.CloudflareTunnelDNSRecordStatus{
		{Hostname: "a.example.com", State: dnsRecordStateReady},
		{Hostname: "b.example.com", State: dnsRecordStateConflict},
	}}}
	reconciler.setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, compiled, tunnel, true, "Waiting for managed DNS records", privatePrerequisiteResult{})
	if got := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)); got == nil || got.Status != metav1.ConditionFalse {
		t.Fatal("Gateway should remain unprogrammed until every required DNS record is ready")
	}
	for i, want := range []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse} {
		got := meta.FindStatusCondition(status.Listeners[i].Conditions, string(gatewayv1.ListenerConditionProgrammed))
		if got == nil || got.Status != want {
			t.Fatalf("listener %s Programmed = %#v, want %s", status.Listeners[i].Name, got, want)
		}
	}
	if got := meta.FindStatusCondition(status.Listeners[1].Conditions, string(gatewayv1.ListenerConditionProgrammed)); got.Reason != "DNSConflict" {
		t.Fatalf("conflicted listener Programmed reason = %s, want DNSConflict", got.Reason)
	}
}
