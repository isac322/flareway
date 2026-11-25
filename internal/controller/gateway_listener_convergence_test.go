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
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
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
	for _, state := range []string{"missing", dnsRecordStateConflict, "Unknown"} {
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

func TestAccessBlockFirstTransitionKeepsGatewayAndListenerPending(t *testing.T) {
	gateway := listenerConvergenceGateway()
	tunnel := persistListenerConvergence(t, gateway)
	tunnel.Spec.DNS.Mode = v1alpha1.DNSModeManaged
	tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{
		{Hostname: "a.example.com", State: dnsRecordStateReady},
		{Hostname: "b.example.com", State: dnsRecordStateReady},
	}
	gateway.Domains[1].Access.AUDs = []string{"new-aud"}
	prepared, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || prepared.Domains[1].BlockReason != ir.BlockReasonAccessTransition {
		t.Fatalf("expected AccessTransition block reason, got transitioning=%t reason=%q", transitioning, prepared.Domains[1].BlockReason)
	}
	status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{
		{Name: "a", Conditions: []metav1.Condition{{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue}}},
		{Name: "b", Conditions: []metav1.Condition{{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue}}},
	}}
	reconciler := &GatewayReconciler{}
	reconciler.setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, prepared, tunnel, true, "Waiting for Access block-first transition", privatePrerequisiteResult{})
	if got := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)); got == nil || got.Status != metav1.ConditionFalse || got.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Fatalf("Gateway must remain Programmed=False (Pending) while publishing 403 block-first snapshot: %#v", got)
	}
	if gotA := meta.FindStatusCondition(status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed)); gotA == nil || gotA.Status != metav1.ConditionTrue {
		t.Fatalf("unaffected listener a Programmed = %#v, want True", gotA)
	}
	if gotB := meta.FindStatusCondition(status.Listeners[1].Conditions, string(gatewayv1.ListenerConditionProgrammed)); gotB == nil || gotB.Status != metav1.ConditionFalse || !strings.Contains(gotB.Message, "block-first") {
		t.Fatalf("transitioning listener b Programmed = %#v, want False with block-first message", gotB)
	}

	// Once the blocked snapshot checkpoints, the next reconcile releases b to Forwarding and Programmed=True.
	tunnel = persistListenerConvergence(t, prepared)
	tunnel.Spec.DNS.Mode = v1alpha1.DNSModeManaged
	tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{
		{Hostname: "a.example.com", State: dnsRecordStateReady},
		{Hostname: "b.example.com", State: dnsRecordStateReady},
	}
	released, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning || released.Domains[1].Guard != ir.GuardForwarding {
		t.Fatalf("expected release to Forwarding, got transitioning=%t guard=%q", transitioning, released.Domains[1].Guard)
	}
	reconciler.setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, released, tunnel, true, "ready", privatePrerequisiteResult{})
	if got := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)); got == nil || got.Status != metav1.ConditionTrue {
		t.Fatalf("Gateway did not promote to Programmed=True after transition completed: %#v", got)
	}
}

func TestManagedDNSNormalizesTrailingDotsAndIDN(t *testing.T) {
	records := []v1alpha1.CloudflareTunnelDNSRecordStatus{
		{Hostname: "xn--bcher-kva.example.", State: dnsRecordStateReady},
	}
	ready := managedDNSReadiness(records)
	if !ready["xn--bcher-kva.example"] {
		t.Fatalf("expected normalized IDN punycode record ready, got %#v", ready)
	}
	gw := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "acct"},
		Listeners:  []ir.Listener{{Name: "idn", Hostname: "Bücher.EXAMPLE.", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "idn", ListenerName: "idn", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
			VirtualHosts: []ir.VirtualHost{{Hostname: "bücher.example"}},
		}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{DNSRecords: records}}
	if !publicDNSReady(gw, tunnel) {
		t.Fatal("publicDNSReady did not normalize Unicode IDN / trailing dot")
	}
	blockDomainsForUnreadyDNS(gw, tunnel)
	if gw.Domains[0].Guard == ir.GuardBlocked {
		t.Fatal("normalized ready IDN listener was unexpectedly blocked")
	}
}

func TestGatewayReconcilerTimeoutAndStopsSteady2sPolling(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, gatewayv1.Install, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	const accountID = "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	hostA := gatewayv1.Hostname("a.example.com")
	hostB := gatewayv1.Hostname("b.example.com")
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default", UID: "gw-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "edge",
			}},
			Listeners: []gatewayv1.Listener{
				{Name: "a", Hostname: &hostA, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "b", Hostname: &hostB, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	class := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cf-token", Namespace: "default", Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{},
				Hostnames:            []string{"*.example.com"},
				Zones:                []string{"example.com"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*.example.com"},
			}},
		},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default", UID: "tunnel-uid", Generation: 1},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeManaged},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:                "tunnel-id",
			AccountID:               accountID,
			OwnershipVerified:       true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: "edge"},
			GatewayUID:              "gw-uid",
			DNSRecords: []v1alpha1.CloudflareTunnelDNSRecordStatus{
				{Hostname: "a.example.com", ZoneID: "zone", RecordID: "rec-a", State: dnsRecordStateReady},
				{Hostname: "b.example.com", ZoneID: "zone", State: dnsRecordStateConflict},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dp-0", Namespace: "default", UID: "pod-uid",
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: "edge"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.2"},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &v1alpha1.CloudflareTunnel{}, &appsv1.Deployment{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cf-token", Namespace: "default"}, Data: map[string][]byte{"token": []byte("tok")}},
			class, account, gateway, tunnel, pod,
		).
		Build()
	remote := &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 0}
	snapshots := newFakeSnapshotPublisher()
	reconciler := &GatewayReconciler{
		Client: kube, APIReader: kube, Scheme: scheme,
		Snapshots:         snapshots,
		CloudflareFactory: gatewayCloudflareFactory{api: remote},
		Prober:            &staticGatewayProber{version: 1, ready: true},
		Now:               func() time.Time { return now },
	}
	reconciler.BuildSnapshot = translator.Build
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "edge"}}

	// Pass 1 pushes version 1 to Cloudflare and publishes the xDS snapshot.
	// Acknowledge xDS right after so Pass 2 sees full data-plane convergence.
	res1, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("pass 1 reconcile: %v", err)
	}
	if res1.RequeueAfter != programmedRequeue {
		t.Fatalf("pass 1 RequeueAfter = %v, want %v while waiting on xDS ACK", res1.RequeueAfter, programmedRequeue)
	}
	if err := snapshots.ACK("default/edge"); err != nil {
		t.Fatalf("ACK snapshot: %v", err)
	}

	// Pass 2: data plane converged (ConfigApplied=True), only DNSConflict remains.
	// Waiting message must appear without false timeout, and RequeueAfter schedules
	// the 30s timeout transition rather than spinning every 2s.
	res2, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("pass 2 reconcile: %v", err)
	}
	if res2.RequeueAfter != cloudflareConvergenceTimeout {
		t.Fatalf("pass 2 RequeueAfter = %v, want %v", res2.RequeueAfter, cloudflareConvergenceTimeout)
	}
	var gw gatewayv1.Gateway
	if err := kube.Get(ctx, req.NamespacedName, &gw); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if cond == nil || cond.Status != metav1.ConditionFalse || !strings.HasPrefix(cond.Message, "Waiting for Cloudflare programming gate:") {
		t.Fatalf("pass 2 Programmed = %#v, want Waiting message", cond)
	}

	// Advance clock by 30s -> message must switch to "Timed out after 30s..."
	// and steady-state RequeueAfter must stop polling every 2s.
	now = now.Add(cloudflareConvergenceTimeout)
	res3, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("pass 3 reconcile: %v", err)
	}
	if res3.RequeueAfter != 0 {
		t.Fatalf("pass 3 RequeueAfter = %v, want 0 (no 2s storm after timeout)", res3.RequeueAfter)
	}
	if err := kube.Get(ctx, req.NamespacedName, &gw); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if cond == nil || cond.Status != metav1.ConditionFalse || !strings.HasPrefix(cond.Message, "Timed out after 30s waiting for Cloudflare programming gate:") {
		t.Fatalf("pass 3 Programmed = %#v, want Timed out after 30s", cond)
	}
}

