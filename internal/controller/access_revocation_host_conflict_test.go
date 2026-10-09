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
	"strings"
	"testing"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	cloudflaredconfig "github.com/isac322/flareway/internal/cloudflared"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

const (
	conflictHost          = "api.example.com"
	conflictTombstoneName = "https-access-default-app-a"
)

// hostConflictInputs models a Gateway listener "https" serving
// api.example.com. AccessApplication app-a protected that host, was then
// retargeted to a missing section and latched for revocation, so it keeps the
// host as a Blocked tombstone on tombstonePort. app-b now protects the same
// host on the same listener. With private set, "https" is a private TLS
// listener whose domains all bind its fixed port 443; otherwise it is a
// public listener and the tombstone holds a positional Access port.
func hostConflictInputs(t *testing.T, private bool, tombstonePort int32) gatewayapi.Inputs {
	t.Helper()
	inputs := revokedTombstoneInputs(tombstonePort)
	host := gatewayv1.Hostname(conflictHost)
	listener := gatewayv1.Listener{Name: "https", Hostname: &host, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}
	grant := &inputs.CloudflareAccount.Spec.Grants[0]
	grant.Hostnames = append(grant.Hostnames, conflictHost)
	if private {
		gomega.RegisterTestingT(t)
		listener.TLS = &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}}
		inputs.Secrets = []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: "private-cert", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       qa92TLSSecretData(t),
		}}
		grant.Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
		inputs.CloudflareTunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
			Name: "https", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "private"},
		}}
		inputs.CloudflareTunnel.Spec.AccountRef = corev1.LocalObjectReference{Name: "account"}
		inputs.VirtualNetworks = []v1alpha1.VirtualNetwork{{
			ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: "default"},
			Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
			Status: v1alpha1.VirtualNetworkStatus{
				VirtualNetworkID: "vnet-private",
				Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
			},
		}}
	}
	inputs.Gateway.Spec.Listeners = []gatewayv1.Listener{listener}
	route := &inputs.HTTPRoutes[0]
	route.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("https"))
	route.Spec.Hostnames = []gatewayv1.Hostname{host}

	appA := &inputs.AccessApplications[0]
	appA.Annotations = map[string]string{accessApplicationRevocationAnnotation: `{"claims":[]}`}
	appA.Spec.TargetRefs[0].SectionName = new(gatewayv1.SectionName("gone"))
	appA.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
		Tunnel: "edge", Listener: "https", ProtectionDomain: conflictTombstoneName, EnvoyPort: tombstonePort,
	}}
	appA.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{Hostname: conflictHost}}
	appB := &inputs.AccessApplications[1]
	appB.Spec.TargetRefs[0].SectionName = new(gatewayv1.SectionName("https"))
	appB.Spec.OriginJWT.AssumeGatewayTLSDecryption = true
	// The tunnel already reports app-a's host Blocked, but the latch is not
	// cleared yet, so the tombstone is still retained.
	inputs.CloudflareTunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
		Hostname: conflictHost, ProtectionDomain: conflictTombstoneName, AccessApplication: "default/app-a",
		Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 3,
	}}
	return inputs
}

// wildcardHostConflictInputs serves both api.example.com and b.example.com on
// the public "https" listener, which the account grants as unprotected. app-a's
// tombstone holds api.example.com; app-b protects the whole listener.
func wildcardHostConflictInputs(t *testing.T) gatewayapi.Inputs {
	t.Helper()
	inputs := hostConflictInputs(t, false, 18090)
	inputs.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("*.example.com"))
	other := *inputs.HTTPRoutes[0].DeepCopy()
	other.Name = "other-route"
	other.Spec.Hostnames = []gatewayv1.Hostname{"b.example.com"}
	inputs.HTTPRoutes = append(inputs.HTTPRoutes, other)
	inputs.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
	return inputs
}

func appBCompilation(statuses gatewayapi.Statuses) gatewayapi.AccessApplicationCompilation {
	return statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "app-b"}]
}

// hostDomains returns every protection domain serving host.
func hostDomains(gateway *ir.Gateway, host string) []ir.ProtectionDomain {
	domains := make([]ir.ProtectionDomain, 0)
	for _, domain := range gateway.Domains {
		for _, virtualHost := range domain.VirtualHosts {
			if virtualHost.Hostname == host {
				domains = append(domains, domain)
				break
			}
		}
	}
	return domains
}

// firstEdgeService returns the service of the first cloudflared ingress rule
// for host, which is the rule the edge applies to it.
func firstEdgeService(t *testing.T, gateway *ir.Gateway, host string) string {
	t.Helper()
	request, _, err := cloudflaredconfig.Compile(gateway)
	if err != nil {
		t.Fatalf("compile cloudflared config: %v", err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal cloudflared config: %v", err)
	}
	var decoded struct {
		Config struct {
			Ingress []struct {
				Hostname string `json:"hostname"`
				Service  string `json:"service"`
			} `json:"ingress"`
		} `json:"config"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode cloudflared config: %v", err)
	}
	for _, rule := range decoded.Config.Ingress {
		if rule.Hostname == host {
			return rule.Service
		}
	}
	t.Fatalf("no cloudflared ingress rule for %s in %#v", host, decoded.Config.Ingress)
	return ""
}

// assertHostHeldByTombstone checks that only Blocked domains serve
// api.example.com, among them app-a's tombstone on the port it holds.
func assertHostHeldByTombstone(t *testing.T, gateway *ir.Gateway, port int32) {
	t.Helper()
	tombstone := false
	for _, domain := range hostDomains(gateway, conflictHost) {
		if domain.Guard != ir.GuardBlocked {
			t.Fatalf("%s served by %s domain %s while a tombstone holds it", conflictHost, domain.Guard, domain.Name)
		}
		if domain.AccessApplication == "default/app-a" && domain.Name == conflictTombstoneName && domain.EnvoyPort == port {
			tombstone = true
		}
	}
	if !tombstone {
		t.Fatalf("no Blocked tombstone %s on %d among %#v", conflictTombstoneName, port, hostDomains(gateway, conflictHost))
	}
}

// assertAppBHeldOff checks that app-b stays accepted, that every domain it
// compiles for api.example.com is Blocked, and that its status names the
// revoked application holding the host.
func assertAppBHeldOff(t *testing.T, gateway *ir.Gateway, statuses gatewayapi.Statuses, port int32) {
	t.Helper()
	compiled := appBCompilation(statuses)
	if !compiled.Accepted || !strings.Contains(compiled.Message, "default/app-a") || !strings.Contains(compiled.Message, conflictHost) {
		t.Fatalf("app-b compilation = accepted %t reason %q message %q, want Accepted naming default/app-a and %s", compiled.Accepted, compiled.Reason, compiled.Message, conflictHost)
	}
	held := false
	for _, domain := range hostDomains(gateway, conflictHost) {
		held = held || domain.AccessApplication == "default/app-b"
	}
	if !held {
		t.Fatalf("app-b compiled no domain for %s", conflictHost)
	}
	assertHostHeldByTombstone(t, gateway, port)
}

func assertAppBForwarding(t *testing.T, gateway *ir.Gateway, statuses gatewayapi.Statuses) {
	t.Helper()
	if compiled := appBCompilation(statuses); !compiled.Accepted || strings.Contains(compiled.Message, "revocation") {
		t.Fatalf("app-b compilation = accepted %t %q %q, want Accepted with no revocation hold", compiled.Accepted, compiled.Reason, compiled.Message)
	}
	if live := domainOf(gateway, "default/app-b"); live == nil || live.Guard != ir.GuardForwarding {
		t.Fatalf("app-b live domain = %#v, want Forwarding", live)
	}
}

// A revoked application's tombstone and another application's live domain on
// one private host would add two filter chains for the listener's server
// name. The host stays Blocked for both until the revocation is acknowledged,
// so they share one chain and the snapshot builds (isac322/flareway#143).
func TestRevokedAccessTombstoneHoldsPrivateHost(t *testing.T) {
	gateway, statuses := buildRevokedGateway(t, hostConflictInputs(t, true, 443))
	assertAppBHeldOff(t, gateway, statuses, 443)
}

// A deleting application keeps its tombstone the same way a latched one does.
func TestDeletingAccessTombstoneHoldsPrivateHost(t *testing.T) {
	inputs := hostConflictInputs(t, true, 443)
	appA := &inputs.AccessApplications[0]
	appA.Annotations = nil
	appA.DeletionTimestamp = new(metav1.NewTime(inputs.Now.Add(-1)))
	appA.Finalizers = []string{"flareway.bhyoo.com/access-application"}
	gateway, statuses := buildRevokedGateway(t, inputs)
	assertAppBHeldOff(t, gateway, statuses, 443)
}

// Once the latch clears, no tombstone holds the host and app-b forwards it.
func TestClearedAccessRevocationReleasesPrivateHost(t *testing.T) {
	inputs := hostConflictInputs(t, true, 443)
	inputs.AccessApplications[0].Annotations = nil
	gateway, statuses := buildRevokedGateway(t, inputs)
	if tombstone := domainOf(gateway, "default/app-a"); tombstone != nil {
		t.Fatalf("cleared revocation kept a tombstone: %#v", tombstone)
	}
	assertAppBForwarding(t, gateway, statuses)
}

// The hold does not depend on exposure: a public tombstone keeps another
// application from forwarding its host at the edge as well.
func TestRevokedAccessTombstoneHoldsPublicHost(t *testing.T) {
	gateway, statuses := buildRevokedGateway(t, hostConflictInputs(t, false, 18081))
	assertAppBHeldOff(t, gateway, statuses, 18081)
	if service := firstEdgeService(t, gateway, conflictHost); service != "http_status:403" {
		t.Fatalf("first edge rule for %s = %s, want http_status:403", conflictHost, service)
	}
}

// A route left on a listener that permits unprotected traffic must not serve
// a tombstone-held host as public: the edge would match its forwarding rule
// before the tombstone's 403.
func TestRevokedAccessTombstoneHostNeverServedUnprotected(t *testing.T) {
	inputs := wildcardHostConflictInputs(t)
	inputs.AccessApplications = inputs.AccessApplications[:1]
	gateway, _ := buildRevokedGateway(t, inputs)
	assertHostHeldByTombstone(t, gateway, 18090)
	if service := firstEdgeService(t, gateway, conflictHost); service != "http_status:403" {
		t.Fatalf("first edge rule for %s = %s, want http_status:403", conflictHost, service)
	}
	if service := firstEdgeService(t, gateway, "b.example.com"); service == "http_status:403" {
		t.Fatalf("b.example.com is blocked although no tombstone holds it")
	}
}

// app-b protects every host on the listener. The tombstone holds only
// api.example.com, so app-b's other host keeps exactly the protection it has
// without a tombstone: Forwarding behind Access once its AUD is ready, and
// Blocked before that. Neither host ever falls back to the listener's
// unprotected guard.
func TestRevokedAccessTombstoneKeepsOtherHostsProtected(t *testing.T) {
	for name, audReady := range map[string]bool{"aud ready": true, "aud missing": false} {
		t.Run(name, func(t *testing.T) {
			inputs := wildcardHostConflictInputs(t)
			if !audReady {
				inputs.AUDSecrets = nil
			}
			gateway, statuses := buildRevokedGateway(t, inputs)
			assertAppBHeldOff(t, gateway, statuses, 18090)
			if service := firstEdgeService(t, gateway, conflictHost); service != "http_status:403" {
				t.Fatalf("first edge rule for %s = %s, want http_status:403", conflictHost, service)
			}
			other := hostDomains(gateway, "b.example.com")
			if len(other) != 1 || other[0].AccessApplication != "default/app-b" || !other[0].Protected {
				t.Fatalf("b.example.com domains = %#v, want one app-b protected domain", other)
			}
			want := ir.GuardBlocked
			if audReady {
				want = ir.GuardForwarding
				if other[0].Access == nil || len(other[0].Access.AUDs) == 0 {
					t.Fatalf("b.example.com forwards without an Access guard: %#v", other[0])
				}
			}
			if other[0].Guard != want {
				t.Fatalf("b.example.com guard = %s, want %s", other[0].Guard, want)
			}
		})
	}
}

// A tombstone holds only its own hostnames on its own listener: app-b may
// forward another host on that listener or the same host on another listener.
func TestRevokedAccessTombstoneLeavesOtherHostsForwarding(t *testing.T) {
	t.Run("other host on the tombstone listener", func(t *testing.T) {
		inputs := hostConflictInputs(t, false, 18081)
		wildcard := gatewayv1.Hostname("*.example.com")
		inputs.Gateway.Spec.Listeners[0].Hostname = &wildcard
		inputs.HTTPRoutes[0].Spec.Hostnames = []gatewayv1.Hostname{"b.example.com"}
		gateway, statuses := buildRevokedGateway(t, inputs)
		assertTombstoneOnHost(t, gateway)
		assertAppBForwarding(t, gateway, statuses)
	})
	t.Run("same host on another listener", func(t *testing.T) {
		inputs := hostConflictInputs(t, false, 18081)
		inputs.AccessApplications[0].Status.DataPlanes[0].Listener = "old"
		gateway, statuses := buildRevokedGateway(t, inputs)
		assertTombstoneOnHost(t, gateway)
		assertAppBForwarding(t, gateway, statuses)
	})
}

// A latched application can compile its host again under a different domain
// name than the one its status records, so its own tombstone and its live
// domain serve the same host. The live domain stays Blocked until the
// revocation is acknowledged, even with the application's AUD ready, and its
// status names no other holder.
func TestRevokedAccessTombstoneBlocksOwnRenamedDomain(t *testing.T) {
	inputs := hostConflictInputs(t, false, 18081)
	inputs.AccessApplications = inputs.AccessApplications[:1]
	inputs.AccessApplications[0].Spec.TargetRefs[0].SectionName = new(gatewayv1.SectionName("https"))
	inputs.AUDSecrets[types.NamespacedName{Namespace: "default", Name: "app-a"}] = gatewayapi.AUDSecret{AUD: "aud-a", ApplicationID: "app-a-id", Ready: true}
	gateway, statuses := buildRevokedGateway(t, inputs)
	compiled := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "app-a"}]
	if !compiled.Accepted || strings.Contains(compiled.Message, "revocation") {
		t.Fatalf("app-a compilation = accepted %t %q %q, want Accepted with no other holder", compiled.Accepted, compiled.Reason, compiled.Message)
	}
	domains := hostDomains(gateway, conflictHost)
	if len(domains) != 2 {
		t.Fatalf("%s domains = %#v, want app-a's live domain and its tombstone", conflictHost, domains)
	}
	assertHostHeldByTombstone(t, gateway, 18081)
	if service := firstEdgeService(t, gateway, conflictHost); service != "http_status:403" {
		t.Fatalf("first edge rule for %s = %s, want http_status:403", conflictHost, service)
	}
}

func assertTombstoneOnHost(t *testing.T, gateway *ir.Gateway) {
	t.Helper()
	tombstone := domainOf(gateway, "default/app-a")
	if tombstone == nil || tombstone.Guard != ir.GuardBlocked || len(tombstone.VirtualHosts) != 1 || tombstone.VirtualHosts[0].Hostname != conflictHost {
		t.Fatalf("revocation tombstone = %#v, want Blocked on %s", tombstone, conflictHost)
	}
}

// Before the tunnel reports a revoked application's hosts, its tombstone falls
// back to the destinations the application recorded. Only destinations its
// public data plane can have served are held there: a standalone private
// destination of the same application never reached this listener, so another
// application keeps forwarding that hostname on it.
func TestRevokedAccessTombstoneFallbackHoldsOnlyItsListenerDestinations(t *testing.T) {
	inputs := wildcardHostConflictInputs(t)
	inputs.HTTPRoutes = inputs.HTTPRoutes[1:]
	inputs.CloudflareTunnel.Status.Hostnames = nil
	inputs.AccessApplications[0].Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{
		{Type: v1alpha1.AccessApplicationDestinationPrivate, Hostname: "b.example.com", PortRange: "5432", L4Protocol: new(v1alpha1.AccessL4ProtocolTCP), VNetID: "vnet-private"},
		{Type: v1alpha1.AccessApplicationDestinationPublic, URI: conflictHost},
	}
	gateway, statuses := buildRevokedGateway(t, inputs)
	assertTombstoneOnHost(t, gateway)
	assertAppBForwarding(t, gateway, statuses)
	other := hostDomains(gateway, "b.example.com")
	if len(other) != 1 || other[0].AccessApplication != "default/app-b" || other[0].Guard != ir.GuardForwarding {
		t.Fatalf("b.example.com domains = %#v, want app-b's Forwarding domain only", other)
	}
	if service := firstEdgeService(t, gateway, "b.example.com"); service == "http_status:403" {
		t.Fatalf("b.example.com is blocked by a destination its tombstone never served")
	}
}

// On a private listener the fallback holds the Private hostname destinations
// compiled for that listener, which carry its port, and not another private
// destination of the same application.
func TestRevokedAccessTombstoneFallbackHoldsPrivateListenerDestinations(t *testing.T) {
	inputs := hostConflictInputs(t, true, 443)
	inputs.AccessApplications = inputs.AccessApplications[:1]
	inputs.CloudflareTunnel.Status.Hostnames = nil
	inputs.AccessApplications[0].Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{
		{Type: v1alpha1.AccessApplicationDestinationPrivate, Hostname: conflictHost, PortRange: "443", L4Protocol: new(v1alpha1.AccessL4ProtocolTCP), VNetID: "vnet-private"},
		{Type: v1alpha1.AccessApplicationDestinationPrivate, Hostname: "db.example.com", PortRange: "5432", L4Protocol: new(v1alpha1.AccessL4ProtocolTCP), VNetID: "vnet-private"},
		{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "www.example.com"},
	}
	gateway, _ := buildRevokedGateway(t, inputs)
	assertTombstoneOnHost(t, gateway)
}
