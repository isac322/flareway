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

package gatewayapi

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

// Holding a tombstone's host drops that host's listener-level domain. The
// drop must not change how other domains are named: a derived Access domain
// that collides with a listener name is renamed, and if the colliding domain
// disappeared before naming, a latched application's live domain would take
// a new name, leave its recorded one behind as an extra tombstone the
// translation never reserved a port for, and break the snapshot.
func TestRevokedAccessHoldKeepsDerivedDomainNames(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareTunnel.Name = "edge"
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
	in.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("b.example.com"))
	// A listener named exactly like app-x's derived domain on "http" forces
	// that domain to be disambiguated. It serves api.example.com, which the
	// revoked app-old's tombstone holds.
	collision := gatewayv1.SectionName("http-access-default-app-x-" + accessHostSuffix("default/app-x", "b.example.com"))
	in.Gateway.Spec.Listeners = append(in.Gateway.Spec.Listeners, gatewayv1.Listener{
		Name: collision, Hostname: new(gatewayv1.Hostname("api.example.com")), Port: 80, Protocol: gatewayv1.HTTPProtocolType,
	})
	routeB := routeWithBackend("b", "backend", 8080)
	routeB.Spec.Hostnames = []gatewayv1.Hostname{"b.example.com"}
	routeB.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("http"))
	routeAPI := routeWithBackend("api", "backend", 8080)
	routeAPI.Spec.Hostnames = []gatewayv1.Hostname{"api.example.com"}
	routeAPI.Spec.ParentRefs[0].SectionName = new(collision)
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routeB, routeAPI}

	appX := accessApplication("app-x", "Gateway", "gateway", "http")
	in.AccessApplications = []v1alpha1.AccessApplication{appX}
	appXKey := types.NamespacedName{Namespace: "default", Name: "app-x"}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{appXKey: {AUD: "aud-x", ApplicationID: "x-id", Ready: true}}
	_, before := Translate(in)
	recorded := before.AccessApplications[appXKey].DataPlanes[0]

	// app-x is latched but still compiles its host; app-old was retargeted
	// away and keeps api.example.com as a tombstone.
	appX.Annotations = map[string]string{AccessRevocationAnnotation: `{"claims":[]}`}
	appX.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
		Tunnel: "edge", Listener: "http", ProtectionDomain: recorded.ProtectionDomain, EnvoyPort: recorded.EnvoyPort,
	}}
	appX.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{Hostname: "b.example.com"}}
	appOld := accessApplication("app-old", "Gateway", "gateway", "gone")
	appOld.CreationTimestamp = metav1.NewTime(time.Unix(9, 0))
	appOld.Annotations = map[string]string{AccessRevocationAnnotation: `{"claims":[]}`}
	appOld.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
		Tunnel: "edge", Listener: collision, ProtectionDomain: "old-api", EnvoyPort: 18090,
	}}
	appOld.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{Hostname: "api.example.com"}}
	in.AccessApplications = []v1alpha1.AccessApplication{appOld, appX}

	gateway, statuses := Translate(in)
	if live := statuses.AccessApplications[appXKey].DataPlanes; len(live) != 1 || live[0].ProtectionDomain != recorded.ProtectionDomain {
		t.Fatalf("app-x data planes = %#v, want its recorded domain %s", live, recorded.ProtectionDomain)
	}
	tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, gateway.Domains)
	if len(tombstones) != 1 || tombstones[0].Application != "default/app-old" {
		t.Fatalf("tombstones = %#v, want only app-old's", tombstones)
	}
	for _, domain := range gateway.Domains {
		for _, virtualHost := range domain.VirtualHosts {
			if virtualHost.Hostname == "api.example.com" && domain.ListenerName == string(collision) {
				t.Fatalf("held api.example.com still served by %s domain %s", domain.Guard, domain.Name)
			}
		}
	}
	// Same retention the Gateway controller applies after Translate.
	for _, tombstone := range tombstones {
		gateway.Domains = append(gateway.Domains, ir.ProtectionDomain{
			Name: tombstone.DataPlane.ProtectionDomain, ListenerName: string(tombstone.DataPlane.Listener), EnvoyPort: tombstone.DataPlane.EnvoyPort,
			Protected: true, AccessApplication: tombstone.Application, Guard: ir.GuardBlocked,
			VirtualHosts: []ir.VirtualHost{{Name: "revoked", Hostname: tombstone.Hostnames[0]}},
		})
	}
	if _, err := translator.Build(gateway, nil); err != nil {
		t.Fatalf("xDS snapshot must build with the retained tombstone: %v", err)
	}
}

func TestReleasedRevocationLatchReleasesTombstoneWhenNotForwarding(t *testing.T) {
	claims := []AccessRevocationClaim{{Tunnel: "edge", ProtectionDomain: "old-api", Hostname: "api.example.com", BaselineVersion: 1}}
	appUID := types.UID("app-old-uid")
	validDigest := AccessRevocationLatchDigest(appUID, claims)

	baseInputs := func(annotation string, rev *v1alpha1.AccessApplicationRevocationStatus, policy v1alpha1.ManagementPolicy, hostnames []v1alpha1.CloudflareTunnelHostnameStatus) Inputs {
		in := accessInputs(true)
		in.CloudflareTunnel.Name = "edge"
		in.CloudflareTunnel.Status.Hostnames = hostnames
		in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com", "api.example.com"}
		in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com", "api.example.com"}
		in.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("api.example.com"))
		route := routeWithBackend("api", "backend", 8080)
		route.Spec.Hostnames = []gatewayv1.Hostname{"api.example.com"}
		route.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("http"))
		in.HTTPRoutes = []gatewayv1.HTTPRoute{route}
		appOld := accessApplication("app-old", "Gateway", "gateway", "gone")
		appOld.UID = appUID
		appOld.Generation = 3
		appOld.Spec.ManagementPolicy = policy
		appOld.Annotations = map[string]string{AccessRevocationAnnotation: annotation}
		appOld.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel: "edge", Listener: "http", ProtectionDomain: "old-api", EnvoyPort: 18090,
		}}
		appOld.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{Hostname: "api.example.com"}}
		appOld.Status.Revocation = rev
		in.AccessApplications = []v1alpha1.AccessApplication{appOld}
		return in
	}

	latchJSON := `{"claims":[{"tunnel":"edge","protectionDomain":"old-api","hostname":"api.example.com","baselineVersion":1}],"tokensRevoked":true}`
	validRev := &v1alpha1.AccessApplicationRevocationStatus{
		LatchDigest: validDigest, ObservedGeneration: 3, Acknowledged: true, TokensRevoked: true, Released: true,
	}
	observeOnlyRev := &v1alpha1.AccessApplicationRevocationStatus{
		LatchDigest: validDigest, ObservedGeneration: 3, Acknowledged: true, TokensRevoked: false, Released: true,
	}
	blockedEntry := []v1alpha1.CloudflareTunnelHostnameStatus{{
		Hostname: "api.example.com", ProtectionDomain: "old-api", AccessApplication: "default/app-old",
		Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
	}}
	forwardingEntry := []v1alpha1.CloudflareTunnelHostnameStatus{{
		Hostname: "api.example.com", ProtectionDomain: "old-api", AccessApplication: "default/app-old",
		Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
	}}

	t.Run("released controller status and blocked drops tombstone", func(t *testing.T) {
		in := baseInputs(latchJSON, validRev, v1alpha1.ManagementPolicyManaged, blockedEntry)
		if tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, nil); len(tombstones) != 0 {
			t.Fatalf("tombstones = %#v, want empty once released and blocked", tombstones)
		}
		gateway, _ := Translate(in)
		for _, domain := range gateway.Domains {
			if domain.AccessApplication == "default/app-old" {
				t.Fatalf("released app-old kept domain in translated gateway: %#v", domain)
			}
		}
	})

	t.Run("released controller status and absent drops tombstone", func(t *testing.T) {
		in := baseInputs(latchJSON, validRev, v1alpha1.ManagementPolicyManaged, nil)
		if tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, nil); len(tombstones) != 0 {
			t.Fatalf("tombstones = %#v, want empty once released and absent from tunnel", tombstones)
		}
	})

	t.Run("ObserveOnly allows release without TokensRevoked", func(t *testing.T) {
		in := baseInputs(`{"claims":[{"tunnel":"edge","protectionDomain":"old-api","hostname":"api.example.com","baselineVersion":1}]}`, observeOnlyRev, v1alpha1.ManagementPolicyObserveOnly, blockedEntry)
		if tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, nil); len(tombstones) != 0 {
			t.Fatalf("tombstones = %#v, want empty for released ObserveOnly application", tombstones)
		}
	})

	t.Run("released status while tunnel still forwarding stays fail-closed", func(t *testing.T) {
		in := baseInputs(latchJSON, validRev, v1alpha1.ManagementPolicyManaged, forwardingEntry)
		tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, nil)
		if len(tombstones) != 1 || tombstones[0].Application != "default/app-old" {
			t.Fatalf("tombstones = %#v, want fail-closed retention while Forwarding remains", tombstones)
		}
	})

	t.Run("missing or mismatched controller-owned proof retains tombstone", func(t *testing.T) {
		cases := []struct {
			name string
			ann  string
			rev  *v1alpha1.AccessApplicationRevocationStatus
		}{
			{
				name: "forged annotation without controller status",
				ann:  `{"claims":[{"tunnel":"edge","protectionDomain":"old-api","hostname":"api.example.com","baselineVersion":1}],"acknowledged":true,"tokensRevoked":true,"released":true}`,
				rev:  nil,
			},
			{
				name: "stale generation",
				ann:  latchJSON,
				rev:  &v1alpha1.AccessApplicationRevocationStatus{LatchDigest: validDigest, ObservedGeneration: 2, Acknowledged: true, TokensRevoked: true, Released: true},
			},
			{
				name: "digest mismatch",
				ann:  latchJSON,
				rev:  &v1alpha1.AccessApplicationRevocationStatus{LatchDigest: "wrong-digest", ObservedGeneration: 3, Acknowledged: true, TokensRevoked: true, Released: true},
			},
			{
				name: "Managed without TokensRevoked",
				ann:  latchJSON,
				rev:  &v1alpha1.AccessApplicationRevocationStatus{LatchDigest: validDigest, ObservedGeneration: 3, Acknowledged: true, TokensRevoked: false, Released: true},
			},
			{
				name: "Released false",
				ann:  latchJSON,
				rev:  &v1alpha1.AccessApplicationRevocationStatus{LatchDigest: validDigest, ObservedGeneration: 3, Acknowledged: true, TokensRevoked: true, Released: false},
			},
			{
				name: "legacy non-JSON sentinel",
				ann:  "latched",
				rev:  validRev,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				in := baseInputs(tc.ann, tc.rev, v1alpha1.ManagementPolicyManaged, blockedEntry)
				tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, nil)
				if len(tombstones) != 1 || tombstones[0].Application != "default/app-old" {
					t.Fatalf("%s tombstones = %#v, want fail-closed retention", tc.name, tombstones)
				}
			})
		}
	})
}

func TestEmptyTargetCompilationDoesNotReleaseOnAllowedRoutesRejection(t *testing.T) {
	in := accessInputs(true)
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"allowed": "true"}}
	in.Gateway.Spec.Listeners[0].AllowedRoutes = &gatewayv1.AllowedRoutes{
		Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromSelector), Selector: selector},
	}
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.Gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("*.example.com"))
	route := routeWithBackend("rejected", "backend", 8080)
	route.Spec.Hostnames = []gatewayv1.Hostname{"app.example.com"}
	route.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("http"))
	in.HTTPRoutes = []gatewayv1.HTTPRoute{route}

	app := accessApplication("app", "Gateway", "gateway", "http")
	compiled := CompileAccessApplication(in, &app)
	if compiled.Accepted || compiled.Reason != "TargetNotFound" {
		t.Fatalf("compiled = %+v, want TargetNotFound rejection", compiled)
	}
	if compiled.NoTargetsResolved {
		t.Fatalf("NoTargetsResolved = true when HTTPRoute attachment was rejected by allowedRoutes, want false")
	}
}
