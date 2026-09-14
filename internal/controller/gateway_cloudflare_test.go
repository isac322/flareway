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
	"time"

	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestGatewayCloudflareEffectiveConfigOverrides(t *testing.T) {
	base := defaultGatewayClassConfig()
	base.Spec.Connector.Image = "base-cloudflared"
	base.Spec.Proxy.Image = "base-envoy"
	tunnel := &v1alpha1.CloudflareTunnel{Spec: v1alpha1.CloudflareTunnelSpec{
		Connector: &v1alpha1.ConnectorSpec{Image: "override-cloudflared", Replicas: ptr.To[int32](3)},
		Proxy:     &v1alpha1.ProxySpec{Image: "override-envoy", StreamIdleTimeout: metav1.Duration{Duration: 2 * time.Hour}},
	}}

	got := effectiveGatewayConfig(base, tunnel)
	if got == base {
		t.Fatal("effectiveGatewayConfig returned the mutable base object")
	}
	if got.Spec.Connector.Image != "override-cloudflared" || got.Spec.Connector.Replicas == nil || *got.Spec.Connector.Replicas != 3 {
		t.Fatalf("connector override = %#v", got.Spec.Connector)
	}
	if got.Spec.Proxy.Image != "override-envoy" || got.Spec.Proxy.StreamIdleTimeout.Duration != 2*time.Hour {
		t.Fatalf("proxy override = %#v", got.Spec.Proxy)
	}
	if base.Spec.Connector.Image != "base-cloudflared" || base.Spec.Proxy.Image != "base-envoy" {
		t.Fatal("effectiveGatewayConfig mutated the base config")
	}
}

func TestGatewayCloudflareStatusAndTeardownHelpers(t *testing.T) {
	gateway := &ir.Gateway{
		Key:        types.NamespacedName{Namespace: "apps", Name: "edge"},
		Cloudflare: &ir.Cloudflare{TunnelID: "11111111-1111-1111-1111-111111111111", Teardown: true},
		Listeners:  []ir.Listener{{Name: "public", Hostname: "app.example.com", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "public", ListenerName: "public", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
			VirtualHosts: []ir.VirtualHost{{Hostname: "app.example.com"}},
		}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{
			Annotations:       map[string]string{v1alpha1.CloudflareTunnelTeardownAnnotation: "true"},
			DeletionTimestamp: &metav1.Time{Time: time.Unix(100, 0)},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:  "11111111-1111-1111-1111-111111111111",
			Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 7}},
		},
	}

	hostnames := desiredTunnelHostnames(gateway, 8)
	if len(hostnames) != 1 || hostnames[0].Guard != v1alpha1.HostnameGuardBlocked || hostnames[0].AppliedVersion != 8 {
		t.Fatalf("teardown hostname status = %#v", hostnames)
	}
	addresses := tunnelGatewayAddresses(gateway, tunnel)
	if len(addresses) != 1 || addresses[0].Type == nil || *addresses[0].Type != gatewayv1.HostnameAddressType || addresses[0].Value != tunnel.Status.TunnelID+".cfargotunnel.com" {
		t.Fatalf("tunnel addresses = %#v", addresses)
	}
	if !shouldScaleDownTunnel(tunnel) {
		t.Fatal("blocked teardown with no DNS records did not permit scale-down")
	}
	tunnel.Status.Hostnames = nil
	if !shouldScaleDownTunnel(tunnel) {
		t.Fatal("teardown with no DNS records must scale down even when no hostname was ever programmed")
	}
	deployment := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](2)}}
	scaleDesiredDeploymentToZero([]client.Object{deployment})
	tunnel.DeletionTimestamp = nil
	if shouldScaleDownTunnel(tunnel) {
		t.Fatal("user-set teardown annotation on an active Tunnel must not scale down the dataplane")
	}
	tunnel.DeletionTimestamp = &metav1.Time{Time: time.Unix(100, 0)}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
		t.Fatalf("scaled replicas = %v, want zero", deployment.Spec.Replicas)
	}

	tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "app.example.com", RecordID: "record"}}
	if shouldScaleDownTunnel(tunnel) {
		t.Fatal("teardown scaled down before DNS removal")
	}
}

func TestGatewayCloudflareDNSGate(t *testing.T) {
	gateway := &ir.Gateway{Listeners: []ir.Listener{
		{Name: "one", Hostname: "one.example.com", Exposure: ir.ExposurePublic},
		{Name: "private", Hostname: "private.example.com", Exposure: ir.ExposurePrivate},
	}}
	tunnel := &v1alpha1.CloudflareTunnel{Spec: v1alpha1.CloudflareTunnelSpec{DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeManaged}}}
	if publicDNSReady(gateway, tunnel) {
		t.Fatal("managed DNS reported ready without the public record")
	}
	tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "ONE.EXAMPLE.COM"}}
	if !publicDNSReady(gateway, tunnel) {
		t.Fatal("managed DNS did not accept the matching public record")
	}
	tunnel.Spec.DNS.Mode = v1alpha1.DNSModeExternal
	if !publicDNSReady(&ir.Gateway{}, tunnel) {
		t.Fatal("private-only Gateway should not require public DNS records")
	}
}

func TestAccessBlockFirstGateway(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{{
			Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
			Access:       &ir.AccessGuard{AUD: "new-aud", TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
			VirtualHosts: []ir.VirtualHost{{Hostname: "app.example.com"}},
		}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{DesiredHash: "old-config"},
		Hostnames:     []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardUnprotected}},
	}}
	blocked, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || blocked == gateway || blocked.Domains[0].Guard != ir.GuardBlocked || blocked.Domains[0].Access != nil {
		t.Fatalf("block-first state = transitioning %v, gateway %#v", transitioning, blocked)
	}
	if gateway.Domains[0].Guard != ir.GuardForwarding || gateway.Domains[0].Access == nil {
		t.Fatal("block-first transition mutated desired Gateway")
	}

	tunnel.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
	desired, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning || desired != gateway {
		t.Fatalf("blocked completion signal did not release desired config: transitioning %v", transitioning)
	}
}

func TestDesiredTunnelHostnamesPreservePerDomainHandshake(t *testing.T) {
	gateway := &ir.Gateway{
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "mixed.example.com"}},
			},
			{
				Name: "protected", Protected: true, Guard: ir.GuardForwarding, AccessApplication: "default/app-a",
				VirtualHosts: []ir.VirtualHost{{Hostname: "mixed.example.com"}},
			},
			{
				Name: "revoking", Protected: true, Guard: ir.GuardBlocked, AccessApplication: "default/app-b",
				VirtualHosts: []ir.VirtualHost{{Hostname: "mixed.example.com"}},
			},
		},
	}
	hostnames := desiredTunnelHostnames(gateway, 9)
	if len(hostnames) != 3 {
		t.Fatalf("per-domain hostname statuses = %#v", hostnames)
	}
	found := false
	for _, hostname := range hostnames {
		if hostname.ProtectionDomain == "revoking" && hostname.AccessApplication == "default/app-b" {
			found = hostname.Guard == v1alpha1.HostnameGuardBlocked && hostname.AppliedVersion == 9
		}
	}
	if !found {
		t.Fatalf("revocation completion signal = %#v", hostnames)
	}
}

func TestAUDRevocationLatchBlocksRestoredSecretUntilFreshBlockedVersion(t *testing.T) {
	reconciler := &GatewayReconciler{}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
			v1alpha1.AccessApplicationGatewayAUDLabel: "apps--edge",
			v1alpha1.AccessApplicationAUDSecretLabel:  "apps--access",
		}},
		Data: map[string][]byte{
			"ready":                                []byte("true"),
			v1alpha1.AccessApplicationAUDSecretKey: []byte("restored-aud"),
			v1alpha1.AccessApplicationIDSecretKey:  []byte("application-id"),
		},
	}
	reconciler.latchAUDRevocation(secret)
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps"}}
	inputs := gatewayapi.Inputs{
		AccessApplications: []v1alpha1.AccessApplication{{ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: "apps"}}},
		AUDSecrets: map[types.NamespacedName]gatewayapi.AUDSecret{{
			Namespace: "apps", Name: "access",
		}: {AUD: "restored-aud", ApplicationID: "application-id", Ready: true}},
	}
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Applied: 1},
		Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: "app.example.com", ProtectionDomain: "access-domain", AccessApplication: "apps/access",
			Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
		}},
	}}
	reconciler.applyAUDRevocationLatches(gateway, tunnel, &inputs)
	if inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}].Ready {
		t.Fatal("restored AUD escaped the revocation latch before Blocked was applied")
	}

	tunnel.Status.ConfigVersion.Applied = 2
	tunnel.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
	tunnel.Status.Hostnames[0].AppliedVersion = 2
	inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}] = gatewayapi.AUDSecret{
		AUD: "restored-aud", ApplicationID: "application-id", Ready: true,
	}
	reconciler.applyAUDRevocationLatches(gateway, tunnel, &inputs)
	if !inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}].Ready {
		t.Fatal("fresh Blocked handshake did not release restored AUD")
	}
}

func TestRetainAccessRevocationDomainAfterTargetDisappears(t *testing.T) {
	gateway := &ir.Gateway{Cloudflare: &ir.Cloudflare{AccountID: "account-id"}}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps"},
		Status: v1alpha1.CloudflareTunnelStatus{Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: "app.example.com", ProtectionDomain: "removed-rule-domain",
			AccessApplication: "apps/access", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 4,
		}}},
	}
	application := v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "access", Namespace: "apps",
			Annotations: map[string]string{accessApplicationRevocationAnnotation: "latched"},
		},
		Status: v1alpha1.AccessApplicationStatus{
			Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: "public", URI: "app.example.com/removed"}},
			DataPlanes: []v1alpha1.AccessApplicationDataPlaneStatus{{
				Tunnel: "edge", Listener: "removed-listener", ProtectionDomain: "removed-rule-domain", EnvoyPort: 18081,
			}},
		},
	}

	retainAccessRevocationDomains(gateway, tunnel, []v1alpha1.AccessApplication{application})
	if len(gateway.Domains) != 1 {
		t.Fatalf("retained domains = %#v", gateway.Domains)
	}
	domain := gateway.Domains[0]
	if domain.Guard != ir.GuardBlocked || domain.AccessApplication != "apps/access" ||
		domain.Name != "removed-rule-domain" || len(domain.VirtualHosts) != 1 ||
		domain.VirtualHosts[0].Hostname != "app.example.com" {
		t.Fatalf("revocation tombstone = %#v", domain)
	}
	if len(gateway.Listeners) != 1 || gateway.Listeners[0].Name != "removed-listener" ||
		gateway.Listeners[0].EnvoyPort != 18081 {
		t.Fatalf("retained deny listener = %#v", gateway.Listeners)
	}
	snapshot, err := translator.Build(gateway, nil)
	if err != nil {
		t.Fatalf("build retained deny snapshot: %v", err)
	}
	if len(snapshot.GetResources(resourcev3.ListenerType)) != 1 {
		t.Fatalf("retained deny listeners = %#v", snapshot.GetResources(resourcev3.ListenerType))
	}
	statuses := desiredTunnelHostnames(gateway, 5)
	if len(statuses) != 1 || statuses[0].ProtectionDomain != "removed-rule-domain" ||
		statuses[0].AccessApplication != "apps/access" || statuses[0].Guard != v1alpha1.HostnameGuardBlocked ||
		statuses[0].AppliedVersion != 5 {
		t.Fatalf("retained Blocked handshake = %#v", statuses)
	}
}
