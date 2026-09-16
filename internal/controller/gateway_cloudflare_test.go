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

	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestGatewayCloudflareEffectiveConfigOverrides(t *testing.T) {
	base := defaultGatewayClassConfig()
	base.Spec.Connector.Image = "base-cloudflared"
	base.Spec.Proxy.Image = "base-envoy"
	tcpKeepAlive := metav1.Duration{Duration: 15 * time.Second}
	http2Origin := true
	tunnel := &v1alpha1.CloudflareTunnel{Spec: v1alpha1.CloudflareTunnelSpec{
		Connector: &v1alpha1.ConnectorSpec{Image: "override-cloudflared", Replicas: ptr.To[int32](3)},
		Proxy:     &v1alpha1.ProxySpec{Image: "override-envoy", StreamIdleTimeout: metav1.Duration{Duration: 2 * time.Hour}},
		OriginRequest: &v1alpha1.GatewayOriginRequestSpec{
			TCPKeepAlive: &tcpKeepAlive, HTTP2Origin: &http2Origin,
		},
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

	if got.Spec.OriginRequest.ConnectTimeout == nil || got.Spec.OriginRequest.ConnectTimeout.Duration != 30*time.Second ||
		got.Spec.OriginRequest.KeepAliveTimeout == nil || got.Spec.OriginRequest.KeepAliveTimeout.Duration != 90*time.Second ||
		got.Spec.OriginRequest.KeepAliveConnections == nil || *got.Spec.OriginRequest.KeepAliveConnections != 100 ||
		got.Spec.OriginRequest.NoHappyEyeballs == nil || *got.Spec.OriginRequest.NoHappyEyeballs ||
		got.Spec.OriginRequest.TCPKeepAlive == nil || got.Spec.OriginRequest.TCPKeepAlive.Duration != 15*time.Second ||
		got.Spec.OriginRequest.HTTP2Origin == nil || !*got.Spec.OriginRequest.HTTP2Origin {
		t.Fatalf("origin request override/defaults = %#v", got.Spec.OriginRequest)
	}
	if base.Spec.Connector.Image != "base-cloudflared" || base.Spec.Proxy.Image != "base-envoy" {
		t.Fatal("effectiveGatewayConfig mutated the base config")
	}
}
func TestGatewayCloudflareRefusesDirectTunnelOwnership(t *testing.T) {
	tunnel := &v1alpha1.CloudflareTunnel{
		Spec: v1alpha1.CloudflareTunnelSpec{
			Configuration: v1alpha1.CloudflareTunnelConfiguration{Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect},
		},
	}
	reconciler := new(GatewayReconciler)
	if _, err := reconciler.reconcileCloudflaredConfiguration(context.Background(), &ir.Gateway{}, tunnel, &v1alpha1.CloudflareAccount{}); err == nil {
		t.Fatal("Gateway configuration writer accepted a Direct-mode tunnel")
	}
	if err := reconciler.patchTunnelGatewayStatus(context.Background(), nil, tunnel, v1alpha1.CloudflareTunnelConfigVersion{}, nil, nil); err == nil {
		t.Fatal("Gateway status writer accepted a Direct-mode tunnel")
	}
}

func TestGatewayCloudflareContextEnforcesExactLiveTunnelOwner(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "apps", UID: "tunnel-uid"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	tunnelInfrastructure := func() *gatewayv1.GatewayInfrastructure {
		return &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: tunnel.Name,
		}}
	}
	first := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first", Namespace: tunnel.Namespace, UID: "first-uid",
			CreationTimestamp: metav1.NewTime(time.Unix(100, 0)),
		},
		Spec: gatewayv1.GatewaySpec{Infrastructure: tunnelInfrastructure()},
	}
	second := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "second", Namespace: tunnel.Namespace, UID: "second-uid",
			CreationTimestamp: metav1.NewTime(time.Unix(200, 0)),
		},
		Spec: gatewayv1.GatewaySpec{Infrastructure: tunnelInfrastructure()},
	}
	tunnel.Status = v1alpha1.CloudflareTunnelStatus{
		TunnelID:                "remote-id",
		OwnershipVerified:       true,
		ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
		GatewayRef:              &corev1.LocalObjectReference{Name: first.Name},
		GatewayUID:              first.UID,
		ConfigVersion:           v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, DesiredHash: "first-owner"},
		Hostnames:               []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "first.example.com"}},
	}
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: tunnel.Spec.AccountRef.Name}}
	kube := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(first, second, tunnel).
		WithObjects(tunnel, account, first, second).
		Build()
	reconciler := &GatewayReconciler{Client: kube}
	cfg := defaultGatewayClassConfig()

	_, selectedAccount, _, stop, err := reconciler.resolveCloudflareContext(context.Background(), first, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if stop || selectedAccount == nil {
		t.Fatalf("recorded owner resolution stopped=%v account=%#v", stop, selectedAccount)
	}

	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), second, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !stop || selectedAccount != nil {
		t.Fatalf("non-owner Gateway resolution stopped=%v account=%#v", stop, selectedAccount)
	}

	if err := kube.Delete(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), second, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !stop || selectedAccount != nil {
		t.Fatalf("successor bypassed ownership checkpoint stopped=%v account=%#v", stop, selectedAccount)
	}
	var currentTunnel v1alpha1.CloudflareTunnel
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &currentTunnel); err != nil {
		t.Fatal(err)
	}
	beforeStatus := currentTunnel.DeepCopy()
	currentTunnel.Status.GatewayRef = &corev1.LocalObjectReference{Name: second.Name}
	currentTunnel.Status.GatewayUID = second.UID
	if err := kube.Status().Patch(context.Background(), &currentTunnel, client.MergeFrom(beforeStatus)); err != nil {
		t.Fatal(err)
	}
	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), second, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if stop || selectedAccount == nil {
		t.Fatalf("checkpointed successor resolution stopped=%v account=%#v", stop, selectedAccount)
	}

	staleFirst := first.DeepCopy()
	if err := kube.Delete(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	replacement := first.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-uid"
	replacement.CreationTimestamp = metav1.NewTime(time.Unix(300, 0))
	replacement.DeletionTimestamp = nil
	replacement.Finalizers = nil
	replacement.Status = gatewayv1.GatewayStatus{}
	if err := kube.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}

	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), staleFirst, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !stop || selectedAccount != nil {
		t.Fatalf("stale same-name UID resolution stopped=%v account=%#v", stop, selectedAccount)
	}
	var untouchedReplacement gatewayv1.Gateway
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(replacement), &untouchedReplacement); err != nil {
		t.Fatal(err)
	}
	if len(untouchedReplacement.Status.Conditions) != 0 {
		t.Fatalf("stale UID patched replacement Gateway status: %#v", untouchedReplacement.Status)
	}
	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), replacement, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !stop || selectedAccount != nil {
		t.Fatalf("replacement bypassed UID ownership checkpoint stopped=%v account=%#v", stop, selectedAccount)
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &currentTunnel); err != nil {
		t.Fatal(err)
	}
	beforeStatus = currentTunnel.DeepCopy()
	currentTunnel.Status.GatewayRef = &corev1.LocalObjectReference{Name: replacement.Name}
	currentTunnel.Status.GatewayUID = replacement.UID
	if err := kube.Status().Patch(context.Background(), &currentTunnel, client.MergeFrom(beforeStatus)); err != nil {
		t.Fatal(err)
	}
	_, selectedAccount, _, stop, err = reconciler.resolveCloudflareContext(context.Background(), replacement, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if stop || selectedAccount == nil {
		t.Fatalf("checkpointed replacement resolution stopped=%v account=%#v", stop, selectedAccount)
	}
}

func TestGatewayCloudflareRejectsRemotelyDeletedTunnel(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	key := types.NamespacedName{Namespace: "apps", Name: "edge"}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "gateway-uid", Generation: 3},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "shared",
			}},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Value: "stale.cfargotunnel.com"}},
		},
	}
	deletedAt := metav1.NewTime(time.Now().Round(0))
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: key.Namespace, UID: "tunnel-uid"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:                "remote-id",
			DeletedAt:               &deletedAt,
			OwnershipVerified:       true,
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "connector-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: gateway.Name},
			GatewayUID:              gateway.UID,
			ConfigVersion:           v1alpha1.CloudflareTunnelConfigVersion{Desired: 7, DesiredHash: "preserve"},
			Hostnames:               []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardForwarding}},
		},
	}
	beforeTunnel := tunnel.DeepCopy()
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: tunnel.Spec.AccountRef.Name}}
	snapshots := newFakeSnapshotPublisher()
	snapshots.versions[key.String()] = "stale"
	kube := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(gateway, tunnel).
		WithObjects(gateway, tunnel, account).
		Build()
	reconciler := &GatewayReconciler{Client: kube, Snapshots: snapshots}

	selectedTunnel, selectedAccount, _, stop, err := reconciler.resolveCloudflareContext(context.Background(), gateway, defaultGatewayClassConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !stop || selectedAccount != nil || selectedTunnel == nil {
		t.Fatalf("soft-deleted Tunnel resolution stopped=%v account=%#v tunnel=%#v", stop, selectedAccount, selectedTunnel)
	}
	if snapshots.Version(key.String()) != "" {
		t.Fatal("soft-deleted Tunnel retained its xDS snapshot")
	}
	var observedGateway gatewayv1.Gateway
	if err := kube.Get(context.Background(), key, &observedGateway); err != nil {
		t.Fatal(err)
	}
	if len(observedGateway.Status.Addresses) != 0 {
		t.Fatalf("soft-deleted Tunnel retained Gateway addresses: %#v", observedGateway.Status.Addresses)
	}
	programmed := meta.FindStatusCondition(observedGateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programmed == nil || programmed.Status != metav1.ConditionFalse || !strings.Contains(programmed.Message, "remotely deleted") {
		t.Fatalf("soft-deleted Tunnel Programmed condition = %#v", programmed)
	}

	compiled := &ir.Gateway{Key: key, UID: gateway.UID}
	if _, err := reconciler.validateGatewayTunnelWriter(context.Background(), compiled, selectedTunnel); err == nil {
		t.Fatal("soft-deleted Tunnel authorized Gateway writer validation")
	}
	if _, err := reconciler.reconcileCloudflaredConfiguration(context.Background(), compiled, selectedTunnel, account); err == nil {
		t.Fatal("soft-deleted Tunnel authorized Cloudflare configuration")
	}
	if err := reconciler.patchTunnelGatewayStatus(context.Background(), compiled, selectedTunnel, v1alpha1.CloudflareTunnelConfigVersion{Desired: 9}, nil, nil); err == nil {
		t.Fatal("soft-deleted Tunnel authorized Gateway-owned Tunnel status")
	}
	var observedTunnel v1alpha1.CloudflareTunnel
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(tunnel), &observedTunnel); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(observedTunnel.Status.ConfigVersion, beforeTunnel.Status.ConfigVersion) ||
		!equality.Semantic.DeepEqual(observedTunnel.Status.Hostnames, beforeTunnel.Status.Hostnames) ||
		!equality.Semantic.DeepEqual(observedTunnel.Status.Listeners, beforeTunnel.Status.Listeners) {
		t.Fatalf("soft-deleted Tunnel Gateway-owned status changed: %#v", observedTunnel.Status)
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
			TunnelID:          "11111111-1111-1111-1111-111111111111",
			OwnershipVerified: true,
			Hostnames:         []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 7}},
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
	deletedAt := metav1.Now()
	tunnel.Status.DeletedAt = &deletedAt
	if addresses := tunnelGatewayAddresses(gateway, tunnel); len(addresses) != 0 {
		t.Fatalf("remotely deleted Tunnel addresses = %#v, want none", addresses)
	}
	tunnel.Status.DeletedAt = nil
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
			Access:       &ir.AccessGuard{AUDs: []string{"new-aud"}, TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
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

func TestAccessBlockFirstGatewayMixedPublicCarveOut(t *testing.T) {
	gateway := &ir.Gateway{
		Cloudflare: &ir.Cloudflare{AccountID: "account-id"},
		Listeners:  []ir.Listener{{Name: "http", Exposure: ir.ExposurePublic}},
		Domains: []ir.ProtectionDomain{
			{
				Name: "public", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "mixed.example.com"}},
			},
			{
				Name: "protected", ListenerName: "http", EnvoyPort: 18081, Protected: true, Guard: ir.GuardForwarding,
				AccessApplication: "apps/access",
				Access:            &ir.AccessGuard{AUDs: []string{"aud"}, TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
				VirtualHosts:      []ir.VirtualHost{{Hostname: "mixed.example.com"}},
			},
		},
	}
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{
		ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{DesiredHash: "old-config"},
		Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{
			{Hostname: "mixed.example.com", ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardUnprotected},
			{Hostname: "mixed.example.com", ProtectionDomain: "protected", AccessApplication: "apps/access", Guard: v1alpha1.HostnameGuardBlocked},
		},
	}}

	// The protected domain already completed block-first: the public carve-out
	// on the same hostname must not pin it in Blocked forever.
	desired, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if transitioning || desired != gateway {
		t.Fatalf("blocked protected domain did not release desired config on mixed hostname: transitioning %v", transitioning)
	}

	// The initial Forwarding -> Blocked security gate still applies: a protected
	// domain observed Forwarding must block before the new config is pushed.
	tunnel.Status.Hostnames[1].Guard = v1alpha1.HostnameGuardForwarding
	blocked, transitioning, err := accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || blocked.Domains[1].Guard != ir.GuardBlocked || blocked.Domains[1].Access != nil {
		t.Fatalf("forwarding protected domain skipped block-first: transitioning %v, gateway %#v", transitioning, blocked)
	}
	if blocked.Domains[0].Guard != ir.GuardUnprotected {
		t.Fatal("block-first transition must keep the public carve-out unprotected")
	}

	// A protected domain never observed Blocked on a host that is still exposed
	// unprotected must block first.
	tunnel.Status.Hostnames = tunnel.Status.Hostnames[:1]
	blocked, transitioning, err = accessBlockFirstGateway(gateway, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !transitioning || blocked.Domains[1].Guard != ir.GuardBlocked {
		t.Fatalf("unprotected host exposure skipped block-first: transitioning %v, gateway %#v", transitioning, blocked)
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
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
		Name: "edge", Namespace: "apps", UID: "gateway-uid",
	}}
	application := v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: "apps", UID: "application-uid"},
		Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "application-id"},
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("add Gateway scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Flareway scheme: %v", err)
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, &application).Build()
	reconciler := &GatewayReconciler{
		Client: kube, OperatorNamespace: dataplane.DefaultOperatorNamespace, audRevocations: &audRevocationState{},
	}
	secret := boundAUDSecret(
		accessAUDSecretName(&application, client.ObjectKeyFromObject(gateway)),
		&application,
		gateway,
		"restored-aud",
	)
	inputs := gatewayapi.Inputs{
		AccessApplications: []v1alpha1.AccessApplication{application},
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

	forged := secret.DeepCopy()
	forged.Namespace = gateway.Namespace
	reconciler.latchAUDRevocation(context.Background(), forged)
	reconciler.applyAUDRevocationLatches(gateway, tunnel, &inputs, reconciler.revocationState().ceiling())
	if !inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}].Ready {
		t.Fatal("tenant-forged AUD handoff altered Gateway readiness")
	}

	reconciler.latchAUDRevocation(context.Background(), &secret)
	reconciler.applyAUDRevocationLatches(gateway, tunnel, &inputs, reconciler.revocationState().ceiling())
	if inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}].Ready {
		t.Fatal("restored AUD escaped the revocation latch before Blocked was applied")
	}

	tunnel.Status.ConfigVersion.Applied = 2
	tunnel.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
	tunnel.Status.Hostnames[0].AppliedVersion = 2
	inputs.AUDSecrets[types.NamespacedName{Namespace: "apps", Name: "access"}] = gatewayapi.AUDSecret{
		AUD: "restored-aud", ApplicationID: "application-id", Ready: true,
	}
	reconciler.applyAUDRevocationLatches(gateway, tunnel, &inputs, reconciler.revocationState().ceiling())
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
