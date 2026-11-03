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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/ir"
)

func TestPrivatePrerequisitesIsolateListeners(t *testing.T) {
	for _, failure := range []string{"VirtualNetwork", "HostnameRoute", "TLS", "DeviceSettings"} {
		t.Run(failure, func(t *testing.T) {
			gateway := listenerConvergenceGateway()
			for i := range gateway.Listeners {
				gateway.Listeners[i].Exposure = ir.ExposurePrivate
			}
			tunnel := persistListenerConvergence(t, gateway)
			tunnel.Name, tunnel.Namespace = "tunnel", "tenant"
			tunnel.Status.TunnelID, tunnel.Status.OwnershipVerified = "tunnel-id", true
			account := privatePrerequisiteAccount("tenant", false)
			tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
				{Name: "a", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "a"}},
				{Name: "b", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: "b"}},
			}
			inputs := gatewayInputsView{}
			for _, name := range []string{"a", "b"} {
				inputs.VirtualNetworks = append(inputs.VirtualNetworks, v1alpha1.VirtualNetwork{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"},
					Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}},
					Status:     v1alpha1.VirtualNetworkStatus{VirtualNetworkID: name, Conditions: []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}}},
				})
				route := v1alpha1.HostnameRoute{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"},
					Spec:       v1alpha1.HostnameRouteSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Hostname: name + ".example.com", TunnelRef: v1alpha1.TunnelReference{Name: "tunnel"}},
				}
				route.Status.RouteID = name
				route.Status.Applied.TunnelID = "tunnel-id"
				route.Status.Applied.Hostname = route.Spec.Hostname
				route.Status.Conditions = []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}}
				inputs.HostnameRoutes = append(inputs.HostnameRoutes, route)
				inputs.AccessApplications = append(inputs.AccessApplications, v1alpha1.AccessApplication{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps"},
					Spec:       v1alpha1.AccessApplicationSpec{OriginJWT: v1alpha1.AccessOriginJWTSpec{AssumeGatewayTLSDecryption: true}},
				})
			}
			settings := flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}
			healthyInputs := inputs
			healthyInputs.AccessApplications = append([]v1alpha1.AccessApplication(nil), inputs.AccessApplications...)
			switch failure {
			case "VirtualNetwork":
				inputs.VirtualNetworks = inputs.VirtualNetworks[:1]
			case "HostnameRoute":
				inputs.HostnameRoutes = inputs.HostnameRoutes[:1]
			case "TLS":
				inputs.AccessApplications[1].Spec.OriginJWT.AssumeGatewayTLSDecryption = false
			case "DeviceSettings":
				settings.GatewayProxyEnabled = false
			}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := v1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test")}}
			r := &GatewayReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build(), CloudflareFactory: gatewayCloudflareFactory{api: &privatePrerequisiteAPI{settings: &settings}}}
			binding := accessBindingDigest(gateway.Domains[1])
			state, err := r.reconcilePrivatePrerequisites(context.Background(), gateway, tunnel, account, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if state.Pending == "" {
				t.Fatal("failed prerequisite was not reported")
			}
			if state.Listeners["b"] == "" || failure != "DeviceSettings" && state.Listeners["a"] != "" {
				t.Fatalf("listener prerequisite diagnostics = %#v", state.Listeners)
			}
			if failure != "DeviceSettings" && (gateway.Domains[0].Guard != ir.GuardForwarding || gateway.Domains[0].Access == nil) {
				t.Fatal("listener B's prerequisite blocked healthy private listener A")
			}
			if failure == "DeviceSettings" && gateway.Domains[0].Guard != ir.GuardBlocked {
				t.Fatal("shared prerequisite did not block listener A")
			}
			if gateway.Domains[1].Guard != ir.GuardBlocked || gateway.Domains[1].Access != nil {
				t.Fatal("failed private listener still forwards")
			}
			if gateway.Domains[1].AccessBinding != binding || binding == "" {
				t.Fatal("private denial lost the binding checkpoint")
			}
			if failure != "DeviceSettings" && !strings.Contains(state.Pending, "b") {
				t.Fatal("diagnostic does not identify affected listener")
			}
			// Checkpoint the actual denied IR, repair the prerequisite, and
			// confirm the same binding can resume without a new denial cycle.
			tunnel.Status.Hostnames = desiredTunnelHostnames(gateway, 8)
			desired := listenerConvergenceGateway()
			for i := range desired.Listeners {
				desired.Listeners[i].Exposure = ir.ExposurePrivate
			}
			settings.GatewayProxyEnabled = true
			released, transitioning, err := accessBlockFirstGateway(desired, tunnel)
			if err != nil {
				t.Fatal(err)
			}
			if transitioning {
				t.Fatal("checkpointed private binding re-entered denial during recovery")
			}
			recovered, err := r.reconcilePrivatePrerequisites(context.Background(), released, tunnel, account, healthyInputs)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Pending != "" || len(recovered.Listeners) != 0 {
				t.Fatalf("repaired prerequisites remain pending: %#v", recovered)
			}
			for _, domain := range released.Domains {
				if domain.Guard != ir.GuardForwarding || domain.Access == nil {
					t.Fatal("recovered private listener did not resume forwarding")
				}
			}
		})
	}
}

func TestPrivatePrerequisiteStatusPreservesDNSConflict(t *testing.T) {
	compiled := listenerConvergenceGateway()
	compiled.Listeners = append(compiled.Listeners, ir.Listener{Name: "private", Hostname: "private.example.com", Exposure: ir.ExposurePrivate})
	tunnel := &v1alpha1.CloudflareTunnel{Status: v1alpha1.CloudflareTunnelStatus{DNSRecords: []v1alpha1.CloudflareTunnelDNSRecordStatus{
		{Hostname: "a.example.com", State: dnsRecordStateReady}, {Hostname: "b.example.com", State: dnsRecordStateConflict},
	}}}
	state := privatePrerequisiteResult{Pending: "private VNet unavailable", Listeners: map[string]string{"private": "private VNet unavailable"}}
	for _, converged := range []bool{false, true} {
		status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{{Name: "a"}, {Name: "b"}, {Name: "private"}}}
		new(GatewayReconciler).setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, compiled, tunnel, converged, "Waiting for DNS and private prerequisites", state)
		if meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)).Status != metav1.ConditionFalse {
			t.Fatal("Gateway ignored pending listener")
		}
		for _, listener := range status.Listeners {
			got := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			want := metav1.ConditionFalse
			if converged && listener.Name == "a" {
				want = metav1.ConditionTrue
			}
			if got == nil || got.Status != want {
				t.Fatalf("converged=%t listener %s = %#v, want %s", converged, listener.Name, got, want)
			}
			if converged && listener.Name == "b" && got.Reason != "DNSConflict" {
				t.Fatal("private pending overwrote public DNSConflict")
			}
			if converged && listener.Name == "private" && got.Message != state.Pending {
				t.Fatal("private listener lost its prerequisite diagnostic")
			}
		}
	}
}
