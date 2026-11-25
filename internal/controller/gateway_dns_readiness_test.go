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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func TestManagedDNSRequiresUniqueExplicitReadyRecord(t *testing.T) {
	for _, test := range []struct {
		name   string
		states []string
		ready  bool
	}{
		{name: "missing"},
		{name: "empty", states: []string{""}},
		{name: "unknown", states: []string{"Unknown"}},
		{name: "wrong case", states: []string{"ready"}},
		{name: "ready", states: []string{dnsRecordStateReady}, ready: true},
		{name: "ready then conflict", states: []string{dnsRecordStateReady, dnsRecordStateConflict}},
		{name: "conflict then ready", states: []string{dnsRecordStateConflict, dnsRecordStateReady}},
		{name: "ready then unknown", states: []string{dnsRecordStateReady, "Unknown"}},
		{name: "unknown then ready", states: []string{"Unknown", dnsRecordStateReady}},
		{name: "duplicate ready", states: []string{dnsRecordStateReady, dnsRecordStateReady}},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := listenerConvergenceGateway()
			tunnel := persistListenerConvergence(t, gateway)
			tunnel.Spec.DNS.Mode = v1alpha1.DNSModeManaged
			tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "a.example.com", State: dnsRecordStateReady}}
			for index, state := range test.states {
				hostname := "b.example.com"
				if index > 0 {
					hostname = strings.ToUpper(hostname)
				}
				tunnel.Status.DNSRecords = append(tunnel.Status.DNSRecords, v1alpha1.CloudflareTunnelDNSRecordStatus{Hostname: hostname, State: state})
			}
			blockDomainsForUnreadyDNS(gateway, tunnel)
			if firstEdgeService(t, gateway, "a.example.com") == "http_status:403" {
				t.Fatal("unrelated healthy listener was blocked")
			}
			if denied := firstEdgeService(t, gateway, "b.example.com") == "http_status:403"; denied == test.ready {
				t.Fatalf("affected listener denied=%t, want ready=%t", denied, test.ready)
			}
			if publicDNSReady(gateway, tunnel) != test.ready {
				t.Fatal("aggregate DNS gate disagrees with actual listener denial")
			}
			status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{{Name: "a"}, {Name: "b"}}}
			new(GatewayReconciler).setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, gateway, tunnel, true, "Waiting for DNS", privatePrerequisiteResult{})
			for _, listener := range status.Listeners {
				condition := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed))
				want := metav1.ConditionTrue
				if listener.Name == "b" && !test.ready {
					want = metav1.ConditionFalse
				}
				if condition == nil || condition.Status != want {
					t.Fatalf("listener %s = %#v, want %s", listener.Name, condition, want)
				}
			}
			global := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			if global == nil || (global.Status == metav1.ConditionTrue) != test.ready {
				t.Fatalf("Gateway Programmed = %#v", global)
			}
			// A fresh unique Ready observation releases the denied hostname;
			// stale duplicates must not poison later authoritative status.
			tunnel.Status.DNSRecords = tunnel.Status.DNSRecords[:1]
			tunnel.Status.DNSRecords = append(tunnel.Status.DNSRecords, v1alpha1.CloudflareTunnelDNSRecordStatus{Hostname: "B.EXAMPLE.COM", State: dnsRecordStateReady})
			recovered := listenerConvergenceGateway()
			blockDomainsForUnreadyDNS(recovered, tunnel)
			if firstEdgeService(t, recovered, "b.example.com") == "http_status:403" || !publicDNSReady(recovered, tunnel) {
				t.Fatal("unique Ready record did not restore forwarding")
			}
		})
	}
}
