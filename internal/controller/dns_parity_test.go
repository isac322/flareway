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
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/ir"
)

func TestEnsureDNSProjectsBoundedCNAMEObservations(t *testing.T) {
	const (
		zoneID      = "zone-example"
		clusterID   = "cluster"
		gatewayName = "gateway"
		hostname    = "bücher.example"
		punycode    = "xn--bcher-kva.example"
		tunnelID    = "tunnel"
	)
	proxied, ipv4Only, ipv6Only := true, true, false
	ttl := int64(1)
	created := time.Date(2026, time.September, 10, 1, 2, 3, 0, time.UTC)
	modified := created.Add(time.Hour)
	commentModified := created.Add(30 * time.Minute)
	tunnel := dnsParityTunnel(proxied, ttl, ipv4Only, ipv6Only)
	owner := flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName)
	remoteSettings := &flarecloudflare.DNSRecordSettings{IPv4Only: &ipv4Only, IPv6Only: &ipv6Only}
	cloudflareClient := newFakeTunnelCloudflareFactory()
	cloudflareClient.PutDNS(zoneID, RemoteDNSRecord{
		ID: "record", Name: punycode, Type: "CNAME", Content: tunnelID + ".cfargotunnel.com",
		Comment: owner, TTL: ttl, Proxied: proxied, Proxiable: true, Settings: remoteSettings,
		CreatedOn: created, ModifiedOn: modified, CommentModifiedOn: commentModified,
	})

	status, conflict, err := new(CloudflareTunnelReconciler).ensureDNS(
		context.Background(), cloudflareClient, tunnel, gatewayName, clusterID, tunnelID,
		[]publicHostname{{Hostname: hostname, ZoneID: zoneID, ZoneName: "example"}},
	)
	if err != nil || conflict != "" || len(status) != 1 {
		t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
	}
	record := status[0]
	if record.Hostname != punycode || record.RecordID != "record" || record.ZoneID != zoneID || record.TTL != ttl ||
		record.Proxied == nil || !*record.Proxied || record.Proxiable == nil || !*record.Proxiable ||
		record.Settings == nil || record.Settings.IPv4Only == nil || !*record.Settings.IPv4Only ||
		record.Settings.IPv6Only == nil || *record.Settings.IPv6Only ||
		!sameMetaTime(record.CreatedOn, created) || !sameMetaTime(record.ModifiedOn, modified) ||
		!sameMetaTime(record.CommentModifiedOn, commentModified) {
		t.Fatalf("bounded DNS status = %#v", record)
	}
	if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords"}) {
		t.Fatalf("converged DNS calls = %v", calls)
	}
}

func TestEnsureDNSNeverMutatesForeignUnicodeCollision(t *testing.T) {
	const (
		zoneID      = "zone-example"
		clusterID   = "cluster"
		gatewayName = "gateway"
		hostname    = "bücher.example"
		punycode    = "xn--bcher-kva.example"
	)
	cloudflareClient := newFakeTunnelCloudflareFactory()
	cloudflareClient.PutDNS(zoneID, RemoteDNSRecord{
		ID: "foreign", Name: punycode, Type: "A", Content: "192.0.2.1", Comment: "terraform",
	})

	status, conflict, err := new(CloudflareTunnelReconciler).ensureDNS(
		context.Background(), cloudflareClient, dnsParityTunnel(true, 1, false, false),
		gatewayName, clusterID, "tunnel", []publicHostname{{Hostname: hostname, ZoneID: zoneID, ZoneName: "example"}},
	)
	if err != nil || conflict == "" || !strings.Contains(conflict, "not owned") || len(status) != 1 {
		t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
	}
	if record := status[0]; record.Hostname != punycode || record.State != dnsRecordStateConflict || record.RecordID != "" || record.OwnershipComment != "" {
		t.Fatalf("foreign record was not reported as an unowned conflict: %#v", record)
	}
	if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords"}) {
		t.Fatalf("foreign DNS calls = %v", calls)
	}
	if record, ok := cloudflareClient.DNSRecord(zoneID, "foreign"); !ok || record.Type != "A" || record.Content != "192.0.2.1" {
		t.Fatalf("foreign DNS record mutated: %#v, present=%t", record, ok)
	}
}

// A record carrying our ownership marker but pointing at foreign content is
// preserved, not deleted: the marker alone never authorizes a destructive
// write (D8), so the conflict is reported and the record is left untouched.
func TestEnsureDNSPreservesMarkerCarryingNonCNAME(t *testing.T) {
	const (
		zoneID      = "zone-example"
		clusterID   = "cluster"
		gatewayName = "gateway"
		hostname    = "bücher.example"
		punycode    = "xn--bcher-kva.example"
		tunnelID    = "tunnel"
	)
	tunnel := dnsParityTunnel(true, 1, false, true)
	owner := flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName)
	cloudflareClient := newFakeTunnelCloudflareFactory()
	cloudflareClient.PutDNS(zoneID, RemoteDNSRecord{
		ID: "owned-a", Name: punycode, Type: "A", Content: "192.0.2.1", Comment: owner,
	})

	status, conflict, err := new(CloudflareTunnelReconciler).ensureDNS(
		context.Background(), cloudflareClient, tunnel, gatewayName, clusterID, tunnelID,
		[]publicHostname{{Hostname: hostname, ZoneID: zoneID, ZoneName: "example"}},
	)
	if err != nil || conflict == "" || !strings.Contains(conflict, "not owned") || len(status) != 1 {
		t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
	}
	if record := status[0]; record.Hostname != punycode || record.State != dnsRecordStateConflict || record.RecordID != "" || record.OwnershipComment != "" {
		t.Fatalf("non-CNAME record was not reported as an unowned conflict: %#v", record)
	}
	record, ok := cloudflareClient.DNSRecord(zoneID, "owned-a")
	if !ok || record.Type != "A" || record.Content != "192.0.2.1" {
		t.Fatalf("marker-carrying A record mutated: %#v, present=%t", record, ok)
	}
	if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords"}) {
		t.Fatalf("marker-carrying A record calls = %v", calls)
	}
}

func TestEnsureDNSFreshConflictReportsListenerWithoutAdoptingForeignRecord(t *testing.T) {
	const (
		zoneID      = "zone-example"
		clusterID   = "cluster"
		gatewayName = "gateway"
		tunnelID    = "tunnel"
	)
	for _, ambiguous := range []bool{false, true} {
		name := "foreign CNAME"
		if ambiguous {
			name = "multiple records"
		}
		t.Run(name, func(t *testing.T) {
			tunnel := dnsParityTunnel(true, 1, false, false)
			owner := flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName)
			ipv4Only, ipv6Only := false, false
			cloudflareClient := newFakeTunnelCloudflareFactory()
			cloudflareClient.PutDNS(zoneID, RemoteDNSRecord{
				ID: "healthy", Name: "a.example.com", Type: "CNAME", Content: tunnelCNAMETarget(tunnelID),
				Comment: owner, TTL: 1, Proxied: true,
				Settings: &flarecloudflare.DNSRecordSettings{IPv4Only: &ipv4Only, IPv6Only: &ipv6Only},
			})
			foreign := RemoteDNSRecord{ID: "foreign", Name: "b.example.com", Type: "CNAME", Content: "other-tunnel.cfargotunnel.com", Comment: "terraform"}
			cloudflareClient.PutDNS(zoneID, foreign)
			if ambiguous {
				cloudflareClient.PutDNS(zoneID, RemoteDNSRecord{ID: "second-foreign", Name: foreign.Name, Type: "A", Content: "192.0.2.1"})
			}

			records, conflict, err := new(CloudflareTunnelReconciler).ensureDNS(
				context.Background(), cloudflareClient, tunnel, gatewayName, clusterID, tunnelID,
				[]publicHostname{{Hostname: "a.example.com", ZoneID: zoneID}, {Hostname: "b.example.com", ZoneID: zoneID}},
			)
			if err != nil || conflict == "" || len(records) != 2 {
				t.Fatalf("ensureDNS() records=%#v conflict=%q error=%v", records, conflict, err)
			}
			conflicted := records[1]
			if conflicted.Hostname != foreign.Name || conflicted.ZoneID != zoneID || conflicted.State != dnsRecordStateConflict || conflicted.RecordID != "" || conflicted.OwnershipComment != "" {
				t.Fatalf("fresh conflict claimed foreign ownership: %#v", conflicted)
			}
			tunnel.Status.DNSRecords = records
			compiled := &ir.Gateway{Listeners: []ir.Listener{
				{Name: "a", Hostname: "a.example.com", Exposure: ir.ExposurePublic},
				{Name: "b", Hostname: "b.example.com", Exposure: ir.ExposurePublic},
			}}
			status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{{Name: "a"}, {Name: "b"}}}
			new(GatewayReconciler).setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, compiled, tunnel, true, "Waiting for managed DNS", privatePrerequisiteResult{})
			global := meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			healthy := meta.FindStatusCondition(status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
			blocked := meta.FindStatusCondition(status.Listeners[1].Conditions, string(gatewayv1.ListenerConditionProgrammed))
			if global == nil || global.Status != metav1.ConditionFalse || healthy == nil || healthy.Status != metav1.ConditionTrue || blocked == nil || blocked.Status != metav1.ConditionFalse || blocked.Reason != "DNSConflict" {
				t.Fatalf("DNS conflict readiness: Gateway=%#v healthy=%#v blocked=%#v", global, healthy, blocked)
			}

			// Removing the listener drops the unowned conflict projection;
			// it must never turn the foreign record into a deletion target.
			remaining, cleanupConflict, err := removeDNSRecords(context.Background(), cloudflareClient, []string{owner}, []string{tunnelCNAMETarget(tunnelID)}, []v1alpha1.CloudflareTunnelDNSRecordStatus{conflicted})
			if err != nil || cleanupConflict != "" || len(remaining) != 0 {
				t.Fatalf("unowned conflict cleanup: remaining=%#v conflict=%q error=%v", remaining, cleanupConflict, err)
			}
			if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords", "ListDNSRecords", "ListDNSRecords"}) {
				t.Fatalf("foreign conflict triggered a DNS write: %v", calls)
			}
			if got, present := cloudflareClient.DNSRecord(zoneID, foreign.ID); !present || got.Content != foreign.Content || got.Comment != foreign.Comment || got.Type != foreign.Type {
				t.Fatalf("foreign DNS record mutated: %#v, present=%t", got, present)
			}
			if ambiguous {
				if got, present := cloudflareClient.DNSRecord(zoneID, "second-foreign"); !present || got.Type != "A" || got.Content != "192.0.2.1" {
					t.Fatalf("ambiguous DNS record mutated: %#v, present=%t", got, present)
				}
			}
		})
	}
}

func TestEnsureDNSKeepsRepurposedStaleRecords(t *testing.T) {
	const (
		zoneID      = "zone-example"
		clusterID   = "cluster"
		gatewayName = "gateway"
		hostname    = "stale.example"
		recordID    = "managed-record"
	)
	tunnel := dnsParityTunnel(true, 1, false, false)
	previous := v1alpha1.CloudflareTunnelDNSRecordStatus{
		Hostname: hostname,
		RecordID: recordID,
		ZoneID:   zoneID,
	}
	tunnel.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{previous}
	owner := flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, gatewayName)

	tests := []struct {
		name   string
		record RemoteDNSRecord
	}{
		{
			name: "ownership comment changed",
			record: RemoteDNSRecord{
				ID: recordID, Name: hostname, Type: "CNAME",
				Content: "foreign.example", Comment: "terraform",
			},
		},
		{
			name: "record ID changed",
			record: RemoteDNSRecord{
				ID: "replacement-record", Name: hostname, Type: "CNAME",
				Content: "foreign.example", Comment: owner,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cloudflareClient := newFakeTunnelCloudflareFactory()
			cloudflareClient.PutDNS(zoneID, test.record)

			status, conflict, err := new(CloudflareTunnelReconciler).ensureDNS(
				context.Background(), cloudflareClient, tunnel, gatewayName, clusterID, "tunnel", nil,
			)
			expected := previous
			if test.name == "record ID changed" {
				if err != nil || conflict != "" || len(status) != 0 {
					t.Fatalf("missing checkpoint should be pruned: status=%#v conflict=%q error=%v", status, conflict, err)
				}
			} else if err != nil || conflict == "" || !slices.Equal(status, []v1alpha1.CloudflareTunnelDNSRecordStatus{expected}) {
				t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
			}
			if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords"}) {
				t.Fatalf("repurposed stale DNS calls = %v", calls)
			}
			if record, ok := cloudflareClient.DNSRecord(zoneID, test.record.ID); !ok || record.Content != "foreign.example" {
				t.Fatalf("repurposed stale DNS record mutated: %#v, present=%t", record, ok)
			}
		})
	}
}

func dnsParityTunnel(proxied bool, ttl int64, ipv4Only, ipv6Only bool) *v1alpha1.CloudflareTunnel {
	return &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant"},
		Spec: v1alpha1.CloudflareTunnelSpec{DNS: v1alpha1.CloudflareTunnelDNSConfig{
			Mode: v1alpha1.DNSModeManaged, Proxied: &proxied, TTL: &ttl,
			Settings: &v1alpha1.DNSRecordSettings{IPv4Only: &ipv4Only, IPv6Only: &ipv6Only},
		}},
	}
}

func sameMetaTime(value *metav1.Time, expected time.Time) bool {
	return value != nil && value.Time.Equal(expected)
}
