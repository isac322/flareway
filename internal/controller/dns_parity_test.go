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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
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
	if err != nil || conflict == "" || !strings.Contains(conflict, "not owned") || len(status) != 0 {
		t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
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
	if err != nil || conflict == "" || !strings.Contains(conflict, "not owned") || len(status) != 0 {
		t.Fatalf("ensureDNS() status=%#v conflict=%q error=%v", status, conflict, err)
	}
	record, ok := cloudflareClient.DNSRecord(zoneID, "owned-a")
	if !ok || record.Type != "A" || record.Content != "192.0.2.1" {
		t.Fatalf("marker-carrying A record mutated: %#v, present=%t", record, ok)
	}
	if calls := cloudflareClient.Calls(); !slices.Equal(calls, []string{"ListDNSRecords"}) {
		t.Fatalf("marker-carrying A record calls = %v", calls)
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
