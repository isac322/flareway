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

package janitor

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
)

type fakeAPI struct {
	applications    []cfapi.AccessApplication
	policies        []cfapi.AccessPolicy
	tokens          []cfapi.ServiceToken
	tunnels         []cfapi.Tunnel
	records         []cfapi.DNSRecord
	virtualNetworks []cfapi.VirtualNetwork
	networkRoutes   []cfapi.NetworkRoute
	hostnameRoutes  []cfapi.HostnameRoute
	deleted         []string
}

func (f *fakeAPI) ListAccessApplications(context.Context) ([]cfapi.AccessApplication, error) {
	return append([]cfapi.AccessApplication(nil), f.applications...), nil
}

func (f *fakeAPI) DeleteAccessApplication(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "application/"+id)
	return nil
}

func (f *fakeAPI) ListAccessPolicies(context.Context) ([]cfapi.AccessPolicy, error) {
	return append([]cfapi.AccessPolicy(nil), f.policies...), nil
}

func (f *fakeAPI) DeleteAccessPolicy(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "policy/"+id)
	return nil
}

func (f *fakeAPI) ListServiceTokens(context.Context) ([]cfapi.ServiceToken, error) {
	return append([]cfapi.ServiceToken(nil), f.tokens...), nil
}

func (f *fakeAPI) DeleteServiceToken(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "token/"+id)
	return nil
}

func (f *fakeAPI) ListTunnels(context.Context) ([]cfapi.Tunnel, error) {
	return append([]cfapi.Tunnel(nil), f.tunnels...), nil
}

func (f *fakeAPI) DeleteTunnel(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "tunnel/"+id)
	return nil
}

func (f *fakeAPI) ListDNSRecords(context.Context) ([]cfapi.DNSRecord, error) {
	return append([]cfapi.DNSRecord(nil), f.records...), nil
}

func (f *fakeAPI) DeleteDNSRecord(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "dns/"+id)
	return nil
}

func (f *fakeAPI) ListVirtualNetworks(context.Context) ([]cfapi.VirtualNetwork, error) {
	return append([]cfapi.VirtualNetwork(nil), f.virtualNetworks...), nil
}

func (f *fakeAPI) DeleteVirtualNetwork(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "virtual-network/"+id)
	return nil
}

func (f *fakeAPI) ListNetworkRoutes(context.Context) ([]cfapi.NetworkRoute, error) {
	return append([]cfapi.NetworkRoute(nil), f.networkRoutes...), nil
}

func (f *fakeAPI) DeleteNetworkRoute(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "network-route/"+id)
	return nil
}

func (f *fakeAPI) ListHostnameRoutes(context.Context) ([]cfapi.HostnameRoute, error) {
	return append([]cfapi.HostnameRoute(nil), f.hostnameRoutes...), nil
}

func (f *fakeAPI) DeleteHostnameRoute(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "hostname-route/"+id)
	return nil
}

func TestSweepPrefixDeletesOnlyOwnedStaleDisconnectedResources(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour)
	recent := now.Add(-time.Hour)
	api := &fakeAPI{
		applications: []cfapi.AccessApplication{
			{ID: "parent", Name: "flareway-e2e-deadbeef/access", CreatedAt: old},
			{ID: "child", Name: "flareway-e2e-deadbeef/access/bypass/v1", Tags: []string{"flareway-bypass-of=parent"}, CreatedAt: old},
			{ID: "recent", Name: "flareway-e2e-deadbeef/recent", CreatedAt: recent},
			{ID: "other-run", Name: "flareway-e2e-cafebabe/access", CreatedAt: old},
		},
		policies: []cfapi.AccessPolicy{
			{ID: "owned", Name: "flareway-e2e-deadbeef/service-auth", CreatedAt: old},
			{ID: "other-run", Name: "flareway-e2e-cafebabe/service-auth", CreatedAt: old},
		},
		tokens: []cfapi.ServiceToken{
			{ID: "owned", Name: "flareway-e2e-deadbeef/service", CreatedAt: old},
			{ID: "other-run", Name: "flareway-e2e-cafebabe/service", CreatedAt: old},
		},
		tunnels: []cfapi.Tunnel{
			{ID: "owned-stale", Name: "flareway-e2e-deadbeef-public", CreatedAt: old},
			{ID: "owned-recent", Name: "flareway-e2e-deadbeef-recent", CreatedAt: recent},
			{ID: "other-run", Name: "flareway-e2e-cafebabe-public", CreatedAt: old},
			{ID: "connected", Name: "flareway-e2e-deadbeef-connected", CreatedAt: old, Connections: []map[string]any{{"id": "connection"}}},
			{ID: "healthy", Name: "flareway-e2e-deadbeef-healthy", Status: "healthy", CreatedAt: old},
			{ID: "unowned", Name: "production", CreatedAt: old},
		},
		records: []cfapi.DNSRecord{
			{ID: "owned-stale", Name: "e2e.example.com", Comment: "flareway flareway-e2e-deadbeef", CreatedOn: old},
			{ID: "owned-tag", Name: "tagged.example.com", Tags: []string{"owner=flareway-e2e-deadbeef"}, CreatedOn: old},
			{ID: "owned-recent", Name: "recent.example.com", Comment: "flareway-e2e-deadbeef", CreatedOn: recent},
			{ID: "other-run", Name: "e2e.example.com", Comment: "flareway-e2e-cafebabe", CreatedOn: old},
			{ID: "unowned", Name: "production.example.com", CreatedOn: old},
		},
		virtualNetworks: []cfapi.VirtualNetwork{
			{ID: "owned", Name: "flareway-e2e-deadbeef/private", CreatedAt: old},
			{ID: "recent", Name: "flareway-e2e-deadbeef/recent", CreatedAt: recent},
			{ID: "other-run", Name: "flareway-e2e-cafebabe/private", CreatedAt: old},
		},
		networkRoutes: []cfapi.NetworkRoute{
			{ID: "owned", Network: "10.96.0.0/12", Comment: "flareway flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "other-run", Network: "10.97.0.0/16", Comment: "flareway flareway-e2e-cafebabe", CreatedAt: old},
		},
		hostnameRoutes: []cfapi.HostnameRoute{
			{ID: "owned", Hostname: "private.internal", Comment: "flareway flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "other-run", Hostname: "private.internal", Comment: "flareway flareway-e2e-cafebabe", CreatedAt: old},
		},
	}

	report, err := SweepPrefix(context.Background(), api, "flareway-e2e-deadbeef", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("SweepPrefix returned error: %v", err)
	}
	if report.AccessApplicationsDeleted != 2 || report.AccessPoliciesDeleted != 1 || report.ServiceTokensDeleted != 1 ||
		report.HostnameRoutesDeleted != 1 || report.NetworkRoutesDeleted != 1 || report.VirtualNetworksDeleted != 1 ||
		report.DNSRecordsDeleted != 2 || report.TunnelsDeleted != 1 || report.ConnectedSkipped != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	want := []string{
		"application/child", "application/parent", "policy/owned", "token/owned",
		"hostname-route/owned", "network-route/owned", "virtual-network/owned",
		"dns/owned-stale", "dns/owned-tag", "tunnel/owned-stale",
	}
	if !reflect.DeepEqual(api.deleted, want) {
		t.Fatalf("deletion order = %#v, want %#v", api.deleted, want)
	}
}

func TestSweepPrefixRejectsBroadPrefix(t *testing.T) {
	_, err := SweepPrefix(context.Background(), &fakeAPI{}, "flareway-", 0, time.Now())
	if err == nil {
		t.Fatal("SweepPrefix accepted an unsafe prefix")
	}
}
