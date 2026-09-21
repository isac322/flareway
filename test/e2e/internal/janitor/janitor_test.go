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
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
	"github.com/isac322/flareway/test/e2e/internal/names"
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
	profiles        []cfapi.DeviceProfile
	registrations   []cfapi.DeviceRegistration
	appPolicies     map[string][]cfapi.AccessPolicy
	deleted         []string
	deleteFailures  map[string]error
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

func (f *fakeAPI) ListDeviceProfiles(context.Context) ([]cfapi.DeviceProfile, error) {
	return append([]cfapi.DeviceProfile(nil), f.profiles...), nil
}

func (f *fakeAPI) DeleteDeviceProfile(_ context.Context, id string) error {
	f.deleted = append(f.deleted, "device-profile/"+id)
	return nil
}

func (f *fakeAPI) ListDeviceRegistrations(context.Context) ([]cfapi.DeviceRegistration, error) {
	return append([]cfapi.DeviceRegistration(nil), f.registrations...), nil
}

func (f *fakeAPI) DeleteDeviceRegistration(_ context.Context, id string) error {
	if err := f.deleteFailures["registration/"+id]; err != nil {
		return err
	}
	f.deleted = append(f.deleted, "registration/"+id)
	return nil
}

func (f *fakeAPI) ListAccessApplicationPolicies(_ context.Context, applicationID string) ([]cfapi.AccessPolicy, error) {
	return append([]cfapi.AccessPolicy(nil), f.appPolicies[applicationID]...), nil
}

func (f *fakeAPI) DeleteAccessApplicationPolicy(_ context.Context, applicationID, policyID string) error {
	f.deleted = append(f.deleted, "app-policy/"+applicationID+"/"+policyID)
	return nil
}

// TestSweepPrefixRetainsProfileWhenRegistrationDeleteFails proves a failed
// registration deletion keeps its owning profile: deleting the profile would
// orphan the registration and erase the only ownership link.
func TestSweepPrefixRetainsProfileWhenRegistrationDeleteFails(t *testing.T) {
	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour)
	api := &fakeAPI{
		profiles: []cfapi.DeviceProfile{
			{PolicyID: "blocked", Name: "flareway-e2e-deadbeef-warp-profile", CreatedAt: old},
			{PolicyID: "clean", Name: "flareway-e2e-deadbeef-device-profile", CreatedAt: old},
		},
		registrations: []cfapi.DeviceRegistration{
			{ID: "reg-fails", Policy: &cfapi.DeviceRegistrationPolicy{ID: "blocked"}, CreatedAt: old},
			{ID: "reg-ok", Policy: &cfapi.DeviceRegistrationPolicy{ID: "clean"}, CreatedAt: old},
		},
		deleteFailures: map[string]error{"registration/reg-fails": errors.New("cloudflare conflict")},
	}

	report, err := SweepPrefix(context.Background(), api, "flareway-e2e-deadbeef", 2*time.Hour, now)
	if err == nil {
		t.Fatal("SweepPrefix did not report the registration failure")
	}
	want := []string{"registration/reg-ok", "device-profile/clean"}
	if !reflect.DeepEqual(api.deleted, want) {
		t.Fatalf("deletions = %#v, want %#v", api.deleted, want)
	}
	if report.DeviceProfilesDeleted != 1 || report.DeviceRegistrationsDeleted != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestSweepPrefixDeletesOnlyOwnedStaleDisconnectedResources(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour)
	recent := now.Add(-time.Hour)
	api := &fakeAPI{
		applications: []cfapi.AccessApplication{
			{ID: "parent", Name: "flareway-e2e-deadbeef/access", CreatedAt: old},
			{ID: "child", Name: "flareway-e2e-deadbeef/access/bypass/v1", Tags: []string{"flareway-bypass-aaaabbbb"}, CreatedAt: old},
			{ID: "recent", Name: "flareway-e2e-deadbeef/recent", CreatedAt: recent},
			{ID: "other-run", Name: "flareway-e2e-cafebabe/access", CreatedAt: old},
			{ID: "warp-app", Name: "warp", Type: "warp", CreatedAt: old},
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
		profiles: []cfapi.DeviceProfile{
			{PolicyID: "owned", Name: "flareway-e2e-deadbeef-device-profile", CreatedAt: old},
			{PolicyID: "owned-match", Name: "renamed", Match: `identity.email == "flareway-e2e-deadbeef@example.invalid"`, CreatedAt: old},
			{PolicyID: "other-run", Name: "flareway-e2e-cafebabe-device-profile", CreatedAt: old},
			{PolicyID: "default", Name: "flareway-e2e-deadbeef-device-profile", Default: true, CreatedAt: old},
			{PolicyID: "recent", Name: "flareway-e2e-deadbeef-warp-profile", CreatedAt: recent},
		},
		registrations: []cfapi.DeviceRegistration{
			{ID: "reg-owned", Policy: &cfapi.DeviceRegistrationPolicy{ID: "owned"}, CreatedAt: old},
			{ID: "reg-owned-nested", Policy: &cfapi.DeviceRegistrationPolicy{ID: "owned-match"}, CreatedAt: old},
			{ID: "reg-recent", Policy: &cfapi.DeviceRegistrationPolicy{ID: "recent"}, CreatedAt: old},
			{ID: "reg-other-run", Policy: &cfapi.DeviceRegistrationPolicy{ID: "other-run"}, CreatedAt: old},
			{ID: "reg-default", Policy: &cfapi.DeviceRegistrationPolicy{ID: "default"}, CreatedAt: old},
			{ID: "reg-foreign", Policy: &cfapi.DeviceRegistrationPolicy{ID: "unrelated-profile"}, CreatedAt: old},
			{ID: "reg-deleted", Policy: &cfapi.DeviceRegistrationPolicy{ID: "owned"}, CreatedAt: old, DeletedAt: &old},
		},
		appPolicies: map[string][]cfapi.AccessPolicy{
			"warp-app": {
				{ID: "enroll-owned", Name: "flareway-e2e-deadbeef-warp-enroll", CreatedAt: old},
				{ID: "enroll-other-run", Name: "flareway-e2e-cafebabe-warp-enroll", CreatedAt: old},
				{ID: "enroll-foreign", Name: "enrollment-policy", CreatedAt: old},
			},
		},
	}

	report, err := SweepPrefix(context.Background(), api, "flareway-e2e-deadbeef", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("SweepPrefix returned error: %v", err)
	}
	if report.AccessApplicationsDeleted != 2 || report.AccessPoliciesDeleted != 2 || report.ServiceTokensDeleted != 1 ||
		report.HostnameRoutesDeleted != 1 || report.NetworkRoutesDeleted != 1 || report.VirtualNetworksDeleted != 1 ||
		report.DNSRecordsDeleted != 2 || report.TunnelsDeleted != 1 || report.DeviceProfilesDeleted != 2 ||
		report.DeviceRegistrationsDeleted != 2 || report.ConnectedSkipped != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	want := []string{
		"application/child", "application/parent", "policy/owned",
		"registration/reg-owned", "registration/reg-owned-nested",
		"device-profile/owned", "device-profile/owned-match",
		"app-policy/warp-app/enroll-owned", "token/owned",
		"hostname-route/owned", "network-route/owned", "virtual-network/owned",
		"dns/owned-stale", "dns/owned-tag", "tunnel/owned-stale",
	}
	if !reflect.DeepEqual(api.deleted, want) {
		t.Fatalf("deletion order = %#v, want %#v", api.deleted, want)
	}
}

func TestSweepPrefixRejectsBroadPrefix(t *testing.T) {
	for _, prefix := range []string{"flareway-", "flareway-e2e", "flareway-e2e-dead", "flareway-e2e-deadbeef-extra", "flareway-e2e-nothexzz"} {
		if _, err := SweepPrefix(context.Background(), &fakeAPI{}, prefix, 0, time.Now()); err == nil {
			t.Fatalf("SweepPrefix accepted unsafe prefix %q", prefix)
		}
	}
}

// TestSweepPrefixRejectsLookAlikeMarkers proves that a substring of the
// ownership marker inside foreign names, comments, or tags never authorizes
// deletion in a shared account.
func TestSweepPrefixRejectsLookAlikeMarkers(t *testing.T) {
	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour)
	api := &fakeAPI{
		applications: []cfapi.AccessApplication{
			{ID: "embedded", Name: "prod-flareway-e2e-deadbeef/access", CreatedAt: old},
			{ID: "extended-run", Name: "flareway-e2e-deadbeef2/access", CreatedAt: old},
			{ID: "tag-lookalike", Name: "foreign/app", Tags: []string{"note=prod-flareway-e2e-deadbeef"}, CreatedAt: old},
			{ID: "warp-app", Name: "warp", Type: "warp", CreatedAt: old},
		},
		policies: []cfapi.AccessPolicy{
			{ID: "embedded", Name: "flareway/uid/prod-flareway-e2e-deadbeef/policy", CreatedAt: old},
			{ID: "extended-run", Name: "flareway/uid/flareway-e2e-deadbeef2/policy", CreatedAt: old},
		},
		tokens: []cfapi.ServiceToken{
			{ID: "embedded", Name: "ci-flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "underscore", Name: "ci_flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "dotted", Name: "ci.flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "extended-run", Name: "flareway-e2e-deadbeefx", CreatedAt: old},
			{ID: "underscore-suffix", Name: "flareway-e2e-deadbeef_extra", CreatedAt: old},
			{ID: "dotted-suffix", Name: "flareway-e2e-deadbeef.example.com", CreatedAt: old},
		},
		tunnels: []cfapi.Tunnel{
			{ID: "embedded", Name: "prod-flareway-e2e-deadbeef-public", CreatedAt: old},
			{ID: "extended-run", Name: "flareway-e2e-deadbeef2-public", CreatedAt: old},
		},
		records: []cfapi.DNSRecord{
			{ID: "embedded-comment", Name: "app.example.com", Comment: "flareway uid/prod-flareway-e2e-deadbeef/app", CreatedOn: old},
			{ID: "extended-run", Name: "app.example.com", Comment: "flareway uid/flareway-e2e-deadbeef2/app", CreatedOn: old},
			{ID: "tag-lookalike", Name: "app.example.com", Tags: []string{"owner=prod-flareway-e2e-deadbeef"}, CreatedOn: old},
		},
		virtualNetworks: []cfapi.VirtualNetwork{
			{ID: "embedded", Name: "prod-flareway-e2e-deadbeef/private", CreatedAt: old},
			{ID: "comment-lookalike", Name: "foreign", Comment: "flareway uid/prod-flareway-e2e-deadbeef/vnet", CreatedAt: old},
		},
		networkRoutes: []cfapi.NetworkRoute{
			{ID: "comment-lookalike", Network: "10.96.0.0/12", Comment: "flareway uid/prod-flareway-e2e-deadbeef/route", CreatedAt: old},
		},
		hostnameRoutes: []cfapi.HostnameRoute{
			{ID: "comment-lookalike", Hostname: "private.internal", Comment: "flareway uid/prod-flareway-e2e-deadbeef/route", CreatedAt: old},
		},
		profiles: []cfapi.DeviceProfile{
			{PolicyID: "embedded", Name: "prod-flareway-e2e-deadbeef-device-profile", CreatedAt: old},
			{PolicyID: "extended-run", Name: "flareway-e2e-deadbeef2-device-profile", CreatedAt: old},
			{PolicyID: "match-lookalike", Name: "foreign", Match: `identity.email == "prod-flareway-e2e-deadbeef@example.invalid"`, CreatedAt: old},
		},
		registrations: []cfapi.DeviceRegistration{
			{ID: "reg-lookalike", Policy: &cfapi.DeviceRegistrationPolicy{ID: "embedded"}, CreatedAt: old},
			{ID: "reg-extended", Policy: &cfapi.DeviceRegistrationPolicy{ID: "extended-run"}, CreatedAt: old},
		},
		appPolicies: map[string][]cfapi.AccessPolicy{
			"warp-app": {
				{ID: "enroll-lookalike", Name: "prod-flareway-e2e-deadbeef-warp-enroll", CreatedAt: old},
				{ID: "enroll-extended", Name: "flareway-e2e-deadbeef2-warp-enroll", CreatedAt: old},
			},
		},
	}

	report, err := SweepPrefix(context.Background(), api, "flareway-e2e-deadbeef", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("SweepPrefix returned error: %v", err)
	}
	if report != (Report{}) {
		t.Fatalf("look-alike markers authorized deletions: %#v", report)
	}
	if len(api.deleted) != 0 {
		t.Fatalf("deleted foreign resources: %#v", api.deleted)
	}
}

// TestSweepGlobalPrefixRequiresWellFormedRunID proves the bare owner prefix
// only matches markers carrying a complete run ID, so global stale sweeps
// cannot delete look-alike or truncated names.
func TestSweepGlobalPrefixRequiresWellFormedRunID(t *testing.T) {
	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour)
	api := &fakeAPI{
		applications: []cfapi.AccessApplication{
			{ID: "warp-app", Name: "warp", Type: "warp", CreatedAt: old},
		},
		tokens: []cfapi.ServiceToken{
			{ID: "owned", Name: "flareway-e2e-deadbeef-warp-token", CreatedAt: old},
			{ID: "other-run", Name: "flareway-e2e-cafebabe-warp-token", CreatedAt: old},
			{ID: "truncated", Name: "flareway-e2e-dead", CreatedAt: old},
			{ID: "extended", Name: "flareway-e2e-deadbeef2", CreatedAt: old},
			{ID: "non-hex", Name: "flareway-e2e-nothexzz", CreatedAt: old},
			{ID: "embedded", Name: "prod-flareway-e2e-deadbeef", CreatedAt: old},
			{ID: "foreign", Name: "ci-token", CreatedAt: old},
		},
		profiles: []cfapi.DeviceProfile{
			{PolicyID: "owned", Name: "flareway-e2e-deadbeef-warp-profile", CreatedAt: old},
			{PolicyID: "dated", Name: "flareway-e2e-cafebabe-warp-profile", Description: "runner " + names.CreatedMarkerPrefix + old.Format(time.RFC3339)},
			{PolicyID: "undated", Name: "flareway-e2e-0badf00d-warp-profile"},
			{PolicyID: "default", Name: "flareway-e2e-deadbeef-device-profile", Default: true, CreatedAt: old},
			{PolicyID: "embedded", Name: "prod-flareway-e2e-deadbeef-profile", CreatedAt: old},
		},
		registrations: []cfapi.DeviceRegistration{
			{ID: "reg-owned", Policy: &cfapi.DeviceRegistrationPolicy{ID: "owned"}, CreatedAt: old},
			{ID: "reg-dated", Policy: &cfapi.DeviceRegistrationPolicy{ID: "dated"}, CreatedAt: old},
			{ID: "reg-undated", Policy: &cfapi.DeviceRegistrationPolicy{ID: "undated"}, CreatedAt: old},
			{ID: "reg-default", Policy: &cfapi.DeviceRegistrationPolicy{ID: "default"}, CreatedAt: old},
			{ID: "reg-embedded", Policy: &cfapi.DeviceRegistrationPolicy{ID: "embedded"}, CreatedAt: old},
			{ID: "reg-foreign", Policy: &cfapi.DeviceRegistrationPolicy{ID: "unrelated"}, CreatedAt: old},
		},
		appPolicies: map[string][]cfapi.AccessPolicy{
			"warp-app": {
				{ID: "enroll-owned", Name: "flareway-e2e-cafebabe-warp-enroll", CreatedAt: old},
				{ID: "enroll-foreign", Name: "enrollment-policy", CreatedAt: old},
			},
		},
	}

	report, err := SweepPrefix(context.Background(), api, "flareway-e2e-", 2*time.Hour, now)
	if err != nil {
		t.Fatalf("SweepPrefix returned error: %v", err)
	}
	want := []string{"registration/reg-owned", "registration/reg-dated", "device-profile/owned", "device-profile/dated", "app-policy/warp-app/enroll-owned", "token/owned", "token/other-run"}
	if !reflect.DeepEqual(api.deleted, want) {
		t.Fatalf("global sweep deletions = %#v, want %#v", api.deleted, want)
	}
	if report.ServiceTokensDeleted != 2 || report.DeviceProfilesDeleted != 2 ||
		report.DeviceRegistrationsDeleted != 2 || report.AccessPoliciesDeleted != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
}
