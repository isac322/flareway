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

package sweep

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"pgregory.net/rapid"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/observability"
)

// This file covers issue #114: the DNS sweep lists only the zones this
// installation can own records in — zones named by any grant, plus zones
// holding checkpoints of the tunnels the pass judges — so a least-privilege
// token scoped to the granted zones yields result=ok instead of a permanent
// partial built from 403s on zones Flareway can never write.

func scanZoneIDs(zones []flarecloudflare.Zone) []string {
	ids := make([]string, 0, len(zones))
	for _, zone := range zones {
		ids = append(ids, zone.ID)
	}
	return ids
}

// healthyRecord is the remote CNAME the controller writes for a tunnel's
// hostname, matching v1alpha1Checkpoint(hostname, id, zone, marker).
func healthyRecord(id, hostname, tunnelName, marker string) flarecloudflare.DNSRecord {
	return flarecloudflare.DNSRecord{
		ID: id, Type: "CNAME", Name: hostname,
		Content: tunnelCNAMETarget("tid-" + tunnelName), Comment: marker,
	}
}

func probeKey(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: "ns", Name: name}
}

func TestDNSScanZones(t *testing.T) {
	t.Parallel()
	inventory := []flarecloudflare.Zone{
		{ID: "id-a", Name: "a.example"},
		{ID: "id-b", Name: "b.example"},
		{ID: "id-c", Name: "c.example"},
	}
	grant := func(zones ...string) v1alpha1.CloudflareAccountGrant {
		return v1alpha1.CloudflareAccountGrant{Zones: zones}
	}
	cases := []struct {
		name        string
		grants      []v1alpha1.CloudflareAccountGrant
		checkpoints map[string]bool
		want        []string
	}{
		{"exact name", []v1alpha1.CloudflareAccountGrant{grant("b.example")}, nil, []string{"id-b"}},
		{"grant name normalized like authz", []v1alpha1.CloudflareAccountGrant{grant(" B.Example. ")}, nil, []string{"id-b"}},
		{"wildcard keeps the whole inventory", []v1alpha1.CloudflareAccountGrant{grant("b.example"), grant("*")}, nil, []string{"id-a", "id-b", "id-c"}},
		{"union across grants", []v1alpha1.CloudflareAccountGrant{grant("a.example"), grant("c.example")}, nil, []string{"id-a", "id-c"}},
		{"no grants lists nothing", nil, nil, []string{}},
		{"grant naming a zone outside the inventory", []v1alpha1.CloudflareAccountGrant{grant("gone.example")}, nil, []string{}},
		{"checkpoint keeps a revoked zone", []v1alpha1.CloudflareAccountGrant{grant("a.example")}, map[string]bool{"id-c": true}, []string{"id-a", "id-c"}},
		{"checkpoint zone that left the inventory", nil, map[string]bool{"id-gone": true}, []string{}},
		{"grant and checkpoint on one zone listed once", []v1alpha1.CloudflareAccountGrant{grant("a.example")}, map[string]bool{"id-a": true}, []string{"id-a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scanZoneIDs(dnsScanZones(inventory, tc.grants, tc.checkpoints))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("scan zones = %v, want %v", got, tc.want)
			}
		})
	}
}

// A least-privilege token denies DNS reads outside the granted zone. Those
// zones are never called, so a healthy pass is ok; RunTargetOnce publishes
// last-success only on ok, and QA-18(a) in dns_sweep_test.go owns the
// serial gauge assertion (the gauge has one-second resolution).
func TestDNSSweepScopedToGrantedZones(t *testing.T) {
	t.Parallel()
	marker := probeMarker("gw")
	checkpoint := v1alpha1Checkpoint("app.zone-a.example.com", "rec-1", "zone-a", marker)
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", records: []flarecloudflare.DNSRecord{healthyRecord("rec-1", "app.zone-a.example.com", "gw", marker)}},
			{id: "zone-b", err: deniedZoneError(errors.New("zone-b denied"), http.StatusForbidden)},
			{id: "zone-c", err: deniedZoneError(errors.New("zone-c denied"), http.StatusForbidden)},
		},
		grantZones: []string{"zone-a.example.com"},
		objects:    []client.Object{probeTunnel("gw", checkpoint)},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultOK || err != nil {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
	}
	requireItems(t, items)
	requireDNSCalls(t, f.api, "zone-a")
}

// A denial on a granted zone is a real token/grant mismatch and keeps the
// isolated partial; the ungranted zone is still never called.
func TestDNSSweepGrantedZoneDeniedStaysPartial(t *testing.T) {
	t.Parallel()
	causeA := errors.New("zone-a denied")
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones: []probeZone{
			{id: "zone-a", err: deniedZoneError(causeA, http.StatusForbidden)},
			{id: "zone-b", err: deniedZoneError(errors.New("zone-b denied"), http.StatusForbidden)},
		},
		grantZones: []string{"zone-a.example.com"},
		objects:    []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.zone-a.example.com", "rec-1", "zone-a", probeMarker("gw")))},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultPartial {
		t.Fatalf("result = %q, want partial (err=%v)", result, err)
	}
	requireScopedFailures(t, err, causeA)
	requireItems(t, items)
	requireDNSCalls(t, f.api, "zone-a")
}

// A zone whose grant was revoked stays in scope while a judged tunnel still
// checkpoints records there: drift is still found, and a denial there is
// still a partial, because the records still need cleanup access.
func TestDNSSweepCheckpointZoneOutsideGrants(t *testing.T) {
	t.Parallel()
	marker := probeMarker("gw")
	checkpoint := v1alpha1Checkpoint("app.zone-b.example.com", "rec-b", "zone-b", marker)
	drifted := healthyRecord("rec-b", "app.zone-b.example.com", "gw", marker)
	drifted.Content = "192.0.2.9"

	t.Run("drift found", func(t *testing.T) {
		t.Parallel()
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones: []probeZone{
				{id: "zone-a"},
				{id: "zone-b", records: []flarecloudflare.DNSRecord{drifted}},
				{id: "zone-c", err: deniedZoneError(errors.New("zone-c denied"), http.StatusForbidden)},
			},
			grantZones: []string{"zone-a.example.com"},
			objects:    []client.Object{probeTunnel("gw", checkpoint)},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultOK || err != nil {
			t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
		}
		requireItems(t, items, DriftItem{Case: DriftCaseMismatch, RemoteID: "rec-b", TargetKind: "CloudflareTunnel", NamespacedName: probeKey("gw")})
		requireDNSCalls(t, f.api, "zone-a", "zone-b")
	})

	t.Run("denied is partial", func(t *testing.T) {
		t.Parallel()
		causeB := errors.New("zone-b denied")
		f := newDNSProbeFixture(t, dnsProbeConfig{
			zones: []probeZone{
				{id: "zone-a"},
				{id: "zone-b", err: deniedZoneError(causeB, http.StatusForbidden)},
			},
			grantZones: []string{"zone-a.example.com"},
			objects:    []client.Object{probeTunnel("gw", checkpoint)},
		})
		items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
		if result != observability.SweepResultPartial {
			t.Fatalf("result = %q, want partial (err=%v)", result, err)
		}
		requireScopedFailures(t, err, causeB)
		requireItems(t, items)
		requireDNSCalls(t, f.api, "zone-a", "zone-b")
	})
}

// Checkpoints of tunnels the pass does not judge — ObserveOnly, deleting,
// or bound to another account — never widen the scan set.
func TestDNSSweepExcludedTunnelCheckpointsDoNotWidenScan(t *testing.T) {
	t.Parallel()
	deletingNow := metav1.Now()
	cases := []struct {
		name   string
		mutate func(tunnel *v1alpha1.CloudflareTunnel)
	}{
		{"observe only", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		}},
		{"deleting", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Finalizers = []string{"flareway.io/test-finalizer"}
			tunnel.DeletionTimestamp = &deletingNow
		}},
		{"foreign account", func(tunnel *v1alpha1.CloudflareTunnel) {
			tunnel.Spec.AccountRef.Name = "other-account"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tunnel := probeTunnel("gw", v1alpha1Checkpoint("app.zone-b.example.com", "rec-b", "zone-b", probeMarker("gw")))
			tc.mutate(tunnel)
			f := newDNSProbeFixture(t, dnsProbeConfig{
				zones: []probeZone{
					{id: "zone-a"},
					{id: "zone-b", err: deniedZoneError(errors.New("zone-b denied"), http.StatusForbidden)},
				},
				grantZones: []string{"zone-a.example.com"},
				objects:    []client.Object{tunnel},
			})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if result != observability.SweepResultOK || err != nil {
				t.Fatalf("RunTargetOnce = (%v, %q, %v), want ok", items, result, err)
			}
			requireDNSCalls(t, f.api, "zone-a")
		})
	}
}

// Without the account the grants are unknown, so the pass fails closed
// before any Cloudflare call.
func TestDNSSweepAccountReadFailure(t *testing.T) {
	t.Parallel()
	f := newDNSProbeFixture(t, dnsProbeConfig{
		zones:          []probeZone{{id: "zone-a"}},
		withoutAccount: true,
		objects:        []client.Object{probeTunnel("gw", v1alpha1Checkpoint("app.zone-a.example.com", "rec-1", "zone-a", probeMarker("gw")))},
	})
	items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
	if result != observability.SweepResultError || err == nil || items != nil {
		t.Fatalf("RunTargetOnce = (%v, %q, %v), want error", items, result, err)
	}
	requireDNSCalls(t, f.api)
}

// Metamorphic: whenever every flareway-marked record lives in a zone the
// installation can own records in (granted or checkpointed — the contract
// enforced by authorizeBindings before ensureDNS writes), the scoped pass
// returns exactly the findings of the full-account pass, and it lists
// only the scan set.
func TestDNSSweepScopedMatchesFullEnumeration(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		zoneCount := rapid.IntRange(1, 5).Draw(rt, "zones")
		zoneIDs := make([]string, zoneCount)
		for i := range zoneIDs {
			zoneIDs[i] = fmt.Sprintf("zone-%d", i)
		}
		granted := make(map[string]bool)
		var grantZones []string
		for _, id := range zoneIDs {
			if rapid.Bool().Draw(rt, "granted-"+id) {
				granted[id] = true
				grantZones = append(grantZones, strings.ToUpper(id)+".example.com.")
			}
		}
		if grantZones == nil {
			grantZones = []string{}
		}

		tunnelNames := []string{"gw", "gw2"}
		checkpoints := make(map[string][]v1alpha1.CloudflareTunnelDNSRecordStatus)
		records := make(map[string][]flarecloudflare.DNSRecord)
		checkpointed := make(map[string]bool)
		for i := range rapid.IntRange(0, 6).Draw(rt, "records") {
			id := fmt.Sprintf("rec-%d", i)
			zone := rapid.SampledFrom(zoneIDs).Draw(rt, "zone-"+id)
			owner := rapid.SampledFrom(tunnelNames).Draw(rt, "owner-"+id)
			host := id + "." + zone + ".example.com"
			record := healthyRecord(id, host, owner, probeMarker(owner))
			// state: 0 healthy, 1 missing remotely, 2 drifted, 3 orphan.
			state := rapid.IntRange(0, 3).Draw(rt, "state-"+id)
			if state == 3 && !granted[zone] {
				// An uncheckpointed record can only exist where the zone
				// was granted at write time; a checkpoint keeps it
				// reachable after revocation.
				state = 0
			}
			if state != 3 {
				checkpoints[owner] = append(checkpoints[owner], v1alpha1Checkpoint(host, id, zone, probeMarker(owner)))
				checkpointed[zone] = true
			}
			switch state {
			case 1:
				continue
			case 2:
				record.Content = "192.0.2.9"
			}
			records[zone] = append(records[zone], record)
		}

		run := func(grants []string) ([]DriftItem, string, []string) {
			zones := make([]probeZone, 0, len(zoneIDs))
			for _, id := range zoneIDs {
				zone := probeZone{id: id, records: records[id]}
				if !granted[id] && !checkpointed[id] {
					// Outside the scan set a least-privilege token is denied;
					// with "*" the zone is readable and holds nothing ours.
					if grants != nil {
						zone.err = deniedZoneError(errors.New(id+" denied"), http.StatusForbidden)
					}
				}
				zones = append(zones, zone)
			}
			objects := make([]client.Object, 0, len(tunnelNames))
			for _, name := range tunnelNames {
				objects = append(objects, probeTunnel(name, checkpoints[name]...))
			}
			f := newDNSProbeFixture(t, dnsProbeConfig{zones: zones, grantZones: grants, objects: objects})
			items, result, err := f.sweeper.RunTargetOnce(context.Background(), dnsTarget())
			if err != nil {
				rt.Fatalf("RunTargetOnce(grants=%v) err = %v", grants, err)
			}
			return items, result, f.api.calls()
		}

		fullItems, fullResult, _ := run(nil)
		scopedItems, scopedResult, scopedCalls := run(grantZones)
		if fullResult != observability.SweepResultOK || scopedResult != observability.SweepResultOK {
			rt.Fatalf("results full=%q scoped=%q, want ok/ok", fullResult, scopedResult)
		}
		if got, want := driftKeys(scopedItems), driftKeys(fullItems); !slices.Equal(got, want) {
			rt.Fatalf("scoped findings %v != full findings %v", got, want)
		}
		var wantCalls []string
		for _, id := range zoneIDs {
			if granted[id] || checkpointed[id] {
				wantCalls = append(wantCalls, id)
			}
		}
		if !slices.Equal(scopedCalls, wantCalls) {
			rt.Fatalf("scoped calls = %v, want %v", scopedCalls, wantCalls)
		}
	})
}

// driftKeys renders items order-independently for comparison.
func driftKeys(items []DriftItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, fmt.Sprintf("%s/%s/%s", item.Case, item.RemoteID, item.NamespacedName))
	}
	slices.Sort(keys)
	return keys
}
