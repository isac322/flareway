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
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/test/cfstub"
)

func TestGatewayOnlySweeperDoesNotListDisabledGroups(t *testing.T) {
	f := newGroupSweepFixture(t, &ControllerGroups{Gateway: true}, nil)
	// Model a Gateway-only token: every disabled group's endpoint rejects reads.
	f.stub.Fault(http.MethodGet, `^/(accounts/[^/]+/(access|infrastructure|devices|gateway|teamnet|zerotrust|warp_connector)(/|$)|zones/[^/]+/access/)`,
		cfstub.Fault{Status: http.StatusForbidden, Times: -1})
	findings := f.runSelected(t, []string{"DNSRecord", "CloudflareTunnel"})
	requireGatewaySweepDrift(t, findings)
}

// These literals deliberately do not come from the production target registry.
// The HTTP oracle rejects every extra call, including singleton reads and writes.
var sweepListRequests = map[string][]string{
	"AccessApplication":           {"/accounts/account-1/access/apps", "/zones/zone-1/access/apps"},
	"AccessStandaloneApplication": {"/accounts/account-1/access/apps", "/zones/zone-1/access/apps"},
	"AccessPolicy":                {"/accounts/account-1/access/policies"},
	"AccessGroup":                 {"/accounts/account-1/access/groups", "/zones/zone-1/access/groups"},
	"ServiceToken":                {"/accounts/account-1/access/service_tokens", "/zones/zone-1/access/service_tokens"},
	"IdentityProvider":            {"/accounts/account-1/access/identity_providers"},
	"AccessCustomPage":            {"/accounts/account-1/access/custom_pages"},
	"AccessInfrastructureTarget":  {"/accounts/account-1/infrastructure/targets"},
	"DNSRecord":                   {"/zones/zone-1/dns_records"},
	"CloudflareTunnel":            {"/accounts/account-1/cfd_tunnel"},
	"ZeroTrustGatewayPolicy":      {"/accounts/account-1/gateway/rules"},
	"ZeroTrustList":               {"/accounts/account-1/gateway/lists"},
	"VirtualNetwork":              {"/accounts/account-1/teamnet/virtual_networks"},
	"NetworkRoute":                {"/accounts/account-1/teamnet/routes"},
	"HostnameRoute":               {"/accounts/account-1/zerotrust/routes/hostname"},
	"DeviceProfile":               {"/accounts/account-1/devices/policies"},
	"DevicePostureRule":           {"/accounts/account-1/devices/posture"},
	"DevicePostureIntegration":    {"/accounts/account-1/devices/posture/integration"},
	"WARPConnector":               {"/accounts/account-1/warp_connector"},
}

var allSweepKinds = []string{
	"AccessApplication", "AccessStandaloneApplication", "AccessPolicy", "AccessGroup",
	"ServiceToken", "IdentityProvider", "AccessCustomPage", "AccessInfrastructureTarget",
	"DNSRecord", "CloudflareTunnel", "ZeroTrustGatewayPolicy", "ZeroTrustList",
	"VirtualNetwork", "NetworkRoute", "HostnameRoute", "DeviceProfile",
	"DevicePostureRule", "DevicePostureIntegration", "WARPConnector",
}

type groupSweepFixture struct {
	stub    *cfstub.Server
	sweeper *Sweeper
	account *v1alpha1.CloudflareAccount
	runner  *AccountSweeper
}

func newGroupSweepFixture(t *testing.T, groups *ControllerGroups, targets []TargetDescriptor) *groupSweepFixture {
	t.Helper()
	stub := cfstub.New(t)
	stub.State.Set("/accounts/account-1/devices/posture/integration", []cfstub.AccessResource{})
	stub.State.AddZone(cfstub.Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
	stub.State.AddTunnel(cfstub.Tunnel{
		ID: "remote-tunnel", AccountID: "account-1", AccountTag: "account-1",
		Name: "unexpected-name", Status: "inactive", TunType: "cfd_tunnel", ConfigSrc: "cloudflare",
	})
	// cfstub owns the stateful endpoints above; these list-only endpoints
	// have no stored objects in this scenario and return the real empty envelope.
	for _, path := range []string{
		`^/accounts/[^/]+/access/custom_pages$`,
		`^/accounts/[^/]+/infrastructure/targets$`,
		`^/accounts/[^/]+/warp_connector$`,
	} {
		stub.Handle(http.MethodGet, path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`)
		})
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	account := probeAccount([]string{"*"})
	account.Spec.Credentials.APITokenSecretRef = v1alpha1.NamespacedSecretKeyReference{
		Namespace: "operator", Name: "cloudflare-token", Key: "token",
	}
	account.Status.Conditions = []metav1.Condition{
		{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue},
		{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue},
	}
	tunnel := probeTunnel("gw", v1alpha1Checkpoint("app.example.com", "missing-record", "zone-1", probeMarker("gw")))
	tunnel.Status.TunnelID = "remote-tunnel"
	tunnel.UID = types.UID("tunnel-uid")
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
		account, tunnel,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "cloudflare-token"},
			Data:       map[string][]byte{"token": []byte("token")},
		},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(probeClusterID)}},
	).Build()
	worker := NewSweeper(SweeperOptions{
		Client:            kube,
		APIReader:         kube,
		CloudflareFactory: flarecloudflare.NewFactory(logr.Discard(), flarecloudflare.WithBaseURL(stub.URL)),
		ControllerGroups:  groups,
		Targets:           targets,
		Logger:            logr.Discard(),
		OperatorNamespace: probeOperatorNamespace,
		SweepRateLimit:    1e9,
	})
	// Use real ready-account discovery and worker startup to exercise target
	// propagation. Zero TTLs keep timer-driven passes disabled; after the Stop
	// barrier each test drives the selected real targets deterministically.
	worker.reconcileAccounts(context.Background())
	runner, started := worker.accounts[account.Name]
	if !started {
		t.Fatal("ready account did not start a worker")
	}
	worker.stopAll()
	return &groupSweepFixture{stub: stub, sweeper: worker, account: account, runner: runner}
}

func (f *groupSweepFixture) runSelected(t *testing.T, wantKinds []string) map[string][]DriftItem {
	t.Helper()
	findings := make(map[string][]DriftItem)
	for _, target := range f.runner.targets {
		if _, duplicate := findings[target.Kind]; duplicate {
			t.Errorf("%s target executed more than once", target.Kind)
		}
		items, result, err := f.runner.RunTargetOnce(context.Background(), target)
		if err != nil || result != observability.SweepResultOK {
			t.Errorf("%s pass = (%#v, %q, %v), want complete pass", target.Kind, items, result, err)
		}
		findings[target.Kind] = items
	}
	if got := targetKinds(f.runner.targets); !slices.Equal(got, wantKinds) {
		t.Errorf("executed targets = %v, want %v", got, wantKinds)
	}
	requireSweepRequests(t, f.stub.Journal(), wantKinds)
	return findings
}

func requireSweepRequests(t *testing.T, calls []cfstub.Call, kinds []string, extraPaths ...string) {
	t.Helper()
	// Compare endpoint sets across the complete journal, not counts: setup,
	// discovery and SDK pagination may legitimately repeat selected endpoints.
	want := make(map[string]bool)
	for _, kind := range kinds {
		paths, known := sweepListRequests[kind]
		if !known {
			t.Fatalf("test has no independent request oracle for %s", kind)
		}
		for _, path := range paths {
			want[path] = true
		}
		switch kind {
		case "AccessApplication", "AccessStandaloneApplication", "AccessGroup", "ServiceToken", "DNSRecord":
			want["/zones"] = true
		}
	}
	for _, path := range extraPaths {
		want[path] = true
	}
	seen := make(map[string]bool)
	for _, call := range calls {
		if call.Method != http.MethodGet {
			t.Errorf("sweep mutated remote state: %s %s", call.Method, call.Path)
		}
		parsed, err := url.Parse(call.Path)
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimPrefix(parsed.Path, "/client/v4")
		if !want[path] {
			t.Errorf("unexpected endpoint in complete request journal: %s %s", call.Method, call.Path)
		}
		seen[path] = true
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("required sweep endpoint %q was not called", path)
		}
	}
}

func requireGatewaySweepDrift(t *testing.T, findings map[string][]DriftItem) {
	t.Helper()
	requireItems(t, findings["DNSRecord"], DriftItem{
		Case: DriftCaseMissing, RemoteID: "missing-record",
		TargetKind: "CloudflareTunnel", NamespacedName: probeKey("gw"),
	})
	requireItems(t, findings["CloudflareTunnel"], DriftItem{
		Case: DriftCaseMismatch, RemoteID: "remote-tunnel",
		TargetKind: "CloudflareTunnel", NamespacedName: probeKey("gw"),
	})
}

func TestSweeperControllerGroupOwnership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups ControllerGroups
		kinds  []string
	}{
		{"access", ControllerGroups{Access: true}, []string{
			"AccessApplication", "AccessStandaloneApplication", "AccessPolicy", "AccessGroup",
			"ServiceToken", "IdentityProvider", "AccessCustomPage", "AccessInfrastructureTarget",
			"DevicePostureRule", "DevicePostureIntegration",
		}},
		{"private-network", ControllerGroups{PrivateNetwork: true}, []string{
			"VirtualNetwork", "NetworkRoute", "HostnameRoute", "WARPConnector",
		}},
		{"device", ControllerGroups{Device: true}, []string{"DeviceProfile"}},
		{"organization", ControllerGroups{Organization: true}, []string{"ZeroTrustGatewayPolicy", "ZeroTrustList"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGroupSweepFixture(t, &tc.groups, nil)
			f.runSelected(t, tc.kinds)
		})
	}
}

func TestMixedControllerGroupsPreserveSelectedSweeps(t *testing.T) {
	f := newGroupSweepFixture(t, &ControllerGroups{Gateway: true, PrivateNetwork: true, Device: true}, nil)
	findings := f.runSelected(t, []string{
		"DNSRecord", "CloudflareTunnel", "VirtualNetwork", "NetworkRoute", "HostnameRoute",
		"DeviceProfile", "WARPConnector",
	})
	requireGatewaySweepDrift(t, findings)
}

func TestAllControllerGroupsPreserveSweepBehavior(t *testing.T) {
	f := newGroupSweepFixture(t, &ControllerGroups{
		Gateway: true, Access: true, PrivateNetwork: true, Device: true, Organization: true,
	}, nil)
	requireGatewaySweepDrift(t, f.runSelected(t, allSweepKinds))
}

func TestUnspecifiedSweepTargetsRetainDefaults(t *testing.T) {
	t.Run("manager constructor", func(t *testing.T) {
		f := newGroupSweepFixture(t, nil, nil)
		requireGatewaySweepDrift(t, f.runSelected(t, allSweepKinds))
	})
	t.Run("account constructor", func(t *testing.T) {
		f := newGroupSweepFixture(t, nil, []TargetDescriptor{})
		f.runner = NewAccountSweeper(AccountSweeperOptions{
			AccountName: f.account.Name, AccountID: f.account.Spec.AccountID, Token: "token",
			Factory: f.sweeper.cloudflareFactory, Client: f.sweeper.client,
			OperatorNamespace: probeOperatorNamespace, RateLimit: 1e9, Logger: logr.Discard(),
		})
		requireGatewaySweepDrift(t, f.runSelected(t, allSweepKinds))
	})
}

func TestExplicitEmptySweepTargetsRemainEmpty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		groups  *ControllerGroups
		targets []TargetDescriptor
	}{
		{"explicit targets override enabled groups", &ControllerGroups{Gateway: true, Access: true, PrivateNetwork: true, Device: true, Organization: true}, []TargetDescriptor{}},
		{"all groups disabled", &ControllerGroups{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGroupSweepFixture(t, tc.groups, tc.targets)
			f.stub.Fault(http.MethodGet, `.*`, cfstub.Fault{Status: http.StatusForbidden, Times: -1})
			if f.sweeper.targets == nil || len(f.sweeper.targets) != 0 {
				t.Fatalf("manager target selection = %#v, want non-nil empty", f.sweeper.targets)
			}
			if f.runner.targets == nil || len(f.runner.targets) != 0 {
				t.Fatalf("account constructor target selection = %#v, want non-nil empty", f.runner.targets)
			}
			f.runner.Start(context.Background())
			f.runner.Stop()
			f.sweeper.reconcileAccounts(context.Background())
			worker, started := f.sweeper.accounts[f.account.Name]
			if !started {
				t.Fatal("ready account did not start a worker")
			}
			// Stop is the barrier: no target can make a request after this returns.
			f.sweeper.stopAll()
			if worker.targets == nil || len(worker.targets) != 0 {
				t.Fatalf("started account worker targets = %#v, want non-nil empty", worker.targets)
			}
			requireSweepRequests(t, f.stub.Journal(), nil)
		})
	}
}

func TestReenablingControllerGroupsRestoresTheirSweeps(t *testing.T) {
	disabled := newGroupSweepFixture(t, &ControllerGroups{Gateway: true}, nil)
	requireGatewaySweepDrift(t, disabled.runSelected(t, []string{"DNSRecord", "CloudflareTunnel"}))
	enabled := newGroupSweepFixture(t, &ControllerGroups{Gateway: true, Access: true}, nil)
	requireGatewaySweepDrift(t, enabled.runSelected(t, []string{
		"AccessApplication", "AccessStandaloneApplication", "AccessPolicy", "AccessGroup",
		"ServiceToken", "IdentityProvider", "AccessCustomPage", "AccessInfrastructureTarget",
		"DNSRecord", "CloudflareTunnel", "DevicePostureRule", "DevicePostureIntegration",
	}))
}

func TestEnabledTargetForbiddenDoesNotStopHealthyTargets(t *testing.T) {
	f := newGroupSweepFixture(t, &ControllerGroups{Gateway: true, Organization: true}, nil)
	list := &v1alpha1.ZeroTrustList{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "missing-list"},
		Spec: v1alpha1.ZeroTrustListSpec{
			AccountRef: corev1.LocalObjectReference{Name: probeAccountName},
			Name:       "list", ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.ZeroTrustListStatus{ListID: "missing-list"},
	}
	if err := f.sweeper.client.Create(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	f.stub.Fault(http.MethodGet, `^/accounts/[^/]+/gateway/rules$`, cfstub.Fault{Status: http.StatusForbidden, Times: -1})
	findings := make(map[string][]DriftItem)
	for _, target := range f.runner.targets {
		items, result, err := f.runner.RunTargetOnce(context.Background(), target)
		if target.Kind == "ZeroTrustGatewayPolicy" {
			var apiError *cloudflaresdk.Error
			if result != observability.SweepResultError || !errors.As(err, &apiError) || apiError.StatusCode != http.StatusForbidden || items != nil {
				t.Fatalf("forbidden pass = (%#v, %q, %v), want error/403 and no unsafe findings", items, result, err)
			}
		} else if err != nil || result != observability.SweepResultOK {
			t.Fatalf("healthy %s pass = (%#v, %q, %v)", target.Kind, items, result, err)
		}
		findings[target.Kind] = items
	}
	requireGatewaySweepDrift(t, findings)
	requireItems(t, findings["ZeroTrustList"], DriftItem{
		Case: DriftCaseMissing, RemoteID: "missing-list",
		TargetKind: "ZeroTrustList", NamespacedName: probeKey("missing-list"),
	})
	requireSweepRequests(t, f.stub.Journal(), []string{"DNSRecord", "CloudflareTunnel", "ZeroTrustGatewayPolicy", "ZeroTrustList"})
}

func TestSelectedDNSSweepPreservesScopedPartialWithoutMutation(t *testing.T) {
	f := newGroupSweepFixture(t, &ControllerGroups{Gateway: true}, nil)
	f.stub.State.AddZone(cfstub.Zone{ID: "zone-2", Name: "denied.example.com", AccountID: "account-1"})
	var tunnel v1alpha1.CloudflareTunnel
	if err := f.sweeper.client.Get(context.Background(), probeKey("gw"), &tunnel); err != nil {
		t.Fatal(err)
	}
	tunnel.Status.DNSRecords = append(tunnel.Status.DNSRecords,
		v1alpha1Checkpoint("app.denied.example.com", "denied-record", "zone-2", probeMarker("gw")))
	if err := f.sweeper.client.Update(context.Background(), &tunnel); err != nil {
		t.Fatal(err)
	}
	f.stub.Fault(http.MethodGet, `^/zones/zone-2/dns_records$`, cfstub.Fault{Status: http.StatusForbidden, Times: -1})
	findings := make(map[string][]DriftItem)
	for _, target := range f.runner.targets {
		items, result, err := f.runner.RunTargetOnce(context.Background(), target)
		if target.Kind == "DNSRecord" {
			if result != observability.SweepResultPartial {
				t.Fatalf("DNS result = %q, want scoped partial", result)
			}
			scoped := requireScopedError(t, err)
			var apiError *cloudflaresdk.Error
			if len(scoped.failures) != 1 || !errors.As(err, &apiError) || apiError.StatusCode != http.StatusForbidden {
				t.Fatalf("DNS scoped error = %v, want one modeled 403", err)
			}
		} else if err != nil || result != observability.SweepResultOK {
			t.Fatalf("healthy %s pass = (%#v, %q, %v)", target.Kind, items, result, err)
		}
		findings[target.Kind] = items
	}
	// The healthy zone's finding survives; the denied checkpoint is not judged.
	requireGatewaySweepDrift(t, findings)
	requireSweepRequests(t, f.stub.Journal(), []string{"DNSRecord", "CloudflareTunnel"}, "/zones/zone-2/dns_records")
}

func targetKinds(targets []TargetDescriptor) []string {
	kinds := make([]string, 0, len(targets))
	for _, target := range targets {
		kinds = append(kinds, target.Kind)
	}
	return kinds
}

func TestInitialDelayBounds(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	for _, ttl := range []time.Duration{time.Nanosecond, 4 * time.Second, 60 * time.Second, 300 * time.Second, time.Hour} {
		for i := 0; i < 2000; i++ {
			got := initialDelay(ttl, rng)
			bound := ttl
			if bound > time.Minute {
				bound = time.Minute
			}
			if got < 0 || got >= bound {
				t.Fatalf("initialDelay(%s) = %s, want [0, %s)", ttl, got, bound)
			}
		}
	}
	// A TTL so small the bound collapses must return 0, never panic.
	if got := initialDelay(time.Nanosecond, rng); got != 0 {
		t.Fatalf("initialDelay(1ns) = %s, want 0", got)
	}
}

func TestJitteredIntervalBounds(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(3, 4))
	for _, ttl := range []time.Duration{4 * time.Second, 60 * time.Second, 300 * time.Second, time.Hour} {
		for i := 0; i < 2000; i++ {
			got := jitteredInterval(ttl, rng)
			if got < ttl || got >= ttl+ttl/5 {
				t.Fatalf("jitteredInterval(%s) = %s, want [%s, %s)", ttl, got, ttl, ttl+ttl/5)
			}
		}
	}
	// ttl/5 == 0 must not panic and must return the base interval.
	for _, ttl := range []time.Duration{time.Nanosecond, 4 * time.Nanosecond} {
		if got := jitteredInterval(ttl, rng); got != ttl {
			t.Fatalf("jitteredInterval(%s) = %s, want %s", ttl, got, ttl)
		}
	}
}

type classifyRemote struct {
	id   string
	name string
}

func classifyTestOptions() classifyOptions[classifyRemote] {
	return classifyOptions[classifyRemote]{
		kind:   "Widget",
		idOf:   func(r classifyRemote) string { return r.id },
		listed: func(localRef) bool { return true },
		nameOf: func(r classifyRemote) string { return r.name },
	}
}

func TestClassifyMissing(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	items := classify(refs, []classifyRemote{}, classifyTestOptions())
	if len(items) != 1 || items[0].Case != DriftCaseMissing || items[0].RemoteID != "r1" {
		t.Fatalf("classify() = %#v, want one missing item for r1", items)
	}
	if items[0].TargetKind != "Widget" || items[0].NamespacedName.Name != "a" {
		t.Fatalf("missing item target = %#v", items[0])
	}
}

func TestClassifyMismatch(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	items := classify(refs, []classifyRemote{{id: "r1", name: "renamed"}}, classifyTestOptions())
	if len(items) != 1 || items[0].Case != DriftCaseMismatch {
		t.Fatalf("classify() = %#v, want one mismatch item", items)
	}
}

func TestClassifySkipsUnlistedScope(t *testing.T) {
	t.Parallel()
	opts := classifyTestOptions()
	opts.listed = func(ref localRef) bool { return ref.scope == "" }
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", scope: "zone-9",
	}}
	items := classify(refs, []classifyRemote{}, opts)
	if len(items) != 0 {
		t.Fatalf("classify() = %#v, want no items for an unlisted scope", items)
	}
}

func TestClassifyNoRemoteIDNoJudgement(t *testing.T) {
	t.Parallel()
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
	}}
	items := classify(refs, []classifyRemote{}, classifyTestOptions())
	if len(items) != 0 {
		t.Fatalf("classify() = %#v, want no items for unconverged ref", items)
	}
}

func TestClassifyOrphan(t *testing.T) {
	t.Parallel()
	opts := classifyTestOptions()
	opts.orphan = func(remote classifyRemote, _ map[string]bool) (types.NamespacedName, bool) {
		return types.NamespacedName{Namespace: "ns", Name: "ghost"}, remote.name == "ours"
	}
	refs := []localRef{{
		kind: "Widget", key: types.NamespacedName{Namespace: "ns", Name: "a"},
		remoteID: "r1", expectedName: "w-a",
	}}
	remotes := []classifyRemote{{id: "r1", name: "w-a"}, {id: "r2", name: "ours"}, {id: "r3", name: "foreign"}}
	items := classify(refs, remotes, opts)
	if len(items) != 1 || items[0].Case != DriftCaseOrphan || items[0].RemoteID != "r2" {
		t.Fatalf("classify() = %#v, want one orphan item for r2", items)
	}
}

func TestListFailureClassification(t *testing.T) {
	t.Parallel()
	generic := errors.New("connection reset")
	if got := listFailure(generic); !errors.Is(got, errIncompleteListing) {
		t.Fatalf("listFailure(generic) = %v, want errIncompleteListing", got)
	}
	forbidden := &cloudflaresdk.Error{StatusCode: 403}
	if got := listFailure(forbidden); got != forbidden {
		t.Fatalf("listFailure(403) = %v, want the raw error", got)
	}
	if got := listFailure(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Fatalf("listFailure(canceled) = %v, want context.Canceled", got)
	}
	if got := listFailure(nil); got != nil {
		t.Fatalf("listFailure(nil) = %v, want nil", got)
	}
}

// TestZoneFailureIsolation covers the per-zone classifier used by
// sweepDNSRecords: only HTTP 403/404, zone-local 5xx, and transport errors
// (no decodable status) are isolated per zone; context errors, 429, 401,
// every other 4xx, and client-side pacing failures (ErrRateLimitWait) abort
// the whole pass (QA-10/QA-11).
func TestZoneFailureIsolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"403 forbidden", dnsListError(403), true},
		{"404 not found", dnsListError(404), true},
		{"500 internal", dnsListError(500), true},
		{"503 unavailable", dnsListError(503), true},
		{"transport error", transportZoneError(errors.New("connection reset")), true},
		{"bare transport error", errors.New("connection reset"), true},
		{"context canceled", context.Canceled, false},
		{"wrapped canceled", fmt.Errorf("zone list: %w", context.Canceled), false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped deadline", fmt.Errorf("zone list: %w", context.DeadlineExceeded), false},
		{"rate limit wait", fmt.Errorf("zone list: %w: %w", flarecloudflare.ErrRateLimitWait, errors.New("would exceed context deadline")), false},
		{"rate limit wait canceled", fmt.Errorf("zone list: %w: %w", flarecloudflare.ErrRateLimitWait, context.Canceled), false},
		{"401 unauthorized", dnsListError(401), false},
		{"429 rate limited", dnsListError(429), false},
		{"400 bad request", dnsListError(400), false},
		{"409 conflict", dnsListError(409), false},
		{"422 unprocessable", dnsListError(422), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := zoneFailureIsolatable(tc.err); got != tc.want {
				t.Fatalf("zoneFailureIsolatable(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestRunTargetOnceResultMapping(t *testing.T) {
	t.Parallel()
	as := NewAccountSweeper(AccountSweeperOptions{Logger: logr.Discard()})
	ctx := context.Background()

	cases := []struct {
		name         string
		items        []DriftItem
		err          error
		wantResult   string
		wantErr      bool
		wantItemsNil bool
		wantItemsLen int
	}{
		{name: "complete listing", items: []DriftItem{}, wantResult: observability.SweepResultOK},
		{name: "nil items is partial", items: nil, wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "incomplete listing error is partial", err: errIncompleteListing, wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "wrapped incomplete listing is partial", err: fmt.Errorf("list: %w", errIncompleteListing), wantResult: observability.SweepResultPartial, wantItemsNil: true},
		{name: "definitive error", err: errors.New("403 forbidden"), wantResult: observability.SweepResultError, wantErr: true, wantItemsNil: true},
		// QA-10(b): a deadline exceeded reaches the generic error branch —
		// the existing asymmetry with context.Canceled is deliberate.
		{name: "deadline exceeded is error", err: context.DeadlineExceeded, wantResult: observability.SweepResultError, wantErr: true, wantItemsNil: true},
		// QA-13: items returned with a generic incomplete-listing error are
		// unsafe and must be discarded; only the typed scoped error may
		// carry safe items.
		{name: "unsafe items on generic partial are discarded",
			items: []DriftItem{{Case: DriftCaseMissing, RemoteID: "r1"}}, err: errIncompleteListing,
			wantResult: observability.SweepResultPartial, wantItemsNil: true},
		// Scoped partial: the typed aggregate carries the safe items through.
		{name: "scoped listing error carries safe items",
			items: []DriftItem{{Case: DriftCaseMissing, RemoteID: "r1"}},
			err: &scopedListingError{failures: []error{
				&zoneFailure{zoneID: "zone-a", err: errors.New("denied")},
			}},
			wantResult: observability.SweepResultPartial, wantErr: true, wantItemsLen: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := TargetDescriptor{
				Kind: "Widget",
				SweepFunc: func(context.Context, *AccountSweeper) ([]DriftItem, error) {
					return tc.items, tc.err
				},
			}
			got, result, err := as.RunTargetOnce(ctx, target)
			if result != tc.wantResult {
				t.Fatalf("RunTargetOnce result = %q, want %q", result, tc.wantResult)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("RunTargetOnce err = %v, wantErr %t", err, tc.wantErr)
			}
			if (got == nil) != tc.wantItemsNil {
				t.Fatalf("RunTargetOnce items = %#v, wantItemsNil %t", got, tc.wantItemsNil)
			}
			if tc.wantItemsLen > 0 && len(got) != tc.wantItemsLen {
				t.Fatalf("RunTargetOnce items = %#v, want %d item(s)", got, tc.wantItemsLen)
			}
		})
	}
}

func TestParseAccessRemoteName(t *testing.T) {
	t.Parallel()
	cluster, ns, name, ok := parseAccessRemoteName("flareway/cluster-1/team-a/some spec name")
	if !ok || cluster != "cluster-1" || ns != "team-a" || name != "some spec name" {
		t.Fatalf("parseAccessRemoteName = %q %q %q %t", cluster, ns, name, ok)
	}
	if _, _, _, ok := parseAccessRemoteName("other/cluster-1/a/b"); ok {
		t.Fatal("non-flareway name parsed")
	}
	if _, _, _, ok := parseAccessRemoteName("flareway/cluster-1/only-two"); ok {
		t.Fatal("two-segment name parsed")
	}
}

func TestParsePrivateOwnerComment(t *testing.T) {
	t.Parallel()
	cluster, ns, name, ok := parsePrivateOwnerComment("flareway cluster-1/team-a/widget | human note")
	if !ok || cluster != "cluster-1" || ns != "team-a" || name != "widget" {
		t.Fatalf("parsePrivateOwnerComment = %q %q %q %t", cluster, ns, name, ok)
	}
	if _, _, _, ok := parsePrivateOwnerComment("flareway hmac:0123456789abcdef0123456789abcdef ns/name"); ok {
		t.Fatal("hmac marker parsed as legacy")
	}
	if _, _, _, ok := parsePrivateOwnerComment("flareway sha256:0123456789abcdef0123456789abcdef"); ok {
		t.Fatal("sha256 marker parsed as legacy")
	}
	if _, _, _, ok := parsePrivateOwnerComment("unrelated comment"); ok {
		t.Fatal("foreign comment parsed")
	}
}

func TestParseTunnelTarget(t *testing.T) {
	t.Parallel()
	id, ok := parseTunnelTarget("abc123.cfargotunnel.com")
	if !ok || id != "abc123" {
		t.Fatalf("parseTunnelTarget = %q %t", id, ok)
	}
	if _, ok := parseTunnelTarget("203.0.113.9"); ok {
		t.Fatal("IP content parsed as tunnel target")
	}
	if _, ok := parseTunnelTarget(""); ok {
		t.Fatal("empty content parsed")
	}
}

func TestDNSOrphanCandidate(t *testing.T) {
	t.Parallel()
	markers := []string{"flareway cluster-1/ns/gw"}
	tunnel := dnsTunnelInfo{
		key:      types.NamespacedName{Namespace: "ns", Name: "gw"},
		tunnelID: "tid-1",
		markers:  markers,
	}
	// Marker + matching tunnel target: orphan candidate.
	candidate := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "ghost.example.com",
		Content: "tid-1.cfargotunnel.com", Comment: "flareway cluster-1/ns/gw",
	}
	item, ok := dnsOrphanCandidate(candidate, []dnsTunnelInfo{tunnel})
	if !ok || item.Case != DriftCaseOrphan || item.NamespacedName != tunnel.key {
		t.Fatalf("dnsOrphanCandidate = %#v %t", item, ok)
	}
	// Marker but foreign target (forged marker on a foreign record): not a
	// candidate — the content check must reject it.
	forged := candidate
	forged.Content = "other.cfargotunnel.com"
	if _, ok := dnsOrphanCandidate(forged, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("forged-target record accepted as orphan")
	}
	// Marker but not a CNAME (the QA-017 forged A record): not a candidate.
	forgedType := candidate
	forgedType.Type = "A"
	forgedType.Content = "203.0.113.9"
	if _, ok := dnsOrphanCandidate(forgedType, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("forged A record accepted as orphan")
	}
	// Unknown tunnel ID: never owned, never a candidate (C14#3).
	noID := tunnel
	noID.tunnelID = ""
	if _, ok := dnsOrphanCandidate(candidate, []dnsTunnelInfo{noID}); ok {
		t.Fatal("record accepted as orphan without a tunnel target")
	}
	// No marker: foreign record, not a candidate.
	foreign := candidate
	foreign.Comment = "someone else's record"
	if _, ok := dnsOrphanCandidate(foreign, []dnsTunnelInfo{tunnel}); ok {
		t.Fatal("foreign record accepted as orphan")
	}
}

func TestDNSMismatchReason(t *testing.T) {
	t.Parallel()
	tunnel := dnsTunnelInfo{
		key:      types.NamespacedName{Namespace: "ns", Name: "gw"},
		tunnelID: "tid-1",
		markers:  []string{"flareway cluster-1/ns/gw"},
	}
	checkpoint := v1alpha1Checkpoint("app.example.com", "rec-1", "zone-1", "flareway cluster-1/ns/gw")
	remote := flarecloudflare.DNSRecord{
		ID: "rec-1", Type: "CNAME", Name: "app.example.com",
		Content: "tid-1.cfargotunnel.com", Comment: "flareway cluster-1/ns/gw",
	}
	if reason := dnsMismatchReason(tunnel, checkpoint, remote); reason != "" {
		t.Fatalf("matching record reported mismatch: %q", reason)
	}
	// Content drift (QA-015): CNAME target changed out-of-band.
	drifted := remote
	drifted.Content = "192.0.2.1"
	if reason := dnsMismatchReason(tunnel, checkpoint, drifted); reason == "" {
		t.Fatal("content drift not reported")
	}
	// Type swap with forged marker (QA-017): the strict check must reject.
	forged := remote
	forged.Type = "A"
	forged.Content = "203.0.113.9"
	if reason := dnsMismatchReason(tunnel, checkpoint, forged); reason == "" {
		t.Fatal("forged A record not reported")
	}
	// Unknown tunnel ID: the content check is impossible, so no verdict is
	// returned — never "owned by default" and never a false mismatch (C14#3).
	noID := tunnel
	noID.tunnelID = ""
	if reason := dnsMismatchReason(noID, checkpoint, drifted); reason != "" {
		t.Fatalf("expected no verdict without tunnel ID, got %q", reason)
	}
	commentDrift := remote
	commentDrift.Comment = "attacker note"
	if reason := dnsMismatchReason(tunnel, checkpoint, commentDrift); reason == "" {
		t.Fatal("comment drift not reported")
	}
}

// v1alpha1Checkpoint builds a DNS checkpoint status entry for tests.
func v1alpha1Checkpoint(hostname, recordID, zoneID, comment string) v1alpha1.CloudflareTunnelDNSRecordStatus {
	return v1alpha1.CloudflareTunnelDNSRecordStatus{
		Hostname:         hostname,
		RecordID:         recordID,
		ZoneID:           zoneID,
		OwnershipComment: comment,
	}
}
