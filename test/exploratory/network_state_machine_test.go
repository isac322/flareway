//go:build exploratory

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

package exploratory

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"pgregory.net/rapid"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/test/cfstub"
)

// networkExplorationSeq makes every Kubernetes object name, remote seed ID,
// and generated CIDR unique across iterations and across actions. Names stay
// short so the private-resource owner comment never exceeds the 100-rune
// hashing threshold and remains parseable as "flareway <cluster>/<ns>/<name>".
var networkExplorationSeq atomic.Int64

// networkAccount is the machine's model of one CloudflareAccount.
type networkAccount struct {
	name      string
	accountID string
	granted   bool
	deleted   bool
}

// networkVNet is the machine's model of one VirtualNetwork.
type networkVNet struct {
	name      string
	account   string
	remoteID  string // seeded remote ID for ObserveOnly objects
	policy    v1alpha1.ManagementPolicy
	deletion  v1alpha1.DeletionPolicy
	isDefault bool
	deleted   bool
}

// networkRoute is the machine's model of one NetworkRoute.
type networkRoute struct {
	name     string
	account  string
	tunnel   string
	vnetName string // spec.virtualNetworkRef.name, "" when absent
	remoteID string // seeded remote ID for ObserveOnly objects
	policy   v1alpha1.ManagementPolicy
	deletion v1alpha1.DeletionPolicy
	deleted  bool
}

// networkTunnel is the machine's model of one Direct-mode CloudflareTunnel.
type networkTunnel struct {
	name       string
	account    string
	remoteName string
}

// networkSeed records the exact remote object an ObserveOnly resource points
// at. The remote must remain byte-identical for the object's lifetime.
type networkSeed struct {
	kind      string // "vnet" or "route"
	accountID string
	remoteID  string
	name      string // expected remote name (vnet) or network (route)
	isDefault bool
	tunnelID  string
	vnetID    string
}

// networkResidue records the remote object a deleted resource left behind and
// the outcome its deletion policy demands once the Kubernetes object is gone.
type networkResidue struct {
	kind      string // "vnet" or "route"
	name      string // Kubernetes object name
	accountID string
	remoteID  string
	policy    v1alpha1.DeletionPolicy // DeletionPolicyOrphan also covers ObserveOnly
}

// networkFault is one registered cfstub fault whose consumption is tracked
// through the journal so invariants can exempt only the affected surface.
type networkFault struct {
	accountID   string
	kind        string // "route", "vnet", "tunnel"; empty affects everything
	method      string
	pattern     *regexp.Regexp
	times       int
	journalBase int
}

// networkMachine is the rapid state machine for family C: CloudflareAccount,
// VirtualNetwork, NetworkRoute, and the Direct-mode CloudflareTunnel targets
// routes resolve through.
type networkMachine struct {
	t         *testing.T
	h         *explorationHarness
	rec       *traceRecorder
	iteration int64
	namespace string

	accounts map[string]*networkAccount
	vnets    map[string]*networkVNet
	routes   map[string]*networkRoute
	tunnels  map[string]*networkTunnel

	seeds    map[string]networkSeed    // remoteID -> seed
	residues map[string]networkResidue // remoteID -> residue
	faults   []*networkFault
	drifted  map[string]bool // remoteID currently under repair after RemoteDrift
}

func TestNetworkRouteStateMachine(t *testing.T) {
	recorder := newTraceRecorder(t, "network")
	h := newExplorationHarness(t)

	rapid.Check(t, func(rt *rapid.T) {
		if violations := h.stub.Violations(); len(violations) > 0 {
			rt.Fatalf("cfstub violations from previous iteration: %s", formatViolations(violations))
		}
		h.stopManager(t)
		purgeNetworkObjects(rt, h)
		h.resetIteration(t)
		h.startManager(t)
		machine := newNetworkMachine(t, h, recorder)
		recorder.BeginIteration()
		rt.Repeat(rapid.StateMachineActions(machine))
	})
}

func newNetworkMachine(t *testing.T, h *explorationHarness, recorder *traceRecorder) *networkMachine {
	t.Helper()
	iteration := networkExplorationSeq.Add(1)
	machine := &networkMachine{
		t:         t,
		h:         h,
		rec:       recorder,
		iteration: iteration,
		namespace: fmt.Sprintf("expl-net-%d", iteration),
		accounts:  map[string]*networkAccount{},
		vnets:     map[string]*networkVNet{},
		routes:    map[string]*networkRoute{},
		tunnels:   map[string]*networkTunnel{},
		seeds:     map[string]networkSeed{},
		residues:  map[string]networkResidue{},
		drifted:   map[string]bool{},
	}
	ctx := context.Background()

	// privateOwnerComment and the tunnel controller read the kube-system UID
	// as the cluster ID; envtest does not create it.
	system := new(corev1.Namespace)
	if err := h.client.Get(ctx, types.NamespacedName{Name: "kube-system"}, system); apierrors.IsNotFound(err) {
		must(t, h.client.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		}), "create kube-system namespace")
	} else {
		must(t, err, "get kube-system namespace")
	}

	must(t, h.client.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   machine.namespace,
			Labels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": machine.namespace},
		},
	}), "create iteration namespace")
	must(t, h.client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: machine.namespace, Name: "cf-token"},
		Data:       map[string][]byte{"token": []byte("exploration-token")},
	}), "create token Secret")
	return machine
}
func purgeNetworkObjects(rt *rapid.T, h *explorationHarness) {
	rt.Helper()
	ctx := context.Background()
	var namespaces corev1.NamespaceList
	must(rt, h.apiReader.List(ctx, &namespaces), "list namespaces for network purge")
	for index := range namespaces.Items {
		namespace := &namespaces.Items[index]
		if _, owned := namespace.Labels["exploratory.flareway.bhyoo.com/tenant"]; !owned {
			continue
		}
		for _, list := range []client.ObjectList{
			&v1alpha1.NetworkRouteList{},
			&v1alpha1.VirtualNetworkList{},
			&v1alpha1.CloudflareTunnelList{},
			&corev1.SecretList{},
		} {
			must(rt, h.apiReader.List(ctx, list, client.InNamespace(namespace.Name)), "list namespaced network leftovers")
			purgeObjectList(rt, h, list)
		}
		purgeOne(rt, h, namespace)
	}
	var accounts v1alpha1.CloudflareAccountList
	must(rt, h.apiReader.List(ctx, &accounts), "list network account leftovers")
	purgeObjectList(rt, h, &accounts)
}

func (m *networkMachine) nextSeq() int64 { return networkExplorationSeq.Add(1) }

// networkCIDR maps a sequence number to a unique masked /24 so generated
// routes never overlap inside one account and virtual network.
func networkCIDR(seq int64) string {
	return fmt.Sprintf("10.%d.%d.0/24", 1+seq%200, (seq/200)%256)
}

func (m *networkMachine) journalDelta(before int) int {
	return len(m.h.stub.Journal()) - before
}

func (m *networkMachine) accountNames(includeDeleted bool) []string {
	names := make([]string, 0, len(m.accounts))
	for name, account := range m.accounts {
		if account.deleted && !includeDeleted {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (m *networkMachine) grantedAccountNames() []string {
	names := make([]string, 0, len(m.accounts))
	for name, account := range m.accounts {
		if account.granted && !account.deleted {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// CreateAccount registers a new CloudflareAccount. Half of the accounts are
// created without platform grants so later actions exercise the
// authorize-before-provision boundary.
func (m *networkMachine) CreateAccount(rt *rapid.T) {
	seq := m.nextSeq()
	name := fmt.Sprintf("acct-%d", seq)
	accountID := fmt.Sprintf("%032x", seq)
	granted := rapid.Bool().Draw(rt, "granted")

	m.h.stub.State.SetOrganization(accountID, cfstub.Organization{
		ID:         fmt.Sprintf("org-%d", seq),
		Name:       "Exploration Org",
		AuthDomain: "exploration.cloudflareaccess.com",
	})
	m.h.stub.State.AddZone(cfstub.Zone{
		ID:          fmt.Sprintf("zone-%d", seq),
		Name:        fmt.Sprintf("expl-%d.example.com", seq),
		Account:     cfstub.ZoneAccount{ID: accountID, Name: "Exploration Org"},
		AccountID:   accountID,
		AccountName: "Exploration Org",
	})

	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Namespace: m.namespace,
					Name:      "cf-token",
					Key:       "token",
				},
			},
		},
	}
	if granted {
		account.Spec.Grants = []v1alpha1.CloudflareAccountGrant{networkGrant(m.namespace)}
	}
	before := len(m.h.stub.Journal())
	must(rt, m.h.client.Create(context.Background(), account), "create CloudflareAccount")
	m.accounts[name] = &networkAccount{name: name, accountID: accountID, granted: granted}
	m.rec.Record("CreateAccount", fmt.Sprintf("%s granted=%t", name, granted), m.journalDelta(before))
}

func networkGrant(namespace string) v1alpha1.CloudflareAccountGrant {
	return v1alpha1.CloudflareAccountGrant{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": namespace},
		},
		Hostnames:       []string{"*"},
		Zones:           []string{"*"},
		Exposures:       []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
		PlatformObjects: v1alpha1.GrantPermissionAllowed,
		PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
			NetworkRouteSelector: &metav1.LabelSelector{},
		},
	}
}

// GrantAccess adds the platform grant to an account created without one. It
// first proves the pre-grant invariant directly: no remote object may exist
// for the account while it was unauthorized.
func (m *networkMachine) GrantAccess(rt *rapid.T) {
	candidates := make([]string, 0, len(m.accounts))
	for name, account := range m.accounts {
		if !account.granted && !account.deleted {
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		rt.Skip("no ungranted account")
	}
	name := candidates[rapid.IntRange(0, len(candidates)-1).Draw(rt, "account")]
	account := m.accounts[name]

	unseededVNetworks := 0
	for _, remote := range m.h.stub.State.VirtualNetworks(account.accountID) {
		if _, seeded := m.seeds[remote.ID]; !seeded {
			unseededVNetworks++
		}
	}
	if unseededVNetworks != 0 {
		rt.Fatalf("ungranted account %s has %d controller-created remote virtual networks", name, unseededVNetworks)
	}
	if got := len(m.h.stub.State.NetworkRoutes(account.accountID)); got != 0 {
		rt.Fatalf("ungranted account %s has %d remote network routes", name, got)
	}
	if got := len(m.h.stub.State.Tunnels(account.accountID)); got != 0 {
		rt.Fatalf("ungranted account %s has %d remote tunnels", name, got)
	}

	ctx := context.Background()
	before := len(m.h.stub.Journal())
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := new(v1alpha1.CloudflareAccount)
		if err := m.h.client.Get(ctx, types.NamespacedName{Name: name}, current); err != nil {
			return err
		}
		current.Spec.Grants = []v1alpha1.CloudflareAccountGrant{networkGrant(m.namespace)}
		return m.h.client.Update(ctx, current)
	})
	must(rt, err, "grant CloudflareAccount")
	account.granted = true
	m.rec.Record("GrantAccess", name, m.journalDelta(before))
}

// CreateVirtualNetwork creates a Managed or ObserveOnly VirtualNetwork.
// ObserveOnly networks point at a seeded remote object that must never change.
func (m *networkMachine) CreateVirtualNetwork(rt *rapid.T) {
	names := m.accountNames(false)
	if len(names) == 0 {
		rt.Skip("no account")
	}
	accountName := names[rapid.IntRange(0, len(names)-1).Draw(rt, "account")]
	account := m.accounts[accountName]
	observeOnly := rapid.Bool().Draw(rt, "observeOnly")
	deletion := v1alpha1.DeletionPolicyOrphan
	if rapid.Bool().Draw(rt, "deletePolicy") {
		deletion = v1alpha1.DeletionPolicyDelete
	}

	seq := m.nextSeq()
	name := fmt.Sprintf("vnet-%d", seq)
	remoteName := fmt.Sprintf("expl-vn-%d", seq)

	// checkSingleWriter rejects a second default network per account.
	isDefault := false
	if !observeOnly {
		hasDefault := false
		for _, other := range m.vnets {
			if other.account == accountName && other.isDefault && !other.deleted {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			isDefault = rapid.Bool().Draw(rt, "isDefault")
		}
	}

	vnet := &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: name},
		Spec: v1alpha1.VirtualNetworkSpec{
			AccountRef:     corev1.LocalObjectReference{Name: accountName},
			Name:           remoteName,
			IsDefault:      isDefault,
			DeletionPolicy: deletion,
		},
	}
	model := &networkVNet{
		name: name, account: accountName, policy: v1alpha1.ManagementPolicyManaged,
		deletion: deletion, isDefault: isDefault,
	}
	if observeOnly {
		remoteID := fmt.Sprintf("seed-vnet-%d", seq)
		m.h.stub.State.AddVirtualNetwork(cfstub.VirtualNetwork{
			ID: remoteID, AccountID: account.accountID, Name: remoteName,
			IsDefaultNetwork: isDefault,
		})
		vnet.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		vnet.Spec.ExternalRef = &v1alpha1.VirtualNetworkExternalReference{VirtualNetworkID: remoteID}
		model.policy = v1alpha1.ManagementPolicyObserveOnly
		model.remoteID = remoteID
		m.seeds[remoteID] = networkSeed{
			kind: "vnet", accountID: account.accountID, remoteID: remoteID,
			name: remoteName, isDefault: isDefault,
		}
	}

	before := len(m.h.stub.Journal())
	must(rt, m.h.client.Create(context.Background(), vnet), "create VirtualNetwork")
	m.vnets[name] = model
	m.rec.Record("CreateVirtualNetwork", fmt.Sprintf("%s policy=%s", name, model.policy), m.journalDelta(before))
}

// CreateTunnel creates a Direct-mode CloudflareTunnel with a single catch-all
// ingress rule. Direct mode needs no owning Gateway and produces a remote
// tunnel ID that NetworkRoute tunnelRef resolution requires.
func (m *networkMachine) CreateTunnel(rt *rapid.T) {
	names := m.grantedAccountNames()
	if len(names) == 0 {
		rt.Skip("no granted account")
	}
	accountName := names[rapid.IntRange(0, len(names)-1).Draw(rt, "account")]

	seq := m.nextSeq()
	name := fmt.Sprintf("tun-%d", seq)
	remoteName := fmt.Sprintf("expl-t-%d", seq)
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: name},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:     corev1.LocalObjectReference{Name: accountName},
			Tunnel:         v1alpha1.CloudflareTunnelRemoteSpec{Name: remoteName},
			DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
					Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
						Service: v1alpha1.CloudflareTunnelIngressService{
							HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404},
						},
					}},
				},
			},
		},
	}
	before := len(m.h.stub.Journal())
	must(rt, m.h.client.Create(context.Background(), tunnel), "create CloudflareTunnel")
	m.tunnels[name] = &networkTunnel{name: name, account: accountName, remoteName: remoteName}
	m.rec.Record("CreateTunnel", name, m.journalDelta(before))
}

// CreateRoute creates a Managed or ObserveOnly NetworkRoute against a tunnel
// of the same account. ObserveOnly routes point at a seeded remote route whose
// fields match the spec exactly so observation succeeds without mutation.
// spec.ipLookup is never set: the lookup endpoint is not part of this family.
func (m *networkMachine) CreateRoute(rt *rapid.T) {
	if len(m.tunnels) == 0 {
		rt.Skip("no tunnel")
	}
	tunnelNames := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		tunnelNames = append(tunnelNames, name)
	}
	sort.Strings(tunnelNames)
	tunnelName := tunnelNames[rapid.IntRange(0, len(tunnelNames)-1).Draw(rt, "tunnel")]
	tunnel := m.tunnels[tunnelName]
	account := m.accounts[tunnel.account]

	// Optional virtualNetworkRef: only vnets of the same account qualify.
	vnetCandidates := make([]string, 0, len(m.vnets)+1)
	vnetCandidates = append(vnetCandidates, "")
	for _, vnet := range m.vnets {
		if vnet.account == tunnel.account && !vnet.deleted {
			vnetCandidates = append(vnetCandidates, vnet.name)
		}
	}
	sort.Strings(vnetCandidates)
	vnetName := vnetCandidates[rapid.IntRange(0, len(vnetCandidates)-1).Draw(rt, "vnet")]

	observeOnly := rapid.Bool().Draw(rt, "observeOnly")
	deletion := v1alpha1.DeletionPolicyOrphan
	if rapid.Bool().Draw(rt, "deletePolicy") {
		deletion = v1alpha1.DeletionPolicyDelete
	}

	seq := m.nextSeq()
	name := fmt.Sprintf("route-%d", seq)
	cidr := networkCIDR(seq)

	route := &v1alpha1.NetworkRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: name},
		Spec: v1alpha1.NetworkRouteSpec{
			AccountRef: corev1.LocalObjectReference{Name: tunnel.account},
			Network:    cidr,
			TunnelRef: v1alpha1.TunnelReference{
				Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel,
				Name: tunnelName,
			},
			DeletionPolicy: deletion,
		},
	}
	if vnetName != "" {
		route.Spec.VirtualNetworkRef = &corev1.LocalObjectReference{Name: vnetName}
	}
	model := &networkRoute{
		name: name, account: tunnel.account, tunnel: tunnelName, vnetName: vnetName,
		policy: v1alpha1.ManagementPolicyManaged, deletion: deletion,
	}

	if observeOnly {
		// The remote route must match the resolved spec: the tunnel's remote
		// ID and, when virtualNetworkRef is set, the vnet's remote ID.
		tunnelObject := new(v1alpha1.CloudflareTunnel)
		if err := m.h.apiReader.Get(context.Background(),
			types.NamespacedName{Namespace: m.namespace, Name: tunnelName}, tunnelObject); err != nil {
			rt.Fatalf("get tunnel for observe route: %v", err)
		}
		if tunnelObject.Status.TunnelID == "" {
			rt.Skip("tunnel has no remote ID yet")
		}
		seedVNetID := ""
		if vnetName != "" {
			vnetObject := new(v1alpha1.VirtualNetwork)
			if err := m.h.apiReader.Get(context.Background(),
				types.NamespacedName{Namespace: m.namespace, Name: vnetName}, vnetObject); err != nil {
				rt.Fatalf("get vnet for observe route: %v", err)
			}
			if vnetObject.Status.VirtualNetworkID == "" {
				rt.Skip("vnet has no remote ID yet")
			}
			seedVNetID = vnetObject.Status.VirtualNetworkID
		}
		remoteID := fmt.Sprintf("seed-route-%d", seq)
		m.h.stub.State.AddNetworkRoute(cfstub.NetworkRoute{
			ID: remoteID, AccountID: account.accountID, Network: cidr,
			TunnelID: tunnelObject.Status.TunnelID, TunType: "cfd_tunnel",
			VirtualNetworkID: seedVNetID,
		})
		route.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		route.Spec.ExternalRef = &v1alpha1.NetworkRouteExternalReference{RouteID: remoteID}
		model.policy = v1alpha1.ManagementPolicyObserveOnly
		model.remoteID = remoteID
		m.seeds[remoteID] = networkSeed{
			kind: "route", accountID: account.accountID, remoteID: remoteID,
			name: cidr, tunnelID: tunnelObject.Status.TunnelID, vnetID: seedVNetID,
		}
	}

	before := len(m.h.stub.Journal())
	must(rt, m.h.client.Create(context.Background(), route), "create NetworkRoute")
	m.routes[name] = model
	m.rec.Record("CreateRoute", fmt.Sprintf("%s policy=%s", name, model.policy), m.journalDelta(before))
}

// UpdateRouteCIDR moves a managed route to a fresh non-overlapping CIDR.
func (m *networkMachine) UpdateRouteCIDR(rt *rapid.T) {
	candidates := make([]string, 0, len(m.routes))
	for name, route := range m.routes {
		if !route.deleted && route.policy == v1alpha1.ManagementPolicyManaged {
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		rt.Skip("no managed route")
	}
	name := candidates[rapid.IntRange(0, len(candidates)-1).Draw(rt, "route")]
	cidr := networkCIDR(m.nextSeq())

	ctx := context.Background()
	before := len(m.h.stub.Journal())
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := new(v1alpha1.NetworkRoute)
		if err := m.h.client.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, current); err != nil {
			return err
		}
		current.Spec.Network = cidr
		return m.h.client.Update(ctx, current)
	})
	must(rt, err, "update NetworkRoute CIDR")
	m.rec.Record("UpdateRouteCIDR", fmt.Sprintf("%s -> %s", name, cidr), m.journalDelta(before))
}

// UpdateVirtualNetwork changes a managed vnet's comment, which flows into the
// remote comment suffix while preserving the ownership prefix.
func (m *networkMachine) UpdateVirtualNetwork(rt *rapid.T) {
	candidates := make([]string, 0, len(m.vnets))
	for name, vnet := range m.vnets {
		if !vnet.deleted && vnet.policy == v1alpha1.ManagementPolicyManaged {
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		rt.Skip("no managed vnet")
	}
	name := candidates[rapid.IntRange(0, len(candidates)-1).Draw(rt, "vnet")]
	comment := fmt.Sprintf("comment-%d", m.nextSeq())

	ctx := context.Background()
	before := len(m.h.stub.Journal())
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := new(v1alpha1.VirtualNetwork)
		if err := m.h.client.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, current); err != nil {
			return err
		}
		current.Spec.Comment = comment
		return m.h.client.Update(ctx, current)
	})
	must(rt, err, "update VirtualNetwork comment")
	m.rec.Record("UpdateVirtualNetwork", name, m.journalDelta(before))
}

// DeleteObject deletes one account, vnet, or route and records the residue
// its deletion policy must leave once the Kubernetes object is gone.
func (m *networkMachine) DeleteObject(rt *rapid.T) {
	type candidate struct {
		kind string
		name string
	}
	candidates := make([]candidate, 0, len(m.accounts)+len(m.vnets)+len(m.routes))
	for name, account := range m.accounts {
		if !account.deleted {
			candidates = append(candidates, candidate{"account", name})
		}
	}
	for name, vnet := range m.vnets {
		if !vnet.deleted {
			candidates = append(candidates, candidate{"vnet", name})
		}
	}
	for name, route := range m.routes {
		if !route.deleted {
			candidates = append(candidates, candidate{"route", name})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].kind != candidates[j].kind {
			return candidates[i].kind < candidates[j].kind
		}
		return candidates[i].name < candidates[j].name
	})
	if len(candidates) == 0 {
		rt.Skip("nothing to delete")
	}
	pick := candidates[rapid.IntRange(0, len(candidates)-1).Draw(rt, "object")]

	ctx := context.Background()
	before := len(m.h.stub.Journal())
	switch pick.kind {
	case "account":
		must(rt, m.h.client.Delete(ctx, &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: pick.name},
		}), "delete CloudflareAccount")
		m.accounts[pick.name].deleted = true
	case "vnet":
		vnet := m.vnets[pick.name]
		object := new(v1alpha1.VirtualNetwork)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: pick.name}, object); err != nil {
			rt.Fatalf("get vnet before delete: %v", err)
		}
		m.recordResidue("vnet", pick.name, m.accounts[vnet.account].accountID, object.Status.VirtualNetworkID,
			vnet.policy == v1alpha1.ManagementPolicyObserveOnly, vnet.deletion)
		must(rt, m.h.client.Delete(ctx, object), "delete VirtualNetwork")
		vnet.deleted = true
	case "route":
		route := m.routes[pick.name]
		object := new(v1alpha1.NetworkRoute)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: pick.name}, object); err != nil {
			rt.Fatalf("get route before delete: %v", err)
		}
		m.recordResidue("route", pick.name, m.accounts[route.account].accountID, object.Status.RouteID,
			route.policy == v1alpha1.ManagementPolicyObserveOnly, route.deletion)
		must(rt, m.h.client.Delete(ctx, object), "delete NetworkRoute")
		route.deleted = true
	}
	m.rec.Record("DeleteObject", fmt.Sprintf("%s/%s", pick.kind, pick.name), m.journalDelta(before))
}

func (m *networkMachine) recordResidue(kind, name, accountID, remoteID string, observeOnly bool, deletion v1alpha1.DeletionPolicy) {
	if remoteID == "" {
		return
	}
	policy := deletion
	if observeOnly {
		policy = v1alpha1.DeletionPolicyOrphan
	}
	m.residues[remoteID] = networkResidue{
		kind: kind, name: name, accountID: accountID, remoteID: remoteID, policy: policy,
	}
}

// RemoteDrift rewrites one field of a managed remote object underneath the
// controller, then touches the object so the next reconcile must repair it.
// The ownership comment prefix is never touched: destroying it is a permanent
// conflict, not drift.
func (m *networkMachine) RemoteDrift(rt *rapid.T) {
	type candidate struct {
		kind     string
		name     string
		remoteID string
		account  string
	}
	candidates := make([]candidate, 0, len(m.routes)+len(m.vnets))
	ctx := context.Background()
	for name, route := range m.routes {
		if route.deleted || route.policy != v1alpha1.ManagementPolicyManaged || m.faultOutstanding(route.account, "route") {
			continue
		}
		object := new(v1alpha1.NetworkRoute)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		if object.Status.RouteID != "" && object.Status.OwnershipVerified &&
			object.Status.Applied.ObservedGeneration == object.Generation &&
			!m.drifted[object.Status.RouteID] {
			candidates = append(candidates, candidate{"route", name, object.Status.RouteID, route.account})
		}
	}
	for name, vnet := range m.vnets {
		if vnet.deleted || vnet.policy != v1alpha1.ManagementPolicyManaged || m.faultOutstanding(vnet.account, "vnet") {
			continue
		}
		object := new(v1alpha1.VirtualNetwork)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		if object.Status.VirtualNetworkID != "" && object.Status.OwnershipVerified &&
			object.Status.ObservedGeneration == object.Generation &&
			!m.drifted[object.Status.VirtualNetworkID] {
			candidates = append(candidates, candidate{"vnet", name, object.Status.VirtualNetworkID, vnet.account})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].kind != candidates[j].kind {
			return candidates[i].kind < candidates[j].kind
		}
		return candidates[i].name < candidates[j].name
	})
	if len(candidates) == 0 {
		rt.Skip("no applied managed object to drift")
	}
	pick := candidates[rapid.IntRange(0, len(candidates)-1).Draw(rt, "object")]
	accountID := m.accounts[pick.account].accountID

	var expect stabilityExpectation
	switch pick.kind {
	case "route":
		object := new(v1alpha1.NetworkRoute)
		must(rt, m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: pick.name}, object), "get route for drift")
		drifted := networkCIDR(m.nextSeq())
		for _, remote := range m.h.stub.State.NetworkRoutes(accountID) {
			if remote.ID == pick.remoteID {
				remote.Network = drifted
				m.h.stub.State.AddNetworkRoute(remote)
			}
		}
		expect = func(ctx context.Context, h *explorationHarness) (string, error) {
			for _, remote := range h.stub.State.NetworkRoutes(accountID) {
				if remote.ID == pick.remoteID && remote.DeletedAt == nil {
					if remote.Network != object.Status.Applied.Network {
						return remote.ID, fmt.Errorf("drifted route network %s not repaired to %s", remote.Network, object.Status.Applied.Network)
					}
					return remote.ID, nil
				}
			}
			return "", fmt.Errorf("drifted route %s missing", pick.remoteID)
		}
	case "vnet":
		object := new(v1alpha1.VirtualNetwork)
		must(rt, m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: pick.name}, object), "get vnet for drift")
		drifted := fmt.Sprintf("drifted-%d", m.nextSeq())
		for _, remote := range m.h.stub.State.VirtualNetworks(accountID) {
			if remote.ID == pick.remoteID {
				remote.Name = drifted
				m.h.stub.State.AddVirtualNetwork(remote)
			}
		}
		expect = func(ctx context.Context, h *explorationHarness) (string, error) {
			for _, remote := range h.stub.State.VirtualNetworks(accountID) {
				if remote.ID == pick.remoteID && remote.DeletedAt == nil {
					if remote.Name != object.Spec.Name {
						return remote.ID, fmt.Errorf("drifted vnet name %s not repaired to %s", remote.Name, object.Spec.Name)
					}
					return remote.ID, nil
				}
			}
			return "", fmt.Errorf("drifted vnet %s missing", pick.remoteID)
		}
	}
	m.drifted[pick.remoteID] = true

	// Touch the object so a reconcile observes the drift promptly.
	must(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var object client.Object
		switch pick.kind {
		case "route":
			object = new(v1alpha1.NetworkRoute)
		case "vnet":
			object = new(v1alpha1.VirtualNetwork)
		}
		key := types.NamespacedName{Namespace: m.namespace, Name: pick.name}
		if err := m.h.client.Get(ctx, key, object); err != nil {
			return err
		}
		annotations := object.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations["exploratory.flareway.bhyoo.com/touch"] = fmt.Sprintf("%d", m.nextSeq())
		object.SetAnnotations(annotations)
		return m.h.client.Update(ctx, object)
	}), "touch object")

	before := len(m.h.stub.Journal())
	if err := m.h.waitStable(ctx, expect); err != nil {
		rt.Fatalf("drift on %s was not repaired: %v", pick.remoteID, err)
	}
	delete(m.drifted, pick.remoteID)
	m.rec.Record("RemoteDrift", fmt.Sprintf("%s/%s", pick.kind, pick.name), m.journalDelta(before))
}

// InjectFault registers a bounded 429 or 500 fault on one account-scoped
// private-network surface or on token verification. Faults are consumed by
// HTTP attempts; the journal tracks consumption so invariants can exempt only
// the affected kind.
func (m *networkMachine) InjectFault(rt *rapid.T) {
	names := m.accountNames(false)
	if len(names) == 0 {
		rt.Skip("no account")
	}
	accountName := names[rapid.IntRange(0, len(names)-1).Draw(rt, "account")]
	accountID := m.accounts[accountName].accountID

	type target struct {
		kind    string
		method  string
		pattern string
	}
	targets := []target{
		{"route", http.MethodPost, fmt.Sprintf(`^/accounts/%s/teamnet/routes$`, accountID)},
		{"route", http.MethodPatch, fmt.Sprintf(`^/accounts/%s/teamnet/routes/`, accountID)},
		{"route", http.MethodGet, fmt.Sprintf(`^/accounts/%s/teamnet/routes`, accountID)},
		{"vnet", http.MethodPost, fmt.Sprintf(`^/accounts/%s/teamnet/virtual_networks$`, accountID)},
		{"vnet", http.MethodPatch, fmt.Sprintf(`^/accounts/%s/teamnet/virtual_networks/`, accountID)},
		{"tunnel", http.MethodGet, fmt.Sprintf(`^/accounts/%s/cfd_tunnel`, accountID)},
		{"", http.MethodGet, `^/user/tokens/verify$`},
	}
	pick := targets[rapid.IntRange(0, len(targets)-1).Draw(rt, "target")]
	status := http.StatusInternalServerError
	if rapid.Bool().Draw(rt, "rateLimited") {
		status = http.StatusTooManyRequests
	}
	times := rapid.IntRange(1, 3).Draw(rt, "times")

	fault := &networkFault{
		accountID: accountID, kind: pick.kind, method: pick.method,
		pattern: regexp.MustCompile(pick.pattern), times: times,
		journalBase: len(m.h.stub.Journal()),
	}
	m.h.stub.Fault(pick.method, pick.pattern, cfstub.Fault{Status: status, Times: times})
	m.faults = append(m.faults, fault)
	m.rec.Record("InjectFault", fmt.Sprintf("%s %s status=%d times=%d", pick.method, pick.pattern, status, times), 0)
}

// RestartManager restarts the controller manager against the same envtest
// environment and stub; every watched object is reconciled again.
func (m *networkMachine) RestartManager(rt *rapid.T) {
	before := len(m.h.stub.Journal())
	m.h.restartManager(m.t)
	m.rec.Record("RestartManager", "ok", m.journalDelta(before))
}

// faultOutstanding reports whether any matching registered fault group can
// still intercept calls. Repeated registrations of one matcher share a FIFO
// budget in cfstub, so their times and earliest journal boundary are combined.
func (m *networkMachine) faultOutstanding(accountName, kind string) bool {
	account, ok := m.accounts[accountName]
	if !ok {
		return false
	}
	type group struct {
		method      string
		pattern     *regexp.Regexp
		times       int
		journalBase int
	}
	groups := map[string]*group{}
	for _, fault := range m.faults {
		if fault.accountID != account.accountID && fault.kind != "" {
			continue
		}
		if fault.kind != "" && fault.kind != kind {
			continue
		}
		key := fault.method + "\x00" + fault.pattern.String()
		current := groups[key]
		if current == nil {
			groups[key] = &group{
				method: fault.method, pattern: fault.pattern,
				times: fault.times, journalBase: fault.journalBase,
			}
			continue
		}
		current.times += fault.times
		if fault.journalBase < current.journalBase {
			current.journalBase = fault.journalBase
		}
	}
	calls := m.h.stub.Journal()
	for _, fault := range groups {
		consumed := 0
		for _, call := range calls[fault.journalBase:] {
			path := strings.TrimPrefix(call.Path, "/client/v4")
			if call.Method == fault.method && fault.pattern.MatchString(path) {
				consumed++
			}
		}
		if consumed < fault.times {
			return true
		}
	}
	return false
}

// Check runs after every action: it waits for the journal and expectations to
// quiesce, records the observed conditions, then evaluates the family
// invariants against Kubernetes status, cfstub remote state, and the journal.
func (m *networkMachine) Check(rt *rapid.T) {
	ctx := context.Background()
	if err := m.h.waitStable(ctx); err != nil {
		rt.Fatalf("network family did not stabilize: %v", err)
	}
	m.recordConditions(ctx)
	m.checkAuthorizedRemoteWrites(rt)
	m.checkSeedsUntouched(rt)
	m.checkDeletionResidue(rt)
	m.checkAppliedConvergence(rt)
	m.checkPeerStability(rt)
}

func (m *networkMachine) recordConditions(ctx context.Context) {
	for name := range m.accounts {
		account := new(v1alpha1.CloudflareAccount)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Name: name}, account); err != nil {
			continue
		}
		for _, condition := range account.Status.Conditions {
			m.rec.RecordCondition("CloudflareAccount", condition.Type, string(condition.Status), condition.Reason)
		}
	}
	for name := range m.vnets {
		vnet := new(v1alpha1.VirtualNetwork)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, vnet); err != nil {
			continue
		}
		for _, condition := range vnet.Status.Conditions {
			m.rec.RecordCondition("VirtualNetwork", condition.Type, string(condition.Status), condition.Reason)
		}
	}
	for name := range m.routes {
		route := new(v1alpha1.NetworkRoute)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, route); err != nil {
			continue
		}
		for _, condition := range route.Status.Conditions {
			m.rec.RecordCondition("NetworkRoute", condition.Type, string(condition.Status), condition.Reason)
		}
	}
	for name := range m.tunnels {
		tunnel := new(v1alpha1.CloudflareTunnel)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, tunnel); err != nil {
			continue
		}
		for _, condition := range tunnel.Status.Conditions {
			m.rec.RecordCondition("CloudflareTunnel", condition.Type, string(condition.Status), condition.Reason)
		}
	}
}

// parseOwnerComment extracts namespace and name from a private-resource
// ownership comment of the form "flareway <cluster>/<ns>/<name>[ | comment]".
func parseOwnerComment(comment string) (namespace, name string, ok bool) {
	owner, _, _ := strings.Cut(comment, " | ")
	owner, found := strings.CutPrefix(owner, "flareway ")
	if !found {
		return "", "", false
	}
	parts := strings.Split(owner, "/")
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// checkAuthorizedRemoteWrites proves remote objects exist only for accounts
// that hold the platform grant, that their owner comments resolve to tracked
// objects of the same account, and that ObserveOnly objects never gained a
// second remote object.
func (m *networkMachine) checkAuthorizedRemoteWrites(rt *rapid.T) {
	for _, account := range m.accounts {
		for _, remote := range m.h.stub.State.VirtualNetworks(account.accountID) {
			m.checkRemoteVNet(rt, account, remote)
		}
		for _, remote := range m.h.stub.State.NetworkRoutes(account.accountID) {
			m.checkRemoteRoute(rt, account, remote)
		}
		for _, remote := range m.h.stub.State.Tunnels(account.accountID) {
			m.checkRemoteTunnel(rt, account, remote)
		}
	}
}

func (m *networkMachine) checkRemoteVNet(rt *rapid.T, account *networkAccount, remote cfstub.VirtualNetwork) {
	if seed, ok := m.seeds[remote.ID]; ok {
		if seed.kind != "vnet" {
			rt.Fatalf("remote vnet %s collides with %s seed", remote.ID, seed.kind)
		}
		return
	}
	if residue, ok := m.residues[remote.ID]; ok {
		if residue.kind != "vnet" {
			rt.Fatalf("remote vnet %s collides with %s residue", remote.ID, residue.kind)
		}
		return
	}
	if remote.DeletedAt != nil {
		rt.Fatalf("remote vnet %s was deleted without a tracked deletion", remote.ID)
	}
	namespace, name, ok := parseOwnerComment(remote.Comment)
	if !ok || namespace != m.namespace {
		rt.Fatalf("remote vnet %s has unowned comment %q", remote.ID, remote.Comment)
	}
	vnet, tracked := m.vnets[name]
	if !tracked {
		rt.Fatalf("remote vnet %s is owned by untracked object %s", remote.ID, name)
	}
	if !account.granted {
		rt.Fatalf("remote vnet %s exists for ungranted account %s", remote.ID, account.name)
	}
	if vnet.account != account.name {
		rt.Fatalf("remote vnet %s owned by %s was written under account %s", remote.ID, name, account.name)
	}
	if vnet.policy == v1alpha1.ManagementPolicyObserveOnly && remote.ID != vnet.remoteID {
		rt.Fatalf("ObserveOnly vnet %s created unexpected remote %s", name, remote.ID)
	}
}

func (m *networkMachine) checkRemoteRoute(rt *rapid.T, account *networkAccount, remote cfstub.NetworkRoute) {
	if seed, ok := m.seeds[remote.ID]; ok {
		if seed.kind != "route" {
			rt.Fatalf("remote route %s collides with %s seed", remote.ID, seed.kind)
		}
		return
	}
	if residue, ok := m.residues[remote.ID]; ok {
		if residue.kind != "route" {
			rt.Fatalf("remote route %s collides with %s residue", remote.ID, residue.kind)
		}
		return
	}
	if remote.DeletedAt != nil {
		rt.Fatalf("remote route %s was deleted without a tracked deletion", remote.ID)
	}
	namespace, name, ok := parseOwnerComment(remote.Comment)
	if !ok || namespace != m.namespace {
		rt.Fatalf("remote route %s has unowned comment %q", remote.ID, remote.Comment)
	}
	route, tracked := m.routes[name]
	if !tracked {
		rt.Fatalf("remote route %s is owned by untracked object %s", remote.ID, name)
	}
	if !account.granted {
		rt.Fatalf("remote route %s exists for ungranted account %s", remote.ID, account.name)
	}
	if route.account != account.name {
		rt.Fatalf("remote route %s owned by %s was written under account %s", remote.ID, name, account.name)
	}
	if route.policy == v1alpha1.ManagementPolicyObserveOnly && remote.ID != route.remoteID {
		rt.Fatalf("ObserveOnly route %s created unexpected remote %s", name, remote.ID)
	}
}

func (m *networkMachine) checkRemoteTunnel(rt *rapid.T, account *networkAccount, remote cfstub.Tunnel) {
	if remote.DeletedAt != nil {
		rt.Fatalf("remote tunnel %s was deleted; tunnels use DeletionPolicy Orphan", remote.ID)
	}
	for _, tunnel := range m.tunnels {
		if tunnel.remoteName == remote.Name {
			if !account.granted {
				rt.Fatalf("remote tunnel %s exists for ungranted account %s", remote.ID, account.name)
			}
			if tunnel.account != account.name {
				rt.Fatalf("remote tunnel %s owned by %s was written under account %s", remote.ID, tunnel.name, account.name)
			}
			return
		}
	}
	rt.Fatalf("remote tunnel %s (%s) is not owned by any tracked tunnel", remote.ID, remote.Name)
}

// checkSeedsUntouched proves ObserveOnly targets are byte-identical to their
// seeded state and that no mutating call ever referenced the seeded remote ID.
func (m *networkMachine) checkSeedsUntouched(rt *rapid.T) {
	for _, seed := range m.seeds {
		switch seed.kind {
		case "vnet":
			remote, found := m.findRemoteVNet(seed.accountID, seed.remoteID)
			if !found || remote.DeletedAt != nil {
				rt.Fatalf("ObserveOnly remote vnet %s is gone", seed.remoteID)
			}
			if remote.Name != seed.name || remote.IsDefaultNetwork != seed.isDefault {
				rt.Fatalf("ObserveOnly remote vnet %s mutated: %#v", seed.remoteID, remote)
			}
		case "route":
			remote, found := m.findRemoteRoute(seed.accountID, seed.remoteID)
			if !found || remote.DeletedAt != nil {
				rt.Fatalf("ObserveOnly remote route %s is gone", seed.remoteID)
			}
			if remote.Network != seed.name || remote.TunnelID != seed.tunnelID || remote.VirtualNetworkID != seed.vnetID {
				rt.Fatalf("ObserveOnly remote route %s mutated: %#v", seed.remoteID, remote)
			}
		}
	}
	for _, call := range m.h.stub.Journal() {
		switch call.Method {
		case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		default:
			continue
		}
		path := strings.TrimPrefix(call.Path, "/client/v4")
		for _, seed := range m.seeds {
			if strings.Contains(path, seed.remoteID) {
				rt.Fatalf("mutating call %s %s touched ObserveOnly remote %s", call.Method, path, seed.remoteID)
			}
		}
	}
}

// checkDeletionResidue proves the remote outcome of every tracked deletion
// once the Kubernetes object is gone: Delete removes the remote object,
// Orphan and ObserveOnly retain it.
func (m *networkMachine) checkDeletionResidue(rt *rapid.T) {
	ctx := context.Background()
	for _, residue := range m.residues {
		gone := m.objectGone(ctx, residue)
		if !gone {
			continue // deletion still in flight; either remote state is legal
		}
		switch residue.kind {
		case "vnet":
			remote, found := m.findRemoteVNet(residue.accountID, residue.remoteID)
			m.assertResidue(rt, residue, found && remote.DeletedAt == nil)
		case "route":
			remote, found := m.findRemoteRoute(residue.accountID, residue.remoteID)
			m.assertResidue(rt, residue, found && remote.DeletedAt == nil)
		}
	}
}

func (m *networkMachine) objectGone(ctx context.Context, residue networkResidue) bool {
	var err error
	key := types.NamespacedName{Namespace: m.namespace, Name: residue.name}
	switch residue.kind {
	case "vnet":
		err = m.h.apiReader.Get(ctx, key, new(v1alpha1.VirtualNetwork))
	case "route":
		err = m.h.apiReader.Get(ctx, key, new(v1alpha1.NetworkRoute))
	}
	return apierrors.IsNotFound(err)
}

func (m *networkMachine) assertResidue(rt *rapid.T, residue networkResidue, active bool) {
	switch residue.policy {
	case v1alpha1.DeletionPolicyDelete:
		if active {
			rt.Fatalf("remote %s %s survived a Delete-policy deletion", residue.kind, residue.remoteID)
		}
	default: // Orphan and ObserveOnly retain the remote object
		if !active {
			rt.Fatalf("remote %s %s was removed despite Orphan/ObserveOnly policy", residue.kind, residue.remoteID)
		}
	}
}

// checkAppliedConvergence proves that an object whose status claims the
// current generation was applied has a remote object matching that claim.
func (m *networkMachine) checkAppliedConvergence(rt *rapid.T) {
	ctx := context.Background()
	for name, model := range m.routes {
		if model.deleted || model.policy != v1alpha1.ManagementPolicyManaged {
			continue
		}
		object := new(v1alpha1.NetworkRoute)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		applied := object.Status.Applied
		if applied.ObservedGeneration != object.Generation || applied.Network == "" || m.drifted[object.Status.RouteID] {
			continue
		}
		remote, found := m.findRemoteRoute(m.accounts[model.account].accountID, object.Status.RouteID)
		if !found || remote.DeletedAt != nil {
			rt.Fatalf("applied route %s remote %s is missing", name, object.Status.RouteID)
		}
		if remote.Network != applied.Network || remote.TunnelID != applied.TunnelID ||
			remote.VirtualNetworkID != applied.VirtualNetworkID {
			rt.Fatalf("applied route %s remote drifted: remote=%#v applied=%#v", name, remote, applied)
		}
	}
	for name, model := range m.vnets {
		if model.deleted || model.policy != v1alpha1.ManagementPolicyManaged {
			continue
		}
		object := new(v1alpha1.VirtualNetwork)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		if object.Status.ObservedGeneration != object.Generation || object.Status.VirtualNetworkID == "" ||
			!meta.IsStatusConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) ||
			m.drifted[object.Status.VirtualNetworkID] {
			continue
		}
		remote, found := m.findRemoteVNet(m.accounts[model.account].accountID, object.Status.VirtualNetworkID)
		if !found || remote.DeletedAt != nil {
			rt.Fatalf("applied vnet %s remote %s is missing", name, object.Status.VirtualNetworkID)
		}
		if remote.Name != object.Spec.Name || remote.IsDefaultNetwork != object.Spec.IsDefault {
			rt.Fatalf("applied vnet %s remote drifted: remote=%#v spec.name=%s", name, remote, object.Spec.Name)
		}
	}
}

// checkPeerStability proves a failed or disrupted operation never invalidates
// the Ready status of unrelated applied objects: only objects in a faulted
// scope, under drift repair, or with a deleted dependency may be unready.
func (m *networkMachine) checkPeerStability(rt *rapid.T) {
	ctx := context.Background()
	for name, model := range m.routes {
		if model.deleted {
			continue
		}
		account := m.accounts[model.account]
		if account == nil || account.deleted {
			continue
		}
		object := new(v1alpha1.NetworkRoute)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		if object.Status.Applied.ObservedGeneration != object.Generation || object.Status.Applied.Network == "" {
			continue // never converged or spec changed since the last apply
		}
		if m.drifted[object.Status.RouteID] || m.faultOutstanding(model.account, "route") {
			continue
		}
		if model.vnetName != "" {
			if vnet, ok := m.vnets[model.vnetName]; ok && vnet.deleted {
				continue
			}
			if m.faultOutstanding(model.account, "vnet") {
				continue
			}
		}
		if !meta.IsStatusConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
			rt.Fatalf("applied route %s lost Ready without a spec change, fault, or drift", name)
		}
	}
	for name, model := range m.vnets {
		if model.deleted {
			continue
		}
		account := m.accounts[model.account]
		if account == nil || account.deleted {
			continue
		}
		object := new(v1alpha1.VirtualNetwork)
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, object); err != nil {
			continue
		}
		if object.Status.ObservedGeneration != object.Generation || object.Status.VirtualNetworkID == "" {
			continue
		}
		if m.drifted[object.Status.VirtualNetworkID] || m.faultOutstanding(model.account, "vnet") {
			continue
		}
		if !meta.IsStatusConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionReady) {
			rt.Fatalf("applied vnet %s lost Ready without a spec change, fault, or drift", name)
		}
	}
}

func (m *networkMachine) findRemoteVNet(accountID, remoteID string) (cfstub.VirtualNetwork, bool) {
	for _, remote := range m.h.stub.State.VirtualNetworks(accountID) {
		if remote.ID == remoteID {
			return remote, true
		}
	}
	return cfstub.VirtualNetwork{}, false
}

func (m *networkMachine) findRemoteRoute(accountID, remoteID string) (cfstub.NetworkRoute, bool) {
	for _, remote := range m.h.stub.State.NetworkRoutes(accountID) {
		if remote.ID == remoteID {
			return remote, true
		}
	}
	return cfstub.NetworkRoute{}, false
}
