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
	"slices"
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// recordingAccessAPI records every Cloudflare call the Access reconcilers
// under test make, so a pass can prove it skipped Cloudflare entirely.
type recordingAccessAPI struct {
	flarecloudflare.AccessAPI
	mu    sync.Mutex
	calls []string
}

func (r *recordingAccessAPI) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recordingAccessAPI) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingAccessAPI) GetAccessPolicy(ctx context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	r.record("GetAccessPolicy")
	return r.AccessAPI.GetAccessPolicy(ctx, id)
}

func (r *recordingAccessAPI) ListAccessPolicies(ctx context.Context) ([]flarecloudflare.AccessPolicy, error) {
	r.record("ListAccessPolicies")
	return r.AccessAPI.ListAccessPolicies(ctx)
}

func (r *recordingAccessAPI) CreateAccessPolicy(ctx context.Context, input flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	r.record("CreateAccessPolicy")
	return r.AccessAPI.CreateAccessPolicy(ctx, input)
}

func (r *recordingAccessAPI) UpdateAccessPolicy(ctx context.Context, id string, input flarecloudflare.AccessPolicyInput) (flarecloudflare.AccessPolicy, error) {
	r.record("UpdateAccessPolicy")
	return r.AccessAPI.UpdateAccessPolicy(ctx, id, input)
}

func (r *recordingAccessAPI) GetAccessGroup(ctx context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.AccessGroup, error) {
	r.record("GetAccessGroup")
	return r.AccessAPI.GetAccessGroup(ctx, scope, id)
}

func (r *recordingAccessAPI) ListAccessGroups(ctx context.Context, options flarecloudflare.AccessGroupListOptions) ([]flarecloudflare.AccessGroup, error) {
	r.record("ListAccessGroups")
	return r.AccessAPI.ListAccessGroups(ctx, options)
}

func (r *recordingAccessAPI) CreateAccessGroup(ctx context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	r.record("CreateAccessGroup")
	return r.AccessAPI.CreateAccessGroup(ctx, scope, input)
}

func (r *recordingAccessAPI) UpdateAccessGroup(ctx context.Context, scope flarecloudflare.AccessScope, id string, input flarecloudflare.AccessGroupInput) (flarecloudflare.AccessGroup, error) {
	r.record("UpdateAccessGroup")
	return r.AccessAPI.UpdateAccessGroup(ctx, scope, id, input)
}

func (r *recordingAccessAPI) GetServiceToken(ctx context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.ServiceToken, error) {
	r.record("GetServiceToken")
	return r.AccessAPI.GetServiceToken(ctx, scope, id)
}

func (r *recordingAccessAPI) ListServiceTokens(ctx context.Context, scope flarecloudflare.AccessScope) ([]flarecloudflare.ServiceToken, error) {
	r.record("ListServiceTokens")
	return r.AccessAPI.ListServiceTokens(ctx, scope)
}

func (r *recordingAccessAPI) CreateServiceToken(ctx context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	r.record("CreateServiceToken")
	return r.AccessAPI.CreateServiceToken(ctx, scope, input)
}

func (r *recordingAccessAPI) UpdateServiceToken(ctx context.Context, scope flarecloudflare.AccessScope, id string, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceToken, error) {
	r.record("UpdateServiceToken")
	return r.AccessAPI.UpdateServiceToken(ctx, scope, id, input)
}

func (r *recordingAccessAPI) GetIdentityProvider(ctx context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	r.record("GetIdentityProvider")
	return r.AccessAPI.GetIdentityProvider(ctx, id)
}

func (r *recordingAccessAPI) ListIdentityProviders(ctx context.Context) ([]flarecloudflare.IdentityProvider, error) {
	r.record("ListIdentityProviders")
	return r.AccessAPI.ListIdentityProviders(ctx)
}

func (r *recordingAccessAPI) CreateIdentityProvider(ctx context.Context, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	r.record("CreateIdentityProvider")
	return r.AccessAPI.CreateIdentityProvider(ctx, input)
}

func (r *recordingAccessAPI) UpdateIdentityProvider(ctx context.Context, id string, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	r.record("UpdateIdentityProvider")
	remote, err := r.AccessAPI.UpdateIdentityProvider(ctx, id, input)
	// Cloudflare returns the SCIM secret once, in the response that enables
	// SCIM; the shared fake does not model it.
	if err == nil && identityProviderSCIMEnabled(remote.SCIMConfig) {
		remote.SCIMSecret = "scim-token"
	}
	return remote, err
}

func (r *recordingAccessAPI) ListIdentityProviderSCIMUsers(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMUser, bool, error) {
	r.record("ListIdentityProviderSCIMUsers")
	return nil, false, nil
}

func (r *recordingAccessAPI) ListIdentityProviderSCIMGroups(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMGroup, bool, error) {
	r.record("ListIdentityProviderSCIMGroups")
	return nil, false, nil
}

func (r *recordingAccessAPI) GetAccessInfrastructureTarget(ctx context.Context, id string) (flarecloudflare.AccessInfrastructureTarget, error) {
	r.record("GetAccessInfrastructureTarget")
	return r.AccessAPI.GetAccessInfrastructureTarget(ctx, id)
}

func (r *recordingAccessAPI) CreateAccessInfrastructureTarget(ctx context.Context, input flarecloudflare.AccessInfrastructureTargetInput) (flarecloudflare.AccessInfrastructureTarget, error) {
	r.record("CreateAccessInfrastructureTarget")
	return r.AccessAPI.CreateAccessInfrastructureTarget(ctx, input)
}

func (r *recordingAccessAPI) UpdateAccessInfrastructureTarget(ctx context.Context, id string, input flarecloudflare.AccessInfrastructureTargetInput) (flarecloudflare.AccessInfrastructureTarget, error) {
	r.record("UpdateAccessInfrastructureTarget")
	return r.AccessAPI.UpdateAccessInfrastructureTarget(ctx, id, input)
}

// contentBaselineWorld is the tenant, account, and credentials every Access
// kind under test reconciles against, plus a controllable clock and latch.
type contentBaselineWorld struct {
	kube   client.Client
	scheme *runtime.Scheme
	latch  *freshness.Latch
	policy freshness.Policy
	now    time.Time
}

func newContentBaselineWorld(t *testing.T, objects ...client.Object) *contentBaselineWorld {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"}, Zones: []string{"*"},
				Exposures:        []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				PlatformObjects:  v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs: v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(start)},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(start)},
		}},
	}
	base := []client.Object{
		account,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}},
	}
	statusTypes := make([]client.Object, 0, len(objects))
	for _, object := range objects {
		statusTypes = append(statusTypes, object.DeepCopyObject().(client.Object))
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(statusTypes...).
		WithObjects(append(base, objects...)...).
		Build()
	return &contentBaselineWorld{
		kube: kube, scheme: scheme, latch: freshness.NewLatch(), policy: freshness.DefaultPolicy(), now: start,
	}
}

func (w *contentBaselineWorld) clock() time.Time { return w.now }

// contentBaselineCase drives one kind through the sweep confirmation
// contract after it has converged.
type contentBaselineCase struct {
	kind string
	key  types.NamespacedName
	// pass runs one reconcile and returns how many Cloudflare calls it made.
	pass func(t *testing.T) int
	// listed returns the object's remote exactly as the kind's list API
	// returns it.
	listed func(t *testing.T) any
	// drift changes a compared field of the remote out of band.
	drift func(t *testing.T)
}

// settle reconciles until a pass skips Cloudflare, which happens only once
// the gate stamp covers the bound remote ID.
func (c contentBaselineCase) settle(t *testing.T, world *contentBaselineWorld) {
	t.Helper()
	for range 5 {
		world.now = world.now.Add(time.Second)
		if c.pass(t) == 0 {
			return
		}
	}
	t.Fatalf("%s never converged to an open gate", c.kind)
}

// confirmKeepsGateOpen proves the sweep confirmation contract for a kind
// with a content baseline:
//   - without a confirmation, a pass after the TTL reads Cloudflare;
//   - a confirmation of the unchanged listing lets the pass after the next
//     TTL skip Cloudflare entirely;
//   - the same listing with a compared field changed out of band is drift,
//     and the pass after that drift is reported reads and repairs it.
func (c contentBaselineCase) confirmKeepsGateOpen(t *testing.T, world *contentBaselineWorld, ttl time.Duration) {
	t.Helper()
	c.settle(t, world)

	world.now = world.now.Add(ttl)
	if calls := c.pass(t); calls == 0 {
		t.Fatalf("%s: pass after the TTL without a sweep confirmation skipped Cloudflare", c.kind)
	}

	world.now = world.now.Add(ttl)
	if world.latch.ConfirmContent(c.kind, c.key, c.listed(t), world.now) {
		t.Fatalf("%s: sweep reported drift on the remote the reconciler just verified", c.kind)
	}
	if calls := c.pass(t); calls != 0 {
		t.Fatalf("%s: pass after a sweep confirmation still made %d Cloudflare calls", c.kind, calls)
	}

	c.drift(t)
	if !world.latch.ConfirmContent(c.kind, c.key, c.listed(t), world.now) {
		t.Fatalf("%s: sweep confirmed a remote changed out of band", c.kind)
	}
	world.latch.Invalidate(c.kind, c.key, "remote content no longer matches")
	if calls := c.pass(t); calls == 0 {
		t.Fatalf("%s: pass after reported drift skipped Cloudflare", c.kind)
	}
	if world.latch.ConfirmContent(c.kind, c.key, c.listed(t), world.now) {
		t.Fatalf("%s: repaired remote still reported as drift", c.kind)
	}
}

func reconcileCount(t *testing.T, reconciler interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
}, key types.NamespacedName, calls func() int) int {
	t.Helper()
	before := calls()
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile %s: %v", key, err)
	}
	return calls() - before
}

func listedByID[T any](t *testing.T, items []T, err error, id func(T) string, want string) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(items, func(item T) bool { return id(item) == want })
	if index < 0 {
		t.Fatalf("remote %q missing from the listing", want)
	}
	return items[index]
}

func TestAccessStandaloneApplicationSweepConfirmationKeepsGateOpen(t *testing.T) {
	object := &v1alpha1.AccessStandaloneApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "bookmark", Namespace: "tenant", UID: "bookmark-uid", Generation: 1, Finalizers: []string{v1alpha1.AccessStandaloneApplicationFinalizer}},
		Spec: v1alpha1.AccessStandaloneApplicationSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Type:             v1alpha1.AccessStandaloneApplicationTypeBookmark,
			Application:      v1alpha1.AccessApplicationSettings{Name: "tenant/bookmark"},
			Bookmark:         &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://wiki.example.test"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	world := newContentBaselineWorld(t, object)
	remote := newFakeAccessApplicationCloudflare()
	reconciler := &AccessStandaloneApplicationReconciler{
		Client: world.kube, Scheme: world.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 world.clock, Freshness: world.policy, Invalidator: world.latch,
	}
	key := client.ObjectKeyFromObject(object)
	applicationID := func(t *testing.T) string {
		var current v1alpha1.AccessStandaloneApplication
		if err := world.kube.Get(context.Background(), key, &current); err != nil {
			t.Fatal(err)
		}
		return current.Status.ApplicationID
	}
	contentBaselineCase{
		kind: "AccessStandaloneApplication", key: key,
		pass: func(t *testing.T) int {
			return reconcileCount(t, reconciler, key, func() int { return len(remote.Calls()) })
		},
		listed: func(t *testing.T) any {
			return listedByID(t, unrecordedApplicationListing(remote), nil, func(a flarecloudflare.AccessApplication) string { return a.ID }, applicationID(t))
		},
		drift: func(t *testing.T) {
			remote.mu.Lock()
			application := remote.applications[applicationID(t)]
			remote.mu.Unlock()
			application.Domain = "https://phishing.example.test"
			remote.Put(application)
		},
	}.confirmKeepsGateOpen(t, world, world.policy.TTL(freshness.GradeAuthz))
}

// unrecordedApplicationListing returns the applications exactly as the fake's
// ListAccessApplications does, without counting as a reconciler call.
func unrecordedApplicationListing(f *fakeAccessApplicationCloudflare) []flarecloudflare.AccessApplication {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]flarecloudflare.AccessApplication, 0, len(f.applications))
	for _, application := range f.applications {
		result = append(result, f.embedPolicies(application))
	}
	return result
}

func TestAccessPolicySweepConfirmationKeepsGateOpen(t *testing.T) {
	object := &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant", UID: "policy-uid", Generation: 1, Finalizers: []string{v1alpha1.AccessPolicyFinalizer}},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "policy",
			Decision:         v1alpha1.AccessPolicyDecisionAllow,
			Include:          []v1alpha1.AccessRule{{Email: &v1alpha1.AccessEmailRule{Email: "user@example.test"}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	world := newContentBaselineWorld(t, object)
	store := newFakeAccessResourceCloudflare()
	remote := &recordingAccessAPI{AccessAPI: store}
	reconciler := &AccessPolicyReconciler{
		Client: world.kube, Scheme: world.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 world.clock, Freshness: world.policy, Invalidator: world.latch,
	}
	key := client.ObjectKeyFromObject(object)
	policyID := func(t *testing.T) string {
		var current v1alpha1.AccessPolicy
		if err := world.kube.Get(context.Background(), key, &current); err != nil {
			t.Fatal(err)
		}
		return current.Status.PolicyID
	}
	contentBaselineCase{
		kind: "AccessPolicy", key: key,
		pass: func(t *testing.T) int { return reconcileCount(t, reconciler, key, remote.count) },
		listed: func(t *testing.T) any {
			items, err := store.ListAccessPolicies(context.Background())
			return listedByID(t, items, err, func(p flarecloudflare.AccessPolicy) string { return p.ID }, policyID(t))
		},
		drift: func(t *testing.T) {
			store.mu.Lock()
			defer store.mu.Unlock()
			policy := store.policies[policyID(t)]
			policy.Decision = string(v1alpha1.AccessPolicyDecisionBypass)
			store.policies[policy.ID] = policy
		},
	}.confirmKeepsGateOpen(t, world, world.policy.TTL(freshness.GradeAuthz))
}

func TestAccessGroupSweepConfirmationKeepsGateOpen(t *testing.T) {
	object := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "tenant", UID: "group-uid", Generation: 1, Finalizers: []string{v1alpha1.AccessGroupFinalizer}},
		Spec: v1alpha1.AccessGroupSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "group",
			Include:          []v1alpha1.AccessRule{{Email: &v1alpha1.AccessEmailRule{Email: "user@example.test"}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	world := newContentBaselineWorld(t, object)
	store := newFakeAccessResourceCloudflare()
	remote := &recordingAccessAPI{AccessAPI: store}
	reconciler := &AccessGroupReconciler{
		Client: world.kube, APIReader: world.kube, Scheme: world.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 world.clock, Freshness: world.policy, Invalidator: world.latch,
	}
	key := client.ObjectKeyFromObject(object)
	contentBaselineCase{
		kind: "AccessGroup", key: key,
		pass: func(t *testing.T) int { return reconcileCount(t, reconciler, key, remote.count) },
		listed: func(t *testing.T) any {
			items, err := store.ListAccessGroups(context.Background(), flarecloudflare.AccessGroupListOptions{})
			return listedByID(t, items, err, func(g flarecloudflare.AccessGroup) string { return g.ID }, store.onlyAccessGroupID())
		},
		drift: func(*testing.T) {
			store.mu.Lock()
			defer store.mu.Unlock()
			for id, group := range store.groups {
				group.Include = []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}
				store.groups[id] = group
			}
		},
	}.confirmKeepsGateOpen(t, world, world.policy.TTL(freshness.GradeAuthz))
}

func TestAccessInfrastructureTargetSweepConfirmationKeepsGateOpen(t *testing.T) {
	object := &v1alpha1.AccessInfrastructureTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "tenant", UID: "target-uid", Generation: 1, Finalizers: []string{v1alpha1.AccessInfrastructureTargetFinalizer}},
		Spec: v1alpha1.AccessInfrastructureTargetSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Hostname: "db.example.test",
			IP:               v1alpha1.AccessInfrastructureTargetIP{IPV4: &v1alpha1.AccessInfrastructureTargetIPv4Address{IPAddr: "192.0.2.10", VirtualNetworkID: "vnet-1"}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	world := newContentBaselineWorld(t, object)
	store := &fakeInfrastructureTargetCloudflare{targets: map[string]flarecloudflare.AccessInfrastructureTarget{}}
	remote := &recordingAccessAPI{AccessAPI: store}
	reconciler := &AccessInfrastructureTargetReconciler{
		Client: world.kube, APIReader: world.kube, Scheme: world.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 world.clock, Freshness: world.policy, Invalidator: world.latch,
	}
	key := client.ObjectKeyFromObject(object)
	targetID := func(t *testing.T) string {
		var current v1alpha1.AccessInfrastructureTarget
		if err := world.kube.Get(context.Background(), key, &current); err != nil {
			t.Fatal(err)
		}
		return current.Status.TargetID
	}
	contentBaselineCase{
		kind: "AccessInfrastructureTarget", key: key,
		pass: func(t *testing.T) int { return reconcileCount(t, reconciler, key, remote.count) },
		listed: func(t *testing.T) any {
			items, err := store.ListAccessInfrastructureTargets(context.Background())
			return listedByID(t, items, err, func(target flarecloudflare.AccessInfrastructureTarget) string { return target.ID }, targetID(t))
		},
		drift: func(t *testing.T) {
			target := store.target(targetID(t))
			target.IPV4 = &flarecloudflare.AccessInfrastructureTargetAddress{IPAddr: "198.51.100.7", VirtualNetworkID: "vnet-1"}
			store.put(target)
		},
	}.confirmKeepsGateOpen(t, world, world.policy.TTL(freshness.GradeAuthz))
}

func newIdentityProviderBaselineWorld(t *testing.T) (*identityProviderWorld, *identityProviderFakeAPI, *recordingAccessAPI, *time.Time) {
	t.Helper()
	store := &identityProviderFakeAPI{providers: make(map[string]flarecloudflare.IdentityProvider)}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	world := newIdentityProviderWorld(t, store, now, v1alpha1.ManagementPolicyManaged, "")
	remote := &recordingAccessAPI{AccessAPI: store}
	world.reconciler.NewCloudflareClient = func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil }
	world.reconciler.Now = func() time.Time { return now }
	world.reconciler.Freshness = freshness.DefaultPolicy()
	world.reconciler.Invalidator = freshness.NewLatch()
	return world, store, remote, &now
}

func TestIdentityProviderSweepConfirmationKeepsGateOpen(t *testing.T) {
	idp, store, remote, now := newIdentityProviderBaselineWorld(t)
	world := &contentBaselineWorld{latch: idp.reconciler.Invalidator}
	providerID := func(t *testing.T) string {
		var current v1alpha1.IdentityProvider
		if err := idp.kube.Get(context.Background(), idp.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		return current.Status.IDPID
	}
	c := contentBaselineCase{
		kind: "IdentityProvider", key: idp.request.NamespacedName,
		pass: func(t *testing.T) int {
			*now = world.now
			return reconcileCount(t, idp.reconciler, idp.request.NamespacedName, remote.count)
		},
		listed: func(t *testing.T) any {
			items, err := store.ListIdentityProviders(context.Background())
			return listedByID(t, items, err, func(p flarecloudflare.IdentityProvider) string { return p.ID }, providerID(t))
		},
		drift: func(t *testing.T) {
			provider := store.providers[providerID(t)]
			provider.Name = "renamed out of band"
			store.providers[provider.ID] = provider
		},
	}
	world.now = *now
	c.confirmKeepsGateOpen(t, world, idp.reconciler.Freshness.TTL(freshness.GradeAuthz))
}

// A provider with SCIM enabled verifies its SCIM directory, which the sweep's
// provider listing does not show. It must register no baseline, so a sweep
// listing neither confirms it nor reports drift, and it keeps reading
// Cloudflare itself once per TTL.
func TestIdentityProviderWithSCIMKeepsItsOwnVerify(t *testing.T) {
	idp, store, remote, now := newIdentityProviderBaselineWorld(t)
	var object v1alpha1.IdentityProvider
	if err := idp.kube.Get(context.Background(), idp.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	enabled := true
	object.Spec.SCIMConfig = &v1alpha1.IdentityProviderSCIMConfig{Enabled: &enabled, SecretRef: &corev1.LocalObjectReference{Name: "scim-secret"}}
	if err := idp.kube.Update(context.Background(), &object); err != nil {
		t.Fatal(err)
	}
	key := idp.request.NamespacedName
	latch := idp.reconciler.Invalidator
	pass := func() int { return reconcileCount(t, idp.reconciler, key, remote.count) }
	settled := false
	for range 5 {
		*now = now.Add(time.Second)
		if pass() == 0 {
			settled = true
			break
		}
	}
	if !settled {
		t.Fatal("SCIM identity provider never converged to an open gate")
	}
	if err := idp.kube.Get(context.Background(), key, &object); err != nil {
		t.Fatal(err)
	}
	provider := store.providers[object.Status.IDPID]
	if !identityProviderSCIMEnabled(provider.SCIMConfig) {
		t.Fatalf("fixture did not enable SCIM remotely: %+v", provider.SCIMConfig)
	}

	ttl := idp.reconciler.Freshness.TTL(freshness.GradeAuthz)
	*now = now.Add(ttl)
	if pass() == 0 {
		t.Fatal("pass after the TTL skipped Cloudflare")
	}
	*now = now.Add(ttl)
	provider.Name = "renamed out of band"
	if latch.ConfirmContent("IdentityProvider", key, provider, *now) {
		t.Fatal("sweep judged the content of a SCIM identity provider it cannot fully see")
	}
	if calls := remote.count(); pass() == 0 {
		t.Fatalf("sweep listing kept a SCIM identity provider's gate open (calls before: %d)", calls)
	}
}

// ServiceToken's verify reads its credential Secret and refreshes on expiry,
// neither of which the token listing shows, so a listing must never stand in
// for that verify.
func TestServiceTokenKeepsItsOwnVerify(t *testing.T) {
	object := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant", UID: "token-uid", Generation: 1, Finalizers: []string{v1alpha1.ServiceTokenFinalizer}},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "token",
			Enabled: true, Duration: "8760h",
			SecretRef:        corev1.LocalObjectReference{Name: "token-credentials"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	world := newContentBaselineWorld(t, object)
	store := newFakeAccessResourceCloudflare()
	remote := &recordingAccessAPI{AccessAPI: store}
	reconciler := &ServiceTokenReconciler{
		Client: world.kube, APIReader: world.kube, Scheme: world.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 world.clock, Freshness: world.policy, Invalidator: world.latch,
	}
	key := client.ObjectKeyFromObject(object)
	c := contentBaselineCase{kind: "ServiceToken", key: key, pass: func(t *testing.T) int { return reconcileCount(t, reconciler, key, remote.count) }}
	c.settle(t, world)

	var current v1alpha1.ServiceToken
	if err := world.kube.Get(context.Background(), key, &current); err != nil {
		t.Fatal(err)
	}
	token, err := store.GetServiceToken(context.Background(), flarecloudflare.AccessScope{}, current.Status.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	ttl := world.policy.TTL(freshness.GradeAuthz)
	world.now = world.now.Add(ttl)
	if c.pass(t) == 0 {
		t.Fatal("pass after the TTL skipped Cloudflare")
	}
	world.now = world.now.Add(ttl)
	token.Enabled = false
	if world.latch.ConfirmContent("ServiceToken", key, token, world.now) {
		t.Fatal("sweep judged the content of a service token whose verify it cannot stand in for")
	}
	if c.pass(t) == 0 {
		t.Fatal("sweep listing kept a service token's gate open")
	}
}
