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
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/sweep"
)

func startPR2EnvtestManager(t *testing.T) (*envtest.Environment, ctrl.Manager, client.Client, *runtime.Scheme) {
	t.Helper()
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join(managerGatewayAPIDir(), "config", "crd", "standard"),
		},
		ErrorIfCRDPathMissing: true,
	}
	if dir := managerEnvtestAssets(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := env.Stop(); stopErr != nil {
			t.Logf("stop envtest: %v", stopErr)
		}
	})

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, gatewayv1.Install, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("add scheme: %v", err)
		}
	}
	ctrllog.SetLogger(logr.Discard())
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Logger:     logr.Discard(),
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}
	if err := direct.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create operator namespace: %v", err)
	}
	return env, mgr, direct, scheme
}

func startManagerAndWait(t *testing.T, mgr ctrl.Manager) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager exited: %v", err)
		}
	}()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache never synced")
	}
	return ctx
}

type noopClientFactory struct{}

func (noopClientFactory) Client(_, _ string) flarecloudflare.API { return nil }

func waitUntilTrue(t *testing.T, timeout time.Duration, desc string, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := fn()
		if err == nil && ok {
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("timed out waiting for %s: %v", desc, lastErr)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func markAccountReady(ctx context.Context, t *testing.T, direct client.Client, account *v1alpha1.CloudflareAccount, zones []v1alpha1.CloudflareVerifiedZone) {
	t.Helper()
	var current v1alpha1.CloudflareAccount
	if err := direct.Get(ctx, client.ObjectKeyFromObject(account), &current); err != nil {
		t.Fatalf("get CloudflareAccount: %v", err)
	}
	now := metav1.Now()
	current.Status.Verified = v1alpha1.CloudflareAccountVerifiedStatus{
		AuthDomain: "team.cloudflareaccess.com",
		TeamName:   "team",
		Zones:      zones,
	}
	current.Status.Conditions = []metav1.Condition{
		{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", Message: "ready", ObservedGeneration: current.Generation, LastTransitionTime: now},
		{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", Message: "valid", ObservedGeneration: current.Generation, LastTransitionTime: now},
	}
	if err := direct.Status().Update(ctx, &current); err != nil {
		t.Fatalf("update CloudflareAccount status: %v", err)
	}
}

func assertConditionTrueForCurrentGen(conditions []metav1.Condition, condType string, generation int64) bool {
	c := meta.FindStatusCondition(conditions, condType)
	return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == generation
}

// QA-2A-1: Multi-controller manager per-kind fan-out must deliver every
// targeted drift wakeup to its owning controller without competing across
// consumers, and a slow/full subscriber for one kind must never block or drop
// wakeups for any other kind.
func TestQA2A1PerKindSweepFanoutEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	// Short TTLs only for sweep target pacing? No: keep real TTLs (60s/300s)
	// so TTL expiry NEVER fires during the test — ONLY sweep wakeups can
	// repair drift inside the test timeout!
	var emitDrift atomic.Bool
	var policyPassCount, vnetPassCount atomic.Int64
	var blockedListMu sync.Mutex
	var blockedListTriggered atomic.Bool

	targets := []sweep.TargetDescriptor{
		{
			Kind:         "ZeroTrustList",
			Grade:        freshness.GradeAuthz,
			InitialDelay: 10 * time.Millisecond,
			SweepFunc: func(_ context.Context, _ *sweep.AccountSweeper) ([]sweep.DriftItem, error) {
				if !emitDrift.Load() {
					return []sweep.DriftItem{}, nil
				}
				blockedListTriggered.Store(true)
				blockedListMu.Lock()
				defer blockedListMu.Unlock()
				// Overflow a small EventBufferSize=3 channel for ZeroTrustList.
				items := make([]sweep.DriftItem, 0, 8)
				for i := range 8 {
					items = append(items, sweep.DriftItem{
						Kind:           "ZeroTrustList",
						TargetKind:     "ZeroTrustList",
						NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: fmt.Sprintf("ztl-%d", i)},
						RemoteID:       fmt.Sprintf("list-%d", i),
						Case:           sweep.DriftCaseMismatch,
						Reason:         "overflow slow subscriber",
					})
				}
				return items, nil
			},
		},
		{
			Kind:         "AccessPolicy",
			Grade:        freshness.GradeAuthz,
			InitialDelay: 30 * time.Millisecond,
			SweepFunc: func(_ context.Context, _ *sweep.AccountSweeper) ([]sweep.DriftItem, error) {
				if !emitDrift.Load() {
					return []sweep.DriftItem{}, nil
				}
				if policyPassCount.Add(1) > 1 {
					return []sweep.DriftItem{}, nil
				}
				items := make([]sweep.DriftItem, 0, 3)
				for i := range 3 {
					items = append(items, sweep.DriftItem{
						Kind:           "AccessPolicy",
						TargetKind:     "AccessPolicy",
						NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: fmt.Sprintf("pol-%d", i)},
						RemoteID:       fmt.Sprintf("policy-%d", i+1),
						Case:           sweep.DriftCaseMismatch,
						Reason:         "out-of-band policy drift",
					})
				}
				return items, nil
			},
		},
		{
			Kind:         "VirtualNetwork",
			Grade:        freshness.GradeAuthz,
			InitialDelay: 30 * time.Millisecond,
			SweepFunc: func(_ context.Context, _ *sweep.AccountSweeper) ([]sweep.DriftItem, error) {
				if !emitDrift.Load() {
					return []sweep.DriftItem{}, nil
				}
				if vnetPassCount.Add(1) > 1 {
					return []sweep.DriftItem{}, nil
				}
				items := make([]sweep.DriftItem, 0, 3)
				for i := range 3 {
					items = append(items, sweep.DriftItem{
						Kind:           "VirtualNetwork",
						TargetKind:     "VirtualNetwork",
						NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: fmt.Sprintf("vnet-%d", i)},
						RemoteID:       fmt.Sprintf("vnet-%d", i+1),
						Case:           sweep.DriftCaseMismatch,
						Reason:         "out-of-band vnet drift",
					})
				}
				return items, nil
			},
		},
	}

	sweeper := sweep.NewSweeper(sweep.SweeperOptions{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		CloudflareFactory:   noopClientFactory{},
		Invalidator:         latch,
		Policy:              freshness.Policy{Authz: 50 * time.Millisecond, Traffic: 50 * time.Millisecond, Indirect: 50 * time.Millisecond},
		Logger:              logr.Discard(),
		EventBufferSize:     3,
		AccountSyncInterval: 20 * time.Millisecond,
		Targets:             targets,
	})
	if err := mgr.Add(sweeper); err != nil {
		t.Fatalf("add sweeper: %v", err)
	}

	accessFake := newFakeAccessResourceCloudflare()
	vnetFake := newFakePrivateNetworkCloudflare()

	// Subscribe ALL 18 production sweep target kinds matching cmd/main.go:
	// - ZeroTrustList: un-drained slow channel (buffer=3, 8 items sent)
	// - AccessPolicy & VirtualNetwork: real production reconcilers repairing drift
	// - Remaining 15 production target kinds: subscribers asserting 0 foreign/cross-kind delivery
	_ = sweeper.EventsFor("ZeroTrustList")
	if err := (&AccessPolicyReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: accessFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
		SweepEvents:         sweeper.EventsFor("AccessPolicy"),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup AccessPolicyReconciler: %v", err)
	}
	if err := (&VirtualNetworkReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: vnetFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
		SweepEvents:         sweeper.EventsFor("VirtualNetwork"),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup VirtualNetworkReconciler: %v", err)
	}
	// Register consumers for every other production sweep target kind (matching cmd/main.go);
	// none of these may receive AccessPolicy or VirtualNetwork events or steal them.
	var foreignHits atomic.Int64
	otherProductionKinds := []string{
		"AccessApplication",
		"AccessStandaloneApplication",
		"AccessInfrastructureTarget",
		"AccessCustomPage",
		"AccessGroup",
		"IdentityProvider",
		"DevicePostureRule",
		"DevicePostureIntegration",
		"ServiceToken",
		"NetworkRoute",
		"HostnameRoute",
		"WARPConnector",
		"DeviceProfile",
		"ZeroTrustGatewayPolicy",
		"CloudflareTunnel",
	}
	for _, kind := range otherProductionKinds {
		k := kind
		if err := ctrl.NewControllerManagedBy(mgr).
			Named("prod-sub-" + k).
			WatchesRawSource(source.Channel(sweeper.EventsFor(k), handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				foreignHits.Add(1)
				return nil
			}))).
			Complete(reconcile.Func(func(_ context.Context, _ reconcile.Request) (ctrl.Result, error) {
				return ctrl.Result{}, nil
			})); err != nil {
			t.Fatalf("setup subscriber %s: %v", k, err)
		}
	}

	startManagerAndWait(t, mgr)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-fanout", Labels: map[string]string{"tenant": "true"}}}
	if err := direct.Create(ctx, ns); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-fanout", Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}
	if err := direct.Create(ctx, secret); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "fanout-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant-fanout", Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	for i := range 3 {
		pol := &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-fanout", Name: fmt.Sprintf("pol-%d", i)},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef:       corev1.LocalObjectReference{Name: account.Name},
				Name:             fmt.Sprintf("pol-%d", i),
				Decision:         v1alpha1.AccessPolicyDecisionAllow,
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		if err := direct.Create(ctx, pol); err != nil {
			t.Fatalf("create pol-%d: %v", i, err)
		}
		vnet := &v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-fanout", Name: fmt.Sprintf("vnet-%d", i)},
			Spec: v1alpha1.VirtualNetworkSpec{
				AccountRef:       corev1.LocalObjectReference{Name: account.Name},
				Name:             fmt.Sprintf("vnet-%d", i),
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		if err := direct.Create(ctx, vnet); err != nil {
			t.Fatalf("create vnet-%d: %v", i, err)
		}
	}

	// Wait for all 6 resources to converge and open their gates.
	waitUntilTrue(t, 15*time.Second, "initial convergence", func() (bool, error) {
		for i := range 3 {
			var p v1alpha1.AccessPolicy
			if err := direct.Get(ctx, types.NamespacedName{Namespace: "tenant-fanout", Name: fmt.Sprintf("pol-%d", i)}, &p); err != nil {
				return false, err
			}
			if !assertConditionTrueForCurrentGen(p.Status.Conditions, "Ready", p.Generation) || p.Status.AppliedHash == "" {
				return false, nil
			}
			var v v1alpha1.VirtualNetwork
			if err := direct.Get(ctx, types.NamespacedName{Namespace: "tenant-fanout", Name: fmt.Sprintf("vnet-%d", i)}, &v); err != nil {
				return false, err
			}
			if !assertConditionTrueForCurrentGen(v.Status.Conditions, v1alpha1.PrivateNetworkConditionReady, v.Generation) || v.Status.AppliedHash == "" {
				return false, nil
			}
		}
		return true, nil
	})

	// Mutate remote state out-of-band so repair requires the controller to wake up
	// and overwrite it back to the desired spec name/decision.
	accessFake.mu.Lock()
	for id, p := range accessFake.policies {
		p.Name = "drifted-out-of-band"
		accessFake.policies[id] = p
	}
	accessFake.mu.Unlock()

	vnetFake.mu.Lock()
	for id, v := range vnetFake.virtualNetworks {
		v.Name = "drifted-out-of-band"
		vnetFake.virtualNetworks[id] = v
	}
	vnetFake.mu.Unlock()

	// Enable sweep drift emission (well before 60s/300s TTLs!).
	emitDrift.Store(true)

	// Every single AccessPolicy and VirtualNetwork MUST be woken up and repaired
	// within 10s (far less than 60s/300s TTL), despite ZeroTrustList overflowing
	// and competing consumers running.
	waitUntilTrue(t, 10*time.Second, "all drifted AccessPolicies and VirtualNetworks repaired via fanout", func() (bool, error) {
		if !blockedListTriggered.Load() {
			return false, nil
		}
		accessFake.mu.Lock()
		for _, p := range accessFake.policies {
			if p.Name == "drifted-out-of-band" {
				accessFake.mu.Unlock()
				return false, nil
			}
		}
		accessFake.mu.Unlock()

		vnetFake.mu.Lock()
		for _, v := range vnetFake.virtualNetworks {
			if v.Name == "drifted-out-of-band" {
				vnetFake.mu.Unlock()
				return false, nil
			}
		}
		vnetFake.mu.Unlock()
		return true, nil
	})
	// Allow one tick to confirm zero cross-kind delivery onto the 15 unaddressed subscriptions.
	time.Sleep(100 * time.Millisecond)
	if got := foreignHits.Load(); got != 0 {
		t.Fatalf("foreign/cross-kind subscriptions received %d unexpected events, want 0", got)
	}
}

type recordingGatewayProber struct {
	version int64
	ready   bool
	probes  atomic.Int64
}

func (p *recordingGatewayProber) Ready(context.Context, string) error {
	p.probes.Add(1)
	if !p.ready {
		return fmt.Errorf("not ready")
	}
	return nil
}

func (p *recordingGatewayProber) ConfigVersion(context.Context, string) (int64, error) {
	return p.version, nil
}

// QA-2A-2: GatewayReconciler receives *unstructured.Unstructured CloudflareTunnel
// sweep events via mapTunnelToGateways and wakes up the owning Gateway.
func TestQA2A2GatewayReceivesUnstructuredTunnelSweepEventEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	snapshots := newFakeSnapshotPublisher()
	tunnelFake := newFakeTunnelCloudflareFactory()
	gwFactory := gatewayCloudflareFactory{api: &tunnelFreshnessGatewayAPI{accountID: "0123456789abcdef0123456789abcdef", remoteVersion: 1}}

	var emitTunnelDrift atomic.Bool
	var tunnelSweepCount atomic.Int64

	sweeper := sweep.NewSweeper(sweep.SweeperOptions{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		CloudflareFactory:   noopClientFactory{},
		Invalidator:         latch,
		Policy:              freshness.Policy{Authz: 50 * time.Millisecond, Traffic: 50 * time.Millisecond, Indirect: 50 * time.Millisecond},
		Logger:              logr.Discard(),
		AccountSyncInterval: 20 * time.Millisecond,
		Targets: []sweep.TargetDescriptor{
			{
				Kind:         "CloudflareTunnel",
				Grade:        freshness.GradeTraffic,
				InitialDelay: 20 * time.Millisecond,
				SweepFunc: func(_ context.Context, _ *sweep.AccountSweeper) ([]sweep.DriftItem, error) {
					if !emitTunnelDrift.Load() {
						return []sweep.DriftItem{}, nil
					}
					if tunnelSweepCount.Add(1) > 1 {
						return []sweep.DriftItem{}, nil
					}
					return []sweep.DriftItem{{
						Kind:           "CloudflareTunnel",
						TargetKind:     "CloudflareTunnel",
						NamespacedName: types.NamespacedName{Namespace: "gw-fanout", Name: "edge"},
						RemoteID:       "remote-tunnel",
						Case:           sweep.DriftCaseMismatch,
						Reason:         "tunnel drift",
					}}, nil
				},
			},
		},
	})
	if err := mgr.Add(sweeper); err != nil {
		t.Fatalf("add sweeper: %v", err)
	}

	if err := (&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayClassReconciler: %v", err)
	}

	prober := &recordingGatewayProber{version: 2, ready: true}
	gwReconciler := &GatewayReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            mgr.GetScheme(),
		Snapshots:         snapshots,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gwFactory,
		Prober:            prober,
		Freshness:         policy,
		Invalidator:       latch,
		SweepEvents:       sweeper.EventsFor("CloudflareTunnel"),
	}
	if err := gwReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayReconciler: %v", err)
	}
	if err := (&CloudflareTunnelReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
		SweepEvents:         sweeper.EventsFor("CloudflareTunnel"),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup CloudflareTunnelReconciler: %v", err)
	}

	startManagerAndWait(t, mgr)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "gw-fanout", Labels: map[string]string{"tenant": "true"}}}
	if err := direct.Create(ctx, ns); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-fanout", Name: "cf-token"},
		Data:       map[string][]byte{"token": []byte("tok")},
	}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-fanout-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "gw-fanout", Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-fanout-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: account.Name},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create GatewayClassConfig: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-fanout-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef: &gatewayv1.ParametersReference{
				Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name,
			},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create GatewayClass: %v", err)
	}
	hostname := gatewayv1.Hostname("edge.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-fanout", Name: "edge"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway: %v", err)
	}
	// Mark active dataplane Pod ready and xDS ACKed so Gateway reaches Programmed=True.
	waitUntilTrue(t, 10*time.Second, "Gateway dataplane Deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace("gw-fanout")); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	// Check mapTunnelToGateways directly on *unstructured.Unstructured AND via live sweep channel.
	unstructuredTunnel := &unstructured.Unstructured{}
	unstructuredTunnel.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("CloudflareTunnel"))
	unstructuredTunnel.SetNamespace("gw-fanout")
	unstructuredTunnel.SetName("edge")
	reqs := gwReconciler.mapTunnelToGateways(ctx, unstructuredTunnel)
	if len(reqs) != 1 || reqs[0].NamespacedName != client.ObjectKeyFromObject(gw) {
		t.Fatalf("mapTunnelToGateways(*unstructured.Unstructured) = %v, want [%v]", reqs, client.ObjectKeyFromObject(gw))
	}

	// Also prove end-to-end: with CloudflareTunnelReconciler + GatewayReconciler both
	// subscribed to the sweeper, emitting a CloudflareTunnel *unstructured.Unstructured
	// drift item wakes up GatewayReconciler (proven by a fresh Prober call after
	// steady state settled, without any Kubernetes object change) and CloudflareTunnel.
	var tunnelObj v1alpha1.CloudflareTunnel
	waitUntilTrue(t, 10*time.Second, "CloudflareTunnel created", func() (bool, error) {
		err := direct.Get(ctx, types.NamespacedName{Namespace: "gw-fanout", Name: "edge"}, &tunnelObj)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil && tunnelObj.Status.TunnelID != "", err
	})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "gw-fanout",
			Name:      "dataplane-0",
			UID:       types.UID("pod-uid-fanout"),
			Labels:    map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, pod); err != nil {
		t.Fatalf("create dataplane pod: %v", err)
	}
	pod.Status.PodIP = "10.0.0.2"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway snapshot published", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	waitUntilTrue(t, 10*time.Second, "Gateway Programmed=True", func() (bool, error) {
		var cur gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &cur); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), cur.Generation), nil
	})
	// Wait briefly for in-flight status reconciles to settle, then snapshot probes
	// and tunnel ResourceVersion (so we prove the subsequent Gateway wakeup
	// originates from the raw SweepEvents channel, not from a tunnel status write).
	time.Sleep(300 * time.Millisecond)
	if err := direct.Get(ctx, client.ObjectKeyFromObject(&tunnelObj), &tunnelObj); err != nil {
		t.Fatalf("refresh tunnel before sweep: %v", err)
	}
	tunnelRVBefore := tunnelObj.ResourceVersion
	probesBefore := prober.probes.Load()

	emitTunnelDrift.Store(true)
	waitUntilTrue(t, 10*time.Second, "tunnel sweep pass ran", func() (bool, error) {
		return tunnelSweepCount.Load() >= 1, nil
	})
	waitUntilTrue(t, 10*time.Second, "GatewayReconciler woken by unstructured tunnel sweep event", func() (bool, error) {
		return prober.probes.Load() > probesBefore, nil
	})
	waitUntilTrue(t, 10*time.Second, "CloudflareTunnel cleared invalidation after sweep wakeup", func() (bool, error) {
		return !latch.IsInvalidated("CloudflareTunnel", client.ObjectKeyFromObject(&tunnelObj)), nil
	})
	var tunnelAfter v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, client.ObjectKeyFromObject(&tunnelObj), &tunnelAfter); err != nil {
		t.Fatalf("get tunnel after sweep wakeup: %v", err)
	}
	if tunnelAfter.ResourceVersion != tunnelRVBefore {
		t.Fatalf("CloudflareTunnel mutated status during sweep wakeup (RV %s -> %s), conflating status watch with SweepEvents delivery", tunnelRVBefore, tunnelAfter.ResourceVersion)
	}
}
