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
	"strings"
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
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
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

type subWatchReader struct {
	client.Reader
	expected    types.NamespacedName
	matchesType func(client.Object) bool
	hits        *atomic.Int64
	foreignHits *atomic.Int64
}

func (r *subWatchReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if r.matchesType(obj) {
		if key == r.expected {
			r.hits.Add(1)
		} else if strings.HasPrefix(key.Name, "probe-") {
			r.foreignHits.Add(1)
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type subWatchClient struct {
	client.Client
	reader *subWatchReader
}

func (c *subWatchClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

// QA-2A-1: Per-kind sweep fan-out delivers drift invalidations independently to
// all 19 production subscriptions across 18 event kinds using real SetupWithManager
// registrations, without slow-subscriber blocking or cross-kind leakage.
func TestQA2A1PerKindSweepFanoutEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	// Short TTLs only for sweep target pacing? No: keep real TTLs (60s/300s)
	// so TTL expiry NEVER fires during the test — ONLY sweep wakeups can
	// repair drift inside the test timeout!
	var emitDrift atomic.Bool
	var emitAllKinds atomic.Bool
	var policyPassCount, vnetPassCount atomic.Int64
	var listProbeOnce, policyProbeOnce, vnetProbeOnce atomic.Int64
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
				if emitAllKinds.Load() {
					if listProbeOnce.Add(1) == 1 {
						return []sweep.DriftItem{{
							Kind:           "ZeroTrustList",
							TargetKind:     "ZeroTrustList",
							NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: "probe-ZeroTrustList"},
							RemoteID:       "remote-ZeroTrustList",
							Case:           sweep.DriftCaseMismatch,
							Reason:         "per-kind positive fanout probe",
						}}, nil
					}
					return []sweep.DriftItem{}, nil
				}
				// Overflow a small EventBufferSize=3 channel for the undrained slow ZeroTrustList consumer in Phase 1.
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
				if policyPassCount.Add(1) == 1 {
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
				}
				if emitAllKinds.Load() && policyProbeOnce.Add(1) == 1 {
					return []sweep.DriftItem{{
						Kind:           "AccessPolicy",
						TargetKind:     "AccessPolicy",
						NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: "probe-AccessPolicy"},
						RemoteID:       "remote-AccessPolicy",
						Case:           sweep.DriftCaseMismatch,
						Reason:         "per-kind positive fanout probe",
					}}, nil
				}
				return []sweep.DriftItem{}, nil
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
				if vnetPassCount.Add(1) == 1 {
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
				}
				if emitAllKinds.Load() && vnetProbeOnce.Add(1) == 1 {
					return []sweep.DriftItem{{
						Kind:           "VirtualNetwork",
						TargetKind:     "VirtualNetwork",
						NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: "probe-VirtualNetwork"},
						RemoteID:       "remote-VirtualNetwork",
						Case:           sweep.DriftCaseMismatch,
						Reason:         "per-kind positive fanout probe",
					}}, nil
				}
				return []sweep.DriftItem{}, nil
			},
		},
	}

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
	subHits := map[string]*atomic.Int64{
		"AccessPolicy":             new(atomic.Int64),
		"VirtualNetwork":           new(atomic.Int64),
		"ZeroTrustList":            new(atomic.Int64),
		"Gateway-CloudflareTunnel": new(atomic.Int64),
	}
	for _, kind := range otherProductionKinds {
		k := kind
		subHits[k] = new(atomic.Int64)
		var kindOnce atomic.Int64
		targets = append(targets, sweep.TargetDescriptor{
			Kind:         k,
			Grade:        freshness.GradeAuthz,
			InitialDelay: 10 * time.Millisecond,
			SweepFunc: func(_ context.Context, _ *sweep.AccountSweeper) ([]sweep.DriftItem, error) {
				if !emitAllKinds.Load() || kindOnce.Add(1) > 1 {
					return []sweep.DriftItem{}, nil
				}
				return []sweep.DriftItem{{
					Kind:           k,
					TargetKind:     k,
					NamespacedName: types.NamespacedName{Namespace: "tenant-fanout", Name: "probe-" + k},
					RemoteID:       "remote-" + k,
					Case:           sweep.DriftCaseMismatch,
					Reason:         "per-kind positive fanout probe",
				}}, nil
			},
		})
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
	standaloneFake := &fakeStandaloneCloudflare{applications: map[string]flarecloudflare.AccessApplication{}, tags: map[string]flarecloudflare.AccessTag{}}
	infraFake := &fakeInfrastructureTargetCloudflare{targets: map[string]flarecloudflare.AccessInfrastructureTarget{}}
	idpFake := &scimIdentityProviderFakeAPI{identityProviderFakeAPI: &identityProviderFakeAPI{providers: map[string]flarecloudflare.IdentityProvider{}}}
	appFake := newFakeAccessApplicationCloudflare()
	customPageFake := newFakeCustomPageCloudflare()
	integrationFake := &fakeDevicePostureIntegrationCloudflare{integrations: map[string]flarecloudflare.DevicePostureIntegration{}}
	warpFake := newFakeWARPConnectorCloudflare()
	profileFake := newFakeDeviceProfileCloudflare()
	gatewayFake := newFakeGlobalGatewayCloudflare()
	tunnelFake := newFakeTunnelCloudflareFactory()
	gwAPI := &tunnelFreshnessGatewayAPI{accountID: "0123456789abcdef0123456789abcdef", remoteVersion: 1}
	snapshots := newFakeSnapshotPublisher()

	var foreignHits atomic.Int64
	wrapClient := func(subName string, expected types.NamespacedName, matches func(client.Object) bool) (*subWatchClient, *subWatchReader) {
		reader := &subWatchReader{
			Reader:      mgr.GetAPIReader(),
			expected:    expected,
			matchesType: matches,
			hits:        subHits[subName],
			foreignHits: &foreignHits,
		}
		return &subWatchClient{
			Client: mgr.GetClient(),
			reader: &subWatchReader{
				Reader:      mgr.GetClient(),
				expected:    expected,
				matchesType: matches,
				hits:        subHits[subName],
				foreignHits: &foreignHits,
			},
		}, reader
	}
	probeKey := func(kind string) types.NamespacedName {
		return types.NamespacedName{Namespace: "tenant-fanout", Name: "probe-" + kind}
	}

	// Separate undrained slow subscriber overflowing buffer=3 on ZeroTrustList.
	_ = sweeper.EventsFor("ZeroTrustList")

	// Register ALL 19 real production reconcilers matching cmd/main.go:357-595.
	polClient, _ := wrapClient("AccessPolicy", probeKey("AccessPolicy"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessPolicy); return ok })
	vnetClient, _ := wrapClient("VirtualNetwork", probeKey("VirtualNetwork"), func(o client.Object) bool { _, ok := o.(*v1alpha1.VirtualNetwork); return ok })
	tunnelClient, _ := wrapClient("CloudflareTunnel", probeKey("CloudflareTunnel"), func(o client.Object) bool { _, ok := o.(*v1alpha1.CloudflareTunnel); return ok })
	gwSubClient, _ := wrapClient("Gateway-CloudflareTunnel", types.NamespacedName{Namespace: "tenant-fanout", Name: "gw-target-for-tunnel"}, func(o client.Object) bool { _, ok := o.(*gatewayv1.Gateway); return ok })
	nrClient, _ := wrapClient("NetworkRoute", probeKey("NetworkRoute"), func(o client.Object) bool { _, ok := o.(*v1alpha1.NetworkRoute); return ok })
	hrClient, _ := wrapClient("HostnameRoute", probeKey("HostnameRoute"), func(o client.Object) bool { _, ok := o.(*v1alpha1.HostnameRoute); return ok })
	wcClient, _ := wrapClient("WARPConnector", probeKey("WARPConnector"), func(o client.Object) bool { _, ok := o.(*v1alpha1.WARPConnector); return ok })
	grpClient, grpReader := wrapClient("AccessGroup", probeKey("AccessGroup"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessGroup); return ok })
	idpClient, _ := wrapClient("IdentityProvider", probeKey("IdentityProvider"), func(o client.Object) bool { _, ok := o.(*v1alpha1.IdentityProvider); return ok })
	dprClient, _ := wrapClient("DevicePostureRule", probeKey("DevicePostureRule"), func(o client.Object) bool { _, ok := o.(*v1alpha1.DevicePostureRule); return ok })
	dpiClient, _ := wrapClient("DevicePostureIntegration", probeKey("DevicePostureIntegration"), func(o client.Object) bool { _, ok := o.(*v1alpha1.DevicePostureIntegration); return ok })
	stClient, _ := wrapClient("ServiceToken", probeKey("ServiceToken"), func(o client.Object) bool { _, ok := o.(*v1alpha1.ServiceToken); return ok })
	appClient, _ := wrapClient("AccessApplication", probeKey("AccessApplication"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessApplication); return ok })
	saClient, _ := wrapClient("AccessStandaloneApplication", probeKey("AccessStandaloneApplication"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessStandaloneApplication); return ok })
	infraClient, infraReader := wrapClient("AccessInfrastructureTarget", probeKey("AccessInfrastructureTarget"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessInfrastructureTarget); return ok })
	cpClient, _ := wrapClient("AccessCustomPage", probeKey("AccessCustomPage"), func(o client.Object) bool { _, ok := o.(*v1alpha1.AccessCustomPage); return ok })
	dpClient, _ := wrapClient("DeviceProfile", probeKey("DeviceProfile"), func(o client.Object) bool { _, ok := o.(*v1alpha1.DeviceProfile); return ok })
	ztlClient, _ := wrapClient("ZeroTrustList", probeKey("ZeroTrustList"), func(o client.Object) bool { _, ok := o.(*v1alpha1.ZeroTrustList); return ok })
	gwPolClient, _ := wrapClient("ZeroTrustGatewayPolicy", probeKey("ZeroTrustGatewayPolicy"), func(o client.Object) bool { _, ok := o.(*v1alpha1.ZeroTrustGatewayPolicy); return ok })

	for _, err := range []error{
		(&AccessPolicyReconciler{Client: polClient, Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessPolicy")}).SetupWithManager(mgr),
		(&VirtualNetworkReconciler{Client: vnetClient, Scheme: mgr.GetScheme(), NewCloudflareClient: vnetFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("VirtualNetwork")}).SetupWithManager(mgr),
		(&CloudflareTunnelReconciler{Client: tunnelClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: tunnelFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("CloudflareTunnel")}).SetupWithManager(mgr),
		(&GatewayReconciler{Client: gwSubClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Snapshots: snapshots, OperatorNamespace: dataplane.DefaultOperatorNamespace, CloudflareFactory: gatewayCloudflareFactory{api: gwAPI}, Prober: &staticGatewayProber{version: 1, ready: true}, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("CloudflareTunnel")}).SetupWithManager(mgr),
		(&NetworkRouteReconciler{Client: nrClient, Scheme: mgr.GetScheme(), NewCloudflareClient: vnetFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("NetworkRoute")}).SetupWithManager(mgr),
		(&HostnameRouteReconciler{Client: hrClient, Scheme: mgr.GetScheme(), OperatorNamespace: dataplane.DefaultOperatorNamespace, NewCloudflareClient: vnetFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("HostnameRoute")}).SetupWithManager(mgr),
		(&WARPConnectorReconciler{Client: wcClient, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.WARPConnectorAPI, error) { return warpFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("WARPConnector")}).SetupWithManager(mgr),
		(&AccessGroupReconciler{Client: grpClient, APIReader: grpReader, Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessGroup")}).SetupWithManager(mgr),
		(&IdentityProviderReconciler{Client: idpClient, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return idpFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("IdentityProvider")}).SetupWithManager(mgr),
		(&DevicePostureRuleReconciler{Client: dprClient, Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("DevicePostureRule")}).SetupWithManager(mgr),
		(&DevicePostureIntegrationReconciler{Client: dpiClient, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return integrationFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("DevicePostureIntegration")}).SetupWithManager(mgr),
		(&ServiceTokenReconciler{Client: stClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("ServiceToken")}).SetupWithManager(mgr),
		(&AccessApplicationReconciler{Client: appClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), OperatorNamespace: dataplane.DefaultOperatorNamespace, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessApplication")}).SetupWithManager(mgr),
		(&AccessStandaloneApplicationReconciler{Client: saClient, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return standaloneFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessStandaloneApplication")}).SetupWithManager(mgr),
		(&AccessInfrastructureTargetReconciler{Client: infraClient, APIReader: infraReader, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return infraFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessInfrastructureTarget")}).SetupWithManager(mgr),
		(&AccessCustomPageReconciler{Client: cpClient, Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return customPageFake, nil }, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("AccessCustomPage")}).SetupWithManager(mgr),
		(&DeviceProfileReconciler{Client: dpClient, Scheme: mgr.GetScheme(), NewCloudflareClient: profileFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("DeviceProfile")}).SetupWithManager(mgr),
		(&ZeroTrustListReconciler{Client: ztlClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: gatewayFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("ZeroTrustList")}).SetupWithManager(mgr),
		(&ZeroTrustGatewayPolicyReconciler{Client: gwPolClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: gatewayFake.Client, Freshness: policy, Invalidator: latch, SweepEvents: sweeper.EventsFor("ZeroTrustGatewayPolicy")}).SetupWithManager(mgr),
	} {
		if err != nil {
			t.Fatalf("setup production reconciler: %v", err)
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
	// Phase 1 check: allow one tick to confirm zero cross-kind delivery onto any subscription.
	time.Sleep(100 * time.Millisecond)
	if got := foreignHits.Load(); got != 0 {
		t.Fatalf("foreign/cross-kind subscriptions received %d unexpected events, want 0", got)
	}

	// Create Gateway referencing probe-CloudflareTunnel so GatewayReconciler maps
	// CloudflareTunnel sweep events via its real SetupWithManager watch & mapTunnelToGateways.
	gwTargetHost := gatewayv1.Hostname("fanout-gw.example.com")
	gwTarget := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-fanout", Name: "gw-target-for-tunnel"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "nonexistent-fanout-class",
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwTargetHost}},
			Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "probe-CloudflareTunnel"}},
		},
	}
	if err := direct.Create(ctx, gwTarget); err != nil {
		t.Fatalf("create gw-target-for-tunnel: %v", err)
	}
	waitUntilTrue(t, 5*time.Second, "Gateway initial create reconcile observed", func() (bool, error) {
		return subHits["Gateway-CloudflareTunnel"].Load() >= 1, nil
	})
	time.Sleep(100 * time.Millisecond)
	subHits["Gateway-CloudflareTunnel"].Store(0)

	// Phase 2: trigger 1 targeted drift event per production target kind and verify
	// positive Reconcile execution across ALL 19 real production subscriptions with zero cross-kind hits.
	emitAllKinds.Store(true)
	var missing []string
	defer func() {
		if t.Failed() && len(missing) > 0 {
			t.Logf("subscriptions with 0 hits: %v", missing)
		}
	}()
	waitUntilTrue(t, 10*time.Second, "all 19 production sweep subscriptions execute Reconcile for their addressed event", func() (bool, error) {
		missing = missing[:0]
		for name, c := range subHits {
			if c.Load() < 1 {
				missing = append(missing, name)
			}
		}
		return len(missing) == 0, nil
	})
	if got := foreignHits.Load(); got != 0 {
		t.Fatalf("Phase 2 cross-kind subscriptions received %d unexpected events, want 0", got)
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
