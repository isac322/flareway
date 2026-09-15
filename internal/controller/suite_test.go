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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

var (
	testClient                       client.Client
	testAPIReader                    client.Reader
	testContext                      context.Context
	testCancel                       context.CancelFunc
	testEnv                          *envtest.Environment
	testSnapshots                    *fakeSnapshotPublisher
	testTunnelCloudflare             *fakeTunnelCloudflareFactory
	testAccessCloudflare             *fakeAccessApplicationCloudflare
	testResourceAccessCloudflare     *fakeAccessResourceCloudflare
	testPrivateNetworkCloudflare     *fakePrivateNetworkCloudflare
	testGlobalDeviceCloudflare       *fakeGlobalDeviceCloudflare
	testGlobalOrganizationCloudflare *fakeGlobalOrganizationCloudflare
	testGlobalGatewayCloudflare      *fakeGlobalGatewayCloudflare

	testSnapshotBuildFailures sync.Map
)

func TestControllers(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Controller Envtest Suite")
}

var _ = ginkgo.BeforeSuite(func() {
	gatewayAPIDir := gatewayAPIModuleDirectory()
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join(gatewayAPIDir, "config", "crd", "standard"),
		},
		ErrorIfCRDPathMissing: true,
	}

	config, err := testEnv.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(config).NotTo(gomega.BeNil())

	scheme := runtime.NewScheme()
	gomega.Expect(clientgoscheme.AddToScheme(scheme)).To(gomega.Succeed())
	gomega.Expect(gatewayv1.Install(scheme)).To(gomega.Succeed())
	gomega.Expect(v1alpha1.AddToScheme(scheme)).To(gomega.Succeed())

	manager, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	testSnapshots = newFakeSnapshotPublisher()
	gomega.Expect((&GatewayClassReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme()}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&CloudflareAccountReconciler{
		Client:     manager.GetClient(),
		Scheme:     manager.GetScheme(),
		Cloudflare: testAccountCloudflare,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&GatewayReconciler{
		Client:            manager.GetClient(),
		Scheme:            manager.GetScheme(),
		Snapshots:         testSnapshots,
		BuildSnapshot:     controlledSnapshotBuild,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testTunnelCloudflare = newFakeTunnelCloudflareFactory()
	gomega.Expect((&CloudflareTunnelReconciler{
		Client:              manager.GetClient(),
		APIReader:           manager.GetAPIReader(),
		Scheme:              manager.GetScheme(),
		NewCloudflareClient: testTunnelCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testAccessCloudflare = newFakeAccessApplicationCloudflare()
	gomega.Expect((&AccessApplicationReconciler{
		Client:              manager.GetClient(),
		APIReader:           manager.GetAPIReader(),
		Scheme:              manager.GetScheme(),
		NewCloudflareClient: testAccessCloudflare.Client,
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testResourceAccessCloudflare = newFakeAccessResourceCloudflare()
	accessClient := testResourceAccessCloudflare.Client
	gomega.Expect((&AccessPolicyReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: accessClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&AccessGroupReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: accessClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&IdentityProviderReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: accessClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&DevicePostureRuleReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: accessClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&ServiceTokenReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: accessClient}).SetupWithManager(manager)).To(gomega.Succeed())
	testPrivateNetworkCloudflare = newFakePrivateNetworkCloudflare()
	privateNetworkClient := testPrivateNetworkCloudflare.Client
	gomega.Expect((&VirtualNetworkReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: privateNetworkClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&NetworkRouteReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: privateNetworkClient}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&HostnameRouteReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(), NewCloudflareClient: privateNetworkClient,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&DeviceProfileReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
		NewCloudflareClient: testDeviceProfileCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testGlobalDeviceCloudflare = new(fakeGlobalDeviceCloudflare)
	gomega.Expect((&DeviceSettingsReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
		APIReader:           manager.GetAPIReader(),
		NewCloudflareClient: testGlobalDeviceCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testGlobalOrganizationCloudflare = new(fakeGlobalOrganizationCloudflare)
	gomega.Expect((&ZeroTrustOrganizationReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
		APIReader:           manager.GetAPIReader(),
		NewCloudflareClient: testGlobalOrganizationCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	testGlobalGatewayCloudflare = newFakeGlobalGatewayCloudflare()
	gomega.Expect((&ZeroTrustListReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
		APIReader:           manager.GetAPIReader(),
		NewCloudflareClient: testGlobalGatewayCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())
	gomega.Expect((&ZeroTrustGatewayPolicyReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
		APIReader:           manager.GetAPIReader(),
		NewCloudflareClient: testGlobalGatewayCloudflare.Client,
	}).SetupWithManager(manager)).To(gomega.Succeed())

	testContext, testCancel = context.WithCancel(context.Background())
	go func() {
		defer ginkgo.GinkgoRecover()
		gomega.Expect(manager.Start(testContext)).To(gomega.Succeed())
	}()
	gomega.Expect(manager.GetCache().WaitForCacheSync(testContext)).To(gomega.BeTrue())
	testClient = manager.GetClient()
	testAPIReader = manager.GetAPIReader()
})

var _ = ginkgo.AfterSuite(func() {
	if testCancel != nil {
		testCancel()
	}
	if testEnv != nil {
		gomega.Expect(testEnv.Stop()).To(gomega.Succeed())
	}
})

func controlledSnapshotBuild(gateway *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) (*cachev3.Snapshot, error) {
	if failure, ok := testSnapshotBuildFailures.Load(gateway.Key.String()); ok {
		return nil, failure.(error)
	}
	return translator.Build(gateway, cfg)
}

func gatewayAPIModuleDirectory() string {
	command := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api")
	output, err := command.Output()
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	directory := strings.TrimSpace(string(output))
	gomega.ExpectWithOffset(1, directory).NotTo(gomega.BeEmpty())
	return directory
}

type fakeSnapshotPublisher struct {
	mu        sync.RWMutex
	snapshots map[string]*cachev3.Snapshot
	versions  map[string]string
	acked     map[string]string
	nacks     map[string]snapshotNACK
}

func newFakeSnapshotPublisher() *fakeSnapshotPublisher {
	return &fakeSnapshotPublisher{
		snapshots: make(map[string]*cachev3.Snapshot),
		versions:  make(map[string]string),
		acked:     make(map[string]string),
		nacks:     make(map[string]snapshotNACK),
	}
}

func (p *fakeSnapshotPublisher) ClearSnapshot(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.snapshots, key)
	delete(p.versions, key)
	delete(p.acked, key)
	delete(p.nacks, key)
}

func (p *fakeSnapshotPublisher) SetSnapshot(_ context.Context, key string, snapshot *cachev3.Snapshot) error {
	version, err := translator.SnapshotVersion(snapshot)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.versions[key] != version {
		delete(p.nacks, key)
	}
	p.snapshots[key] = snapshot
	p.versions[key] = version
	return nil
}

func (p *fakeSnapshotPublisher) IsACKed(key, version string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.acked[key] == version
}

func (p *fakeSnapshotPublisher) LastNACK(key string) (string, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	nack, ok := p.nacks[key]
	return nack.version, nack.detail, ok
}

type snapshotNACK struct {
	version string
	detail  string
}

func (p *fakeSnapshotPublisher) NACK(key, detail string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	version := p.versions[key]
	if version == "" {
		return fmt.Errorf("no snapshot has been published for %s", key)
	}
	delete(p.acked, key)
	p.nacks[key] = snapshotNACK{version: version, detail: detail}
	return nil
}

func (p *fakeSnapshotPublisher) ACK(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	version := p.versions[key]
	if version == "" {
		return fmt.Errorf("no snapshot has been published for %s", key)
	}
	p.acked[key] = version
	return nil
}

func (p *fakeSnapshotPublisher) Version(key string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.versions[key]
}
