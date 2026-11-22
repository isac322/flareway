/*
Copyright 2026 The Flareway Authors.

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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/pki"
	xdsserver "github.com/isac322/flareway/internal/xds/server"
	"github.com/isac322/flareway/internal/xds/translator"
	"github.com/isac322/flareway/test/envtesthelpers"
)

type xdsEnvHarness struct {
	t         *testing.T
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	direct    client.Client
	xdsAddr   string
	xdsServer *xdsserver.Server
	caSecret  *corev1.Secret
	prober    *managerProber
	remote    *managerRemote
	clock     *stepClock
}

type stepClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

func newXDSEnvHarness(t *testing.T) *xdsEnvHarness {
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
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("stop envtest: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	caSecret, err := pki.EnsureCA(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := pki.ServerTLSConfig(caSecret)
	if err != nil {
		t.Fatal(err)
	}

	xdsAddr := reserveLoopbackAddr(t)
	xdsServer, err := xdsserver.New(xdsserver.Options{
		Address:   xdsAddr,
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctrllog.SetLogger(logr.Discard())
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Logger:     logr.Discard(),
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add(xdsServer); err != nil {
		t.Fatal(err)
	}
	if err := (&GatewayClassReconciler{
		Client: mgr.GetClient(),
		Scheme: scheme,
	}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}

	clock := &stepClock{}
	remote := newManagerRemote()
	prober := &managerProber{ready: true}

	gwReconciler := &GatewayReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            scheme,
		Snapshots:         xdsServer,
		BuildSnapshot:     translator.Build,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               clock.now,
		CloudflareFactory: managerGatewayFactory{api: &managerGatewayAPI{remote: remote}},
		Prober:            prober,
		XDSEvents:         xdsServer.Events(),
	}
	if err := gwReconciler.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	tunReconciler := &CloudflareTunnelReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            scheme,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		Now:               clock.now,
		NewCloudflareClient: func(token, accountID string) (TunnelCloudflareClient, error) {
			remote.use(token, accountID)
			return remote, nil
		},
	}
	if err := tunReconciler.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	h := &xdsEnvHarness{
		t:         t,
		ctx:       ctx,
		cancel:    cancel,
		done:      done,
		direct:    direct,
		xdsAddr:   xdsAddr,
		xdsServer: xdsServer,
		caSecret:  caSecret,
		prober:    prober,
		remote:    remote,
		clock:     clock,
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Log("manager did not stop within 15s")
		}
	})
	go func() {
		defer close(done)
		if err := mgr.Start(ctx); err != nil {
			t.Logf("manager exited: %v", err)
		}
	}()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}
	return h
}

func (h *xdsEnvHarness) waitFor(timeout time.Duration, desc string, fn func() (bool, error)) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ok, err := fn()
		if err == nil && ok {
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s (last err: %v)", desc, lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (h *xdsEnvHarness) connectEnvoyStream(t *testing.T, gwKey types.NamespacedName, podUID types.UID, ackResponses bool) context.CancelFunc {
	t.Helper()
	var clientSecret corev1.Secret
	h.waitFor(15*time.Second, "xDS client secret", func() (bool, error) {
		err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: gwKey.Namespace, Name: pki.ClientSecretName(gwKey.Name)}, &clientSecret)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	})
	cert, err := tls.X509KeyPair(clientSecret.Data[corev1.TLSCertKey], clientSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.caSecret.Data[corev1.TLSCertKey]) {
		_ = pool.AppendCertsFromPEM(h.caSecret.Data["ca.crt"])
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   "flareway-xds.flareway-system.svc.cluster.local",
		Certificates: []tls.Certificate{cert},
	})
	streamCtx, streamCancel := context.WithCancel(h.ctx)
	conn, err := grpc.NewClient(h.xdsAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-streamCtx.Done()
		_ = conn.Close()
	}()

	ads := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	var stream discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	h.waitFor(10*time.Second, "Delta ADS stream open", func() (bool, error) {
		s, err := ads.DeltaAggregatedResources(streamCtx)
		if err != nil {
			return false, nil
		}
		stream = s
		return true, nil
	})

	nodeID := dataplane.EnvoyNodeID(gwKey.Namespace, gwKey.Name, string(podUID))
	var sendMu sync.Mutex
	send := func(req *discoveryv3.DeltaDiscoveryRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(req)
	}
	if err := send(&discoveryv3.DeltaDiscoveryRequest{
		Node:    &corev3.Node{Cluster: gwKey.String(), Id: nodeID},
		TypeUrl: resourcev3.ClusterType,
	}); err != nil {
		t.Fatal(err)
	}
	for _, typeURL := range []string{resourcev3.EndpointType, resourcev3.ListenerType, resourcev3.RouteType, resourcev3.SecretType} {
		if err := send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err != io.EOF && streamCtx.Err() == nil {
					t.Logf("stream recv ended: %v", err)
				}
				return
			}
			if !ackResponses {
				continue
			}
			if err := send(&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:       resp.GetTypeUrl(),
				ResponseNonce: resp.GetNonce(),
			}); err != nil {
				return
			}
		}
	}()
	return streamCancel
}

func TestEnvtestCloudflareModePerPodXDSConvergenceAndDisconnectWakeup(t *testing.T) {
	h := newXDSEnvHarness(t)
	ns := "xds-cf-conv"
	gwName := "edge"
	gwKey := types.NamespacedName{Namespace: ns, Name: gwName}
	className := "cls-cf-conv"
	cfgName := "cfg-cf-conv"
	acctName := "acct-cf-conv"
	secName := "cf-token"
	host := "app.example.com"

	create := func(obj client.Object) {
		if err := h.direct.Create(h.ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secName, Namespace: ns}, Data: map[string][]byte{"token": []byte("tok")}})
	acct := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: acctName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: secName, Namespace: ns, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
			}},
		},
	}
	create(acct)
	seedAccountVerified(t, h, acctName)
	create(&v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: cfgName},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: acctName},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	})
	group := gatewayv1.Group(v1alpha1.Group)
	kind := gatewayv1.Kind("GatewayClassConfig")
	create(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: className},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: cfgName},
		},
	})
	hostname := gatewayv1.Hostname(host)
	create(&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: ns},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Listeners: []gatewayv1.Listener{{
				Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	})

	h.prober.set(true, func() int64 {
		var tun v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwKey, &tun); err != nil {
			return -1
		}
		return h.remote.configVersion(tun.Status.TunnelID)
	})

	makePod := func(name string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    map[string]string{dataplane.StandardGatewayLabelKey: gwName},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "example.invalid/pause"}}},
		}
		create(p)
		p.Status.PodIP = "10.10.0.1"
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := h.direct.Status().Update(h.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pod1 := makePod("dp-1")
	pod2 := makePod("dp-2")

	// Only pod1 connects & ACKs: Programmed must stay False with 1/2 count and zero UID leak.
	stopPod1 := h.connectEnvoyStream(t, gwKey, pod1.UID, true)
	defer stopPod1()

	h.waitFor(15*time.Second, "1/2 partial convergence pending condition", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwKey, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		if cond == nil || cond.Status != metav1.ConditionFalse {
			return false, nil
		}
		if strings.Contains(cond.Message, string(pod1.UID)) || strings.Contains(cond.Message, string(pod2.UID)) {
			t.Fatalf("Gateway Programmed message leaked Pod UID: %q", cond.Message)
		}
		return strings.Contains(cond.Message, "1/2 dataplane Pod(s) connected"), nil
	})

	// Terminating Pod with an un-ACKed stream must NOT block active 2/2 convergence.
	termPod := makePod("dp-terminating")
	var freshTerm corev1.Pod
	if err := h.direct.Get(h.ctx, types.NamespacedName{Namespace: ns, Name: "dp-terminating"}, &freshTerm); err != nil {
		t.Fatal(err)
	}
	freshTerm.Finalizers = []string{"flareway.test/hold"}
	if err := h.direct.Update(h.ctx, &freshTerm); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Delete(h.ctx, &freshTerm); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var p corev1.Pod
		if err := h.direct.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "dp-terminating"}, &p); err == nil {
			p.Finalizers = nil
			_ = h.direct.Update(context.Background(), &p)
		}
	})
	stopTerm := h.connectEnvoyStream(t, gwKey, termPod.UID, false)
	defer stopTerm()

	// Connect pod2 -> both active Pods ACK -> Programmed=True even with terminating un-ACKed stream!
	stopPod2 := h.connectEnvoyStream(t, gwKey, pod2.UID, true)

	h.waitFor(15*time.Second, "2/2 Programmed=True", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwKey, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return cond != nil && cond.Status == metav1.ConditionTrue, nil
	})

	// Advance fake clock well beyond 30s convergence timeout while ConfigApplied=True,
	// then drop pod2's xDS stream with NO Kubernetes resource edits:
	// XDSEvents must wake GatewayReconciler immediately, Programmed must drop to False,
	// and message must say "Waiting for..." (NOT false "Timed out after 30s...").
	h.clock.advance(2 * time.Minute)
	stopPod2()

	h.waitFor(10*time.Second, "XDSEvents disconnect drop without false 30s timeout", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwKey, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		if cond == nil || cond.Status != metav1.ConditionFalse {
			return false, nil
		}
		if strings.HasPrefix(cond.Message, "Timed out after 30s") {
			t.Fatalf("false timeout immediately on disconnect: %q", cond.Message)
		}
		return strings.Contains(cond.Message, "1/2 dataplane Pod(s) connected"), nil
	})
}

func TestEnvtestConformanceModeAndTeardownDenyConvergence(t *testing.T) {
	h := newXDSEnvHarness(t)

	// 1. ConformanceMode requires 2/2 active Pod xDS ACKs.
	nsConf := "xds-conf-conv"
	gwConf := types.NamespacedName{Namespace: nsConf, Name: "conf-gw"}
	if err := h.direct.Create(h.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsConf}}); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, conformanceConfig("cfg-conf-conv", corev1.ServiceTypeClusterIP)); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, gatewayClass("cls-conf-conv", "cfg-conf-conv")); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, httpGateway(gwConf, "cls-conf-conv")); err != nil {
		t.Fatal(err)
	}

	deployKey := types.NamespacedName{Namespace: nsConf, Name: dataplane.ResourceName(&ir.Gateway{Key: gwConf})}
	h.waitFor(15*time.Second, "conformance Deployment created", func() (bool, error) {
		var d appsv1.Deployment
		err := h.direct.Get(h.ctx, deployKey, &d)
		return err == nil, client.IgnoreNotFound(err)
	})
	if err := envtesthelpers.MarkDeploymentAvailable(h.ctx, h.direct, deployKey); err != nil {
		t.Fatal(err)
	}
	// Mark ClusterIP Service type by checking service ready (ClusterIP is ready immediately without LB ingress).
	createPod := func(namespace, gw, name string, phase corev1.PodPhase, ip string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    map[string]string{dataplane.StandardGatewayLabelKey: gw},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "example.invalid/pause"}}},
		}
		if err := h.direct.Create(h.ctx, p); err != nil {
			t.Fatal(err)
		}
		p.Status.Phase = phase
		p.Status.PodIP = ip
		if err := h.direct.Status().Update(h.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cPod1 := createPod(nsConf, gwConf.Name, "dp-c1", corev1.PodRunning, "10.20.1.1")
	cPod2 := createPod(nsConf, gwConf.Name, "dp-c2", corev1.PodRunning, "10.20.1.2")

	stopC1 := h.connectEnvoyStream(t, gwConf, cPod1.UID, true)
	defer stopC1()
	h.waitFor(15*time.Second, "conformance 1/2 pending", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwConf, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return cond != nil && cond.Status == metav1.ConditionFalse && strings.HasPrefix(cond.Message, "Waiting for Envoy to acknowledge xDS snapshot "), nil
	})
	stopC2 := h.connectEnvoyStream(t, gwConf, cPod2.UID, true)
	defer stopC2()
	h.waitFor(15*time.Second, "conformance 2/2 Programmed=True", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwConf, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return cond != nil && cond.Status == metav1.ConditionTrue, nil
	})

	// 2. Teardown denySnapshotApplied:
	// (a) 2 Running Pods with only 1 ACKed fails closed (no premature TeardownBlocked);
	// (b) 1 Running ACKed + 1 unscheduled Pending (PodIP == "") succeeds without deadlock.
	nsTD := "xds-td-conv"
	gwTD := types.NamespacedName{Namespace: nsTD, Name: "td-gw"}
	if err := h.direct.Create(h.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsTD}}); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cf-token", Namespace: nsTD}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "acct-td"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "cf-token", Namespace: nsTD, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	seedAccountVerified(t, h, "acct-td")
	if err := h.direct.Create(h.ctx, &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg-td"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: "acct-td"},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Create(h.ctx, &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cls-td"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("GatewayClassConfig"), Name: "cfg-td"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	hostTD := gatewayv1.Hostname("td.example.com")
	if err := h.direct.Create(h.ctx, &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwTD.Name, Namespace: nsTD},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cls-td",
			Listeners:        []gatewayv1.Listener{{Name: "http", Hostname: &hostTD, Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	h.prober.set(true, func() int64 {
		var tun v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwTD, &tun); err != nil {
			return -1
		}
		return h.remote.configVersion(tun.Status.TunnelID)
	})
	tdPod1 := createPod(nsTD, gwTD.Name, "dp-td1", corev1.PodRunning, "10.30.1.1")
	tdPod2 := createPod(nsTD, gwTD.Name, "dp-td2", corev1.PodRunning, "10.30.1.2")
	stopTD1 := h.connectEnvoyStream(t, gwTD, tdPod1.UID, true)
	defer stopTD1()
	stopTD2 := h.connectEnvoyStream(t, gwTD, tdPod2.UID, true)

	h.waitFor(15*time.Second, "teardown fixture initial Programmed=True", func() (bool, error) {
		var gw gatewayv1.Gateway
		if err := h.direct.Get(h.ctx, gwTD, &gw); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return cond != nil && cond.Status == metav1.ConditionTrue, nil
	})

	// Drop tdPod2 stream before deleting Tunnel -> 1/2 Running Pods connected.
	stopTD2()
	// Hold a test-only finalizer on the live CloudflareTunnel so envtest retains
	// origTunnelUID until we observe teardown completion, preventing a delete+auto-recreate
	// cycle from racing our poll window.
	const teardownHoldFinalizer = "flareway.test/hold-teardown"
	var origTunnelUID types.UID
	h.waitFor(10*time.Second, "hold teardown finalizer on CloudflareTunnel", func() (bool, error) {
		var tun v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwTD, &tun); err != nil {
			return false, err
		}
		if controllerutil.ContainsFinalizer(&tun, teardownHoldFinalizer) {
			origTunnelUID = tun.UID
			return true, nil
		}
		before := tun.DeepCopy()
		controllerutil.AddFinalizer(&tun, teardownHoldFinalizer)
		if err := h.direct.Patch(h.ctx, &tun, client.MergeFrom(before)); err != nil {
			if apierrors.IsConflict(err) {
				return false, nil
			}
			return false, err
		}
		origTunnelUID = tun.UID
		return true, nil
	})
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		var cur v1alpha1.CloudflareTunnel
		if err := h.direct.Get(cleanCtx, gwTD, &cur); err != nil || cur.UID != origTunnelUID {
			return
		}
		if !controllerutil.ContainsFinalizer(&cur, teardownHoldFinalizer) {
			return
		}
		before := cur.DeepCopy()
		controllerutil.RemoveFinalizer(&cur, teardownHoldFinalizer)
		_ = h.direct.Patch(cleanCtx, &cur, client.MergeFrom(before))
	})

	// Make tdPod2 stream fail closed while Running during teardown: delete Tunnel so teardown starts.
	var tun v1alpha1.CloudflareTunnel
	if err := h.direct.Get(h.ctx, gwTD, &tun); err != nil {
		t.Fatal(err)
	}
	if err := h.direct.Delete(h.ctx, &tun); err != nil {
		t.Fatal(err)
	}
	h.waitFor(10*time.Second, "tunnel teardown annotation set", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwTD, &cur); err != nil {
			return false, err
		}
		return cur.UID == origTunnelUID && cur.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] == "true", nil
	})

	// With tdPod2 Running & disconnected, teardown must NOT block hostnames or release the finalizer.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		var cur v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwTD, &cur); err != nil {
			t.Fatalf("get CloudflareTunnel during negative teardown check: %v", err)
		}
		if cur.UID != origTunnelUID {
			t.Fatalf("CloudflareTunnel UID changed during negative teardown check: got %s, want %s", cur.UID, origTunnelUID)
		}
		if !controllerutil.ContainsFinalizer(&cur, v1alpha1.CloudflareTunnelFinalizer) {
			t.Fatalf("CloudflareTunnel finalizer removed while Running Pod tdPod2 lacked deny ACK")
		}
		if len(cur.Status.Hostnames) > 0 && allHostnamesBlocked(cur.Status.Hostnames) {
			t.Fatalf("CloudflareTunnel hostnames were all blocked while Running Pod tdPod2 lacked deny ACK: %#v", cur.Status.Hostnames)
		}
		applied := meta.FindStatusCondition(cur.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		if applied != nil && applied.Reason == "TeardownBlocked" {
			t.Fatalf("teardown promoted TeardownBlocked while Running Pod tdPod2 lacked deny ACK: %#v", applied)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Create the unscheduled Pending Pod (PodIP == "") before deleting tdPod2 so
	// deny convergence is always evaluated with dp-td-pending present alongside dp-td1.
	createPod(nsTD, gwTD.Name, "dp-td-pending", corev1.PodPending, "")
	if err := h.direct.Delete(h.ctx, tdPod2); err != nil {
		t.Fatalf("delete tdPod2: %v", err)
	}
	h.waitFor(15*time.Second, "teardown completes with unscheduled Pending Pod skipped", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		if err := h.direct.Get(h.ctx, gwTD, &cur); err != nil {
			return false, err
		}
		if cur.UID != origTunnelUID {
			return false, nil
		}
		return len(cur.Status.Hostnames) > 0 &&
			allHostnamesBlocked(cur.Status.Hostnames) &&
			!controllerutil.ContainsFinalizer(&cur, v1alpha1.CloudflareTunnelFinalizer), nil
	})
}

func TestGatewayPromotionGuardWrapsPodListError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	podErr := errors.New("injected pod list failure")
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.PodList); ok {
				return podErr
			}
			return c.List(ctx, list, opts...)
		},
	}).Build()

	reconciler := &GatewayReconciler{
		Client:    kube,
		Snapshots: newFakeSnapshotPublisher(),
	}
	gw := &ir.Gateway{Key: types.NamespacedName{Namespace: "apps", Name: "edge"}}
	live := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "edge"},
		Status: v1alpha1.CloudflareTunnelStatus{
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{
				Desired:     5,
				DesiredHash: "h1",
				Remote:      5,
			},
		},
	}
	guard := reconciler.gatewayPromotionGuard(context.Background(), gw, cloudflareConfigResult{
		version: 5, hash: "h1", remoteVersion: 5,
	}, "snap-5", true)
	err := guard(live)
	if !errors.Is(err, errTunnelGateObservation) {
		t.Fatalf("guard error = %v, want wrapped errTunnelGateObservation", err)
	}
	if !strings.Contains(err.Error(), podErr.Error()) {
		t.Fatalf("guard error %v missing underlying pod list error", err)
	}
}

func seedAccountVerified(t *testing.T, h *xdsEnvHarness, name string) {
	t.Helper()
	h.waitFor(10*time.Second, "seed CloudflareAccount status", func() (bool, error) {
		var cur v1alpha1.CloudflareAccount
		if err := h.direct.Get(h.ctx, types.NamespacedName{Name: name}, &cur); err != nil {
			return false, err
		}
		now := metav1.Now()
		cur.Status.Verified = v1alpha1.CloudflareAccountVerifiedStatus{
			AccountName: "test-account",
			Zones:       []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.com"}},
		}
		cur.Status.Conditions = []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: cur.Generation, LastTransitionTime: now},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", ObservedGeneration: cur.Generation, LastTransitionTime: now},
		}
		if err := h.direct.Status().Update(h.ctx, &cur); err != nil {
			return false, nil
		}
		return true, nil
	})
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

var _ flarecloudflare.ClientFactory = managerGatewayFactory{}
var _ atomic.Bool
