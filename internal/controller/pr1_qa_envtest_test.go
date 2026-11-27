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
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

type handoffIndexedClient struct {
	client.Client
}

func (c handoffIndexedClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	var listOpts client.ListOptions
	for _, opt := range opts {
		opt.ApplyToList(&listOpts)
	}
	if listOpts.FieldSelector == nil {
		return c.Client.List(ctx, list, opts...)
	}
	wanted, hasIndex := listOpts.FieldSelector.RequiresExactMatch(accessApplicationHandoffOwnerIndex)
	if !hasIndex {
		return c.Client.List(ctx, list, opts...)
	}
	filtered := make([]client.ListOption, 0, len(opts))
	for _, opt := range opts {
		if _, ok := opt.(client.MatchingFields); ok {
			continue
		}
		if fs, ok := opt.(fields.Selector); ok && fs == listOpts.FieldSelector {
			continue
		}
		filtered = append(filtered, opt)
	}
	secrets, isSecretList := list.(*corev1.SecretList)
	if !isSecretList {
		return c.Client.List(ctx, list, filtered...)
	}
	if err := c.Client.List(ctx, secrets, filtered...); err != nil {
		return err
	}
	indexFn := accessHandoffOwnerIndexKeys(accessApplicationAUDNamespace)
	kept := secrets.Items[:0]
	for index := range secrets.Items {
		if slices.Contains(indexFn(&secrets.Items[index]), wanted) {
			kept = append(kept, secrets.Items[index])
		}
	}
	secrets.Items = kept
	return nil
}

var _ = ginkgo.Describe("PR-1 Private Access & Reserved Port Validation (envtest)", func() {
	// QA-1B-1: Invalid Private AccessApplications (pathScope / per-rule split /
	// same-host duplicate) must be rejected with Accepted=False/Invalid on the
	// offending AccessApplication without crashing translator.Build or taking
	// down sibling healthy listeners.
	ginkgo.It("QA-1B-1: rejects invalid Private AccessApplication without failing Gateway snapshot build or healthy siblings", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace
		tunnel := *f.tunnel()
		accountName := tunnel.Spec.AccountRef.Name

		// Allow wildcard *.internal.example and edge-a.example.com in account grants.
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: accountName}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "*.internal.example"}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		// Update Gateway to have a Private wildcard listener *.internal.example
		// alongside the healthy Public listener on port 80.
		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		privWild := gatewayv1.Hostname("*.internal.example")
		gw.Spec.Listeners[1].Hostname = &privWild
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		// Create ready VirtualNetwork & DeviceSettings for the Private listener.
		vnet := &v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "private-vnet", Namespace: ns},
			Spec:       v1alpha1.VirtualNetworkSpec{Name: "private-vnet", AccountRef: corev1.LocalObjectReference{Name: accountName}},
		}
		gomega.Expect(f.direct.Create(f.ctx, vnet)).To(gomega.Succeed())
		vnet.Status.VirtualNetworkID = "vnet-pr1"
		vnet.Status.ObservedGeneration = vnet.Generation
		vnet.Status.Conditions = []metav1.Condition{{
			Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue,
			Reason: "Accepted", ObservedGeneration: vnet.Generation, LastTransitionTime: metav1.Now(),
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, vnet)).To(gomega.Succeed())

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
			Name: "private", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name},
		}}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		// Create backend Service + HTTPRoutes for edge-a.example.com, a.internal.example, b.internal.example.
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())
		port := gatewayv1.PortNumber(8080)
		pathType := gatewayv1.PathMatchPathPrefix
		privSection := gatewayv1.SectionName("private")
		pubSection := gatewayv1.SectionName("http")
		routePub := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "pub-route", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &pubSection}}},
				Hostnames:       []gatewayv1.Hostname{"edge-a.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		routeA := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-a", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &privSection}}},
				Hostnames:       []gatewayv1.Hostname{"a.internal.example"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		routeB := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-b", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &privSection}}},
				Hostnames:       []gatewayv1.Hostname{"b.internal.example"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, routePub)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, routeA)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, routeB)).To(gomega.Succeed())

		// Offending AccessApplication: uses pathScope on Private hostname a.internal.example.
		badApp := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-private-scoped", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "priv-a"},
				}},
				PathScope:   &v1alpha1.AccessTargetPath{Type: gatewayv1.PathMatchPathPrefix, Value: "/admin"},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "bad-scoped", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		// Healthy sibling AccessApplication on b.internal.example.
		goodApp := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "good-private", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "priv-b"},
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "good-private", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, badApp)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, goodApp)).To(gomega.Succeed())

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		// Reconcile both AccessApplications (first pass adds finalizer, second pass writes status).
		for _, app := range []*v1alpha1.AccessApplication{badApp, goodApp} {
			for range 2 {
				_, err := accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		}

		var storedBad, storedGood v1alpha1.AccessApplication
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(badApp), &storedBad)).To(gomega.Succeed())
		badCond := meta.FindStatusCondition(storedBad.Status.Conditions, accessApplicationConditionAccepted)
		gomega.Expect(badCond).NotTo(gomega.BeNil())
		gomega.Expect(badCond.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(badCond.Reason).To(gomega.Equal("Invalid"))

		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(goodApp), &storedGood)).To(gomega.Succeed())
		goodCond := meta.FindStatusCondition(storedGood.Status.Conditions, accessApplicationConditionAccepted)
		gomega.Expect(goodCond).NotTo(gomega.BeNil())
		gomega.Expect(goodCond.Status).To(gomega.Equal(metav1.ConditionTrue))

		// Reconcile GatewayReconciler: it must NOT fail snapshot build and must keep
		// healthy Public and Private listeners operational.
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		pubListener := listenerStatusByName(gw.Status.Listeners, "http")
		gomega.Expect(pubListener).NotTo(gomega.BeNil())
		gomega.Expect(meta.FindStatusCondition(pubListener.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		privListener := listenerStatusByName(gw.Status.Listeners, "private")
		gomega.Expect(privListener).NotTo(gomega.BeNil())
		gomega.Expect(meta.FindStatusCondition(privListener.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		// Verify xDS snapshot was built and published cleanly.
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
	})

	// QA-1G-1: Reserved dataplane pod ports (53, 2000, 18000, 19000, 19001)
	// on Private listeners must be rejected with Accepted=False/PortUnavailable
	// during Gateway validation so they never enter xDS snapshots or cause
	// Envoy LDS EADDRINUSE NACKs affecting sibling healthy listeners.
	ginkgo.It("QA-1G-1: rejects reserved dataplane pod ports on Private listeners while sibling listeners stay healthy", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "bad.internal.example", "good.internal.example"}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "bad-reserved", Exposure: v1alpha1.ExposurePrivate},
			{Name: "good-private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		badHost := gatewayv1.Hostname("bad.internal.example")
		goodHost := gatewayv1.Hostname("good.internal.example")
		gw.Spec.Listeners = []gatewayv1.Listener{
			gw.Spec.Listeners[0], // healthy Public HTTP listener on port 80
			{
				Name: "bad-reserved", Hostname: &badHost, Port: 19000, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			},
			{
				Name: "good-private", Hostname: &goodHost, Port: 8443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			},
		}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		badListener := listenerStatusByName(gw.Status.Listeners, "bad-reserved")
		gomega.Expect(badListener).NotTo(gomega.BeNil())
		badAcc := meta.FindStatusCondition(badListener.Conditions, string(gatewayv1.ListenerConditionAccepted))
		gomega.Expect(badAcc).NotTo(gomega.BeNil())
		gomega.Expect(badAcc.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(badAcc.Reason).To(gomega.Equal(string(gatewayv1.ListenerReasonPortUnavailable)))

		goodPub := listenerStatusByName(gw.Status.Listeners, "http")
		gomega.Expect(meta.FindStatusCondition(goodPub.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))
		goodPriv := listenerStatusByName(gw.Status.Listeners, "good-private")
		gomega.Expect(meta.FindStatusCondition(goodPriv.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		// Published xDS snapshot must contain good-private (8443) and http, and MUST NOT
		// bind reserved Envoy Admin port 19000.
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
		var has8443 bool
		for _, res := range snap.GetResources(resourcev3.ListenerType) {
			l := res.(*listenerv3.Listener)
			port := l.GetAddress().GetSocketAddress().GetPortValue()
			gomega.Expect(port).NotTo(gomega.Equal(uint32(19000)), "reserved port 19000 leaked into xDS Listener resources")
			if port == 8443 {
				has8443 = true
			}
		}
		gomega.Expect(has8443).To(gomega.BeTrue(), "healthy sibling private listener 8443 missing from xDS snapshot")
	})

	ginkgo.It("QA-1G-1 (all reserved ports): rejects 53, 2000, 18000, 19000, 19001 in real envtest", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"*"}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		reserved := []struct {
			name string
			port gatewayv1.PortNumber
		}{
			{"p53", 53},
			{"p2000", 2000},
			{"p18000", 18000},
			{"p19000", 19000},
			{"p19001", 19001},
		}
		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		listeners := []gatewayv1.Listener{gw.Spec.Listeners[0]}
		tunnel.Spec.Listeners = nil
		for _, r := range reserved {
			tunnel.Spec.Listeners = append(tunnel.Spec.Listeners, v1alpha1.CloudflareTunnelListener{
				Name: gatewayv1.SectionName(r.name), Exposure: v1alpha1.ExposurePrivate,
			})
			h := gatewayv1.Hostname(r.name + ".internal.example")
			listeners = append(listeners, gatewayv1.Listener{
				Name: gatewayv1.SectionName(r.name), Hostname: &h, Port: r.port, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			})
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		gw.Spec.Listeners = listeners
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		for _, r := range reserved {
			ls := listenerStatusByName(gw.Status.Listeners, gatewayv1.SectionName(r.name))
			gomega.Expect(ls).NotTo(gomega.BeNil())
			acc := meta.FindStatusCondition(ls.Conditions, string(gatewayv1.ListenerConditionAccepted))
			gomega.Expect(acc).NotTo(gomega.BeNil())
			gomega.Expect(acc.Status).To(gomega.Equal(metav1.ConditionFalse), "port %d should be rejected", r.port)
			gomega.Expect(acc.Reason).To(gomega.Equal(string(gatewayv1.ListenerReasonPortUnavailable)), "port %d reason", r.port)
		}
		goodLS := listenerStatusByName(gw.Status.Listeners, "http")
		gomega.Expect(meta.FindStatusCondition(goodLS.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
		for _, res := range snap.GetResources(resourcev3.ListenerType) {
			port := res.(*listenerv3.Listener).GetAddress().GetSocketAddress().GetPortValue()
			for _, r := range reserved {
				gomega.Expect(port).NotTo(gomega.Equal(uint32(r.port)))
			}
		}
	})
})

// QA-1-REG-4 (controller): Mixed PodIP + Loopback active Private listeners keep
// PrivateListenerDegraded=True (PodIPFallback) while All-Loopback reports False.
func TestPR1MixedBindingsKeepPrivateListenerDegradedTrue(t *testing.T) {
	mixed := &ir.Gateway{
		Listeners: []ir.Listener{
			{Name: "a", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
			{Name: "b", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
		},
	}
	state := privatePrerequisiteResult{Listeners: map[string]string{}}
	state.Degraded = privateActiveUsesPodIPBinding(mixed, state.Listeners)
	if !state.Degraded {
		t.Fatal("mixed active PodIP + Loopback listeners must report Degraded=true")
	}
	cond := privateListenerCondition(mixed, state, metav1.Now())
	if cond.Status != metav1.ConditionTrue || cond.Reason != "PodIPFallback" {
		t.Fatalf("mixed condition = %#v, want True/PodIPFallback", cond)
	}

	loopbackOnly := &ir.Gateway{
		Listeners: []ir.Listener{
			{Name: "a", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
			{Name: "b", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
		},
	}
	loopState := privatePrerequisiteResult{Listeners: map[string]string{}}
	loopState.Degraded = privateActiveUsesPodIPBinding(loopbackOnly, loopState.Listeners)
	loopCond := privateListenerCondition(loopbackOnly, loopState, metav1.Now())
	if loopCond.Status != metav1.ConditionFalse || loopCond.Reason != "Loopback" {
		t.Fatalf("all-loopback condition = %#v, want False/Loopback", loopCond)
	}
}
