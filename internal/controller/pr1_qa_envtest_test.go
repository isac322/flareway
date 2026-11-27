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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

type tunnelStatusWriteCounterClient struct {
	client.Client
	tunnelName string
	writes     atomic.Int64
}

func (c *tunnelStatusWriteCounterClient) Status() client.SubResourceWriter {
	return &tunnelStatusWriteCounterWriter{writer: c.Client.Status(), owner: c}
}

type tunnelStatusWriteCounterWriter struct {
	writer client.SubResourceWriter
	owner  *tunnelStatusWriteCounterClient
}

func (w *tunnelStatusWriteCounterWriter) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	return w.writer.Create(ctx, obj, subResource, opts...)
}

func (w *tunnelStatusWriteCounterWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if tunnel, ok := obj.(*v1alpha1.CloudflareTunnel); ok && tunnel.Name == w.owner.tunnelName {
		w.owner.writes.Add(1)
	}
	return w.writer.Update(ctx, obj, opts...)
}

func (w *tunnelStatusWriteCounterWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if tunnel, ok := obj.(*v1alpha1.CloudflareTunnel); ok && tunnel.Name == w.owner.tunnelName {
		w.owner.writes.Add(1)
	}
	return w.writer.Patch(ctx, obj, patch, opts...)
}

func (w *tunnelStatusWriteCounterWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	name := ""
	switch typed := obj.(type) {
	case client.Object:
		name = typed.GetName()
	case interface{ GetName() *string }:
		if value := typed.GetName(); value != nil {
			name = *value
		}
	}
	if name == w.owner.tunnelName {
		w.owner.writes.Add(1)
	}
	return w.writer.Apply(ctx, obj, opts...)
}

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

		// Allow wildcard *.internal.example and edge-a.example.com in account grants (Public + Private).
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: accountName}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "*.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
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

		// Create ready VirtualNetwork and HostnameRoute prerequisites for *.internal.example.
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

		hr := &v1alpha1.HostnameRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "hr-wild-internal", Namespace: ns},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Hostname:   "*.internal.example",
				TunnelRef:  v1alpha1.TunnelReference{Name: tunnel.Name},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, hr)).To(gomega.Succeed())
		hr.Status = v1alpha1.HostnameRouteStatus{
			RouteID:            "route-wild-internal",
			Hostname:           "*.internal.example",
			TunnelID:           tunnel.Status.TunnelID,
			ObservedGeneration: hr.Generation,
			Applied: v1alpha1.HostnameRouteAppliedStatus{
				Hostname:           "*.internal.example",
				TunnelID:           tunnel.Status.TunnelID,
				ObservedGeneration: hr.Generation,
			},
			Conditions: []metav1.Condition{{
				Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue,
				Reason: "Accepted", ObservedGeneration: hr.Generation, LastTransitionTime: metav1.Now(),
			}},
		}
		gomega.Expect(f.direct.Status().Update(f.ctx, hr)).To(gomega.Succeed())

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
					Name:        new(gatewayv1.SectionName("admin")),
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		routeSplit := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-split", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &privSection}}},
				Hostnames:       []gatewayv1.Hostname{"split.internal.example"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Name:        new(gatewayv1.SectionName("admin")),
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
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
		gomega.Expect(f.direct.Create(f.ctx, routeSplit)).To(gomega.Succeed())
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
		// Offending AccessApplication: uses named per-rule sectionName on Private hostname.
		badRuleApp := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-private-rule", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "priv-split"},
					SectionName:                new(gatewayv1.SectionName("admin")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "bad-rule", SessionDuration: "1h"},
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
		// Duplicate AccessApplication targeting the same Private host b.internal.example.
		dupApp := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "z-dup-private", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: accountName},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "priv-b"},
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "dup-private", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, badApp)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, badRuleApp)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, goodApp)).To(gomega.Succeed())
		gomega.Eventually(func() time.Time { return metav1.Now().Time }).Should(gomega.BeTemporally(">=", goodApp.CreationTimestamp.Time))
		gomega.Expect(f.direct.Create(f.ctx, dupApp)).To(gomega.Succeed())

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		// Reconcile all AccessApplications (first pass adds finalizer, second pass writes status).
		for _, app := range []*v1alpha1.AccessApplication{badApp, badRuleApp, goodApp, dupApp} {
			for range 2 {
				_, err := accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		}

		for _, offending := range []*v1alpha1.AccessApplication{badApp, badRuleApp, dupApp} {
			var stored v1alpha1.AccessApplication
			gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(offending), &stored)).To(gomega.Succeed())
			cond := meta.FindStatusCondition(stored.Status.Conditions, accessApplicationConditionAccepted)
			gomega.Expect(cond).NotTo(gomega.BeNil(), "missing Accepted condition for %s", offending.Name)
			gomega.Expect(cond.Status).To(gomega.Equal(metav1.ConditionFalse), "expected Accepted=False for %s", offending.Name)
			gomega.Expect(cond.Reason).To(gomega.Equal("Invalid"), "expected Reason=Invalid for %s", offending.Name)
		}

		var storedGood v1alpha1.AccessApplication
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(goodApp), &storedGood)).To(gomega.Succeed())
		goodCond := meta.FindStatusCondition(storedGood.Status.Conditions, accessApplicationConditionAccepted)
		gomega.Expect(goodCond).NotTo(gomega.BeNil())
		gomega.Expect(goodCond.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(storedGood.Status.ApplicationID).NotTo(gomega.BeEmpty(), "goodApp failed remote provision / AUD handoff: conditions=%#v", storedGood.Status.Conditions)

		// Reconcile GatewayReconciler through the block-first transition:
		// first converge records Blocked + AccessBinding on tunnel status;
		// second converge transitions good-private to Forwarding in xDS.
		f.converge()
		f.converge()
		gomega.Expect(f.condition(v1alpha1.CloudflareTunnelConditionConfigApplied).Status).To(gomega.Equal(metav1.ConditionTrue))
		privDegraded := f.condition(v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded)
		gomega.Expect(privDegraded.Reason).To(gomega.Equal("Loopback"), "private listener prerequisite block: %#v", privDegraded)

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		pubListener := listenerStatusByName(gw.Status.Listeners, "http")
		gomega.Expect(pubListener).NotTo(gomega.BeNil())
		gomega.Expect(meta.FindStatusCondition(pubListener.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		privListener := listenerStatusByName(gw.Status.Listeners, "private")
		gomega.Expect(privListener).NotTo(gomega.BeNil())
		gomega.Expect(meta.FindStatusCondition(privListener.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		// Verify xDS snapshot was built and both healthy sibling routes actually
		// forward (not 403), with b.internal.example requiring Access JWT.
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
		forwardingHosts := map[string]bool{}
		jwtProtectedHosts := map[string]bool{}
		for _, res := range snap.GetResources(resourcev3.RouteType) {
			rc := res.(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				hasForward := len(vh.GetRoutes()) > 0 && vh.GetRoutes()[0].GetRoute() != nil
				var hasJWTRequirement bool
				if filterCfg := vh.GetTypedPerFilterConfig()["envoy.filters.http.jwt_authn"]; filterCfg != nil {
					var perRoute jwtauthnv3.PerRouteConfig
					if err := filterCfg.UnmarshalTo(&perRoute); err == nil && perRoute.GetRequirementName() != "" {
						hasJWTRequirement = true
					}
				}
				for _, dom := range vh.GetDomains() {
					if hasForward {
						forwardingHosts[dom] = true
					}
					if hasJWTRequirement {
						jwtProtectedHosts[dom] = true
					}
				}
			}
		}
		gomega.Expect(forwardingHosts["edge-a.example.com"]).To(gomega.BeTrue(), "healthy Public sibling route missing forwarding action in xDS RouteConfiguration: %#v", forwardingHosts)
		gomega.Expect(forwardingHosts["b.internal.example"]).To(gomega.BeTrue(), "healthy Private sibling route missing forwarding action (must not be 403) in xDS RouteConfiguration: %#v", forwardingHosts)
		gomega.Expect(jwtProtectedHosts["b.internal.example"]).To(gomega.BeTrue(), "healthy Private sibling route missing JWT requirement in xDS RouteConfiguration: %#v", jwtProtectedHosts)
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

		f.converge()

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
		// Include boundary non-reserved port 18080 (Public allocator start port).
		tunnel.Spec.Listeners = append(tunnel.Spec.Listeners, v1alpha1.CloudflareTunnelListener{
			Name: "p18080", Exposure: v1alpha1.ExposurePrivate,
		})
		h18080 := gatewayv1.Hostname("p18080.internal.example")
		listeners = append(listeners, gatewayv1.Listener{
			Name: "p18080", Hostname: &h18080, Port: 18080, Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
		})
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		gw.Spec.Listeners = listeners
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		f.converge()

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
		p18080LS := listenerStatusByName(gw.Status.Listeners, "p18080")
		gomega.Expect(meta.FindStatusCondition(p18080LS.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
		var saw18080 bool
		for _, res := range snap.GetResources(resourcev3.ListenerType) {
			port := res.(*listenerv3.Listener).GetAddress().GetSocketAddress().GetPortValue()
			if port == 18080 {
				saw18080 = true
			}
			for _, r := range reserved {
				gomega.Expect(port).NotTo(gomega.Equal(uint32(r.port)))
			}
		}
		gomega.Expect(saw18080).To(gomega.BeTrue(), "boundary non-reserved Private port 18080 missing from xDS snapshot")
	})

	// QA-1G-1 (retained state) & QA-1-REG-2 (Private tombstone + sibling forwarding):
	// When an existing Private AccessApplication has retained tombstone state on
	// a now-reserved port (19000), GatewayReconciler rejects the Private listener
	// (Accepted=False/PortUnavailable), preserves the Blocked revocation proof in
	// tunnel.Status.Hostnames, and still publishes a valid xDS snapshot serving
	// the healthy sibling listener without binding 19000 or crashing on port 0.
	ginkgo.It("QA-1G-1 (retained tombstone): isolates reserved-port Private tombstone without blocking sibling xDS publication", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "revoked-reserved.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		revokedHost := gatewayv1.Hostname("revoked-reserved.internal.example")
		gw.Spec.Listeners[1].Hostname = &revokedHost
		gw.Spec.Listeners[1].Port = 19000
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())
		svcPort := gatewayv1.PortNumber(8080)
		pathType := gatewayv1.PathMatchPathPrefix
		pubSection := gatewayv1.SectionName("http")
		pubRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "pub-sibling", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &pubSection}}},
				Hostnames:       []gatewayv1.Hostname{"edge-a.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &svcPort}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, pubRoute)).To(gomega.Succeed())

		// Settle the baseline remote version with the healthy Public sibling and
		// rejected reserved-port Private listener before introducing the latched
		// Private revocation tombstone, so the remote config version stays unchanged.
		f.converge()
		baselineVersion := f.tunnel().Status.ConfigVersion.Applied
		gomega.Expect(baselineVersion).To(gomega.BeNumerically(">", 0))

		// Retained deleting Private AccessApplication holding port 19000 tombstone
		// state and an existing revocation latch at the settled baseline version.
		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "private-access-default-app-a",
				Hostname:         "revoked-reserved.internal.example",
				BaselineVersion:  baselineVersion,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "app-a",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("private")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-a", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "private",
			ProtectionDomain: "private-access-default-app-a",
			EnvoyPort:        19000,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPrivate,
			Hostname: "revoked-reserved.internal.example",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())

		f.converge()

		// Remote version must remain unchanged at baselineVersion because Private
		// tombstones are excluded from remote cloudflared ingress.
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.ConfigVersion.Applied).To(gomega.Equal(baselineVersion))

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		privLS := listenerStatusByName(gw.Status.Listeners, "private")
		gomega.Expect(privLS).NotTo(gomega.BeNil())
		privAcc := meta.FindStatusCondition(privLS.Conditions, string(gatewayv1.ListenerConditionAccepted))
		gomega.Expect(privAcc).NotTo(gomega.BeNil())
		gomega.Expect(privAcc.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(privAcc.Reason).To(gomega.Equal(string(gatewayv1.ListenerReasonPortUnavailable)))

		httpLS := listenerStatusByName(gw.Status.Listeners, "http")
		gomega.Expect(meta.FindStatusCondition(httpLS.Conditions, string(gatewayv1.ListenerConditionAccepted)).Status).To(gomega.Equal(metav1.ConditionTrue))

		// Snapshot MUST be published for healthy siblings without binding 19000 or 0.
		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())
		for _, res := range snap.GetResources(resourcev3.ListenerType) {
			port := res.(*listenerv3.Listener).GetAddress().GetSocketAddress().GetPortValue()
			gomega.Expect(port).NotTo(gomega.Equal(uint32(0)))
			gomega.Expect(port).NotTo(gomega.Equal(uint32(19000)))
		}
		var sawSibling bool
		for _, res := range snap.GetResources(resourcev3.RouteType) {
			rc := res.(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				if slices.Contains(vh.GetDomains(), "edge-a.example.com") && len(vh.GetRoutes()) > 0 && vh.GetRoutes()[0].GetRoute() != nil {
					sawSibling = true
				}
			}
		}
		gomega.Expect(sawSibling).To(gomega.BeTrue(), "healthy sibling edge-a.example.com missing forwarding route from xDS snapshot")

		// Revocation proof for old Private hostname remains recorded as Blocked.
		var sawBlockedProof bool
		for _, h := range tunnel.Status.Hostnames {
			if h.Hostname == "revoked-reserved.internal.example" && h.Guard == v1alpha1.HostnameGuardBlocked {
				sawBlockedProof = true
			}
		}
		gomega.Expect(sawBlockedProof).To(gomega.BeTrue(), "expected Blocked revocation status for revoked-reserved.internal.example in %#v", tunnel.Status.Hostnames)

		// AccessApplicationReconciler MUST acknowledge the Blocked status at the
		// unchanged baselineVersion (requiring Private listener status identity)
		// and finish removing its finalizer.
		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		_, err = accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var deletedCheck v1alpha1.AccessApplication
		err = f.direct.Get(f.ctx, client.ObjectKeyFromObject(app), &deletedCheck)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "deleting Private reserved-port AccessApplication stalled instead of acknowledging Blocked at unchanged version %d; err=%v conditions=%#v", baselineVersion, err, deletedCheck.Status.Conditions)
	})

	// QA-1-REG-2: A retained Private revocation tombstone blocks its old Private
	// host on Envoy while allowing an independent Private sibling listener to
	// build and keep forwarding cleanly in xDS.
	ginkgo.It("QA-1-REG-2: Private revocation tombstone keeps independent Private sibling forwarding", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "revoked.internal.example", "live.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"live.internal.example"}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		vnet := &v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "private-vnet", Namespace: ns},
			Spec:       v1alpha1.VirtualNetworkSpec{Name: "private-vnet", AccountRef: corev1.LocalObjectReference{Name: acct.Name}},
		}
		gomega.Expect(f.direct.Create(f.ctx, vnet)).To(gomega.Succeed())
		vnet.Status.VirtualNetworkID = "vnet-reg2"
		vnet.Status.ObservedGeneration = vnet.Generation
		vnet.Status.Conditions = []metav1.Condition{{
			Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue,
			Reason: "Accepted", ObservedGeneration: vnet.Generation, LastTransitionTime: metav1.Now(),
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, vnet)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "revoked-priv", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name}},
			{Name: "live-priv", Exposure: v1alpha1.ExposurePrivate, VirtualNetworkRef: &corev1.LocalObjectReference{Name: vnet.Name}},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		revokedHost := gatewayv1.Hostname("revoked.internal.example")
		liveHost := gatewayv1.Hostname("live.internal.example")
		gw.Spec.Listeners = []gatewayv1.Listener{
			gw.Spec.Listeners[0],
			{
				Name: "revoked-priv", Hostname: &revokedHost, Port: 8443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			},
			{
				Name: "live-priv", Hostname: &liveHost, Port: 9443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "listener-cert"}}},
			},
		}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())
		svcPort := gatewayv1.PortNumber(8080)
		pathType := gatewayv1.PathMatchPathPrefix
		liveSection := gatewayv1.SectionName("live-priv")
		liveRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "live-route", Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(f.gatewayKey.Name), SectionName: &liveSection}}},
				Hostnames:       []gatewayv1.Hostname{"live.internal.example"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &svcPort}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, liveRoute)).To(gomega.Succeed())

		// Pre-create ready HostnameRoutes for both Private listeners so live-priv
		// forwards while revoked-priv stays Blocked by its tombstone.
		for _, hrName := range []struct {
			name, host string
		}{
			{"hr-live", "live.internal.example"},
			{"hr-revoked", "revoked.internal.example"},
		} {
			hr := &v1alpha1.HostnameRoute{
				ObjectMeta: metav1.ObjectMeta{Name: hrName.name, Namespace: ns},
				Spec: v1alpha1.HostnameRouteSpec{
					AccountRef: corev1.LocalObjectReference{Name: acct.Name},
					Hostname:   hrName.host,
					TunnelRef:  v1alpha1.TunnelReference{Name: tunnel.Name},
				},
			}
			gomega.Expect(f.direct.Create(f.ctx, hr)).To(gomega.Succeed())
			hr.Status = v1alpha1.HostnameRouteStatus{
				RouteID:            "route-" + hrName.name,
				Hostname:           hrName.host,
				TunnelID:           tunnel.Status.TunnelID,
				ObservedGeneration: hr.Generation,
				Applied: v1alpha1.HostnameRouteAppliedStatus{
					Hostname:           hrName.host,
					TunnelID:           tunnel.Status.TunnelID,
					ObservedGeneration: hr.Generation,
				},
				Conditions: []metav1.Condition{{
					Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue,
					Reason: "Accepted", ObservedGeneration: hr.Generation, LastTransitionTime: metav1.Now(),
				}},
			}
			gomega.Expect(f.direct.Status().Update(f.ctx, hr)).To(gomega.Succeed())
		}

		// Deleting Private AccessApplication holding a non-reserved Private tombstone on revoked-priv (8443).
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "revoked-app",
				Namespace:  ns,
				Finalizers: []string{"flareway.bhyoo.com/access-application"},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("revoked-priv")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "revoked-app", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "revoked-priv",
			ProtectionDomain: "revoked-priv-access-default-revoked-app",
			EnvoyPort:        8443,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPrivate,
			Hostname: "revoked.internal.example",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())

		f.converge()

		f.snapshots.publisher.mu.RLock()
		snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
		f.snapshots.publisher.mu.RUnlock()
		gomega.Expect(snap).NotTo(gomega.BeNil())

		var sawRevoked403, sawLiveForward bool
		for _, res := range snap.GetResources(resourcev3.RouteType) {
			rc := res.(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				if slices.Contains(vh.GetDomains(), "revoked.internal.example") {
					if len(vh.GetRoutes()) > 0 && vh.GetRoutes()[0].GetDirectResponse().GetStatus() == 403 {
						sawRevoked403 = true
					}
				}
				if slices.Contains(vh.GetDomains(), "live.internal.example") {
					if len(vh.GetRoutes()) > 0 && vh.GetRoutes()[0].GetRoute() != nil {
						sawLiveForward = true
					}
				}
			}
		}
		gomega.Expect(sawRevoked403).To(gomega.BeTrue(), "revoked Private host must answer 403 locally")
		gomega.Expect(sawLiveForward).To(gomega.BeTrue(), "independent Private sibling host must continue forwarding")
	})

	// Finding 2 (v0.5.0 upgrade): When a Gateway's sole Private listener moves
	// onto a newly reserved port (18000 -> Accepted=False/PortUnavailable) while
	// holding a pre-upgrade Forwarding checkpoint, the Gateway must first retract
	// and wait for its dataplane Deployment to drain before clearing Forwarding,
	// acknowledging GuardBlocked, and letting deleting AccessApplication finish.
	ginkgo.It("Finding 2: sole reserved-port Private listener waits for dataplane drain then converges Access revocation", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"sole.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		// Make the sole listener a Private HTTPS listener on reserved port 18000.
		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		soleHost := gatewayv1.Hostname("sole.internal.example")
		privListener := gw.Spec.Listeners[1]
		privListener.Hostname = &soleHost
		privListener.Port = 18000
		gw.Spec.Listeners = []gatewayv1.Listener{privListener}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		// Seed pre-upgrade dataplane Deployment running 1 ready replica owned by gw.
		one := int32(1)
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      dataplane.ResourceName(&ir.Gateway{Key: f.gatewayKey}),
				Namespace: ns,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &one,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "sole"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "sole"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "envoyproxy/envoy:v1.32.0"}}},
				},
			},
		}
		gomega.Expect(ctrl.SetControllerReference(&gw, deploy, f.direct.Scheme())).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, deploy)).To(gomega.Succeed())
		deploy.Status.Replicas = 1
		deploy.Status.ReadyReplicas = 1
		gomega.Expect(f.direct.Status().Update(f.ctx, deploy)).To(gomega.Succeed())

		// Seed pre-upgrade converged Tunnel status with Forwarding checkpoint on 18000.
		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
			Desired: 1, Applied: 1, Remote: 1,
		}
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:          "sole.internal.example",
			ProtectionDomain:  "private-access-default-sole-app",
			AccessApplication: ns + "/sole-app",
			Guard:             v1alpha1.HostnameGuardForwarding,
			AppliedVersion:    1,
		}}
		tunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "private",
			Exposure: v1alpha1.ExposurePrivate,
			Binding:  v1alpha1.ListenerBindingLoopback,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
				Name: "private-access-default-sole-app", EnvoyPort: 18000, Protected: true,
			}},
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel)).To(gomega.Succeed())

		// Deleting AccessApplication with pre-upgrade latch at baselineVersion=1.
		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "private-access-default-sole-app",
				Hostname:         "sole.internal.example",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "sole-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("private")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "sole-app", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "private",
			ProtectionDomain: "private-access-default-sole-app",
			EnvoyPort:        18000,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPrivate,
			Hostname: "sole.internal.example",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())

		// Reconcile Gateway while Deployment still has Status.ReadyReplicas=1:
		// Deployment must be scaled to Spec.Replicas=0, snapshot cleared,
		// Gateway Accepted=False/PortUnavailable, RequeueAfter > 0, and
		// tunnel.Status.Hostnames must NOT yet drop Forwarding/claim Blocked.
		res, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.BeNumerically(">", 0))

		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(deploy), deploy)).To(gomega.Succeed())
		gomega.Expect(deploy.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*deploy.Spec.Replicas).To(gomega.Equal(int32(0)))

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Hostnames).To(gomega.HaveLen(1))
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardForwarding))

		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		privLS := listenerStatusByName(gw.Status.Listeners, "private")
		gomega.Expect(privLS).NotTo(gomega.BeNil())
		privAcc := meta.FindStatusCondition(privLS.Conditions, string(gatewayv1.ListenerConditionAccepted))
		gomega.Expect(privAcc.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(privAcc.Reason).To(gomega.Equal(string(gatewayv1.ListenerReasonPortUnavailable)))

		// Remove fixture's running dataplane-0 Pod so subsequent assertions isolate
		// Deployment TerminatingReplicas, stale ObservedGeneration, and terminatingPod.
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		// Simulate Deployment with TerminatingReplicas=1 even though Replicas=0 and ReadyReplicas=0:
		// drain must STILL wait because a terminating Envoy Pod can keep serving traffic.
		termOne := int32(1)
		deploy.Status.ObservedGeneration = deploy.Generation
		deploy.Status.Replicas = 0
		deploy.Status.ReadyReplicas = 0
		deploy.Status.TerminatingReplicas = &termOne
		gomega.Expect(f.direct.Status().Update(f.ctx, deploy)).To(gomega.Succeed())

		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.BeNumerically(">", 0))
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardForwarding))

		// Simulate stale ObservedGeneration < deploy.Generation with all replica counts 0:
		// drain must NOT rely on unacknowledged status counts.
		termZero := int32(0)
		deploy.Status.ObservedGeneration = deploy.Generation - 1
		deploy.Status.TerminatingReplicas = &termZero
		gomega.Expect(f.direct.Status().Update(f.ctx, deploy)).To(gomega.Succeed())

		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.BeNumerically(">", 0))
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardForwarding))

		// Even with Deployment fully at 0 and ObservedGeneration up to date, a
		// terminating non-Succeeded/non-Failed dataplane Pod must still block
		// Blocked acknowledgment until terminated.
		deploy.Status.ObservedGeneration = deploy.Generation
		gomega.Expect(f.direct.Status().Update(f.ctx, deploy)).To(gomega.Succeed())
		terminatingPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "envoy-terminating",
				Namespace:  ns,
				Finalizers: []string{"test.flareway.bhyoo.com/terminating"},
				Labels: map[string]string{
					dataplane.GatewayLabelKey:         dataplane.GatewayLabelValueForKey(ns, f.gatewayKey.Name),
					dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(f.gatewayKey.Name),
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "envoy", Image: "envoyproxy/envoy:v1.32.0"}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, terminatingPod)).To(gomega.Succeed())
		terminatingPod.Status.Phase = corev1.PodRunning
		gomega.Expect(f.direct.Status().Update(f.ctx, terminatingPod)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, terminatingPod)).To(gomega.Succeed())

		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.BeNumerically(">", 0))
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardForwarding))

		// Remove the terminating Pod finalizer so the Pod finishes disappearing,
		// then reconcile again: tunnel.Status.Hostnames must now transition from
		// Forwarding to Blocked.
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(terminatingPod), terminatingPod)).To(gomega.Succeed())
		terminatingPod.Finalizers = nil
		gomega.Expect(f.direct.Update(f.ctx, terminatingPod)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, client.ObjectKeyFromObject(terminatingPod), &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var sawBlocked, sawForwarding bool
		for _, h := range tunnel.Status.Hostnames {
			if h.Hostname == "sole.internal.example" {
				if h.Guard == v1alpha1.HostnameGuardBlocked {
					sawBlocked = true
				}
				if h.Guard == v1alpha1.HostnameGuardForwarding {
					sawForwarding = true
				}
			}
		}
		gomega.Expect(sawForwarding).To(gomega.BeFalse(), "stale Forwarding claim must be cleared once dataplane drains: %#v", tunnel.Status.Hostnames)
		gomega.Expect(sawBlocked).To(gomega.BeTrue(), "expected Blocked revocation status once dataplane drains: %#v", tunnel.Status.Hostnames)

		// AccessApplicationReconciler now converges and finishes deleting the AccessApplication.
		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		_, err = accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var deletedCheck v1alpha1.AccessApplication
		err = f.direct.Get(f.ctx, client.ObjectKeyFromObject(app), &deletedCheck)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "AccessApplication should finish deleting once sole rejected Gateway drains and acknowledges Blocked; err=%v", err)
	})

	// Finding 2A (interrupted Private rollout): Desired=2, Applied=1 on a sole
	// reserved-port Private listener must still converge Access revocation once the
	// dataplane is drained and GatewayInvalid is recorded on ConfigApplied.
	ginkgo.It("Finding 2A: interrupted Private rollout (Desired=2, Applied=1) converges Access revocation after drain", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"interrupted.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		soleHost := gatewayv1.Hostname("interrupted.internal.example")
		privListener := gw.Spec.Listeners[1]
		privListener.Hostname = &soleHost
		privListener.Port = 18000
		gw.Spec.Listeners = []gatewayv1.Listener{privListener}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
			Desired: 2, Applied: 1, Remote: 2,
		}
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:          "interrupted.internal.example",
			ProtectionDomain:  "private-access-default-interrupted-app",
			AccessApplication: ns + "/interrupted-app",
			Guard:             v1alpha1.HostnameGuardForwarding,
			AppliedVersion:    1,
		}}
		tunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "private",
			Exposure: v1alpha1.ExposurePrivate,
			Binding:  v1alpha1.ListenerBindingLoopback,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
				Name: "private-access-default-interrupted-app", EnvoyPort: 18000, Protected: true,
			}},
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel)).To(gomega.Succeed())

		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "private-access-default-interrupted-app",
				Hostname:         "interrupted.internal.example",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "interrupted-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("private")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "interrupted-app", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "private",
			ProtectionDomain: "private-access-default-interrupted-app",
			EnvoyPort:        18000,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPrivate,
			Hostname: "interrupted.internal.example",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())
		// Simulate already-drained dataplane (no running dataplane-0 Pod).
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		// Must not fabricate Desired == Applied for unpushed desired config; stays 2/1.
		gomega.Expect(tunnel.Status.ConfigVersion.Desired).To(gomega.Equal(int64(2)))
		gomega.Expect(tunnel.Status.ConfigVersion.Applied).To(gomega.Equal(int64(1)))
		gomega.Expect(tunnel.Status.Hostnames).To(gomega.HaveLen(1))
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardBlocked))

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		_, err = accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var deletedCheck v1alpha1.AccessApplication
		err = f.direct.Get(f.ctx, client.ObjectKeyFromObject(app), &deletedCheck)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "AccessApplication should finish deleting on drained GatewayInvalid interrupted Private rollout; err=%v", err)
	})

	// Finding 2B: Sole Public rejected listener (Desired=Applied=1, BaselineVersion=1)
	// pushes genuine deny-only remote Cloudflare config (version 2) once dataplane
	// is drained, publishes Blocked@2, converges Access cleanup, and does 0 remote
	// updates on subsequent steady-state reconciles.
	ginkgo.It("Finding 2B: sole Public rejected listener pushes deny-only remote config and converges Access revocation", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())

		// Make the sole Public listener invalid (ungranted hostname) -> Gateway Accepted=False.
		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		gw.Spec.Listeners = []gatewayv1.Listener{{
			Name:     "http",
			Hostname: new(gatewayv1.Hostname("ungranted.example.com")),
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		}}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		f.remote.remoteVersion = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
			Desired: 1, Applied: 1, Remote: 1,
		}
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:          "edge-a.example.com",
			ProtectionDomain:  "http-access-default-pub-app-a1b2c3d4",
			AccessApplication: ns + "/pub-app",
			Guard:             v1alpha1.HostnameGuardForwarding,
			AppliedVersion:    1,
		}}
		tunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "http",
			Exposure: v1alpha1.ExposurePublic,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
				Name: "http-access-default-pub-app-a1b2c3d4", EnvoyPort: 18080, Protected: true,
			}},
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel)).To(gomega.Succeed())

		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "http-access-default-pub-app-a1b2c3d4",
				Hostname:         "edge-a.example.com",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pub-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("http")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "pub-app", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "http",
			ProtectionDomain: "http-access-default-pub-app-a1b2c3d4",
			EnvoyPort:        18080,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPublic,
			Hostname: "edge-a.example.com",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())
		// Simulate already-drained dataplane (no running dataplane-0 Pod).
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "expected genuine deny-only Cloudflare push")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.ConfigVersion.Desired).To(gomega.Equal(int64(2)))
		gomega.Expect(tunnel.Status.ConfigVersion.Applied).To(gomega.Equal(int64(2)))
		gomega.Expect(tunnel.Status.Hostnames).To(gomega.HaveLen(1))
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardBlocked))
		gomega.Expect(tunnel.Status.Hostnames[0].AppliedVersion).To(gomega.Equal(int64(2)))

		// Second steady-state Gateway reconcile makes 0 remote updates.
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "steady-state rejected Gateway must not repeat remote updates")

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		_, err = accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var deletedCheck v1alpha1.AccessApplication
		err = f.direct.Get(f.ctx, client.ObjectKeyFromObject(app), &deletedCheck)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "sole Public rejected AccessApplication should finish deleting after deny-only push; err=%v", err)
	})

	// Finding 2C: A rejected Public listener with retained Public revocation
	// must keep the freshness gate active (0 remote reads/writes and 0 status
	// writes + non-zero freshness RequeueAfter when fresh) and still detect and
	// handle out-of-band remote drift under both Overwrite and Hold policies
	// when the freshness TTL expires or is invalidated.
	ginkgo.It("Finding 2C: rejected Public listener keeps freshness requeue and repairs or holds out-of-band drift", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		f.reconciler.Freshness = freshness.DefaultPolicy()
		f.reconciler.Invalidator = freshness.NewLatch()
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		gw.Spec.Listeners = []gatewayv1.Listener{{
			Name:     "http",
			Hostname: new(gatewayv1.Hostname("ungranted.example.com")),
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		}}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		f.remote.remoteVersion = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
			Desired: 1, Applied: 1, Remote: 1,
		}
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:          "edge-a.example.com",
			ProtectionDomain:  "http-access-default-pub-drift-app",
			AccessApplication: ns + "/pub-drift-app",
			Guard:             v1alpha1.HostnameGuardForwarding,
			AppliedVersion:    1,
		}}
		tunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "http",
			Exposure: v1alpha1.ExposurePublic,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
				Name: "http-access-default-pub-drift-app", EnvoyPort: 18080, Protected: true,
			}},
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel)).To(gomega.Succeed())

		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "http-access-default-pub-drift-app",
				Hostname:         "edge-a.example.com",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pub-drift-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("http")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "pub-drift-app", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "http",
			ProtectionDomain: "http-access-default-pub-drift-app",
			EnvoyPort:        18080,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPublic,
			Hostname: "edge-a.example.com",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		statusCounter := &tunnelStatusWriteCounterClient{Client: f.reconciler.Client, tunnelName: f.tunnelKey.Name}
		f.reconciler.Client = statusCounter

		// Initial deny-only push -> v2 + freshness requeue horizon.
		res, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(1))
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(f.reconciler.Freshness.Traffic), "initial rejected Public push must return freshness requeue horizon")

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		rvAfterPush := tunnel.ResourceVersion
		locksAfterPush := f.remote.locks
		writesAfterPush := statusCounter.writes.Load()

		// Immediate steady-state reconcile while gate is fresh: 0 remote locks/writes,
		// 0 status write requests on tunnel, non-zero freshness RequeueAfter.
		f.clock = f.clock.Add(30 * time.Second)
		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.locks).To(gomega.Equal(locksAfterPush), "fresh gate must skip remote reads")
		gomega.Expect(f.remote.updates).To(gomega.Equal(1))
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesAfterPush), "fresh steady-state reconcile must emit 0 CloudflareTunnel/status write requests")
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(f.reconciler.Freshness.Traffic-30*time.Second), "fresh steady-state reconcile must keep freshness requeue")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.ResourceVersion).To(gomega.Equal(rvAfterPush), "fresh steady-state reconcile must make 0 tunnel status writes")

		// Advance clock past TTL and simulate out-of-band remote bump to v3:
		// default Overwrite policy must detect drift and repair to deny-only v4.
		f.clock = f.clock.Add(6 * time.Minute)
		f.remote.remoteVersion = 3
		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(2), "expired gate with remote drift must re-apply deny-only config")
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(f.reconciler.Freshness.Traffic))

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.ConfigVersion.Applied).To(gomega.Equal(int64(4)))
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardBlocked))
		gomega.Expect(tunnel.Status.Hostnames[0].AppliedVersion).To(gomega.Equal(int64(4)))
		driftCond := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDriftDetected)
		gomega.Expect(driftCond).NotTo(gomega.BeNil())
		gomega.Expect(driftCond.Status).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(driftCond.Reason).To(gomega.Equal("OutOfBandChangeDetected"))

		// Switch to DriftPolicyHold, invalidate freshness latch, and bump remote to v5:
		// must detect drift WITHOUT overwriting remote and surface DriftHold.
		f.reconciler.DriftPolicy = DriftPolicyHold
		f.reconciler.Invalidator.Invalidate("CloudflareTunnelConfig", f.tunnelKey, "sweep detected version drift")
		f.remote.remoteVersion = 5
		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(2), "DriftPolicyHold must not overwrite remote")
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(programmedRequeue))

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.ConfigVersion.Remote).To(gomega.Equal(int64(5)))
		gomega.Expect(tunnel.Status.ConfigVersion.Applied).To(gomega.Equal(int64(4)))
		gomega.Expect(tunnel.Status.Hostnames[0].Guard).To(gomega.Equal(v1alpha1.HostnameGuardBlocked))
		appliedCond := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(appliedCond).NotTo(gomega.BeNil())
		gomega.Expect(appliedCond.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(appliedCond.Reason).To(gomega.Equal("DriftHold"))

		// Repeated unchanged DriftHold reconcile must emit 0 CloudflareTunnel/status write requests.
		writesBeforeRepeatHold := statusCounter.writes.Load()
		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(programmedRequeue))
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeRepeatHold), "repeated unchanged DriftHold reconcile must emit 0 CloudflareTunnel/status write requests")

		// Zero-TTL (--freshness-traffic=0) with matching remote must synchronize
		// once and then emit 0 CloudflareTunnel/status write requests on repeats.
		f.reconciler.Freshness = freshness.Policy{}
		f.reconciler.DriftPolicy = ""
		f.remote.remoteVersion = 4
		res, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(time.Duration(0)))

		writesBeforeZeroTTL := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeZeroTTL), "repeated unchanged --freshness-traffic=0 reconcile must emit 0 CloudflareTunnel/status write requests")

		// ADR 0004 regression 1: legacy-only condition ownership with identical
		// condition values must still migrate to flareway-tunnel-status in 1 write,
		// then settle to 0 writes on the next pass.
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		existingDegraded := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded)
		gomega.Expect(existingDegraded).NotTo(gomega.BeNil())
		keptWithoutDegraded := make([]metav1.Condition, 0, len(tunnel.Status.Conditions))
		for _, cond := range tunnel.Status.Conditions {
			if cond.Type != v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded {
				keptWithoutDegraded = append(keptWithoutDegraded, cond)
			}
		}
		applyTunnelConditions(f.direct, f.tunnelKey, tunnelStatusFieldManager, keptWithoutDegraded...)
		applyTunnelConditions(f.direct, f.tunnelKey, "legacy-tunnel-controller", *existingDegraded)
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnelConditionOwners(&tunnel)[v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded]).To(gomega.Equal([]string{"legacy-tunnel-controller"}))

		writesBeforeMigrate := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeMigrate+1), "legacy-only condition ownership must migrate in exactly 1 condition write")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnelConditionOwners(&tunnel)[v1alpha1.CloudflareTunnelConditionPrivateListenerDegraded]).To(gomega.ContainElement(tunnelStatusFieldManager))

		writesAfterMigrate := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesAfterMigrate), "post-migration steady-state reconcile must emit 0 status writes")

		// ADR 0004 regression 2: torn Ready=True alongside ConfigApplied=False
		// must clamp Ready back to False in 1 write, then settle to 0 writes.
		applyTunnelConditions(f.direct, f.tunnelKey, "legacy-tunnel-controller",
			tunnelCondition(v1alpha1.CloudflareTunnelConditionReady, metav1.ConditionTrue, "Ready", "torn ready", tunnel.Generation, metav1.NewTime(f.clock)))
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady).Status).To(gomega.Equal(metav1.ConditionTrue))

		writesBeforeClamp := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeClamp+1), "torn Ready=True over ConfigApplied=False must clamp in exactly 1 condition write")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		readyCond := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)
		gomega.Expect(readyCond).NotTo(gomega.BeNil())
		gomega.Expect(readyCond.Status).To(gomega.Equal(metav1.ConditionFalse))

		writesAfterClamp := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesAfterClamp), "post-clamp steady-state reconcile must emit 0 status writes")

		applyTunnelStatusUnstructured := func(manager string, status map[string]any) {
			u := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": v1alpha1.GroupVersion.String(),
				"kind":       "CloudflareTunnel",
				"metadata":   map[string]any{"name": f.tunnelKey.Name, "namespace": f.tunnelKey.Namespace},
				"status":     status,
			}}
			gomega.Expect(f.direct.Status().Apply(f.ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(manager), client.ForceOwnership)).To(gomega.Succeed())
		}
		assertRecoverInOneWrite := func(desc string) {
			before := statusCounter.writes.Load()
			_, recErr := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(recErr).NotTo(gomega.HaveOccurred())
			gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(before+1), "%s: first reconcile must emit 1 write to recover ownership", desc)

			after := statusCounter.writes.Load()
			_, recErr = f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(recErr).NotTo(gomega.HaveOccurred())
			gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(after), "%s: second reconcile must emit 0 writes", desc)
		}

		// Leaf ownership loss 1: configVersion.remote owned solely by alternate manager with identical value 4.
		applyTunnelStatusUnstructured("other-status-manager", map[string]any{"configVersion": map[string]any{"remote": int64(99)}})
		applyTunnelStatusUnstructured("other-status-manager", map[string]any{"configVersion": map[string]any{"remote": int64(4)}})
		assertRecoverInOneWrite("configVersion.remote leaf ownership loss")

		// Leaf ownership loss 2: hostnames[composite key].appliedVersion owned solely by alternate manager with identical value 4.
		hostLeaf := func(ver int64) map[string]any {
			return map[string]any{
				"hostnames": []any{map[string]any{
					"hostname":          "edge-a.example.com",
					"protectionDomain":  "http-access-default-pub-drift-app",
					"accessApplication": ns + "/pub-drift-app",
					"guard":             "Blocked",
					"appliedVersion":    ver,
				}},
			}
		}
		applyTunnelStatusUnstructured("other-status-manager", hostLeaf(99))
		applyTunnelStatusUnstructured("other-status-manager", hostLeaf(4))
		assertRecoverInOneWrite("hostnames[].appliedVersion leaf ownership loss")

		// Leaf ownership loss 3: listeners[name].protectionDomains[name].envoyPort owned solely by alternate manager with identical value 18080.
		listenerLeaf := func(port int64) map[string]any {
			return map[string]any{
				"listeners": []any{map[string]any{
					"name":     "http",
					"exposure": "Public",
					"protectionDomains": []any{map[string]any{
						"name":      "http-access-default-pub-drift-app",
						"envoyPort": port,
						"protected": true,
					}},
				}},
			}
		}
		applyTunnelStatusUnstructured("other-status-manager", listenerLeaf(19999))
		applyTunnelStatusUnstructured("other-status-manager", listenerLeaf(18080))
		assertRecoverInOneWrite("listeners[].protectionDomains[].envoyPort leaf ownership loss")

		// Legacy f:conditions co-ownership on flareway-gateway status ManagedFields must be shed in 1 apply.
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnelDataObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&v1alpha1.CloudflareTunnelStatus{
			ConfigVersion: tunnel.Status.ConfigVersion,
			Hostnames:     tunnel.Status.Hostnames,
			Listeners:     tunnel.Status.Listeners,
			Conditions:    tunnel.Status.Conditions,
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		applyTunnelStatusUnstructured(gatewayFieldManager, tunnelDataObj)
		assertRecoverInOneWrite("legacy f:conditions on flareway-gateway status ManagedFields")

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		for _, entry := range tunnel.ManagedFields {
			if entry.Manager != gatewayFieldManager || entry.Subresource != "status" || entry.Operation != metav1.ManagedFieldsOperationApply || entry.FieldsV1 == nil {
				continue
			}
			var fields map[string]any
			gomega.Expect(json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields)).To(gomega.Succeed())
			statusMap, _ := fields["f:status"].(map[string]any)
			_, hasConditions := statusMap["f:conditions"]
			gomega.Expect(hasConditions).To(gomega.BeFalse(), "flareway-gateway status Apply ManagedFields must shed f:conditions")
		}

		// ADR 0004 Line 100: A lingering Status().Update entry under flareway-gateway
		// owning f:conditions alongside shared flareway-tunnel-status condition ownership
		// and flareway-gateway Apply data ownership must NOT force status writes.
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.Conditions = append(tunnel.Status.Conditions, metav1.Condition{
			Type:               "LegacyUpdateCoOwner",
			Status:             metav1.ConditionTrue,
			Reason:             "Legacy",
			Message:            "lingering Status().Update co-owner entry",
			ObservedGeneration: tunnel.Generation,
			LastTransitionTime: metav1.NewTime(f.clock),
		})
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel, client.FieldOwner(gatewayFieldManager))).To(gomega.Succeed())

		hasGatewayUpdateConditions := func(obj *v1alpha1.CloudflareTunnel) bool {
			for _, entry := range obj.ManagedFields {
				if entry.Manager != gatewayFieldManager || entry.Subresource != "status" || entry.Operation != metav1.ManagedFieldsOperationUpdate || entry.FieldsV1 == nil {
					continue
				}
				var fields map[string]any
				if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
					continue
				}
				statusMap, _ := fields["f:status"].(map[string]any)
				if _, ok := statusMap["f:conditions"]; ok {
					return true
				}
			}
			return false
		}
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(hasGatewayUpdateConditions(&tunnel)).To(gomega.BeTrue(), "Status().Update must record flareway-gateway Update entry owning f:conditions")

		writesBeforeUpdateCoOwner := statusCounter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeUpdateCoOwner), "lingering Status().Update f:conditions entry must emit 0 status writes")
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(statusCounter.writes.Load()).To(gomega.Equal(writesBeforeUpdateCoOwner), "repeated reconcile with lingering Status().Update f:conditions entry must emit 0 status writes")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(hasGatewayUpdateConditions(&tunnel)).To(gomega.BeTrue(), "Status().Update f:conditions entry remains intact")

		// Case 5: Non-status subresource (Subresource == "") ownership is ignored so missing
		// status Apply ownership converges 1 -> 0; note Kubernetes omits empty hostnames/listeners
		// from FieldsV1 even on an explicit [] apply (leaving f:configVersion under f:status),
		// and nonempty -> empty transitions still take 1 write to clear both slices -> 0 writes.
		emptyTunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "empty-list-tunnel", Namespace: ns},
			Spec:       tunnel.Spec,
		}
		gomega.Expect(f.direct.Create(f.ctx, emptyTunnel)).To(gomega.Succeed())
		mainMetaApply := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": v1alpha1.GroupVersion.String(),
			"kind":       "CloudflareTunnel",
			"metadata": map[string]any{
				"name":      emptyTunnel.Name,
				"namespace": ns,
				"labels":    map[string]any{"flareway.test/non-status": "true"},
			},
		}}
		gomega.Expect(f.direct.Apply(f.ctx, client.ApplyConfigurationFromUnstructured(mainMetaApply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)).To(gomega.Succeed())
		otherEmptyStatus := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": v1alpha1.GroupVersion.String(),
			"kind":       "CloudflareTunnel",
			"metadata":   map[string]any{"name": emptyTunnel.Name, "namespace": ns},
			"status": map[string]any{
				"tunnelId":                "empty-tunnel-id",
				"accountId":               tunnel.Status.AccountID,
				"ownershipVerified":       true,
				"gatewayRef":              map[string]any{"name": f.gatewayKey.Name},
				"gatewayUid":              string(gw.UID),
				"connectorTokenSecretRef": map[string]any{"name": tunnel.Status.ConnectorTokenSecretRef.Name},
				"hostnames":               []any{},
				"listeners":               []any{},
			},
		}}
		gomega.Expect(f.direct.Status().Apply(f.ctx, client.ApplyConfigurationFromUnstructured(otherEmptyStatus), client.FieldOwner("other-status-manager"), client.ForceOwnership)).To(gomega.Succeed())

		emptyCounter := &tunnelStatusWriteCounterClient{Client: f.direct, tunnelName: emptyTunnel.Name}
		emptyWriter := &GatewayReconciler{Client: emptyCounter, APIReader: f.direct, Scheme: f.direct.Scheme()}
		irEmpty := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(emptyTunnel), emptyTunnel)).To(gomega.Succeed())

		// Make gw reference emptyTunnel temporarily so validateGatewayTunnelWriter passes.
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		origParamName := gw.Spec.Infrastructure.ParametersRef.Name
		gw.Spec.Infrastructure.ParametersRef.Name = emptyTunnel.Name
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())
		defer func() {
			var cur gatewayv1.Gateway
			if getErr := f.direct.Get(f.ctx, f.gatewayKey, &cur); getErr == nil {
				cur.Spec.Infrastructure.ParametersRef.Name = origParamName
				_ = f.direct.Update(f.ctx, &cur)
			}
		}()

		gomega.Expect(emptyWriter.patchTunnelGatewayData(f.ctx, irEmpty, emptyTunnel, v1alpha1.CloudflareTunnelConfigVersion{}, nil, nil)).To(gomega.Succeed())
		gomega.Expect(emptyCounter.writes.Load()).To(gomega.Equal(int64(1)), "missing status Apply ownership must trigger 1 write even when non-status ManagedFields exists")
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(emptyTunnel), emptyTunnel)).To(gomega.Succeed())
		gomega.Expect(emptyWriter.patchTunnelGatewayData(f.ctx, irEmpty, emptyTunnel, v1alpha1.CloudflareTunnelConfigVersion{}, nil, nil)).To(gomega.Succeed())
		gomega.Expect(emptyCounter.writes.Load()).To(gomega.Equal(int64(1)), "steady-state empty lists + zeroed ConfigVersion must emit 0 writes")

		// Nonempty -> empty clear transition on real API server: 1 write populates nonempty,
		// 1 write clears both hostnames and listeners to [], and follow-up unchanged pass emits 0 writes.
		populatedHostnames := []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:         "clear-me.example.com",
			ProtectionDomain: "http-unprotected",
			Guard:            v1alpha1.HostnameGuardUnprotected,
		}}
		populatedListeners := []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "http",
			Exposure: v1alpha1.ExposurePublic,
		}}
		gomega.Expect(emptyWriter.patchTunnelGatewayData(f.ctx, irEmpty, emptyTunnel, v1alpha1.CloudflareTunnelConfigVersion{}, populatedHostnames, populatedListeners)).To(gomega.Succeed())
		gomega.Expect(emptyCounter.writes.Load()).To(gomega.Equal(int64(2)), "populating hostnames and listeners must emit 1 write")
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(emptyTunnel), emptyTunnel)).To(gomega.Succeed())
		gomega.Expect(emptyTunnel.Status.Hostnames).To(gomega.HaveLen(1))
		gomega.Expect(emptyTunnel.Status.Listeners).To(gomega.HaveLen(1))

		gomega.Expect(emptyWriter.patchTunnelGatewayData(f.ctx, irEmpty, emptyTunnel, v1alpha1.CloudflareTunnelConfigVersion{}, nil, nil)).To(gomega.Succeed())
		gomega.Expect(emptyCounter.writes.Load()).To(gomega.Equal(int64(3)), "transitioning nonempty hostnames and listeners to empty must emit 1 write")
		gomega.Expect(f.direct.Get(f.ctx, client.ObjectKeyFromObject(emptyTunnel), emptyTunnel)).To(gomega.Succeed())
		gomega.Expect(emptyTunnel.Status.Hostnames).To(gomega.BeEmpty())
		gomega.Expect(emptyTunnel.Status.Listeners).To(gomega.BeEmpty())

		gomega.Expect(emptyWriter.patchTunnelGatewayData(f.ctx, irEmpty, emptyTunnel, v1alpha1.CloudflareTunnelConfigVersion{}, nil, nil)).To(gomega.Succeed())
		gomega.Expect(emptyCounter.writes.Load()).To(gomega.Equal(int64(3)), "follow-up unchanged pass after clearing to empty must emit 0 writes")
	})

	// #4722620743: After a drained Private interrupted rollout writes Blocked and
	// ConfigApplied=False/GatewayInvalid at Gen 1, a Tunnel spec edit bumping
	// Tunnel.Generation -> Gen 2 (without changing hostnames or listeners) must
	// refresh ConfigApplied.ObservedGeneration -> 2 in 1 write -> 0 on repeat so
	// AccessApplication finishes revocation.
	ginkgo.It("Finding 2D: interrupted Private rollout refreshes ConfigApplied=False/GatewayInvalid on Tunnel generation bump", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"genbump.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		soleHost := gatewayv1.Hostname("genbump.internal.example")
		privListener := gw.Spec.Listeners[1]
		privListener.Hostname = &soleHost
		privListener.Port = 18000
		gw.Spec.Listeners = []gatewayv1.Listener{privListener}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		tunnel.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{
			Desired: 2, Applied: 1, Remote: 2,
		}
		tunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname:          "genbump.internal.example",
			ProtectionDomain:  "private-access-default-genbump-app",
			AccessApplication: ns + "/genbump-app",
			Guard:             v1alpha1.HostnameGuardForwarding,
			AppliedVersion:    1,
		}}
		tunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "private",
			Exposure: v1alpha1.ExposurePrivate,
			Binding:  v1alpha1.ListenerBindingLoopback,
			ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
				Name: "private-access-default-genbump-app", EnvoyPort: 18000, Protected: true,
			}},
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, &tunnel)).To(gomega.Succeed())

		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "private-access-default-genbump-app",
				Hostname:         "genbump.internal.example",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "genbump-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("private")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "genbump-app", SessionDuration: "1h"},
				OriginJWT:   v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired, AssumeGatewayTLSDecryption: true},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())
		app.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel:           tunnel.Name,
			Listener:         "private",
			ProtectionDomain: "private-access-default-genbump-app",
			EnvoyPort:        18000,
		}}
		app.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type:     v1alpha1.AccessApplicationDestinationPrivate,
			Hostname: "genbump.internal.example",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, app)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		counter := &tunnelStatusWriteCounterClient{Client: f.direct, tunnelName: tunnel.Name}
		f.reconciler.Client = counter
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		genBefore := tunnel.Generation
		cfgCond := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(cfgCond).NotTo(gomega.BeNil())
		gomega.Expect(cfgCond.Reason).To(gomega.Equal("GatewayInvalid"))
		gomega.Expect(cfgCond.ObservedGeneration).To(gomega.Equal(genBefore))

		// DNS-only Tunnel spec edit bumps Generation while hostnames/listeners stay equal.
		tunnel.Spec.DNS.Mode = v1alpha1.DNSModeManaged
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Generation).To(gomega.BeNumerically(">", genBefore))

		writesBeforeGenBump := counter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(counter.writes.Load()).To(gomega.Equal(writesBeforeGenBump+1), "Tunnel generation bump must emit 1 condition write refreshing GatewayInvalid ObservedGeneration")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		cfgCond = meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(cfgCond).NotTo(gomega.BeNil())
		gomega.Expect(cfgCond.ObservedGeneration).To(gomega.Equal(tunnel.Generation))

		writesAfterGenBump := counter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(counter.writes.Load()).To(gomega.Equal(writesAfterGenBump), "steady-state after refreshing GatewayInvalid ObservedGeneration must emit 0 writes")

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		_, err = accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var deletedCheck v1alpha1.AccessApplication
		err = f.direct.Get(f.ctx, client.ObjectKeyFromObject(app), &deletedCheck)
		gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), "AccessApplication should finish deleting once ConfigApplied.ObservedGeneration catches up to Tunnel generation; err=%v", err)
	})

	// #4722620830: When an Unprotected PodIP Private listener without an Access
	// tombstone is rejected (e.g. reserved port 18000) while the Gateway syncs
	// a retained Public revocation claim, desiredTunnelListeners must preserve the
	// recorded PodIP binding as long as the listener stays configured as Private
	// on CloudflareTunnel.Spec.Listeners, while still clearing removed listeners.
	ginkgo.It("Finding 3: rejected Unprotected PodIP Private listener without Access tombstone preserves PodIP binding", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "pub.example.com", "priv.internal.example"}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"priv.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())

		// Pre-existing converged Gateway-owned Tunnel status: Public revocation claim on "http"
		// plus Unprotected PodIP Private listener "private" (and a removed Private
		// listener "stale-private" no longer in Spec.Listeners that must clear).
		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		f.remote.remoteVersion = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		seedWriter := &GatewayReconciler{Client: f.direct, APIReader: f.direct, Scheme: f.direct.Scheme()}
		seedIR := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(seedWriter.patchTunnelGatewayData(
			f.ctx, seedIR, &tunnel,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "old-hash", Applied: 1, Remote: 1},
			[]v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname:          "pub.example.com",
				ProtectionDomain:  "http-access-default-pub-app",
				AccessApplication: ns + "/pub-app",
				Guard:             v1alpha1.HostnameGuardForwarding,
				AppliedVersion:    1,
			}},
			[]v1alpha1.CloudflareTunnelListenerStatus{
				{
					Name: "http", Exposure: v1alpha1.ExposurePublic,
					ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{
						Name: "http-access-default-pub-app", EnvoyPort: 18080, Protected: true,
					}},
				},
				{
					Name:     "private",
					Exposure: v1alpha1.ExposurePrivate,
					Binding:  v1alpha1.ListenerBindingPodIP,
				},
				{
					Name:     "stale-private",
					Exposure: v1alpha1.ExposurePrivate,
					Binding:  v1alpha1.ListenerBindingPodIP,
				},
			},
		)).To(gomega.Succeed())

		rejectedPubHost := gatewayv1.Hostname("ungranted.example.com")
		privHost := gatewayv1.Hostname("priv.internal.example")
		gw.Spec.Listeners[0].Hostname = &rejectedPubHost // Reject "http" while retaining pub-app claim -> Gateway Accepted=False.
		gw.Spec.Listeners[1].Hostname = &privHost
		gw.Spec.Listeners[1].Port = 18000 // Temporarily reject Unprotected Private listener without Access tombstone.
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		// Retaining Public revocation claim on "http" while "private" is rejected.
		latchPayload, err := json.Marshal(gatewayapi.AccessRevocationLatch{
			Claims: []gatewayapi.AccessRevocationClaim{{
				Tunnel:           tunnel.Name,
				ProtectionDomain: "http-access-default-pub-app",
				Hostname:         "pub.example.com",
				BaselineVersion:  1,
			}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		pubApp := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pub-app",
				Namespace:   ns,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{gatewayapi.AccessRevocationAnnotation: string(latchPayload)},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gw.Name)},
					SectionName:                new(gatewayv1.SectionName("http")),
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "pub-app", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, pubApp)).To(gomega.Succeed())
		pubApp.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
			Tunnel: tunnel.Name, Listener: "http", ProtectionDomain: "http-access-default-pub-app", EnvoyPort: 18080,
		}}
		pubApp.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{
			Type: v1alpha1.AccessApplicationDestinationPublic, Hostname: "pub.example.com",
		}}
		gomega.Expect(f.direct.Status().Update(f.ctx, pubApp)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, pubApp)).To(gomega.Succeed())

		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: ns}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		acceptedCond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(acceptedCond).NotTo(gomega.BeNil())
		gomega.Expect(acceptedCond.Status).To(gomega.Equal(metav1.ConditionFalse), "Gateway must enter rejected syncRejectedGatewayTunnelRevocation path")

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var privStatus, staleStatus *v1alpha1.CloudflareTunnelListenerStatus
		for i := range tunnel.Status.Listeners {
			switch tunnel.Status.Listeners[i].Name {
			case "private":
				privStatus = &tunnel.Status.Listeners[i]
			case "stale-private":
				staleStatus = &tunnel.Status.Listeners[i]
			}
		}
		gomega.Expect(staleStatus).To(gomega.BeNil(), "removed Private listener absent from Spec.Listeners must clear cleanly; gwConds=%#v, tunnelStatus=%#v", gw.Status.Conditions, tunnel.Status)
		gomega.Expect(privStatus).NotTo(gomega.BeNil(), "rejected Private listener configured in Spec.Listeners must remain in Status.Listeners")
		gomega.Expect(privStatus.Exposure).To(gomega.Equal(v1alpha1.ExposurePrivate))
		gomega.Expect(privStatus.Binding).To(gomega.Equal(v1alpha1.ListenerBindingPodIP), "rejected Unprotected Private listener must preserve recorded PodIP binding")

		// Recover "http" to granted hostname and "private" back to supported port 8443:
		// must keep PodIP rather than reverting to Loopback.
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		grantedPubHost := gatewayv1.Hostname("pub.example.com")
		gw.Spec.Listeners[0].Hostname = &grantedPubHost
		gw.Spec.Listeners[1].Port = 8443
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		privStatus = nil
		for i := range tunnel.Status.Listeners {
			if tunnel.Status.Listeners[i].Name == "private" {
				privStatus = &tunnel.Status.Listeners[i]
				break
			}
		}
		gomega.Expect(privStatus).NotTo(gomega.BeNil())
		gomega.Expect(privStatus.Binding).To(gomega.Equal(v1alpha1.ListenerBindingPodIP), "recovered Private listener must stay PodIP instead of reverting to Loopback")
	})

	// Removing a rejected unprotected PodIP Private listener (no AccessApplication)
	// from CloudflareTunnel.Spec.Listeners while the Gateway stays Accepted=False
	// must clear the stale PodIP entry in Status.Listeners, then settle to 0 writes.
	ginkgo.It("Finding 3B: removing rejected unprotected PodIP Private listener from Spec.Listeners clears Status.Listeners when Gateway stays Accepted=False", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{
			privateListener: true,
		})

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"edge-a.example.com", "unprot.internal.example"}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"unprot.internal.example"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{
			{Name: "private", Exposure: v1alpha1.ExposurePrivate},
		}
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		_, tunnelErr := f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		privHost := gatewayv1.Hostname("unprot.internal.example")
		privListener := gw.Spec.Listeners[1]
		privListener.Hostname = &privHost
		privListener.Port = 8443
		gw.Spec.Listeners = []gatewayv1.Listener{privListener}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		// Seed previously published, unprotected PodIP Private listener (no AccessApplication).
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		seedWriter := &GatewayReconciler{Client: f.direct, APIReader: f.direct, Scheme: f.direct.Scheme()}
		seedIR := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(seedWriter.patchTunnelGatewayData(
			f.ctx, seedIR, &tunnel,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, Applied: 1, Remote: 1},
			[]v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname:         "unprot.internal.example",
				ProtectionDomain: "private",
				Guard:            v1alpha1.HostnameGuardUnprotected,
				AppliedVersion:   1,
			}},
			[]v1alpha1.CloudflareTunnelListenerStatus{{
				Name:     "private",
				Exposure: v1alpha1.ExposurePrivate,
				Binding:  v1alpha1.ListenerBindingPodIP,
			}},
		)).To(gomega.Succeed())

		// Move sole Private listener to reserved port 18000 (Accepted=False) and drain dataplane.
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		gw.Spec.Listeners[0].Port = 18000
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())
		gomega.Expect(f.direct.Delete(f.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dataplane-0", Namespace: f.gatewayKey.Namespace}})).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(f.direct.Get(f.ctx, types.NamespacedName{Namespace: f.gatewayKey.Namespace, Name: "dataplane-0"}, &corev1.Pod{}))
		}, 10*time.Second, 50*time.Millisecond).Should(gomega.BeTrue())

		// Pass 1: clears unprotected hostname while preserving PodIP in Status.Listeners.
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		acceptedCond := meta.FindStatusCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		gomega.Expect(acceptedCond).NotTo(gomega.BeNil())
		gomega.Expect(acceptedCond.Status).To(gomega.Equal(metav1.ConditionFalse))

		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Hostnames).To(gomega.BeEmpty())
		gomega.Expect(tunnel.Status.Listeners).To(gomega.Equal([]v1alpha1.CloudflareTunnelListenerStatus{{
			Name:     "private",
			Exposure: v1alpha1.ExposurePrivate,
			Binding:  v1alpha1.ListenerBindingPodIP,
		}}))

		// Pass 2 (unchanged): emits 0 status writes.
		counter := &tunnelStatusWriteCounterClient{Client: f.direct, tunnelName: tunnel.Name}
		f.reconciler.Client = counter
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(counter.writes.Load()).To(gomega.Equal(int64(0)))

		// Remove "private" from CloudflareTunnel.Spec.Listeners while Gateway stays Accepted=False.
		tunnel.Spec.Listeners = nil
		gomega.Expect(f.direct.Update(f.ctx, &tunnel)).To(gomega.Succeed())
		_, tunnelErr = f.tunnelReconciler.Reconcile(f.ctx, f.tunnelRequest)
		gomega.Expect(tunnelErr).NotTo(gomega.HaveOccurred())

		writesBeforeRemove := counter.writes.Load()
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Listeners).To(gomega.BeEmpty(), "removing Private listener from Spec.Listeners must clear Status.Listeners even when Gateway stays Accepted=False")
		writesAfterClear := counter.writes.Load()
		gomega.Expect(writesAfterClear).To(gomega.Equal(writesBeforeRemove+2), "expected 1 condition write (Gen bump) + 1 data write clearing Status.Listeners")

		// Two subsequent unchanged reconciles emit 0 Tunnel status writes.
		for range 2 {
			_, err = f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(counter.writes.Load()).To(gomega.Equal(writesAfterClear), "subsequent unchanged reconciles after clearing Status.Listeners must emit 0 writes")
		}
	})

	// #4723566864: During an in-place v0.5.0 upgrade on a wildcard Public listener
	// where base ("web") and carve-out ("web-public") shared 18080, keep the
	// shadow route on xDS port 18080 and "web-public: 18080" in Status.Listeners
	// while connector holds v1, while cloudflared targets ONLY the new port;
	// once connector ACKs v2 (Status.Hostnames drops "web-public"), a follow-up
	// reconcile removes ShadowOnly (403 on 18080), drops "web-public" from
	// Status.Listeners with 0 extra Cloudflare PUTs, and converges to 0 writes.
	ginkgo.It("Finding 4: upgrading v0.5.0 wildcard Public listener keeps legacy carve-out shadow on xDS until connector ACK without extra Cloudflare PUTs", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		wildHost := gatewayv1.Hostname("*.example.com")
		gw.Spec.Listeners = []gatewayv1.Listener{{
			Name: "web", Hostname: &wildHost, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
		}}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())
		pathType := gatewayv1.PathMatchPathPrefix
		adminRule := gatewayv1.SectionName("admin")
		healthRule := gatewayv1.SectionName("health")
		homeRule := gatewayv1.SectionName("home")
		port := gatewayv1.PortNumber(8080)
		routeA := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{"app.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Name:        &adminRule,
						Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
						BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
					},
					{
						Name:        &healthRule,
						Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/health")}}},
						BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
					},
				},
			},
		}
		routeB := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-b", Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{"other.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Name:        &homeRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, routeA)).To(gomega.Succeed())
		gomega.Expect(f.direct.Create(f.ctx, routeB)).To(gomega.Succeed())

		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "app-a", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: acct.Name},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "route-a"},
					SectionName:                &adminRule,
				}},
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-a", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		for range 2 {
			_, err := accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		// Seed v0.5.0 Tunnel status (web + web-public both recorded on 18080) and connector holding v1.
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: acct.Name}, &acct)).To(gomega.Succeed())
		var audSecret corev1.Secret
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{
			Namespace: accessApplicationAUDNamespace,
			Name:      accessAUDSecretName(app, f.gatewayKey),
		}, &audSecret)).To(gomega.Succeed())
		appDigest := accessBindingDigest(ir.ProtectionDomain{
			AccessApplication: ns + "/app-a",
			Protected:         true,
			Access: &ir.AccessGuard{
				AUDs:       []string{string(audSecret.Data["aud"])},
				TeamName:   acct.Status.Verified.TeamName,
				AuthDomain: acct.Status.Verified.AuthDomain,
			},
		})
		appHash := sha256.Sum256([]byte(ns + "/app-a\x00app.example.com"))
		appPD := "web-access-" + ns + "-app-a-" + hex.EncodeToString(appHash[:4])
		f.remote.remoteVersion = 1
		f.prober.version = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		seedWriter := &GatewayReconciler{Client: f.direct, APIReader: f.direct, Scheme: f.direct.Scheme()}
		seedIR := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(seedWriter.patchTunnelGatewayData(
			f.ctx, seedIR, &tunnel,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "v05-hash", Applied: 1, Remote: 1},
			[]v1alpha1.CloudflareTunnelHostnameStatus{
				{Hostname: "app.example.com", ProtectionDomain: "web-public", Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
				{Hostname: "app.example.com", ProtectionDomain: appPD, AccessApplication: ns + "/app-a", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
				{Hostname: "other.example.com", ProtectionDomain: "web", Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
			},
			[]v1alpha1.CloudflareTunnelListenerStatus{{
				Name:     "web",
				Exposure: v1alpha1.ExposurePublic,
				ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
					{Name: "web", EnvoyPort: 18080},
					{Name: "web-public", EnvoyPort: 18080},
				},
			}},
		)).To(gomega.Succeed())

		inspectPort18080 := func() (hasHealthRoute bool, has403Block bool) {
			f.snapshots.publisher.mu.RLock()
			snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
			f.snapshots.publisher.mu.RUnlock()
			gomega.Expect(snap).NotTo(gomega.BeNil(), "expected published xDS snapshot")
			var targetRoute string
			for _, res := range snap.GetResources(resourcev3.ListenerType) {
				l := res.(*listenerv3.Listener)
				if l.GetAddress().GetSocketAddress().GetPortValue() != 18080 {
					continue
				}
				for _, fc := range l.GetFilterChains() {
					for _, filter := range fc.GetFilters() {
						if filter.Name != "envoy.filters.network.http_connection_manager" {
							continue
						}
						var hcm hcmv3.HttpConnectionManager
						if err := filter.GetTypedConfig().UnmarshalTo(&hcm); err == nil {
							if rdsName := hcm.GetRds().GetRouteConfigName(); rdsName != "" {
								targetRoute = rdsName
							}
						}
					}
				}
			}
			gomega.Expect(targetRoute).NotTo(gomega.BeEmpty(), "expected listener on 18080")
			rc := snap.GetResources(resourcev3.RouteType)[targetRoute].(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				if !slices.Contains(vh.GetDomains(), "app.example.com") {
					continue
				}
				for _, route := range vh.GetRoutes() {
					if route.GetDirectResponse() != nil && route.GetDirectResponse().GetStatus() == 403 {
						has403Block = true
					}
					if route.GetMatch().GetPathSeparatedPrefix() == "/health" && route.GetRoute() != nil {
						hasHealthRoute = true
					}
				}
			}
			return hasHealthRoute, has403Block
		}

		listenerPDPort := func(tObj *v1alpha1.CloudflareTunnel, pdName string) (int32, bool) {
			for _, ls := range tObj.Status.Listeners {
				if ls.Name != "web" {
					continue
				}
				for _, pd := range ls.ProtectionDomains {
					if pd.Name == pdName {
						return pd.EnvoyPort, true
					}
				}
			}
			return 0, false
		}

		// Reconcile 1 & 2 while connector still holds v1:
		// xDS port 18080 must keep /health (no 403), Status.Listeners keeps web-public:18080,
		// and cloudflared puts only 1 config update targeting ONLY the new port.
		for range 2 {
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
			hasHealth, has403 := inspectPort18080()
			gomega.Expect(hasHealth).To(gomega.BeTrue(), "while connector holds v1, 18080 must keep /health shadow route")
			gomega.Expect(has403).To(gomega.BeFalse(), "while connector holds v1, 18080 must NOT 403 app.example.com")
		}
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "expected exactly 1 Cloudflare configuration update during v1 rollout")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		basePort, hasBasePD := listenerPDPort(&tunnel, "web")
		gomega.Expect(hasBasePD).To(gomega.BeTrue(), "Case A Status.Listeners must retain base web:18080")
		gomega.Expect(basePort).To(gomega.Equal(int32(18080)))
		_, hasLegacyPD := listenerPDPort(&tunnel, "web-public")
		gomega.Expect(hasLegacyPD).To(gomega.BeFalse(), "Case A Status.Listeners must omit duplicate ShadowOnly web-public when base web already records 18080")

		// Verify Case B (no base domain) retains web-public:18080 in desiredTunnelListeners
		// until post-ACK cleanup.
		caseBDomains := []ir.ProtectionDomain{
			{Name: "web-public-ba7765d5", ListenerName: "web", Exposure: ir.ExposurePublic, EnvoyPort: 54598},
			{Name: "web-public", ListenerName: "web", Exposure: ir.ExposurePublic, EnvoyPort: 18080, ShadowOnly: true},
		}
		caseBStatus := tunnelListenerStatus("web", ir.ExposurePublic, "", caseBDomains)
		gomega.Expect(caseBStatus.ProtectionDomains).To(gomega.ContainElement(v1alpha1.CloudflareProtectionDomainStatus{
			Name: "web-public", EnvoyPort: 18080,
		}))

		// Connector ACKs v2: Reconcile 3 promotes ConfigApplied=True and drops legacy web-public from Status.Hostnames.
		f.prober.version = 2
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())

		// Follow-up Reconcile 4 sees web-public absent from Status.Hostnames -> removes ShadowOnly
		// (18080 switches to 403 for app.example.com), drops web-public from Status.Listeners, 0 extra Cloudflare PUTs.
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "removing ShadowOnly post-ACK must cause 0 extra Cloudflare PUTs")
		hasHealth, has403 := inspectPort18080()
		gomega.Expect(hasHealth).To(gomega.BeFalse(), "post-ACK 18080 must remove /health shadow route")
		gomega.Expect(has403).To(gomega.BeTrue(), "post-ACK 18080 must enforce 403 for app.example.com")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		_, hasLegacyPD = listenerPDPort(&tunnel, "web-public")
		gomega.Expect(hasLegacyPD).To(gomega.BeFalse(), "post-ACK Status.Listeners must drop legacy web-public")

		// Steady-state Reconcile 5 emits 0 writes and 0 Cloudflare PUTs.
		counter := &tunnelStatusWriteCounterClient{Client: f.direct, tunnelName: tunnel.Name}
		f.reconciler.Client = counter
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(counter.writes.Load()).To(gomega.Equal(int64(0)))
		gomega.Expect(f.remote.updates).To(gomega.Equal(1))
	})

	// #4723566864 (256-domain Case A boundary + pre-PUT representability guard):
	// Case A with 256 live domains (127 split hosts = 254 + 1 protected-only = 255
	// + 1 base = 256) + legacy web-public:18080 must NOT exceed MaxItems=256 in
	// Status.Listeners, keeps shadow on 18080 across pre-ACK passes, converges
	// post-ACK with 0 extra Cloudflare PUTs, and >256 live domains fails pre-PUT
	// with 0 remote UpdateTunnelConfiguration calls.
	ginkgo.It("Finding 4B: 256 live-domain Case A boundary succeeds with 1 PUT and 257 domains blocks pre-PUT", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		wildHost := gatewayv1.Hostname("*.example.com")
		gw.Spec.Listeners = []gatewayv1.Listener{{
			Name: "web", Hostname: &wildHost, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
		}}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())

		pathType := gatewayv1.PathMatchPathPrefix
		adminRule := gatewayv1.SectionName("admin")
		healthRule := gatewayv1.SectionName("health")
		port := gatewayv1.PortNumber(8080)

		// 127 split hosts across 8 HTTPRoutes (maxItems=16 each) -> 254 live domains.
		targetRefs := make([]gatewayv1.LocalPolicyTargetReferenceWithSectionName, 0, 9)
		splitHosts := make([]string, 0, 127)
		for chunk := range 8 {
			count := 16
			if chunk == 7 {
				count = 15
			}
			hostnames := make([]gatewayv1.Hostname, 0, count)
			for j := range count {
				h := fmt.Sprintf("s%03d.example.com", chunk*16+j)
				hostnames = append(hostnames, gatewayv1.Hostname(h))
				splitHosts = append(splitHosts, h)
			}
			routeName := fmt.Sprintf("split-%d", chunk)
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(int64(chunk+1), 0))},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
					Hostnames:       hostnames,
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Name:        &adminRule,
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
						},
						{
							Name:        &healthRule,
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/health")}}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
						},
					},
				},
			}
			gomega.Expect(f.direct.Create(f.ctx, route)).To(gomega.Succeed())
			targetRefs = append(targetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: gatewayv1.ObjectName(routeName)},
				SectionName:                &adminRule,
			})
		}

		// +1 protected-only host -> 255 live domains.
		protOnlyHost := "ponly.example.com"
		protOnlyRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "prot-only", Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(20, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(protOnlyHost)},
				Rules: []gatewayv1.HTTPRouteRule{{
					Name:        &adminRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, protOnlyRoute)).To(gomega.Succeed())
		targetRefs = append(targetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "prot-only"},
			SectionName:                &adminRule,
		})

		// Wildcard base listener ("web", *.example.com) contributes the 256th live
		// ProtectionDomain and 256th TunnelHostname without needing an extra route.

		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "app-256", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:  corev1.LocalObjectReference{Name: acct.Name},
				Type:        v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:  &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs:  targetRefs,
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-256", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		for range 2 {
			_, err := accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: acct.Name}, &acct)).To(gomega.Succeed())
		var audSecret corev1.Secret
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{
			Namespace: accessApplicationAUDNamespace,
			Name:      accessAUDSecretName(app, f.gatewayKey),
		}, &audSecret)).To(gomega.Succeed())
		appDigest := accessBindingDigest(ir.ProtectionDomain{
			AccessApplication: ns + "/app-256",
			Protected:         true,
			Access: &ir.AccessGuard{
				AUDs:       []string{string(audSecret.Data["aud"])},
				TeamName:   acct.Status.Verified.TeamName,
				AuthDomain: acct.Status.Verified.AuthDomain,
			},
		})

		// Pre-upgrade v0.5.0 seed: s000.example.com legacy carve-out on web-public:18080 alongside base web:18080.
		seedHostnames := make([]v1alpha1.CloudflareTunnelHostnameStatus, 0, 256)
		appHashFor := func(h string) string {
			sum := sha256.Sum256([]byte(ns + "/app-256\x00" + h))
			return "web-access-" + ns + "-app-256-" + hex.EncodeToString(sum[:4])
		}
		pubHashFor := func(h string) string {
			sum := sha256.Sum256([]byte("public\x00" + h))
			return "web-public-" + hex.EncodeToString(sum[:4])
		}
		for idx, h := range splitHosts {
			pubPD := pubHashFor(h)
			if idx == 0 {
				pubPD = "web-public"
			}
			seedHostnames = append(seedHostnames,
				v1alpha1.CloudflareTunnelHostnameStatus{Hostname: h, ProtectionDomain: pubPD, Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
				v1alpha1.CloudflareTunnelHostnameStatus{Hostname: h, ProtectionDomain: appHashFor(h), AccessApplication: ns + "/app-256", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
			)
		}
		seedHostnames = append(seedHostnames,
			v1alpha1.CloudflareTunnelHostnameStatus{Hostname: protOnlyHost, ProtectionDomain: appHashFor(protOnlyHost), AccessApplication: ns + "/app-256", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
			v1alpha1.CloudflareTunnelHostnameStatus{Hostname: "*.example.com", ProtectionDomain: "web", Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
		)

		f.remote.remoteVersion = 1
		f.prober.version = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		seedWriter := &GatewayReconciler{Client: f.direct, APIReader: f.direct, Scheme: f.direct.Scheme()}
		seedIR := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(seedWriter.patchTunnelGatewayData(
			f.ctx, seedIR, &tunnel,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "v05-hash", Applied: 1, Remote: 1},
			seedHostnames,
			[]v1alpha1.CloudflareTunnelListenerStatus{{
				Name:     "web",
				Exposure: v1alpha1.ExposurePublic,
				ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
					{Name: "web", EnvoyPort: 18080},
					{Name: "web-public", EnvoyPort: 18080},
				},
			}},
		)).To(gomega.Succeed())

		inspectS000On18080 := func() (hasHealthRoute bool, has403Block bool) {
			f.snapshots.publisher.mu.RLock()
			snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
			f.snapshots.publisher.mu.RUnlock()
			gomega.Expect(snap).NotTo(gomega.BeNil())
			var targetRoute string
			for _, res := range snap.GetResources(resourcev3.ListenerType) {
				l := res.(*listenerv3.Listener)
				if l.GetAddress().GetSocketAddress().GetPortValue() != 18080 {
					continue
				}
				for _, fc := range l.GetFilterChains() {
					for _, filter := range fc.GetFilters() {
						if filter.Name != "envoy.filters.network.http_connection_manager" {
							continue
						}
						var hcm hcmv3.HttpConnectionManager
						if err := filter.GetTypedConfig().UnmarshalTo(&hcm); err == nil {
							if rdsName := hcm.GetRds().GetRouteConfigName(); rdsName != "" {
								targetRoute = rdsName
							}
						}
					}
				}
			}
			gomega.Expect(targetRoute).NotTo(gomega.BeEmpty())
			rc := snap.GetResources(resourcev3.RouteType)[targetRoute].(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				if !slices.Contains(vh.GetDomains(), "s000.example.com") {
					continue
				}
				for _, route := range vh.GetRoutes() {
					if route.GetDirectResponse() != nil && route.GetDirectResponse().GetStatus() == 403 {
						has403Block = true
					}
					if route.GetMatch().GetPathSeparatedPrefix() == "/health" && route.GetRoute() != nil {
						hasHealthRoute = true
					}
				}
			}
			return hasHealthRoute, has403Block
		}

		// Reconcile 1 & 2 while connector holds v1:
		// Must succeed without hitting 256 MaxItems rejection, emitting 1 Cloudflare PUT (Desired==2)
		// and keeping s000.example.com /health shadow active on 18080 across both pre-ACK passes.
		for range 2 {
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
			hasHealth, has403 := inspectS000On18080()
			gomega.Expect(hasHealth).To(gomega.BeTrue(), "256-domain Case A pre-ACK pass must keep s000 /health on 18080")
			gomega.Expect(has403).To(gomega.BeFalse(), "256-domain Case A pre-ACK pass must not 403 s000")
		}
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "exact 256-domain boundary must emit exactly 1 remote PUT")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.ConfigVersion.Desired).To(gomega.Equal(int64(2)))
		gomega.Expect(tunnel.Status.Listeners).To(gomega.HaveLen(1))
		gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).To(gomega.HaveLen(256))

		// Connector ACKs v2 -> follow-up drops shadow with 0 extra PUTs and 403s legacy 18080.
		f.prober.version = 2
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "post-ACK cleanup must cause 0 extra Cloudflare PUTs")
		hasHealth, has403 := inspectS000On18080()
		gomega.Expect(hasHealth).To(gomega.BeFalse())
		gomega.Expect(has403).To(gomega.BeTrue())

		// Exceeding 256 live domains (add 1 extra protected host -> 257 domains) must fail
		// pre-PUT representability guard with 0 remote UpdateTunnelConfiguration calls.
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Namespace: ns, Name: "prot-only"}, protOnlyRoute)).To(gomega.Succeed())
		protOnlyRoute.Spec.Hostnames = append(protOnlyRoute.Spec.Hostnames, "overflow-257.example.com")
		gomega.Expect(f.direct.Update(f.ctx, protOnlyRoute)).To(gomega.Succeed())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("exceeds maximum 256")))
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "257-domain config must be blocked pre-PUT (0 extra UpdateTunnelConfiguration calls)")
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		cfgApplied := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
		gomega.Expect(cfgApplied).NotTo(gomega.BeNil())
		gomega.Expect(cfgApplied.Status).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(cfgApplied.Reason).To(gomega.Equal("ConfigurationError"))
	})

	// Case B at exact 256 live-domain boundary (no literal "web" base domain):
	// 127 split hosts (254) + 1 protected-only (255) + 1 protected wildcard *.example.com (256)
	// + legacy web-public:18080 must retain web-public:18080 in Status.Listeners by temporarily
	// deferring the trailing new unprotected carve-out status row (255 live + 1 shadow = 256),
	// keep s000 /health reachable on 18080 across Pass 1 & Pass 2 while connector holds v1,
	// keep all 256 dedicated ports deterministic (0 extra Cloudflare PUTs), and post-ACK drop
	// web-public, restore all 256 live domains in Status.Listeners, 403 18080, and converge to 0 writes.
	ginkgo.It("Finding 4C: Case B 256 live-domain boundary retains shadow across v1 rollout and restores 256 live rows post-ACK", func() {
		f := newQA92Fixture(ginkgo.GinkgoT(), qa92FixtureOptions{})
		ns := f.gatewayKey.Namespace

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		var acct v1alpha1.CloudflareAccount
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: tunnel.Spec.AccountRef.Name}, &acct)).To(gomega.Succeed())
		acct.Spec.Grants[0].Hostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].UnprotectedHostnames = []string{"*.example.com"}
		acct.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic}
		acct.Spec.Grants[0].Backends = &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		}
		gomega.Expect(f.direct.Update(f.ctx, &acct)).To(gomega.Succeed())

		var gw gatewayv1.Gateway
		gomega.Expect(f.direct.Get(f.ctx, f.gatewayKey, &gw)).To(gomega.Succeed())
		wildHost := gatewayv1.Hostname("*.example.com")
		gw.Spec.Listeners = []gatewayv1.Listener{{
			Name: "web", Hostname: &wildHost, Port: 80, Protocol: gatewayv1.HTTPProtocolType,
		}}
		gomega.Expect(f.direct.Update(f.ctx, &gw)).To(gomega.Succeed())

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}
		gomega.Expect(f.direct.Create(f.ctx, svc)).To(gomega.Succeed())

		pathType := gatewayv1.PathMatchPathPrefix
		adminRule := gatewayv1.SectionName("admin")
		healthRule := gatewayv1.SectionName("health")
		wildRule := gatewayv1.SectionName("wild")
		port := gatewayv1.PortNumber(8080)

		// 127 split hosts across 8 HTTPRoutes -> 254 live domains.
		targetRefs := make([]gatewayv1.LocalPolicyTargetReferenceWithSectionName, 0, 10)
		splitHosts := make([]string, 0, 127)
		for chunk := range 8 {
			count := 16
			if chunk == 7 {
				count = 15
			}
			hostnames := make([]gatewayv1.Hostname, 0, count)
			for j := range count {
				h := fmt.Sprintf("s%03d.example.com", chunk*16+j)
				hostnames = append(hostnames, gatewayv1.Hostname(h))
				splitHosts = append(splitHosts, h)
			}
			routeName := fmt.Sprintf("split-%d", chunk)
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(int64(chunk+1), 0))},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
					Hostnames:       hostnames,
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Name:        &adminRule,
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
						},
						{
							Name:        &healthRule,
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/health")}}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
						},
					},
				},
			}
			gomega.Expect(f.direct.Create(f.ctx, route)).To(gomega.Succeed())
			targetRefs = append(targetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: gatewayv1.ObjectName(routeName)},
				SectionName:                &adminRule,
			})
		}

		// +1 protected-only host -> 255 live domains.
		protOnlyHost := "ponly.example.com"
		protOnlyRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "prot-only", Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(20, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(protOnlyHost)},
				Rules: []gatewayv1.HTTPRouteRule{{
					Name:        &adminRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/admin")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, protOnlyRoute)).To(gomega.Succeed())
		targetRefs = append(targetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "prot-only"},
			SectionName:                &adminRule,
		})

		// +1 protected wildcard HTTPRoute (*.example.com) -> 256 live domains, NO literal "web" base domain (Case B).
		wildRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "wild-protected", Namespace: ns, CreationTimestamp: metav1.NewTime(time.Unix(21, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{wildHost},
				Rules: []gatewayv1.HTTPRouteRule{{
					Name:        &wildRule,
					Matches:     []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: new("/")}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}},
				}},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, wildRoute)).To(gomega.Succeed())
		targetRefs = append(targetRefs, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "wild-protected"},
			SectionName:                &wildRule,
		})

		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "app-caseb", Namespace: ns},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:  corev1.LocalObjectReference{Name: acct.Name},
				Type:        v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:  &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs:  targetRefs,
				Policies:    []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-caseb", SessionDuration: "1h"},
			},
		}
		gomega.Expect(f.direct.Create(f.ctx, app)).To(gomega.Succeed())

		indexedClient := handoffIndexedClient{Client: f.direct}
		accessReconciler := &AccessApplicationReconciler{
			Client:              indexedClient,
			APIReader:           indexedClient,
			Scheme:              f.direct.Scheme(),
			NewCloudflareClient: newFakeAccessApplicationCloudflare().Client,
			OperatorNamespace:   accessApplicationAUDNamespace,
			Now:                 func() time.Time { return f.clock },
		}
		for range 2 {
			_, err := accessReconciler.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{Name: acct.Name}, &acct)).To(gomega.Succeed())
		var audSecret corev1.Secret
		gomega.Expect(f.direct.Get(f.ctx, types.NamespacedName{
			Namespace: accessApplicationAUDNamespace,
			Name:      accessAUDSecretName(app, f.gatewayKey),
		}, &audSecret)).To(gomega.Succeed())
		appDigest := accessBindingDigest(ir.ProtectionDomain{
			AccessApplication: ns + "/app-caseb",
			Protected:         true,
			Access: &ir.AccessGuard{
				AUDs:       []string{string(audSecret.Data["aud"])},
				TeamName:   acct.Status.Verified.TeamName,
				AuthDomain: acct.Status.Verified.AuthDomain,
			},
		})

		// Pre-upgrade v0.5.0 Case B seed: web-public:18080 for s000.example.com and NO literal "web" domain.
		seedHostnames := make([]v1alpha1.CloudflareTunnelHostnameStatus, 0, 256)
		appHashFor := func(h string) string {
			sum := sha256.Sum256([]byte(ns + "/app-caseb\x00" + h))
			return "web-access-" + ns + "-app-caseb-" + hex.EncodeToString(sum[:4])
		}
		pubHashFor := func(h string) string {
			sum := sha256.Sum256([]byte("public\x00" + h))
			return "web-public-" + hex.EncodeToString(sum[:4])
		}
		for idx, h := range splitHosts {
			pubPD := pubHashFor(h)
			if idx == 0 {
				pubPD = "web-public"
			}
			seedHostnames = append(seedHostnames,
				v1alpha1.CloudflareTunnelHostnameStatus{Hostname: h, ProtectionDomain: pubPD, Guard: v1alpha1.HostnameGuardUnprotected, AppliedVersion: 1},
				v1alpha1.CloudflareTunnelHostnameStatus{Hostname: h, ProtectionDomain: appHashFor(h), AccessApplication: ns + "/app-caseb", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
			)
		}
		seedHostnames = append(seedHostnames,
			v1alpha1.CloudflareTunnelHostnameStatus{Hostname: protOnlyHost, ProtectionDomain: appHashFor(protOnlyHost), AccessApplication: ns + "/app-caseb", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
			v1alpha1.CloudflareTunnelHostnameStatus{Hostname: string(wildHost), ProtectionDomain: appHashFor(string(wildHost)), AccessApplication: ns + "/app-caseb", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1, AccessBinding: appDigest},
		)

		f.remote.remoteVersion = 1
		f.prober.version = 1
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		seedWriter := &GatewayReconciler{Client: f.direct, APIReader: f.direct, Scheme: f.direct.Scheme()}
		seedIR := &ir.Gateway{Key: f.gatewayKey, UID: gw.UID}
		gomega.Expect(seedWriter.patchTunnelGatewayData(
			f.ctx, seedIR, &tunnel,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "v05-caseb-hash", Applied: 1, Remote: 1},
			seedHostnames,
			[]v1alpha1.CloudflareTunnelListenerStatus{{
				Name:     "web",
				Exposure: v1alpha1.ExposurePublic,
				ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{
					{Name: "web-public", EnvoyPort: 18080},
				},
			}},
		)).To(gomega.Succeed())

		inspectS000On18080 := func() (hasListener bool, hasHealthRoute bool, has403Block bool) {
			f.snapshots.publisher.mu.RLock()
			snap := f.snapshots.publisher.snapshots[f.gatewayKey.String()]
			f.snapshots.publisher.mu.RUnlock()
			gomega.Expect(snap).NotTo(gomega.BeNil())
			var targetRoute string
			for _, res := range snap.GetResources(resourcev3.ListenerType) {
				l := res.(*listenerv3.Listener)
				if l.GetAddress().GetSocketAddress().GetPortValue() != 18080 {
					continue
				}
				for _, fc := range l.GetFilterChains() {
					for _, filter := range fc.GetFilters() {
						if filter.Name != "envoy.filters.network.http_connection_manager" {
							continue
						}
						var hcm hcmv3.HttpConnectionManager
						if err := filter.GetTypedConfig().UnmarshalTo(&hcm); err == nil {
							if rdsName := hcm.GetRds().GetRouteConfigName(); rdsName != "" {
								targetRoute = rdsName
							}
						}
					}
				}
			}
			if targetRoute == "" {
				return false, false, false
			}
			rc := snap.GetResources(resourcev3.RouteType)[targetRoute].(*routev3.RouteConfiguration)
			for _, vh := range rc.GetVirtualHosts() {
				if !slices.Contains(vh.GetDomains(), "s000.example.com") {
					continue
				}
				for _, route := range vh.GetRoutes() {
					if route.GetDirectResponse() != nil && route.GetDirectResponse().GetStatus() == 403 {
						has403Block = true
					}
					if route.GetMatch().GetPathSeparatedPrefix() == "/health" && route.GetRoute() != nil {
						hasHealthRoute = true
					}
				}
			}
			return true, hasHealthRoute, has403Block
		}

		// Pass 1 & Pass 2 while connector holds v1:
		// Both passes must retain web-public:18080 in Status.Listeners (256 items = 255 live + web-public),
		// keep s000.example.com /health active on 18080 (no 403), and emit exactly 1 PUT total.
		for pass := 1; pass <= 2; pass++ {
			_, err := f.reconciler.Reconcile(f.ctx, f.request)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
			hasListener, hasHealth, has403 := inspectS000On18080()
			gomega.Expect(hasListener).To(gomega.BeTrue(), fmt.Sprintf("Case B pass %d must keep legacy 18080 listener", pass))
			gomega.Expect(hasHealth).To(gomega.BeTrue(), fmt.Sprintf("Case B pass %d must keep s000 /health on 18080", pass))
			gomega.Expect(has403).To(gomega.BeFalse(), fmt.Sprintf("Case B pass %d must not 403 s000", pass))

			gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
			gomega.Expect(tunnel.Status.Listeners).To(gomega.HaveLen(1))
			gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).To(gomega.HaveLen(256))
			gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).To(gomega.ContainElement(v1alpha1.CloudflareProtectionDomainStatus{
				Name: "web-public", EnvoyPort: 18080,
			}), fmt.Sprintf("Case B pass %d must retain web-public:18080 in Status.Listeners", pass))
			gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).NotTo(gomega.ContainElement(gomega.HaveField("Name", "web")))
		}
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "Case B 256-domain pre-ACK passes must emit exactly 1 remote PUT")
		gomega.Expect(tunnel.Status.ConfigVersion.Desired).To(gomega.Equal(int64(2)))

		// Connector ACKs v2 -> drops web-public from Status.Hostnames; follow-up removes shadow
		// (closing legacy 18080 listener in Case B), drops web-public from Status.Listeners,
		// restores all 256 live domains, and causes 0 extra PUTs.
		f.prober.version = 2
		_, err := f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())

		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.snapshots.ACK(f.gatewayKey.String())).To(gomega.Succeed())
		// Reconcile once after post-shadow Envoy ACK so ConfigApplied=True settles before counting steady-state writes.
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.remote.updates).To(gomega.Equal(1), "post-ACK cleanup and 256-row restoration must cause 0 extra Cloudflare PUTs")
		hasListener, hasHealth, _ := inspectS000On18080()
		gomega.Expect(hasListener).To(gomega.BeFalse(), "post-ACK Case B has no base domain so legacy 18080 listener must be removed")
		gomega.Expect(hasHealth).To(gomega.BeFalse())
		gomega.Expect(f.direct.Get(f.ctx, f.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(tunnel.Status.Listeners).To(gomega.HaveLen(1))
		gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).To(gomega.HaveLen(256))
		gomega.Expect(tunnel.Status.Listeners[0].ProtectionDomains).NotTo(gomega.ContainElement(gomega.HaveField("Name", "web-public")))

		// Steady-state reconcile converges to 0 writes and 0 PUTs.
		counter := &tunnelStatusWriteCounterClient{Client: f.direct, tunnelName: tunnel.Name}
		f.reconciler.Client = counter
		_, err = f.reconciler.Reconcile(f.ctx, f.request)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(counter.writes.Load()).To(gomega.Equal(int64(0)))
		gomega.Expect(f.remote.updates).To(gomega.Equal(1))
	})
})

// QA-1-REG-5 (controller): Mixed PodIP + Loopback and All-PodIP active Private
// listeners report PrivateListenerDegraded=True (PodIPFallback), while
// All-Loopback reports False (Loopback).
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

	allPodIP := &ir.Gateway{
		Listeners: []ir.Listener{
			{Name: "a", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
			{Name: "b", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP},
		},
	}
	podIPState := privatePrerequisiteResult{Listeners: map[string]string{}}
	podIPState.Degraded = privateActiveUsesPodIPBinding(allPodIP, podIPState.Listeners)
	if !podIPState.Degraded {
		t.Fatal("all-PodIP listeners must report Degraded=true")
	}
	podIPCond := privateListenerCondition(allPodIP, podIPState, metav1.Now())
	if podIPCond.Status != metav1.ConditionTrue || podIPCond.Reason != "PodIPFallback" {
		t.Fatalf("all-PodIP condition = %#v, want True/PodIPFallback", podIPCond)
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

func TestValidateDesiredTunnelStatusLimitsShadowRecoverability(t *testing.T) {
	makeCaseB := func(protectedCount, unprotectedCount int, withShadow bool) *ir.Gateway {
		domains := make([]ir.ProtectionDomain, 0, protectedCount+unprotectedCount+1)
		for i := range protectedCount {
			domains = append(domains, ir.ProtectionDomain{
				Name:         fmt.Sprintf("web-access-%03d", i),
				ListenerName: "web",
				Exposure:     ir.ExposurePublic,
				EnvoyPort:    int32(20000 + i),
				Protected:    true,
			})
		}
		for i := range unprotectedCount {
			domains = append(domains, ir.ProtectionDomain{
				Name:         fmt.Sprintf("web-public-%03d", i),
				ListenerName: "web",
				Exposure:     ir.ExposurePublic,
				EnvoyPort:    int32(30000 + i),
				Protected:    false,
			})
		}
		if withShadow {
			domains = append(domains, ir.ProtectionDomain{
				Name:         "web-public",
				ListenerName: "web",
				Exposure:     ir.ExposurePublic,
				EnvoyPort:    18080,
				ShadowOnly:   true,
			})
		}
		return &ir.Gateway{
			Listeners: []ir.Listener{{Name: "web", Exposure: ir.ExposurePublic}},
			Domains:   domains,
		}
	}

	// 255 Protected + 1 unprotected carve-out + 1 ShadowOnly -> defers the 1 trailing unprotected carve-out, keeps 256 items with ShadowOnly.
	gwOK := makeCaseB(255, 1, true)
	if err := validateDesiredTunnelStatusLimits(gwOK, nil); err != nil {
		t.Fatalf("255 protected + 1 unprotected + 1 shadow must validate, got: %v", err)
	}
	statusOK := tunnelListenerStatus("web", ir.ExposurePublic, "", gwOK.Domains)
	if len(statusOK.ProtectionDomains) != maxTunnelListenerProtectionDomains {
		t.Fatalf("ProtectionDomains len = %d, want %d", len(statusOK.ProtectionDomains), maxTunnelListenerProtectionDomains)
	}
	if last := statusOK.ProtectionDomains[len(statusOK.ProtectionDomains)-1]; last.Name != "web-public" || last.EnvoyPort != 18080 {
		t.Fatalf("last retained PD = %#v, want web-public:18080", last)
	}

	// 256 Protected + 0 unprotected + 1 ShadowOnly -> cannot defer Protected domains, fails pre-PUT representability guard.
	gwUnrecoverable := makeCaseB(256, 0, true)
	if err := validateDesiredTunnelStatusLimits(gwUnrecoverable, nil); err == nil || !strings.Contains(err.Error(), "cannot retain legacy shadow domain") {
		t.Fatalf("expected unrecoverable shadow error, got: %v", err)
	}

	// 257 live domains (even with unprotected carve-outs) never defer and always fail pre-PUT representability guard.
	gwOverflow := makeCaseB(255, 2, true)
	if err := validateDesiredTunnelStatusLimits(gwOverflow, nil); err == nil || !strings.Contains(err.Error(), "exceeds maximum 256") {
		t.Fatalf("expected >256 live domains error, got: %v", err)
	}
}
