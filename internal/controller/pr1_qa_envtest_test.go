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
	"encoding/json"
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
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

		// Drain Deployment replicas (Status.Replicas=0, ReadyReplicas=0) and reconcile again:
		// tunnel.Status.Hostnames must now transition from Forwarding to Blocked.
		deploy.Status.Replicas = 0
		deploy.Status.ReadyReplicas = 0
		gomega.Expect(f.direct.Status().Update(f.ctx, deploy)).To(gomega.Succeed())

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
