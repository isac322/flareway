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
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

func TestGeneratedRouteCleanupWithoutAccount(t *testing.T) {
	for _, mode := range []string{"no listeners", "public listener", "private listener"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			gateway := listenerConvergenceGateway()
			gateway.UID = "gateway-uid"
			if mode == "no listeners" {
				gateway.Listeners = nil
				gateway.Domains = nil
			} else if mode == "private listener" {
				gateway.Listeners[1].Exposure = ir.ExposurePrivate
			}
			tunnel := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant"},
				Status:     v1alpha1.CloudflareTunnelStatus{TunnelID: "tunnel-id", OwnershipVerified: true},
			}
			route := &v1alpha1.HostnameRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateHostnameRouteName(tunnel.Namespace, tunnel.Name, "old"), Namespace: dataplane.DefaultOperatorNamespace,
					Labels:      map[string]string{generatedPlatformObjectLabel: "true", generatedSourceNamespaceLabel: tunnel.Namespace, generatedGatewayLabel: tunnel.Namespace + "--" + tunnel.Name},
					Annotations: map[string]string{sourceGatewayUIDAnnotation: "previous-gateway-uid"},
				},
				Spec: v1alpha1.HostnameRouteSpec{
					AccountRef: corev1.LocalObjectReference{Name: "absent-account"}, Hostname: "b.example.com",
					TunnelRef: v1alpha1.TunnelReference{Name: tunnel.Name, Namespace: tunnel.Namespace},
				},
			}
			scheme := runtime.NewScheme()
			if err := v1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route).Build()
			r := &GatewayReconciler{Client: kube}
			inputs := gatewayInputsView{HostnameRoutes: []v1alpha1.HostnameRoute{*route.DeepCopy()}}
			state, err := r.reconcilePrivatePrerequisites(ctx, gateway, tunnel, nil, inputs)
			if err != nil {
				t.Fatal(err)
			}
			var stored v1alpha1.HostnameRoute
			if err := kube.Get(ctx, client.ObjectKeyFromObject(route), &stored); err != nil {
				t.Fatal(err)
			}
			if mode == "private listener" {
				if state.Pending == "" || state.Listeners["b"] == "" || state.Listeners["a"] != "" ||
					gateway.Domains[1].Guard != ir.GuardBlocked || gateway.Domains[1].Access != nil {
					t.Fatalf("missing account did not isolate the private listener: %#v", state)
				}
				if stored.Annotations[sourceGatewayUIDAnnotation] != "previous-gateway-uid" || !stored.DeletionTimestamp.IsZero() {
					t.Fatal("missing account changed a route still required by an active private listener")
				}
			} else {
				if state.Pending == "" || len(state.Listeners) != 0 || stored.Annotations[sourceGatewayUIDAnnotation] != string(gateway.UID) {
					t.Fatalf("obsolete route did not bind the current Gateway UID without an account: %#v", state)
				}
				inputs.HostnameRoutes[0] = stored
				state, err = r.reconcilePrivatePrerequisites(ctx, gateway, tunnel, nil, inputs)
				if err != nil {
					t.Fatal(err)
				}
				if state.Pending == "" || len(state.Listeners) != 0 {
					t.Fatalf("route removal incorrectly blocked a listener: %#v", state)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(route), &stored); !apierrors.IsNotFound(err) {
					t.Fatalf("obsolete route was not deleted without an account: %v", err)
				}
				state, err = r.reconcilePrivatePrerequisites(ctx, gateway, tunnel, nil, gatewayInputsView{})
				if err != nil || state.Pending != "" || len(state.Listeners) != 0 {
					t.Fatalf("completed cleanup did not converge: %#v, %v", state, err)
				}
			}
			if mode != "no listeners" && (gateway.Domains[0].Guard != ir.GuardForwarding || gateway.Domains[0].Access == nil) {
				t.Fatal("absent account blocked the public listener")
			}
		})
	}
}

func TestGeneratedRouteRemovalBlocksOnlyReplacementListener(t *testing.T) {
	for _, test := range []struct {
		name                                  string
		protected, staleUID, creationDisabled bool
	}{
		{name: "unprotected"},
		{name: "Access", protected: true},
		{name: "rebind obsolete route", staleUID: true},
		{name: "creation disabled", creationDisabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			newGateway := func() *ir.Gateway {
				gateway := listenerConvergenceGateway()
				gateway.UID = "gateway-uid"
				for i := range gateway.Listeners {
					gateway.Listeners[i].Exposure = ir.ExposurePrivate
					gateway.Listeners[i].Port = gateway.Domains[i].EnvoyPort
					gateway.Listeners[i].Protocol = "HTTP"
					gateway.Listeners[i].EnvoyPort = gateway.Domains[i].EnvoyPort
					gateway.Domains[i].VirtualHosts[0].Routes = []ir.Route{{
						Name: "backend", Match: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"},
						Backends: []ir.BackendRef{{ClusterName: "backend", Weight: 1}},
					}}
				}
				gateway.Listeners[1].Name = "renamed"
				gateway.Domains[1].ListenerName = "renamed"
				if !test.protected {
					gateway.Domains[1].Protected = false
					gateway.Domains[1].Guard = ir.GuardUnprotected
					gateway.Domains[1].Access = nil
					gateway.Domains[1].AccessApplication = ""
				}
				return gateway
			}
			gateway := newGateway()
			account := privatePrerequisiteAccount("tenant", true)
			tunnel := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: "tenant"},
				Status:     v1alpha1.CloudflareTunnelStatus{TunnelID: "tunnel-id", OwnershipVerified: true},
			}
			if test.creationDisabled {
				create := false
				tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{Name: "renamed", HostnameRoute: v1alpha1.CloudflareTunnelHostnameRouteConfig{Create: &create}}}
			}
			inputs := gatewayInputsView{VirtualNetworks: []v1alpha1.VirtualNetwork{{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: tunnel.Namespace},
				Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, IsDefault: true},
				Status:     v1alpha1.VirtualNetworkStatus{VirtualNetworkID: "vnet-id", Conditions: []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}}},
			}}}
			for _, name := range []string{"a", "b"} {
				inputs.HostnameRoutes = append(inputs.HostnameRoutes, v1alpha1.HostnameRoute{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"},
					Spec:       v1alpha1.HostnameRouteSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}, Hostname: name + ".example.com", TunnelRef: v1alpha1.TunnelReference{Name: tunnel.Name}},
					Status: v1alpha1.HostnameRouteStatus{
						RouteID: name, Applied: v1alpha1.HostnameRouteAppliedStatus{Hostname: name + ".example.com", TunnelID: tunnel.Status.TunnelID},
						Conditions: []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
					},
				})
			}
			obsolete := &inputs.HostnameRoutes[1]
			obsolete.Namespace = dataplane.DefaultOperatorNamespace
			obsolete.Name = privateHostnameRouteName(tunnel.Namespace, tunnel.Name, "old")
			obsolete.Spec.Hostname = "B.EXAMPLE.COM."
			obsolete.Spec.TunnelRef.Namespace = tunnel.Namespace
			obsolete.Labels = map[string]string{generatedPlatformObjectLabel: "true", generatedSourceNamespaceLabel: tunnel.Namespace, generatedGatewayLabel: tunnel.Namespace + "--" + tunnel.Name}
			obsolete.Annotations = map[string]string{sourceGatewayUIDAnnotation: string(gateway.UID)}
			if test.staleUID {
				obsolete.Annotations[sourceGatewayUIDAnnotation] = "previous-gateway-uid"
			}
			obsolete.Finalizers = []string{"test.example.com/remote-cleanup"}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := v1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test")}}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, obsolete.DeepCopy()).Build()
			r := &GatewayReconciler{Client: routeDeleteWithoutInputMutation{Client: kube}, CloudflareFactory: gatewayCloudflareFactory{api: &privatePrerequisiteAPI{settings: &flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}}}}
			binding := accessBindingDigest(gateway.Domains[1])
			state, err := r.reconcilePrivatePrerequisites(ctx, gateway, tunnel, account, inputs)
			if err != nil {
				t.Fatal(err)
			}
			var deleting v1alpha1.HostnameRoute
			if err := kube.Get(ctx, client.ObjectKeyFromObject(obsolete), &deleting); err != nil {
				t.Fatal(err)
			}
			if test.staleUID {
				if !deleting.DeletionTimestamp.IsZero() || deleting.Annotations[sourceGatewayUIDAnnotation] != string(gateway.UID) {
					t.Fatal("obsolete route must bind the current Gateway UID before deletion")
				}
				if state.Listeners["renamed"] == "" || gateway.Domains[1].Guard != ir.GuardBlocked || state.Listeners["a"] != "" {
					t.Fatalf("UID rebinding did not isolate the replacement listener: %#v", state)
				}
				inputs.HostnameRoutes[1] = deleting
				gateway = newGateway()
				state, err = r.reconcilePrivatePrerequisites(ctx, gateway, tunnel, account, inputs)
				if err != nil {
					t.Fatal(err)
				}
				if err := kube.Get(ctx, client.ObjectKeyFromObject(obsolete), &deleting); err != nil {
					t.Fatal(err)
				}
			}
			if deleting.DeletionTimestamp.IsZero() || !obsolete.DeletionTimestamp.IsZero() {
				t.Fatal("fixture must retain a pre-delete Applied input while the route is deleting")
			}
			if state.Pending == "" || state.Listeners["renamed"] == "" || state.Listeners["a"] != "" {
				t.Fatalf("replacement listener was not isolated during removal: %#v", state)
			}
			if gateway.Domains[1].Guard != ir.GuardBlocked || gateway.Domains[1].Access != nil {
				t.Fatal("replacement hostname still forwards while its route is being removed")
			}
			if test.protected && (binding == "" || gateway.Domains[1].AccessBinding != binding) {
				t.Fatal("retiring route denial lost the Access binding checkpoint")
			}
			if gateway.Domains[0].Guard != ir.GuardForwarding || gateway.Domains[0].Access == nil {
				t.Fatal("obsolete route removal blocked the healthy sibling")
			}
			snapshot, err := translator.Build(gateway, defaultGatewayClassConfig())
			if err != nil {
				t.Fatal(err)
			}
			for i, domain := range gateway.Domains {
				configuration := snapshot.GetResources(resourcev3.RouteType)[domain.Name].(*routev3.RouteConfiguration)
				if len(configuration.VirtualHosts) == 0 || len(configuration.VirtualHosts[0].Routes) == 0 {
					t.Fatal("published hostname routes are missing")
				}
				route := configuration.VirtualHosts[0].Routes[0]
				if i == 1 && route.GetDirectResponse().GetStatus() != 403 {
					t.Fatal("replacement snapshot does not deny the hostname")
				}
				if i == 0 && route.GetRoute() == nil {
					t.Fatal("healthy sibling snapshot no longer forwards")
				}
			}
			status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{{Name: "a"}, {Name: "renamed"}}}
			r.setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, gateway, tunnel, true, state.Pending, state)
			for _, listener := range status.Listeners {
				want := metav1.ConditionTrue
				if listener.Name == "renamed" {
					want = metav1.ConditionFalse
				}
				condition := meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed))
				if condition == nil || condition.Status != want {
					t.Fatalf("listener %s Programmed = %#v", listener.Name, condition)
				}
			}
			if meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)).Status != metav1.ConditionFalse {
				t.Fatal("Gateway ignored route removal")
			}
			// Once the obsolete route is gone and a replacement is Applied, the
			// same desired listener must resume without affecting its sibling.
			deleting.Finalizers = nil
			if err := kube.Update(ctx, &deleting); err != nil {
				t.Fatal(err)
			}
			replacement := obsolete.DeepCopy()
			replacement.Name = privateHostnameRouteName(tunnel.Namespace, tunnel.Name, "renamed")
			replacement.Spec.Hostname = "b.example.com"
			replacement.Spec.TunnelRef.Kind = v1alpha1.TunnelReferenceKindCloudflareTunnel
			replacement.Spec.AllowedNamespaces = v1alpha1.AllowedNamespaces{From: v1alpha1.AllowedNamespaceFromSelector, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": tunnel.Namespace}}}
			replacement.Spec.Comment = "flareway private listener tenant/tunnel/renamed"
			replacement.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
			replacement.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
			if test.creationDisabled {
				replacement.Namespace = tunnel.Namespace
				replacement.Labels = nil
				replacement.Annotations = nil
			}
			notApplied := replacement.DeepCopy()
			notApplied.Status = v1alpha1.HostnameRouteStatus{}
			inputs.HostnameRoutes[1] = *notApplied
			pending := newGateway()
			state, err = r.reconcilePrivatePrerequisites(ctx, pending, tunnel, account, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if state.Listeners["renamed"] == "" || pending.Domains[1].Guard != ir.GuardBlocked || state.Listeners["a"] != "" {
				t.Fatalf("unapplied replacement was treated as ready: %#v", state)
			}
			inputs.HostnameRoutes[1] = *replacement
			recovered := newGateway()
			state, err = r.reconcilePrivatePrerequisites(ctx, recovered, tunnel, account, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if state.Pending != "" || len(state.Listeners) != 0 || recovered.Domains[1].Guard != newGateway().Domains[1].Guard {
				t.Fatalf("Applied replacement failed to recover: %#v", state)
			}
			snapshot, err = translator.Build(recovered, defaultGatewayClassConfig())
			if err != nil {
				t.Fatal(err)
			}
			configuration := snapshot.GetResources(resourcev3.RouteType)[recovered.Domains[1].Name].(*routev3.RouteConfiguration)
			if configuration.VirtualHosts[0].Routes[0].GetRoute() == nil {
				t.Fatal("Applied replacement snapshot did not resume forwarding")
			}
			r.setCloudflareDNSProgrammedStatus(&status, &gatewayv1.Gateway{}, recovered, tunnel, true, "ready", state)
			if meta.FindStatusCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed)).Status != metav1.ConditionTrue {
				t.Fatal("Gateway did not recover after replacement became Applied")
			}
			for _, listener := range status.Listeners {
				if meta.FindStatusCondition(listener.Conditions, string(gatewayv1.ListenerConditionProgrammed)).Status != metav1.ConditionTrue {
					t.Fatalf("listener %s did not recover", listener.Name)
				}
			}
		})
	}
}

// The API client does not update its input object from a DELETE response.
type routeDeleteWithoutInputMutation struct{ client.Client }

func (c routeDeleteWithoutInputMutation) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	return c.Client.Delete(ctx, object.DeepCopyObject().(client.Object), options...)
}
