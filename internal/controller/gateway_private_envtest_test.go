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
	"fmt"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
)

var _ = ginkgo.Describe("Gateway private prerequisites", func() {
	ginkgo.It("creates a platform HostnameRoute only with platformObjects grant", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-private-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName, Labels: map[string]string{"tenant": "private"}}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })
		operatorNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}
		if err := testClient.Create(testContext, operatorNamespace); err != nil {
			gomega.Expect(apierrors.IsAlreadyExists(err)).To(gomega.BeTrue())
		}
		token := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: namespaceName}, Data: map[string][]byte{"token": []byte("secret")}}
		gomega.Expect(testClient.Create(testContext, token)).To(gomega.Succeed())

		account := privatePrerequisiteAccount(namespaceName, true)
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: namespaceName},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef: corev1.LocalObjectReference{Name: account.Name},
				Listeners: []v1alpha1.CloudflareTunnelListener{{
					Name: "private", Exposure: v1alpha1.ExposurePrivate,
					VirtualNetworkRef: &corev1.LocalObjectReference{Name: "prod"},
				}},
			},
			Status: v1alpha1.CloudflareTunnelStatus{
				TunnelID: "11111111-1111-1111-1111-111111111111", OwnershipVerified: true,
			},
		}
		vnet := v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: namespaceName},
			Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}},
			Status: v1alpha1.VirtualNetworkStatus{
				VirtualNetworkID: "vnet-prod",
				Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
			},
		}
		gateway := privatePrerequisiteIR(namespaceName)
		reconciler := &GatewayReconciler{
			Client: testClient, OperatorNamespace: dataplane.DefaultOperatorNamespace,
			CloudflareFactory: gatewayCloudflareFactory{api: &privatePrerequisiteAPI{}},
		}
		var state privatePrerequisiteResult
		var err error
		gomega.Eventually(func(g gomega.Gomega) {
			probeGateway := privatePrerequisiteIR(namespaceName)
			state, err = reconciler.reconcilePrivatePrerequisites(testContext, probeGateway, tunnel, account, gatewayInputsView{
				Namespaces: []corev1.Namespace{*namespace}, VirtualNetworks: []v1alpha1.VirtualNetwork{vnet},
			})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(state.Pending).To(gomega.ContainSubstring("Waiting for the platform HostnameRoute"))
			g.Expect(probeGateway.Domains[0].Guard).To(gomega.Equal(ir.GuardBlocked))
			g.Expect(probeGateway.Domains[0].Access).To(gomega.BeNil())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		routeKey := types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: privateHostnameRouteName(namespaceName, tunnel.Name, "private")}
		gomega.Eventually(func(g gomega.Gomega) {
			var route v1alpha1.HostnameRoute
			g.Expect(testClient.Get(testContext, routeKey, &route)).To(gomega.Succeed())
			g.Expect(route.Spec.TunnelRef.Namespace).To(gomega.Equal(namespaceName))
			g.Expect(route.Spec.AllowedNamespaces.From).To(gomega.Equal(v1alpha1.AllowedNamespaceFromSelector))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		var drifted v1alpha1.HostnameRoute
		gomega.Expect(testClient.Get(testContext, routeKey, &drifted)).To(gomega.Succeed())
		before := drifted.DeepCopy()
		drifted.Spec.Hostname = "stale.internal.example"
		gomega.Expect(testClient.Patch(testContext, &drifted, client.MergeFrom(before))).To(gomega.Succeed())
		changed, err := reconciler.reconcileGeneratedHostnameRoutes(testContext, gateway, tunnel, account, []v1alpha1.HostnameRoute{drifted})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(changed).To(gomega.BeTrue())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.HostnameRoute
			g.Expect(testClient.Get(testContext, routeKey, &current)).To(gomega.Succeed())
			g.Expect(current.Spec.Hostname).To(gomega.Equal("private.internal.example"))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		var activeRoute v1alpha1.HostnameRoute
		gomega.Expect(testClient.Get(testContext, routeKey, &activeRoute)).To(gomega.Succeed())
		tunnel.Annotations = map[string]string{v1alpha1.CloudflareTunnelTeardownAnnotation: "true"}
		activeGateway := privatePrerequisiteIR(namespaceName)
		activeState, err := reconciler.reconcilePrivatePrerequisites(testContext, activeGateway, tunnel, account, gatewayInputsView{
			Namespaces:      []corev1.Namespace{*namespace},
			VirtualNetworks: []v1alpha1.VirtualNetwork{vnet},
			HostnameRoutes:  []v1alpha1.HostnameRoute{activeRoute},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(activeState.Pending).NotTo(gomega.ContainSubstring("teardown"))
		gomega.Expect(testClient.Get(testContext, routeKey, &activeRoute)).To(gomega.Succeed())
		tunnel.Annotations = nil
		var retiringRoute v1alpha1.HostnameRoute
		gomega.Expect(testClient.Get(testContext, routeKey, &retiringRoute)).To(gomega.Succeed())
		retiringGateway := privatePrerequisiteIR(namespaceName)
		retiringGateway.Listeners = nil
		retiringGateway.Domains = nil
		retiringState, err := reconciler.reconcilePrivatePrerequisites(testContext, retiringGateway, tunnel, account, gatewayInputsView{
			Namespaces:      []corev1.Namespace{*namespace},
			VirtualNetworks: []v1alpha1.VirtualNetwork{vnet},
			HostnameRoutes:  []v1alpha1.HostnameRoute{retiringRoute},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(retiringState.Pending).To(gomega.ContainSubstring("block-first"))
		gomega.Eventually(func() bool {
			var current v1alpha1.HostnameRoute
			return apierrors.IsNotFound(testClient.Get(testContext, routeKey, &current))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.BeTrue())
		ginkgo.DeferCleanup(func() {
			var route v1alpha1.HostnameRoute
			if testClient.Get(testContext, routeKey, &route) == nil {
				clearFinalizers(testContext, &route)
				_ = testClient.Delete(testContext, &route)
			}
		})

		deniedNamespaceName := namespaceName + "-denied"
		deniedNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: deniedNamespaceName, Labels: map[string]string{"tenant": "private"}}}
		gomega.Expect(testClient.Create(testContext, deniedNamespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, deniedNamespace) })
		gomega.Expect(testClient.Create(testContext, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: deniedNamespaceName},
			Data:       map[string][]byte{"token": []byte("secret")},
		})).To(gomega.Succeed())
		deniedAccount := privatePrerequisiteAccount(deniedNamespaceName, false)
		deniedTunnel := tunnel.DeepCopy()
		deniedTunnel.Namespace = deniedNamespaceName
		deniedGateway := privatePrerequisiteIR(deniedNamespaceName)
		deniedVNet := vnet.DeepCopy()
		deniedVNet.Namespace = deniedNamespaceName
		deniedVNet.Spec.AccountRef.Name = deniedAccount.Name
		gomega.Eventually(func(g gomega.Gomega) {
			var cachedSecret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: deniedNamespaceName, Name: "token"}, &cachedSecret)).To(gomega.Succeed())
			state, err = reconciler.reconcilePrivatePrerequisites(testContext, deniedGateway, deniedTunnel, deniedAccount, gatewayInputsView{
				Namespaces: []corev1.Namespace{*deniedNamespace}, VirtualNetworks: []v1alpha1.VirtualNetwork{*deniedVNet},
			})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(state.Pending).To(gomega.ContainSubstring("requires a ready HostnameRoute"))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		var deniedRoute v1alpha1.HostnameRoute
		deniedKey := types.NamespacedName{Namespace: dataplane.DefaultOperatorNamespace, Name: privateHostnameRouteName(deniedNamespaceName, deniedTunnel.Name, "private")}
		gomega.Expect(apierrors.IsNotFound(testClient.Get(testContext, deniedKey, &deniedRoute))).To(gomega.BeTrue())
	})

	ginkgo.It("blocks private prerequisites while a remotely deleted Tunnel drains", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-private-deleted-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })
		gomega.Expect(testClient.Create(testContext, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: namespaceName},
			Data:       map[string][]byte{"token": []byte("secret")},
		})).To(gomega.Succeed())

		account := privatePrerequisiteAccount(namespaceName, true)
		deletedAt := metav1.Now()
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tunnel", Namespace: namespaceName},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef: corev1.LocalObjectReference{Name: account.Name},
				Listeners: []v1alpha1.CloudflareTunnelListener{{
					Name: "private", Exposure: v1alpha1.ExposurePrivate,
					VirtualNetworkRef: &corev1.LocalObjectReference{Name: "prod"},
				}},
			},
			Status: v1alpha1.CloudflareTunnelStatus{
				TunnelID: "11111111-1111-1111-1111-111111111111", OwnershipVerified: true, DeletedAt: &deletedAt,
			},
		}
		vnet := v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: namespaceName},
			Spec:       v1alpha1.VirtualNetworkSpec{AccountRef: corev1.LocalObjectReference{Name: account.Name}},
			Status: v1alpha1.VirtualNetworkStatus{
				VirtualNetworkID: "vnet-prod",
				Conditions:       []metav1.Condition{{Type: v1alpha1.PrivateNetworkConditionAccepted, Status: metav1.ConditionTrue}},
			},
		}
		gateway := privatePrerequisiteIR(namespaceName)
		gateway.UID = "gateway-uid"
		reconciler := &GatewayReconciler{
			Client: testClient, OperatorNamespace: dataplane.DefaultOperatorNamespace,
			CloudflareFactory: gatewayCloudflareFactory{api: &privatePrerequisiteAPI{}},
		}

		state, err := reconciler.reconcilePrivatePrerequisites(testContext, gateway, tunnel, account, gatewayInputsView{
			Namespaces: []corev1.Namespace{*namespace}, VirtualNetworks: []v1alpha1.VirtualNetwork{vnet},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(state.Pending).To(gomega.ContainSubstring("remotely deleted"))
		gomega.Expect(gateway.Domains[0].Guard).To(gomega.Equal(ir.GuardBlocked))
		gomega.Expect(gateway.Domains[0].Access).To(gomega.BeNil())

		routeKey := types.NamespacedName{
			Namespace: dataplane.DefaultOperatorNamespace,
			Name:      privateHostnameRouteName(namespaceName, tunnel.Name, "private"),
		}
		var route v1alpha1.HostnameRoute
		gomega.Expect(apierrors.IsNotFound(testClient.Get(testContext, routeKey, &route))).To(gomega.BeTrue())
	})

	ginkgo.It("publishes Programmed Pending while a private JWT listener lacks the TLS decryption contract", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-private-pending-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })
		className := fmt.Sprintf("private-unmanaged-%d", fixtureID)
		gatewayClass := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: className},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/other-controller"},
		}
		gomega.Expect(testClient.Create(testContext, gatewayClass)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var current gatewayv1.GatewayClass
			return testClient.Get(testContext, types.NamespacedName{Name: className}, &current)
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, gatewayClass) })
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: namespaceName, Generation: 1},
			Spec:       gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName(className), Listeners: []gatewayv1.Listener{{Name: "private", Port: 443, Protocol: gatewayv1.HTTPSProtocolType}}},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var current gatewayv1.Gateway
			return testClient.Get(testContext, clientObjectKey(gateway), &current)
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		compiled := privatePrerequisiteIR(namespaceName)
		compiled.Domains[0].AccessApplication = namespaceName + "/access"
		application := v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: namespaceName},
			Spec:       v1alpha1.AccessApplicationSpec{OriginJWT: v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired}},
		}
		state := privatePrerequisiteResult{Pending: fmt.Sprintf("Private AccessApplication %s/access requires assumeGatewayTLSDecryption=true before origin JWT enforcement can be programmed", namespaceName)}
		blockPrivateDomains(compiled)
		status := gatewayv1.GatewayStatus{Listeners: []gatewayv1.ListenerStatus{{Name: "private"}}}
		reconciler := &GatewayReconciler{Client: testClient}
		reconciler.setCloudflareProgrammedStatus(&status, gateway, false, state.Pending)
		gomega.Expect(reconciler.patchGatewayStatus(testContext, clientObjectKey(gateway), status)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, clientObjectKey(gateway), &current)).To(gomega.Succeed())
			condition := gatewayCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(condition).NotTo(gomega.BeNil())
			g.Expect(condition.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(condition.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonPending)))
			g.Expect(condition.Message).To(gomega.ContainSubstring("assumeGatewayTLSDecryption=true"))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(privateOriginJWTWithoutTLSContract(compiled, []v1alpha1.AccessApplication{application})).To(gomega.Equal(namespaceName + "/access"))
		gomega.Expect(compiled.Domains[0].Guard).To(gomega.Equal(ir.GuardBlocked))
	})

	ginkgo.It("ignores denied DeviceSettings and selects an authorized current Managed singleton", func() {
		fixtureID := fixtureCounter.Add(1)
		deniedNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("device-denied-%d", fixtureID)}}
		platformNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("device-platform-%d", fixtureID), Labels: map[string]string{"platform": "true"}}}
		gomega.Expect(testClient.Create(testContext, deniedNS)).To(gomega.Succeed())
		gomega.Expect(testClient.Create(testContext, platformNS)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = testClient.Delete(testContext, deniedNS)
			_ = testClient.Delete(testContext, platformNS)
		})
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("device-account-%d", fixtureID)},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID:   "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: deniedNS.Name, Key: "token"}},
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"platform": "true"}},
					Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate},
					PlatformObjects: v1alpha1.GrantPermissionAllowed,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: deniedNS.Name}, Data: map[string][]byte{"token": []byte("secret")}})).To(gomega.Succeed())
		testGlobalDeviceCloudflare.reset(flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true})
		reconciler := &GatewayReconciler{Client: testClient, CloudflareFactory: gatewayCloudflareFactory{api: &privatePrerequisiteAPI{}}}
		falsity, truth := false, true
		denied := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: deniedNS.Name},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef: corev1.LocalObjectReference{Name: account.Name}, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				GatewayProxyEnabled: &falsity, GatewayUDPProxyEnabled: &falsity,
			},
		}
		gomega.Expect(testClient.Create(testContext, denied)).To(gomega.Succeed())
		gomega.Eventually(func() error { return setDeviceSettingsStatus(testContext, denied, falsity, falsity) }, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
		settings, message, err := reconciler.privateDeviceSettings(testContext, account)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(message).To(gomega.BeEmpty())
		gomega.Expect(settings).To(gomega.Equal(observedDeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}))

		authorized := &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: platformNS.Name},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef: corev1.LocalObjectReference{Name: account.Name}, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				GatewayProxyEnabled: &truth, GatewayUDPProxyEnabled: &falsity,
			},
		}
		gomega.Expect(testClient.Create(testContext, authorized)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(setDeviceSettingsStatus(testContext, authorized, truth, falsity)).To(gomega.Succeed())
			settings, message, err = reconciler.privateDeviceSettings(testContext, account)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(message).To(gomega.BeEmpty())
			g.Expect(settings).To(gomega.Equal(observedDeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: false}))
		}, 15*time.Second, 100*time.Millisecond).Should(gomega.Succeed())
	})
})

func setDeviceSettingsStatus(ctx context.Context, object *v1alpha1.DeviceSettings, proxy, udp bool) error {
	var current v1alpha1.DeviceSettings
	if err := testClient.Get(ctx, client.ObjectKeyFromObject(object), &current); err != nil {
		return err
	}
	current.Status.Observed = v1alpha1.DeviceSettingsValues{GatewayProxyEnabled: &proxy, GatewayUDPProxyEnabled: &udp}
	current.Status.ObservedGeneration = current.Generation
	current.Status.Conditions = []metav1.Condition{{
		Type: v1alpha1.DeviceSettingsConditionAccepted, Status: metav1.ConditionTrue,
		Reason: "Accepted", Message: "test fixture is current", LastTransitionTime: metav1.Now(),
		ObservedGeneration: current.Generation,
	}}
	return testClient.Status().Update(ctx, &current)
}

var _ flarecloudflare.API = (*privatePrerequisiteAPI)(nil)

type privatePrerequisiteAPI struct {
	flarecloudflare.API
	settings *flarecloudflare.DeviceSettings
}

func (api *privatePrerequisiteAPI) GetDeviceSettings(context.Context) (flarecloudflare.DeviceSettings, error) {
	if api.settings != nil {
		return *api.settings, nil
	}
	return flarecloudflare.DeviceSettings{GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}, nil
}

func privatePrerequisiteAccount(namespace string, platformObjects bool) *v1alpha1.CloudflareAccount {
	permission := v1alpha1.GrantPermissionDenied
	if platformObjects {
		permission = v1alpha1.GrantPermissionAllowed
	}
	return &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account-" + namespace},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: "token", Namespace: namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"private.internal.example"}, Zones: []string{"*"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePrivate}, PlatformObjects: permission,
			}},
		},
	}
}

func privatePrerequisiteIR(namespace string) *ir.Gateway {
	return &ir.Gateway{
		Key: types.NamespacedName{Namespace: namespace, Name: "gateway"},
		Listeners: []ir.Listener{{
			Name: "private", Hostname: "private.internal.example", Port: 443, EnvoyPort: 443,
			Protocol: "HTTPS", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback,
		}},
		Domains: []ir.ProtectionDomain{{
			Name: "private", ListenerName: "private", EnvoyPort: 443, Protected: true, Guard: ir.GuardForwarding,
			Access: &ir.AccessGuard{AUDs: []string{"aud"}, AuthDomain: "team.cloudflareaccess.com", TeamName: "team"},
		}},
	}
}

func (*privatePrerequisiteAPI) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	return fn()
}

func (*privatePrerequisiteAPI) GetTunnel(_ context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	return flarecloudflare.Tunnel{
		ID:           tunnelID,
		AccountTag:   "0123456789abcdef0123456789abcdef",
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *privatePrerequisiteAPI) UpdateTunnelName(ctx context.Context, tunnelID, name string) (flarecloudflare.Tunnel, error) {
	tunnel, err := api.GetTunnel(ctx, tunnelID)
	if err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	tunnel.Name = name
	return tunnel, nil
}

func (*privatePrerequisiteAPI) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	return flarecloudflare.TunnelConfiguration{
		AccountID: "0123456789abcdef0123456789abcdef",
		TunnelID:  tunnelID,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (*privatePrerequisiteAPI) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	return flarecloudflare.TunnelConfiguration{
		AccountID: "0123456789abcdef0123456789abcdef",
		TunnelID:  tunnelID,
		Version:   1,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (*privatePrerequisiteAPI) IssueTunnelManagementToken(context.Context, string, []flarecloudflare.TunnelManagementResource) (string, error) {
	return "test-management-token", nil
}

func (*privatePrerequisiteAPI) GetTunnelConnector(_ context.Context, _ string, connectorID string, _ int64) (flarecloudflare.TunnelConnector, error) {
	return flarecloudflare.TunnelConnector{ID: connectorID}, nil
}

func (*privatePrerequisiteAPI) ListTunnelConnections(context.Context, string, int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	return nil, false, nil
}

func (*privatePrerequisiteAPI) EvictTunnelConnections(context.Context, string, *string) error {
	return nil
}

func clientObjectKey(object metav1.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
}

func gatewayCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}
