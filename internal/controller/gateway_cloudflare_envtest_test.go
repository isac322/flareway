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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

var _ = ginkgo.Describe("Gateway Cloudflare mode", func() {
	ginkgo.It("creates a default owned CloudflareTunnel named after the Gateway", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-cloudflare-%d", fixtureID)
		configName := fmt.Sprintf("cloudflare-%d", fixtureID)
		className := fmt.Sprintf("cloudflare-%d", fixtureID)
		gatewayName := fmt.Sprintf("edge-%d", fixtureID)

		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		config := &v1alpha1.GatewayClassConfig{
			ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec:       v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: "account"}},
		}
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, config) })

		group := gatewayv1.Group(v1alpha1.Group)
		kind := gatewayv1.Kind("GatewayClassConfig")
		class := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: className},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: gatewayapi.ControllerName,
				ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: configName},
			},
		}
		gomega.Expect(testClient.Create(testContext, class)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, class) })

		hostname := gatewayv1.Hostname("edge.example.com")
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(className),
				Listeners:        []gatewayv1.Listener{{Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())

		key := types.NamespacedName{Namespace: namespaceName, Name: gatewayName}
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, key, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Spec.AccountRef.Name).To(gomega.Equal("account"))
			g.Expect(tunnel.Spec.ManagementPolicy).To(gomega.Equal(v1alpha1.ManagementPolicyManaged))
			g.Expect(tunnel.Spec.DeletionPolicy).To(gomega.Equal(v1alpha1.DeletionPolicyDelete))
			g.Expect(tunnel.OwnerReferences).To(gomega.HaveLen(1))
			g.Expect(tunnel.OwnerReferences[0].Kind).To(gomega.Equal("Gateway"))
			g.Expect(tunnel.OwnerReferences[0].Name).To(gomega.Equal(gatewayName))
			g.Expect(tunnel.OwnerReferences[0].Controller).NotTo(gomega.BeNil())
			g.Expect(*tunnel.OwnerReferences[0].Controller).To(gomega.BeTrue())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		var observed v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, key, &observed)).To(gomega.Succeed())
		statusWriter := &GatewayReconciler{Client: testClient}
		condition := gatewayTunnelCondition(&observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "Pending", "waiting for probes", metav1.Now())
		gomega.Expect(statusWriter.patchTunnelGatewayStatus(
			testContext,
			&observed,
			v1alpha1.CloudflareTunnelConfigVersion{Desired: 3, DesiredHash: "hash"},
			[]v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "edge.example.com", ProtectionDomain: "http", Guard: v1alpha1.HostnameGuardBlocked}},
			[]v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}},
			condition,
		)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, key, &current)).To(gomega.Succeed())
			g.Expect(current.Status.ConfigVersion.Desired).To(gomega.Equal(int64(3)))
			g.Expect(current.Status.ConfigVersion.DesiredHash).To(gomega.Equal("hash"))
			g.Expect(current.Status.Hostnames).To(gomega.HaveLen(1))
			g.Expect(current.Status.Listeners).To(gomega.HaveLen(1))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, key, &observed)).To(gomega.Succeed())
		gomega.Expect(statusWriter.patchTunnelGatewayStatus(
			testContext,
			&observed,
			observed.Status.ConfigVersion,
			nil,
			nil,
			gatewayTunnelCondition(&observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionTrue, "Applied", "applied", metav1.Now()),
		)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, key, &current)).To(gomega.Succeed())
			g.Expect(current.Status.Hostnames).To(gomega.BeEmpty())
			g.Expect(current.Status.Listeners).To(gomega.BeEmpty())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		tokenSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cf-token", Namespace: namespaceName},
			Data:       map[string][]byte{"token": []byte("test-token")},
		}
		gomega.Expect(testClient.Create(testContext, tokenSecret)).To(gomega.Succeed())
		account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: tokenSecret.Name, Namespace: namespaceName, Key: "token",
			}},
		}}
		observed.Status.TunnelID = "11111111-1111-1111-1111-111111111111"
		observed.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{Applied: 4}
		compiled := &ir.Gateway{
			Key:        types.NamespacedName{Namespace: namespaceName, Name: gatewayName},
			Cloudflare: &ir.Cloudflare{AccountID: account.Spec.AccountID, TunnelID: observed.Status.TunnelID},
			Listeners:  []ir.Listener{{Name: "http", Hostname: "edge.example.com", Exposure: ir.ExposurePublic}},
			Domains: []ir.ProtectionDomain{{
				Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "edge.example.com"}},
			}},
		}
		remote := &recordingGatewayCloudflareAPI{remoteVersion: 5, updateVersion: 6}
		statusWriter.CloudflareFactory = gatewayCloudflareFactory{api: remote}
		result, err := statusWriter.reconcileCloudflaredConfiguration(testContext, compiled, &observed, account)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.drift).To(gomega.BeTrue())
		gomega.Expect(result.message).To(gomega.ContainSubstring("overwriting with desired configuration"))
		gomega.Expect(result.version).To(gomega.Equal(int64(6)))
		gomega.Expect(remote.updates).To(gomega.Equal(1))
		gomega.Expect(remote.locks).To(gomega.Equal(1))

		remote.remoteVersion = 4
		result, err = statusWriter.reconcileCloudflaredConfiguration(testContext, compiled, &observed, account)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.drift).To(gomega.BeFalse())
		gomega.Expect(result.version).To(gomega.Equal(int64(6)))
		gomega.Expect(result.hash).NotTo(gomega.BeEmpty())
		gomega.Expect(remote.updates).To(gomega.Equal(2))
		gomega.Expect(remote.locks).To(gomega.Equal(2))
		observed.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{Desired: 6, DesiredHash: result.hash, Applied: 6}
		remote.remoteVersion = 7
		result, err = statusWriter.reconcileCloudflaredConfiguration(testContext, compiled, &observed, account)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.drift).To(gomega.BeTrue())
		gomega.Expect(result.version).To(gomega.Equal(int64(6)))
		gomega.Expect(remote.updates).To(gomega.Equal(3))
		gomega.Expect(remote.locks).To(gomega.Equal(3))

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dataplane",
				Namespace: namespaceName,
				Labels:    map[string]string{dataplane.StandardGatewayLabelKey: gatewayName},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "example.invalid/pause"}}},
		}
		gomega.Expect(testClient.Create(testContext, pod)).To(gomega.Succeed())
		pod.Status.PodIP = "10.0.0.8"
		pod.Status.Phase = corev1.PodRunning
		gomega.Expect(testClient.Status().Update(testContext, pod)).To(gomega.Succeed())
		testSnapshots.mu.Lock()
		testSnapshots.acked[compiled.Key.String()] = "snapshot-1"
		testSnapshots.mu.Unlock()
		statusWriter.Snapshots = testSnapshots
		statusWriter.Prober = &staticGatewayProber{version: 6, ready: true}
		observed.Spec.DNS.Mode = v1alpha1.DNSModeManaged
		observed.Status.DNSRecords = []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "edge.example.com", RecordID: "record"}}
		gomega.Eventually(func(g gomega.Gomega) {
			ready, lagging, dnsReady, err := statusWriter.cloudflareGate(testContext, compiled, &observed, "6", "snapshot-1")
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(ready).To(gomega.BeTrue())
			g.Expect(lagging).To(gomega.BeEmpty())
			g.Expect(dnsReady).To(gomega.BeTrue())
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		statusWriter.Prober = &staticGatewayProber{version: 5, ready: true}
		ready, lagging, _, err := statusWriter.cloudflareGate(testContext, compiled, &observed, "6", "snapshot-1")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(ready).To(gomega.BeFalse())
		gomega.Expect(lagging).To(gomega.ContainElement("dataplane(version 5)"))
		gomega.Expect(testClient.Delete(testContext, gateway)).To(gomega.Succeed())

	})
	ginkgo.It("applies the dataplane while an ObserveOnly tunnel remains pending", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-observe-%d", fixtureID)
		configName := fmt.Sprintf("observe-%d", fixtureID)
		className := fmt.Sprintf("observe-%d", fixtureID)
		gatewayName := fmt.Sprintf("observe-%d", fixtureID)
		tunnelName := fmt.Sprintf("external-%d", fixtureID)
		accountName := fmt.Sprintf("account-%d", fixtureID)
		operatorNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}
		if err := testClient.Create(testContext, operatorNamespace); err != nil {
			gomega.Expect(apierrors.IsAlreadyExists(err)).To(gomega.BeTrue())
		}

		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName, Labels: map[string]string{"tenant": "observe"}}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: accountName},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: "unused", Namespace: namespaceName, Key: "token",
				}},
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "observe"}},
					Hostnames:            []string{"observe.example.com"},
					Zones:                []string{"example.com"},
					Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
					UnprotectedHostnames: []string{"observe.example.com"},
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, account) })

		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: namespaceName},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: accountName},
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				Tunnel: v1alpha1.CloudflareTunnelRemoteSpec{ExternalRef: &v1alpha1.CloudflareTunnelExternalReference{
					TunnelID: "11111111-1111-1111-1111-111111111111",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, tunnel)).To(gomega.Succeed())

		config := &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}, Spec: v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: accountName}}}
		gomega.Expect(testClient.Create(testContext, config)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, config) })
		group := gatewayv1.Group(v1alpha1.Group)
		class := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: className},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: gatewayapi.ControllerName,
				ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: "GatewayClassConfig", Name: configName},
			},
		}
		gomega.Expect(testClient.Create(testContext, class)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, class) })

		hostname := gatewayv1.Hostname("observe.example.com")
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(className),
				Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
					Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: tunnelName,
				}},
				Listeners: []gatewayv1.Listener{{Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		direct := &GatewayReconciler{
			Client:            testClient,
			Scheme:            testClient.Scheme(),
			Snapshots:         testSnapshots,
			BuildSnapshot:     controlledSnapshotBuild,
			OperatorNamespace: dataplane.DefaultOperatorNamespace,
		}

		deploymentKey := types.NamespacedName{Namespace: namespaceName, Name: "flareway-gw-" + gatewayName}
		gomega.Eventually(func() error {
			if _, err := direct.Reconcile(testContext, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespaceName, Name: gatewayName}}); err != nil {
				return fmt.Errorf("reconcile ObserveOnly Gateway: %w", err)
			}
			var deployment appsv1.Deployment
			if err := testClient.Get(testContext, deploymentKey, &deployment); err != nil {
				var current gatewayv1.Gateway
				_ = testClient.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: gatewayName}, &current)
				return fmt.Errorf("get dataplane Deployment: %w; Gateway conditions: %#v", err, current.Status.Conditions)
			}
			if len(deployment.Spec.Template.Spec.Containers) != 2 ||
				deployment.Spec.Template.Spec.Containers[0].Name != "cloudflared" ||
				deployment.Spec.Template.Spec.Containers[1].Name != "envoy" {
				return fmt.Errorf("unexpected dataplane containers: %#v", deployment.Spec.Template.Spec.Containers)
			}
			return nil
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, gateway)).To(gomega.Succeed())
	})

	ginkgo.It("maps labeled AUD Secret lifecycle events to the target Gateway", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-aud-%d", fixtureID)
		gatewayName := fmt.Sprintf("edge-%d", fixtureID)
		applicationName := fmt.Sprintf("access-%d", fixtureID)

		operatorNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}
		if err := testClient.Create(testContext, operatorNamespace); err != nil {
			gomega.Expect(apierrors.IsAlreadyExists(err)).To(gomega.BeTrue())
		}
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		hostname := gatewayv1.Hostname("aud.example.com")
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "missing-class",
				Listeners:        []gatewayv1.Listener{{Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, gateway) })

		audSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "aud-" + applicationName,
				Namespace: dataplane.DefaultOperatorNamespace,
				Labels: map[string]string{
					v1alpha1.AccessApplicationGatewayAUDLabel: gateway.Namespace + "--" + gateway.Name,
					v1alpha1.AccessApplicationAUDSecretLabel:  namespaceName + "--" + applicationName,
				},
			},
			Data: map[string][]byte{
				v1alpha1.AccessApplicationAUDSecretKey: []byte("secret-audience"),
				v1alpha1.AccessApplicationIDSecretKey:  []byte("application-id"),
				"ready":                                []byte("true"),
			},
		}
		gomega.Expect(testClient.Create(testContext, audSecret)).To(gomega.Succeed())

		reconciler := &GatewayReconciler{Client: testClient, OperatorNamespace: dataplane.DefaultOperatorNamespace}
		gomega.Eventually(func(g gomega.Gomega) {
			requests := reconciler.mapSecretToGateways(testContext, audSecret)
			g.Expect(requests).To(gomega.ContainElement(ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespaceName, Name: gatewayName}}))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, audSecret)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			current := &corev1.Secret{}
			return apierrors.IsNotFound(testClient.Get(testContext, types.NamespacedName{
				Namespace: audSecret.Namespace, Name: audSecret.Name,
			}, current))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.BeTrue())
	})

})

type gatewayCloudflareFactory struct {
	api flarecloudflare.API
}

func (factory gatewayCloudflareFactory) Client(_, _ string) flarecloudflare.API {
	return factory.api
}

type recordingGatewayCloudflareAPI struct {
	flarecloudflare.API
	remoteVersion int64
	updateVersion int64
	updates       int
	locks         int
}

func (api *recordingGatewayCloudflareAPI) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	api.locks++
	return fn()
}

func (api *recordingGatewayCloudflareAPI) GetTunnelConfigurationVersion(context.Context, string) (int64, error) {
	return api.remoteVersion, nil
}

func (api *recordingGatewayCloudflareAPI) UpdateTunnelConfiguration(_ context.Context, _ string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (int64, error) {
	api.updates++
	return api.updateVersion, nil
}

type staticGatewayProber struct {
	version int64
	ready   bool
}

func (prober *staticGatewayProber) ConfigVersion(context.Context, string) (int64, error) {
	return prober.version, nil
}

func (prober *staticGatewayProber) Ready(context.Context, string) error {
	if !prober.ready {
		return fmt.Errorf("not ready")
	}
	return nil
}
