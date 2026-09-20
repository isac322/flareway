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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

		directClient, err := client.New(testEnv.Config, client.Options{Scheme: testClient.Scheme()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var observed v1alpha1.CloudflareTunnel
		gomega.Expect(directClient.Get(testContext, key, &observed)).To(gomega.Succeed())
		var currentGateway gatewayv1.Gateway
		gomega.Expect(directClient.Get(testContext, key, &currentGateway)).To(gomega.Succeed())
		observed.Status.TunnelID = "11111111-1111-1111-1111-111111111111"
		observed.Status.OwnershipVerified = true
		observed.Status.ConnectorTokenSecretRef = &corev1.LocalObjectReference{Name: "tunnel-token"}
		observed.Status.GatewayRef = &corev1.LocalObjectReference{Name: currentGateway.Name}
		observed.Status.GatewayUID = currentGateway.UID
		gomega.Expect(directClient.Status().Update(testContext, &observed)).To(gomega.Succeed())
		writerGateway := &ir.Gateway{Key: key, UID: currentGateway.UID}
		statusWriter := &GatewayReconciler{Client: directClient}
		condition := gatewayTunnelCondition(&observed, v1alpha1.CloudflareTunnelConditionConfigApplied, metav1.ConditionFalse, "Pending", "waiting for probes", metav1.Now())
		gomega.Expect(statusWriter.patchTunnelGatewayStatus(
			testContext,
			writerGateway,
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

		gomega.Expect(directClient.Get(testContext, key, &observed)).To(gomega.Succeed())
		gomega.Expect(statusWriter.patchTunnelGatewayStatus(
			testContext,
			writerGateway,
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
		gomega.Eventually(func() error {
			var current v1alpha1.CloudflareTunnel
			if err := directClient.Get(testContext, key, &current); err != nil {
				return err
			}
			current.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{Applied: 4}
			return directClient.Status().Update(testContext, &current)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(directClient.Get(testContext, key, &observed)).To(gomega.Succeed())
		compiled := &ir.Gateway{
			Key:        types.NamespacedName{Namespace: namespaceName, Name: gatewayName},
			UID:        currentGateway.UID,
			Cloudflare: &ir.Cloudflare{AccountID: account.Spec.AccountID, TunnelID: observed.Status.TunnelID},
			Listeners:  []ir.Listener{{Name: "http", Hostname: "edge.example.com", Exposure: ir.ExposurePublic}},
			Domains: []ir.ProtectionDomain{{
				Name: "http", ListenerName: "http", EnvoyPort: 18080, Guard: ir.GuardUnprotected,
				VirtualHosts: []ir.VirtualHost{{Hostname: "edge.example.com"}},
			}},
		}
		remote := &recordingGatewayCloudflareAPI{accountID: account.Spec.AccountID, remoteVersion: 5, updateVersion: 6}
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
		gomega.Eventually(func() error {
			var current v1alpha1.CloudflareTunnel
			if err := directClient.Get(testContext, key, &current); err != nil {
				return err
			}
			current.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{Desired: 6, DesiredHash: result.hash, Applied: 6}
			return directClient.Status().Update(testContext, &current)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(directClient.Get(testContext, key, &observed)).To(gomega.Succeed())
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
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		gomega.Expect(testClient.Status().Update(testContext, pod)).To(gomega.Succeed())
		// The suite's running GatewayReconciler clears the shared publisher for
		// this Gateway while its CloudflareAccount is absent, so the gate checks
		// use a dedicated publisher to keep the seeded ACK isolated.
		gateSnapshots := newFakeSnapshotPublisher()
		gateSnapshots.mu.Lock()
		gateSnapshots.acked[compiled.Key.String()] = "snapshot-1"
		gateSnapshots.mu.Unlock()
		statusWriter.Snapshots = gateSnapshots
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

		statusWriter.Prober = &staticGatewayProber{version: 6, ready: true}
		gateSnapshots.mu.Lock()
		delete(gateSnapshots.acked, compiled.Key.String())
		gateSnapshots.mu.Unlock()
		initial := observed.DeepCopy()
		initial.Status.ConfigVersion.Applied = 0
		ready, lagging, _, err = statusWriter.cloudflareGate(testContext, compiled, initial, "6", "snapshot-1")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(ready).To(gomega.BeFalse())
		gomega.Expect(lagging).To(gomega.ContainElement("Envoy xDS ACK"))
		gomega.Expect(testClient.Delete(testContext, gateway)).To(gomega.Succeed())

	})
	ginkgo.DescribeTable("preserves a colliding xDS client Secret",
		func(foreignOwner bool) {
			fixtureID := fixtureCounter.Add(1)
			namespaceName := fmt.Sprintf("gateway-xds-collision-%d", fixtureID)
			gatewayName := fmt.Sprintf("edge-%d", fixtureID)
			operatorNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dataplane.DefaultOperatorNamespace}}
			if err := testClient.Create(testContext, operatorNamespace); err != nil {
				gomega.Expect(apierrors.IsAlreadyExists(err)).To(gomega.BeTrue())
			}
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
			gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
			ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

			gateway := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: namespaceName},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "missing-class",
					Listeners: []gatewayv1.Listener{{
						Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
					}},
				},
			}
			gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())

			var owners []metav1.OwnerReference
			if foreignOwner {
				foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
					Name: "foreign-owner", Namespace: namespaceName,
				}}
				gomega.Expect(testClient.Create(testContext, foreign)).To(gomega.Succeed())
				owners = []metav1.OwnerReference{
					*metav1.NewControllerRef(foreign, corev1.SchemeGroupVersion.WithKind("ConfigMap")),
				}
			}
			collision := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "flareway-xds-" + gatewayName,
					Namespace:       namespaceName,
					Labels:          map[string]string{"foreign": "keep"},
					Annotations:     map[string]string{"foreign": "keep"},
					OwnerReferences: owners,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foreign": []byte("keep"), corev1.TLSCertKey: []byte("invalid")},
			}
			gomega.Expect(testClient.Create(testContext, collision)).To(gomega.Succeed())
			beforeVersion := collision.ResourceVersion

			reconciler := &GatewayReconciler{Client: testClient, Scheme: testClient.Scheme()}
			err := reconciler.ensureXDSClientCertificate(testContext, gateway)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

			var preserved corev1.Secret
			gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(collision), &preserved)).To(gomega.Succeed())
			gomega.Expect(preserved.ResourceVersion).To(gomega.Equal(beforeVersion))
			gomega.Expect(preserved.Type).To(gomega.Equal(collision.Type))
			gomega.Expect(preserved.Data).To(gomega.Equal(collision.Data))
			gomega.Expect(preserved.Labels).To(gomega.Equal(collision.Labels))
			gomega.Expect(preserved.Annotations).To(gomega.Equal(collision.Annotations))
			gomega.Expect(preserved.OwnerReferences).To(gomega.Equal(collision.OwnerReferences))
		},
		ginkgo.Entry("when it is ownerless", false),
		ginkgo.Entry("when it has a foreign controller", true),
	)

	ginkgo.It("creates and updates an exact Gateway-owned dataplane object through the API server", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-dataplane-owned-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "missing-class",
				Listeners: []gatewayv1.Listener{{
					Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		reconciler := &GatewayReconciler{Client: testClient, Scheme: testClient.Scheme()}

		_, desired := configMapDataplaneObjects(namespaceName, "dataplane")
		gomega.Expect(reconcileGatewayOwnedObject(testContext, reconciler.Client, reconciler.Scheme, gateway, desired)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var created corev1.ConfigMap
			g.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(desired), &created)).To(gomega.Succeed())
			g.Expect(created.Data).To(gomega.Equal(map[string]string{"desired": "value"}))
			g.Expect(metav1.GetControllerOf(&created)).To(gomega.Equal(metav1.NewControllerRef(
				gateway,
				gatewayControllerGVK(),
			)))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		gomega.Eventually(func() error {
			_, updated := configMapDataplaneObjects(namespaceName, "dataplane")
			updated.(*corev1.ConfigMap).Data = map[string]string{"desired": "updated"}
			return reconcileGatewayOwnedObject(testContext, reconciler.Client, reconciler.Scheme, gateway, updated)
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		var updated corev1.ConfigMap
		gomega.Expect(testAPIReader.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: "dataplane"}, &updated)).To(gomega.Succeed())
		gomega.Expect(updated.Data).To(gomega.Equal(map[string]string{"desired": "updated"}))
	})

	ginkgo.It("prunes removed Service listener ports after atomic creation", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-service-ports-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "missing-class",
				Listeners: []gatewayv1.Listener{{
					Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		reconciler := &GatewayReconciler{Client: testClient, Scheme: testClient.Scheme()}
		key := types.NamespacedName{Namespace: namespaceName, Name: "dataplane"}
		initial := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
				{Name: "listener-0", Protocol: corev1.ProtocolTCP, Port: 80},
				{Name: "listener-1", Protocol: corev1.ProtocolTCP, Port: 8080},
			}},
		}
		gomega.Expect(reconcileGatewayOwnedObject(testContext, reconciler.Client, reconciler.Scheme, gateway, initial)).To(gomega.Succeed())

		desired := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{
				Name: "listener-0", Protocol: corev1.ProtocolTCP, Port: 8080,
			}}},
		}
		gomega.Eventually(func() error {
			return reconcileGatewayOwnedObject(testContext, reconciler.Client, reconciler.Scheme, gateway, desired)
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		var service corev1.Service
		gomega.Expect(testAPIReader.Get(testContext, key, &service)).To(gomega.Succeed())
		gomega.Expect(service.Spec.Ports).To(gomega.HaveLen(1))
		gomega.Expect(service.Spec.Ports[0].Name).To(gomega.Equal("listener-0"))
		gomega.Expect(service.Spec.Ports[0].Port).To(gomega.Equal(int32(8080)))
	})

	ginkgo.DescribeTable("preserves colliding dataplane objects through the API server",
		func(objects dataplaneObjectFactory, foreignOwner bool) {
			fixtureID := fixtureCounter.Add(1)
			namespaceName := fmt.Sprintf("gateway-dataplane-collision-%d", fixtureID)
			namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
			gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
			ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

			gateway := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespaceName},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "missing-class",
					Listeners: []gatewayv1.Listener{{
						Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
					}},
				},
			}
			gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())

			current, desired := objects(namespaceName, "dataplane")
			if foreignOwner {
				foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
					Name: "foreign-owner", Namespace: namespaceName,
				}}
				gomega.Expect(testClient.Create(testContext, foreign)).To(gomega.Succeed())
				current.SetOwnerReferences([]metav1.OwnerReference{
					*metav1.NewControllerRef(foreign, corev1.SchemeGroupVersion.WithKind("ConfigMap")),
				})
			}
			gomega.Expect(testClient.Create(testContext, current)).To(gomega.Succeed())

			before := current.DeepCopyObject().(client.Object)
			gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(current), before)).To(gomega.Succeed())
			gomega.Eventually(func() error {
				observed := current.DeepCopyObject().(client.Object)
				return testClient.Get(testContext, client.ObjectKeyFromObject(current), observed)
			}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

			err := reconcileGatewayOwnedObject(testContext, testClient, testClient.Scheme(), gateway, desired)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("not controlled by expected Gateway")))

			after := current.DeepCopyObject().(client.Object)
			gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(current), after)).To(gomega.Succeed())
			gomega.Expect(after).To(gomega.Equal(before))
		},
		ginkgo.Entry("ownerless ConfigMap", dataplaneObjectFactory(configMapDataplaneObjects), false),
		ginkgo.Entry("foreign ConfigMap", dataplaneObjectFactory(configMapDataplaneObjects), true),
		ginkgo.Entry("ownerless Deployment", dataplaneObjectFactory(deploymentDataplaneObjects), false),
		ginkgo.Entry("foreign Deployment", dataplaneObjectFactory(deploymentDataplaneObjects), true),
		ginkgo.Entry("ownerless Service", dataplaneObjectFactory(serviceDataplaneObjects), false),
		ginkgo.Entry("foreign Service", dataplaneObjectFactory(serviceDataplaneObjects), true),
	)

	ginkgo.It("returns a conflict when the controller owner changes before server-side apply", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-dataplane-race-%d", fixtureID)
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })

		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "missing-class",
				Listeners: []gatewayv1.Listener{{
					Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
		foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-owner", Namespace: namespaceName}}
		gomega.Expect(testClient.Create(testContext, foreign)).To(gomega.Succeed())

		currentObject, _ := configMapDataplaneObjects(namespaceName, "dataplane")
		current := currentObject.(*corev1.ConfigMap)
		current.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(gateway, gatewayControllerGVK()),
		}
		gomega.Expect(testClient.Create(testContext, current)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var observed corev1.ConfigMap
			return testClient.Get(testContext, client.ObjectKeyFromObject(current), &observed)
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		racing := &concurrentDataplaneOwnerClient{
			Client: testClient,
			beforeApply: func(ctx context.Context) error {
				var raced corev1.ConfigMap
				if err := testAPIReader.Get(ctx, client.ObjectKeyFromObject(current), &raced); err != nil {
					return err
				}
				raced.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(foreign, corev1.SchemeGroupVersion.WithKind("ConfigMap")),
				}
				return testClient.Update(ctx, &raced)
			},
		}
		_, desired := configMapDataplaneObjects(namespaceName, "dataplane")
		err := reconcileGatewayOwnedObject(testContext, racing, testClient.Scheme(), gateway, desired)
		gomega.Expect(apierrors.IsConflict(err)).To(gomega.BeTrue(), "expected conflict, got %v", err)

		var preserved corev1.ConfigMap
		gomega.Expect(testAPIReader.Get(testContext, client.ObjectKeyFromObject(current), &preserved)).To(gomega.Succeed())
		gomega.Expect(preserved.Data).To(gomega.Equal(map[string]string{"foreign": "keep"}))
		gomega.Expect(metav1.GetControllerOf(&preserved)).To(gomega.Equal(metav1.NewControllerRef(
			foreign,
			corev1.SchemeGroupVersion.WithKind("ConfigMap"),
		)))
	})

	ginkgo.It("allows only the exact live owner to reconcile a shared Tunnel", func() {
		fixtureID := fixtureCounter.Add(1)
		namespaceName := fmt.Sprintf("gateway-shared-owner-%d", fixtureID)
		configName := fmt.Sprintf("shared-owner-%d", fixtureID)
		className := fmt.Sprintf("shared-owner-%d", fixtureID)
		tunnelName := fmt.Sprintf("shared-%d", fixtureID)
		accountName := fmt.Sprintf("shared-account-%d", fixtureID)

		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		gomega.Expect(testClient.Create(testContext, namespace)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, namespace) })
		credential := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cloudflare-token", Namespace: namespaceName},
			Data:       map[string][]byte{"token": []byte("test-token")},
		}
		gomega.Expect(testClient.Create(testContext, credential)).To(gomega.Succeed())

		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: accountName},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Name: credential.Name, Namespace: credential.Namespace, Key: "token",
				}},
			},
		}
		gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, account) })

		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: tunnelName, Namespace: namespaceName},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: accountName},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			},
		}
		gomega.Expect(testClient.Create(testContext, tunnel)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = testClient.Delete(testContext, tunnel) })
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			current.Status.TunnelID = "11111111-1111-1111-1111-111111111111"
			current.Status.AccountID = account.Spec.AccountID
			current.Status.ConnectorTokenSecretRef = &corev1.LocalObjectReference{Name: "first-owner-token"}
			current.Status.ConfigVersion = v1alpha1.CloudflareTunnelConfigVersion{Desired: 17, DesiredHash: "first-owner"}
			current.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: "first.example.com", ProtectionDomain: "http", Guard: v1alpha1.HostnameGuardUnprotected,
			}}
			g.Expect(testClient.Status().Update(testContext, &current)).To(gomega.Succeed())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		config := &v1alpha1.GatewayClassConfig{
			ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec:       v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: accountName}},
		}
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

		tunnelInfrastructure := func() *gatewayv1.GatewayInfrastructure {
			return &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: tunnelName,
			}}
		}
		first := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "a-first", Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(className),
				Infrastructure:   tunnelInfrastructure(),
				Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		second := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "z-second", Namespace: namespaceName},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(className),
				Infrastructure:   tunnelInfrastructure(),
				Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		gomega.Expect(testClient.Create(testContext, first)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.IgnoreNotFound(testClient.Delete(testContext, first))
		})
		gomega.Expect(testClient.Create(testContext, second)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.IgnoreNotFound(testClient.Delete(testContext, second))
		})
		secondReplicas := int32(2)
		secondDataplaneLabels := map[string]string{dataplaneGatewayLabel: namespaceName + "--" + second.Name}
		secondDataplane := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + second.Name, Namespace: namespaceName,
				Labels:          secondDataplaneLabels,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(second, gatewayControllerGVK())},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &secondReplicas,
				Selector: &metav1.LabelSelector{MatchLabels: secondDataplaneLabels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: secondDataplaneLabels},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "example.invalid/cloudflared:latest"}}},
				},
			},
		}
		gomega.Expect(testClient.Create(testContext, secondDataplane)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.IgnoreNotFound(testClient.Delete(testContext, secondDataplane))
		})
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			current.Status.GatewayRef = &corev1.LocalObjectReference{Name: first.Name}
			current.Status.GatewayUID = first.UID
			current.Status.OwnershipVerified = true
			current.Status.ConnectorTokenSecretRef = &corev1.LocalObjectReference{Name: "first-owner-token"}
			g.Expect(testClient.Status().Update(testContext, &current)).To(gomega.Succeed())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		staleFirst := first.DeepCopy()
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			selected, _, _, err := selectLiveTunnelGateway(testContext, testClient, &current)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(sameGatewayIdentity(first, selected)).To(gomega.BeTrue())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		factoryCalls := 0
		remote := &recordingGatewayCloudflareAPI{
			accountID: account.Spec.AccountID, remoteVersion: 17, updateVersion: 18,
		}
		reconciler := &GatewayReconciler{
			Client:            testClient,
			Scheme:            testClient.Scheme(),
			Snapshots:         testSnapshots,
			BuildSnapshot:     controlledSnapshotBuild,
			CloudflareFactory: gatewayCloudflareFactory{api: remote, calls: &factoryCalls},
			OperatorNamespace: dataplane.DefaultOperatorNamespace,
		}
		_, err := reconciler.Reconcile(testContext, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(second)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.updates).To(gomega.Equal(0))
		gomega.Expect(remote.locks).To(gomega.Equal(0))
		gomega.Expect(factoryCalls).To(gomega.Equal(0))

		var observedSecondDataplane appsv1.Deployment
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{
			Namespace: namespaceName, Name: "flareway-gw-" + second.Name,
		}, &observedSecondDataplane)).To(gomega.Succeed())
		gomega.Expect(observedSecondDataplane.Spec.Replicas).NotTo(gomega.BeNil())
		gomega.Expect(*observedSecondDataplane.Spec.Replicas).To(gomega.Equal(int32(0)))

		var preserved v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &preserved)).To(gomega.Succeed())
		gomega.Expect(preserved.Status.ConfigVersion.DesiredHash).To(gomega.Equal("first-owner"))
		gomega.Expect(preserved.Status.Hostnames).To(gomega.Equal(
			[]v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: "first.example.com", ProtectionDomain: "http", Guard: v1alpha1.HostnameGuardUnprotected,
			}},
		))
		gomega.Eventually(func(g gomega.Gomega) {
			var pending gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(second), &pending)).To(gomega.Succeed())
			programmed := meta.FindStatusCondition(pending.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Reason).To(gomega.Equal(string(gatewayv1.GatewayReasonPending)))
			g.Expect(programmed.Message).To(gomega.ContainSubstring(first.Name))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, first)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current gatewayv1.Gateway
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(first), &current))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			selected, _, waitingForDrain, err := selectLiveTunnelGateway(testContext, testClient, &current)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(waitingForDrain).To(gomega.BeFalse())
			g.Expect(sameGatewayIdentity(second, selected)).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, second)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current gatewayv1.Gateway
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(second), &current))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		replacement := first.DeepCopy()
		replacement.ResourceVersion = ""
		replacement.UID = ""
		replacement.CreationTimestamp = metav1.Time{}
		replacement.ManagedFields = nil
		replacement.DeletionTimestamp = nil
		replacement.Finalizers = nil
		replacement.Status = gatewayv1.GatewayStatus{}
		gomega.Expect(testClient.Create(testContext, replacement)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.IgnoreNotFound(testClient.Delete(testContext, replacement))
		})
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(tunnel), &current)).To(gomega.Succeed())
			selected, _, _, err := selectLiveTunnelGateway(testContext, testClient, &current)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(sameGatewayIdentity(replacement, selected)).To(gomega.BeTrue())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(replacement.UID).NotTo(gomega.Equal(staleFirst.UID))

	})

	ginkgo.It("does not create a connector dataplane for an ObserveOnly Tunnel", func() {
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
		gomega.Eventually(func(g gomega.Gomega) {
			_, err := direct.Reconcile(testContext, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespaceName, Name: gatewayName}})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			var deployment appsv1.Deployment
			err = testClient.Get(testContext, deploymentKey, &deployment)
			g.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue())
			var current gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: namespaceName, Name: gatewayName}, &current)).To(gomega.Succeed())
			programmed := meta.FindStatusCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
			g.Expect(programmed).NotTo(gomega.BeNil())
			g.Expect(programmed.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(programmed.Message).To(gomega.ContainSubstring("ObserveOnly"))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, gateway)).To(gomega.Succeed())
	})

	ginkgo.It("maps only exact operator AUD Secret lifecycle events to the target Gateway", func() {
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

		targetKind := gatewayv1.Kind("Gateway")
		targetName := gatewayv1.ObjectName(gateway.Name)
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Name: applicationName, Namespace: namespaceName},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: corev1.LocalObjectReference{Name: "missing-account"},
				Type:       v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					Group: gatewayv1.Group(gatewayv1.GroupName), Kind: targetKind, Name: targetName,
				}},
				Application:      v1alpha1.AccessApplicationSettings{Name: namespaceName + "/" + applicationName, SessionDuration: "1h"},
				Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "policy-allow"}}},
				OriginJWT:        v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
		}
		gomega.Expect(testClient.Create(testContext, application)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.AccessApplication
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(application), &current)).To(gomega.Succeed())
			current.Status.ApplicationID = "application-id"
			g.Expect(testClient.Status().Update(testContext, &current)).To(gomega.Succeed())
			*application = current
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.Succeed())

		audSecret := boundAUDSecret(
			accessAUDSecretName(application, client.ObjectKeyFromObject(gateway)),
			application,
			gateway,
			"secret-audience",
		)
		gomega.Expect(testClient.Create(testContext, &audSecret)).To(gomega.Succeed())

		reconciler := &GatewayReconciler{Client: testClient, OperatorNamespace: dataplane.DefaultOperatorNamespace}
		gomega.Expect(reconciler.mapSecretToGateways(testContext, &audSecret)).To(gomega.ContainElement(
			ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespaceName, Name: gatewayName}},
		))

		forged := audSecret.DeepCopy()
		forged.Namespace = namespaceName
		forged.ResourceVersion = ""
		forged.UID = ""
		forged.CreationTimestamp = metav1.Time{}
		forged.ManagedFields = nil
		gomega.Expect(testClient.Create(testContext, forged)).To(gomega.Succeed())
		gomega.Expect(reconciler.mapSecretToGateways(testContext, forged)).To(gomega.BeEmpty())

		gomega.Expect(client.IgnoreNotFound(testClient.Delete(testContext, &audSecret))).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			current := &corev1.Secret{}
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(&audSecret), current))
		}, 10*time.Second, 100*time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(reconciler.mapSecretToGateways(testContext, &audSecret)).To(gomega.ContainElement(
			ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespaceName, Name: gatewayName}},
		))
	})

})

type gatewayCloudflareFactory struct {
	api   flarecloudflare.API
	calls *int
}

func (factory gatewayCloudflareFactory) Client(_, _ string) flarecloudflare.API {
	if factory.calls != nil {
		(*factory.calls)++
	}
	return factory.api
}

var _ flarecloudflare.API = (*recordingGatewayCloudflareAPI)(nil)

type recordingGatewayCloudflareAPI struct {
	flarecloudflare.API
	accountID     string
	remoteVersion int64
	updateVersion int64
	updates       int
	locks         int
}

func (api *recordingGatewayCloudflareAPI) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	api.locks++
	return fn()
}

func (api *recordingGatewayCloudflareAPI) GetTunnel(_ context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	return flarecloudflare.Tunnel{
		ID:           tunnelID,
		AccountTag:   api.accountID,
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *recordingGatewayCloudflareAPI) UpdateTunnelName(ctx context.Context, tunnelID, name string) (flarecloudflare.Tunnel, error) {
	tunnel, err := api.GetTunnel(ctx, tunnelID)
	if err != nil {
		return flarecloudflare.Tunnel{}, err
	}
	tunnel.Name = name
	return tunnel, nil
}

func (api *recordingGatewayCloudflareAPI) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID,
		TunnelID:  tunnelID,
		Version:   api.remoteVersion,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (api *recordingGatewayCloudflareAPI) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	api.updates++
	return flarecloudflare.TunnelConfiguration{
		AccountID: api.accountID,
		TunnelID:  tunnelID,
		Version:   api.updateVersion,
		Source:    flarecloudflare.TunnelConfigSourceCloudflare,
	}, nil
}

func (*recordingGatewayCloudflareAPI) IssueTunnelManagementToken(context.Context, string, []flarecloudflare.TunnelManagementResource) (string, error) {
	return "test-management-token", nil
}

func (*recordingGatewayCloudflareAPI) GetTunnelConnector(_ context.Context, _ string, connectorID string, _ int64) (flarecloudflare.TunnelConnector, error) {
	return flarecloudflare.TunnelConnector{ID: connectorID}, nil
}

func (*recordingGatewayCloudflareAPI) ListTunnelConnections(context.Context, string, int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	return nil, false, nil
}

func (*recordingGatewayCloudflareAPI) EvictTunnelConnections(context.Context, string, *string) error {
	return nil
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
