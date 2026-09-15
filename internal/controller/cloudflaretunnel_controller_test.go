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
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/ir"
)

var tunnelFixtureCounter atomic.Uint64

func TestCloudflareTunnelGatewayMapper(t *testing.T) {
	g := gomega.NewWithT(t)
	reconciler := new(CloudflareTunnelReconciler)

	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
		Name: "gateway", Namespace: "tenant",
		OwnerReferences: []metav1.OwnerReference{{Name: "irrelevant-owner"}},
	}}
	g.Expect(reconciler.mapGatewayToTunnel(context.Background(), gateway)).To(gomega.Equal([]reconcile.Request{{
		NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "gateway"},
	}}))

	gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "explicit-tunnel",
		},
	}
	g.Expect(reconciler.mapGatewayToTunnel(context.Background(), gateway)).To(gomega.Equal([]reconcile.Request{{
		NamespacedName: types.NamespacedName{Namespace: "tenant", Name: "explicit-tunnel"},
	}}))
}

func TestSelectLiveTunnelGatewayUsesStableUIDBoundElection(t *testing.T) {
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

	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "tenant"},
		Status: v1alpha1.CloudflareTunnelStatus{
			GatewayRef:              &corev1.LocalObjectReference{Name: "second"},
			GatewayUID:              "second-uid",
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "shared-token"},
		},
	}
	tunnelInfrastructure := func() *gatewayv1.GatewayInfrastructure {
		return &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
			Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: tunnel.Name,
		}}
	}
	first := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first", Namespace: tunnel.Namespace, UID: "first-uid",
			CreationTimestamp: metav1.NewTime(time.Unix(100, 0)),
		},
		Spec: gatewayv1.GatewaySpec{Infrastructure: tunnelInfrastructure()},
	}
	second := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "second", Namespace: tunnel.Namespace, UID: "second-uid",
			CreationTimestamp: metav1.NewTime(time.Unix(200, 0)),
		},
		Spec: gatewayv1.GatewaySpec{Infrastructure: tunnelInfrastructure()},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, first, second).Build()

	selected, extra, waitingForDrain, err := selectLiveTunnelGateway(context.Background(), kube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if waitingForDrain || !sameGatewayIdentity(second, selected) {
		t.Fatalf("sticky selected Gateway = %#v, waitingForDrain=%v; want exact recorded identity %#v", selected, waitingForDrain, second)
	}
	if !slices.Equal(extra, []string{first.Name}) {
		t.Fatalf("extra Gateway names = %v, want [%s]", extra, first.Name)
	}

	deleting := second.DeepCopy()
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Unix(250, 0)}
	deleting.Finalizers = []string{"test.flareway.dev/hold"}
	replicas := int32(1)
	staleDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flareway-gw-" + second.Name, Namespace: tunnel.Namespace,
			Labels:          map[string]string{dataplaneGatewayLabel: tunnel.Namespace + "--" + second.Name},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(second, schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}.WithKind("Gateway"))},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "cloudflared",
				Env: []corev1.EnvVar{{Name: "TUNNEL_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "shared-token"},
				}}}},
			}}}},
		},
	}
	deletingKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, deleting, first, staleDeployment).Build()
	selected, _, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), deletingKube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil || !waitingForDrain {
		t.Fatalf("successor admitted before prior connector drain: selected=%#v waitingForDrain=%v", selected, waitingForDrain)
	}
	released := second.DeepCopy()
	released.Spec.Infrastructure = tunnelInfrastructure()
	released.Spec.Infrastructure.ParametersRef.Name = "other-tunnel"
	releasedKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, released, first, staleDeployment.DeepCopy()).Build()
	selected, _, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), releasedKube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil || !waitingForDrain {
		t.Fatalf("successor admitted before released owner drain: selected=%#v waitingForDrain=%v", selected, waitingForDrain)
	}

	zero := int32(0)
	staleDeployment.Spec.Replicas = &zero
	terminatingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "old-connector", Namespace: tunnel.Namespace,
			Labels:            map[string]string{dataplaneGatewayLabel: tunnel.Namespace + "--" + second.Name},
			DeletionTimestamp: &metav1.Time{Time: time.Unix(260, 0)},
			Finalizers:        []string{"test.flareway.dev/hold"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "cloudflared",
			Env: []corev1.EnvVar{{Name: "TUNNEL_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "shared-token"},
			}}}},
		}}},
	}
	terminatingKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, first, staleDeployment.DeepCopy(), terminatingPod).Build()
	selected, _, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), terminatingKube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil || !waitingForDrain {
		t.Fatalf("successor admitted while prior connector Pod was terminating: selected=%#v waitingForDrain=%v", selected, waitingForDrain)
	}

	drainedKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, first, staleDeployment).Build()
	selected, extra, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), drainedKube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if waitingForDrain || !sameGatewayIdentity(first, selected) || len(extra) != 0 {
		t.Fatalf("post-drain election = %#v, extras %v, waitingForDrain=%v", selected, extra, waitingForDrain)
	}

	replacement := second.DeepCopy()
	replacement.UID = "replacement-uid"
	replacement.DeletionTimestamp = nil
	replacement.Finalizers = nil
	staleDeployment.Spec.Replicas = &replicas
	recreatedKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tunnel, replacement, first, staleDeployment.DeepCopy()).Build()
	selected, _, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), recreatedKube, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil || !waitingForDrain {
		t.Fatalf("recreated same-name UID reused recorded ownership: selected=%#v waitingForDrain=%v", selected, waitingForDrain)
	}
	unrelatedDeployment := staleDeployment.DeepCopy()
	unrelatedDeployment.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(replacement, schema.GroupVersion{
		Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version,
	}.WithKind("Gateway"))}
	unrelatedDeployment.Spec.Template.Spec.Containers[0].Env = nil
	noTokenCheckpoint := tunnel.DeepCopy()
	noTokenCheckpoint.Status.ConnectorTokenSecretRef = nil
	if deploymentBelongsToRecordedTunnelOwner(unrelatedDeployment, noTokenCheckpoint) {
		t.Fatal("empty token checkpoint treated a replacement-UID cloudflared Deployment as the prior owner")
	}

	ownedTunnel := tunnel.DeepCopy()
	ownedTunnel.Name = first.Name
	ownedTunnel.Status = v1alpha1.CloudflareTunnelStatus{}
	ownedTunnel.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(first, schema.GroupVersion{
		Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version,
	}.WithKind("Gateway"))}
	firstDefault := first.DeepCopy()
	firstDefault.Spec.Infrastructure = nil
	defaultKube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(ownedTunnel, firstDefault).Build()
	selected, extra, waitingForDrain, err = selectLiveTunnelGateway(context.Background(), defaultKube, ownedTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if waitingForDrain || !sameGatewayIdentity(firstDefault, selected) || len(extra) != 0 {
		t.Fatalf("default Tunnel owner election = %#v, extras %v, waitingForDrain=%v", selected, extra, waitingForDrain)
	}
}

func TestTunnelGatewayBindingsDeduplicateSamePublicHostname(t *testing.T) {
	g := gomega.NewWithT(t)
	httpHostname := gatewayv1.Hostname("app.example.test")
	httpsHostname := gatewayv1.Hostname("app.example.test")
	gateway := &gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
		Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &httpHostname,
	}, {
		Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443, Hostname: &httpsHostname,
	}}}}
	tunnel := &v1alpha1.CloudflareTunnel{}
	zones := []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}}

	public, bindings, err := tunnelGatewayBindings(tunnel, gateway, zones)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(public).To(gomega.Equal([]publicHostname{{
		Hostname: "app.example.test", ZoneID: "zone-example", ZoneName: "example.test",
	}}))
	g.Expect(bindings).To(gomega.HaveLen(2))

	tunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
		Name: "https", Exposure: v1alpha1.ExposurePrivate,
	}}
	_, _, err = tunnelGatewayBindings(tunnel, gateway, zones)
	g.Expect(err).To(gomega.MatchError("hostname exposure must be unique per Gateway: app.example.test"))
}

func TestRemoveDNSRecordsPrefersCurrentOwnershipComment(t *testing.T) {
	g := gomega.NewWithT(t)
	cf := newFakeTunnelCloudflareFactory()
	expected := v1alpha1.CloudflareTunnelDNSRecordStatus{
		Hostname: "app.example.test", RecordID: "record", ZoneID: "zone",
		OwnershipComment: "checkpointed-owner",
	}
	cf.PutDNS(expected.ZoneID, RemoteDNSRecord{
		ID: expected.RecordID, Name: expected.Hostname, Type: "CNAME",
		Content: "tunnel.cfargotunnel.com", Comment: expected.OwnershipComment,
	})

	remaining, conflict, err := removeDNSRecords(
		context.Background(), cf, "current-owner", []v1alpha1.CloudflareTunnelDNSRecordStatus{expected},
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(conflict).NotTo(gomega.BeEmpty())
	g.Expect(remaining).To(gomega.ConsistOf(expected))
	g.Expect(cf.HasDNSRecord(expected.ZoneID, expected.RecordID)).To(gomega.BeTrue())
	g.Expect(cf.Calls()).NotTo(gomega.ContainElement("DeleteDNSRecord"))
}

func TestValidateRemoteTunnelIdentity(t *testing.T) {
	base := RemoteTunnel{
		ID: "tunnel-id", AccountTag: "account-id", Name: "edge",
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
		Status:       flarecloudflare.TunnelStatusHealthy,
	}
	if err := validateRemoteTunnel(base, "account-id"); err != nil {
		t.Fatalf("valid Cloudflare Tunnel rejected: %v", err)
	}
	wrongType := base
	wrongType.Type = flarecloudflare.TunnelTypeWARPConnector
	if err := validateRemoteTunnel(wrongType, "account-id"); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("WARP Connector validation error = %v", err)
	}
	local := base
	local.ConfigSource = flarecloudflare.TunnelConfigSourceLocal
	if err := validateRemoteTunnel(local, "account-id"); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("local configuration validation error = %v", err)
	}
	foreignAccount := base
	foreignAccount.AccountTag = "other-account"
	if err := validateRemoteTunnel(foreignAccount, "account-id"); err == nil || !strings.Contains(err.Error(), "other-account") {
		t.Fatalf("foreign account validation error = %v", err)
	}
}

func TestEnsureRemoteTunnelNeverMutatesWrongRemoteKindOrSource(t *testing.T) {
	for _, test := range []struct {
		name   string
		remote RemoteTunnel
	}{
		{
			name: "WARP Connector",
			remote: RemoteTunnel{
				ID: "remote-id", AccountTag: "account-id", Name: "old-name",
				Type:         flarecloudflare.TunnelTypeWARPConnector,
				ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
			},
		},
		{
			name: "local configuration",
			remote: RemoteTunnel{
				ID: "remote-id", AccountTag: "account-id", Name: "old-name",
				Type:         flarecloudflare.TunnelTypeCloudflared,
				ConfigSource: flarecloudflare.TunnelConfigSourceLocal,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote := newFakeTunnelCloudflareFactory()
			remote.accountID = "account-id"
			remote.PutTunnel(test.remote)
			tunnel := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps"},
				Spec: v1alpha1.CloudflareTunnelSpec{
					Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "desired-name"},
					ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				},
				Status: v1alpha1.CloudflareTunnelStatus{TunnelID: "remote-id", OwnershipVerified: true},
			}
			_, conflict, err := new(CloudflareTunnelReconciler).ensureRemoteTunnel(
				context.Background(), remote, tunnel, "cluster", "account-id",
			)
			if err != nil || conflict == "" {
				t.Fatalf("ensureRemoteTunnel() conflict=%q err=%v", conflict, err)
			}
			if slices.Contains(remote.Calls(), "UpdateTunnelName") {
				t.Fatalf("wrong remote was renamed: calls=%v", remote.Calls())
			}
		})
	}
}
func TestEnsureRemoteTunnelReconcilesManagedNameDrift(t *testing.T) {
	remote := newFakeTunnelCloudflareFactory()
	remote.accountID = "account-id"
	remote.PutTunnel(RemoteTunnel{
		ID: "remote-id", AccountTag: "account-id", Name: "old-name",
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
		Status:       flarecloudflare.TunnelStatusHealthy,
	})
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "apps"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "desired-name"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
		Status: v1alpha1.CloudflareTunnelStatus{TunnelID: "remote-id", OwnershipVerified: true},
	}
	observed, conflict, err := new(CloudflareTunnelReconciler).ensureRemoteTunnel(
		context.Background(), remote, tunnel, "cluster", "account-id",
	)
	if err != nil || conflict != "" || observed.Name != "desired-name" {
		t.Fatalf("ensureRemoteTunnel() = %#v, conflict=%q, err=%v", observed, conflict, err)
	}
	if !slices.Contains(remote.Calls(), "UpdateTunnelName") {
		t.Fatalf("name drift was not reconciled: calls=%v", remote.Calls())
	}
}

func TestDirectTunnelConfigurationTranslation(t *testing.T) {
	proxyType := v1alpha1.CloudflareTunnelProxyTypeSOCKS5
	required := true
	enabled := true
	connectTimeout := int64(30)
	configuration, err := directTunnelConfiguration(&v1alpha1.CloudflareTunnelDirectConfiguration{
		Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
			Hostname: "API.Example.COM",
			Service:  v1alpha1.CloudflareTunnelIngressService{HTTPS: &v1alpha1.CloudflareTunnelAddressService{Address: "origin.example.com:443"}},
			OriginRequest: &v1alpha1.CloudflareTunnelOriginRequest{
				ProxyType: &proxyType,
				Access:    &v1alpha1.CloudflareTunnelOriginAccess{AUDTags: []string{"aud"}, TeamName: "team", Required: &required},
			},
		}, {
			Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
		}},
		WARPRouting: &v1alpha1.CloudflareTunnelWARPRouting{Enabled: &enabled, ConnectTimeout: &connectTimeout},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Ingress) != 2 || configuration.Ingress[0].Hostname != "api.example.com" ||
		configuration.Ingress[0].Service.HTTPS == nil ||
		configuration.Ingress[0].Service.HTTPS.Address != "origin.example.com:443" ||
		configuration.Ingress[0].OriginRequest == nil ||
		configuration.Ingress[0].OriginRequest.ProxyType == nil ||
		*configuration.Ingress[0].OriginRequest.ProxyType != ir.OriginProxyTypeSOCKS5 ||
		configuration.Ingress[0].OriginRequest.Access == nil ||
		configuration.WARPRouting == nil || configuration.WARPRouting.ConnectTimeout == nil ||
		*configuration.WARPRouting.ConnectTimeout != 30 {
		t.Fatalf("Direct configuration IR = %#v", configuration)
	}
}

func TestDirectTunnelAuthorizationRequiresOneGrant(t *testing.T) {
	required, disabled := true, false
	tunnel := &v1alpha1.CloudflareTunnel{
		Spec: v1alpha1.CloudflareTunnelSpec{Configuration: v1alpha1.CloudflareTunnelConfiguration{
			Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
			Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
				OriginRequest: &v1alpha1.CloudflareTunnelOriginRequest{Access: &v1alpha1.CloudflareTunnelOriginAccess{
					AUDTags: []string{"global-aud"}, TeamName: "team", Required: &required,
				}},
				Ingress: []v1alpha1.CloudflareTunnelIngressRule{
					{
						Hostname: "protected.example.com",
						Service:  v1alpha1.CloudflareTunnelIngressService{HTTPS: &v1alpha1.CloudflareTunnelAddressService{Address: "protected.internal:443"}},
					},
					{
						Hostname: "public.example.com",
						Service:  v1alpha1.CloudflareTunnelIngressService{HTTPS: &v1alpha1.CloudflareTunnelAddressService{Address: "public.internal:443"}},
						OriginRequest: &v1alpha1.CloudflareTunnelOriginRequest{Access: &v1alpha1.CloudflareTunnelOriginAccess{
							AUDTags: []string{"public-aud"}, TeamName: "team", Required: &disabled,
						}},
					},
					{Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}}},
				},
			},
		}},
	}
	_, bindings, err := directTunnelBindings(tunnel, []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 || bindings[0].Hostname != "protected.example.com" || bindings[0].Unprotected ||
		bindings[1].Hostname != "public.example.com" || !bindings[1].Unprotected {
		t.Fatalf("Direct bindings = %#v", bindings)
	}

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "blue"}}}
	grant := v1alpha1.CloudflareAccountGrant{
		NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
		Hostnames:            []string{"*.example.com"},
		Zones:                []string{"example.com"},
		Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
		UnprotectedHostnames: []string{"public.example.com"},
	}
	account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{
		grant,
		{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
			PlatformObjects:   v1alpha1.GrantPermissionAllowed,
		},
	}}}
	if decision := authorizeBindings(account, namespace, bindings, true); decision.Allowed {
		t.Fatalf("split Direct grants were combined: %#v", decision)
	}
	account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
	if decision := authorizeBindings(account, namespace, bindings, true); !decision.Allowed || decision.GrantIndex != 0 {
		t.Fatalf("single complete Direct grant was denied: %#v", decision)
	}
}
func TestDirectTunnelBindingsRequireUnprotectedForAnyDuplicateForward(t *testing.T) {
	required := true
	connectTimeout := int64(5)
	tunnel := &v1alpha1.CloudflareTunnel{
		Spec: v1alpha1.CloudflareTunnelSpec{Configuration: v1alpha1.CloudflareTunnelConfiguration{
			Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
			Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
				OriginRequest: &v1alpha1.CloudflareTunnelOriginRequest{Access: &v1alpha1.CloudflareTunnelOriginAccess{
					AUDTags: []string{"aud"}, TeamName: "team", Required: &required,
				}},
				Ingress: []v1alpha1.CloudflareTunnelIngressRule{
					{
						Hostname: "api.example.com",
						Service:  v1alpha1.CloudflareTunnelIngressService{HTTPS: &v1alpha1.CloudflareTunnelAddressService{Address: "first.internal:443"}},
					},
					{
						Hostname:      "api.example.com",
						Service:       v1alpha1.CloudflareTunnelIngressService{HTTPS: &v1alpha1.CloudflareTunnelAddressService{Address: "second.internal:443"}},
						OriginRequest: &v1alpha1.CloudflareTunnelOriginRequest{ConnectTimeout: &connectTimeout},
					},
					{Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}}},
				},
			},
		}},
	}

	_, bindings, err := directTunnelBindings(tunnel, []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Hostname != "api.example.com" || !bindings[0].Unprotected {
		t.Fatalf("duplicate Direct bindings = %#v", bindings)
	}
}

func TestDirectCatchAllRequiresNamespacePlatformGrant(t *testing.T) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"tenant": "blue"}}}
	account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{
		NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "blue"}},
	}}}}

	decision := authorizeBindings(account, namespace, nil, true)
	if decision.Allowed || decision.Reason != authz.ReasonRefNotPermitted {
		t.Fatalf("catch-all Direct configuration without PlatformObjects was allowed: %#v", decision)
	}
	account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
	if decision = authorizeBindings(account, namespace, nil, true); !decision.Allowed || decision.GrantIndex != 0 {
		t.Fatalf("catch-all Direct configuration with a namespace PlatformObjects grant was denied: %#v", decision)
	}
}

func TestReconcileDirectConfigurationOwnsWholeObject(t *testing.T) {
	remote := newFakeTunnelCloudflareFactory()
	remote.accountID = "account-id"
	remote.PutTunnel(RemoteTunnel{
		ID: "remote-id", AccountTag: "account-id", Name: "direct",
		Type:         flarecloudflare.TunnelTypeCloudflared,
		ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare,
		Status:       flarecloudflare.TunnelStatusHealthy,
	})
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "direct", Namespace: "apps", Generation: 3},
		Spec: v1alpha1.CloudflareTunnelSpec{
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
					Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
				}}},
			},
		},
	}
	account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{AccountID: "account-id"}}
	status := v1alpha1.CloudflareTunnelStatus{TunnelID: "remote-id"}
	reconciler := new(CloudflareTunnelReconciler)
	if err := reconciler.reconcileConfiguration(
		context.Background(), remote, tunnel, account,
		v1alpha1.CloudflareTunnelConfigurationModeDirect, &status, metav1.NewTime(time.Unix(100, 0)),
	); err != nil {
		t.Fatal(err)
	}
	if status.ConfigVersion.Applied == 0 || status.ConfigVersion.DesiredHash == "" {
		t.Fatalf("Direct configuration status = %#v", status.ConfigVersion)
	}
	condition := findCondition(status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Direct ConfigApplied condition = %#v", condition)
	}
	if !slices.Contains(remote.Calls(), "UpdateTunnelConfiguration") {
		t.Fatalf("Direct configuration was not written: calls=%v", remote.Calls())
	}
}

func TestTunnelClientStatusIsBounded(t *testing.T) {
	connectors := make([]flarecloudflare.TunnelConnector, tunnelObservationLimit+2)
	for index := range connectors {
		connectors[index].Features = make([]string, tunnelObservationLimit+2)
		connectors[index].ID = fmt.Sprintf("client-%02d", index)
		connectors[index].Connections = make([]flarecloudflare.TunnelConnection, tunnelObservationLimit+2)
		for connectionIndex := range connectors[index].Connections {
			connectors[index].Connections[connectionIndex].ID = fmt.Sprintf("connection-%02d", connectionIndex)
		}
	}
	statuses := tunnelClientStatuses(connectors)
	if len(statuses) != int(tunnelObservationLimit) {
		t.Fatalf("client status length = %d", len(statuses))
	}
	for _, status := range statuses {
		if len(status.Features) != int(tunnelObservationLimit) {
			t.Fatalf("feature status length = %d", len(status.Features))
		}
		if len(status.Connections) != int(tunnelObservationLimit) {
			t.Fatalf("connection status length = %d", len(status.Connections))
		}
	}
}

var _ = ginkgo.Describe("CloudflareTunnel reconciler", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func() {
		ensureSystemNamespace("kube-system")
		ensureSystemNamespace("flareway-system")
	})

	ginkgo.BeforeEach(func() {
		testTunnelCloudflare.Reset()
		testAccountCloudflare.reset()
	})

	ginkgo.It("creates a managed Tunnel, token Secret, DNS record, and merged Ready status", func() {
		fixture := newTunnelFixture("create", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.AccountID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.Name).To(gomega.Equal(fixture.tunnel.Spec.Tunnel.Name))
			g.Expect(tunnel.Status.TunnelType).To(gomega.Equal(v1alpha1.TunnelRemoteTypeCloudflareTunnel))
			g.Expect(tunnel.Status.ConfigSource).To(gomega.Equal(v1alpha1.TunnelConfigSourceCloudflare))
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(tunnel.Status.ConnectorTokenSecretRef).To(gomega.Equal(&corev1.LocalObjectReference{Name: "flareway-tunnel-" + fixture.tunnelKey.Name}))
			var gateway gatewayv1.Gateway
			g.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
			g.Expect(tunnel.Status.GatewayUID).To(gomega.Equal(gateway.UID))
			g.Expect(tunnel.Status.GatewayRef).To(gomega.Equal(&corev1.LocalObjectReference{Name: fixture.gatewayKey.Name}))
			g.Expect(tunnel.Status.Addresses).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords[0].Hostname).To(gomega.Equal(fixture.hostname))
			tunnelReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(tunnelReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(tunnelReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))

			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name}, &secret)).To(gomega.Succeed())
			g.Expect(secret.Data["token"]).To(gomega.Equal([]byte("token-" + tunnel.Status.TunnelID)))
			g.Expect(secret.OwnerReferences).To(gomega.HaveLen(1))
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, []metav1.Condition{{
			Type: v1alpha1.CloudflareTunnelConditionConfigApplied, Status: metav1.ConditionTrue,
			Reason: "Applied", Message: "configuration converged", ObservedGeneration: tunnel.Generation,
			LastTransitionTime: metav1.Now(),
		}}, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
		}})).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			ready := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.Hostnames).To(gomega.Equal([]v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
			}}))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		calls := testTunnelCloudflare.Calls()
		gomega.Expect(calls).To(gomega.ContainElement("CreateTunnel"))
		gomega.Expect(calls).To(gomega.ContainElement("GetTunnelToken"))
		gomega.Expect(calls).To(gomega.ContainElement("CreateCNAME"))
	})
	ginkgo.It("issues an optional management token only into an owned Secret", func() {
		fixture := newTunnelFixture("management-token", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.ManagementToken = &v1alpha1.CloudflareTunnelManagementTokenRequest{
			Resources: []v1alpha1.CloudflareTunnelManagementResource{v1alpha1.CloudflareTunnelManagementResourceLogs},
		}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			ref := tunnel.Status.ManagementTokenSecretRef
			g.Expect(ref).To(gomega.Equal(&corev1.LocalObjectReference{Name: "flareway-tunnel-" + fixture.tunnelKey.Name + "-management"}))
			var secret corev1.Secret
			g.Expect(testClient.Get(testContext, types.NamespacedName{Namespace: fixture.namespace, Name: ref.Name}, &secret)).To(gomega.Succeed())
			g.Expect(secret.Data[v1alpha1.CloudflareTunnelManagementTokenSecretKey]).To(gomega.Equal([]byte("management-token-" + tunnel.Status.TunnelID)))
			g.Expect(secret.OwnerReferences).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(countCall(testTunnelCloudflare.Calls(), "IssueTunnelManagementToken")).To(gomega.Equal(1))
	})
	ginkgo.It("rejects a foreign connector token Secret before retrieving the token", func() {
		fixture := newTunnelFixture("connector-secret-collision", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		secretKey := types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name}
		fixture.beforeTunnel = append(fixture.beforeTunnel, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
			Data:       map[string][]byte{"foreign": []byte("keep")},
		})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			ready := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(gomega.Equal("TokenUnavailable"))
			g.Expect(ready.Message).To(gomega.ContainSubstring("not owned"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var secret corev1.Secret
		gomega.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
		gomega.Expect(secret.Data).To(gomega.Equal(map[string][]byte{"foreign": []byte("keep")}))
		gomega.Expect(secret.OwnerReferences).To(gomega.BeEmpty())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("GetTunnelToken"))
	})

	ginkgo.It("rejects a foreign management token Secret before issuing a token", func() {
		fixture := newTunnelFixture("management-secret-collision", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.ManagementToken = &v1alpha1.CloudflareTunnelManagementTokenRequest{
			Resources: []v1alpha1.CloudflareTunnelManagementResource{v1alpha1.CloudflareTunnelManagementResourceLogs},
		}
		secretKey := types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name + "-management"}
		fixture.beforeTunnel = append(fixture.beforeTunnel, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
			Data:       map[string][]byte{"foreign": []byte("keep")},
		})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			ready := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(gomega.Equal("TokenUnavailable"))
			g.Expect(ready.Message).To(gomega.ContainSubstring("not owned"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var secret corev1.Secret
		gomega.Expect(testClient.Get(testContext, secretKey, &secret)).To(gomega.Succeed())
		gomega.Expect(secret.Data).To(gomega.Equal(map[string][]byte{"foreign": []byte("keep")}))
		gomega.Expect(secret.OwnerReferences).To(gomega.BeEmpty())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("IssueTunnelManagementToken"))
	})

	ginkgo.It("denies an unauthorized Direct catch-all before creating a Tunnel or retrieving credentials", func() {
		fixture := newTunnelFixture("direct-catchall-create-denied", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Configuration = v1alpha1.CloudflareTunnelConfiguration{
			Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
			Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
				Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
			}}},
		}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			accepted := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal(authz.ReasonRefNotPermitted))
			g.Expect(tunnel.Status.TunnelID).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("CreateTunnel", "GetTunnelToken"))
	})

	ginkgo.It("denies an unauthorized Direct catch-all before adopting a Tunnel or retrieving credentials", func() {
		fixture := newTunnelFixture("direct-catchall-adopt-denied", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Configuration = v1alpha1.CloudflareTunnelConfiguration{
			Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
			Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
				Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
			}}},
		}
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "foreign-direct"}
		fixture.tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: fixture.tunnel.Spec.Tunnel.Name}}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "foreign-direct", Name: fixture.tunnel.Spec.Tunnel.Name})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			accepted := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
			g.Expect(accepted).NotTo(gomega.BeNil())
			g.Expect(accepted.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(accepted.Reason).To(gomega.Equal(authz.ReasonRefNotPermitted))
			g.Expect(tunnel.Status.TunnelID).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("GetTunnel", "GetTunnelToken"))
	})

	ginkgo.It("removes a user-supplied teardown annotation from an active Tunnel", func() {
		fixture := newTunnelFixture("active-teardown-annotation", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Annotations = map[string]string{v1alpha1.CloudflareTunnelTeardownAnnotation: "true"}
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Annotations).NotTo(gomega.HaveKey(v1alpha1.CloudflareTunnelTeardownAnnotation))
			g.Expect(tunnel.DeletionTimestamp.IsZero()).To(gomega.BeTrue())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("reports a conflict without adopting a Tunnel whose expected name differs", func() {
		fixture := newTunnelFixture("adopt-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "existing-tunnel"}
		fixture.tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "expected-name"}}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "existing-tunnel", Name: "foreign-name", Status: "healthy"})
		fixture.create()

		gomega.Eventually(func() error {
			var tunnel v1alpha1.CloudflareTunnel
			if err := testClient.Get(testContext, fixture.tunnelKey, &tunnel); err != nil {
				return err
			}
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			if conflict == nil || conflict.Status != metav1.ConditionTrue || conflict.Reason != "AdoptionMismatch" || tunnel.Status.TunnelID != "" {
				return fmt.Errorf("conditions=%v tunnelID=%q calls=%v", tunnel.Status.Conditions, tunnel.Status.TunnelID, testTunnelCloudflare.Calls())
			}
			return nil
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("GetTunnel"))
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("CreateTunnel", "GetTunnelToken", "CreateCNAME"))
	})

	ginkgo.It("rejects adoption of a soft-deleted Tunnel", func() {
		fixture := newTunnelFixture("adopt-deleted", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "deleted-adoption"}
		fixture.tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "deleted-name"}}
		deletedAt := time.Now()
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "deleted-adoption", Name: "deleted-name", Status: "inactive", DeletedAt: &deletedAt})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Message).To(gomega.ContainSubstring("deleted"))
			g.Expect(tunnel.Status.TunnelID).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("GetTunnelToken", "CreateCNAME"))
	})

	ginkgo.It("marks an already-managed soft-deleted Tunnel not ready", func() {
		fixture := newTunnelFixture("managed-deleted", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.MarkTunnelDeleted(tunnel.Status.TunnelID)

		var credential corev1.Secret
		gomega.Expect(testClient.Get(testContext, fixture.credential, &credential)).To(gomega.Succeed())
		before := credential.DeepCopy()
		if credential.Annotations == nil {
			credential.Annotations = map[string]string{}
		}
		credential.Annotations["flareway.bhyoo.com/test-refresh"] = time.Now().Format(time.RFC3339Nano)
		gomega.Expect(testClient.Patch(testContext, &credential, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			ready := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionTunnelReady)
			g.Expect(ready).NotTo(gomega.BeNil())
			g.Expect(ready.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(ready.Message).To(gomega.ContainSubstring("deleted"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("observes an external Tunnel and writes no remote resources", func() {
		fixture := newTunnelFixture("observe", v1alpha1.ManagementPolicyObserveOnly, v1alpha1.DNSModeManaged)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-tunnel"}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "observed-tunnel", Name: "terraform-tunnel", Status: "healthy"})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal("observed-tunnel"))
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeFalse())
			g.Expect(tunnel.Status.ConnectorTokenSecretRef).To(gomega.BeNil())
			g.Expect(tunnel.Status.ManagementTokenSecretRef).To(gomega.BeNil())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.BeEmpty())
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Reason).To(gomega.Equal("ObserveOnly"))
			var connectorSecret corev1.Secret
			err := testClient.Get(testContext, types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name}, &connectorSecret)
			g.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue())
			var managementSecret corev1.Secret
			err = testClient.Get(testContext, types.NamespacedName{Namespace: fixture.namespace, Name: "flareway-tunnel-" + fixture.tunnelKey.Name + "-management"}, &managementSecret)
			g.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		calls := testTunnelCloudflare.Calls()
		gomega.Expect(calls).To(gomega.ContainElements("GetTunnel", "ListTunnelConnections"))
		gomega.Expect(calls).NotTo(gomega.ContainElements(
			"CreateTunnel", "UpdateTunnelName", "GetTunnelToken", "IssueTunnelManagementToken",
			"GetTunnelConfiguration", "UpdateTunnelConfiguration",
			"CreateCNAME", "UpdateCNAME", "DeleteDNSRecord", "DeleteTunnel",
		))
	})

	ginkgo.It("requires explicit matching adoption before a Tunnel observed under ObserveOnly becomes Managed", func() {
		fixture := newTunnelFixture("observe-managed-rejected", v1alpha1.ManagementPolicyObserveOnly, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-managed-rejected"}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "observed-managed-rejected", Name: "terraform-tunnel", Status: "healthy"})
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal("observed-managed-rejected"))
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		before := tunnel.DeepCopy()
		tunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		tunnel.Spec.Tunnel.ExternalRef = nil
		gomega.Expect(testClient.Patch(testContext, &tunnel, client.MergeFrom(before))).To(gomega.Succeed())
		tokenCalls := countCall(testTunnelCloudflare.Calls(), "GetTunnelToken")

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Message).To(gomega.ContainSubstring("observed without ownership"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(countCall(testTunnelCloudflare.Calls(), "GetTunnelToken")).To(gomega.Equal(tokenCalls))
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("UpdateTunnelName"))
	})

	ginkgo.It("adopts an ObserveOnly Tunnel only with matching externalRef and expectation", func() {
		fixture := newTunnelFixture("observe-managed-adopted", v1alpha1.ManagementPolicyObserveOnly, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-managed-adopted"}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "observed-managed-adopted", Name: "terraform-tunnel", Status: "healthy"})
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal("observed-managed-adopted"))
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		before := tunnel.DeepCopy()
		tunnel.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		tunnel.Spec.Adoption = v1alpha1.AdoptionSpec{
			Mode:   v1alpha1.AdoptionModeAdoptByID,
			Expect: v1alpha1.AdoptionExpect{Name: "terraform-tunnel"},
		}
		gomega.Expect(testClient.Patch(testContext, &tunnel, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			g.Expect(current.Status.TunnelID).To(gomega.Equal("observed-managed-adopted"))
			g.Expect(current.Status.OwnershipVerified).To(gomega.BeTrue())
			g.Expect(current.Status.ConnectorTokenSecretRef).NotTo(gomega.BeNil())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElements("GetTunnelToken", "UpdateTunnelName"))
	})

	ginkgo.It("preserves an unverified observed Tunnel during deletion", func() {
		fixture := newTunnelFixture("observe-delete-preserved", v1alpha1.ManagementPolicyObserveOnly, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.Tunnel.ExternalRef = &v1alpha1.CloudflareTunnelExternalReference{TunnelID: "observed-delete-preserved"}
		testTunnelCloudflare.PutTunnel(RemoteTunnel{ID: "observed-delete-preserved", Name: "terraform-tunnel", Status: "healthy"})
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.OwnershipVerified).To(gomega.BeFalse())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasTunnel("observed-delete-preserved")).To(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("EvictTunnelConnections", "DeleteTunnel"))
	})

	ginkgo.It("treats External DNS as ready without listing or mutating records", func() {
		fixture := newTunnelFixture("external-dns", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.BeEmpty())
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(dnsReady.Reason).To(gomega.Equal("External"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("ListDNSRecords", "CreateCNAME", "UpdateCNAME"))
	})

	ginkgo.It("refuses to overwrite a foreign DNS record", func() {
		fixture := newTunnelFixture("dns-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "foreign-record", Name: fixture.hostname, Type: "CNAME",
			Content: "foreign.example.net", Comment: "terraform", Proxied: true,
		})
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			conflict := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("DNSOwnership"))
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionFalse))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElements("UpdateCNAME", "DeleteDNSRecord"))
	})

	ginkgo.It("updates a comment-owned DNS record without requiring Cloudflare tags", func() {
		fixture := newTunnelFixture("dns-comment-owner", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.tunnel.Spec.DNS.RecordComment = "operator note"
		var systemNamespace corev1.Namespace
		gomega.Expect(testClient.Get(testContext, types.NamespacedName{Name: "kube-system"}, &systemNamespace)).To(gomega.Succeed())
		owner := flarecloudflare.DNSRecordComment(string(systemNamespace.UID), fixture.namespace, fixture.gatewayKey.Name)
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "owned-without-tags", Name: fixture.hostname, Type: "CNAME",
			Content: "stale.cfargotunnel.com", Comment: owner, Proxied: false,
		})
		fixture.create()

		var recordID, remoteID string
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
			g.Expect(tunnel.Status.DNSRecords[0].RecordID).To(gomega.Equal("owned-without-tags"))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
			recordID = tunnel.Status.DNSRecords[0].RecordID
			remoteID = tunnel.Status.TunnelID
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		record, ok := testTunnelCloudflare.DNSRecord("zone-example", recordID)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(record.Content).To(gomega.Equal(remoteID + ".cfargotunnel.com"))
		gomega.Expect(record.Comment).To(gomega.Equal(owner + " operator note"))
		gomega.Expect(record.Proxied).To(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("UpdateCNAME"))
	})

	ginkgo.It("keeps a repurposed managed record when DNS becomes External and reports a conflict", func() {
		fixture := newTunnelFixture("external-repurposed-dns", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		managed := tunnel.Status.DNSRecords[0]
		record, ok := testTunnelCloudflare.DNSRecord(managed.ZoneID, managed.RecordID)
		gomega.Expect(ok).To(gomega.BeTrue())
		record.Comment = "terraform"
		record.Content = "foreign.example.net"
		testTunnelCloudflare.PutDNS(managed.ZoneID, record)
		deleteCalls := countCall(testTunnelCloudflare.Calls(), "DeleteDNSRecord")

		before := tunnel.DeepCopy()
		tunnel.Spec.DNS.Mode = v1alpha1.DNSModeExternal
		gomega.Expect(testClient.Patch(testContext, &tunnel, client.MergeFrom(before))).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			g.Expect(current.Status.DNSRecords).To(gomega.ConsistOf(managed))
			dnsReady := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionFalse))
			g.Expect(dnsReady.Reason).To(gomega.Equal("Conflict"))
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(testTunnelCloudflare.HasDNSRecord(managed.ZoneID, managed.RecordID)).To(gomega.BeTrue())
			g.Expect(countCall(testTunnelCloudflare.Calls(), "DeleteDNSRecord")).To(gomega.Equal(deleteCalls))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("checkpoints a created Tunnel before DNS failure and reuses it on retry", func() {
		fixture := newTunnelFixture("dns-checkpoint", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		var tokenChecked, tokenCheckpointed atomic.Bool
		var dnsChecked, dnsCheckpointed atomic.Bool
		checkStatus := func(checked, checkpointed *atomic.Bool) func() {
			return func() {
				if !checked.CompareAndSwap(false, true) {
					return
				}
				var current v1alpha1.CloudflareTunnel
				err := testAPIReader.Get(testContext, fixture.tunnelKey, &current)
				checkpointed.Store(err == nil && current.Status.TunnelID != "")
			}
		}
		testTunnelCloudflare.Before("GetTunnelToken", checkStatus(&tokenChecked, &tokenCheckpointed))
		testTunnelCloudflare.Before("CreateCNAME", checkStatus(&dnsChecked, &dnsCheckpointed))
		testTunnelCloudflare.FailNext("CreateCNAME", errors.New("injected DNS creation failure"))
		fixture.create()

		var remoteID string
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.ConnectorState).To(gomega.Equal(v1alpha1.ConnectorStateHealthy))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionFalse))
			remoteID = tunnel.Status.TunnelID
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(tokenChecked.Load()).To(gomega.BeTrue())
		gomega.Expect(tokenCheckpointed.Load()).To(gomega.BeTrue(), "status.tunnelId was not persisted before GetTunnelToken")
		gomega.Expect(dnsChecked.Load()).To(gomega.BeTrue())
		gomega.Expect(dnsCheckpointed.Load()).To(gomega.BeTrue(), "status.tunnelId was not persisted before CreateCNAME")

		gomega.Eventually(func() bool {
			calls := testTunnelCloudflare.Calls()
			return slices.Contains(calls, "GetTunnel") && countCall(calls, "CreateTunnel") == 1
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasTunnel(remoteID)).To(gomega.BeTrue())

		testTunnelCloudflare.ClearFailure("CreateCNAME")
		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).To(gomega.Equal(remoteID))
			dnsReady := findCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady)
			g.Expect(dnsReady).NotTo(gomega.BeNil())
			g.Expect(dnsReady.Status).To(gomega.Equal(metav1.ConditionTrue))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(countCall(testTunnelCloudflare.Calls(), "CreateTunnel")).To(gomega.Equal(1))
	})

	ginkgo.It("preserves every owned DNS record when another hostname collides and deletes owned records during teardown", func() {
		fixture := newTunnelFixture("multi-host", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		ownedRecord := tunnel.Status.DNSRecords[0]

		collisionHostname := "aaa-" + fixture.hostname
		testTunnelCloudflare.PutDNS("zone-example", RemoteDNSRecord{
			ID: "foreign-multi-host", Name: collisionHostname, Type: "CNAME",
			Content: "foreign.example.net", Comment: "terraform", Proxied: true,
		})
		var gateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		before := gateway.DeepCopy()
		hostname := gatewayv1.Hostname(collisionHostname)
		gateway.Spec.Listeners = append(gateway.Spec.Listeners, gatewayv1.Listener{
			Name: "collision", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname,
		})
		gomega.Expect(testClient.Patch(testContext, &gateway, client.MergeFrom(before))).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("DNSOwnership"))
			g.Expect(current.Status.DNSRecords).To(gomega.ConsistOf(ownedRecord))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasDNSRecord("zone-example", ownedRecord.RecordID)).To(gomega.BeFalse())
		gomega.Expect(testTunnelCloudflare.HasDNSRecord("zone-example", "foreign-multi-host")).To(gomega.BeTrue())
	})

	ginkgo.It("blocks Gateway-absent teardown when a managed DNS record was repurposed", func() {
		fixture := newTunnelFixture("teardown-repurposed-dns", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		managed := tunnel.Status.DNSRecords[0]
		record, ok := testTunnelCloudflare.DNSRecord(managed.ZoneID, managed.RecordID)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(managed.OwnershipComment).NotTo(gomega.BeEmpty())
		gomega.Expect(managed.OwnershipComment).To(gomega.Equal(record.Comment))
		record.Comment = "terraform"
		record.Content = "foreign.example.net"
		testTunnelCloudflare.PutDNS(managed.ZoneID, record)
		deleteCalls := countCall(testTunnelCloudflare.Calls(), "DeleteDNSRecord")

		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardBlocked,
		}})).To(gomega.Succeed())
		var gateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &gateway)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.gatewayKey, &gateway))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			g.Expect(current.Status.GatewayRef).To(gomega.BeNil())
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			blocked := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("DNSOwnership"))
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(current.Status.DNSRecords).To(gomega.ConsistOf(managed))
			g.Expect(testTunnelCloudflare.HasDNSRecord(managed.ZoneID, managed.RecordID)).To(gomega.BeTrue())
			g.Expect(countCall(testTunnelCloudflare.Calls(), "DeleteDNSRecord")).To(gomega.Equal(deleteCalls))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("reports an out-of-band configuration version conflict", func() {
		fixture := newTunnelFixture("version-conflict", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.SetConfigVersion(tunnel.Status.TunnelID, 8)
		gomega.Expect(applyGatewayTunnelVersion(&tunnel, 7, 7)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			conflict := findCondition(current.Status.Conditions, v1alpha1.CloudflareTunnelConditionConflict)
			g.Expect(conflict).NotTo(gomega.BeNil())
			g.Expect(conflict.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(conflict.Reason).To(gomega.Equal("ConfigurationChanged"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("orphans the remote Tunnel when deletionPolicy is Orphan", func() {
		fixture := newTunnelFixture("orphan", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.tunnel.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		remoteID := tunnel.Status.TunnelID
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.HasTunnel(remoteID)).To(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
	})

	ginkgo.It("continues fail-closed teardown when the owning Gateway is already absent", func() {
		fixture := newTunnelFixture("owner-gone", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		managed := tunnel.Status.DNSRecords[0]
		record, ok := testTunnelCloudflare.DNSRecord(managed.ZoneID, managed.RecordID)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(managed.OwnershipComment).NotTo(gomega.BeEmpty())
		gomega.Expect(managed.OwnershipComment).To(gomega.Equal(record.Comment))
		testTunnelCloudflare.PutDNS(managed.ZoneID, RemoteDNSRecord{
			ID: "foreign-same-hostname", Name: managed.Hostname, Type: "CNAME",
			Content: "foreign.example.net", Comment: "terraform", Proxied: true,
		})
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding,
		}})).To(gomega.Succeed())

		var gateway gatewayv1.Gateway
		gomega.Expect(testClient.Get(testContext, fixture.gatewayKey, &gateway)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &gateway)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.gatewayKey, &gateway))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Eventually(func(g gomega.Gomega) {
			var current v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &current)).To(gomega.Succeed())
			g.Expect(current.Status.GatewayRef).To(gomega.BeNil())
			g.Expect(current.Status.DNSRecords).To(gomega.ConsistOf(managed))
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

		replicas := int32(1)
		staleDataplane := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + fixture.gatewayKey.Name, Namespace: fixture.namespace,
				Labels: map[string]string{dataplaneGatewayLabel: fixture.namespace + "--" + fixture.gatewayKey.Name},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "stale-dataplane"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "stale-dataplane"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "placeholder", Image: "example.invalid/placeholder",
					}}},
				},
			},
		}
		gomega.Expect(testClient.Create(testContext, staleDataplane)).To(gomega.Succeed())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func() error {
			var current v1alpha1.CloudflareTunnel
			err := testClient.Get(testContext, fixture.tunnelKey, &current)
			if apierrors.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("still deleting: gatewayRef=%v conditions=%v calls=%v", current.Status.GatewayRef, current.Status.Conditions, testTunnelCloudflare.Calls())
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElements("DeleteDNSRecord", "DeleteTunnel"))
		gomega.Expect(testTunnelCloudflare.HasDNSRecord(managed.ZoneID, managed.RecordID)).To(gomega.BeFalse())
		gomega.Expect(testTunnelCloudflare.HasDNSRecord(managed.ZoneID, "foreign-same-hostname")).To(gomega.BeTrue())
	})

	ginkgo.It("actively scales the recorded Gateway dataplane to zero before remote deletion", func() {
		fixture := newTunnelFixture("empty-host-drain", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.Hostnames).To(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		replicas := int32(1)
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flareway-gw-" + fixture.gatewayKey.Name, Namespace: fixture.namespace,
				Labels: map[string]string{dataplaneGatewayLabel: fixture.namespace + "--" + fixture.gatewayKey.Name},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "drain-test"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "drain-test"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "cloudflared", Image: "example.invalid/cloudflared",
						Env: []corev1.EnvVar{{Name: "TUNNEL_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: tunnel.Status.ConnectorTokenSecretRef.Name},
							Key:                  v1alpha1.CloudflareTunnelConnectorTokenSecretKey,
						}}}},
					}}},
				},
			},
		}
		gomega.Expect(testClient.Create(testContext, deployment)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var current appsv1.Deployment
			g.Expect(testClient.Get(testContext, client.ObjectKeyFromObject(deployment), &current)).To(gomega.Succeed())
			g.Expect(current.Spec.Replicas).NotTo(gomega.BeNil())
			g.Expect(*current.Spec.Replicas).To(gomega.Equal(int32(0)))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("DeleteTunnel"))
	})

	ginkgo.It("blocks teardown on a platform HostnameRoute that cross-references the tenant Tunnel", func() {
		fixture := newTunnelFixture("cross-ns-route", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		route := &v1alpha1.HostnameRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "platform-route-" + fixture.tunnelKey.Namespace, Namespace: "flareway-system"},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: corev1.LocalObjectReference{Name: fixture.account},
				Hostname:   "private." + fixture.hostname,
				TunnelRef: v1alpha1.TunnelReference{
					Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel,
					Name: fixture.tunnelKey.Name, Namespace: fixture.tunnelKey.Namespace,
				},
				DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}
		gomega.Expect(testClient.Create(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.HostnameRoute
			return testClient.Get(testContext, client.ObjectKeyFromObject(route), &current) == nil
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.BeTrue())

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())
		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("DependenciesRemain"))
			g.Expect(blocked.Message).To(gomega.ContainSubstring("HostnameRoute/flareway-system/" + route.Name))
			g.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		gomega.Expect(testClient.Delete(testContext, route)).To(gomega.Succeed())
		gomega.Eventually(func() bool {
			var current v1alpha1.HostnameRoute
			return apierrors.IsNotFound(testClient.Get(testContext, client.ObjectKeyFromObject(route), &current))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Eventually(func() bool {
			var current v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &current))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
		gomega.Expect(testTunnelCloudflare.Calls()).To(gomega.ContainElement("DeleteTunnel"))
	})

	ginkgo.It("keeps the finalizer when remote Tunnel deletion fails and retries safely", func() {
		fixture := newTunnelFixture("delete-tunnel-failure", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeExternal)
		fixture.create()

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Eventually(func(g gomega.Gomega) {
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		testTunnelCloudflare.FailNext("DeleteTunnel", errors.New("injected Tunnel delete failure"))
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("TunnelDeleteFailed"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testTunnelCloudflare.ClearFailure("DeleteTunnel")
		gomega.Eventually(func() bool {
			var deleting v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &deleting))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())
	})

	ginkgo.It("keeps the finalizer on DNS deletion failure and resumes the ordered teardown", func() {
		fixture := newTunnelFixture("delete", v1alpha1.ManagementPolicyManaged, v1alpha1.DNSModeManaged)
		fixture.create()

		gomega.Eventually(func(g gomega.Gomega) {
			var tunnel v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
			g.Expect(tunnel.Status.TunnelID).NotTo(gomega.BeEmpty())
			g.Expect(tunnel.Status.DNSRecords).To(gomega.HaveLen(1))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		var tunnel v1alpha1.CloudflareTunnel
		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardForwarding,
		}})).To(gomega.Succeed())
		testTunnelCloudflare.FailNext("DeleteDNSRecord", errors.New("injected DNS delete failure"))
		gomega.Expect(testClient.Delete(testContext, &tunnel)).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			g.Expect(deleting.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation]).To(gomega.Equal("true"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())
		gomega.Consistently(func() []string { return testTunnelCloudflare.Calls() }).WithTimeout(750 * time.Millisecond).ShouldNot(gomega.ContainElement("DeleteDNSRecord"))

		gomega.Expect(testClient.Get(testContext, fixture.tunnelKey, &tunnel)).To(gomega.Succeed())
		gomega.Expect(applyGatewayTunnelStatus(&tunnel, nil, []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: fixture.hostname, ProtectionDomain: "public", Guard: v1alpha1.HostnameGuardBlocked,
		}})).To(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			var deleting v1alpha1.CloudflareTunnel
			g.Expect(testClient.Get(testContext, fixture.tunnelKey, &deleting)).To(gomega.Succeed())
			blocked := findCondition(deleting.Status.Conditions, v1alpha1.CloudflareTunnelConditionCleanupBlocked)
			g.Expect(blocked).NotTo(gomega.BeNil())
			g.Expect(blocked.Status).To(gomega.Equal(metav1.ConditionTrue))
			g.Expect(blocked.Reason).To(gomega.Equal("DNSDeleteFailed"))
			g.Expect(deleting.Finalizers).To(gomega.ContainElement(v1alpha1.CloudflareTunnelFinalizer))
			g.Expect(testTunnelCloudflare.Calls()).NotTo(gomega.ContainElement("DeleteTunnel"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.Succeed())

		testTunnelCloudflare.ClearFailure("DeleteDNSRecord")
		gomega.Eventually(func() bool {
			var deleting v1alpha1.CloudflareTunnel
			return apierrors.IsNotFound(testClient.Get(testContext, fixture.tunnelKey, &deleting))
		}).WithTimeout(15 * time.Second).WithPolling(200 * time.Millisecond).Should(gomega.BeTrue())

		calls := testTunnelCloudflare.Calls()
		dnsDelete := slices.Index(calls, "DeleteDNSRecord")
		connectionEviction := slices.Index(calls, "EvictTunnelConnections")
		tunnelDelete := slices.Index(calls, "DeleteTunnel")
		gomega.Expect(dnsDelete).To(gomega.BeNumerically(">=", 0))
		gomega.Expect(connectionEviction).To(gomega.BeNumerically(">", dnsDelete))
		gomega.Expect(tunnelDelete).To(gomega.BeNumerically(">", connectionEviction))
	})
})

type tunnelFixture struct {
	namespace    string
	account      string
	credential   types.NamespacedName
	gatewayKey   types.NamespacedName
	tunnelKey    types.NamespacedName
	hostname     string
	tunnel       *v1alpha1.CloudflareTunnel
	beforeTunnel []client.Object
}

func newTunnelFixture(prefix string, management v1alpha1.ManagementPolicy, dnsMode v1alpha1.DNSMode) *tunnelFixture {
	id := tunnelFixtureCounter.Add(1)
	namespace := fmt.Sprintf("tunnel-%s-%d", prefix, id)
	account := fmt.Sprintf("account-%d", id)
	gatewayName := "gateway"
	hostname := fmt.Sprintf("%s-%d.example.test", prefix, id)
	key := types.NamespacedName{Namespace: namespace, Name: "tunnel"}
	return &tunnelFixture{
		namespace: namespace, account: account,
		credential: types.NamespacedName{Namespace: namespace, Name: "cloudflare-token"},
		gatewayKey: types.NamespacedName{Namespace: namespace, Name: gatewayName},
		tunnelKey:  key, hostname: hostname,
		tunnel: &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: v1alpha1.CloudflareTunnelSpec{
				AccountRef:       corev1.LocalObjectReference{Name: account},
				Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: fmt.Sprintf("remote-%d", id)},
				ManagementPolicy: management,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: dnsMode},
			},
		},
	}
}

func (f *tunnelFixture) create() {
	ginkgo.By("creating the namespace, credential, verified account, Gateway, and Tunnel")
	gomega.Expect(testClient.Create(testContext, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: f.namespace, Labels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace},
	}})).To(gomega.Succeed())
	ginkgo.DeferCleanup(forceDeleteTunnelNamespace, f.namespace)
	gomega.Expect(testClient.Create(testContext, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: f.credential.Name, Namespace: f.credential.Namespace},
		Data:       map[string][]byte{"token": []byte("api-token")},
	})).To(gomega.Succeed())

	testAccountCloudflare.mu.Lock()
	testAccountCloudflare.zones = []flarecloudflare.Zone{{ID: "zone-example", Name: "example.test"}}
	testAccountCloudflare.mu.Unlock()

	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: f.account},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: fmt.Sprintf("%032x", tunnelFixtureCounter.Load()),
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
				Name: f.credential.Name, Namespace: f.credential.Namespace, Key: "token",
			}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"flareway.bhyoo.com/tenant": f.namespace}},
				Hostnames:         []string{"*.example.test"}, Zones: []string{"example.test"},
				Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
			}},
		},
	}
	gomega.Expect(testClient.Create(testContext, account)).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { _ = testClient.Delete(context.Background(), account) })
	gomega.Eventually(func() error {
		var current v1alpha1.CloudflareAccount
		if err := testClient.Get(testContext, types.NamespacedName{Name: f.account}, &current); err != nil {
			return err
		}
		current.Status.Verified.Zones = []v1alpha1.CloudflareVerifiedZone{{ID: "zone-example", Name: "example.test"}}
		current.Status.Conditions = []metav1.Condition{{
			Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted",
			ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now(),
		}, {
			Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid",
			ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now(),
		}}
		return testClient.Status().Update(testContext, &current)
	}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(gomega.Succeed())

	hostname := gatewayv1.Hostname(f.hostname)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: f.gatewayKey.Name, Namespace: f.gatewayKey.Namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "unused-by-tunnel-controller",
			Listeners:        []gatewayv1.Listener{{Name: "public", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("CloudflareTunnel"), Name: f.tunnelKey.Name,
			}},
		},
	}
	gomega.Expect(testClient.Create(testContext, gateway)).To(gomega.Succeed())
	for _, object := range f.beforeTunnel {
		gomega.Expect(testClient.Create(testContext, object)).To(gomega.Succeed())
	}
	gomega.Expect(testClient.Create(testContext, f.tunnel)).To(gomega.Succeed())
}

func ensureSystemNamespace(name string) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := testClient.Create(testContext, namespace)
	gomega.Expect(err).To(gomega.Or(gomega.Succeed(), gomega.MatchError(gomega.ContainSubstring("already exists"))))
}

func applyGatewayTunnelStatus(tunnel *v1alpha1.CloudflareTunnel, conditions []metav1.Condition, hostnames []v1alpha1.CloudflareTunnelHostnameStatus) error {
	conditionValues := make([]any, 0, len(conditions))
	for _, condition := range conditions {
		conditionValues = append(conditionValues, map[string]any{
			"type": condition.Type, "status": string(condition.Status), "reason": condition.Reason,
			"message": condition.Message, "observedGeneration": condition.ObservedGeneration,
			"lastTransitionTime": condition.LastTransitionTime.Format(time.RFC3339),
		})
	}
	hostnameValues := make([]any, 0, len(hostnames))
	for _, hostname := range hostnames {
		hostnameValues = append(hostnameValues, map[string]any{
			"hostname": hostname.Hostname, "protectionDomain": hostname.ProtectionDomain,
			"guard": string(hostname.Guard), "accessApplication": hostname.AccessApplication,
			"appliedVersion": hostname.AppliedVersion,
		})
	}
	status := map[string]any{"conditions": conditionValues, "hostnames": hostnameValues}
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(), "kind": "CloudflareTunnel",
		"metadata": map[string]any{"name": tunnel.Name, "namespace": tunnel.Namespace},
		"status":   status,
	}}
	return testClient.Status().Apply(testContext, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func applyGatewayTunnelVersion(tunnel *v1alpha1.CloudflareTunnel, desired, applied int64) error {
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.GroupVersion.String(), "kind": "CloudflareTunnel",
		"metadata": map[string]any{"name": tunnel.Name, "namespace": tunnel.Namespace},
		"status": map[string]any{"configVersion": map[string]any{
			"desired": desired, "applied": applied, "desiredHash": fmt.Sprintf("version-%d", desired),
		}},
	}}
	return testClient.Status().Apply(testContext, client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership)
}

func forceDeleteTunnelNamespace(namespace string) {
	ctx := context.Background()
	var tunnels v1alpha1.CloudflareTunnelList
	if err := testClient.List(ctx, &tunnels, client.InNamespace(namespace)); err == nil {
		for i := range tunnels.Items {
			if len(tunnels.Items[i].Finalizers) == 0 {
				continue
			}
			before := tunnels.Items[i].DeepCopy()
			tunnels.Items[i].Finalizers = nil
			_ = testClient.Patch(ctx, &tunnels.Items[i], client.MergeFrom(before))
		}
	}
	_ = testClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
}

type fakeTunnelCloudflareFactory struct {
	mu sync.Mutex

	accountID   string
	tunnels     map[string]RemoteTunnel
	tokens      map[string]string
	configs     map[string]flarecloudflare.TunnelConfiguration
	connections map[string][]flarecloudflare.TunnelConnector
	dns         map[string]map[string]RemoteDNSRecord
	calls       []string
	fail        map[string]error
	before      map[string]func()
	next        int
}

func newFakeTunnelCloudflareFactory() *fakeTunnelCloudflareFactory {
	factory := &fakeTunnelCloudflareFactory{}
	factory.Reset()
	return factory
}

func (f *fakeTunnelCloudflareFactory) Client(_ string, accountID string) (TunnelCloudflareClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accountID = accountID
	return f, nil
}

func (f *fakeTunnelCloudflareFactory) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accountID = ""
	f.tunnels = map[string]RemoteTunnel{}
	f.tokens = map[string]string{}
	f.configs = map[string]flarecloudflare.TunnelConfiguration{}
	f.connections = map[string][]flarecloudflare.TunnelConnector{}
	f.dns = map[string]map[string]RemoteDNSRecord{}
	f.calls = nil
	f.fail = map[string]error{}
	f.before = map[string]func(){}
	f.next = 0
}
func (f *fakeTunnelCloudflareFactory) PutTunnel(tunnel RemoteTunnel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tunnel = f.normalizeTunnel(tunnel)
	f.tunnels[tunnel.ID] = tunnel
	f.tokens[tunnel.ID] = "token-" + tunnel.ID
	f.configs[tunnel.ID] = f.configuration(tunnel.ID, 1)
}

func (f *fakeTunnelCloudflareFactory) MarkTunnelDeleted(tunnelID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tunnel := f.tunnels[tunnelID]
	deletedAt := time.Now()
	tunnel.DeletedAt = &deletedAt
	tunnel.Status = flarecloudflare.TunnelStatusInactive
	f.tunnels[tunnelID] = tunnel
}

func (f *fakeTunnelCloudflareFactory) SetConfigVersion(tunnelID string, version int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs[tunnelID] = f.configuration(tunnelID, version)
}

func (f *fakeTunnelCloudflareFactory) HasTunnel(tunnelID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tunnels[tunnelID]
	return ok
}

func (f *fakeTunnelCloudflareFactory) HasDNSRecord(zoneID, recordID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.dns[zoneID][recordID]
	return ok
}

func (f *fakeTunnelCloudflareFactory) DNSRecord(zoneID, recordID string) (RemoteDNSRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.dns[zoneID][recordID]
	return record, ok
}

func (f *fakeTunnelCloudflareFactory) PutDNS(zone string, record RemoteDNSRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dns[zone] == nil {
		f.dns[zone] = map[string]RemoteDNSRecord{}
	}
	f.dns[zone][record.ID] = record
}

func (f *fakeTunnelCloudflareFactory) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func countCall(calls []string, operation string) int {
	count := 0
	for _, call := range calls {
		if call == operation {
			count++
		}
	}
	return count
}

func (f *fakeTunnelCloudflareFactory) FailNext(operation string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[operation] = err
}

func (f *fakeTunnelCloudflareFactory) ClearFailure(operation string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fail, operation)
}

func (f *fakeTunnelCloudflareFactory) Before(operation string, hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before[operation] = hook
}

func (f *fakeTunnelCloudflareFactory) record(operation string) error {
	f.calls = append(f.calls, operation)
	if hook := f.before[operation]; hook != nil {
		hook()
	}
	if err := f.fail[operation]; err != nil {
		return err
	}
	return nil
}
func (f *fakeTunnelCloudflareFactory) CreateTunnel(_ context.Context, name string) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateTunnel"); err != nil {
		return RemoteTunnel{}, err
	}
	f.next++
	id := fmt.Sprintf("tunnel-%d", f.next)
	tunnel := f.normalizeTunnel(RemoteTunnel{ID: id, Name: name, Status: flarecloudflare.TunnelStatusHealthy})
	f.tunnels[id] = tunnel
	f.tokens[id] = "token-" + id
	f.configs[id] = f.configuration(id, 1)
	return tunnel, nil
}

func (f *fakeTunnelCloudflareFactory) normalizeTunnel(tunnel RemoteTunnel) RemoteTunnel {
	if tunnel.AccountTag == "" {
		tunnel.AccountTag = f.accountID
	}
	if tunnel.Type == "" {
		tunnel.Type = flarecloudflare.TunnelTypeCloudflared
	}
	if tunnel.ConfigSource == "" {
		tunnel.ConfigSource = flarecloudflare.TunnelConfigSourceCloudflare
	}
	if tunnel.Status == "" || tunnel.Status == flarecloudflare.TunnelStatus("healthy") {
		tunnel.Status = flarecloudflare.TunnelStatusHealthy
	}
	if tunnel.Status == flarecloudflare.TunnelStatus("inactive") {
		tunnel.Status = flarecloudflare.TunnelStatusInactive
	}
	if tunnel.CreatedAt.IsZero() {
		tunnel.CreatedAt = time.Unix(100, 0)
	}
	return tunnel
}

func (f *fakeTunnelCloudflareFactory) configuration(tunnelID string, version int64) flarecloudflare.TunnelConfiguration {
	return flarecloudflare.TunnelConfiguration{
		AccountID: f.accountID, TunnelID: tunnelID, Version: version,
		Source: flarecloudflare.TunnelConfigSourceCloudflare, CreatedAt: time.Unix(100, 0),
		Config: []byte(`{"ingress":[{"service":"http_status:404"}]}`),
	}
}

func (f *fakeTunnelCloudflareFactory) GetTunnel(_ context.Context, tunnelID string) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnel"); err != nil {
		return RemoteTunnel{}, err
	}
	tunnel, ok := f.tunnels[tunnelID]
	if !ok {
		return RemoteTunnel{}, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	tunnel = f.normalizeTunnel(tunnel)
	f.tunnels[tunnelID] = tunnel
	configuration := f.configs[tunnelID]
	if configuration.AccountID == "" {
		f.configs[tunnelID] = f.configuration(tunnelID, configuration.Version)
	}
	return tunnel, nil
}

func (f *fakeTunnelCloudflareFactory) UpdateTunnelName(_ context.Context, tunnelID, name string) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateTunnelName"); err != nil {
		return RemoteTunnel{}, err
	}
	tunnel, ok := f.tunnels[tunnelID]
	if !ok {
		return RemoteTunnel{}, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	tunnel.Name = name
	f.tunnels[tunnelID] = tunnel
	return tunnel, nil
}

func (f *fakeTunnelCloudflareFactory) DeleteTunnel(_ context.Context, tunnelID string, cascade bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !cascade {
		return errors.New("cascade must be true")
	}
	if err := f.record("DeleteTunnel"); err != nil {
		return err
	}
	delete(f.tunnels, tunnelID)
	delete(f.tokens, tunnelID)
	return nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnelToken(_ context.Context, tunnelID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelToken"); err != nil {
		return "", err
	}
	token, ok := f.tokens[tunnelID]
	if !ok {
		return "", fmt.Errorf("token for %s not found", tunnelID)
	}
	return token, nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnelConfiguration(_ context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetTunnelConfiguration"); err != nil {
		return flarecloudflare.TunnelConfiguration{}, err
	}
	configuration, ok := f.configs[tunnelID]
	if !ok {
		return flarecloudflare.TunnelConfiguration{}, fmt.Errorf("configuration for %s not found", tunnelID)
	}
	return configuration, nil
}

func (f *fakeTunnelCloudflareFactory) UpdateTunnelConfiguration(_ context.Context, tunnelID string, _ zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateTunnelConfiguration"); err != nil {
		return flarecloudflare.TunnelConfiguration{}, err
	}
	version := f.configs[tunnelID].Version + 1
	configuration := f.configuration(tunnelID, version)
	f.configs[tunnelID] = configuration
	return configuration, nil
}

func (f *fakeTunnelCloudflareFactory) IssueTunnelManagementToken(_ context.Context, tunnelID string, resources []flarecloudflare.TunnelManagementResource) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("IssueTunnelManagementToken"); err != nil {
		return "", err
	}
	if len(resources) == 0 {
		return "", errors.New("management token resources are empty")
	}
	return "management-token-" + tunnelID, nil
}

func (f *fakeTunnelCloudflareFactory) GetTunnelConnector(_ context.Context, tunnelID, connectorID string, _ int64) (flarecloudflare.TunnelConnector, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, connector := range f.connections[tunnelID] {
		if connector.ID == connectorID {
			return connector, nil
		}
	}
	return flarecloudflare.TunnelConnector{}, fmt.Errorf("connector %s not found", connectorID)
}

func (f *fakeTunnelCloudflareFactory) ListTunnelConnections(_ context.Context, tunnelID string, limit int64) ([]flarecloudflare.TunnelConnector, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListTunnelConnections"); err != nil {
		return nil, false, err
	}
	connectors := append([]flarecloudflare.TunnelConnector(nil), f.connections[tunnelID]...)
	truncated := int64(len(connectors)) > limit
	if truncated {
		connectors = connectors[:limit]
	}
	return connectors, truncated, nil
}

func (f *fakeTunnelCloudflareFactory) EvictTunnelConnections(_ context.Context, tunnelID string, connectorID *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("EvictTunnelConnections"); err != nil {
		return err
	}
	connectors := f.connections[tunnelID]
	for index := range connectors {
		if connectorID == nil || connectors[index].ID == *connectorID {
			connectors[index].Connections = nil
			connectors[index].ConnectionsTruncated = false
		}
	}
	f.connections[tunnelID] = connectors
	return nil
}

func (f *fakeTunnelCloudflareFactory) WithTunnelLock(_ context.Context, _ string, fn func() error) error {
	return fn()
}

func (f *fakeTunnelCloudflareFactory) ListDNSRecords(_ context.Context, zoneID, name string) ([]RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ListDNSRecords"); err != nil {
		return nil, err
	}
	var result []RemoteDNSRecord
	for _, record := range f.dns[zoneID] {
		if flarecloudflare.DNSHostnamesEqual(record.Name, name) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (f *fakeTunnelCloudflareFactory) CreateCNAME(_ context.Context, zoneID string, input RemoteDNSRecordInput) (RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateCNAME"); err != nil {
		return RemoteDNSRecord{}, err
	}
	f.next++
	record := fakeDNSRecordFromInput(fmt.Sprintf("record-%d", f.next), input)
	if f.dns[zoneID] == nil {
		f.dns[zoneID] = map[string]RemoteDNSRecord{}
	}
	f.dns[zoneID][record.ID] = record
	return record, nil
}

func (f *fakeTunnelCloudflareFactory) UpdateCNAME(_ context.Context, zoneID, recordID string, input RemoteDNSRecordInput) (RemoteDNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateCNAME"); err != nil {
		return RemoteDNSRecord{}, err
	}
	record := fakeDNSRecordFromInput(recordID, input)
	f.dns[zoneID][recordID] = record
	return record, nil
}

func fakeDNSRecordFromInput(id string, input RemoteDNSRecordInput) RemoteDNSRecord {
	record := RemoteDNSRecord{
		ID: id, Name: input.Name, Type: "CNAME", Content: input.Content, Comment: input.Comment,
		Settings: input.Settings,
	}
	if input.Proxied != nil {
		record.Proxied = *input.Proxied
	}
	if input.TTL != nil {
		record.TTL = *input.TTL
	}
	return record
}

func (f *fakeTunnelCloudflareFactory) DeleteDNSRecord(_ context.Context, zoneID, recordID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DeleteDNSRecord"); err != nil {
		return err
	}
	delete(f.dns[zoneID], recordID)
	return nil
}

var _ TunnelCloudflareClient = (*fakeTunnelCloudflareFactory)(nil)
