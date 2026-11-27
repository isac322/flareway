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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	zero_trust "github.com/cloudflare/cloudflare-go/v7/zero_trust"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
)

type accountMatchedWARPCloudflare struct {
	*fakeWARPConnectorCloudflare
	accountID string
}

func (a *accountMatchedWARPCloudflare) CreateWARPConnector(ctx context.Context, input flarecloudflare.WARPConnectorCreateInput) (flarecloudflare.WARPConnector, error) {
	c, err := a.fakeWARPConnectorCloudflare.CreateWARPConnector(ctx, input)
	c.AccountTag = a.accountID
	a.connector.AccountTag = a.accountID
	return c, err
}

type scimIdentityProviderFakeAPI struct {
	*identityProviderFakeAPI
}

func (f *scimIdentityProviderFakeAPI) UpdateIdentityProvider(ctx context.Context, id string, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	remote, err := f.identityProviderFakeAPI.UpdateIdentityProvider(ctx, id, input)
	if err != nil {
		return remote, err
	}
	if input.SCIMConfig != nil && input.SCIMConfig.Enabled != nil && *input.SCIMConfig.Enabled {
		if remote.SCIMSecret == "" {
			remote.SCIMSecret = "scim-secret-1"
		}
		if remote.SCIMBaseURL == "" {
			remote.SCIMBaseURL = "https://scim.example.test"
		}
		f.providers[id] = remote
	}
	return remote, nil
}

func (f *scimIdentityProviderFakeAPI) ListIdentityProviderSCIMUsers(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMUser, bool, error) {
	return nil, false, nil
}

func (f *scimIdentityProviderFakeAPI) ListIdentityProviderSCIMGroups(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMGroup, bool, error) {
	return nil, false, nil
}

type statusWriteCountingClient struct {
	client.Client
	writes *atomic.Int64
}

func (c *statusWriteCountingClient) Status() client.SubResourceWriter {
	return &statusWriteCountingSubResource{
		SubResourceWriter: c.Client.Status(),
		writes:            c.writes,
	}
}

type statusWriteCountingSubResource struct {
	client.SubResourceWriter
	writes *atomic.Int64
}

func (w *statusWriteCountingSubResource) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Create(ctx, obj, subResource, opts...)
}

func (w *statusWriteCountingSubResource) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func (w *statusWriteCountingSubResource) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

func (w *statusWriteCountingSubResource) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Apply(ctx, obj, opts...)
}

type fakeAccountVerifyFactory struct {
	accountID string
	zoneName  string
}

func (f fakeAccountVerifyFactory) AccountClient(_, _ string) flarecloudflare.AccountAPI {
	return f
}

func (f fakeAccountVerifyFactory) VerifyToken(context.Context) (flarecloudflare.TokenVerification, error) {
	return flarecloudflare.TokenVerification{ID: "tok-1", Status: "active"}, nil
}

func (f fakeAccountVerifyFactory) ListZones(context.Context) ([]flarecloudflare.Zone, error) {
	zoneName := f.zoneName
	if zoneName == "" {
		zoneName = "example.com"
	}
	return []flarecloudflare.Zone{{ID: "z1", Name: zoneName, AccountID: f.accountID, AccountName: "test-account"}}, nil
}

func (f fakeAccountVerifyFactory) GetOrganization(context.Context) (flarecloudflare.Organization, error) {
	return flarecloudflare.Organization{Name: "test-account", AuthDomain: "test.cloudflareaccess.com"}, nil
}

func setAccountCredentialsValid(ctx context.Context, t *testing.T, direct client.Client, accountName string, valid metav1.ConditionStatus) {
	t.Helper()
	var current v1alpha1.CloudflareAccount
	if err := direct.Get(ctx, types.NamespacedName{Name: accountName}, &current); err != nil {
		t.Fatalf("get CloudflareAccount: %v", err)
	}
	now := metav1.Now()
	reason := "Valid"
	msg := "valid"
	if valid != metav1.ConditionTrue {
		reason = "InvalidToken"
		msg = "transient credential failure"
	}
	meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
		Type:               v1alpha1.CloudflareAccountConditionCredentialsValid,
		Status:             valid,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: current.Generation,
		LastTransitionTime: now,
	})
	if err := direct.Status().Update(ctx, &current); err != nil {
		t.Fatalf("update CloudflareAccount status: %v", err)
	}
}

func checkObjectConverged(ctx context.Context, direct client.Client, obj client.Object, key types.NamespacedName, readyCond string, acceptCond string) (bool, error) {
	if err := direct.Get(ctx, key, obj); err != nil {
		return false, err
	}
	var gen, obsGen int64
	var conds []metav1.Condition
	var appliedHash string
	var appliedAt *metav1.Time
	switch o := obj.(type) {
	case *v1alpha1.AccessPolicy:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.AccessGroup:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.AccessStandaloneApplication:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.AccessInfrastructureTarget:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.IdentityProvider:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.AccessApplication:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.VirtualNetwork:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.NetworkRoute:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.HostnameRoute:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.ZeroTrustGatewayPolicy:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.ServiceToken:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.AccessCustomPage:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.DevicePostureRule:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.DevicePostureIntegration:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.DeviceProfile:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.DeviceSettings:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.WARPConnector:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.ZeroTrustList:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.ZeroTrustOrganization:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.AppliedHash, o.Status.AppliedAt
	case *v1alpha1.CloudflareTunnel:
		gen, obsGen, conds, appliedHash, appliedAt = o.Generation, o.Status.ObservedGeneration, o.Status.Conditions, o.Status.ConfigVersion.DesiredHash, o.Status.ConfigVersion.AppliedAt
	default:
		return false, fmt.Errorf("unexpected type %T", obj)
	}
	if obsGen != gen || appliedHash == "" || appliedAt == nil {
		return false, nil
	}
	return assertConditionTrueForCurrentGen(conds, readyCond, gen) &&
		assertConditionTrueForCurrentGen(conds, acceptCond, gen), nil
}

func checkObjectFailed(ctx context.Context, direct client.Client, obj client.Object, key types.NamespacedName, readyCond string) (bool, error) {
	if err := direct.Get(ctx, key, obj); err != nil {
		return false, err
	}
	var conds []metav1.Condition
	switch o := obj.(type) {
	case *v1alpha1.AccessPolicy:
		conds = o.Status.Conditions
	case *v1alpha1.AccessGroup:
		conds = o.Status.Conditions
	case *v1alpha1.AccessStandaloneApplication:
		conds = o.Status.Conditions
	case *v1alpha1.AccessInfrastructureTarget:
		conds = o.Status.Conditions
	case *v1alpha1.IdentityProvider:
		conds = o.Status.Conditions
	case *v1alpha1.AccessApplication:
		conds = o.Status.Conditions
	case *v1alpha1.VirtualNetwork:
		conds = o.Status.Conditions
	case *v1alpha1.NetworkRoute:
		conds = o.Status.Conditions
	case *v1alpha1.HostnameRoute:
		conds = o.Status.Conditions
	case *v1alpha1.ZeroTrustGatewayPolicy:
		conds = o.Status.Conditions
	case *v1alpha1.ServiceToken:
		conds = o.Status.Conditions
	case *v1alpha1.AccessCustomPage:
		conds = o.Status.Conditions
	case *v1alpha1.DevicePostureRule:
		conds = o.Status.Conditions
	case *v1alpha1.DevicePostureIntegration:
		conds = o.Status.Conditions
	case *v1alpha1.DeviceProfile:
		conds = o.Status.Conditions
	case *v1alpha1.DeviceSettings:
		conds = o.Status.Conditions
	case *v1alpha1.WARPConnector:
		conds = o.Status.Conditions
	case *v1alpha1.ZeroTrustList:
		conds = o.Status.Conditions
	case *v1alpha1.ZeroTrustOrganization:
		conds = o.Status.Conditions
	case *v1alpha1.CloudflareTunnel:
		conds = o.Status.Conditions
	default:
		return false, fmt.Errorf("unexpected type %T", obj)
	}
	c := meta.FindStatusCondition(conds, readyCond)
	return c != nil && c.Status == metav1.ConditionFalse, nil
}

// QA-2C-1: ALL 19 gated CRDs recover to Ready=True / Programmed=True + Accepted=True
// + current ObservedGeneration immediately after a transient pre-gate failure and
// dependency restoration, even under active Sweep ConfirmContent and well inside TTL.
func TestQA2C1All19GatedCRDsRecoverUnderActiveSweepEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	const ns = "tenant-qa2c1"
	const accountName = "account-qa2c1"
	const accountID = "0123456789abcdef0123456789abcdef"

	accessFake := newFakeAccessResourceCloudflare()
	standaloneFake := &fakeStandaloneCloudflare{applications: map[string]flarecloudflare.AccessApplication{}, tags: map[string]flarecloudflare.AccessTag{}}
	infraFake := &fakeInfrastructureTargetCloudflare{targets: map[string]flarecloudflare.AccessInfrastructureTarget{}}
	idpFake := &scimIdentityProviderFakeAPI{identityProviderFakeAPI: &identityProviderFakeAPI{providers: map[string]flarecloudflare.IdentityProvider{}}}
	appFake := newFakeAccessApplicationCloudflare()
	customPageFake := newFakeCustomPageCloudflare()
	integrationFake := &fakeDevicePostureIntegrationCloudflare{integrations: map[string]flarecloudflare.DevicePostureIntegration{}}
	privateFake := newFakePrivateNetworkCloudflare()
	warpFake := &accountMatchedWARPCloudflare{
		fakeWARPConnectorCloudflare: newFakeWARPConnectorCloudflare(),
		accountID:                   accountID,
	}
	profileFake := newFakeDeviceProfileCloudflare()
	deviceSettingsFake := new(fakeGlobalDeviceCloudflare)
	orgFake := new(fakeGlobalOrganizationCloudflare)
	gatewayFake := newFakeGlobalGatewayCloudflare()
	tunnelFake := newFakeTunnelCloudflareFactory()
	prober := &liveRemoteVersionProber{version: 2}
	gwAPI := &reg1GatewayAPI{
		tunnelFreshnessGatewayAPI: &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 1},
		prober:                    prober,
	}
	snapshots := newFakeSnapshotPublisher()

	for _, err := range []error{
		(&AccessPolicyReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&AccessGroupReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&AccessStandaloneApplicationReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return standaloneFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&AccessInfrastructureTargetReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return infraFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&IdentityProviderReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return idpFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&AccessApplicationReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), OperatorNamespace: dataplane.DefaultOperatorNamespace, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&VirtualNetworkReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: privateFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&NetworkRouteReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: privateFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&HostnameRouteReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), OperatorNamespace: dataplane.DefaultOperatorNamespace, NewCloudflareClient: privateFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&ZeroTrustGatewayPolicyReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: gatewayFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&ServiceTokenReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&AccessCustomPageReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return customPageFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&DevicePostureRuleReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: accessFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&DevicePostureIntegrationReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return integrationFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&DeviceProfileReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: profileFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&DeviceSettingsReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: deviceSettingsFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&WARPConnectorReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), NewCloudflareClient: func(string, string) (flarecloudflare.WARPConnectorAPI, error) { return warpFake, nil }, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&ZeroTrustListReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: gatewayFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&ZeroTrustOrganizationReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: orgFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&CloudflareTunnelReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), NewCloudflareClient: tunnelFake.Client, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
		(&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr),
		(&GatewayReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Snapshots: snapshots, OperatorNamespace: dataplane.DefaultOperatorNamespace, CloudflareFactory: gatewayCloudflareFactory{api: gwAPI}, Prober: prober, Freshness: policy, Invalidator: latch}).SetupWithManager(mgr),
	} {
		if err != nil {
			t.Fatalf("setup controller: %v", err)
		}
	}

	startManagerAndWait(t, mgr)

	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}}); err != nil {
		t.Fatalf("create token secret: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "kolide-secret"}, Data: map[string][]byte{"client-secret": []byte("kolide-client-secret")}}); err != nil {
		t.Fatalf("create integration secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:     v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs: v1alpha1.GrantPermissionAllowed,
				PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
					NetworkRouteSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
					HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
				},
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.com"}})

	// Real Direct-mode External-DNS CloudflareTunnel managed by CloudflareTunnelReconciler
	// (also used as the tunnel target for NetworkRoute and HostnameRoute).
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "route-tunnel"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: accountName},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "route-tunnel"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
					Ingress: []v1alpha1.CloudflareTunnelIngressRule{{
						Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}},
					}},
				},
			},
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	waitUntilTrue(t, 15*time.Second, "Direct CloudflareTunnel converged", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(tunnel), v1alpha1.CloudflareTunnelConditionReady, v1alpha1.CloudflareTunnelConditionAccepted)
	})

	// Real Gateway + Gateway-mode CloudflareTunnel (covering Gateway CloudflareTunnelConfig gate).
	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2c1-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: accountName},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create GatewayClassConfig: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2c1-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create GatewayClass: %v", err)
	}
	gwHost := gatewayv1.Hostname("qa2c1.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw-2c1"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway dataplane Deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	gwPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-2c1-0", UID: types.UID("dp-2c1-uid"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, gwPod); err != nil {
		t.Fatalf("create Gateway pod: %v", err)
	}
	gwPod.Status.PodIP = "10.0.0.12"
	gwPod.Status.Phase = corev1.PodRunning
	gwPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, gwPod); err != nil {
		t.Fatalf("update Gateway pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway snapshot ACKed", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	gwTunnelKey := types.NamespacedName{Namespace: ns, Name: gw.Name}
	waitUntilTrue(t, 15*time.Second, "Gateway ConfigApplied=True & Programmed=True", func() (bool, error) {
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curTunnel v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &curTunnel); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) &&
			assertConditionTrueForCurrentGen(curTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curTunnel.Generation), nil
	})

	accountRef := corev1.LocalObjectReference{Name: accountName}
	appFake.SetPolicy(flarecloudflare.AccessPolicy{ID: "ext-pol-1", Name: "ext-pol", Decision: "Allow"})

	ztList := &v1alpha1.ZeroTrustList{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "zt-list"},
		Spec: v1alpha1.ZeroTrustListSpec{
			AccountRef: accountRef, Name: "zt-list", Type: v1alpha1.ZeroTrustListTypeIP,
			Items: []string{"10.0.0.0/8"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	vnet := &v1alpha1.VirtualNetwork{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vnet-1"},
		Spec: v1alpha1.VirtualNetworkSpec{
			AccountRef: accountRef, Name: "vnet-1", ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	addr10 := "10.20.0.0/16"
	objects := []struct {
		kind      string
		obj       client.Object
		readyCond string
	}{
		{"AccessPolicy", &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-1"},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: accountRef, Name: "pol-1", Decision: v1alpha1.AccessPolicyDecisionAllow,
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"AccessGroup", &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "grp-1"},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "grp-1",
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"AccessStandaloneApplication", &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "standalone-1"},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: accountRef, Type: v1alpha1.AccessStandaloneApplicationTypeWARP,
				Application:      v1alpha1.AccessApplicationSettings{SessionDuration: "24h"},
				WARP:             &v1alpha1.AccessWARPApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"AccessInfrastructureTarget", &v1alpha1.AccessInfrastructureTarget{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "infra-1"},
			Spec: v1alpha1.AccessInfrastructureTargetSpec{
				AccountRef: accountRef, Hostname: "db.example.test",
				IP:               v1alpha1.AccessInfrastructureTargetIP{IPV4: &v1alpha1.AccessInfrastructureTargetIPv4Address{IPAddr: "192.0.2.10", VirtualNetworkID: "vnet-ext"}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"IdentityProvider", &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "idp-1"},
			Spec: v1alpha1.IdentityProviderSpec{
				AccountRef: accountRef, Name: "idp-1", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"IdentityProvider", &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "idp-scim"},
			Spec: v1alpha1.IdentityProviderSpec{
				AccountRef: accountRef, Name: "idp-scim", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
				SCIMConfig: &v1alpha1.IdentityProviderSCIMConfig{
					Enabled:   new(true),
					SecretRef: &corev1.LocalObjectReference{Name: "idp-scim-secret"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"AccessApplication", &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-1"},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: accountRef, Type: v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:  &v1alpha1.AccessSelfHostedApplicationSpec{},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-1", SessionDuration: "1h"},
				Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
					Type: v1alpha1.AccessApplicationDestinationWorker, Worker: &v1alpha1.AccessWorkerDestinationSpec{WorkerID: "worker-1"},
				}},
				Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-1"}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, accessApplicationConditionProgrammed},
		{"VirtualNetwork", vnet, v1alpha1.PrivateNetworkConditionReady},
		{"NetworkRoute", &v1alpha1.NetworkRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nr-1", Labels: map[string]string{"private-route": "allowed"}},
			Spec: v1alpha1.NetworkRouteSpec{
				AccountRef: accountRef, Network: "10.30.0.0/16",
				TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: tunnel.Name, Namespace: ns},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.PrivateNetworkConditionReady},
		{"HostnameRoute", &v1alpha1.HostnameRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hr-1", Labels: map[string]string{"private-route": "allowed"}},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: accountRef, Hostname: "internal.example.test",
				TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: tunnel.Name, Namespace: ns},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.PrivateNetworkConditionReady},
		{"ZeroTrustGatewayPolicy", &v1alpha1.ZeroTrustGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gwpol-1"},
			Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
				AccountRef: accountRef, Name: "gwpol-1",
				Filters:          []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterL4},
				Action:           v1alpha1.ZeroTrustGatewayAction("allow"),
				Traffic:          "net.dst.ip == 10.0.0.1",
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.ZeroTrustGatewayPolicyConditionReady},
		{"ServiceToken", &v1alpha1.ServiceToken{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "st-1"},
			Spec: v1alpha1.ServiceTokenSpec{
				AccountRef: accountRef, Name: "st-1", Enabled: true, Duration: "8760h",
				SecretRef:        corev1.LocalObjectReference{Name: "st-1-creds"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"AccessCustomPage", &v1alpha1.AccessCustomPage{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cp-1"},
			Spec: v1alpha1.AccessCustomPageSpec{
				AccountRef: accountRef, Name: "cp-1", Type: v1alpha1.AccessCustomPageTypeForbidden,
				HTML: "<main>denied</main>", ContractVersion: 1,
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.AccessCustomPageConditionReady},
		{"DevicePostureRule", &v1alpha1.DevicePostureRule{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dpr-1"},
			Spec: v1alpha1.DevicePostureRuleSpec{
				AccountRef: accountRef, Name: "dpr-1", Type: v1alpha1.DevicePostureRuleTypeWARP,
				Match:            []v1alpha1.DevicePostureMatch{{Platform: v1alpha1.DevicePosturePlatformWindows}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"DevicePostureIntegration", &v1alpha1.DevicePostureIntegration{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dpi-1"},
			Spec: v1alpha1.DevicePostureIntegrationSpec{
				AccountRef: accountRef, Type: v1alpha1.DevicePostureIntegrationTypeKolide,
				Name: "dpi-1", Interval: "1h",
				Config: v1alpha1.DevicePostureIntegrationConfig{
					ClientID:        "kolide-id",
					ClientSecretRef: &v1alpha1.DevicePostureIntegrationSecretReference{Name: "kolide-secret", Key: "client-secret"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready"},
		{"DeviceProfile", &v1alpha1.DeviceProfile{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dp-1"},
			Spec: v1alpha1.DeviceProfileSpec{
				AccountRef: accountRef,
				Profile:    v1alpha1.DeviceProfileTarget{Kind: v1alpha1.DeviceProfileKindDefault},
				SplitTunnel: v1alpha1.DeviceProfileSplitTunnel{
					Mode:   v1alpha1.DeviceProfileSplitTunnelModeInclude,
					Static: []v1alpha1.DeviceProfileSplitTunnelEntry{{Address: &addr10, Description: "static"}},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}, v1alpha1.DeviceProfileConditionReady},
		{"DeviceSettings", &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef: accountRef, GatewayProxyEnabled: new(true),
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.OrphanOnlyDeletionPolicyOrphan,
			},
		}, v1alpha1.DeviceSettingsConditionReady},
		{"WARPConnector", &v1alpha1.WARPConnector{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "wc-1"},
			Spec: v1alpha1.WARPConnectorSpec{
				AccountRef: accountRef, Name: "wc-1",
				HighAvailability: v1alpha1.WARPConnectorHighAvailability{Enabled: new(false), Mode: v1alpha1.WARPConnectorHAModeDisabled},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}, v1alpha1.WARPConnectorConditionReady},
		{"ZeroTrustList", ztList, v1alpha1.ZeroTrustListConditionReady},
		{"ZeroTrustOrganization", &v1alpha1.ZeroTrustOrganization{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
			Spec: v1alpha1.ZeroTrustOrganizationSpec{
				AccountRef: accountRef, Name: new("org"), AuthDomain: new("team.cloudflareaccess.com"),
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.OrphanOnlyDeletionPolicyOrphan,
			},
		}, v1alpha1.ZeroTrustOrganizationConditionReady},
	}
	if len(objects) != 20 {
		t.Fatalf("expected 20 gated CRD instances (19 CRDs + SCIM IdentityProvider), got %d", len(objects))
	}

	for _, item := range objects {
		if err := direct.Create(ctx, item.obj); err != nil {
			t.Fatalf("create %s: %v", item.kind, err)
		}
	}

	// Step 1: Converge all 20 gated CRD instances (19 CRDs + SCIM IdentityProvider), plus Direct CloudflareTunnel and Gateway.
	waitUntilTrue(t, 20*time.Second, "all gated CRDs converged", func() (bool, error) {
		var pending []string
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectConverged(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond, "Accepted")
			if err != nil {
				return false, err
			}
			if !ok {
				pending = append(pending, item.kind+"/"+item.obj.GetName())
			}
		}
		if len(pending) > 0 {
			return false, fmt.Errorf("pending convergence: %v", pending)
		}
		return true, nil
	})

	// Step 2: Run active Sweep ConfirmContent on ALL 10 ConfirmContent CRDs and
	// REQUIRE a non-zero ConfirmedAt timestamp matching each object's AppliedHash
	// BEFORE injecting any failure.
	type confirmSpec struct {
		kind string
		name string
		read func() any
	}
	confirmSpecs := []confirmSpec{
		{"AccessPolicy", "pol-1", func() any {
			var obj v1alpha1.AccessPolicy
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "pol-1"}, &obj); err != nil {
				return nil
			}
			items, _ := accessFake.ListAccessPolicies(ctx)
			for _, it := range items {
				if it.ID == obj.Status.PolicyID {
					return it
				}
			}
			return nil
		}},
		{"AccessGroup", "grp-1", func() any {
			var obj v1alpha1.AccessGroup
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "grp-1"}, &obj); err != nil {
				return nil
			}
			items, _ := accessFake.ListAccessGroups(ctx, flarecloudflare.AccessGroupListOptions{})
			for _, it := range items {
				if it.ID == obj.Status.GroupID {
					return it
				}
			}
			return nil
		}},
		{"AccessStandaloneApplication", "standalone-1", func() any {
			var obj v1alpha1.AccessStandaloneApplication
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "standalone-1"}, &obj); err != nil {
				return nil
			}
			items, _ := standaloneFake.ListAccessApplications(ctx, flarecloudflare.AccessScope{})
			for _, it := range items {
				if it.ID == obj.Status.ApplicationID {
					return it
				}
			}
			return nil
		}},
		{"AccessInfrastructureTarget", "infra-1", func() any {
			var obj v1alpha1.AccessInfrastructureTarget
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "infra-1"}, &obj); err != nil {
				return nil
			}
			items, _ := infraFake.ListAccessInfrastructureTargets(ctx)
			for _, it := range items {
				if it.ID == obj.Status.TargetID {
					return it
				}
			}
			return nil
		}},
		{"IdentityProvider", "idp-1", func() any {
			var obj v1alpha1.IdentityProvider
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "idp-1"}, &obj); err != nil {
				return nil
			}
			items, _ := idpFake.ListIdentityProviders(ctx)
			for _, it := range items {
				if it.ID == obj.Status.IDPID {
					return it
				}
			}
			return nil
		}},
		{"AccessApplication", "app-1", func() any {
			var obj v1alpha1.AccessApplication
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "app-1"}, &obj); err != nil {
				return nil
			}
			items := unrecordedApplicationListing(appFake)
			byID := make(map[string]flarecloudflare.AccessApplication, len(items))
			for _, app := range items {
				byID[app.ID] = app
			}
			if app, ok := byID[obj.Status.ApplicationID]; ok {
				return flarecloudflare.AccessApplicationListing{Application: app, Applications: byID}
			}
			return nil
		}},
		{"VirtualNetwork", "vnet-1", func() any {
			var obj v1alpha1.VirtualNetwork
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vnet-1"}, &obj); err != nil {
				return nil
			}
			items, _ := privateFake.ListVirtualNetworks(ctx)
			for _, it := range items {
				if it.ID == obj.Status.VirtualNetworkID {
					return it
				}
			}
			return nil
		}},
		{"NetworkRoute", "nr-1", func() any {
			var obj v1alpha1.NetworkRoute
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "nr-1"}, &obj); err != nil {
				return nil
			}
			items, _ := privateFake.ListNetworkRoutes(ctx)
			for _, it := range items {
				if it.ID == obj.Status.RouteID {
					return it
				}
			}
			return nil
		}},
		{"HostnameRoute", "hr-1", func() any {
			var obj v1alpha1.HostnameRoute
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hr-1"}, &obj); err != nil {
				return nil
			}
			items, _ := privateFake.ListHostnameRoutes(ctx)
			for _, it := range items {
				if it.ID == obj.Status.RouteID {
					return it
				}
			}
			return nil
		}},
		{"ZeroTrustGatewayPolicy", "gwpol-1", func() any {
			var obj v1alpha1.ZeroTrustGatewayPolicy
			if err := direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "gwpol-1"}, &obj); err != nil {
				return nil
			}
			items, _ := gatewayFake.ListGatewayRules(ctx)
			for _, it := range items {
				if it.ID == obj.Status.RuleID {
					return it
				}
			}
			return nil
		}},
	}
	appliedHashes := make(map[string]string, len(confirmSpecs))
	waitUntilTrue(t, 15*time.Second, "all 10 ConfirmContent CRDs establish non-zero ConfirmedAt", func() (bool, error) {
		now := time.Now()
		for _, spec := range confirmSpecs {
			key := types.NamespacedName{Namespace: ns, Name: spec.name}
			listed := spec.read()
			if listed == nil {
				return false, nil
			}
			if latch.ConfirmContent(spec.kind, key, listed, now) {
				return false, fmt.Errorf("unexpected drift during ConfirmContent for %s", spec.kind)
			}
			var hash string
			switch spec.kind {
			case "AccessPolicy":
				var o v1alpha1.AccessPolicy
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "AccessGroup":
				var o v1alpha1.AccessGroup
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "AccessStandaloneApplication":
				var o v1alpha1.AccessStandaloneApplication
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "AccessInfrastructureTarget":
				var o v1alpha1.AccessInfrastructureTarget
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "IdentityProvider":
				var o v1alpha1.IdentityProvider
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "AccessApplication":
				var o v1alpha1.AccessApplication
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "VirtualNetwork":
				var o v1alpha1.VirtualNetwork
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "NetworkRoute":
				var o v1alpha1.NetworkRoute
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "HostnameRoute":
				var o v1alpha1.HostnameRoute
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			case "ZeroTrustGatewayPolicy":
				var o v1alpha1.ZeroTrustGatewayPolicy
				_ = direct.Get(ctx, key, &o)
				hash = o.Status.AppliedHash
			}
			if hash == "" {
				return false, nil
			}
			ts, ok := latch.ConfirmedAt(spec.kind, key, hash)
			if !ok || ts.IsZero() {
				return false, nil
			}
			appliedHashes[spec.kind+"/"+spec.name] = hash
		}
		return true, nil
	})

	// Step 3: Inject transient pre-gate failure (CloudflareAccount CredentialsValid=False + retract Gateway dataplane Pod).
	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionFalse)
	if err := direct.Delete(ctx, gwPod); err != nil {
		t.Fatalf("delete gwPod: %v", err)
	}

	waitUntilTrue(t, 15*time.Second, "all gated CRDs + tunnel + Gateway turn False on pre-gate failure", func() (bool, error) {
		var stillTrue []string
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectFailed(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond)
			if err != nil {
				return false, err
			}
			if !ok {
				stillTrue = append(stillTrue, item.kind+"/"+item.obj.GetName())
			}
		}
		var curDirectTunnel v1alpha1.CloudflareTunnel
		if ok, err := checkObjectFailed(ctx, direct, &curDirectTunnel, client.ObjectKeyFromObject(tunnel), v1alpha1.CloudflareTunnelConditionReady); err != nil {
			return false, err
		} else if !ok {
			stillTrue = append(stillTrue, "CloudflareTunnel/"+tunnel.Name)
		}
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		prog := meta.FindStatusCondition(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		if prog == nil || prog.Status != metav1.ConditionFalse {
			stillTrue = append(stillTrue, "Gateway/"+gw.Name)
		}
		if len(stillTrue) > 0 {
			return false, fmt.Errorf("not False yet: %v", stillTrue)
		}
		return true, nil
	})

	// Forget MUST have cleared all 10 ConfirmContent baselines & ConfirmedAt timestamps.
	for _, spec := range confirmSpecs {
		key := types.NamespacedName{Namespace: ns, Name: spec.name}
		prevHash := appliedHashes[spec.kind+"/"+spec.name]
		if _, ok := latch.ConfirmedAt(spec.kind, key, prevHash); ok {
			t.Fatalf("%s/%s retained ConfirmedAt after pre-gate failure", spec.kind, spec.name)
		}
		if listed := spec.read(); listed != nil {
			_ = latch.ConfirmContent(spec.kind, key, listed, time.Now())
		}
		if _, ok := latch.ConfirmedAt(spec.kind, key, prevHash); ok {
			t.Fatalf("%s/%s re-recorded ConfirmedAt after Forget while failed", spec.kind, spec.name)
		}
	}

	// Step 4: Restore CloudflareAccount CredentialsValid=True and Gateway dataplane Pod ready well inside TTL.
	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionTrue)
	restoredPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-2c1-1", UID: types.UID("dp-2c1-uid-1"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, restoredPod); err != nil {
		t.Fatalf("recreate gwPod: %v", err)
	}
	restoredPod.Status.PodIP = "10.0.0.13"
	restoredPod.Status.Phase = corev1.PodRunning
	restoredPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, restoredPod); err != nil {
		t.Fatalf("update recreated gwPod ready: %v", err)
	}

	// Step 5: ALL gated resources MUST recover immediately (within 15s, far below 60s/300s/1800s TTL).
	waitUntilTrue(t, 15*time.Second, "all gated CRDs + tunnel + Gateway recover immediately after dependency restoration", func() (bool, error) {
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectConverged(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond, "Accepted")
			if err != nil || !ok {
				return false, err
			}
		}
		var curDirectTunnel v1alpha1.CloudflareTunnel
		if ok, err := checkObjectConverged(ctx, direct, &curDirectTunnel, client.ObjectKeyFromObject(tunnel), v1alpha1.CloudflareTunnelConditionReady, v1alpha1.CloudflareTunnelConditionAccepted); err != nil || !ok {
			return false, err
		}
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curGWTunnel v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &curGWTunnel); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) &&
			assertConditionTrueForCurrentGen(curGWTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curGWTunnel.Generation), nil
	})
}

// QA-2C-2: Gateway-backed AccessApplication (HTTPRoute recreated within 60s)
// & ServiceToken recover immediately without waiting for TTL expiry.
func TestQA2C2GatewayAccessAppHTTPRouteAndServiceTokenRecoverImmediatelyEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	const ns = "tenant-qa2c2"
	const accountName = "account-qa2c2"
	const accountID = "0123456789abcdef0123456789abcdef"

	accessFake := newFakeAccessResourceCloudflare()
	appFake := newFakeAccessApplicationCloudflare()
	appFake.SetPolicy(flarecloudflare.AccessPolicy{ID: "ext-pol-2", Name: "ext-pol-2", Decision: "Allow"})

	if err := (&AccessApplicationReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil },
		Freshness:           policy,
		Invalidator:         latch,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup AccessApplicationReconciler: %v", err)
	}
	if err := (&ServiceTokenReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: accessFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup ServiceTokenReconciler: %v", err)
	}
	if err := (&CloudflareAccountReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Cloudflare: fakeAccountVerifyFactory{accountID: accountID, zoneName: "example.test"},
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup CloudflareAccountReconciler: %v", err)
	}

	startManagerAndWait(t, mgr)

	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*.example.test"},
				Zones:             []string{"example.test"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "CloudflareAccount CredentialsValid=True", func() (bool, error) {
		var cur v1alpha1.CloudflareAccount
		if err := direct.Get(ctx, client.ObjectKeyFromObject(account), &cur); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid, cur.Generation), nil
	})

	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2c2-cfg"},
		Spec:       v1alpha1.GatewayClassConfigSpec{AccountRef: &corev1.LocalObjectReference{Name: accountName}},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create cfg: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2c2-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create gc: %v", err)
	}
	hostname := gatewayv1.Hostname("app.example.test")
	section := gatewayv1.SectionName("public")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: section, Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
			Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "gw-tunnel"}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw-tunnel"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: accountName},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name), SectionName: &section}}},
			Hostnames:       []gatewayv1.Hostname{hostname},
		},
	}
	if err := direct.Create(ctx, route); err != nil {
		t.Fatalf("create httproute: %v", err)
	}
	app := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw-app"},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: accountName},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: gatewayv1.ObjectName(route.Name)},
			}},
			Application:      v1alpha1.AccessApplicationSettings{Name: "gw-app", SessionDuration: "1h"},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-2"}}},
			OriginJWT:        v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyOrphan,
		},
	}
	if err := direct.Create(ctx, app); err != nil {
		t.Fatalf("create AccessApplication: %v", err)
	}

	// Wait for DataPlanes so we can mark tunnel forwarding.
	var protectionDomain string
	waitUntilTrue(t, 10*time.Second, "AccessApplication compiles DataPlanes", func() (bool, error) {
		var cur v1alpha1.AccessApplication
		if err := direct.Get(ctx, client.ObjectKeyFromObject(app), &cur); err != nil {
			return false, err
		}
		if len(cur.Status.DataPlanes) == 0 {
			return false, nil
		}
		protectionDomain = cur.Status.DataPlanes[0].ProtectionDomain
		return protectionDomain != "", nil
	})
	updateTunnelForwarding := func() {
		var cur v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), &cur); err != nil {
			t.Fatalf("get tunnel: %v", err)
		}
		cur.Status.ConfigVersion.Desired++
		cur.Status.ConfigVersion.Applied = cur.Status.ConfigVersion.Desired
		cur.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: string(hostname), ProtectionDomain: protectionDomain,
			AccessApplication: ns + "/gw-app", Guard: v1alpha1.HostnameGuardForwarding,
			AppliedVersion: cur.Status.ConfigVersion.Applied,
		}}
		if err := direct.Status().Update(ctx, &cur); err != nil {
			t.Fatalf("update tunnel status: %v", err)
		}
	}
	updateTunnelForwarding()
	waitUntilTrue(t, 10*time.Second, "Gateway-backed AccessApplication converges", func() (bool, error) {
		var cur v1alpha1.AccessApplication
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(app), accessApplicationConditionProgrammed, accessApplicationConditionAccepted)
	})

	// Delete HTTPRoute (simulating transient route deletion; tunnel still carries
	// forwarding guard and DeletionPolicy=Orphan retains ApplicationID).
	if err := direct.Delete(ctx, route); err != nil {
		t.Fatalf("delete httproute: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "AccessApplication turns False on HTTPRoute deletion", func() (bool, error) {
		var cur v1alpha1.AccessApplication
		return checkObjectFailed(ctx, direct, &cur, client.ObjectKeyFromObject(app), accessApplicationConditionProgrammed)
	})

	// Acknowledge revocation on tunnel if latched, or recreate HTTPRoute immediately within 60s.
	var curApp v1alpha1.AccessApplication
	if err := direct.Get(ctx, client.ObjectKeyFromObject(app), &curApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if curApp.Annotations[accessApplicationRevocationAnnotation] != "" {
		// Simulate Gateway acknowledging revocation on the tunnel.
		var curTunnel v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), &curTunnel); err != nil {
			t.Fatalf("get tunnel: %v", err)
		}
		curTunnel.Status.ConfigVersion.Desired++
		curTunnel.Status.ConfigVersion.Applied = curTunnel.Status.ConfigVersion.Desired
		curTunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
			Hostname: string(hostname), ProtectionDomain: protectionDomain,
			AccessApplication: ns + "/gw-app", Guard: v1alpha1.HostnameGuardBlocked,
			AppliedVersion: curTunnel.Status.ConfigVersion.Applied,
		}}
		if err := direct.Status().Update(ctx, &curTunnel); err != nil {
			t.Fatalf("update tunnel blocked status: %v", err)
		}
		waitUntilTrue(t, 10*time.Second, "revocation acknowledged", func() (bool, error) {
			var refreshed v1alpha1.AccessApplication
			if err := direct.Get(ctx, client.ObjectKeyFromObject(app), &refreshed); err != nil {
				return false, err
			}
			return refreshed.Annotations[accessApplicationRevocationAnnotation] == "" ||
				(refreshed.Status.Revocation != nil && refreshed.Status.Revocation.Acknowledged), nil
		})
	}

	// Recreate HTTPRoute well within 60s TTL and restore forwarding.
	recreated := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name), SectionName: &section}}},
			Hostnames:       []gatewayv1.Hostname{hostname},
		},
	}
	if err := direct.Create(ctx, recreated); err != nil {
		t.Fatalf("recreate httproute: %v", err)
	}
	updateTunnelForwarding()

	waitUntilTrue(t, 10*time.Second, "Gateway-backed AccessApplication recovers immediately after HTTPRoute recreation", func() (bool, error) {
		var cur v1alpha1.AccessApplication
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(app), accessApplicationConditionProgrammed, accessApplicationConditionAccepted)
	})

	// Part B: ServiceToken recovers immediately after credential Secret deletion and restoration inside 60s TTL.
	stSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "st-api-token"},
		Data:       map[string][]byte{"token": []byte("tok")},
	}
	if err := direct.Create(ctx, stSecret); err != nil {
		t.Fatalf("create st-api-token secret: %v", err)
	}
	stAccount := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "st-account-qa2c2"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: stSecret.Name, Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, stAccount); err != nil {
		t.Fatalf("create st-account: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "st-account CredentialsValid=True", func() (bool, error) {
		var cur v1alpha1.CloudflareAccount
		if err := direct.Get(ctx, client.ObjectKeyFromObject(stAccount), &cur); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid, cur.Generation), nil
	})

	st := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "st-qa2c2"},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: stAccount.Name}, Name: "st-qa2c2",
			Enabled: true, Duration: "8760h",
			SecretRef:        corev1.LocalObjectReference{Name: "st-qa2c2-creds"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := direct.Create(ctx, st); err != nil {
		t.Fatalf("create ServiceToken: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "ServiceToken converges", func() (bool, error) {
		var cur v1alpha1.ServiceToken
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(st), "Ready", "Accepted")
	})

	// Capture established tokenID and saved spec.secretRef Secret before deleting it.
	var convergedST v1alpha1.ServiceToken
	if err := direct.Get(ctx, client.ObjectKeyFromObject(st), &convergedST); err != nil {
		t.Fatalf("get converged ServiceToken: %v", err)
	}
	tokenIDBefore := convergedST.Status.TokenID
	if tokenIDBefore == "" {
		t.Fatal("expected non-empty ServiceToken status.tokenId")
	}
	var savedCreds corev1.Secret
	credsKey := types.NamespacedName{Namespace: ns, Name: st.Spec.SecretRef.Name}
	if err := direct.Get(ctx, credsKey, &savedCreds); err != nil {
		t.Fatalf("get ServiceToken credential Secret %s: %v", credsKey, err)
	}
	restoredCreds := savedCreds.DeepCopy()
	restoredCreds.ResourceVersion = ""
	restoredCreds.UID = ""
	restoredCreds.CreationTimestamp = metav1.Time{}

	// Delete ServiceToken's own spec.secretRef Secret inside the 60s TTL.
	// Open freshness gate MUST NOT mask its loss; ServiceToken must turn
	// Ready=False (SecretMissing), forget cached stamps, preserve tokenId,
	// and never silently rotate/recreate the token.
	if err := direct.Delete(ctx, &savedCreds); err != nil {
		t.Fatalf("delete ServiceToken spec.secretRef Secret: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "ServiceToken turns Ready=False (SecretMissing) after spec.secretRef deletion", func() (bool, error) {
		var cur v1alpha1.ServiceToken
		if err := direct.Get(ctx, client.ObjectKeyFromObject(st), &cur); err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(cur.Status.Conditions, "Ready")
		return cond != nil && cond.Status == metav1.ConditionFalse && cond.Reason == "SecretMissing", nil
	})
	var failedST v1alpha1.ServiceToken
	if err := direct.Get(ctx, client.ObjectKeyFromObject(st), &failedST); err != nil {
		t.Fatalf("get failed ServiceToken: %v", err)
	}
	if failedST.Status.TokenID != tokenIDBefore {
		t.Fatalf("ServiceToken tokenId mutated on SecretMissing: %q -> %q", tokenIDBefore, failedST.Status.TokenID)
	}

	// Administratively restore spec.secretRef Secret inside the original 60s TTL.
	if err := direct.Create(ctx, restoredCreds); err != nil {
		t.Fatalf("restore ServiceToken spec.secretRef Secret: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "ServiceToken recovers immediately after spec.secretRef restoration inside 60s TTL", func() (bool, error) {
		var cur v1alpha1.ServiceToken
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(st), "Ready", "Accepted")
	})
	var recoveredST v1alpha1.ServiceToken
	if err := direct.Get(ctx, client.ObjectKeyFromObject(st), &recoveredST); err != nil {
		t.Fatalf("get recovered ServiceToken: %v", err)
	}
	if recoveredST.Status.TokenID != tokenIDBefore {
		t.Fatalf("ServiceToken rotated tokenId on Secret restoration: got %q, want %q", recoveredST.Status.TokenID, tokenIDBefore)
	}
}

// QA-2D-1: dns.mode: External Direct & Gateway tunnels with publicHosts converge
// and open the T2 freshness gate (zero remote tunnel/config reads on subsequent passes).
func TestQA2D1ExternalDNSTunnelsOpenT2GateEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	tunnelFake := newFakeTunnelCloudflareFactory()
	snapshots := newFakeSnapshotPublisher()
	gwAPI := &tunnelFreshnessGatewayAPI{accountID: "0123456789abcdef0123456789abcdef", remoteVersion: 1}
	prober := &staticGatewayProber{version: 2, ready: true}

	tunnelReconciler := &CloudflareTunnelReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
	}
	if err := tunnelReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup tunnel reconciler: %v", err)
	}
	if err := (&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayClassReconciler: %v", err)
	}
	if err := (&GatewayReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            mgr.GetScheme(),
		Snapshots:         snapshots,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gatewayCloudflareFactory{api: gwAPI},
		Prober:            prober,
		Freshness:         policy,
		Invalidator:       latch,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayReconciler: %v", err)
	}

	startManagerAndWait(t, mgr)

	const ns = "tenant-qa2d1"
	const accountName = "account-qa2d1"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cf-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: accountName},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.com"}})

	// 1. Direct tunnel with dns.mode: External and publicHosts.
	directTunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "direct-ext"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: accountName},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "direct-ext"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
					Ingress: []v1alpha1.CloudflareTunnelIngressRule{
						{Hostname: "direct.example.com", Service: v1alpha1.CloudflareTunnelIngressService{HelloWorld: &v1alpha1.CloudflareTunnelBuiltinService{}}},
						{Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}}},
					},
				},
			},
		},
	}
	if err := direct.Create(ctx, directTunnel); err != nil {
		t.Fatalf("create direct tunnel: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Direct External DNS tunnel Ready=True", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, client.ObjectKeyFromObject(directTunnel), &cur); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady, cur.Generation) &&
			assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady, cur.Generation) &&
			len(cur.Status.DNSRecords) == 0 &&
			cur.Status.ConfigVersion.DesiredHash != "", nil
	})
	var directStored v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, client.ObjectKeyFromObject(directTunnel), &directStored); err != nil {
		t.Fatalf("get direct tunnel: %v", err)
	}
	if !tunnelConvergedForGate(&directStored, account, []publicHostname{{Hostname: "direct.example.com", ZoneID: "zone-1"}}) {
		t.Fatalf("tunnelConvergedForGate returned false for converged Direct External DNS tunnel with publicHosts")
	}
	callsBefore := len(tunnelFake.Calls())
	if _, err := tunnelReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(directTunnel)}); err != nil {
		t.Fatalf("steady-state direct reconcile: %v", err)
	}
	newCalls := tunnelFake.Calls()[callsBefore:]
	if slices.Contains(newCalls, "GetTunnel") || slices.Contains(newCalls, "GetTunnelConfiguration") {
		t.Fatalf("Direct External DNS tunnel did not open T2 gate; remote calls: %v", newCalls)
	}

	// 2. Gateway-mode tunnel with dns.mode: External and publicHosts.
	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2d1-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: accountName},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create cfg: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "qa2d1-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create gc: %v", err)
	}
	gwHost := gatewayv1.Hostname("gw.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw-ext"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-ext-0", UID: types.UID("dp-ext-uid"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, pod); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	pod.Status.PodIP = "10.0.0.9"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway snapshot ACKed", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	gwTunnelKey := types.NamespacedName{Namespace: ns, Name: "gw-ext"}
	waitUntilTrue(t, 15*time.Second, "Gateway External DNS tunnel Ready=True", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady, cur.Generation) &&
			assertConditionTrueForCurrentGen(cur.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady, cur.Generation) &&
			len(cur.Status.DNSRecords) == 0 &&
			cur.Status.ConfigVersion.DesiredHash != "" &&
			cur.Status.ConfigVersion.AppliedAt != nil, nil
	})
	var gwTunnelStored v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, gwTunnelKey, &gwTunnelStored); err != nil {
		t.Fatalf("get gateway tunnel: %v", err)
	}
	if !tunnelConvergedForGate(&gwTunnelStored, account, []publicHostname{{Hostname: "gw.example.com", ZoneID: "zone-1"}}) {
		t.Fatalf("tunnelConvergedForGate returned false for converged Gateway External DNS tunnel with publicHosts")
	}
	gwCallsBefore := len(tunnelFake.Calls())
	if _, err := tunnelReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwTunnelKey}); err != nil {
		t.Fatalf("steady-state gateway tunnel reconcile: %v", err)
	}
	gwNewCalls := tunnelFake.Calls()[gwCallsBefore:]
	if slices.Contains(gwNewCalls, "GetTunnel") || slices.Contains(gwNewCalls, "GetTunnelConfiguration") {
		t.Fatalf("Gateway External DNS tunnel did not open T2 gate; remote calls: %v", gwNewCalls)
	}
}

type liveRemoteVersionProber struct {
	mu      sync.Mutex
	version int64
}

func (p *liveRemoteVersionProber) set(v int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version = v
}

func (p *liveRemoteVersionProber) ConfigVersion(context.Context, string) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version, nil
}

func (p *liveRemoteVersionProber) Ready(context.Context, string) error {
	return nil
}

type reg1GatewayAPI struct {
	*tunnelFreshnessGatewayAPI
	mu     sync.Mutex
	prober *liveRemoteVersionProber
}

func (a *reg1GatewayAPI) GetTunnel(ctx context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunnelFreshnessGatewayAPI.GetTunnel(ctx, tunnelID)
}

func (a *reg1GatewayAPI) GetTunnelConfiguration(ctx context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunnelFreshnessGatewayAPI.GetTunnelConfiguration(ctx, tunnelID)
}

func (a *reg1GatewayAPI) UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, err := a.tunnelFreshnessGatewayAPI.UpdateTunnelConfiguration(ctx, tunnelID, params)
	if err == nil && a.prober != nil {
		a.prober.set(cfg.Version)
	}
	return cfg, err
}

type reg1OrganizationAPI struct {
	mu           sync.Mutex
	organization flarecloudflare.Organization
	doh          *flarecloudflare.OrganizationDOHSettings
	calls        []string
}

func (f *reg1OrganizationAPI) Client(_, _ string) (flarecloudflare.OrganizationAPI, error) {
	return f, nil
}

func (f *reg1OrganizationAPI) GetOrganization(context.Context) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetOrganization")
	return f.organization, nil
}

func (f *reg1OrganizationAPI) UpdateOrganization(_ context.Context, _ flarecloudflare.OrganizationInput) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateOrganization")
	return f.organization, nil
}

func (f *reg1OrganizationAPI) GetAccessOrganization(context.Context, flarecloudflare.AccessScope) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetAccessOrganization")
	if f.organization.AuthDomain == "" {
		return flarecloudflare.Organization{}, globalOrganizationNotFound()
	}
	return f.organization, nil
}

func (f *reg1OrganizationAPI) CreateAccessOrganization(_ context.Context, _ flarecloudflare.AccessScope, input flarecloudflare.OrganizationCreateInput) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateAccessOrganization")
	org := flarecloudflare.Organization{AuthDomain: input.AuthDomain}
	applyFakeOrganizationInput(&org, input.OrganizationInput)
	f.organization = org
	return org, nil
}

func (f *reg1OrganizationAPI) UpdateAccessOrganization(_ context.Context, _ flarecloudflare.AccessScope, input flarecloudflare.OrganizationInput) (flarecloudflare.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateAccessOrganization")
	applyFakeOrganizationInput(&f.organization, input)
	return f.organization, nil
}

func (f *reg1OrganizationAPI) RevokeAccessOrganizationUser(context.Context, flarecloudflare.AccessScope, flarecloudflare.OrganizationUserRevocationInput) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "RevokeAccessOrganizationUser")
	return true, nil
}

func (f *reg1OrganizationAPI) GetAccessOrganizationDOH(context.Context) (flarecloudflare.OrganizationDOHSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetAccessOrganizationDOH")
	if f.doh == nil {
		return flarecloudflare.OrganizationDOHSettings{}, globalOrganizationNotFound()
	}
	return *f.doh, nil
}

func (f *reg1OrganizationAPI) UpdateAccessOrganizationDOH(_ context.Context, input flarecloudflare.OrganizationDOHInput) (flarecloudflare.OrganizationDOHSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateAccessOrganizationDOH")
	doh := flarecloudflare.OrganizationDOHSettings{ServiceTokenID: input.ServiceTokenID}
	if input.JWTDuration != nil {
		doh.JWTDuration = *input.JWTDuration
	}
	f.doh = &doh
	return doh, nil
}

func (f *reg1OrganizationAPI) GetAccessCustomPage(context.Context, string) (flarecloudflare.AccessCustomPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetAccessCustomPage")
	return flarecloudflare.AccessCustomPage{ID: "ext-cp-reg1", Name: "ext-cp-reg1", Type: v1alpha1.AccessCustomPageTypeForbidden}, nil
}

func (f *reg1OrganizationAPI) GetServiceToken(context.Context, flarecloudflare.AccessScope, string) (flarecloudflare.ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GetServiceToken")
	return flarecloudflare.ServiceToken{ID: "ext-st-reg1", Name: "ext-st-reg1"}, nil
}

type standaloneWithExternalLookupAPI struct {
	*fakeStandaloneCloudflare
	policies flarecloudflare.AccessAPI
	pages    flarecloudflare.AccessAPI
}

func (s *standaloneWithExternalLookupAPI) GetAccessPolicy(ctx context.Context, id string) (flarecloudflare.AccessPolicy, error) {
	return s.policies.GetAccessPolicy(ctx, id)
}

func (s *standaloneWithExternalLookupAPI) GetAccessCustomPage(ctx context.Context, id string) (flarecloudflare.AccessCustomPage, error) {
	return s.pages.GetAccessCustomPage(ctx, id)
}

// QA-2-REG-1: Steady-state 0 remote reads and 0 K8s status write requests for
// healthy converged resources across ALL 19 ordinary gated CRDs (including SCIM
// IdentityProvider, Gateway-backed AccessApplication, external-ref AccessPolicy,
// external-ref AccessGroup, external-ref AccessStandaloneApplication, external-ref
// DevicePostureRule, external-ref ZeroTrustOrganization, and sweep-confirmed
// variants), Direct External DNS CloudflareTunnel, and Gateway.
func TestQA2REG1SteadyStateZeroRemoteReadsAndStatusWritesEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	const accountID = "0123456789abcdef0123456789abcdef"

	store := newFakeAccessResourceCloudflare()
	extGroup, err := store.CreateAccessGroup(ctx, flarecloudflare.AccessScope{}, flarecloudflare.AccessGroupInput{
		Name: "ext-grp-reg1", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
	})
	if err != nil {
		t.Fatalf("seed external AccessGroup: %v", err)
	}
	extPolStandalone, err := store.CreateAccessPolicy(ctx, flarecloudflare.AccessPolicyInput{
		Name: "ext-pol-standalone-reg1", Decision: "Allow", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
	})
	if err != nil {
		t.Fatalf("seed external standalone AccessPolicy: %v", err)
	}
	customPageBase := newFakeCustomPageCloudflare()
	extCPStandalone, err := customPageBase.CreateAccessCustomPage(ctx, flarecloudflare.AccessCustomPageInput{
		Name: "ext-cp-standalone-reg1", Type: v1alpha1.AccessCustomPageTypeForbidden, HTML: "<p>ext</p>",
	})
	if err != nil {
		t.Fatalf("seed external standalone AccessCustomPage: %v", err)
	}
	integrationBase := &fakeDevicePostureIntegrationCloudflare{
		integrations: map[string]flarecloudflare.DevicePostureIntegration{
			"ext-tanium-1": {ID: "ext-tanium-1", Name: "ext-tanium", Type: v1alpha1.DevicePostureIntegrationTypeTaniumS2S},
		},
	}
	remote := &countingAccessExtendedAPI{
		recordingAccessAPI: &recordingAccessAPI{AccessAPI: store},
		integrations:       integrationBase,
	}
	standaloneBase := &standaloneWithExternalLookupAPI{
		fakeStandaloneCloudflare: &fakeStandaloneCloudflare{applications: map[string]flarecloudflare.AccessApplication{}, tags: map[string]flarecloudflare.AccessTag{}},
		policies:                 store,
		pages:                    customPageBase,
	}
	standaloneRemote := &countingAccessExtendedAPI{recordingAccessAPI: &recordingAccessAPI{AccessAPI: standaloneBase}}
	infraBase := &fakeInfrastructureTargetCloudflare{targets: map[string]flarecloudflare.AccessInfrastructureTarget{}}
	infraRemote := &countingAccessExtendedAPI{recordingAccessAPI: &recordingAccessAPI{AccessAPI: infraBase}}
	customPageRemote := &countingAccessExtendedAPI{recordingAccessAPI: &recordingAccessAPI{AccessAPI: customPageBase}}
	integrationRemote := &countingAccessExtendedAPI{
		recordingAccessAPI: &recordingAccessAPI{AccessAPI: store},
		integrations:       integrationBase,
	}
	idpFake := &scimIdentityProviderFakeAPI{identityProviderFakeAPI: &identityProviderFakeAPI{providers: map[string]flarecloudflare.IdentityProvider{}}}
	idpRemote := &recordingAccessAPI{AccessAPI: idpFake}
	appFake := newFakeAccessApplicationCloudflare()
	privateFake := newFakePrivateNetworkCloudflare()
	gatewayFake := newFakeGlobalGatewayCloudflare()
	profileBase := newFakeDeviceProfileCloudflare()
	profileRemote := &countingDeviceProfileAPI{DeviceProfileAPI: profileBase}
	deviceSettingsFake := new(fakeGlobalDeviceCloudflare)
	warpBase := &accountMatchedWARPCloudflare{
		fakeWARPConnectorCloudflare: newFakeWARPConnectorCloudflare(),
		accountID:                   accountID,
	}
	warpRemote := &countingWARPConnectorAPI{WARPConnectorAPI: warpBase}
	orgFake := new(reg1OrganizationAPI)
	tunnelFake := newFakeTunnelCloudflareFactory()
	prober := &liveRemoteVersionProber{version: 2}
	gwAPI := &reg1GatewayAPI{
		tunnelFreshnessGatewayAPI: &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 1},
		prober:                    prober,
	}
	snapshots := newFakeSnapshotPublisher()

	var statusWrites atomic.Int64
	countingClient := &statusWriteCountingClient{
		Client: mgr.GetClient(),
		writes: &statusWrites,
	}

	type gatedCheck struct {
		name      string
		reconcile func(context.Context, ctrl.Request) (ctrl.Result, error)
		key       types.NamespacedName
	}

	polReconciler := &AccessPolicyReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	grpReconciler := &AccessGroupReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	standaloneReconciler := &AccessStandaloneApplicationReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return standaloneRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	infraReconciler := &AccessInfrastructureTargetReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return infraRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	idpReconciler := &IdentityProviderReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return idpRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	appReconciler := &AccessApplicationReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil },
		Freshness:           policy, Invalidator: latch,
	}
	vnetReconciler := &VirtualNetworkReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: privateFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	nrReconciler := &NetworkRouteReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: privateFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	hrReconciler := &HostnameRouteReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
		NewCloudflareClient: privateFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	gwPolReconciler := &ZeroTrustGatewayPolicyReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: gatewayFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	stReconciler := &ServiceTokenReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	cpReconciler := &AccessCustomPageReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return customPageRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	dprReconciler := &DevicePostureRuleReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	dpiReconciler := &DevicePostureIntegrationReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return integrationRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	dpReconciler := &DeviceProfileReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.DeviceProfileAPI, error) { return profileRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	dsReconciler := &DeviceSettingsReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: deviceSettingsFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	wcReconciler := &WARPConnectorReconciler{
		Client: countingClient, Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.WARPConnectorAPI, error) { return warpRemote, nil },
		Freshness:           policy, Invalidator: latch,
	}
	ztListReconciler := &ZeroTrustListReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: gatewayFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	orgReconciler := &ZeroTrustOrganizationReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: orgFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	tunnelReconciler := &CloudflareTunnelReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           policy, Invalidator: latch,
	}
	gwReconciler := &GatewayReconciler{
		Client: countingClient, APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		Snapshots: snapshots, OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gatewayCloudflareFactory{api: gwAPI},
		Prober:            prober,
		Freshness:         policy, Invalidator: latch,
	}

	for _, err := range []error{
		polReconciler.SetupWithManager(mgr),
		grpReconciler.SetupWithManager(mgr),
		standaloneReconciler.SetupWithManager(mgr),
		infraReconciler.SetupWithManager(mgr),
		idpReconciler.SetupWithManager(mgr),
		appReconciler.SetupWithManager(mgr),
		vnetReconciler.SetupWithManager(mgr),
		nrReconciler.SetupWithManager(mgr),
		hrReconciler.SetupWithManager(mgr),
		gwPolReconciler.SetupWithManager(mgr),
		stReconciler.SetupWithManager(mgr),
		cpReconciler.SetupWithManager(mgr),
		dprReconciler.SetupWithManager(mgr),
		dpiReconciler.SetupWithManager(mgr),
		dpReconciler.SetupWithManager(mgr),
		dsReconciler.SetupWithManager(mgr),
		wcReconciler.SetupWithManager(mgr),
		ztListReconciler.SetupWithManager(mgr),
		orgReconciler.SetupWithManager(mgr),
		tunnelReconciler.SetupWithManager(mgr),
		(&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr),
		gwReconciler.SetupWithManager(mgr),
	} {
		if err != nil {
			t.Fatalf("setup controller: %v", err)
		}
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-reg1"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "kolide-secret"}, Data: map[string][]byte{"client-secret": []byte("kolide-client-secret")}}); err != nil {
		t.Fatalf("create integration secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg1-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:     v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs: v1alpha1.GrantPermissionAllowed,
				PrivateRoutes: &v1alpha1.CloudflarePrivateRouteGrant{
					NetworkRouteSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
					HostnameRouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"private-route": "allowed"}},
				},
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	// 1. Direct External-DNS CloudflareTunnel with publicHosts (also tunnel target for routes).
	directTunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "direct-ext-reg1"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Tunnel:     v1alpha1.CloudflareTunnelRemoteSpec{Name: "direct-ext-reg1"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration: v1alpha1.CloudflareTunnelConfiguration{
				Mode: v1alpha1.CloudflareTunnelConfigurationModeDirect,
				Direct: &v1alpha1.CloudflareTunnelDirectConfiguration{
					Ingress: []v1alpha1.CloudflareTunnelIngressRule{
						{Hostname: "reg1-direct.example.com", Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 200}}},
						{Service: v1alpha1.CloudflareTunnelIngressService{HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404}}},
					},
				},
			},
		},
	}
	if err := direct.Create(ctx, directTunnel); err != nil {
		t.Fatalf("create direct tunnel: %v", err)
	}
	tunnelKey := client.ObjectKeyFromObject(directTunnel)
	waitUntilTrue(t, 15*time.Second, "Direct External DNS tunnel converged", func() (bool, error) {
		var cur v1alpha1.CloudflareTunnel
		return checkObjectConverged(ctx, direct, &cur, tunnelKey, v1alpha1.CloudflareTunnelConditionReady, v1alpha1.CloudflareTunnelConditionDNSReady)
	})

	// 2. Gateway + Gateway-mode tunnel.
	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "reg1-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: account.Name},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create cfg: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reg1-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create gc: %v", err)
	}
	gwHost := gatewayv1.Hostname("reg1-gw.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg1-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "reg1 Gateway dataplane Deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	gwPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-reg1-0", UID: types.UID("dp-reg1-uid"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, gwPod); err != nil {
		t.Fatalf("create gw pod: %v", err)
	}
	gwPod.Status.PodIP = "10.0.0.20"
	gwPod.Status.Phase = corev1.PodRunning
	gwPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, gwPod); err != nil {
		t.Fatalf("update gw pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "reg1 Gateway snapshot ACKed", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	gwTunnelKey := types.NamespacedName{Namespace: ns, Name: gw.Name}
	waitUntilTrue(t, 15*time.Second, "reg1 Gateway Programmed=True & ConfigApplied=True", func() (bool, error) {
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curT v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &curT); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) &&
			assertConditionTrueForCurrentGen(curT.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curT.Generation), nil
	})

	// 3. Service + HTTPRoute on reg1-gw for Gateway-backed AccessApplication.
	svcPort := int32(80)
	appSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg1-app-svc"},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: svcPort}}},
	}
	if err := direct.Create(ctx, appSvc); err != nil {
		t.Fatalf("create app Service: %v", err)
	}
	gwSection := gatewayv1.SectionName("http")
	routePort := gatewayv1.PortNumber(svcPort)
	appRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg1-app-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name), SectionName: &gwSection}}},
			Hostnames:       []gatewayv1.Hostname{gwHost},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{Name: gatewayv1.ObjectName(appSvc.Name), Port: &routePort},
					},
				}},
			}},
		},
	}
	if err := direct.Create(ctx, appRoute); err != nil {
		t.Fatalf("create app HTTPRoute: %v", err)
	}

	// 4. All 19 ordinary gated CRDs + variants.
	accountRef := corev1.LocalObjectReference{Name: account.Name}
	appFake.SetPolicy(flarecloudflare.AccessPolicy{ID: "ext-pol-reg1", Name: "ext-pol", Decision: "Allow"})
	addr10 := "10.21.0.0/16"

	gwApp := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gw-app-steady"},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: accountRef, Type: v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: gatewayv1.ObjectName(appRoute.Name)},
			}},
			Application:      v1alpha1.AccessApplicationSettings{Name: "gw-app-steady", SessionDuration: "1h"},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-reg1"}}},
			OriginJWT:        v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
		},
	}

	items := []struct {
		kind      string
		obj       client.Object
		readyCond string
		reconcile func(context.Context, ctrl.Request) (ctrl.Result, error)
	}{
		{"AccessPolicy-ext", &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-steady"},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: accountRef, Name: "pol-steady", Decision: v1alpha1.AccessPolicyDecisionAllow,
				Include: []v1alpha1.AccessRule{
					{Everyone: &v1alpha1.AccessEveryoneRule{}},
					{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{ExternalID: extGroup.ID}}},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", polReconciler.Reconcile},
		{"AccessPolicy-sweep", &v1alpha1.AccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-plain"},
			Spec: v1alpha1.AccessPolicySpec{
				AccountRef: accountRef, Name: "pol-plain", Decision: v1alpha1.AccessPolicyDecisionAllow,
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", polReconciler.Reconcile},
		{"AccessGroup", &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "grp-steady"},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "grp-steady",
				Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", grpReconciler.Reconcile},
		{"AccessGroup-ext", &v1alpha1.AccessGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "grp-ext-steady"},
			Spec: v1alpha1.AccessGroupSpec{
				AccountRef: accountRef, Name: "grp-ext-steady",
				Include:          []v1alpha1.AccessRule{{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{ExternalID: extGroup.ID}}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", grpReconciler.Reconcile},
		{"AccessStandaloneApplication", &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "standalone-steady"},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: accountRef, Type: v1alpha1.AccessStandaloneApplicationTypeWARP,
				Application:      v1alpha1.AccessApplicationSettings{SessionDuration: "24h"},
				WARP:             &v1alpha1.AccessWARPApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", standaloneReconciler.Reconcile},
		{"AccessStandaloneApplication-ext", &v1alpha1.AccessStandaloneApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "standalone-ext-steady"},
			Spec: v1alpha1.AccessStandaloneApplicationSpec{
				AccountRef: accountRef, Type: v1alpha1.AccessStandaloneApplicationTypeBookmark,
				Bookmark: &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://ext-bookmark.example.com"},
				Application: v1alpha1.AccessApplicationSettings{
					Name:            "standalone-ext-steady",
					SessionDuration: "1h",
					CustomPageRefs:  []v1alpha1.AccessCustomPageReference{{ExternalID: extCPStandalone.ID}},
				},
				Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: extPolStandalone.ID}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", standaloneReconciler.Reconcile},
		{"AccessInfrastructureTarget", &v1alpha1.AccessInfrastructureTarget{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "infra-steady"},
			Spec: v1alpha1.AccessInfrastructureTargetSpec{
				AccountRef: accountRef, Hostname: "db-reg1.example.test",
				IP:               v1alpha1.AccessInfrastructureTargetIP{IPV4: &v1alpha1.AccessInfrastructureTargetIPv4Address{IPAddr: "192.0.2.11", VirtualNetworkID: "vnet-ext"}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", infraReconciler.Reconcile},
		{"IdentityProvider", &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "idp-steady"},
			Spec: v1alpha1.IdentityProviderSpec{
				AccountRef: accountRef, Name: "idp-steady", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", idpReconciler.Reconcile},
		{"IdentityProvider-SCIM", &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "idp-scim-steady"},
			Spec: v1alpha1.IdentityProviderSpec{
				AccountRef: accountRef, Name: "idp-scim-steady", Type: v1alpha1.IdentityProviderTypeOneTimePIN,
				SCIMConfig: &v1alpha1.IdentityProviderSCIMConfig{
					Enabled:   new(true),
					SecretRef: &corev1.LocalObjectReference{Name: "idp-scim-reg1-secret"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", idpReconciler.Reconcile},
		{"AccessApplication-declared", &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-steady"},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef: accountRef, Type: v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:  &v1alpha1.AccessSelfHostedApplicationSpec{},
				Application: v1alpha1.AccessApplicationSettings{Name: "app-steady", SessionDuration: "1h"},
				Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
					Type: v1alpha1.AccessApplicationDestinationWorker, Worker: &v1alpha1.AccessWorkerDestinationSpec{WorkerID: "worker-reg1"},
				}},
				Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-reg1"}}},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, accessApplicationConditionProgrammed, appReconciler.Reconcile},
		{"VirtualNetwork", &v1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vnet-steady"},
			Spec: v1alpha1.VirtualNetworkSpec{
				AccountRef: accountRef, Name: "vnet-steady",
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.PrivateNetworkConditionReady, vnetReconciler.Reconcile},
		{"NetworkRoute", &v1alpha1.NetworkRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nr-steady", Labels: map[string]string{"private-route": "allowed"}},
			Spec: v1alpha1.NetworkRouteSpec{
				AccountRef: accountRef, Network: "10.31.0.0/16",
				TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: directTunnel.Name, Namespace: ns},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.PrivateNetworkConditionReady, nrReconciler.Reconcile},
		{"HostnameRoute", &v1alpha1.HostnameRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hr-steady", Labels: map[string]string{"private-route": "allowed"}},
			Spec: v1alpha1.HostnameRouteSpec{
				AccountRef: accountRef, Hostname: "internal-reg1.example.test",
				TunnelRef:        v1alpha1.TunnelReference{Kind: v1alpha1.TunnelReferenceKindCloudflareTunnel, Name: directTunnel.Name, Namespace: ns},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.PrivateNetworkConditionReady, hrReconciler.Reconcile},
		{"ZeroTrustGatewayPolicy", &v1alpha1.ZeroTrustGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gwpol-steady"},
			Spec: v1alpha1.ZeroTrustGatewayPolicySpec{
				AccountRef: accountRef, Name: "gwpol-steady",
				Filters:          []v1alpha1.ZeroTrustGatewayFilter{v1alpha1.ZeroTrustGatewayFilterL4},
				Action:           v1alpha1.ZeroTrustGatewayAction("allow"),
				Traffic:          "net.dst.ip == 10.0.0.2",
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.ZeroTrustGatewayPolicyConditionReady, gwPolReconciler.Reconcile},
		{"ServiceToken", &v1alpha1.ServiceToken{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "st-steady"},
			Spec: v1alpha1.ServiceTokenSpec{
				AccountRef: accountRef, Name: "st-steady", Enabled: true, Duration: "8760h",
				SecretRef:        corev1.LocalObjectReference{Name: "st-steady-creds"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", stReconciler.Reconcile},
		{"AccessCustomPage", &v1alpha1.AccessCustomPage{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cp-steady"},
			Spec: v1alpha1.AccessCustomPageSpec{
				AccountRef: accountRef, Name: "cp-steady", Type: v1alpha1.AccessCustomPageTypeForbidden,
				HTML: "<main>denied</main>", ContractVersion: 1,
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.AccessCustomPageConditionReady, cpReconciler.Reconcile},
		{"DevicePostureRule-ext", &v1alpha1.DevicePostureRule{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dpr-steady"},
			Spec: v1alpha1.DevicePostureRuleSpec{
				AccountRef: accountRef, Name: "dpr-steady", Type: v1alpha1.DevicePostureRuleTypeTaniumS2S,
				Input: v1alpha1.DevicePostureInput{
					IntegrationRef: &v1alpha1.DevicePostureIntegrationReference{ExternalID: "ext-tanium-1"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", dprReconciler.Reconcile},
		{"DevicePostureIntegration", &v1alpha1.DevicePostureIntegration{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dpi-steady"},
			Spec: v1alpha1.DevicePostureIntegrationSpec{
				AccountRef: accountRef, Type: v1alpha1.DevicePostureIntegrationTypeKolide,
				Name: "dpi-steady", Interval: "1h",
				Config: v1alpha1.DevicePostureIntegrationConfig{
					ClientID:        "kolide-id",
					ClientSecretRef: &v1alpha1.DevicePostureIntegrationSecretReference{Name: "kolide-secret", Key: "client-secret"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, "Ready", dpiReconciler.Reconcile},
		{"DeviceProfile", &v1alpha1.DeviceProfile{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dp-steady"},
			Spec: v1alpha1.DeviceProfileSpec{
				AccountRef: accountRef,
				Profile:    v1alpha1.DeviceProfileTarget{Kind: v1alpha1.DeviceProfileKindDefault},
				SplitTunnel: v1alpha1.DeviceProfileSplitTunnel{
					Mode:   v1alpha1.DeviceProfileSplitTunnelModeInclude,
					Static: []v1alpha1.DeviceProfileSplitTunnelEntry{{Address: &addr10, Description: "static"}},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}, v1alpha1.DeviceProfileConditionReady, dpReconciler.Reconcile},
		{"DeviceSettings", &v1alpha1.DeviceSettings{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
			Spec: v1alpha1.DeviceSettingsSpec{
				AccountRef: accountRef, GatewayProxyEnabled: new(true),
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.OrphanOnlyDeletionPolicyOrphan,
			},
		}, v1alpha1.DeviceSettingsConditionReady, dsReconciler.Reconcile},
		{"WARPConnector", &v1alpha1.WARPConnector{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "wc-steady"},
			Spec: v1alpha1.WARPConnectorSpec{
				AccountRef: accountRef, Name: "wc-steady",
				HighAvailability: v1alpha1.WARPConnectorHighAvailability{Enabled: new(false), Mode: v1alpha1.WARPConnectorHAModeDisabled},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyOrphan,
			},
		}, v1alpha1.WARPConnectorConditionReady, wcReconciler.Reconcile},
		{"ZeroTrustList", &v1alpha1.ZeroTrustList{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "zt-list-steady"},
			Spec: v1alpha1.ZeroTrustListSpec{
				AccountRef: accountRef, Name: "zt-list-steady", Type: v1alpha1.ZeroTrustListTypeIP,
				Items:            []string{"10.0.0.0/8"},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}, v1alpha1.ZeroTrustListConditionReady, ztListReconciler.Reconcile},
		{"ZeroTrustOrganization-ext", &v1alpha1.ZeroTrustOrganization{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"},
			Spec: v1alpha1.ZeroTrustOrganizationSpec{
				AccountRef: accountRef, Name: new("org-reg1"), AuthDomain: new("reg1-team.cloudflareaccess.com"),
				CustomPages: &v1alpha1.ZeroTrustOrganizationCustomPageReferences{
					Forbidden: &v1alpha1.AccessObjectReference{ExternalID: "ext-cp-reg1"},
				},
				DOH: &v1alpha1.ZeroTrustOrganizationDOH{
					ServiceTokenRef: v1alpha1.AccessObjectReference{ExternalID: "ext-st-reg1"},
				},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.OrphanOnlyDeletionPolicyOrphan,
			},
		}, v1alpha1.ZeroTrustOrganizationConditionReady, orgReconciler.Reconcile},
	}

	for _, item := range items {
		if err := direct.Create(ctx, item.obj); err != nil {
			t.Fatalf("create %s: %v", item.kind, err)
		}
	}
	if err := direct.Create(ctx, gwApp); err != nil {
		t.Fatalf("create gw-app-steady: %v", err)
	}

	checks := make([]gatedCheck, 0, len(items)+3)
	for _, item := range items {
		checks = append(checks, gatedCheck{name: item.kind, reconcile: item.reconcile, key: client.ObjectKeyFromObject(item.obj)})
	}
	checks = append(checks,
		gatedCheck{name: "AccessApplication-Gateway", reconcile: appReconciler.Reconcile, key: client.ObjectKeyFromObject(gwApp)},
		gatedCheck{name: "CloudflareTunnel-DirectExternal", reconcile: tunnelReconciler.Reconcile, key: tunnelKey},
		gatedCheck{name: "Gateway-CloudflareTunnelConfig", reconcile: gwReconciler.Reconcile, key: client.ObjectKeyFromObject(gw)},
	)

	var lastPending []string
	defer func() {
		if t.Failed() && len(lastPending) > 0 {
			t.Logf("still pending convergence: %v", lastPending)
		}
	}()
	waitUntilTrue(t, 20*time.Second, "all 19 CRDs + variants + Gateway converged", func() (bool, error) {
		_ = snapshots.ACK(client.ObjectKeyFromObject(gw).String())
		var pending []string
		for _, item := range items {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectConverged(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond, "Accepted")
			if err != nil {
				return false, err
			}
			if !ok {
				pending = append(pending, item.kind)
			}
		}
		var curGWApp v1alpha1.AccessApplication
		okApp, err := checkObjectConverged(ctx, direct, &curGWApp, client.ObjectKeyFromObject(gwApp), accessApplicationConditionProgrammed, accessApplicationConditionAccepted)
		if err != nil {
			return false, err
		}
		if !okApp {
			pending = append(pending, "AccessApplication-Gateway")
		}
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curT v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &curT); err != nil {
			return false, err
		}
		if !assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) {
			pending = append(pending, "Gateway-Programmed")
		}
		if !assertConditionTrueForCurrentGen(curT.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curT.Generation) {
			pending = append(pending, "Gateway-ConfigApplied")
		}
		if !assertConditionTrueForCurrentGen(curT.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady, curT.Generation) ||
			!assertConditionTrueForCurrentGen(curT.Status.Conditions, v1alpha1.CloudflareTunnelConditionDNSReady, curT.Generation) ||
			curT.Status.ConfigVersion.AppliedAt == nil {
			pending = append(pending, "GatewayTunnel-Ready")
		}
		lastPending = pending
		return len(pending) == 0, nil
	})
	_ = lastPending

	// Run one rebind reconcile so remote-assigned IDs settle in AppliedHash before steady-state measurement.
	for _, chk := range checks {
		if _, err := chk.reconcile(ctx, ctrl.Request{NamespacedName: chk.key}); err != nil {
			t.Fatalf("rebind %s reconcile: %v", chk.name, err)
		}
	}

	// Establish active sweep ConfirmContent & verify non-zero ConfirmedAt for the 10 sweep-confirmable kinds.
	confirm := func(kind string, key types.NamespacedName, hash string, listed any) {
		if latch.ConfirmContent(kind, key, listed, time.Now()) {
			t.Fatalf("ConfirmContent(%s, %v) reported unexpected drift", kind, key)
		}
		ts, ok := latch.ConfirmedAt(kind, key, hash)
		if !ok || ts.IsZero() {
			t.Fatalf("ConfirmedAt(%s, %v) missing", kind, key)
		}
	}
	var curPolPlain v1alpha1.AccessPolicy
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "pol-plain"}, &curPolPlain)
	for _, it := range func() []flarecloudflare.AccessPolicy { v, _ := store.ListAccessPolicies(ctx); return v }() {
		if it.ID == curPolPlain.Status.PolicyID {
			confirm("AccessPolicy", client.ObjectKeyFromObject(&curPolPlain), curPolPlain.Status.AppliedHash, it)
		}
	}
	var curGrp v1alpha1.AccessGroup
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "grp-steady"}, &curGrp)
	for _, it := range func() []flarecloudflare.AccessGroup {
		v, _ := store.ListAccessGroups(ctx, flarecloudflare.AccessGroupListOptions{})
		return v
	}() {
		if it.ID == curGrp.Status.GroupID {
			confirm("AccessGroup", client.ObjectKeyFromObject(&curGrp), curGrp.Status.AppliedHash, it)
		}
	}
	var curStandalone v1alpha1.AccessStandaloneApplication
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "standalone-steady"}, &curStandalone)
	if listed, ok := standaloneBase.applications[curStandalone.Status.ApplicationID]; ok {
		confirm("AccessStandaloneApplication", client.ObjectKeyFromObject(&curStandalone), curStandalone.Status.AppliedHash, listed)
	}
	var curInfra v1alpha1.AccessInfrastructureTarget
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "infra-steady"}, &curInfra)
	if listed, ok := infraBase.targets[curInfra.Status.TargetID]; ok {
		confirm("AccessInfrastructureTarget", client.ObjectKeyFromObject(&curInfra), curInfra.Status.AppliedHash, listed)
	}
	var curIDP v1alpha1.IdentityProvider
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "idp-steady"}, &curIDP)
	if listed, ok := idpFake.providers[curIDP.Status.IDPID]; ok {
		confirm("IdentityProvider", client.ObjectKeyFromObject(&curIDP), curIDP.Status.AppliedHash, listed)
	}
	var curApp v1alpha1.AccessApplication
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "app-steady"}, &curApp)
	appItems := unrecordedApplicationListing(appFake)
	appByID := make(map[string]flarecloudflare.AccessApplication, len(appItems))
	for _, a := range appItems {
		appByID[a.ID] = a
	}
	if listed, ok := appByID[curApp.Status.ApplicationID]; ok {
		confirm("AccessApplication", client.ObjectKeyFromObject(&curApp), curApp.Status.AppliedHash, flarecloudflare.AccessApplicationListing{
			Application:  listed,
			Applications: appByID,
		})
	}
	var curVNet v1alpha1.VirtualNetwork
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vnet-steady"}, &curVNet)
	if listed, err := privateFake.GetVirtualNetwork(ctx, curVNet.Status.VirtualNetworkID); err == nil {
		confirm("VirtualNetwork", client.ObjectKeyFromObject(&curVNet), curVNet.Status.AppliedHash, listed)
	}
	var curNR v1alpha1.NetworkRoute
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "nr-steady"}, &curNR)
	if listed, err := privateFake.GetNetworkRoute(ctx, curNR.Status.RouteID); err == nil {
		confirm("NetworkRoute", client.ObjectKeyFromObject(&curNR), curNR.Status.AppliedHash, listed)
	}
	var curHR v1alpha1.HostnameRoute
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hr-steady"}, &curHR)
	if listed, err := privateFake.GetHostnameRoute(ctx, curHR.Status.RouteID); err == nil {
		confirm("HostnameRoute", client.ObjectKeyFromObject(&curHR), curHR.Status.AppliedHash, listed)
	}
	var curGWPol v1alpha1.ZeroTrustGatewayPolicy
	_ = direct.Get(ctx, types.NamespacedName{Namespace: ns, Name: "gwpol-steady"}, &curGWPol)
	if listed, err := gatewayFake.GetGatewayRule(ctx, curGWPol.Status.RuleID); err == nil {
		confirm("ZeroTrustGatewayPolicy", client.ObjectKeyFromObject(&curGWPol), curGWPol.Status.AppliedHash, listed)
	}

	// Allow any initial in-flight manager reconciles/requeues to settle cleanly.
	waitUntilTrue(t, 10*time.Second, "manager status writes quiescent", func() (bool, error) {
		before := statusWrites.Load()
		time.Sleep(500 * time.Millisecond)
		return statusWrites.Load() == before, nil
	})

	// Snapshot every Cloudflare call counter across ALL reconcilers.
	remoteBefore := remote.count()
	standaloneBefore := standaloneRemote.count()
	infraBefore := infraRemote.count()
	customPageBefore := customPageRemote.count()
	integrationBefore := integrationRemote.count()
	idpBefore := idpRemote.count()
	appFake.mu.Lock()
	appBefore := len(appFake.calls)
	appFake.mu.Unlock()
	privateFake.mu.Lock()
	privateBefore := len(privateFake.calls)
	privateFake.mu.Unlock()
	gatewayFake.mu.Lock()
	gatewayBefore := len(gatewayFake.calls)
	gatewayFake.mu.Unlock()
	profileBefore := profileRemote.calls.Load()
	deviceSettingsFake.mu.Lock()
	dsBefore := len(deviceSettingsFake.calls)
	deviceSettingsFake.mu.Unlock()
	warpBefore := warpRemote.calls.Load()
	orgFake.mu.Lock()
	orgBefore := len(orgFake.calls)
	orgFake.mu.Unlock()
	tunnelBefore := len(tunnelFake.Calls())
	gwAPI.mu.Lock()
	gwBefore := len(gwAPI.calls)
	gwAPI.mu.Unlock()

	for _, chk := range checks {
		writesBefore := statusWrites.Load()
		if _, err := chk.reconcile(ctx, ctrl.Request{NamespacedName: chk.key}); err != nil {
			t.Fatalf("steady %s reconcile: %v", chk.name, err)
		}
		if got := statusWrites.Load() - writesBefore; got != 0 {
			t.Fatalf("steady %s reconcile issued %d Kubernetes status write requests, want 0", chk.name, got)
		}
	}

	if got := remote.calls[remoteBefore:]; len(got) != 0 {
		t.Fatalf("steady AccessPolicy/AccessGroup/ServiceToken/DevicePostureRule reconciles issued remote calls %v, want 0", got)
	}
	if got := standaloneRemote.calls[standaloneBefore:]; len(got) != 0 {
		t.Fatalf("steady AccessStandaloneApplication reconcile issued remote calls %v, want 0", got)
	}
	if got := infraRemote.calls[infraBefore:]; len(got) != 0 {
		t.Fatalf("steady AccessInfrastructureTarget reconcile issued remote calls %v, want 0", got)
	}
	if got := customPageRemote.calls[customPageBefore:]; len(got) != 0 {
		t.Fatalf("steady AccessCustomPage reconcile issued remote calls %v, want 0", got)
	}
	if got := integrationRemote.calls[integrationBefore:]; len(got) != 0 {
		t.Fatalf("steady DevicePostureIntegration reconcile issued remote calls %v, want 0", got)
	}
	if got := idpRemote.calls[idpBefore:]; len(got) != 0 {
		t.Fatalf("steady IdentityProvider (plain + SCIM) reconciles issued remote calls %v, want 0", got)
	}
	appFake.mu.Lock()
	appCalls := slices.Clone(appFake.calls[appBefore:])
	appFake.mu.Unlock()
	if len(appCalls) != 0 {
		t.Fatalf("steady AccessApplication (declared + Gateway) reconciles issued remote calls %v, want 0", appCalls)
	}
	privateFake.mu.Lock()
	privateCalls := slices.Clone(privateFake.calls[privateBefore:])
	privateFake.mu.Unlock()
	if len(privateCalls) != 0 {
		t.Fatalf("steady VirtualNetwork/NetworkRoute/HostnameRoute reconciles issued remote calls %v, want 0", privateCalls)
	}
	gatewayFake.mu.Lock()
	gwPolCalls := slices.Clone(gatewayFake.calls[gatewayBefore:])
	gatewayFake.mu.Unlock()
	if len(gwPolCalls) != 0 {
		t.Fatalf("steady ZeroTrustGatewayPolicy/ZeroTrustList reconciles issued remote calls %v, want 0", gwPolCalls)
	}
	if got := profileRemote.calls.Load() - profileBefore; got != 0 {
		t.Fatalf("steady DeviceProfile reconcile issued %d remote calls, want 0", got)
	}
	deviceSettingsFake.mu.Lock()
	dsCalls := slices.Clone(deviceSettingsFake.calls[dsBefore:])
	deviceSettingsFake.mu.Unlock()
	if len(dsCalls) != 0 {
		t.Fatalf("steady DeviceSettings reconcile issued remote calls %v, want 0", dsCalls)
	}
	if got := warpRemote.calls.Load() - warpBefore; got != 0 {
		t.Fatalf("steady WARPConnector reconcile issued %d remote calls, want 0", got)
	}
	orgFake.mu.Lock()
	orgCalls := slices.Clone(orgFake.calls[orgBefore:])
	orgFake.mu.Unlock()
	if len(orgCalls) != 0 {
		t.Fatalf("steady ZeroTrustOrganization reconcile issued remote calls %v, want 0", orgCalls)
	}
	if got := tunnelFake.Calls()[tunnelBefore:]; len(got) != 0 {
		t.Fatalf("steady Direct External CloudflareTunnel reconcile issued remote calls %v, want 0", got)
	}
	gwAPI.mu.Lock()
	gwCalls := slices.Clone(gwAPI.calls[gwBefore:])
	gwAPI.mu.Unlock()
	if len(gwCalls) != 0 {
		t.Fatalf("steady Gateway CloudflareTunnelConfig reconcile issued remote calls %v, want 0", gwCalls)
	}
}

// QA-2-REG-2: ObserveOnly (Safety Condition 9) is never gated and always reads
// Cloudflare even when Freshness is enabled, TTL/AppliedHash/AppliedAt are fresh,
// and Sweep confirmation + VerifiedAt are cached in the latch.
func TestQA2REG2ObserveOnlyNeverGatedEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	store := newFakeAccessResourceCloudflare()
	remote := &recordingAccessAPI{AccessAPI: store}
	extPol, err := store.CreateAccessPolicy(ctx, flarecloudflare.AccessPolicyInput{
		Name: "external-pol", Decision: "Allow", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
	})
	if err != nil {
		t.Fatalf("seed remote policy: %v", err)
	}
	reconciler := &AccessPolicyReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy,
		Invalidator:         latch,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-reg2"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg2-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, nil)

	pol := &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-obs"},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "external-pol",
			Decision:         v1alpha1.AccessPolicyDecisionAllow,
			Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
			ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
			ExternalRef:      &v1alpha1.AccessPolicyExternalReference{PolicyID: extPol.ID},
		},
	}
	if err := direct.Create(ctx, pol); err != nil {
		t.Fatalf("create observe policy: %v", err)
	}
	key := client.ObjectKeyFromObject(pol)
	waitUntilTrue(t, 10*time.Second, "ObserveOnly policy Ready=True", func() (bool, error) {
		var cur v1alpha1.AccessPolicy
		if err := direct.Get(ctx, key, &cur); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(cur.Status.Conditions, "Ready", cur.Generation), nil
	})

	// Seed otherwise-open TTL stamp, VerifiedAt, and Sweep ConfirmedAt matching the
	// object's gate hash so an identical Managed object would have gate.Open == true.
	var obsPol v1alpha1.AccessPolicy
	if err := direct.Get(ctx, key, &obsPol); err != nil {
		t.Fatalf("get ObserveOnly policy: %v", err)
	}
	clusterID := gateClusterID(ctx, direct)
	remoteName, err := accessRemoteName(ctx, direct, obsPol.Namespace, obsPol.Spec.Name)
	if err != nil {
		t.Fatalf("accessRemoteName: %v", err)
	}
	obsInput := accessPolicyInput(obsPol.Spec, remoteName, []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}}, nil, nil)
	seedDecision := evaluateGate(policy, latch, freshness.GradeAuthz, gateInput{
		Kind: "AccessPolicy", Namespace: obsPol.Namespace, Name: obsPol.Name,
		UID: obsPol.UID, RemoteID: obsPol.Status.PolicyID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID, Converged: true,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: obsPol.Spec, Input: obsInput},
	}, "", nil, time.Now())
	now := metav1.Now()
	obsPol.Status.AppliedHash = seedDecision.DesiredHash
	obsPol.Status.AppliedAt = &now
	if err := direct.Status().Update(ctx, &obsPol); err != nil {
		t.Fatalf("seed AppliedHash/AppliedAt: %v", err)
	}
	latch.MarkVerified("AccessPolicy", key, seedDecision.DesiredHash, now.Time)
	latch.SetBaseline("AccessPolicy", key, seedDecision.DesiredHash, func(any) bool { return true })
	latch.ConfirmContent("AccessPolicy", key, extPol, now.Time)
	if !evaluateGate(policy, latch, freshness.GradeAuthz, gateInput{
		Kind: "AccessPolicy", Namespace: obsPol.Namespace, Name: obsPol.Name,
		UID: obsPol.UID, RemoteID: obsPol.Status.PolicyID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID, Converged: true,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: obsPol.Spec, Input: obsInput},
	}, obsPol.Status.AppliedHash, obsPol.Status.AppliedAt, time.Now()).Open {
		t.Fatal("precondition failed: seeded managed-equivalent gate did not open")
	}

	callsBefore := remote.count()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("ObserveOnly reconcile: %v", err)
	}
	if remote.count() <= callsBefore {
		t.Fatalf("ObserveOnly skipped remote read (Safety Condition 9 violated): calls before=%d after=%d", callsBefore, remote.count())
	}
}

// QA-2-REG-3: dns.mode: External tunnel with stale status.DNSRecords or DNSReady=False
// keeps the T2 gate closed until records are cleaned up and DNSReady=True.
func TestQA2REG3ExternalDNSWithStaleRecordsStaysClosedEnvtest(t *testing.T) {
	account := &v1alpha1.CloudflareAccount{Spec: v1alpha1.CloudflareAccountSpec{AccountID: "acct-1"}}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "t1", Generation: 2},
		Spec: v1alpha1.CloudflareTunnelSpec{
			DNS: v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
		Status: v1alpha1.CloudflareTunnelStatus{
			TunnelID:          "tid-1",
			AccountID:         "acct-1",
			OwnershipVerified: true,
			DNSRecords:        []v1alpha1.CloudflareTunnelDNSRecordStatus{{Hostname: "a.example.com", RecordID: "rec-1", ZoneID: "z1", State: dnsRecordStateReady}},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareTunnelConditionReady, Status: metav1.ConditionTrue, ObservedGeneration: 2},
				{Type: v1alpha1.CloudflareTunnelConditionDNSReady, Status: metav1.ConditionTrue, ObservedGeneration: 2},
			},
		},
	}
	if tunnelConvergedForGate(tunnel, account, []publicHostname{{Hostname: "a.example.com", ZoneID: "z1"}}) {
		t.Fatal("tunnelConvergedForGate opened gate for External DNS tunnel that still carries stale status.DNSRecords")
	}
	tunnel.Status.DNSRecords = nil
	tunnel.Status.Conditions[1].Status = metav1.ConditionFalse
	if tunnelConvergedForGate(tunnel, account, []publicHostname{{Hostname: "a.example.com", ZoneID: "z1"}}) {
		t.Fatal("tunnelConvergedForGate opened gate for External DNS tunnel with DNSReady=False")
	}
	tunnel.Status.Conditions[1].Status = metav1.ConditionTrue
	tunnel.Status.Conditions[1].ObservedGeneration = 1
	if tunnelConvergedForGate(tunnel, account, []publicHostname{{Hostname: "a.example.com", ZoneID: "z1"}}) {
		t.Fatal("tunnelConvergedForGate opened gate for External DNS tunnel with stale DNSReady.ObservedGeneration")
	}
}

type failingTunnelConfigCloudflareAPI struct {
	*tunnelFreshnessGatewayAPI
	failGetTunnel atomic.Bool
	mu            sync.Mutex
}

func (api *failingTunnelConfigCloudflareAPI) GetTunnel(ctx context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	if api.failGetTunnel.Load() {
		api.mu.Lock()
		api.calls = append(api.calls, "GetTunnel(err)")
		api.mu.Unlock()
		return flarecloudflare.Tunnel{}, fmt.Errorf("injected GetTunnel failure")
	}
	return api.tunnelFreshnessGatewayAPI.GetTunnel(ctx, tunnelID)
}

// Gateway CloudflareTunnelConfig gate closes when ConfigApplied=False (RemoteError)
// and recovers on retry without trusting stale VerifiedAt/AppliedAt, while
// preserving ADR 0004 SSA condition ownership split.
func TestGatewayTunnelConfigGateRecoversAfterRemoteErrorEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	snapshots := newFakeSnapshotPublisher()
	const accountID = "0123456789abcdef0123456789abcdef"
	innerAPI := &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 1}
	gwAPI := &failingTunnelConfigCloudflareAPI{tunnelFreshnessGatewayAPI: innerAPI}
	tunnelFake := newFakeTunnelCloudflareFactory()
	prober := &staticGatewayProber{version: 2, ready: true}

	if err := (&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayClassReconciler: %v", err)
	}
	gwReconciler := &GatewayReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            mgr.GetScheme(),
		Snapshots:         snapshots,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gatewayCloudflareFactory{api: gwAPI},
		Prober:            prober,
		Freshness:         policy,
		Invalidator:       latch,
	}
	if err := gwReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayReconciler: %v", err)
	}
	if err := (&CloudflareTunnelReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup CloudflareTunnelReconciler: %v", err)
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-reg4"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cf-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: account.Name},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create cfg: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create gc: %v", err)
	}
	gwHost := gatewayv1.Hostname("reg4.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg4-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-reg4-0", UID: types.UID("dp-reg4-uid"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, pod); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	pod.Status.PodIP = "10.0.0.10"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "Gateway snapshot ACKed", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	tunnelKey := types.NamespacedName{Namespace: ns, Name: "reg4-gw"}
	waitUntilTrue(t, 15*time.Second, "Gateway ConfigApplied=True & Programmed=True", func() (bool, error) {
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curTunnel v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, tunnelKey, &curTunnel); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) &&
			assertConditionTrueForCurrentGen(curTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curTunnel.Generation), nil
	})

	// Simulate remoteConfigFailure demoting ConfigApplied=False (RemoteError).
	var curTunnel v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, tunnelKey, &curTunnel); err != nil {
		t.Fatalf("get tunnel: %v", err)
	}
	compiled := &ir.Gateway{
		Key:        client.ObjectKeyFromObject(gw),
		UID:        gw.UID,
		Cloudflare: &ir.Cloudflare{AccountID: accountID, TunnelID: curTunnel.Status.TunnelID},
	}
	gwAPI.failGetTunnel.Store(true)
	latch.Invalidate("CloudflareTunnelConfig", tunnelKey, "force remote pass")
	_, err := gwReconciler.reconcileCloudflaredConfiguration(ctx, compiled, &curTunnel, account)
	if err == nil {
		t.Fatal("expected remoteConfigFailure error")
	}
	gwAPI.failGetTunnel.Store(false)
	// Clear the test-only invalidation so we specifically prove ConfigApplied=False
	// (RemoteError) alone keeps the gate closed even inside the TTL of AppliedAt.
	latch.Clear("CloudflareTunnelConfig", tunnelKey)

	// Re-read tunnel: ConfigApplied must be False (RemoteError), and VerifiedAt must be forgotten.
	if err := direct.Get(ctx, tunnelKey, &curTunnel); err != nil {
		t.Fatalf("get tunnel after demote: %v", err)
	}
	ca := meta.FindStatusCondition(curTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied)
	if ca == nil || ca.Status != metav1.ConditionFalse || ca.Reason != "RemoteError" {
		t.Fatalf("ConfigApplied = %+v, want False/RemoteError", ca)
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", tunnelKey, curTunnel.Status.ConfigVersion.DesiredHash); ok {
		t.Fatal("remoteConfigFailure left VerifiedAt in latch")
	}
	// Verify ADR 0004 SSA condition ownership split is intact (tunnel-owned Ready/Accepted vs gateway-owned ConfigApplied).
	callsBefore := len(innerAPI.calls)
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	// Gate MUST have closed (DecisionClosedUnconverged) and called GetTunnel/GetTunnelConfiguration
	// rather than trusting AppliedAt within TTL!
	if !slices.Contains(innerAPI.calls[callsBefore:], "GetTunnelConfiguration") {
		t.Fatalf("CloudflareTunnelConfig gate stayed open despite ConfigApplied=False(RemoteError); calls=%v", innerAPI.calls[callsBefore:])
	}
	if err := direct.Get(ctx, tunnelKey, &curTunnel); err != nil {
		t.Fatalf("get tunnel after recovery: %v", err)
	}
	if !assertConditionTrueForCurrentGen(curTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curTunnel.Generation) {
		t.Fatalf("ConfigApplied did not recover to True: %+v", curTunnel.Status.Conditions)
	}
	// Tunnel-owned conditions (Accepted, TunnelReady, DNSReady) must still belong to tunnel controller field manager.
	var managedByTunnel, managedByGateway int
	for _, mf := range curTunnel.ManagedFields {
		switch mf.Manager {
		case tunnelFieldManager:
			managedByTunnel++
		case gatewayFieldManager:
			managedByGateway++
		}
	}
	if managedByTunnel == 0 || managedByGateway == 0 {
		t.Fatalf("ADR 0004 SSA condition ownership split broken: tunnel=%d gateway=%d", managedByTunnel, managedByGateway)
	}
}

// QA-2-REG-4: With freshness disabled (zero policy, no Sweep running),
// QA-2-REG-4 (AccessApplication): When --freshness-authz=0, a converged
// AccessApplication returns RequeueAfter=0s (event-driven, zero polling) and
// re-verifies/repairs out-of-band drift immediately on watch or explicit reconcile.
func TestQA2REG4ZeroFreshnessAccessApplicationEventDrivenDriftEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	appFake := newFakeAccessApplicationCloudflare()
	appReconciler := &AccessApplicationReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil },
		Freshness:           freshness.Policy{}, // zero freshness (--freshness-*=0)
		Invalidator:         latch,
	}
	if err := appReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup AccessApplicationReconciler: %v", err)
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-reg4-zero"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-zero-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, nil)
	appFake.SetPolicy(flarecloudflare.AccessPolicy{ID: "ext-pol-reg4", Name: "ext-pol", Decision: "Allow"})

	app := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-zero-fresh"},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			Application: v1alpha1.AccessApplicationSettings{
				Name:            "app-zero-fresh",
				SessionDuration: "1h",
			},
			Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
				Type:   v1alpha1.AccessApplicationDestinationWorker,
				Worker: &v1alpha1.AccessWorkerDestinationSpec{WorkerID: "worker-reg4"},
			}},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-reg4"}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := direct.Create(ctx, app); err != nil {
		t.Fatalf("create AccessApplication: %v", err)
	}
	appKey := client.ObjectKeyFromObject(app)
	waitUntilTrue(t, 15*time.Second, "AccessApplication converged", func() (bool, error) {
		var cur v1alpha1.AccessApplication
		return checkObjectConverged(ctx, direct, &cur, appKey, accessApplicationConditionProgrammed, accessApplicationConditionAccepted)
	})

	// Direct Reconcile on converged AccessApplication MUST stay event-driven (RequeueAfter == 0).
	directRes, err := appReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey})
	if err != nil {
		t.Fatalf("direct steady AccessApplication reconcile: %v", err)
	}
	if directRes.RequeueAfter != 0 {
		t.Fatalf("zero-freshness converged AccessApplication RequeueAfter = %v, want 0 (event-driven)", directRes.RequeueAfter)
	}

	var curApp v1alpha1.AccessApplication
	if err := direct.Get(ctx, appKey, &curApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	appID := curApp.Status.ApplicationID
	if appID == "" {
		t.Fatal("missing ApplicationID")
	}

	// Mutate remote state out-of-band: next reconcile (with gate closed at freshness=0) repairs it immediately.
	appFake.mu.Lock()
	remoteApp := appFake.applications[appID]
	remoteApp.Name = "drifted-out-of-band"
	appFake.applications[appID] = remoteApp
	appFake.mu.Unlock()

	if _, err := appReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err != nil {
		t.Fatalf("reconcile repair after drift: %v", err)
	}
	appFake.mu.Lock()
	repairedName := appFake.applications[appID].Name
	appFake.mu.Unlock()
	if repairedName != "app-zero-fresh" {
		t.Fatalf("remote drifted name = %q, want app-zero-fresh", repairedName)
	}
}

type countingAccessExtendedAPI struct {
	*recordingAccessAPI
	integrations flarecloudflare.DevicePostureIntegrationAPI
}

func (c *countingAccessExtendedAPI) GetDevicePostureRule(ctx context.Context, id string) (flarecloudflare.DevicePostureRule, error) {
	c.record("GetDevicePostureRule")
	return c.AccessAPI.GetDevicePostureRule(ctx, id)
}

func (c *countingAccessExtendedAPI) ListDevicePostureRules(ctx context.Context) ([]flarecloudflare.DevicePostureRule, error) {
	c.record("ListDevicePostureRules")
	return c.AccessAPI.ListDevicePostureRules(ctx)
}

func (c *countingAccessExtendedAPI) CreateDevicePostureRule(ctx context.Context, input flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	c.record("CreateDevicePostureRule")
	return c.AccessAPI.CreateDevicePostureRule(ctx, input)
}

func (c *countingAccessExtendedAPI) UpdateDevicePostureRule(ctx context.Context, id string, input flarecloudflare.DevicePostureRuleInput) (flarecloudflare.DevicePostureRule, error) {
	c.record("UpdateDevicePostureRule")
	return c.AccessAPI.UpdateDevicePostureRule(ctx, id, input)
}

func (c *countingAccessExtendedAPI) CreateDevicePostureIntegration(ctx context.Context, input flarecloudflare.DevicePostureIntegrationInput) (flarecloudflare.DevicePostureIntegration, error) {
	c.record("CreateDevicePostureIntegration")
	return c.integrations.CreateDevicePostureIntegration(ctx, input)
}

func (c *countingAccessExtendedAPI) UpdateDevicePostureIntegration(ctx context.Context, id string, input flarecloudflare.DevicePostureIntegrationInput) (flarecloudflare.DevicePostureIntegration, error) {
	c.record("UpdateDevicePostureIntegration")
	return c.integrations.UpdateDevicePostureIntegration(ctx, id, input)
}

func (c *countingAccessExtendedAPI) GetDevicePostureIntegration(ctx context.Context, id string) (flarecloudflare.DevicePostureIntegration, error) {
	c.record("GetDevicePostureIntegration")
	return c.integrations.GetDevicePostureIntegration(ctx, id)
}

func (c *countingAccessExtendedAPI) ListDevicePostureIntegrations(ctx context.Context) ([]flarecloudflare.DevicePostureIntegration, error) {
	c.record("ListDevicePostureIntegrations")
	return c.integrations.ListDevicePostureIntegrations(ctx)
}

func (c *countingAccessExtendedAPI) DeleteDevicePostureIntegration(ctx context.Context, id string) error {
	c.record("DeleteDevicePostureIntegration")
	return c.integrations.DeleteDevicePostureIntegration(ctx, id)
}

func (c *countingAccessExtendedAPI) GetAccessCustomPage(ctx context.Context, id string) (flarecloudflare.AccessCustomPage, error) {
	c.record("GetAccessCustomPage")
	return c.AccessAPI.GetAccessCustomPage(ctx, id)
}

func (c *countingAccessExtendedAPI) ListAccessCustomPages(ctx context.Context) ([]flarecloudflare.AccessCustomPageSummary, error) {
	c.record("ListAccessCustomPages")
	return c.AccessAPI.ListAccessCustomPages(ctx)
}

func (c *countingAccessExtendedAPI) CreateAccessCustomPage(ctx context.Context, input flarecloudflare.AccessCustomPageInput) (flarecloudflare.AccessCustomPage, error) {
	c.record("CreateAccessCustomPage")
	return c.AccessAPI.CreateAccessCustomPage(ctx, input)
}

func (c *countingAccessExtendedAPI) UpdateAccessCustomPage(ctx context.Context, id string, input flarecloudflare.AccessCustomPageInput) (flarecloudflare.AccessCustomPage, error) {
	c.record("UpdateAccessCustomPage")
	return c.AccessAPI.UpdateAccessCustomPage(ctx, id, input)
}

func (c *countingAccessExtendedAPI) GetAccessApplication(ctx context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.AccessApplication, error) {
	c.record("GetAccessApplication")
	return c.AccessAPI.GetAccessApplication(ctx, scope, id)
}

func (c *countingAccessExtendedAPI) ListAccessApplications(ctx context.Context, scope flarecloudflare.AccessScope) ([]flarecloudflare.AccessApplication, error) {
	c.record("ListAccessApplications")
	return c.AccessAPI.ListAccessApplications(ctx, scope)
}

func (c *countingAccessExtendedAPI) CreateAccessApplication(ctx context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplicationCreateResult, error) {
	c.record("CreateAccessApplication")
	return c.AccessAPI.CreateAccessApplication(ctx, scope, input)
}

func (c *countingAccessExtendedAPI) UpdateAccessApplication(ctx context.Context, scope flarecloudflare.AccessScope, id string, input flarecloudflare.AccessApplicationInput) (flarecloudflare.AccessApplication, error) {
	c.record("UpdateAccessApplication")
	return c.AccessAPI.UpdateAccessApplication(ctx, scope, id, input)
}

func (c *countingAccessExtendedAPI) GetAccessTag(ctx context.Context, name string) (flarecloudflare.AccessTag, error) {
	c.record("GetAccessTag")
	return c.AccessAPI.GetAccessTag(ctx, name)
}

func (c *countingAccessExtendedAPI) CreateAccessTag(ctx context.Context, name string) (flarecloudflare.AccessTag, error) {
	c.record("CreateAccessTag")
	return c.AccessAPI.CreateAccessTag(ctx, name)
}

func (c *countingAccessExtendedAPI) ListAccessTags(ctx context.Context) ([]flarecloudflare.AccessTag, error) {
	c.record("ListAccessTags")
	return c.AccessAPI.ListAccessTags(ctx)
}

type countingDeviceProfileAPI struct {
	flarecloudflare.DeviceProfileAPI
	calls atomic.Int64
}

func (c *countingDeviceProfileAPI) GetDefaultDeviceProfile(ctx context.Context) (flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.GetDefaultDeviceProfile(ctx)
}

func (c *countingDeviceProfileAPI) UpdateDefaultDeviceProfile(ctx context.Context, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.UpdateDefaultDeviceProfile(ctx, input)
}

func (c *countingDeviceProfileAPI) CreateCustomDeviceProfile(ctx context.Context, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.CreateCustomDeviceProfile(ctx, input)
}

func (c *countingDeviceProfileAPI) ListCustomDeviceProfiles(ctx context.Context) ([]flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.ListCustomDeviceProfiles(ctx)
}

func (c *countingDeviceProfileAPI) GetCustomDeviceProfile(ctx context.Context, id string) (flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.GetCustomDeviceProfile(ctx, id)
}

func (c *countingDeviceProfileAPI) UpdateCustomDeviceProfile(ctx context.Context, id string, input flarecloudflare.DeviceProfileInput) (flarecloudflare.DeviceProfile, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.UpdateCustomDeviceProfile(ctx, id, input)
}

func (c *countingDeviceProfileAPI) GetDeviceProfileInclude(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.GetDeviceProfileInclude(ctx, ref)
}

func (c *countingDeviceProfileAPI) GetDeviceProfileExclude(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.SplitTunnelEntry, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.GetDeviceProfileExclude(ctx, ref)
}

func (c *countingDeviceProfileAPI) GetDeviceProfileFallbackDomains(ctx context.Context, ref flarecloudflare.DeviceProfileRef) ([]flarecloudflare.FallbackDomain, error) {
	c.calls.Add(1)
	return c.DeviceProfileAPI.GetDeviceProfileFallbackDomains(ctx, ref)
}

type countingWARPConnectorAPI struct {
	flarecloudflare.WARPConnectorAPI
	calls atomic.Int64
}

func (c *countingWARPConnectorAPI) CreateWARPConnector(ctx context.Context, input flarecloudflare.WARPConnectorCreateInput) (flarecloudflare.WARPConnector, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.CreateWARPConnector(ctx, input)
}

func (c *countingWARPConnectorAPI) ListWARPConnectors(ctx context.Context, filter flarecloudflare.WARPConnectorListFilter) ([]flarecloudflare.WARPConnector, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.ListWARPConnectors(ctx, filter)
}

func (c *countingWARPConnectorAPI) UpdateWARPConnector(ctx context.Context, id string, input flarecloudflare.WARPConnectorUpdateInput) (flarecloudflare.WARPConnector, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.UpdateWARPConnector(ctx, id, input)
}

func (c *countingWARPConnectorAPI) GetWARPConnector(ctx context.Context, id string) (flarecloudflare.WARPConnector, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.GetWARPConnector(ctx, id)
}

func (c *countingWARPConnectorAPI) UpdateWARPConnectorConfiguration(ctx context.Context, id string, input flarecloudflare.WARPConnectorConfigurationInput) (flarecloudflare.WARPConnectorConfiguration, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.UpdateWARPConnectorConfiguration(ctx, id, input)
}

func (c *countingWARPConnectorAPI) GetWARPConnectorConfiguration(ctx context.Context, id string) (flarecloudflare.WARPConnectorConfiguration, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.GetWARPConnectorConfiguration(ctx, id)
}

func (c *countingWARPConnectorAPI) ListWARPConnectorClients(ctx context.Context, id string) ([]flarecloudflare.WARPConnectorClient, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.ListWARPConnectorClients(ctx, id)
}

func (c *countingWARPConnectorAPI) GetWARPConnectorClient(ctx context.Context, tunnelID, clientID string) (flarecloudflare.WARPConnectorClient, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.GetWARPConnectorClient(ctx, tunnelID, clientID)
}

func (c *countingWARPConnectorAPI) GetWARPConnectorToken(ctx context.Context, id string) (string, error) {
	c.calls.Add(1)
	return c.WARPConnectorAPI.GetWARPConnectorToken(ctx, id)
}

// Verifies that resources referencing un-listed ExternalID/ExternalRef dependencies
// never receive parent-only sweep content confirmation (ConfirmedAt stays unset),
// so TTL expiry detects a deleted external Group even while the parent listing is unchanged.
func TestQA2SweepDoesNotExtendExternalRefPastTTLEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	var clockMu sync.Mutex
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = now.Add(d)
	}

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	store := newFakeAccessResourceCloudflare()
	extGroup, err := store.CreateAccessGroup(ctx, flarecloudflare.AccessScope{}, flarecloudflare.AccessGroupInput{
		Name: "ext-grp-gone", Include: []flarecloudflare.ResolvedAccessRule{{Kind: "everyone"}},
	})
	if err != nil {
		t.Fatalf("seed external AccessGroup: %v", err)
	}
	extIDP, err := store.CreateIdentityProvider(ctx, flarecloudflare.IdentityProviderInput{
		Name: "ext-idp-gone", Type: "onetimepin",
	})
	if err != nil {
		t.Fatalf("seed external IdentityProvider: %v", err)
	}
	remote := &recordingAccessAPI{AccessAPI: store}
	standaloneFake := &fakeStandaloneCloudflare{
		AccessAPI:    remote,
		applications: map[string]flarecloudflare.AccessApplication{},
		tags:         map[string]flarecloudflare.AccessTag{},
	}
	standaloneRemote := &countingAccessExtendedAPI{recordingAccessAPI: &recordingAccessAPI{AccessAPI: standaloneFake}}

	polReconciler := &AccessPolicyReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch, Now: nowFn,
	}
	grpReconciler := &AccessGroupReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Freshness:           policy, Invalidator: latch, Now: nowFn,
	}
	standaloneReconciler := &AccessStandaloneApplicationReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return standaloneRemote, nil },
		Freshness:           policy, Invalidator: latch, Now: nowFn,
	}
	if err := polReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup policy reconciler: %v", err)
	}
	if err := grpReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup group reconciler: %v", err)
	}
	if err := standaloneReconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup standalone reconciler: %v", err)
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-extref-sweep"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "extref-sweep-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"}, Zones: []string{"*"},
				Exposures:       []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects: v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, nil)

	pol := &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-extref"},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "pol-extref",
			Decision:         v1alpha1.AccessPolicyDecisionAllow,
			Include:          []v1alpha1.AccessRule{{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{ExternalID: extGroup.ID}}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	grp := &v1alpha1.AccessGroup{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "grp-extref"},
		Spec: v1alpha1.AccessGroupSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "grp-extref",
			Include:          []v1alpha1.AccessRule{{Group: &v1alpha1.AccessGroupRule{GroupRef: v1alpha1.AccessObjectReference{ExternalID: extGroup.ID}}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	standalone := &v1alpha1.AccessStandaloneApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "standalone-extref"},
		Spec: v1alpha1.AccessStandaloneApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Type:       v1alpha1.AccessStandaloneApplicationTypeBookmark,
			Bookmark:   &v1alpha1.AccessBookmarkApplicationSpec{URL: "https://bookmark.example.com"},
			Application: v1alpha1.AccessApplicationSettings{
				Name:            "standalone-extref",
				SessionDuration: "1h",
				AllowedIDPRefs:  []v1alpha1.AccessIdentityProviderReference{{ExternalID: extIDP.ID}},
			},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	for _, obj := range []client.Object{pol, grp, standalone} {
		if err := direct.Create(ctx, obj); err != nil {
			t.Fatalf("create %T: %v", obj, err)
		}
	}
	polKey := client.ObjectKeyFromObject(pol)
	grpKey := client.ObjectKeyFromObject(grp)
	standaloneKey := client.ObjectKeyFromObject(standalone)

	waitUntilTrue(t, 10*time.Second, "external-ref objects converged", func() (bool, error) {
		var p v1alpha1.AccessPolicy
		if ok, err := checkObjectConverged(ctx, direct, &p, polKey, "Ready", "Accepted"); err != nil || !ok {
			return false, err
		}
		var g v1alpha1.AccessGroup
		if ok, err := checkObjectConverged(ctx, direct, &g, grpKey, "Ready", "Accepted"); err != nil || !ok {
			return false, err
		}
		var s v1alpha1.AccessStandaloneApplication
		return checkObjectConverged(ctx, direct, &s, standaloneKey, "Ready", "Accepted")
	})

	// Run one rebind reconcile so AppliedHash captures assigned remote IDs.
	for _, pair := range []struct {
		r   interface{ Reconcile(context.Context, ctrl.Request) (ctrl.Result, error) }
		key types.NamespacedName
	}{
		{polReconciler, polKey},
		{grpReconciler, grpKey},
		{standaloneReconciler, standaloneKey},
	} {
		if _, err := pair.r.Reconcile(ctx, ctrl.Request{NamespacedName: pair.key}); err != nil {
			t.Fatalf("rebind %v: %v", pair.key, err)
		}
	}

	var curPol v1alpha1.AccessPolicy
	var curGrp v1alpha1.AccessGroup
	var curStandalone v1alpha1.AccessStandaloneApplication
	if err := direct.Get(ctx, polKey, &curPol); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, grpKey, &curGrp); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, standaloneKey, &curStandalone); err != nil {
		t.Fatal(err)
	}

	// Simulate active parent-only sweep listings matching parent state.
	// Because all 3 carry un-listed ExternalID refs, ConfirmContent MUST NOT confirm or extend them.
	listedPol, _ := store.GetAccessPolicy(ctx, curPol.Status.PolicyID)
	listedGrp, _ := store.GetAccessGroup(ctx, flarecloudflare.AccessScope{}, curGrp.Status.GroupID)
	listedApp, _ := standaloneFake.GetAccessApplication(ctx, flarecloudflare.AccessScope{}, curStandalone.Status.ApplicationID)

	_ = latch.ConfirmContent("AccessPolicy", polKey, listedPol, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessPolicy", polKey, curPol.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("AccessPolicy ConfirmedAt = %v, want zero", ts)
	}
	_ = latch.ConfirmContent("AccessGroup", grpKey, listedGrp, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessGroup", grpKey, curGrp.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("AccessGroup ConfirmedAt = %v, want zero", ts)
	}
	_ = latch.ConfirmContent("AccessStandaloneApplication", standaloneKey, listedApp, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessStandaloneApplication", standaloneKey, curStandalone.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("AccessStandaloneApplication ConfirmedAt = %v, want zero", ts)
	}

	// Delete the external Group and external IdentityProvider out of band while parent listings remain unchanged.
	if err := store.DeleteAccessGroup(ctx, flarecloudflare.AccessScope{}, extGroup.ID); err != nil {
		t.Fatalf("delete external group: %v", err)
	}
	if err := store.DeleteIdentityProvider(ctx, extIDP.ID); err != nil {
		t.Fatalf("delete external identity provider: %v", err)
	}
	standaloneFake.mu.Lock()
	standaloneFake.idpLookupErr = globalOrganizationNotFound()
	standaloneFake.mu.Unlock()

	// Advance inside TTL (+30s) and confirm parent listings again: gate stays open within TTL (0 reads).
	advanceClock(30 * time.Second)
	_ = latch.ConfirmContent("AccessPolicy", polKey, listedPol, nowFn())
	_ = latch.ConfirmContent("AccessGroup", grpKey, listedGrp, nowFn())
	_ = latch.ConfirmContent("AccessStandaloneApplication", standaloneKey, listedApp, nowFn())
	callsBefore := remote.count()
	standaloneCallsBefore := standaloneRemote.count()
	if _, err := polReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: polKey}); err != nil {
		t.Fatalf("within-TTL policy reconcile: %v", err)
	}
	if _, err := grpReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: grpKey}); err != nil {
		t.Fatalf("within-TTL group reconcile: %v", err)
	}
	if _, err := standaloneReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: standaloneKey}); err != nil {
		t.Fatalf("within-TTL standalone reconcile: %v", err)
	}
	if got := remote.count() - callsBefore; got != 0 {
		t.Fatalf("within-TTL reconciles issued %d remote calls, want 0", got)
	}
	if got := standaloneRemote.count() - standaloneCallsBefore; got != 0 {
		t.Fatalf("within-TTL standalone reconcile issued %d remote calls, want 0", got)
	}

	// Advance past 60s TTL (+35s) even while parent-only sweep keeps calling ConfirmContent:
	// the gate MUST expire and detect the deleted external group / IDP!
	advanceClock(35 * time.Second)
	_ = latch.ConfirmContent("AccessPolicy", polKey, listedPol, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessPolicy", polKey, curPol.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("parent-only sweep confirmed AccessPolicy past TTL: %v", ts)
	}
	_ = latch.ConfirmContent("AccessGroup", grpKey, listedGrp, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessGroup", grpKey, curGrp.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("parent-only sweep confirmed AccessGroup past TTL: %v", ts)
	}
	_ = latch.ConfirmContent("AccessStandaloneApplication", standaloneKey, listedApp, nowFn())
	if ts, ok := latch.ConfirmedAt("AccessStandaloneApplication", standaloneKey, curStandalone.Status.AppliedHash); ok && !ts.IsZero() {
		t.Fatalf("parent-only sweep confirmed AccessStandaloneApplication past TTL: %v", ts)
	}

	if _, err := polReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: polKey}); err != nil {
		t.Fatalf("post-TTL policy reconcile: %v", err)
	}
	if _, err := grpReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: grpKey}); err != nil {
		t.Fatalf("post-TTL group reconcile: %v", err)
	}
	if _, err := standaloneReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: standaloneKey}); err != nil {
		t.Fatalf("post-TTL standalone reconcile: %v", err)
	}

	if err := direct.Get(ctx, polKey, &curPol); err != nil {
		t.Fatal(err)
	}
	polReady := meta.FindStatusCondition(curPol.Status.Conditions, "Ready")
	if polReady == nil || polReady.Status != metav1.ConditionFalse || polReady.Reason != "RefNotPermitted" {
		t.Fatalf("AccessPolicy after external group deletion + TTL expiry = %#v, want Ready=False (RefNotPermitted)", polReady)
	}
	if err := direct.Get(ctx, grpKey, &curGrp); err != nil {
		t.Fatal(err)
	}
	grpReady := meta.FindStatusCondition(curGrp.Status.Conditions, "Ready")
	if grpReady == nil || grpReady.Status != metav1.ConditionFalse || grpReady.Reason != "RefNotPermitted" {
		t.Fatalf("AccessGroup after external group deletion + TTL expiry = %#v, want Ready=False (RefNotPermitted)", grpReady)
	}
	if err := direct.Get(ctx, standaloneKey, &curStandalone); err != nil {
		t.Fatal(err)
	}
	standaloneReady := meta.FindStatusCondition(curStandalone.Status.Conditions, "Ready")
	if standaloneReady == nil || standaloneReady.Status != metav1.ConditionFalse {
		t.Fatalf("AccessStandaloneApplication after external IDP deletion + TTL expiry = %#v, want Ready=False", standaloneReady)
	}
}

type lockingGatewayDriftAPI struct {
	*tunnelFreshnessGatewayAPI
	mu          sync.Mutex
	updateCount int
}

func (a *lockingGatewayDriftAPI) GetTunnel(ctx context.Context, tunnelID string) (flarecloudflare.Tunnel, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunnelFreshnessGatewayAPI.GetTunnel(ctx, tunnelID)
}

func (a *lockingGatewayDriftAPI) GetTunnelConfiguration(ctx context.Context, tunnelID string) (flarecloudflare.TunnelConfiguration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunnelFreshnessGatewayAPI.GetTunnelConfiguration(ctx, tunnelID)
}

func (a *lockingGatewayDriftAPI) UpdateTunnelConfiguration(ctx context.Context, tunnelID string, params zero_trust.TunnelCloudflaredConfigurationUpdateParams) (flarecloudflare.TunnelConfiguration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updateCount++
	return a.tunnelFreshnessGatewayAPI.UpdateTunnelConfiguration(ctx, tunnelID, params)
}

// QA-2-REG-4 (Gateway): When --freshness-traffic=0, a converged/programmed Gateway
// continues periodic drift checks and repairs out-of-band remote tunnel config drift
// with zero Kubernetes events.
func TestQA2REG4ZeroFreshnessGatewayPeriodicDriftEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	const accountID = "0123456789abcdef0123456789abcdef"
	tunnelFake := newFakeTunnelCloudflareFactory()
	gwAPI := &lockingGatewayDriftAPI{
		tunnelFreshnessGatewayAPI: &tunnelFreshnessGatewayAPI{accountID: accountID, remoteVersion: 1},
	}
	snapshots := newFakeSnapshotPublisher()
	prober := &staticGatewayProber{version: 2, ready: true}

	gwReconciler := &GatewayReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		Snapshots: snapshots, OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gatewayCloudflareFactory{api: gwAPI},
		Prober:            prober,
		Freshness:         freshness.Policy{}, // zero freshness (--freshness-traffic=0)
		Invalidator:       latch,
	}
	for _, err := range []error{
		(&CloudflareTunnelReconciler{
			Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
			NewCloudflareClient: tunnelFake.Client,
			Freshness:           freshness.Policy{}, // zero freshness
			Invalidator:         latch,
		}).SetupWithManager(mgr),
		(&GatewayClassReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr),
		gwReconciler.SetupWithManager(mgr),
	} {
		if err != nil {
			t.Fatalf("setup controller: %v", err)
		}
	}
	startManagerAndWait(t, mgr)

	const ns = "tenant-reg4-gw-zero"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-gw-zero-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.com"}})

	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-gw-zero-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: account.Name},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create cfg: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reg4-gw-zero-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create gc: %v", err)
	}
	gwHost := gatewayv1.Hostname("reg4-gw-zero.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reg4-gw-zero"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "reg4 Gateway dataplane Deployment created", func() (bool, error) {
		var dep appsv1.DeploymentList
		if err := direct.List(ctx, &dep, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(dep.Items) > 0, nil
	})
	gwPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "dp-reg4-gw-0", UID: types.UID("dp-reg4-gw-uid"),
			Labels: map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, gwPod); err != nil {
		t.Fatalf("create gw pod: %v", err)
	}
	gwPod.Status.PodIP = "10.0.0.25"
	gwPod.Status.Phase = corev1.PodRunning
	gwPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, gwPod); err != nil {
		t.Fatalf("update gw pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "reg4 Gateway snapshot ACKed", func() (bool, error) {
		return snapshots.ACK(client.ObjectKeyFromObject(gw).String()) == nil, nil
	})
	gwTunnelKey := types.NamespacedName{Namespace: ns, Name: gw.Name}
	waitUntilTrue(t, 15*time.Second, "reg4 Gateway Programmed=True & ConfigApplied=True", func() (bool, error) {
		var curGW gatewayv1.Gateway
		if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &curGW); err != nil {
			return false, err
		}
		var curT v1alpha1.CloudflareTunnel
		if err := direct.Get(ctx, gwTunnelKey, &curT); err != nil {
			return false, err
		}
		return assertConditionTrueForCurrentGen(curGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), curGW.Generation) &&
			assertConditionTrueForCurrentGen(curT.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, curT.Generation), nil
	})

	// Drain startup reconciles and queued watches completely before testing the timer.
	waitUntilTrue(t, 10*time.Second, "Gateway startup reconciles drained", func() (bool, error) {
		gwAPI.mu.Lock()
		before := len(gwAPI.calls)
		gwAPI.mu.Unlock()
		time.Sleep(1500 * time.Millisecond)
		gwAPI.mu.Lock()
		after := len(gwAPI.calls)
		gwAPI.mu.Unlock()
		return after == before, nil
	})

	// Directly assert converged Gateway schedules gatewayZeroFreshnessRequeue (10s) at zero traffic freshness.
	directRes, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	if err != nil {
		t.Fatalf("direct steady zero-freshness Gateway reconcile: %v", err)
	}
	if directRes.RequeueAfter != gatewayZeroFreshnessRequeue {
		t.Fatalf("zero-freshness programmed Gateway RequeueAfter = %v, want %v", directRes.RequeueAfter, gatewayZeroFreshnessRequeue)
	}

	// Mutate remote tunnel config version out of band WITHOUT any Kubernetes event.
	gwAPI.mu.Lock()
	updatesBefore := gwAPI.updateCount
	gwAPI.remoteVersion = 99
	gwAPI.mu.Unlock()

	// Gateway periodic fallback requeue (gatewayZeroFreshnessRequeue = 10s) MUST detect and overwrite drift.
	waitUntilTrue(t, 20*time.Second, "zero-freshness Gateway periodic timer repaired remote config drift", func() (bool, error) {
		gwAPI.mu.Lock()
		defer gwAPI.mu.Unlock()
		return gwAPI.updateCount > updatesBefore && gwAPI.remoteVersion != 99, nil
	})
}

// Regression test for stale-snapshot admission overwrite on Gateway:
// an admission-only prepareGatewayStatus + patchGatewayStatus starting from an
// older revision (Programmed=True, stale Addresses) MUST NOT overwrite a newer
// live demotion (Programmed=False, Addresses=nil).
func TestDefensiveGatewayAdmissionDoesNotRepublishAStaleProgrammedCondition(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-stale-admission"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	host := gatewayv1.Hostname("stale-guard.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "stale-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &host}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}

	// Step 1: Persist rev A with Translated admission fields plus Programmed=True, Addresses=[host].
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	t1 := metav1.Now()
	addrType := gatewayv1.HostnameAddressType
	reconciler := &GatewayReconciler{
		Client:    direct,
		APIReader: direct,
		Scheme:    mgr.GetScheme(),
	}
	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	gwCfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway-cfg"},
		Spec:       v1alpha1.GatewayClassConfigSpec{ConformanceMode: true},
	}
	_, initialStatuses := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway:            gw,
		GatewayClass:       gwClass,
		GatewayClassConfig: gwCfg,
		Namespaces:         []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&initialStatuses.Gateway, gw)
	initialStatuses.Gateway.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &addrType, Value: string(host)}}
	meta.SetStatusCondition(&initialStatuses.Gateway.Conditions, metav1.Condition{
		Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok", ObservedGeneration: gw.Generation, LastTransitionTime: t1,
	})
	meta.SetStatusCondition(&initialStatuses.Gateway.Listeners[0].Conditions, metav1.Condition{
		Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok", ObservedGeneration: gw.Generation, LastTransitionTime: t1,
	})
	gw.Status = initialStatuses.Gateway
	if err := direct.Status().Update(ctx, gw); err != nil {
		t.Fatalf("write rev A status: %v", err)
	}
	staleSnapshot := gw.DeepCopy()

	// Step 2: Live demotion (rev B): Programmed=False/Pending, listener Programmed=False/Pending, Addresses=nil.
	var liveGW gatewayv1.Gateway
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &liveGW); err != nil {
		t.Fatal(err)
	}
	t2 := metav1.NewTime(t1.Add(time.Second))
	liveGW.Status.Addresses = nil
	meta.SetStatusCondition(&liveGW.Status.Conditions, metav1.Condition{
		Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionFalse, Reason: "Pending", Message: "probe down", ObservedGeneration: liveGW.Generation, LastTransitionTime: t2,
	})
	meta.SetStatusCondition(&liveGW.Status.Listeners[0].Conditions, metav1.Condition{
		Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionFalse, Reason: "Pending", Message: "probe down", ObservedGeneration: liveGW.Generation, LastTransitionTime: t2,
	})
	if err := direct.Status().Update(ctx, &liveGW); err != nil {
		t.Fatalf("write rev B demotion: %v", err)
	}
	demotedRV := liveGW.ResourceVersion

	// Step 3: Run the real Translate -> prepareGatewayStatus -> patchGatewayAdmissionStatus path using staleSnapshot (rev A).
	_, translatedStatuses := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway:            staleSnapshot,
		GatewayClass:       gwClass,
		GatewayClassConfig: gwCfg,
		Namespaces:         []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&translatedStatuses.Gateway, staleSnapshot)
	if err := reconciler.patchGatewayAdmissionStatus(ctx, client.ObjectKeyFromObject(gw), translatedStatuses.Gateway); err != nil {
		t.Fatalf("patchGatewayAdmissionStatus with stale translated admission snapshot: %v", err)
	}

	var after gatewayv1.Gateway
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &after); err != nil {
		t.Fatal(err)
	}
	prog := meta.FindStatusCondition(after.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionFalse || prog.Reason != "Pending" {
		t.Fatalf("stale admission patch overwrote live Programmed condition: got %#v, want False/Pending", prog)
	}
	lprog := meta.FindStatusCondition(after.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if lprog == nil || lprog.Status != metav1.ConditionFalse || lprog.Reason != "Pending" {
		t.Fatalf("stale admission patch overwrote live listener Programmed condition: got %#v, want False/Pending", lprog)
	}
	if len(after.Status.Addresses) != 0 {
		t.Fatalf("stale admission patch restored stale Addresses %#v, want nil", after.Status.Addresses)
	}
	if after.ResourceVersion != demotedRV {
		t.Fatalf("admission no-op bumped ResourceVersion %s -> %s, want unchanged %s", demotedRV, after.ResourceVersion, demotedRV)
	}

	// Step 4: Reverse direction (root cause of TestCloudflareModeGatewayRemovesListenerService
	// flake): a stale reconcile-start snapshot carrying Programmed=False/Pending from
	// OwnershipCheckpoint/credentials wait runs Translate -> prepareGatewayStatus ->
	// patchGatewayStatus after live Gateway already converged to Programmed=True.
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &liveGW); err != nil {
		t.Fatal(err)
	}
	stalePending := liveGW.DeepCopy()
	t3 := metav1.NewTime(t2.Add(time.Second))
	liveGW.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &addrType, Value: string(host)}}
	meta.SetStatusCondition(&liveGW.Status.Conditions, metav1.Condition{
		Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed", Message: "converged", ObservedGeneration: liveGW.Generation, LastTransitionTime: t3,
	})
	meta.SetStatusCondition(&liveGW.Status.Listeners[0].Conditions, metav1.Condition{
		Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed", Message: "converged", ObservedGeneration: liveGW.Generation, LastTransitionTime: t3,
	})
	if err := direct.Status().Update(ctx, &liveGW); err != nil {
		t.Fatalf("write rev C programmed: %v", err)
	}
	convergedRV := liveGW.ResourceVersion

	_, stalePendingStatuses := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway:            stalePending,
		GatewayClass:       gwClass,
		GatewayClassConfig: gwCfg,
		Namespaces:         []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&stalePendingStatuses.Gateway, stalePending)
	if err := reconciler.patchGatewayAdmissionStatus(ctx, client.ObjectKeyFromObject(gw), stalePendingStatuses.Gateway); err != nil {
		t.Fatalf("patchGatewayAdmissionStatus with stale pending snapshot: %v", err)
	}

	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &after); err != nil {
		t.Fatal(err)
	}
	prog = meta.FindStatusCondition(after.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionTrue || prog.Reason != "Programmed" {
		t.Fatalf("stale pending admission patch overwrote live Programmed=True: got %#v, want True/Programmed", prog)
	}
	lprog = meta.FindStatusCondition(after.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if lprog == nil || lprog.Status != metav1.ConditionTrue || lprog.Reason != "Programmed" {
		t.Fatalf("stale pending admission patch overwrote live listener Programmed=True: got %#v, want True/Programmed", lprog)
	}
	if len(after.Status.Addresses) != 1 || after.Status.Addresses[0].Value != string(host) {
		t.Fatalf("stale pending admission patch cleared live Addresses %#v, want [%s]", after.Status.Addresses, host)
	}
	if after.ResourceVersion != convergedRV {
		t.Fatalf("stale pending admission no-op bumped ResourceVersion %s -> %s, want unchanged %s", convergedRV, after.ResourceVersion, convergedRV)
	}
}

// Envtest regression test for Finding #4: if flareway-gateway still co-owns
// status.conditions alongside matching data fields (upgraded cluster), the
// next patchTunnelGatewayData call MUST execute an SSA Apply to shed
// status.conditions ownership, and the subsequent pass MUST skip (0 requests).
func TestPatchTunnelGatewayDataShedsCoOwnedConditionsEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-ssa-shed"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	if err := direct.Create(ctx, gc); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create gatewayclass: %v", err)
	}
	gwHost := gatewayv1.Hostname("edge.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "edge",
			}},
			Listeners: []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "acct"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Configuration:    v1alpha1.CloudflareTunnelConfiguration{Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway},
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	appliedAt := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	config := v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "cfg-h1", Applied: 1, Remote: 1, AppliedAt: &appliedAt}
	hostnames := []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1}}
	listeners := []v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}}

	// Seed tunnel identity ownership under flareway-tunnel (as CloudflareTunnelReconciler does)
	// and legacy flareway-gateway co-ownership of status.conditions + data fields.
	identityApply := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"tunnelId":                "tunnel-1",
			"accountId":               "0123456789abcdef0123456789abcdef",
			"ownershipVerified":       true,
			"connectorTokenSecretRef": map[string]any{"name": "token-secret"},
			"gatewayRef":              map[string]any{"name": gw.Name},
			"gatewayUid":              string(gw.UID),
		},
	}}
	identityApply.SetAPIVersion(v1alpha1.GroupVersion.String())
	identityApply.SetKind("CloudflareTunnel")
	identityApply.SetNamespace(ns)
	identityApply.SetName(tunnel.Name)
	if err := direct.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(identityApply), client.FieldOwner("flareway-tunnel"), client.ForceOwnership); err != nil {
		t.Fatalf("seed tunnel identity SSA status: %v", err)
	}

	legacyApply := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"configVersion": map[string]any{
				"desired":     1,
				"desiredHash": "cfg-h1",
				"applied":     1,
				"remote":      1,
				"appliedAt":   appliedAt.Format(time.RFC3339),
			},
			"hostnames": []any{map[string]any{"hostname": "app.example.com", "protectionDomain": "", "accessApplication": "", "guard": "Forwarding", "appliedVersion": 1}},
			"listeners": []any{map[string]any{"name": "http", "exposure": "Public"}},
			"conditions": []any{map[string]any{
				"type":               v1alpha1.CloudflareTunnelConditionConfigApplied,
				"status":             "True",
				"reason":             "Applied",
				"message":            "ok",
				"observedGeneration": tunnel.Generation,
				"lastTransitionTime": appliedAt.Format(time.RFC3339),
			}},
		},
	}}
	legacyApply.SetAPIVersion(v1alpha1.GroupVersion.String())
	legacyApply.SetKind("CloudflareTunnel")
	legacyApply.SetNamespace(ns)
	legacyApply.SetName(tunnel.Name)
	if err := direct.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(legacyApply), client.FieldOwner(gatewayFieldManager), client.ForceOwnership); err != nil {
		t.Fatalf("seed legacy flareway-gateway SSA status: %v", err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
		t.Fatal(err)
	}

	var statusApplies atomic.Int64
	countingClient := &countingSSAStatusClient{Client: direct, applies: &statusApplies}
	reconciler := &GatewayReconciler{
		Client:    countingClient,
		APIReader: direct,
		Scheme:    mgr.GetScheme(),
	}
	irGW := &ir.Gateway{Key: client.ObjectKeyFromObject(gw), UID: gw.UID}

	// Run shared conditions stage first (as gateway_controller.go does) so conditions migrate
	// to tunnelStatusFieldManager while flareway-gateway still retains legacy f:conditions co-ownership.
	if err := (&GatewayReconciler{Client: direct, APIReader: direct, Scheme: mgr.GetScheme()}).patchTunnelGatewayConditions(ctx, irGW, tunnel, appliedAt); err != nil {
		t.Fatalf("patchTunnelGatewayConditions: %v", err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
		t.Fatal(err)
	}

	// First call: data matches, but flareway-gateway still owns status.conditions -> MUST SSA Apply once to shed it.
	if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hostnames, listeners); err != nil {
		t.Fatalf("first patchTunnelGatewayData: %v", err)
	}
	if got := statusApplies.Load(); got != 1 {
		t.Fatalf("first patchTunnelGatewayData status applies = %d, want 1 (to shed status.conditions co-ownership)", got)
	}

	if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
		t.Fatal(err)
	}
	for _, mf := range tunnel.ManagedFields {
		if mf.Manager == gatewayFieldManager && mf.Subresource == "status" && mf.FieldsV1 != nil {
			var fields map[string]any
			if err := json.Unmarshal(mf.FieldsV1.GetRawBytes(), &fields); err == nil {
				if sf, ok := fields["f:status"].(map[string]any); ok {
					if _, hasCond := sf["f:conditions"]; hasCond {
						t.Fatalf("flareway-gateway still owns status.conditions after patchTunnelGatewayData: %s", string(mf.FieldsV1.GetRawBytes()))
					}
				}
			}
		}
	}

	// Second call: data matches and status.conditions co-ownership is shed -> MUST skip (0 applies).
	statusApplies.Store(0)
	if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hostnames, listeners); err != nil {
		t.Fatalf("second patchTunnelGatewayData: %v", err)
	}
	if got := statusApplies.Load(); got != 0 {
		t.Fatalf("second patchTunnelGatewayData status applies = %d, want 0", got)
	}

	// Third check (leaf-level ownership gap via real apiserver SSA): another manager steals
	// exclusive ownership of a nested leaf (configVersion.remote: 1 -> 2 -> 1) while leaving
	// final status values identical to config/hostnames/listeners.
	// patchTunnelGatewayData MUST detect the leaf gap and apply once to reclaim it, then skip.
	for _, val := range []int{2, 1} {
		stealLeafApply := &unstructured.Unstructured{Object: map[string]any{
			"status": map[string]any{
				"configVersion": map[string]any{
					"remote": val,
				},
			},
		}}
		stealLeafApply.SetAPIVersion(v1alpha1.GroupVersion.String())
		stealLeafApply.SetKind("CloudflareTunnel")
		stealLeafApply.SetNamespace(ns)
		stealLeafApply.SetName(tunnel.Name)
		if err := direct.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(stealLeafApply), client.FieldOwner("foreign-status-writer"), client.ForceOwnership); err != nil {
			t.Fatalf("steal configVersion.remote=%d leaf ownership: %v", val, err)
		}
	}
	statusApplies.Store(0)
	if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hostnames, listeners); err != nil {
		t.Fatalf("reclaim leaf patchTunnelGatewayData: %v", err)
	}
	if got := statusApplies.Load(); got != 1 {
		t.Fatalf("reclaim leaf patchTunnelGatewayData status applies = %d, want 1", got)
	}
	statusApplies.Store(0)
	if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hostnames, listeners); err != nil {
		t.Fatalf("post-reclaim patchTunnelGatewayData: %v", err)
	}
	if got := statusApplies.Load(); got != 0 {
		t.Fatalf("post-reclaim patchTunnelGatewayData status applies = %d, want 0", got)
	}
}

type countingSSAStatusClient struct {
	client.Client
	applies *atomic.Int64
}

func (c *countingSSAStatusClient) Status() client.SubResourceWriter {
	return &countingSSASubResourceWriter{SubResourceWriter: c.Client.Status(), applies: c.applies}
}

type countingSSASubResourceWriter struct {
	client.SubResourceWriter
	applies *atomic.Int64
}

func (w *countingSSASubResourceWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	w.applies.Add(1)
	return w.SubResourceWriter.Apply(ctx, obj, opts...)
}

// Regression test for Finding #7: after a generation bump, admission writes
// Programmed=Unknown with a newer LastTransitionTime while statuses.Gateway
// still holds the previous generation's Programmed=True timestamp; a full
// patchGatewayStatus writing Programmed=True MUST keep monotonic timestamps
// on both Gateway-level and listener-level Programmed conditions.
func TestGatewayFullPatchPreservesMonotonicProgrammedTransitionTimeEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-monotonic-programmed"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	host := gatewayv1.Hostname("mono.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "mono-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &host}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}

	t1 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(5 * time.Second)
	t3 := t2.Add(5 * time.Second)
	currentClock := t1

	reconciler := &GatewayReconciler{
		Client:    direct,
		APIReader: direct,
		Scheme:    mgr.GetScheme(),
		Now:       func() time.Time { return currentClock },
	}
	gwClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
	gwCfg := &v1alpha1.GatewayClassConfig{ObjectMeta: metav1.ObjectMeta{Name: "flareway-cfg"}, Spec: v1alpha1.GatewayClassConfigSpec{ConformanceMode: true}}

	// Gen 1 converged at t1 with Programmed=True.
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	_, s1 := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway: gw, GatewayClass: gwClass, GatewayClassConfig: gwCfg,
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&s1.Gateway, gw)
	reconciler.setCloudflareProgrammedStatus(&s1.Gateway, gw, true, "ok", nil)
	if err := reconciler.patchGatewayStatus(ctx, client.ObjectKeyFromObject(gw), s1.Gateway); err != nil {
		t.Fatalf("seed gen1 Programmed=True: %v", err)
	}

	// Gen 2 bump + snapshot captured BEFORE admission updates current to Unknown(t2).
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	newHost := gatewayv1.Hostname("mono2.example.com")
	gw.Spec.Listeners[0].Hostname = &newHost
	if err := direct.Update(ctx, gw); err != nil {
		t.Fatalf("bump gen2: %v", err)
	}
	reconcileStartGen2 := gw.DeepCopy()

	// Concurrent admission pass on gen 2 records Unknown at t2 > t1.
	currentClock = t2
	_, admStatuses := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway: reconcileStartGen2, GatewayClass: gwClass, GatewayClassConfig: gwCfg,
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&admStatuses.Gateway, reconcileStartGen2)
	if err := reconciler.patchGatewayAdmissionStatus(ctx, client.ObjectKeyFromObject(gw), admStatuses.Gateway); err != nil {
		t.Fatalf("admission Unknown at t2: %v", err)
	}

	// Now our pass converges at t3 > t2 using reconcileStartGen2 (whose status still carries True at t1!).
	// setCloudflareProgrammedStatus calls meta.SetStatusCondition(True) onto True(t1), leaving t1 on desired.
	currentClock = t3
	_, convStatuses := gatewayapi.Translate(gatewayapi.Inputs{
		Gateway: reconcileStartGen2, GatewayClass: gwClass, GatewayClassConfig: gwCfg,
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}},
	})
	reconciler.prepareGatewayStatus(&convStatuses.Gateway, reconcileStartGen2)
	reconciler.setCloudflareProgrammedStatus(&convStatuses.Gateway, reconcileStartGen2, true, "ok", nil)
	if err := reconciler.patchGatewayStatus(ctx, client.ObjectKeyFromObject(gw), convStatuses.Gateway); err != nil {
		t.Fatalf("full patchGatewayStatus at t3: %v", err)
	}

	var after gatewayv1.Gateway
	if err := direct.Get(ctx, client.ObjectKeyFromObject(gw), &after); err != nil {
		t.Fatal(err)
	}
	prog := meta.FindStatusCondition(after.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionTrue {
		t.Fatalf("Gateway Programmed = %#v, want True", prog)
	}
	if prog.LastTransitionTime.Time.Before(t2) {
		t.Fatalf("Gateway Programmed.LastTransitionTime moved backward: got %v, live Unknown was %v", prog.LastTransitionTime.Time, t2)
	}
	lprog := meta.FindStatusCondition(after.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if lprog == nil || lprog.Status != metav1.ConditionTrue {
		t.Fatalf("Listener Programmed = %#v, want True", lprog)
	}
	if lprog.LastTransitionTime.Time.Before(t2) {
		t.Fatalf("Listener Programmed.LastTransitionTime moved backward: got %v, live Unknown was %v", lprog.LastTransitionTime.Time, t2)
	}
}

// Envtest regression tests for P2 Blocker #2: real kube-apiserver omits
// empty associative lists from FieldsV1. Removing the last hostname, last
// listener, or both MUST apply once to clear etcd and then send 0 applies on
// subsequent unchanged passes.
func TestPatchTunnelGatewayDataEmptyListsZeroSteadyAppliesEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-ssa-empty-lists"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
	}
	if err := direct.Create(ctx, gc); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create gatewayclass: %v", err)
	}
	gwHost := gatewayv1.Hostname("edge.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "edge",
			}},
			Listeners: []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "acct"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			Configuration:    v1alpha1.CloudflareTunnelConfiguration{Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway},
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	appliedAt := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	identityApply := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"tunnelId":                "tunnel-1",
			"accountId":               "0123456789abcdef0123456789abcdef",
			"ownershipVerified":       true,
			"connectorTokenSecretRef": map[string]any{"name": "token-secret"},
			"gatewayRef":              map[string]any{"name": gw.Name},
			"gatewayUid":              string(gw.UID),
		},
	}}
	identityApply.SetAPIVersion(v1alpha1.GroupVersion.String())
	identityApply.SetKind("CloudflareTunnel")
	identityApply.SetNamespace(ns)
	identityApply.SetName(tunnel.Name)
	if err := direct.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(identityApply), client.FieldOwner("flareway-tunnel"), client.ForceOwnership); err != nil {
		t.Fatalf("seed tunnel identity SSA status: %v", err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
		t.Fatal(err)
	}
	irGW := &ir.Gateway{Key: client.ObjectKeyFromObject(gw), UID: gw.UID}
	if err := (&GatewayReconciler{Client: direct, APIReader: direct, Scheme: mgr.GetScheme()}).patchTunnelGatewayConditions(ctx, irGW, tunnel, appliedAt); err != nil {
		t.Fatalf("patchTunnelGatewayConditions: %v", err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
		t.Fatal(err)
	}

	var statusApplies atomic.Int64
	reconciler := &GatewayReconciler{
		Client:    &countingSSAStatusClient{Client: direct, applies: &statusApplies},
		APIReader: direct,
		Scheme:    mgr.GetScheme(),
	}
	config := v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, DesiredHash: "cfg-h1", Applied: 1, Remote: 1, AppliedAt: &appliedAt}
	oneHost := []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example.com", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1}}
	oneListener := []v1alpha1.CloudflareTunnelListenerStatus{{Name: "http", Exposure: v1alpha1.ExposurePublic}}

	assertApplyThenSkip := func(label string, hosts []v1alpha1.CloudflareTunnelHostnameStatus, lists []v1alpha1.CloudflareTunnelListenerStatus) {
		t.Helper()
		statusApplies.Store(0)
		if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hosts, lists); err != nil {
			t.Fatalf("%s pass 1: %v", label, err)
		}
		if got := statusApplies.Load(); got != 1 {
			t.Fatalf("%s pass 1 status applies = %d, want 1", label, got)
		}
		if err := direct.Get(ctx, client.ObjectKeyFromObject(tunnel), tunnel); err != nil {
			t.Fatal(err)
		}
		if len(tunnel.Status.Hostnames) != len(hosts) || len(tunnel.Status.Listeners) != len(lists) {
			t.Fatalf("%s persisted lengths = (%d,%d), want (%d,%d)", label, len(tunnel.Status.Hostnames), len(tunnel.Status.Listeners), len(hosts), len(lists))
		}
		statusApplies.Store(0)
		if err := reconciler.patchTunnelGatewayData(ctx, irGW, tunnel, config, hosts, lists); err != nil {
			t.Fatalf("%s pass 2: %v", label, err)
		}
		if got := statusApplies.Load(); got != 0 {
			t.Fatalf("%s pass 2 status applies = %d, want 0", label, got)
		}
	}

	// Seed non-empty hostnames + listeners first.
	assertApplyThenSkip("seed non-empty", oneHost, oneListener)
	// (a) Remove last hostname, keep non-empty listeners.
	assertApplyThenSkip("empty hostnames only", nil, oneListener)
	// Restore non-empty hostnames, then (b) remove last listener.
	assertApplyThenSkip("restore hostnames", oneHost, oneListener)
	assertApplyThenSkip("empty listeners only", oneHost, nil)
	// (c) Empty both hostnames and listeners.
	assertApplyThenSkip("empty both lists", nil, nil)
}

// failingStatusClient delegates reads/writes to Client while allowing tests to
// inject a stale object snapshot on Get and fail status subresource writes.
type failingStatusClient struct {
	client.Client
	failStatusWrite atomic.Bool
	failStatusKind  string // optional object kind filter; empty fails all status writes
	staleTunnel     *v1alpha1.CloudflareTunnel
	staleApp        *v1alpha1.AccessApplication
	staleGateway    *gatewayv1.Gateway
}

func (c *failingStatusClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	switch target := obj.(type) {
	case *v1alpha1.CloudflareTunnel:
		if c.staleTunnel != nil && client.ObjectKeyFromObject(c.staleTunnel) == key {
			*target = *c.staleTunnel.DeepCopy()
			return nil
		}
	case *v1alpha1.AccessApplication:
		if c.staleApp != nil && client.ObjectKeyFromObject(c.staleApp) == key {
			*target = *c.staleApp.DeepCopy()
			return nil
		}
	case *gatewayv1.Gateway:
		if c.staleGateway != nil && client.ObjectKeyFromObject(c.staleGateway) == key {
			*target = *c.staleGateway.DeepCopy()
			return nil
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *failingStatusClient) Status() client.SubResourceWriter {
	return &failingStatusWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type failingStatusWriter struct {
	client.SubResourceWriter
	parent *failingStatusClient
}

func (w *failingStatusWriter) shouldFailObj(obj client.Object) bool {
	if !w.parent.failStatusWrite.Load() {
		return false
	}
	if w.parent.failStatusKind == "" {
		return true
	}
	switch obj.(type) {
	case *gatewayv1.Gateway:
		return w.parent.failStatusKind == "Gateway"
	case *v1alpha1.CloudflareTunnel:
		return w.parent.failStatusKind == "CloudflareTunnel"
	case *v1alpha1.AccessApplication:
		return w.parent.failStatusKind == "AccessApplication"
	default:
		return false
	}
}

func (w *failingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if w.shouldFailObj(obj) {
		return fmt.Errorf("injected status Update failure")
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func (w *failingStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if w.shouldFailObj(obj) {
		return fmt.Errorf("injected status Patch failure")
	}
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

func (w *failingStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	if w.parent.failStatusWrite.Load() {
		return fmt.Errorf("injected status Apply failure")
	}
	return w.SubResourceWriter.Apply(ctx, obj, opts...)
}

// Envtest regression test for P2 Blocker #1 (CloudflareTunnel): a demoted
// Gateway-mode External DNS Tunnel whose status write fails MUST keep its
// "demoted" invalidation latch intact so a retry observing a stale converged
// Ready=True cache still verifies Cloudflare and clears the latch only after
// patchOwnedStatus durably succeeds.
func TestDemotedCloudflareTunnelStaysInvalidatedOnStatusWriteFailure(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-demote-tunnel-retry"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cf-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "demote-tunnel-acct"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:            []string{"*"},
				Zones:                []string{"*"},
				Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	gwHost := gatewayv1.Hostname("edge.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: v1alpha1.Group, Kind: "CloudflareTunnel", Name: "edge",
			}},
			Listeners: []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &gwHost}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge", Finalizers: []string{v1alpha1.CloudflareTunnelFinalizer}},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Tunnel:           v1alpha1.CloudflareTunnelRemoteSpec{Name: "edge"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			DNS:              v1alpha1.CloudflareTunnelDNSConfig{Mode: v1alpha1.DNSModeExternal},
			Configuration:    v1alpha1.CloudflareTunnelConfiguration{Mode: v1alpha1.CloudflareTunnelConfigurationModeGateway},
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	tunnelKey := client.ObjectKeyFromObject(tunnel)

	tunnelFake := newFakeTunnelCloudflareFactory()
	tunnelFake.tunnels["tunnel-1"] = RemoteTunnel{
		ID: "tunnel-1", AccountTag: account.Spec.AccountID, Name: "edge",
		Type: flarecloudflare.TunnelTypeCloudflared, ConfigSource: flarecloudflare.TunnelConfigSourceCloudflare, Status: flarecloudflare.TunnelStatusHealthy,
	}
	tunnelFake.tokens["tunnel-1"] = "token-1"

	appliedAt := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	seedApply := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"tunnelId":          "tunnel-1",
			"accountId":         account.Spec.AccountID,
			"ownershipVerified": true,
			"gatewayRef":        map[string]any{"name": gw.Name},
			"gatewayUid":        string(gw.UID),
			"configVersion": map[string]any{
				"desired":     1,
				"desiredHash": "cfg-h1",
				"applied":     1,
				"remote":      1,
				"appliedAt":   appliedAt.Format(time.RFC3339),
			},
			"conditions": []any{map[string]any{
				"type":               v1alpha1.CloudflareTunnelConditionConfigApplied,
				"status":             "True",
				"reason":             "Applied",
				"message":            "ok",
				"observedGeneration": tunnel.Generation,
				"lastTransitionTime": appliedAt.Format(time.RFC3339),
			}},
		},
	}}
	seedApply.SetAPIVersion(v1alpha1.GroupVersion.String())
	seedApply.SetKind("CloudflareTunnel")
	seedApply.SetNamespace(ns)
	seedApply.SetName(tunnel.Name)
	if err := direct.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(seedApply), client.FieldOwner("flareway-gateway"), client.ForceOwnership); err != nil {
		t.Fatalf("seed tunnel gateway status: %v", err)
	}

	latch := freshness.NewLatch()
	faultClient := &failingStatusClient{Client: direct}
	reconciler := &CloudflareTunnelReconciler{
		Client:              faultClient,
		APIReader:           direct,
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           freshness.DefaultPolicy(),
		Invalidator:         latch,
	}

	// Converge once so Ready=True + DNSReady=True are persisted with fresh AppliedAt.
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: tunnelKey}); err != nil {
		t.Fatalf("initial converge reconcile: %v", err)
	}
	var staleReady v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, tunnelKey, &staleReady); err != nil {
		t.Fatal(err)
	}
	if !assertConditionTrueForCurrentGen(staleReady.Status.Conditions, v1alpha1.CloudflareTunnelConditionReady, staleReady.Generation) {
		t.Fatalf("tunnel did not converge Ready=True: %+v", staleReady.Status.Conditions)
	}

	// Demote tunnel via transient remote failure -> status becomes Ready=False and latch holds "demoted".
	tunnelFake.FailNext("GetTunnel", errors.New("boom"))
	latch.Invalidate("CloudflareTunnel", tunnelKey, "force remote check")
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: tunnelKey}); err == nil {
		t.Fatal("expected GetTunnel failure")
	}
	tunnelFake.FailNext("GetTunnel", nil)
	if !latch.IsInvalidated("CloudflareTunnel", tunnelKey) {
		t.Fatal("expected demotion to hold invalidation latch")
	}

	// Inject staleReady on informer cache AND fail status write on recovery pass.
	faultClient.staleTunnel = staleReady.DeepCopy()
	faultClient.failStatusWrite.Store(true)
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: tunnelKey}); err == nil {
		t.Fatal("expected injected status write failure")
	}
	if !latch.IsInvalidated("CloudflareTunnel", tunnelKey) {
		t.Fatal("clearGate released invalidation latch BEFORE patchOwnedStatus persisted")
	}

	// Retry still seeing staleReady with status writes succeeding MUST execute remote verification
	// and only clear the latch after durable persistence.
	faultClient.failStatusWrite.Store(false)
	callsBefore := len(tunnelFake.Calls())
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: tunnelKey}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if len(tunnelFake.Calls()[callsBefore:]) == 0 {
		t.Fatalf("retry skipped Cloudflare verification despite unpersisted recovery")
	}
	if latch.IsInvalidated("CloudflareTunnel", tunnelKey) {
		t.Fatal("invalidation latch stayed set after durable Ready=True persistence")
	}
}

// Envtest regression test for P2 Blocker #1 (AccessApplication): if patchStatus
// fails on recovery, the "demoted" invalidation latch MUST NOT clear before
// durable status persistence.
func TestDemotedAccessApplicationStaysInvalidatedOnStatusWriteFailure(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-demote-app-retry"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cf-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "demote-app-acct"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, nil)

	appFake := newFakeAccessApplicationCloudflare()
	appFake.SetPolicy(flarecloudflare.AccessPolicy{ID: "ext-pol-demote", Name: "ext-pol", Decision: "Allow"})
	app := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app-demote-retry", Finalizers: []string{v1alpha1.AccessApplicationFinalizer}},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			Application: v1alpha1.AccessApplicationSettings{
				Name:            "app-demote-retry",
				SessionDuration: "1h",
			},
			Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
				Type:   v1alpha1.AccessApplicationDestinationWorker,
				Worker: &v1alpha1.AccessWorkerDestinationSpec{WorkerID: "worker-1"},
			}},
			Policies:         []v1alpha1.AccessApplicationPolicyReference{{ExternalRef: &v1alpha1.AccessApplicationPolicyExternalReference{PolicyID: "ext-pol-demote"}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := direct.Create(ctx, app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	appKey := client.ObjectKeyFromObject(app)

	latch := freshness.NewLatch()
	faultClient := &failingStatusClient{Client: mgr.GetClient()}
	reconciler := &AccessApplicationReconciler{
		Client:              faultClient,
		APIReader:           direct,
		Scheme:              mgr.GetScheme(),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return appFake, nil },
		Freshness:           freshness.DefaultPolicy(),
		Invalidator:         latch,
	}
	if err := reconciler.registerFieldIndexers(mgr); err != nil {
		t.Fatalf("register AccessApplication indexers: %v", err)
	}
	startManagerAndWait(t, mgr)
	waitUntilTrue(t, 10*time.Second, "cache observes app and ready account", func() (bool, error) {
		var curApp v1alpha1.AccessApplication
		var curAcc v1alpha1.CloudflareAccount
		if err := mgr.GetClient().Get(ctx, appKey, &curApp); err != nil {
			return false, nil
		}
		if err := mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(account), &curAcc); err != nil {
			return false, nil
		}
		return assertConditionTrueForCurrentGen(curAcc.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted, curAcc.Generation), nil
	})

	// Converge + rebind so Programmed=True and AppliedHash/AppliedAt settle.
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err != nil {
		t.Fatalf("rebind reconcile: %v", err)
	}
	var staleReady v1alpha1.AccessApplication
	if err := direct.Get(ctx, appKey, &staleReady); err != nil {
		t.Fatal(err)
	}
	if !assertConditionTrueForCurrentGen(staleReady.Status.Conditions, accessApplicationConditionProgrammed, staleReady.Generation) {
		t.Fatalf("app did not converge Programmed=True: %+v", staleReady.Status.Conditions)
	}

	// Demote via failing remote error -> status drops Programmed=False and latch holds "demoted".
	appFake.mu.Lock()
	appFake.failures["Update:"+staleReady.Status.ApplicationID] = errors.New("boom")
	remote := appFake.applications[staleReady.Status.ApplicationID]
	remote.Name = "trigger-update"
	appFake.applications[staleReady.Status.ApplicationID] = remote
	appFake.mu.Unlock()
	latch.Invalidate("AccessApplication", appKey, "force remote check")
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err != nil {
		t.Fatalf("demote reconcile returned unexpected error: %v", err)
	}
	appFake.mu.Lock()
	delete(appFake.failures, "Update:"+staleReady.Status.ApplicationID)
	appFake.mu.Unlock()
	if !latch.IsInvalidated("AccessApplication", appKey) {
		t.Fatal("expected AccessApplication demotion to hold invalidation latch")
	}

	// Simulate staleReady on informer cache AND fail status write on recovery attempt.
	faultClient.staleApp = staleReady.DeepCopy()
	faultClient.failStatusWrite.Store(true)
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err == nil {
		t.Fatal("expected injected status Patch failure")
	}
	if !latch.IsInvalidated("AccessApplication", appKey) {
		t.Fatal("clearGate released AccessApplication invalidation latch BEFORE patchStatus persisted")
	}

	// Retry still seeing staleReady with status Patch working MUST run Cloudflare verify & clear after persist.
	faultClient.failStatusWrite.Store(false)
	appFake.mu.Lock()
	callsBefore := len(appFake.calls)
	appFake.mu.Unlock()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: appKey}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	appFake.mu.Lock()
	newCalls := len(appFake.calls) - callsBefore
	appFake.mu.Unlock()
	if newCalls == 0 {
		t.Fatal("retry skipped AccessApplication remote verification despite unpersisted recovery")
	}
	if latch.IsInvalidated("AccessApplication", appKey) {
		t.Fatal("AccessApplication invalidation latch stayed set after durable Programmed=True persistence")
	}
}

// Envtest regression test for P2 Blocker #1 (Gateway CloudflareTunnelConfig):
// if Gateway Programmed=True status patch fails after ConfigApplied=True, the
// "demoted" invalidation latch on CloudflareTunnelConfig MUST remain set and
// VerifiedAt MUST NOT be recorded, so a retry observing stale Programmed=True /
// ConfigApplied=True snapshots still re-verifies GetTunnelConfiguration and
// clears only after Programmed=True durably persists.
func TestDemotedGatewayTunnelConfigStaysInvalidatedOnStatusWriteFailure(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	const ns = "tenant-demote-gw-retry"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cf-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "demote-gw-acct"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "cf-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				UnprotectedHostnames: []string{"*"},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.com"}})

	cfg := &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "demote-gw-cfg"},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: account.Name},
			DNS:        v1alpha1.GatewayClassDNSConfig{Mode: v1alpha1.DNSModeExternal},
		},
	}
	if err := direct.Create(ctx, cfg); err != nil {
		t.Fatalf("create GatewayClassConfig: %v", err)
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "demote-gw-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: v1alpha1.Group, Kind: "GatewayClassConfig", Name: cfg.Name},
		},
	}
	if err := direct.Create(ctx, gc); err != nil {
		t.Fatalf("create GatewayClass: %v", err)
	}
	hostname := gatewayv1.Hostname("demote.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "edge"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners:        []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80, Hostname: &hostname}},
		},
	}
	if err := direct.Create(ctx, gw); err != nil {
		t.Fatalf("create gw: %v", err)
	}
	gwKey := client.ObjectKeyFromObject(gw)

	innerAPI := &tunnelFreshnessGatewayAPI{accountID: account.Spec.AccountID, remoteVersion: 1}
	gwAPI := &failingTunnelConfigCloudflareAPI{tunnelFreshnessGatewayAPI: innerAPI}
	tunnelFake := newFakeTunnelCloudflareFactory()
	snapshots := newFakeSnapshotPublisher()
	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	faultClient := &failingStatusClient{Client: mgr.GetClient(), failStatusKind: "Gateway"}

	gwReconciler := &GatewayReconciler{
		Client:            faultClient,
		APIReader:         direct,
		Scheme:            mgr.GetScheme(),
		Snapshots:         snapshots,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: gatewayCloudflareFactory{api: gwAPI},
		Prober:            &staticGatewayProber{version: 2, ready: true},
		Freshness:         policy,
		Invalidator:       latch,
	}
	if err := gwReconciler.registerFieldIndexers(mgr); err != nil {
		t.Fatalf("register Gateway indexers: %v", err)
	}
	tunnelReconciler := &CloudflareTunnelReconciler{
		Client:              direct,
		APIReader:           direct,
		Scheme:              mgr.GetScheme(),
		NewCloudflareClient: tunnelFake.Client,
		Freshness:           policy,
		Invalidator:         latch,
	}
	if err := (&GatewayClassReconciler{Client: direct, Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup GatewayClass: %v", err)
	}
	startManagerAndWait(t, mgr)
	waitUntilTrue(t, 10*time.Second, "GatewayClass accepted and objects cached", func() (bool, error) {
		var curGC gatewayv1.GatewayClass
		if err := mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(gc), &curGC); err != nil {
			return false, nil
		}
		var curCfg v1alpha1.GatewayClassConfig
		if err := mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(cfg), &curCfg); err != nil {
			return false, nil
		}
		var curGW gatewayv1.Gateway
		if err := mgr.GetClient().Get(ctx, gwKey, &curGW); err != nil {
			return false, nil
		}
		var curAcc v1alpha1.CloudflareAccount
		if err := mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(account), &curAcc); err != nil {
			return false, nil
		}
		return assertConditionTrueForCurrentGen(curGC.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted), curGC.Generation) &&
			assertConditionTrueForCurrentGen(curAcc.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted, curAcc.Generation), nil
	})

	// Run Gateway + Tunnel reconciles until TunnelID exists, create Ready Pod + ACK snapshot, then converge both.
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
		t.Fatalf("bootstrap gw reconcile: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "tunnel created in etcd", func() (bool, error) {
		var curT v1alpha1.CloudflareTunnel
		return direct.Get(ctx, gwKey, &curT) == nil, nil
	})
	for range 3 {
		if _, err := tunnelReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
			t.Fatalf("bootstrap tunnel reconcile: %v", err)
		}
	}
	var debugT v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, gwKey, &debugT); err != nil {
		t.Fatalf("get tunnel after bootstrap: %v", err)
	}
	if debugT.Status.TunnelID == "" || debugT.Status.ConnectorTokenSecretRef == nil {
		t.Fatalf("bootstrap tunnel did not populate TunnelID/secretRef: %+v", debugT.Status)
	}
	waitUntilTrue(t, 10*time.Second, "cache sees tunnel TunnelID", func() (bool, error) {
		var curT v1alpha1.CloudflareTunnel
		if err := mgr.GetClient().Get(ctx, gwKey, &curT); err != nil {
			return false, nil
		}
		return curT.Status.TunnelID != "" && curT.Status.ConnectorTokenSecretRef != nil, nil
	})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      "dataplane-0",
			UID:       types.UID("pod-uid-demote-gw"),
			Labels:    map[string]string{dataplane.StandardGatewayLabelKey: dataplane.StandardGatewayLabelValue(gw.Name)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "example.invalid/envoy"}}},
	}
	if err := direct.Create(ctx, pod); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	pod.Status.PodIP = "10.0.0.5"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
	waitUntilTrue(t, 10*time.Second, "cache sees Ready pod", func() (bool, error) {
		var curPod corev1.Pod
		if err := mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(pod), &curPod); err != nil {
			return false, nil
		}
		return curPod.Status.PodIP == "10.0.0.5", nil
	})
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
		t.Fatalf("publish snapshot gw reconcile: %v", err)
	}
	if err := snapshots.ACK(gwKey.String()); err != nil {
		t.Fatalf("ack snapshot: %v", err)
	}
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
		t.Fatalf("converge gw reconcile: %v", err)
	}

	var staleGW gatewayv1.Gateway
	var staleTunnel v1alpha1.CloudflareTunnel
	if err := direct.Get(ctx, gwKey, &staleGW); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, gwKey, &staleTunnel); err != nil {
		t.Fatal(err)
	}
	if !assertConditionTrueForCurrentGen(staleGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), staleGW.Generation) ||
		!assertConditionTrueForCurrentGen(staleTunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionConfigApplied, staleTunnel.Generation) {
		t.Fatalf("fixture not converged: gw=%+v tunnel=%+v", staleGW.Status.Conditions, staleTunnel.Status.Conditions)
	}

	// Demote tunnel config gate via remote failure -> ConfigApplied=False and latch holds "demoted".
	gwAPI.failGetTunnel.Store(true)
	latch.Invalidate("CloudflareTunnelConfig", gwKey, "force remote check")
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err == nil {
		t.Fatal("expected GetTunnel failure")
	}
	gwAPI.failGetTunnel.Store(false)
	if !latch.IsInvalidated("CloudflareTunnelConfig", gwKey) {
		t.Fatal("expected Gateway config demotion to hold invalidation latch")
	}

	// Simulate stale converged snapshots + fail Gateway Programmed=True patch.
	faultClient.staleGateway = staleGW.DeepCopy()
	faultClient.staleTunnel = staleTunnel.DeepCopy()
	faultClient.failStatusWrite.Store(true)
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err == nil {
		t.Fatal("expected injected Gateway status Patch failure")
	}
	if !latch.IsInvalidated("CloudflareTunnelConfig", gwKey) {
		t.Fatal("clearGate released CloudflareTunnelConfig invalidation latch BEFORE Gateway Programmed=True persisted")
	}
	if _, ok := latch.VerifiedAt("CloudflareTunnelConfig", gwKey, staleTunnel.Status.ConfigVersion.DesiredHash); ok {
		t.Fatal("MarkVerified recorded CloudflareTunnelConfig verify BEFORE Gateway Programmed=True persisted")
	}

	// Retry still seeing stale converged snapshots with status Patch working MUST re-verify
	// GetTunnelConfiguration and clear/MarkVerified only after durable Programmed=True persistence.
	faultClient.failStatusWrite.Store(false)
	callsBefore := len(innerAPI.calls)
	if _, err := gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
		t.Fatalf("retry gw reconcile: %v", err)
	}
	if !slices.Contains(innerAPI.calls[callsBefore:], "GetTunnelConfiguration") {
		t.Fatalf("retry skipped GetTunnelConfiguration despite unpersisted Programmed=True; calls=%v", innerAPI.calls[callsBefore:])
	}
	if latch.IsInvalidated("CloudflareTunnelConfig", gwKey) {
		t.Fatal("CloudflareTunnelConfig invalidation latch stayed set after durable Programmed=True persistence")
	}
}
