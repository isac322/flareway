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
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	idpFake := &identityProviderFakeAPI{providers: map[string]flarecloudflare.IdentityProvider{}}
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

	// Pre-seeded Accepted CloudflareTunnel for NetworkRoute and HostnameRoute.
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "route-tunnel"},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef:       corev1.LocalObjectReference{Name: accountName},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	if err := direct.Create(ctx, tunnel); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	tunnel.Status.TunnelID = "tunnel-1"
	tunnel.Status.OwnershipVerified = true
	tunnel.Status.Conditions = []metav1.Condition{{
		Type: v1alpha1.CloudflareTunnelConditionAccepted, Status: metav1.ConditionTrue,
		Reason: "Accepted", Message: "ready", ObservedGeneration: tunnel.Generation, LastTransitionTime: metav1.Now(),
	}}
	if err := direct.Status().Update(ctx, tunnel); err != nil {
		t.Fatalf("update tunnel status: %v", err)
	}

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
	if len(objects) != 19 {
		t.Fatalf("expected 19 gated CRDs, got %d", len(objects))
	}

	for _, item := range objects {
		if err := direct.Create(ctx, item.obj); err != nil {
			t.Fatalf("create %s: %v", item.kind, err)
		}
	}

	// Step 1: Converge all 19 CRDs.
	waitUntilTrue(t, 20*time.Second, "all 19 gated CRDs converged", func() (bool, error) {
		var pending []string
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectConverged(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond, "Accepted")
			if err != nil {
				return false, err
			}
			if !ok {
				pending = append(pending, item.kind)
			}
		}
		if len(pending) > 0 {
			return false, fmt.Errorf("pending convergence: %v", pending)
		}
		return true, nil
	})

	// Step 2: Simulate active Sweep ConfirmContent on all 10 ConfirmContent CRDs.
	confirmAll10 := func() {
		now := time.Now()
		confirmKind := func(kind string, name string, listed any) {
			if latch.ConfirmContent(kind, types.NamespacedName{Namespace: ns, Name: name}, listed, now) {
				t.Fatalf("unexpected drift during ConfirmContent for %s", kind)
			}
		}
		if items, err := accessFake.ListAccessPolicies(ctx); err == nil && len(items) > 0 {
			confirmKind("AccessPolicy", "pol-1", items[0])
		}
		if items, err := accessFake.ListAccessGroups(ctx, flarecloudflare.AccessGroupListOptions{}); err == nil && len(items) > 0 {
			confirmKind("AccessGroup", "grp-1", items[0])
		}
		if items, err := standaloneFake.ListAccessApplications(ctx, flarecloudflare.AccessScope{}); err == nil && len(items) > 0 {
			confirmKind("AccessStandaloneApplication", "standalone-1", items[0])
		}
		if items, err := infraFake.ListAccessInfrastructureTargets(ctx); err == nil && len(items) > 0 {
			confirmKind("AccessInfrastructureTarget", "infra-1", items[0])
		}
		if items, err := idpFake.ListIdentityProviders(ctx); err == nil && len(items) > 0 {
			confirmKind("IdentityProvider", "idp-1", items[0])
		}
		if items := unrecordedApplicationListing(appFake); len(items) > 0 {
			byID := make(map[string]flarecloudflare.AccessApplication, len(items))
			for _, app := range items {
				byID[app.ID] = app
			}
			confirmKind("AccessApplication", "app-1", flarecloudflare.AccessApplicationListing{Application: items[0], Applications: byID})
		}
		if items, err := privateFake.ListVirtualNetworks(ctx); err == nil && len(items) > 0 {
			confirmKind("VirtualNetwork", "vnet-1", items[0])
		}
		if items, err := privateFake.ListNetworkRoutes(ctx); err == nil && len(items) > 0 {
			confirmKind("NetworkRoute", "nr-1", items[0])
		}
		if items, err := privateFake.ListHostnameRoutes(ctx); err == nil && len(items) > 0 {
			confirmKind("HostnameRoute", "hr-1", items[0])
		}
		if items, err := gatewayFake.ListGatewayRules(ctx); err == nil && len(items) > 0 {
			confirmKind("ZeroTrustGatewayPolicy", "gwpol-1", items[0])
		}
	}
	confirmAll10()

	// Step 3: Inject transient pre-gate failure (CloudflareAccount CredentialsValid=False).
	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionFalse)

	waitUntilTrue(t, 15*time.Second, "all 19 gated CRDs turn False on pre-gate failure", func() (bool, error) {
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectFailed(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	})

	// Even if a sweep pass attempts ConfirmContent right here, Forget must have cleared baselines.
	confirmAll10()

	// Step 4: Restore CloudflareAccount CredentialsValid=True well inside TTL.
	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionTrue)

	// Step 5: ALL 19 CRDs MUST recover immediately (within 15s, far below 60s/300s/1800s TTL).
	waitUntilTrue(t, 15*time.Second, "all 19 gated CRDs recover immediately after dependency restoration", func() (bool, error) {
		for _, item := range objects {
			copyObj := item.obj.DeepCopyObject().(client.Object)
			ok, err := checkObjectConverged(ctx, direct, copyObj, client.ObjectKeyFromObject(item.obj), item.readyCond, "Accepted")
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
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
	markAccountReady(ctx, t, direct, account, []v1alpha1.CloudflareVerifiedZone{{ID: "z1", Name: "example.test"}})

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

	// Part B: ServiceToken recovers immediately after transient failure inside 60s TTL.
	st := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "st-qa2c2"},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: accountName}, Name: "st-qa2c2",
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

	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionFalse)
	waitUntilTrue(t, 10*time.Second, "ServiceToken turns Ready=False", func() (bool, error) {
		var cur v1alpha1.ServiceToken
		return checkObjectFailed(ctx, direct, &cur, client.ObjectKeyFromObject(st), "Ready")
	})

	setAccountCredentialsValid(ctx, t, direct, accountName, metav1.ConditionTrue)
	waitUntilTrue(t, 10*time.Second, "ServiceToken recovers immediately inside 60s TTL", func() (bool, error) {
		var cur v1alpha1.ServiceToken
		return checkObjectConverged(ctx, direct, &cur, client.ObjectKeyFromObject(st), "Ready", "Accepted")
	})
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

// QA-2-REG-1: Steady-state 0 remote reads and 0 status writes for healthy converged
// resources (including active Sweep ConfirmContent).
func TestQA2REG1SteadyStateZeroRemoteReadsAndStatusWritesEnvtest(t *testing.T) {
	_, mgr, direct, _ := startPR2EnvtestManager(t)
	ctx := context.Background()

	latch := freshness.NewLatch()
	policy := freshness.DefaultPolicy()
	store := newFakeAccessResourceCloudflare()
	remote := &recordingAccessAPI{AccessAPI: store}
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

	const ns = "tenant-reg1"
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"tenant": "true"}}}); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	if err := direct.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api-token"}, Data: map[string][]byte{"token": []byte("tok")}}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "reg1-account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: ns, Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
			}},
		},
	}
	if err := direct.Create(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	markAccountReady(ctx, t, direct, account, nil)

	pol := &v1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pol-steady"},
		Spec: v1alpha1.AccessPolicySpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "pol-steady",
			Decision:         v1alpha1.AccessPolicyDecisionAllow,
			Include:          []v1alpha1.AccessRule{{Everyone: &v1alpha1.AccessEveryoneRule{}}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := direct.Create(ctx, pol); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	key := client.ObjectKeyFromObject(pol)
	waitUntilTrue(t, 10*time.Second, "policy converged", func() (bool, error) {
		var cur v1alpha1.AccessPolicy
		return checkObjectConverged(ctx, direct, &cur, key, "Ready", "Accepted")
	})
	// Run one rebind pass so AppliedHash binds the newly assigned PolicyID.
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("rebind reconcile: %v", err)
	}

	var before v1alpha1.AccessPolicy
	if err := direct.Get(ctx, key, &before); err != nil {
		t.Fatalf("get policy: %v", err)
	}
	callsBefore := remote.count()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("steady reconcile: %v", err)
	}
	if remote.count() != callsBefore {
		t.Fatalf("steady-state reconcile issued %d remote calls, want 0", remote.count()-callsBefore)
	}
	var after v1alpha1.AccessPolicy
	if err := direct.Get(ctx, key, &after); err != nil {
		t.Fatalf("get policy after steady reconcile: %v", err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("steady-state reconcile wrote status: RV %s -> %s", before.ResourceVersion, after.ResourceVersion)
	}
}

// QA-2-REG-2: ObserveOnly (Safety Condition 9) is never gated and always reads
// Cloudflare even when Freshness is enabled and status is Observed/Ready=True.
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
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				Hostnames:         []string{"*"},
				Zones:             []string{"*"},
				Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
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

// QA-2-REG-4: Gateway CloudflareTunnelConfig gate closes when ConfigApplied=False
// (RemoteError) and recovers on retry without trusting stale VerifiedAt/AppliedAt,
// while preserving ADR 0004 SSA condition ownership split.
func TestQA2REG4GatewayTunnelConfigGateRecoversAfterRemoteErrorEnvtest(t *testing.T) {
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
