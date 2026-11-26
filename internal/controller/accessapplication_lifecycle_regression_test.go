package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/gatewayapi"
)

func TestAccessApplicationInvalidationClearsRemoteProjection(t *testing.T) {
	now := time.Unix(1, 0)
	r := &AccessApplicationReconciler{Now: func() time.Time { return now }}
	application := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", Generation: 3}, Status: v1alpha1.AccessApplicationStatus{
		Type: v1alpha1.AccessApplicationTypeSelfHosted, OwnershipVerified: true, Domain: "old.example", ZoneID: "zone", Tags: []string{"managed"},
	}}
	status := r.desiredStatus(application, gatewayapi.AccessApplicationCompilation{Accepted: false, Reason: "TargetNotFound"}, "", nil, false)
	if status.Type != "" || status.OwnershipVerified || status.Domain != "" || status.ZoneID != "" || len(status.Tags) != 0 {
		t.Fatalf("deleted remote projection retained: %#v", status)
	}
}

func TestAccessApplicationUnprogrammedConditionsUsePendingReason(t *testing.T) {
	r := &AccessApplicationReconciler{Now: time.Now}
	application := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", Generation: 1}}
	status := r.desiredStatus(application, gatewayapi.AccessApplicationCompilation{Accepted: true, Reason: "Accepted", OriginJWTEnforced: true}, "remote", nil, false)
	programmed := conditionByType(status.Conditions, accessApplicationConditionProgrammed)
	origin := conditionByType(status.Conditions, v1alpha1.AccessApplicationConditionOriginJWTEnforced)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "Pending" {
		t.Fatalf("programmed condition = %#v", programmed)
	}
	if origin == nil || origin.Status != metav1.ConditionFalse || origin.Reason != "Pending" {
		t.Fatalf("origin condition = %#v", origin)
	}
}

func TestAccessApplicationInvalidationClearsProjectionAfterRemoteDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Domain: "old.example", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))}})
	application := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[]}`}}, Spec: v1alpha1.AccessApplicationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete}, Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", Type: v1alpha1.AccessApplicationTypeSelfHosted, OwnershipVerified: true, Domain: "old.example", ZoneID: "zone", Tags: []string{"managed"}, Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "old.example"}}, DataPlanes: []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tunnel", ProtectionDomain: "public"}}}}
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account", Generation: 1}, Spec: v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}}, Grants: []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic}}}}, Status: v1alpha1.CloudflareAccountStatus{Verified: v1alpha1.CloudflareAccountVerifiedStatus{Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "old.example"}}}, Conditions: []metav1.Condition{{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 1}, {Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	credential := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("token")}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}
	clusterNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.AccessApplication{}).WithObjects(application, account, credential, namespace, clusterNamespace).Build()
	var current v1alpha1.AccessApplication
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "app"}, &current); err != nil {
		t.Fatal(err)
	}
	r := &AccessApplicationReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil }, Now: time.Now}
	application = &current
	if _, err := r.reconcileInvalidation(context.Background(), application, rejectedCompilationLoss("target missing", gatewayapi.AccessTargetLossGateway)); err != nil {
		t.Fatal(err)
	}
	var stored v1alpha1.AccessApplication
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "app"}, &stored); err != nil {
		t.Fatal(err)
	}
	if remote.Has("remote-id") {
		t.Fatal("managed remote Access application was not deleted")
	}
	if stored.Status.OwnershipVerified || stored.Status.Type != "" || stored.Status.Domain != "" || stored.Status.ZoneID != "" || len(stored.Status.Tags) != 0 {
		t.Fatalf("remote projection retained: %#v", stored.Status)
	}
	if len(stored.Status.Destinations) == 0 || len(stored.Status.DataPlanes) == 0 {
		t.Fatal("revocation projection was not retained")
	}
}
func TestAccessApplicationDeleteBlocksForMissingPublisherAndRecovers(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	uid := types.UID("recorded")
	now := metav1.NewTime(time.Unix(10, 0))
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", Generation: 1, DeletionTimestamp: &now, Finalizers: []string{v1alpha1.AccessApplicationFinalizer},
			Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"gateway","protectionDomain":"public","hostname":"app.example","baselineVersion":1}]}`}},
		Spec: v1alpha1.AccessApplicationSpec{ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly},
	}
	tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}, Status: v1alpha1.CloudflareTunnelStatus{
		GatewayRef: &corev1.LocalObjectReference{Name: "gateway"}, GatewayUID: uid,
		ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Applied: 2, Desired: 2},
		Hostnames:     []v1alpha1.CloudflareTunnelHostnameStatus{{Hostname: "app.example", ProtectionDomain: "public", AccessApplication: "tenant/app", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 2}},
	}}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.AccessApplication{}, &v1alpha1.CloudflareTunnel{}).WithObjects(application, tunnel).Build()
	r := &AccessApplicationReconciler{Client: kube, Scheme: scheme, Now: func() time.Time { return now.Time }}
	if _, err := r.reconcileDelete(context.Background(), application); err != nil {
		t.Fatal(err)
	}
	var blocked v1alpha1.AccessApplication
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "app"}, &blocked); err != nil {
		t.Fatal(err)
	}
	condition := conditionByType(blocked.Status.Conditions, accessApplicationConditionCleanupBlocked)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "RevocationPublisherUnavailable" {
		t.Fatalf("missing publisher diagnostic = %#v", condition)
	}
	if len(blocked.Finalizers) == 0 {
		t.Fatal("finalizer removed while publisher was unavailable")
	}
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: uid}}
	if err := kube.Create(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	tunnel.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardBlocked
	if err := kube.Status().Update(context.Background(), tunnel); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileDelete(context.Background(), &blocked); err != nil {
		t.Fatal(err)
	}
}

func TestAccessApplicationDeleteConvergesForSettledPrivateBlock(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		exposure        v1alpha1.Exposure
		expectFinalizer bool
	}{
		{name: "private block is acknowledged at the settled version", exposure: v1alpha1.ExposurePrivate, expectFinalizer: false},
		{name: "public block still requires a newer version", exposure: v1alpha1.ExposurePublic, expectFinalizer: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			uid := types.UID("recorded")
			now := metav1.NewTime(time.Unix(10, 0))
			application := &v1alpha1.AccessApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", Generation: 1, DeletionTimestamp: &now, Finalizers: []string{v1alpha1.AccessApplicationFinalizer},
					Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"gateway","protectionDomain":"domain","hostname":"app.internal","baselineVersion":1}]}`}},
				Spec: v1alpha1.AccessApplicationSpec{ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly},
			}
			tunnel := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}, Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gateway"}, GatewayUID: uid,
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Applied: 1, Desired: 1},
				Listeners: []v1alpha1.CloudflareTunnelListenerStatus{{
					Name: "listener", Exposure: testCase.exposure,
					ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: "domain"}},
				}},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.internal", ProtectionDomain: "domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 1,
				}},
			}}
			gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: uid}}
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&v1alpha1.AccessApplication{}, &v1alpha1.CloudflareTunnel{}).
				WithObjects(application, tunnel, gateway).Build()
			r := &AccessApplicationReconciler{Client: kube, Scheme: scheme, Now: func() time.Time { return now.Time }}
			if _, err := r.reconcileDelete(context.Background(), application); err != nil {
				t.Fatal(err)
			}
			var stored v1alpha1.AccessApplication
			err := kube.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "app"}, &stored)
			if testCase.expectFinalizer {
				if err != nil {
					t.Fatalf("get application: %v", err)
				}
				if len(stored.Finalizers) == 0 {
					t.Fatal("public revocation released the finalizer without a newer acknowledged version")
				}
				return
			}
			if err == nil && len(stored.Finalizers) != 0 {
				t.Fatalf("private revocation kept finalizers %v at the settled version", stored.Finalizers)
			}
			if err != nil && !apierrors.IsNotFound(err) {
				t.Fatalf("get application: %v", err)
			}
		})
	}
}
func conditionByType(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func TestAccessApplicationDeletionWithdrawsProgrammedAndRetainsDeniedCleanup(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Unix(10, 0))
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2, DeletionTimestamp: &now, Finalizers: []string{v1alpha1.AccessApplicationFinalizer}},
		Spec:       v1alpha1.AccessApplicationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete},
		Status:     v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", OwnershipVerified: true, Conditions: []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 1, LastTransitionTime: now}}},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec:       v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}}},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: now},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
		}},
	}
	remote := newFakeAccessApplicationCloudflare()
	remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))}})
	kube := accessApplicationTestClientBuilder(scheme).WithStatusSubresource(application).
		WithObjects(application, account,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
	).Build()
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time }, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil }}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	var stored v1alpha1.AccessApplication
	if err := kube.Get(ctx, request.NamespacedName, &stored); err != nil {
		t.Fatal(err)
	}
	programmed := meta.FindStatusCondition(stored.Status.Conditions, "Programmed")
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.ObservedGeneration != stored.Generation {
		t.Fatalf("deletion did not withdraw programmed status: %#v", programmed)
	}
	if stored.Annotations[accessApplicationRevocationAnnotation] == "" {
		t.Fatal("deletion did not persist revocation")
	}
	for range 2 {
		if _, err := r.Reconcile(ctx, request); err == nil {
			t.Fatal("cleanup unexpectedly passed denied authorization")
		}
		if err := kube.Get(ctx, request.NamespacedName, &stored); err != nil {
			t.Fatal(err)
		}
		blocked := meta.FindStatusCondition(stored.Status.Conditions, "CleanupBlocked")
		programmed = meta.FindStatusCondition(stored.Status.Conditions, "Programmed")
		if blocked == nil || blocked.Status != metav1.ConditionTrue || blocked.ObservedGeneration != stored.Generation {
			t.Fatalf("denied cleanup was not reported: %#v", blocked)
		}
		if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.ObservedGeneration != stored.Generation {
			t.Fatalf("blocked deletion reported programmed: %#v", programmed)
		}
		if len(stored.Finalizers) != 1 || stored.Finalizers[0] != v1alpha1.AccessApplicationFinalizer || !remote.Has("remote-id") {
			t.Fatal("denied cleanup lost finalizer or remote application")
		}
		if calls := remote.Calls(); len(calls) != 0 {
			t.Fatalf("denied cleanup made remote calls: %v", calls)
		}
	}
	account.Spec.Grants = []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic}}}
	if err := kube.Update(ctx, account); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
		t.Fatalf("deletion did not finish after grant restoration: %v", err)
	}
	if remote.Has("remote-id") {
		t.Fatal("remote application survived completed deletion")
	}
}

// deniedDeletionWorld is an AccessApplication under deletion whose namespace
// the CloudflareAccount does not grant. factoryCalls counts every attempt to
// construct a Cloudflare client, which happens only after the grant gate and
// the credential Secret read succeed.
type deniedDeletionWorld struct {
	kube         client.Client
	reconciler   *AccessApplicationReconciler
	remote       *fakeAccessApplicationCloudflare
	account      *v1alpha1.CloudflareAccount
	request      ctrl.Request
	factoryCalls *int
}

func newDeniedDeletionWorld(t *testing.T, application *v1alpha1.AccessApplication) deniedDeletionWorld {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Unix(10, 0))
	application.DeletionTimestamp = &now
	application.Finalizers = []string{v1alpha1.AccessApplicationFinalizer}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec:       v1alpha1.CloudflareAccountSpec{AccountID: "0123456789abcdef0123456789abcdef", Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "flareway-system", Key: "token"}}},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: now},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
		}},
	}
	remote := newFakeAccessApplicationCloudflare()
	kube := accessApplicationTestClientBuilder(scheme).WithStatusSubresource(application).
		WithObjects(application, account,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: application.Namespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "flareway-system"}, Data: map[string][]byte{"token": []byte("test-token")}},
	).Build()
	factoryCalls := new(int)
	r := &AccessApplicationReconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time }, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) {
		*factoryCalls++
		return remote, nil
	}}
	return deniedDeletionWorld{kube: kube, reconciler: r, remote: remote, account: account, request: ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)}, factoryCalls: factoryCalls}
}

func (w deniedDeletionWorld) grantAll(t *testing.T) {
	t.Helper()
	w.account.Spec.Grants = []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic}}}
	if err := w.kube.Update(context.Background(), w.account); err != nil {
		t.Fatal(err)
	}
}

func TestAccessApplicationDeletionWithoutRemoteEvidenceSkipsDeniedGrant(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		policy v1alpha1.DeletionPolicy
	}{
		{name: "delete policy", policy: v1alpha1.DeletionPolicyDelete},
		{name: "orphan policy", policy: v1alpha1.DeletionPolicyOrphan},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			world := newDeniedDeletionWorld(t, &v1alpha1.AccessApplication{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 1},
				Spec:       v1alpha1.AccessApplicationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: testCase.policy},
			})
			ctx := context.Background()
			for attempt := range 3 {
				if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
					t.Fatalf("reconcile %d: %v", attempt, err)
				}
				var stored v1alpha1.AccessApplication
				if err := world.kube.Get(ctx, world.request.NamespacedName, &stored); apierrors.IsNotFound(err) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
			var stored v1alpha1.AccessApplication
			if err := world.kube.Get(ctx, world.request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
				t.Fatalf("never-provisioned application kept its finalizer: err=%v finalizers=%v conditions=%v", err, stored.Finalizers, stored.Status.Conditions)
			}
			if *world.factoryCalls != 0 || len(world.remote.Calls()) != 0 {
				t.Fatalf("deletion without remote evidence reached Cloudflare: factory=%d calls=%v", *world.factoryCalls, world.remote.Calls())
			}
		})
	}
}

func TestAccessApplicationDeletionWithRemoteAttemptKeepsGrantGatedRecovery(t *testing.T) {
	ctx := context.Background()
	// The attempt marker without status evidence is the create-then-lost-status
	// window: an owner-tagged remote application exists but status never
	// recorded it. Cleanup must stay grant-gated and recover it by owner tag.
	world := newDeniedDeletionWorld(t, &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 1, Annotations: map[string]string{accessApplicationRemoteAttemptAnnotation: "true"}},
		Spec:       v1alpha1.AccessApplicationSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete},
	})
	ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
	world.remote.Put(flarecloudflare.AccessApplication{ID: "lost-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
	for range 3 {
		_, _ = world.reconciler.Reconcile(ctx, world.request)
	}
	var stored v1alpha1.AccessApplication
	if err := world.kube.Get(ctx, world.request.NamespacedName, &stored); err != nil {
		t.Fatalf("denied cleanup with a remote attempt released the object: %v", err)
	}
	blocked := meta.FindStatusCondition(stored.Status.Conditions, accessApplicationConditionCleanupBlocked)
	if blocked == nil || blocked.Status != metav1.ConditionTrue {
		t.Fatalf("denied cleanup was not reported: %#v", blocked)
	}
	if *world.factoryCalls != 0 || len(world.remote.Calls()) != 0 || !world.remote.Has("lost-id") {
		t.Fatalf("denied cleanup reached Cloudflare: factory=%d calls=%v", *world.factoryCalls, world.remote.Calls())
	}

	world.grantAll(t)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatal(err)
	}
	if err := world.kube.Get(ctx, world.request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
		t.Fatalf("deletion did not finish after grant restoration: %v", err)
	}
	if world.remote.Has("lost-id") {
		t.Fatal("owner-tagged application recorded only by the attempt marker leaked")
	}
}

func TestAccessApplicationUnacknowledgedLatchPreservesStatusDataPlanesAcrossActiveRecovery(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.NewTime(time.Unix(100, 0).UTC())
	oldLatch := `{"claims":[{"tunnel":"gateway","protectionDomain":"old-domain","hostname":"app.example","baselineVersion":1}]}`
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
			Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
			Annotations: map[string]string{accessApplicationRevocationAnnotation: oldLatch},
		},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Type:             v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gateway"},
				SectionName:                new(gatewayv1.SectionName("public")),
			}},
		},
		Status: v1alpha1.AccessApplicationStatus{
			ApplicationID: "remote-id",
			DataPlanes:    []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "gateway", Listener: "public", ProtectionDomain: "old-domain", EnvoyPort: 18081}},
			Destinations:  []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "app.example"}},
		},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{},
				Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				Backends: &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Verified: v1alpha1.CloudflareAccountVerifiedStatus{
				TeamName: "team", AuthDomain: "team.cloudflareaccess.com",
				Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example"}},
			},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, LastTransitionTime: now},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, LastTransitionTime: now},
			},
		},
	}
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
	wildcard := gatewayv1.Hostname("*.example")
	group := gatewayv1.Group(v1alpha1.Group)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "gw-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners:        []gatewayv1.Listener{{Name: "public", Hostname: &wildcard, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
			Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "gateway"}},
		},
	}
	// Tunnel is still Forwarding on old-domain, so the latch must stay unacknowledged.
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"},
		Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		Status: v1alpha1.CloudflareTunnelStatus{
			OwnershipVerified: true, TunnelID: "tunnel-id",
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: "gateway"}, GatewayUID: "gw-uid",
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 1, Applied: 1},
			Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: "app.example", ProtectionDomain: "old-domain", AccessApplication: "tenant/app",
				Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 1,
			}},
		},
	}
	port := gatewayv1.PortNumber(8080)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "tenant", Generation: 1},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: new(gatewayv1.SectionName("public"))}}},
			Hostnames:       []gatewayv1.Hostname{"new.example"},
			Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}}}},
		},
	}
	kube := accessApplicationTestClientBuilder(scheme).
		WithStatusSubresource(application).
		WithObjects(
			application, account, gatewayClass, gateway, tunnel, route,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "tenant"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}},
		).Build()
	remote := newFakeAccessApplicationCloudflare()
	r := &AccessApplicationReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var stored v1alpha1.AccessApplication
	if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
		t.Fatal(err)
	}
	programmed := conditionByType(stored.Status.Conditions, accessApplicationConditionProgrammed)
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "RevocationPending" {
		t.Fatalf("programmed = %#v, want RevocationPending", programmed)
	}
	if len(stored.Status.DataPlanes) != 1 || stored.Status.DataPlanes[0].ProtectionDomain != "old-domain" || stored.Status.DataPlanes[0].EnvoyPort != 18081 {
		t.Fatalf("unacknowledged active recovery overwrote DataPlanes: %#v", stored.Status.DataPlanes)
	}
	if len(stored.Status.Destinations) != 1 || stored.Status.Destinations[0].URI != "app.example" {
		t.Fatalf("unacknowledged active recovery overwrote Destinations: %#v", stored.Status.Destinations)
	}
}

func TestAccessApplicationOrphanRevocationClaimResolvesOnConvergedTunnelUnlessDataPlaneForwarding(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, currentGuard v1alpha1.HostnameGuard, dataPlanes []v1alpha1.AccessApplicationDataPlaneStatus, configVersion v1alpha1.CloudflareTunnelConfigVersion, includeCurrentInHostnames bool, want bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			app := &v1alpha1.AccessApplication{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ws-preview", Namespace: "monitoring",
					Annotations: map[string]string{
						accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"runbear-local","protectionDomain":"orphan-domain","hostname":"ws-old.runbear.io","baselineVersion":0}]}`,
					},
				},
				Status: v1alpha1.AccessApplicationStatus{DataPlanes: dataPlanes},
			}
			hostnames := []v1alpha1.CloudflareTunnelHostnameStatus{}
			if includeCurrentInHostnames {
				hostnames = append(hostnames, v1alpha1.CloudflareTunnelHostnameStatus{
					Hostname: "ws-new.runbear.io", ProtectionDomain: "current-domain",
					AccessApplication: "monitoring/ws-preview", Guard: currentGuard, AppliedVersion: configVersion.Applied,
				})
			}
			tunnel := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "runbear-local", Namespace: "monitoring"},
				Status: v1alpha1.CloudflareTunnelStatus{
					GatewayRef: &corev1.LocalObjectReference{Name: "runbear-local"}, GatewayUID: "gw-uid",
					ConfigVersion: configVersion,
					Hostnames:     hostnames,
				},
			}
			gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "runbear-local", Namespace: "monitoring", UID: "gw-uid"}}
			kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(app, tunnel, gw).Build()
			r := &AccessApplicationReconciler{Client: kube, Scheme: scheme, Now: time.Now}
			got, msg, _, err := r.revocationAcknowledged(ctx, app)
			if err != nil {
				t.Fatalf("revocationAcknowledged error: %v", err)
			}
			if got != want {
				t.Fatalf("revocationAcknowledged = %t (%q), want %t", got, msg, want)
			}
		})
	}

	converged := v1alpha1.CloudflareTunnelConfigVersion{Desired: 1076, Applied: 1076}
	currentDP := []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "runbear-local", Listener: "ws-preview", ProtectionDomain: "current-domain", EnvoyPort: 18127}}
	orphanRecordedDP := []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "runbear-local", Listener: "ws-preview", ProtectionDomain: "orphan-domain", EnvoyPort: 18126}}

	run("orphan claim resolves when current dataplane is Blocked", v1alpha1.HostnameGuardBlocked, currentDP, converged, true, true)
	run("current dataplane still Forwarding stays unacknowledged", v1alpha1.HostnameGuardForwarding, currentDP, converged, true, false)
	run("recorded dataplane absent on unacknowledged latch stays unacknowledged", v1alpha1.HostnameGuardBlocked, orphanRecordedDP, converged, false, false)
	run("unconverged tunnel keeps orphan claim unacknowledged", v1alpha1.HostnameGuardBlocked, currentDP, v1alpha1.CloudflareTunnelConfigVersion{Desired: 1077, Applied: 1076}, true, false)
}

func TestAccessApplicationNoTargetsResolvedReleasesCompletedTombstoneAndRecovers(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.NewTime(time.Unix(100, 0).UTC())
	makeWorld := func() (*v1alpha1.AccessApplication, *v1alpha1.CloudflareTunnel, *fakeAccessApplicationCloudflare, *AccessApplicationReconciler, client.Client) {
		latch := `{"claims":[{"tunnel":"edge","protectionDomain":"preview-domain","hostname":"pr-1.example","baselineVersion":1}]}`
		application := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "preview", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: latch},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true, Type: v1alpha1.AccessApplicationTypeSelfHosted,
				DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "edge", Listener: "preview", ProtectionDomain: "preview-domain", EnvoyPort: 18081}},
				Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "pr-1.example"}},
			},
		}
		account := &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account", Generation: 1},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID:   "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
				Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{}, Hostnames: []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic}}},
			},
			Status: v1alpha1.CloudflareAccountStatus{
				Verified: v1alpha1.CloudflareAccountVerifiedStatus{TeamName: "team", AuthDomain: "team.cloudflareaccess.com", Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example"}}},
				Conditions: []metav1.Condition{
					{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 1},
					{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, ObservedGeneration: 1},
				},
			},
		}
		tunnel := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gateway"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "pr-1.example", ProtectionDomain: "preview-domain",
					AccessApplication: "tenant/preview", Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "gw-uid"}}
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/preview", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(application, tunnel).
			WithObjects(
				application, account, tunnel, gateway,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		return application, tunnel, remote, r, kube
	}

	t.Run("NoTargetsResolved marks controller revocation released, frees tombstones, and restores hold on config invalid", func(t *testing.T) {
		application, tunnel, remote, r, kube := makeWorld()
		invalid := gatewayapi.AccessApplicationCompilation{
			Accepted: false, Reason: "TargetNotFound", Message: "no targetRef or destination resolves to this Gateway", NoTargetsResolved: true,
		}
		if _, err := r.reconcileInvalidation(ctx, application, invalid); err != nil {
			t.Fatalf("reconcileInvalidation: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
			t.Fatal(err)
		}
		if !remote.Has("remote-id") {
			t.Fatal("NoTargetsResolved deleted remote application instead of keeping it for reuse")
		}
		expectedDigest := gatewayapi.AccessRevocationLatchDigest(stored.UID, []gatewayapi.AccessRevocationClaim{{
			Tunnel: "edge", ProtectionDomain: "preview-domain", Hostname: "pr-1.example", BaselineVersion: 1,
		}})
		if stored.Status.Revocation == nil ||
			!stored.Status.Revocation.Acknowledged ||
			!stored.Status.Revocation.TokensRevoked ||
			!stored.Status.Revocation.Released ||
			stored.Status.Revocation.ObservedGeneration != stored.Generation ||
			stored.Status.Revocation.LatchDigest != expectedDigest {
			t.Fatalf("status.revocation = %+v, want Acknowledged=true TokensRevoked=true Released=true Gen=%d Digest=%s", stored.Status.Revocation, stored.Generation, expectedDigest)
		}
		if tombstones := gatewayapi.AccessRevocationTombstones(tunnel, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 0 {
			t.Fatalf("released NoTargetsResolved application kept tombstones: %#v", tombstones)
		}
		// Moving the same object from released back to a configuration error must
		// restore Released=false and reinstate the fail-closed tombstone.
		configErr := gatewayapi.AccessApplicationCompilation{
			Accepted: false, Reason: "Invalid", Message: "invalid pathScope",
		}
		if _, err := r.reconcileInvalidation(ctx, &stored, configErr); err != nil {
			t.Fatalf("reconcileInvalidation (configErr): %v", err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || stored.Status.Revocation.Released || !stored.Status.Revocation.Acknowledged || !stored.Status.Revocation.TokensRevoked {
			t.Fatalf("status.revocation after configErr = %+v, want Released=false", stored.Status.Revocation)
		}
		if tombstones := gatewayapi.AccessRevocationTombstones(tunnel, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 1 {
			t.Fatalf("configuration rejection did not restore tombstone: %#v", tombstones)
		}

		// Releasing again and dropping the tombstone from tunnel status must still
		// acknowledge through controller-owned status without deadlocking.
		if _, err := r.reconcileInvalidation(ctx, &stored, invalid); err != nil {
			t.Fatalf("reconcileInvalidation (re-release): %v", err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
			t.Fatal(err)
		}
		tunnel.Status.Hostnames = nil
		if err := kube.Status().Update(ctx, tunnel); err != nil {
			t.Fatal(err)
		}
		ack, msg, _, err := r.revocationAcknowledged(ctx, &stored)
		if err != nil {
			t.Fatalf("revocationAcknowledged after release: %v", err)
		}
		if !ack {
			t.Fatalf("revocationAcknowledged after tombstone release = false (%q), want true", msg)
		}
	})

	t.Run("configuration error keeps latch unreleased and retains tombstones", func(t *testing.T) {
		application, tunnel, _, r, kube := makeWorld()
		invalid := gatewayapi.AccessApplicationCompilation{
			Accepted: false, Reason: "Invalid", Message: "invalid pathScope",
		}
		if _, err := r.reconcileInvalidation(ctx, application, invalid); err != nil {
			t.Fatalf("reconcileInvalidation: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || !stored.Status.Revocation.TokensRevoked || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation = %+v, want Acknowledged=true TokensRevoked=true Released=false", stored.Status.Revocation)
		}
		if tombstones := gatewayapi.AccessRevocationTombstones(tunnel, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 1 {
			t.Fatalf("configuration rejection dropped tombstone: %#v", tombstones)
		}
	})
}

func TestAccessApplicationFirstLatchOnActiveRecoveryPreservesOldDataPlanes(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.NewTime(time.Unix(100, 0).UTC())
	// Previously programmed on listener "old" serving old.example; now the
	// referenced HTTPRoute moved to listener "new" (new.example) while the AUD
	// handoff Secret is missing, so Reconcile must first latch the old claim and
	// preserve the old DataPlanes/Destinations for tombstone generation.
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 3,
			Finalizers: []string{v1alpha1.AccessApplicationFinalizer},
		},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Type:             v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "moved-route"},
			}},
		},
		Status: v1alpha1.AccessApplicationStatus{
			ApplicationID: "remote-id",
			DataPlanes:    []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "gateway", Listener: "old", ProtectionDomain: "old-domain", EnvoyPort: 18081}},
			Destinations:  []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "old.example"}},
			Conditions:    []metav1.Condition{{Type: accessApplicationConditionProgrammed, Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 2, LastTransitionTime: now}},
		},
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{},
				Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
				Backends: &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Verified: v1alpha1.CloudflareAccountVerifiedStatus{
				TeamName: "team", AuthDomain: "team.cloudflareaccess.com",
				Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example"}},
			},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, LastTransitionTime: now},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, LastTransitionTime: now},
			},
		},
	}
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
	hostOld := gatewayv1.Hostname("old.example")
	hostNew := gatewayv1.Hostname("new.example")
	group := gatewayv1.Group(v1alpha1.Group)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "gw-uid", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "flareway",
			Listeners: []gatewayv1.Listener{
				{Name: "old", Hostname: &hostOld, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "new", Hostname: &hostNew, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "gateway"}},
		},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"},
		Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		Status: v1alpha1.CloudflareTunnelStatus{
			OwnershipVerified: true, TunnelID: "tunnel-id",
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "tunnel-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: "gateway"}, GatewayUID: "gw-uid",
			ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 5, Applied: 5},
			Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: "old.example", ProtectionDomain: "old-domain", AccessApplication: "tenant/app",
				Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 5,
			}},
		},
	}
	port := gatewayv1.PortNumber(8080)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "moved-route", Namespace: "tenant", Generation: 2},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gateway", SectionName: new(gatewayv1.SectionName("new"))}}},
			Hostnames:       []gatewayv1.Hostname{"new.example"},
			Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}}}},
		},
	}
	kube := accessApplicationTestClientBuilder(scheme).
		WithStatusSubresource(application).
		WithObjects(
			application, account, gatewayClass, gateway, tunnel, route,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "tenant"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}},
		).Build()
	remote := newFakeAccessApplicationCloudflare()
	r := &AccessApplicationReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(application)}); err != nil {
		t.Fatalf("first latch Reconcile: %v", err)
	}
	var stored v1alpha1.AccessApplication
	if err := kube.Get(ctx, client.ObjectKeyFromObject(application), &stored); err != nil {
		t.Fatal(err)
	}
	latch, ok := gatewayapi.ParseAccessRevocationLatch(stored.Annotations[accessApplicationRevocationAnnotation])
	if !ok || len(latch.Claims) != 1 || latch.Claims[0].ProtectionDomain != "old-domain" {
		t.Fatalf("first latch = %+v (ok=%t), want old-domain claim", latch, ok)
	}
	if len(stored.Status.DataPlanes) != 1 || stored.Status.DataPlanes[0].ProtectionDomain != "old-domain" || stored.Status.DataPlanes[0].EnvoyPort != 18081 {
		t.Fatalf("first latch overwrote old DataPlanes: %#v", stored.Status.DataPlanes)
	}
	if len(stored.Status.Destinations) != 1 || stored.Status.Destinations[0].URI != "old.example" {
		t.Fatalf("first latch overwrote old Destinations: %#v", stored.Status.Destinations)
	}
}

func TestAccessApplicationApplicationWideTargetAbsenceThroughReconcile(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.NewTime(time.Unix(100, 0).UTC())
	wildcard := gatewayv1.Hostname("*.example")
	liveHost := gatewayv1.Hostname("live.example")
	group := gatewayv1.Group(v1alpha1.Group)
	port := gatewayv1.PortNumber(8080)

	newAccount := func() *v1alpha1.CloudflareAccount {
		return &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID:   "0123456789abcdef0123456789abcdef",
				Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Name: "token", Namespace: "tenant", Key: "token"}},
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector: metav1.LabelSelector{},
					Hostnames:         []string{"*"}, Zones: []string{"*"}, Exposures: []v1alpha1.Exposure{v1alpha1.ExposurePublic},
					Backends: &v1alpha1.CloudflareBackendGrant{Namespaces: v1alpha1.BackendNamespaceSame, Kinds: []v1alpha1.BackendKind{v1alpha1.BackendKindService}},
				}},
			},
			Status: v1alpha1.CloudflareAccountStatus{
				Verified: v1alpha1.CloudflareAccountVerifiedStatus{
					TeamName: "team", AuthDomain: "team.cloudflareaccess.com",
					Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone", Name: "example"}},
				},
				Conditions: []metav1.Condition{
					{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, LastTransitionTime: now},
					{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, LastTransitionTime: now},
				},
			},
		}
	}

	for _, order := range []struct {
		name string
		refs []gatewayv1.LocalPolicyTargetReferenceWithSectionName
	}{
		{
			name: "empty gateway before live gateway",
			refs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-empty"}},
				{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-live"}},
			},
		},
		{
			name: "live gateway before empty gateway",
			refs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-live"}},
				{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-empty"}},
			},
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			app := &v1alpha1.AccessApplication{
				ObjectMeta: metav1.ObjectMeta{
					Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
					Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
					Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun-live","protectionDomain":"live-domain","hostname":"live.example","baselineVersion":1}]}`},
				},
				Spec: v1alpha1.AccessApplicationSpec{
					AccountRef:       corev1.LocalObjectReference{Name: "account"},
					Type:             v1alpha1.AccessApplicationTypeSelfHosted,
					SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
					ManagementPolicy: v1alpha1.ManagementPolicyManaged,
					DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
					TargetRefs:       order.refs,
				},
				Status: v1alpha1.AccessApplicationStatus{
					ApplicationID: "remote-id", OwnershipVerified: true,
					DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun-live", Listener: "web", ProtectionDomain: "live-domain", EnvoyPort: 18082}},
					Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "live.example"}},
				},
			}
			gwClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
			gwEmpty := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-empty", Namespace: "tenant", UID: "gw-empty-uid"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "flareway",
					Listeners:        []gatewayv1.Listener{{Name: "preview", Hostname: &wildcard, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
					Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "tun-empty"}},
				},
			}
			gwLive := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-live", Namespace: "tenant", UID: "gw-live-uid"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "flareway",
					Listeners:        []gatewayv1.Listener{{Name: "web", Hostname: &liveHost, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
					Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "tun-live"}},
				},
			}
			tunEmpty := &v1alpha1.CloudflareTunnel{ObjectMeta: metav1.ObjectMeta{Name: "tun-empty", Namespace: "tenant"}, Spec: v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}}}
			tunLive := &v1alpha1.CloudflareTunnel{
				ObjectMeta: metav1.ObjectMeta{Name: "tun-live", Namespace: "tenant"},
				Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
				Status: v1alpha1.CloudflareTunnelStatus{
					GatewayRef: &corev1.LocalObjectReference{Name: "gw-live"}, GatewayUID: "gw-live-uid",
					ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
					Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
						Hostname: "live.example", ProtectionDomain: "live-domain", AccessApplication: "tenant/app",
						Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
					}},
				},
			}
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "live-route", Namespace: "tenant"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw-live", SectionName: new(gatewayv1.SectionName("web"))}}},
					Hostnames:       []gatewayv1.Hostname{"live.example"},
					Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}}}},
				},
			}
			remote := newFakeAccessApplicationCloudflare()
			remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
			kube := accessApplicationTestClientBuilder(scheme).
				WithStatusSubresource(app).
				WithObjects(
					app, newAccount(), gwClass, gwEmpty, gwLive, tunEmpty, tunLive, route,
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
					&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "tenant"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}},
				).Build()
			r := &AccessApplicationReconciler{
				Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
				NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
			}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			var stored v1alpha1.AccessApplication
			if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
				t.Fatal(err)
			}
			if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
				t.Fatalf("mixed Gateway Released = %+v, want Acknowledged=true Released=false", stored.Status.Revocation)
			}
			if tombstones := gatewayapi.AccessRevocationTombstones(tunLive, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 1 {
				t.Fatalf("mixed Gateway dropped live tunnel tombstone: %#v", tombstones)
			}
		})
	}

	t.Run("deleted sole referenced HTTPRoute releases hold through Reconcile", func(t *testing.T) {
		for _, mode := range []v1alpha1.ManagementPolicy{v1alpha1.ManagementPolicyManaged, v1alpha1.ManagementPolicyObserveOnly} {
			t.Run(string(mode), func(t *testing.T) {
				app := &v1alpha1.AccessApplication{
					ObjectMeta: metav1.ObjectMeta{
						Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
						Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
						Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
					},
					Spec: v1alpha1.AccessApplicationSpec{
						AccountRef:       corev1.LocalObjectReference{Name: "account"},
						Type:             v1alpha1.AccessApplicationTypeSelfHosted,
						SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
						ManagementPolicy: mode,
						DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "deleted-route"},
						}},
					},
					Status: v1alpha1.AccessApplicationStatus{
						ApplicationID: "remote-id", OwnershipVerified: true,
						DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun", Listener: "web", ProtectionDomain: "route-domain", EnvoyPort: 18082}},
						Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "app.example"}},
					},
				}
				tun := &v1alpha1.CloudflareTunnel{
					ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
					Status: v1alpha1.CloudflareTunnelStatus{
						GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
						ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
						Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
							Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
							Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
						}},
					},
				}
				gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
				remote := newFakeAccessApplicationCloudflare()
				remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
				kube := accessApplicationTestClientBuilder(scheme).
					WithStatusSubresource(app).
					WithObjects(
						app, newAccount(), tun, gw,
						&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
						&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
						&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
					).Build()
				r := &AccessApplicationReconciler{
					Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
					NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
				}
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
					t.Fatalf("Reconcile: %v", err)
				}
				var stored v1alpha1.AccessApplication
				if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
					t.Fatal(err)
				}
				wantTokensRevoked := mode != v1alpha1.ManagementPolicyObserveOnly
				if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || !stored.Status.Revocation.Released || stored.Status.Revocation.TokensRevoked != wantTokensRevoked {
					t.Fatalf("status.revocation = %+v, want Acknowledged=true Released=true TokensRevoked=%t", stored.Status.Revocation, wantTokensRevoked)
				}
				if mode == v1alpha1.ManagementPolicyObserveOnly && len(remote.Calls()) != 0 {
					t.Fatalf("ObserveOnly made remote calls: %v", remote.Calls())
				}
				if tombstones := gatewayapi.AccessRevocationTombstones(tun, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 0 {
					t.Fatalf("deleted sole route retained tombstone: %#v", tombstones)
				}
			})
		}
	})

	t.Run("intermediate Desired != Applied rollout preserves Released=true until Forwarding returns", func(t *testing.T) {
		claimDigest := gatewayapi.AccessRevocationLatchDigest("app-uid", []gatewayapi.AccessRevocationClaim{{
			Tunnel: "tun", ProtectionDomain: "route-domain", Hostname: "app.example", BaselineVersion: 1,
		}})
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 3,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "deleted-route"},
				}},
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true,
				Revocation: &v1alpha1.AccessApplicationRevocationStatus{
					LatchDigest: claimDigest, ObservedGeneration: 3, Acknowledged: true, TokensRevoked: true, Released: true,
				},
			},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 3, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile rollout: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || !stored.Status.Revocation.Released {
			t.Fatalf("status.revocation during rollout = %+v, want Acknowledged=true Released=true", stored.Status.Revocation)
		}
		tun.Status.Hostnames[0].Guard = v1alpha1.HostnameGuardForwarding
		if err := kube.Update(ctx, tun); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile forwarding return: %v", err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation after Forwarding return = %+v, want Acknowledged=false Released=false", stored.Status.Revocation)
		}
	})

	t.Run("deleted HTTPRoute with valid declared Destinations keeps remote app and Released=false", func(t *testing.T) {
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "deleted-route"},
				}},
				Destinations: []v1alpha1.AccessApplicationDestinationSpec{{
					Type:       v1alpha1.AccessApplicationDestinationAllWorkers,
					AllWorkers: &v1alpha1.AccessAllWorkersDestinationSpec{},
				}},
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true,
				DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun", Listener: "web", ProtectionDomain: "route-domain", EnvoyPort: 18082}},
				Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationAllWorkers}},
			},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.ApplicationID != "remote-id" {
			t.Fatalf("ApplicationID = %q, want remote-id preserved when declared destination remains", stored.Status.ApplicationID)
		}
		programmed := conditionByType(stored.Status.Conditions, accessApplicationConditionProgrammed)
		if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != "TargetNotFound" {
			t.Fatalf("Programmed = %+v, want False/TargetNotFound for missing HTTPRoute", programmed)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation = %+v, want Acknowledged=true Released=false", stored.Status.Revocation)
		}
		if _, ok := remote.applications["remote-id"]; !ok {
			t.Fatal("remote application was deleted despite remaining declared destination")
		}
	})

	t.Run("forged annotation tokensRevoked=true without Status.Revocation still invokes Revoke", func(t *testing.T) {
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}],"tokensRevoked":true}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "deleted-route"},
				}},
			},
			Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", OwnershipVerified: true},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		revoked := false
		for _, call := range remote.Calls() {
			if call == "Revoke:remote-id" {
				revoked = true
				break
			}
		}
		if !revoked {
			t.Fatalf("Calls() = %v, want Revoke:remote-id even when annotation claims tokensRevoked=true", remote.Calls())
		}
	})

	t.Run("mixed missing Gateway and live Gateway keeps remote app and live tunnel tombstone", func(t *testing.T) {
		group := gatewayv1.Group(v1alpha1.Group)
		liveHost := gatewayv1.Hostname("*.example")
		port := gatewayv1.PortNumber(8080)
		refs := []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-missing"}},
			{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-live"}, SectionName: new(gatewayv1.SectionName("web"))},
		}
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun-live","protectionDomain":"live-domain","hostname":"live.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs:       refs,
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true,
				DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun-live", Listener: "web", ProtectionDomain: "live-domain", EnvoyPort: 18082}},
				Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "live.example"}},
			},
		}
		gwClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
		gwLive := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-live", Namespace: "tenant", UID: "gw-live-uid"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "flareway",
				Listeners:        []gatewayv1.Listener{{Name: "web", Hostname: &liveHost, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
				Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "tun-live"}},
			},
		}
		tunLive := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun-live", Namespace: "tenant"},
			Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw-live"}, GatewayUID: "gw-live-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "live.example", ProtectionDomain: "live-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "live-route", Namespace: "tenant"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw-live", SectionName: new(gatewayv1.SectionName("web"))}}},
				Hostnames:       []gatewayv1.Hostname{"live.example"},
				Rules:           []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port}}}}}},
			},
		}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), gwClass, gwLive, tunLive, route,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "tenant"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.ApplicationID != "remote-id" {
			t.Fatalf("ApplicationID = %q, want remote-id preserved when gw-live still resolves targets", stored.Status.ApplicationID)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation = %+v, want Acknowledged=true Released=false", stored.Status.Revocation)
		}
		if tombstones := gatewayapi.AccessRevocationTombstones(tunLive, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 1 {
			t.Fatalf("mixed gw-missing/gw-live dropped live tunnel tombstone: %#v", tombstones)
		}
	})

	t.Run("concurrent Generation bump during token revocation requeues instead of stamping Released onto new Generation", func(t *testing.T) {
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "deleted-route"},
				}},
			},
			Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", OwnershipVerified: true},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		baseRemote := newFakeAccessApplicationCloudflare()
		baseRemote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		remote := &revokeHookCloudflare{
			fakeAccessApplicationCloudflare: baseRemote,
			onRevoke: func(string) error {
				var current v1alpha1.AccessApplication
				if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
					return err
				}
				current.Generation = 3
				return kube.Update(ctx, &current)
			},
		}
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if res.RequeueAfter == 0 {
			t.Fatalf("result = %+v, want RequeueAfter > 0 when Generation changed during RevokeAccessApplicationTokens", res)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.TokensRevoked || stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation = %+v, want TokensRevoked=true with Acknowledged=false Released=false when Generation changed during RevokeAccessApplicationTokens", stored.Status.Revocation)
		}
	})

	t.Run("mixed missing Gateway and rejected Gateway prefers non-loss rejection regardless of targetRefs order", func(t *testing.T) {
		group := gatewayv1.Group(v1alpha1.Group)
		rejectedHost := gatewayv1.Hostname("*.example")
		orders := []struct {
			name string
			refs []gatewayv1.LocalPolicyTargetReferenceWithSectionName
		}{
			{
				name: "missing first",
				refs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-missing"}},
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-rejected"}},
				},
			},
			{
				name: "rejected first",
				refs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-rejected"}},
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-missing"}},
				},
			},
		}
		for _, order := range orders {
			t.Run(order.name, func(t *testing.T) {
				app := &v1alpha1.AccessApplication{
					ObjectMeta: metav1.ObjectMeta{
						Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
						Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
						Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun-rejected","protectionDomain":"rejected-domain","hostname":"app.example","baselineVersion":1}]}`},
					},
					Spec: v1alpha1.AccessApplicationSpec{
						AccountRef:       corev1.LocalObjectReference{Name: "account"},
						Type:             v1alpha1.AccessApplicationTypeSelfHosted,
						SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
						ManagementPolicy: v1alpha1.ManagementPolicyManaged,
						DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
						TargetRefs:       order.refs,
					},
					Status: v1alpha1.AccessApplicationStatus{
						ApplicationID: "remote-id", OwnershipVerified: true,
						DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun-rejected", Listener: "web", ProtectionDomain: "rejected-domain", EnvoyPort: 18082}},
						Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "app.example"}},
					},
				}
				gwClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "flareway"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName}}
				gwRejected := &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-rejected", Namespace: "tenant", UID: "gw-rejected-uid"},
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "flareway",
						Listeners:        []gatewayv1.Listener{{Name: "web", Hostname: &rejectedHost, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
						Infrastructure:   &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: group, Kind: "CloudflareTunnel", Name: "tun-rejected"}},
					},
				}
				tunRejected := &v1alpha1.CloudflareTunnel{
					ObjectMeta: metav1.ObjectMeta{Name: "tun-rejected", Namespace: "tenant"},
					Spec:       v1alpha1.CloudflareTunnelSpec{AccountRef: corev1.LocalObjectReference{Name: "other-account"}},
					Status: v1alpha1.CloudflareTunnelStatus{
						GatewayRef: &corev1.LocalObjectReference{Name: "gw-rejected"}, GatewayUID: "gw-rejected-uid",
						ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
						Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
							Hostname: "app.example", ProtectionDomain: "rejected-domain", AccessApplication: "tenant/app",
							Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
						}},
					},
				}
				remote := newFakeAccessApplicationCloudflare()
				remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
				kube := accessApplicationTestClientBuilder(scheme).
					WithStatusSubresource(app).
					WithObjects(
						app, newAccount(), gwClass, gwRejected, tunRejected,
						&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
						&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
						&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
					).Build()
				r := &AccessApplicationReconciler{
					Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
					NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
				}
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
					t.Fatalf("Reconcile: %v", err)
				}
				var stored v1alpha1.AccessApplication
				if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
					t.Fatal(err)
				}
				if stored.Status.ApplicationID != "remote-id" {
					t.Fatalf("ApplicationID = %q, want remote-id preserved when another target failed non-loss rejection", stored.Status.ApplicationID)
				}
				if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
					t.Fatalf("status.revocation = %+v, want Acknowledged=true Released=false", stored.Status.Revocation)
				}
				if _, ok := remote.applications["remote-id"]; !ok {
					t.Fatal("remote application deleted despite non-loss RefNotPermitted rejection")
				}
			})
		}
	})

	t.Run("deletion checkpoints Status.Revocation.TokensRevoked before failed Delete so retry skips Revoke", func(t *testing.T) {
		deletedAt := metav1.NewTime(now.Time)
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				DeletionTimestamp: &deletedAt,
				Finalizers:        []string{v1alpha1.AccessApplicationFinalizer},
				Annotations:       map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
			Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", OwnershipVerified: true},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		remote.Fail("Delete:remote-id", errors.New("transient delete error"))
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err == nil {
			t.Fatal("first delete reconcile succeeded, want transient Delete error")
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.TokensRevoked {
			t.Fatalf("status.revocation = %+v, want TokensRevoked=true checkpointed on failed cleanup", stored.Status.Revocation)
		}
		remote.ClearFailure("Delete:remote-id")
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("second delete Reconcile: %v", err)
		}
		revokeCount := 0
		for _, call := range remote.Calls() {
			if call == "Revoke:remote-id" {
				revokeCount++
			}
		}
		if revokeCount != 1 {
			t.Fatalf("Revoke calls = %d (%v), want 1 when TokensRevoked was checkpointed before failed Delete", revokeCount, remote.Calls())
		}
	})

	t.Run("ObserveOnly recovery skips token checkpoint so subsequent Managed switch still revokes", func(t *testing.T) {
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
			Status: v1alpha1.AccessApplicationStatus{ApplicationID: "remote-id", OwnershipVerified: true},
		}
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if err := r.revokeApplicationTokensWithClient(ctx, remote, flarecloudflare.AccessScope{}, app); err != nil {
			t.Fatalf("ObserveOnly revokeApplicationTokensWithClient: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation != nil {
			t.Fatalf("ObserveOnly stamped status.revocation = %+v, want nil", stored.Status.Revocation)
		}
		if latch, ok := gatewayapi.ParseAccessRevocationLatch(stored.Annotations[accessApplicationRevocationAnnotation]); !ok || latch.TokensRevoked {
			t.Fatalf("ObserveOnly marked annotation tokensRevoked=%t, want false", latch.TokensRevoked)
		}
		stored.Spec.ManagementPolicy = v1alpha1.ManagementPolicyManaged
		if err := kube.Update(ctx, &stored); err != nil {
			t.Fatal(err)
		}
		if err := r.revokeApplicationTokensWithClient(ctx, remote, flarecloudflare.AccessScope{}, &stored); err != nil {
			t.Fatalf("Managed revokeApplicationTokensWithClient: %v", err)
		}
		revoked := false
		for _, call := range remote.Calls() {
			if call == "Revoke:remote-id" {
				revoked = true
				break
			}
		}
		if !revoked {
			t.Fatalf("Calls() = %v, want Revoke:remote-id after switching from ObserveOnly to Managed", remote.Calls())
		}
	})

	t.Run("markRevocationTokensRevoked preserves prior ObservedGeneration so old Released=true cannot promote to new generation", func(t *testing.T) {
		claimDigest := gatewayapi.AccessRevocationLatchDigest("app-uid", []gatewayapi.AccessRevocationClaim{{
			Tunnel: "tun", ProtectionDomain: "route-domain", Hostname: "app.example", BaselineVersion: 1,
		}})
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true,
				DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun", Listener: "web", ProtectionDomain: "route-domain", EnvoyPort: 18082}},
				Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "app.example"}},
				Revocation: &v1alpha1.AccessApplicationRevocationStatus{
					LatchDigest: claimDigest, ObservedGeneration: 1, Acknowledged: true, TokensRevoked: false, Released: true,
				},
			},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		kube := accessApplicationTestClientBuilder(scheme).WithStatusSubresource(app).WithObjects(app, tun).Build()
		r := &AccessApplicationReconciler{Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time }}
		if err := r.markRevocationTokensRevoked(ctx, app); err != nil {
			t.Fatalf("markRevocationTokensRevoked: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.TokensRevoked || stored.Status.Revocation.ObservedGeneration != 1 {
			t.Fatalf("status.revocation = %+v, want TokensRevoked=true and ObservedGeneration=1", stored.Status.Revocation)
		}
		if tombstones := gatewayapi.AccessRevocationTombstones(tun, []v1alpha1.AccessApplication{stored}, nil); len(tombstones) != 1 {
			t.Fatalf("tombstones = %#v, want stale Gen 1 release NOT to release Gen 2 hold", tombstones)
		}
	})

	t.Run("missing Gateway alongside unattached HTTPRoute keeps remote app and Released=false", func(t *testing.T) {
		app := &v1alpha1.AccessApplication{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "tenant", UID: "app-uid", Generation: 2,
				Finalizers:  []string{v1alpha1.AccessApplicationFinalizer},
				Annotations: map[string]string{accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"tun","protectionDomain":"route-domain","hostname":"app.example","baselineVersion":1}]}`},
			},
			Spec: v1alpha1.AccessApplicationSpec{
				AccountRef:       corev1.LocalObjectReference{Name: "account"},
				Type:             v1alpha1.AccessApplicationTypeSelfHosted,
				SelfHosted:       &v1alpha1.AccessSelfHostedApplicationSpec{},
				ManagementPolicy: v1alpha1.ManagementPolicyManaged,
				DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "gw-missing"}},
					{LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "HTTPRoute", Name: "unattached-route"}},
				},
			},
			Status: v1alpha1.AccessApplicationStatus{
				ApplicationID: "remote-id", OwnershipVerified: true,
				DataPlanes:   []v1alpha1.AccessApplicationDataPlaneStatus{{Tunnel: "tun", Listener: "web", ProtectionDomain: "route-domain", EnvoyPort: 18082}},
				Destinations: []v1alpha1.AccessApplicationDestinationStatus{{Type: v1alpha1.AccessApplicationDestinationPublic, URI: "app.example"}},
			},
		}
		unattached := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "unattached-route", Namespace: "tenant"},
			Spec: gatewayv1.HTTPRouteSpec{
				Hostnames: []gatewayv1.Hostname{"app.example"},
			},
		}
		tun := &v1alpha1.CloudflareTunnel{
			ObjectMeta: metav1.ObjectMeta{Name: "tun", Namespace: "tenant"},
			Status: v1alpha1.CloudflareTunnelStatus{
				GatewayRef: &corev1.LocalObjectReference{Name: "gw"}, GatewayUID: "gw-uid",
				ConfigVersion: v1alpha1.CloudflareTunnelConfigVersion{Desired: 2, Applied: 2},
				Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
					Hostname: "app.example", ProtectionDomain: "route-domain", AccessApplication: "tenant/app",
					Guard: v1alpha1.HostnameGuardBlocked, AppliedVersion: 2,
				}},
			},
		}
		gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tenant", UID: "gw-uid"}}
		ownerTag := accessDigestTag(accessOwnerTagPrefix, flarecloudflare.OwnerTag("cluster-uid", "tenant", "app", "app-uid"))
		remote := newFakeAccessApplicationCloudflare()
		remote.Put(flarecloudflare.AccessApplication{ID: "remote-id", Name: "tenant/app", Type: flarecloudflare.AccessApplicationTypeSelfHosted, Tags: []string{accessManagedTag, ownerTag}})
		kube := accessApplicationTestClientBuilder(scheme).
			WithStatusSubresource(app).
			WithObjects(
				app, newAccount(), tun, gw, unattached,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("test-token")}},
			).Build()
		r := &AccessApplicationReconciler{
			Client: kube, APIReader: kube, Scheme: scheme, Now: func() time.Time { return now.Time },
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		var stored v1alpha1.AccessApplication
		if err := kube.Get(ctx, client.ObjectKeyFromObject(app), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.ApplicationID != "remote-id" {
			t.Fatalf("ApplicationID = %q, want remote-id preserved when unattached HTTPRoute exists", stored.Status.ApplicationID)
		}
		if stored.Status.Revocation == nil || !stored.Status.Revocation.Acknowledged || stored.Status.Revocation.Released {
			t.Fatalf("status.revocation = %+v, want Acknowledged=true Released=false", stored.Status.Revocation)
		}
		if _, ok := remote.applications["remote-id"]; !ok {
			t.Fatal("remote application deleted despite existing unattached HTTPRoute")
		}
	})
}

type revokeHookCloudflare struct {
	*fakeAccessApplicationCloudflare
	onRevoke func(id string) error
}

func (r *revokeHookCloudflare) RevokeAccessApplicationTokens(ctx context.Context, scope flarecloudflare.AccessScope, id string) error {
	if err := r.fakeAccessApplicationCloudflare.RevokeAccessApplicationTokens(ctx, scope, id); err != nil {
		return err
	}
	if r.onRevoke != nil {
		return r.onRevoke(id)
	}
	return nil
}
