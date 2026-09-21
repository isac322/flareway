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
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// identityProviderFakeAPI implements only the identity-provider surface the
// reconciler uses; missing providers report a typed Cloudflare 404.
type identityProviderFakeAPI struct {
	flarecloudflare.AccessAPI
	getErr    error
	deleteErr error
	deletes   int
	providers map[string]flarecloudflare.IdentityProvider
}

func (f *identityProviderFakeAPI) CreateIdentityProvider(_ context.Context, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	id := fmt.Sprintf("idp-%d", len(f.providers)+1)
	remote := flarecloudflare.IdentityProvider{ID: id, Name: input.Name, Type: input.Type, Config: input.Config, SCIMConfig: input.SCIMConfig}
	f.providers[id] = remote
	return remote, nil
}

func (f *identityProviderFakeAPI) UpdateIdentityProvider(_ context.Context, id string, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	remote, found := f.providers[id]
	if !found {
		return flarecloudflare.IdentityProvider{}, cloudflareAPIError(http.StatusNotFound)
	}
	remote.Name = input.Name
	remote.Type = input.Type
	remote.Config = input.Config
	remote.SCIMConfig = input.SCIMConfig
	f.providers[id] = remote
	return remote, nil
}

func (f *identityProviderFakeAPI) GetIdentityProvider(_ context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	if f.getErr != nil {
		return flarecloudflare.IdentityProvider{}, f.getErr
	}
	remote, found := f.providers[id]
	if !found {
		return flarecloudflare.IdentityProvider{}, cloudflareAPIError(http.StatusNotFound)
	}
	return remote, nil
}

func (f *identityProviderFakeAPI) ListIdentityProviders(context.Context) ([]flarecloudflare.IdentityProvider, error) {
	result := make([]flarecloudflare.IdentityProvider, 0, len(f.providers))
	for _, remote := range f.providers {
		result = append(result, remote)
	}
	return result, nil
}

func (f *identityProviderFakeAPI) DeleteIdentityProvider(_ context.Context, id string) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.providers, id)
	return nil
}

type identityProviderWorld struct {
	kube       client.Client
	reconciler *IdentityProviderReconciler
	account    *v1alpha1.CloudflareAccount
	request    ctrl.Request
}

func newIdentityProviderWorld(t *testing.T, api *identityProviderFakeAPI, clock time.Time, policy v1alpha1.ManagementPolicy, externalID string) *identityProviderWorld {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				PlatformObjects:   v1alpha1.GrantPermissionAllowed,
				AccessPolicyRefs:  v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(clock)},
			},
		},
	}
	provider := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "tenant",
			Name:       "idp",
			UID:        types.UID("idp-uid"),
			Generation: 1,
			Finalizers: []string{v1alpha1.IdentityProviderFinalizer},
		},
		Spec: v1alpha1.IdentityProviderSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Type:             v1alpha1.IdentityProviderTypeOneTimePIN,
			Name:             "idp",
			ManagementPolicy: policy,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	if externalID != "" {
		provider.Spec.ExternalRef = &v1alpha1.IdentityProviderExternalReference{IDPID: externalID}
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.IdentityProvider{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}},
			account, provider,
		).Build()
	return &identityProviderWorld{
		kube: kube,
		reconciler: &IdentityProviderReconciler{
			Client:              kube,
			Scheme:              scheme,
			NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
			Now:                 func() time.Time { return clock },
		},
		account: account,
		request: ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)},
	}
}

func identityProviderCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}

func (w *identityProviderWorld) createProvider(ctx context.Context, t *testing.T) v1alpha1.IdentityProvider {
	t.Helper()
	if _, err := w.reconciler.Reconcile(ctx, w.request); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	var created v1alpha1.IdentityProvider
	if err := w.kube.Get(ctx, w.request.NamespacedName, &created); err != nil {
		t.Fatal(err)
	}
	if created.Status.IDPID == "" || !created.Status.OwnershipVerified {
		t.Fatalf("identity provider was not created: %#v", created.Status)
	}
	if ready := identityProviderCondition(created.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("created identity provider is not Ready: %#v", created.Status.Conditions)
	}
	return created
}

func (w *identityProviderWorld) resolveIDP(ctx context.Context, t *testing.T, api flarecloudflare.AccessAPI, name string) (string, error) {
	t.Helper()
	var account v1alpha1.CloudflareAccount
	if err := w.kube.Get(ctx, types.NamespacedName{Name: w.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	return resolveIDPID(ctx, w.kube, "tenant", &account, api,
		v1alpha1.AccessObjectReference{Name: name})
}

// A failing remote read on a fresh ObserveOnly object still reports the
// failure on its conditions instead of leaving status empty.
func TestIdentityProviderObserveOnlyRemoteErrorWritesStatus(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &identityProviderFakeAPI{providers: make(map[string]flarecloudflare.IdentityProvider)}
	api.getErr = fmt.Errorf("cloudflare returned 500 for identity provider read")
	world := newIdentityProviderWorld(t, api, clock, v1alpha1.ManagementPolicyObserveOnly, "external-idp")

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("ObserveOnly reconcile unexpectedly succeeded while the remote read fails")
	}
	var current v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	ready := identityProviderCondition(current.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("ObserveOnly IdentityProvider wrote no Ready=False after a remote read failure: %#v", current.Status.Conditions)
	}

	// Once the remote read recovers the observed provider is reported Ready.
	api.getErr = nil
	api.providers["external-idp"] = flarecloudflare.IdentityProvider{ID: "external-idp", Name: "idp", Type: v1alpha1.IdentityProviderTypeOneTimePIN}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("ObserveOnly reconcile after the remote read recovered: %v", err)
	}
	var observed v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &observed); err != nil {
		t.Fatal(err)
	}
	if ready := identityProviderCondition(observed.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("ObserveOnly IdentityProvider did not report Ready after the remote read recovered: %#v", observed.Status.Conditions)
	}
	if observed.Status.IDPID != "external-idp" {
		t.Fatalf("ObserveOnly IdentityProvider did not record the observed remote ID: %#v", observed.Status)
	}
}

// A transient remote failure keeps the provider Accepted and resolvable — the
// remote object may still exist — while Ready reports the error.
func TestIdentityProviderTransientRemoteErrorPreservesAccepted(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &identityProviderFakeAPI{providers: make(map[string]flarecloudflare.IdentityProvider)}
	world := newIdentityProviderWorld(t, api, clock, v1alpha1.ManagementPolicyManaged, "")
	created := world.createProvider(ctx, t)

	api.getErr = fmt.Errorf("cloudflare returned 500 for identity provider read")
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile during a transient remote error unexpectedly succeeded")
	}
	var degraded v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &degraded); err != nil {
		t.Fatal(err)
	}
	if accepted := identityProviderCondition(degraded.Status.Conditions, "Accepted"); accepted == nil || accepted.Status != metav1.ConditionTrue {
		t.Fatalf("transient remote error revoked acceptance: %#v", accepted)
	}
	if ready := identityProviderCondition(degraded.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("transient remote error left no Ready=False marker: %#v", ready)
	}
	if degraded.Status.IDPID != created.Status.IDPID {
		t.Fatalf("transient remote error rewrote the recorded provider ID: %#v", degraded.Status)
	}
	if resolved, resolveErr := world.resolveIDP(ctx, t, api, degraded.Name); resolveErr != nil || resolved != created.Status.IDPID {
		t.Errorf("transient remote error blocked resolution of the still-valid provider ID: resolved=%q err=%v", resolved, resolveErr)
	}

	api.getErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after the transient error cleared: %v", err)
	}
	var healthy v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &healthy); err != nil {
		t.Fatal(err)
	}
	if ready := identityProviderCondition(healthy.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("IdentityProvider did not return to Ready after the transient error cleared: %#v", healthy.Status.Conditions)
	}
}

// A typed remote 404 revokes acceptance so consumers stop resolving the stale
// provider ID, while the recorded identifier stays for diagnosis. Restoring
// the remote provider returns the object to Ready.
func TestIdentityProviderRemoteLossRevokesAccepted(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &identityProviderFakeAPI{providers: make(map[string]flarecloudflare.IdentityProvider)}
	world := newIdentityProviderWorld(t, api, clock, v1alpha1.ManagementPolicyManaged, "")
	created := world.createProvider(ctx, t)

	// The remote Cloudflare identity provider disappears out of band.
	remote := api.providers[created.Status.IDPID]
	delete(api.providers, created.Status.IDPID)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile after remote loss unexpectedly succeeded")
	}
	var lost v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &lost); err != nil {
		t.Fatal(err)
	}
	if accepted := identityProviderCondition(lost.Status.Conditions, "Accepted"); accepted == nil || accepted.Status != metav1.ConditionFalse {
		t.Fatalf("IdentityProvider does not report Accepted=False after its remote provider vanished: %#v", accepted)
	}
	if ready := identityProviderCondition(lost.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("IdentityProvider does not report Ready=False after its remote provider vanished: %#v", ready)
	}
	if lost.Status.IDPID != created.Status.IDPID {
		t.Fatalf("remote loss rewrote the recorded provider ID: %#v", lost.Status)
	}
	if resolved, resolveErr := world.resolveIDP(ctx, t, api, lost.Name); resolveErr == nil {
		t.Errorf("Access rule resolution still hands out the deleted identity provider ID %q to policy compilation", resolved)
	}

	// The remote provider reappears; the next reconcile converges back to Ready.
	api.providers[remote.ID] = remote
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after remote recovery: %v", err)
	}
	var recovered v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &recovered); err != nil {
		t.Fatal(err)
	}
	if ready := identityProviderCondition(recovered.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("IdentityProvider did not return to Ready after the remote provider reappeared: %#v", recovered.Status.Conditions)
	}
}

// A failing remote deletion keeps the finalizer and reports CleanupBlocked
// instead of leaving the terminating object on its stale Ready=True.
func TestIdentityProviderDeletionFailureReportsCleanupBlocked(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &identityProviderFakeAPI{providers: make(map[string]flarecloudflare.IdentityProvider)}
	world := newIdentityProviderWorld(t, api, clock, v1alpha1.ManagementPolicyManaged, "")
	created := world.createProvider(ctx, t)

	api.deleteErr = fmt.Errorf("cloudflare returned 500 for identity provider deletion")
	if err := world.kube.Delete(ctx, &created); err != nil {
		t.Fatal(err)
	}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("finalization unexpectedly succeeded while remote deletion fails")
	}
	var terminating v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &terminating); err != nil {
		t.Fatalf("terminating IdentityProvider disappeared despite the failed remote deletion: %v", err)
	}
	if terminating.DeletionTimestamp.IsZero() {
		t.Fatal("IdentityProvider is not terminating")
	}
	if api.deletes == 0 {
		t.Fatal("remote deletion was never attempted")
	}
	if !controllerutil.ContainsFinalizer(&terminating, v1alpha1.IdentityProviderFinalizer) {
		t.Fatal("finalizer was removed while the remote deletion still fails")
	}
	blocked := identityProviderCondition(terminating.Status.Conditions, "CleanupBlocked")
	if blocked == nil || blocked.Status != metav1.ConditionTrue {
		t.Fatalf("terminating IdentityProvider does not report CleanupBlocked: %#v", terminating.Status.Conditions)
	}
	if ready := identityProviderCondition(terminating.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("terminating IdentityProvider still reports Ready=True while remote deletion fails: %#v", ready)
	}

	// Once the remote deletion succeeds the finalizer is released.
	api.deleteErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("finalization after the remote deletion recovered: %v", err)
	}
	var gone v1alpha1.IdentityProvider
	if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
		t.Fatalf("IdentityProvider still exists after successful remote deletion: %v", err)
	}
}
