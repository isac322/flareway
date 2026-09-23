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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
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

// serviceTokenFakeAPI implements only the service-token surface the reconciler
// uses; missing tokens report a typed Cloudflare 404. Remote state is scoped —
// account tokens key by bare ID, zone tokens by "zone:<zoneID>/<id>" — and IDs
// are monotonic so a deletion never recycles one. The bare counters record
// committed mutations (deletes keeps its original attempt-count semantics);
// calls journals every attempted remote operation in order.
type serviceTokenFakeAPI struct {
	flarecloudflare.AccessAPI
	now     func() time.Time
	next    int
	tokens  map[string]flarecloudflare.ServiceToken
	secrets map[string]string
	calls   []string

	createCalls int
	creates     int
	updates     int
	rotates     int
	refreshes   int
	lists       int
	deletes     int

	getErr    error
	updateErr error
	deleteErr error
	createErr error
	rotateErr error
	listErr   error

	// failCreateAt fails the Nth create call before commit;
	// commitThenFailCreateAt commits the Nth create and then reports an error
	// (a lost create response). createNameOverride rewrites the committed
	// token's name (provider divergence). rejectDuplicateName answers a
	// committed 409 when the requested name already exists in scope.
	failCreateAt           int
	commitThenFailCreateAt int
	createNameOverride     string
	rejectDuplicateName    bool
}

// serviceTokenInScope reports whether a scoped storage key belongs to the
// account endpoint (no ZoneID) or the given zone endpoint.
func serviceTokenInScope(scope flarecloudflare.AccessScope, key string) bool {
	if scope.ZoneID == "" {
		return !strings.HasPrefix(key, "zone:")
	}
	return strings.HasPrefix(key, "zone:"+scope.ZoneID+"/")
}

// mutations counts committed remote mutations; reads are excluded.
func (f *serviceTokenFakeAPI) mutations() int {
	return f.creates + f.updates + f.rotates + f.refreshes + f.deletes
}

func (f *serviceTokenFakeAPI) CreateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	f.createCalls++
	f.calls = append(f.calls, "create:"+input.Name)
	if f.createErr != nil {
		return flarecloudflare.ServiceTokenSecret{}, f.createErr
	}
	if f.failCreateAt > 0 && f.createCalls == f.failCreateAt {
		return flarecloudflare.ServiceTokenSecret{}, fmt.Errorf("injected service token create failure")
	}
	if f.rejectDuplicateName {
		for key, remote := range f.tokens {
			if remote.Name == input.Name && serviceTokenInScope(scope, key) {
				return flarecloudflare.ServiceTokenSecret{}, cloudflareAPIError(http.StatusConflict)
			}
		}
	}
	f.next++
	id := fmt.Sprintf("token-%d", f.next)
	remote := flarecloudflare.ServiceToken{
		ID:        id,
		ClientID:  "client-" + id,
		Name:      input.Name,
		Duration:  input.Duration,
		Enabled:   input.Enabled,
		ExpiresAt: f.now().Add(24 * time.Hour),
	}
	if f.createNameOverride != "" {
		remote.Name = f.createNameOverride
	}
	key := parityServiceTokenKey(scope, id)
	if f.tokens == nil {
		f.tokens = make(map[string]flarecloudflare.ServiceToken)
	}
	if f.secrets == nil {
		f.secrets = make(map[string]string)
	}
	f.tokens[key] = remote
	f.secrets[key] = "secret-" + id
	f.creates++
	if f.commitThenFailCreateAt > 0 && f.createCalls == f.commitThenFailCreateAt {
		return flarecloudflare.ServiceTokenSecret{}, fmt.Errorf("injected service token create response loss")
	}
	return flarecloudflare.ServiceTokenSecret{ServiceToken: remote, ClientSecret: f.secrets[key]}, nil
}

func (f *serviceTokenFakeAPI) GetServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.ServiceToken, error) {
	f.calls = append(f.calls, "get:"+id)
	if f.getErr != nil {
		return flarecloudflare.ServiceToken{}, f.getErr
	}
	remote, found := f.tokens[parityServiceTokenKey(scope, id)]
	if !found {
		return flarecloudflare.ServiceToken{}, cloudflareAPIError(http.StatusNotFound)
	}
	return remote, nil
}

func (f *serviceTokenFakeAPI) ListServiceTokens(_ context.Context, scope flarecloudflare.AccessScope) ([]flarecloudflare.ServiceToken, error) {
	f.calls = append(f.calls, "list")
	f.lists++
	if f.listErr != nil {
		return nil, f.listErr
	}
	result := make([]flarecloudflare.ServiceToken, 0)
	for key, remote := range f.tokens {
		if serviceTokenInScope(scope, key) {
			result = append(result, remote)
		}
	}
	return result, nil
}

func (f *serviceTokenFakeAPI) UpdateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceToken, error) {
	f.calls = append(f.calls, "update:"+id)
	if f.updateErr != nil {
		return flarecloudflare.ServiceToken{}, f.updateErr
	}
	key := parityServiceTokenKey(scope, id)
	remote, found := f.tokens[key]
	if !found {
		return flarecloudflare.ServiceToken{}, cloudflareAPIError(http.StatusNotFound)
	}
	remote.Name = input.Name
	remote.Enabled = input.Enabled
	if input.Duration != "" {
		remote.Duration = input.Duration
	}
	f.tokens[key] = remote
	f.updates++
	return remote, nil
}

func (f *serviceTokenFakeAPI) DeleteServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) error {
	f.calls = append(f.calls, "delete:"+id)
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	key := parityServiceTokenKey(scope, id)
	if _, found := f.tokens[key]; !found {
		return cloudflareAPIError(http.StatusNotFound)
	}
	delete(f.tokens, key)
	delete(f.secrets, key)
	return nil
}

// RotateServiceToken is account-scoped only, like the real API surface: zone
// tokens are unreachable here and report a typed 404.
func (f *serviceTokenFakeAPI) RotateServiceToken(_ context.Context, id string, _ time.Time) (flarecloudflare.ServiceTokenSecret, error) {
	f.calls = append(f.calls, "rotate:"+id)
	if f.rotateErr != nil {
		return flarecloudflare.ServiceTokenSecret{}, f.rotateErr
	}
	remote, found := f.tokens[id]
	if !found {
		return flarecloudflare.ServiceTokenSecret{}, cloudflareAPIError(http.StatusNotFound)
	}
	f.rotates++
	f.secrets[id] = fmt.Sprintf("rotated-%d", f.rotates)
	return flarecloudflare.ServiceTokenSecret{ServiceToken: remote, ClientSecret: f.secrets[id]}, nil
}

func (f *serviceTokenFakeAPI) RefreshServiceToken(_ context.Context, id string) (flarecloudflare.ServiceToken, error) {
	f.calls = append(f.calls, "refresh:"+id)
	remote, found := f.tokens[id]
	if !found {
		return flarecloudflare.ServiceToken{}, cloudflareAPIError(http.StatusNotFound)
	}
	f.refreshes++
	remote.ExpiresAt = f.now().Add(24 * time.Hour)
	f.tokens[id] = remote
	return remote, nil
}

type serviceTokenWorld struct {
	kube       client.Client
	scheme     *runtime.Scheme
	api        *serviceTokenFakeAPI
	clock      time.Time
	reconciler *ServiceTokenReconciler
	account    *v1alpha1.CloudflareAccount
	request    ctrl.Request
}

// restart swaps in a fresh reconciler over the same world — the controller
// restart the recovery tests simulate. A nil client reuses the world client;
// APIReader always reads the authoritative store directly.
func (w *serviceTokenWorld) restart(kubeClient client.Client) {
	if kubeClient == nil {
		kubeClient = w.kube
	}
	w.reconciler = &ServiceTokenReconciler{
		Client:              kubeClient,
		APIReader:           w.kube,
		Scheme:              w.scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return w.api, nil },
		Now:                 func() time.Time { return w.clock },
	}
}

func newServiceTokenWorld(t *testing.T, api *serviceTokenFakeAPI, clock time.Time) *serviceTokenWorld {
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
	token := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "tenant",
			Name:       "token",
			UID:        types.UID("token-uid"),
			Generation: 1,
			Finalizers: []string{v1alpha1.ServiceTokenFinalizer},
		},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Name:             "token",
			Enabled:          true,
			Duration:         "8760h",
			SecretRef:        corev1.LocalObjectReference{Name: "token-credentials"},
			Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.ServiceToken{}).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}},
			account, token,
		).Build()
	world := &serviceTokenWorld{
		kube:    kube,
		scheme:  scheme,
		api:     api,
		clock:   clock,
		account: account,
		request: ctrl.Request{NamespacedName: client.ObjectKeyFromObject(token)},
	}
	world.restart(nil)
	return world
}

func serviceTokenCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}

// cloudflareAPIError builds a Cloudflare API error whose Error() is safe to
// call: apierror.Error.Error dereferences Request and Response.
func cloudflareAPIError(statusCode int) error {
	return &cloudflaresdk.Error{
		StatusCode: statusCode,
		Request:    httptest.NewRequest(http.MethodGet, "https://api.cloudflare.test/client/v4", nil),
		Response:   &http.Response{StatusCode: statusCode},
	}
}

func (w *serviceTokenWorld) issueToken(ctx context.Context, t *testing.T) v1alpha1.ServiceToken {
	t.Helper()
	if _, err := w.reconciler.Reconcile(ctx, w.request); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	var issued v1alpha1.ServiceToken
	if err := w.kube.Get(ctx, w.request.NamespacedName, &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Status.TokenID == "" || !issued.Status.OwnershipVerified {
		t.Fatalf("service token was not issued: %#v", issued.Status)
	}
	if ready := serviceTokenCondition(issued.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("issued service token is not Ready: %#v", issued.Status.Conditions)
	}
	return issued
}

func (w *serviceTokenWorld) resolveTokenID(ctx context.Context, t *testing.T, api flarecloudflare.AccessAPI, name string) (string, error) {
	t.Helper()
	var account v1alpha1.CloudflareAccount
	if err := w.kube.Get(ctx, types.NamespacedName{Name: w.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	return resolveServiceTokenID(ctx, w.kube, "tenant", &account, api,
		v1alpha1.AccessObjectReference{Name: name})
}

// A typed remote 404 revokes acceptance so consumers stop resolving the stale
// token ID, while the recorded identifiers stay for diagnosis. Restoring the
// remote token returns the object to Ready.
func TestServiceTokenRemoteLossRevokesAccepted(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	// The remote Cloudflare service token disappears out of band.
	remote := api.tokens[issued.Status.TokenID]
	delete(api.tokens, issued.Status.TokenID)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile after remote loss unexpectedly succeeded")
	}
	var lost v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &lost); err != nil {
		t.Fatal(err)
	}
	if accepted := serviceTokenCondition(lost.Status.Conditions, "Accepted"); accepted == nil || accepted.Status != metav1.ConditionFalse {
		t.Fatalf("ServiceToken does not report Accepted=False after its remote token vanished: %#v", accepted)
	}
	if ready := serviceTokenCondition(lost.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("ServiceToken does not report Ready=False after its remote token vanished: %#v", ready)
	}
	if lost.Status.TokenID != issued.Status.TokenID || lost.Status.ClientID != issued.Status.ClientID {
		t.Fatalf("remote loss rewrote recorded identifiers: %#v", lost.Status)
	}
	if resolved, resolveErr := world.resolveTokenID(ctx, t, api, lost.Name); resolveErr == nil {
		t.Errorf("Access rule resolution still hands out the deleted service token ID %q to policy compilation", resolved)
	}

	// The remote token reappears; the next reconcile converges back to Ready.
	api.tokens[remote.ID] = remote
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after remote recovery: %v", err)
	}
	var recovered v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &recovered); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(recovered.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("ServiceToken did not return to Ready after the remote token reappeared: %#v", recovered.Status.Conditions)
	}
}

// A transient remote failure keeps the token Accepted and resolvable — the
// remote object may still exist — while Ready reports the error.
func TestServiceTokenTransientRemoteErrorPreservesAccepted(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	api.getErr = fmt.Errorf("cloudflare returned 500 for service token read")
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile during a transient remote error unexpectedly succeeded")
	}
	var degraded v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &degraded); err != nil {
		t.Fatal(err)
	}
	if accepted := serviceTokenCondition(degraded.Status.Conditions, "Accepted"); accepted == nil || accepted.Status != metav1.ConditionTrue {
		t.Fatalf("transient remote error revoked acceptance: %#v", accepted)
	}
	if ready := serviceTokenCondition(degraded.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("transient remote error left no Ready=False marker: %#v", ready)
	}
	if degraded.Status.TokenID != issued.Status.TokenID {
		t.Fatalf("transient remote error rewrote the recorded token ID: %#v", degraded.Status)
	}
	if resolved, resolveErr := world.resolveTokenID(ctx, t, api, degraded.Name); resolveErr != nil || resolved != issued.Status.TokenID {
		t.Errorf("transient remote error blocked resolution of the still-valid token ID: resolved=%q err=%v", resolved, resolveErr)
	}

	api.getErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after the transient error cleared: %v", err)
	}
	var healthy v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &healthy); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(healthy.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("ServiceToken did not return to Ready after the transient error cleared: %#v", healthy.Status.Conditions)
	}
}

// A typed 404 from UpdateServiceToken — the remote token vanished between the
// read and the write — revokes acceptance the same way a failed read does.
func TestServiceTokenUpdateRemoteLossRevokesAccepted(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	// The remote token drifted out of band, so the next reconcile must update it.
	drifted := api.tokens[issued.Status.TokenID]
	drifted.Enabled = false
	api.tokens[issued.Status.TokenID] = drifted
	api.updateErr = cloudflareAPIError(http.StatusNotFound)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile with a failing remote update unexpectedly succeeded")
	}
	var lost v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &lost); err != nil {
		t.Fatal(err)
	}
	if accepted := serviceTokenCondition(lost.Status.Conditions, "Accepted"); accepted == nil || accepted.Status != metav1.ConditionFalse {
		t.Fatalf("ServiceToken does not report Accepted=False after the remote update returned 404: %#v", accepted)
	}
	if ready := serviceTokenCondition(lost.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("ServiceToken does not report Ready=False after the remote update returned 404: %#v", ready)
	}
	if resolved, resolveErr := world.resolveTokenID(ctx, t, api, lost.Name); resolveErr == nil {
		t.Errorf("Access rule resolution still hands out the lost service token ID %q to policy compilation", resolved)
	}

	api.updateErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after the remote update recovered: %v", err)
	}
	var healthy v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &healthy); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(healthy.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("ServiceToken did not return to Ready after the remote update recovered: %#v", healthy.Status.Conditions)
	}
}

// A failing remote deletion keeps the finalizer and reports CleanupBlocked
// instead of leaving the terminating object on its stale Ready=True.
func TestServiceTokenDeletionFailureReportsCleanupBlocked(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	api.deleteErr = fmt.Errorf("cloudflare returned 500 for service token deletion")
	if err := world.kube.Delete(ctx, &issued); err != nil {
		t.Fatal(err)
	}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("finalization unexpectedly succeeded while remote deletion fails")
	}
	var terminating v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &terminating); err != nil {
		t.Fatalf("terminating ServiceToken disappeared despite the failed remote deletion: %v", err)
	}
	if terminating.DeletionTimestamp.IsZero() {
		t.Fatal("ServiceToken is not terminating")
	}
	if api.deletes == 0 {
		t.Fatal("remote deletion was never attempted")
	}
	if !controllerutil.ContainsFinalizer(&terminating, v1alpha1.ServiceTokenFinalizer) {
		t.Fatal("finalizer was removed while the remote deletion still fails")
	}
	blocked := serviceTokenCondition(terminating.Status.Conditions, "CleanupBlocked")
	if blocked == nil || blocked.Status != metav1.ConditionTrue {
		t.Fatalf("terminating ServiceToken does not report CleanupBlocked: %#v", terminating.Status.Conditions)
	}
	if ready := serviceTokenCondition(terminating.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("terminating ServiceToken still reports Ready=True while remote deletion fails: %#v", ready)
	}

	// Once the remote deletion succeeds the finalizer is released.
	api.deleteErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("finalization after the remote deletion recovered: %v", err)
	}
	var gone v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
		t.Fatalf("ServiceToken still exists after successful remote deletion: %v", err)
	}
}
