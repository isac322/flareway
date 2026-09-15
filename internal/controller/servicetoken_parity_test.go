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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/test/cfstub"
)

func TestServiceTokenCloudflareScopeParity(t *testing.T) {
	server := cfstub.New(t)
	api := flarecloudflare.New(
		"api-token", "account-1", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	ctx := context.Background()
	accountScope := flarecloudflare.AccessScope{}
	zoneScope := flarecloudflare.AccessScope{ZoneID: "zone-1"}

	accountToken, err := api.CreateServiceToken(ctx, accountScope, flarecloudflare.ServiceTokenInput{Name: "account", Duration: "24h", Enabled: true})
	if err != nil {
		t.Fatalf("create account service token: %v", err)
	}
	zoneToken, err := api.CreateServiceToken(ctx, zoneScope, flarecloudflare.ServiceTokenInput{Name: "zone", Duration: "24h", Enabled: false})
	if err != nil {
		t.Fatalf("create zone service token: %v", err)
	}
	observedZone, err := api.GetServiceToken(ctx, zoneScope, zoneToken.ID)
	if err != nil {
		t.Fatalf("get zone service token: %v", err)
	}
	if observedZone.Enabled {
		t.Fatal("disabled zone service token was enabled")
	}
	updatedZone, err := api.UpdateServiceToken(ctx, zoneScope, zoneToken.ID, flarecloudflare.ServiceTokenInput{Name: "zone", Duration: "48h", Enabled: false})
	if err != nil {
		t.Fatalf("update zone service token: %v", err)
	}
	if updatedZone.Enabled || updatedZone.Duration != "48h" {
		t.Fatalf("updated zone token = %#v", updatedZone)
	}
	if _, err := api.GetServiceToken(ctx, accountScope, accountToken.ID); err != nil {
		t.Fatalf("get account service token: %v", err)
	}
	updatedAccount, err := api.UpdateServiceToken(ctx, accountScope, accountToken.ID, flarecloudflare.ServiceTokenInput{Name: "account", Duration: "48h", Enabled: true})
	if err != nil {
		t.Fatalf("update account service token: %v", err)
	}
	if !updatedAccount.Enabled || updatedAccount.Duration != "48h" {
		t.Fatalf("updated account token has enabled=%t duration=%q", updatedAccount.Enabled, updatedAccount.Duration)
	}
	accountTokens, err := api.ListServiceTokens(ctx, accountScope)
	if err != nil || len(accountTokens) != 1 || accountTokens[0].ID != accountToken.ID {
		t.Fatalf("list account service tokens = %#v, %v", accountTokens, err)
	}
	zoneTokens, err := api.ListServiceTokens(ctx, zoneScope)
	if err != nil || len(zoneTokens) != 1 || zoneTokens[0].ID != zoneToken.ID {
		t.Fatalf("list zone service tokens = %#v, %v", zoneTokens, err)
	}

	original, found := server.State.ServiceTokenCredentials("accounts/account-1", accountToken.ID)
	if !found {
		t.Fatal("account token credentials were not persisted by stub")
	}
	previousExpiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Add(123456789 * time.Nanosecond)
	rotated, err := api.RotateServiceToken(ctx, accountToken.ID, previousExpiresAt)
	if err != nil {
		t.Fatalf("rotate account service token: %v", err)
	}
	credentials, found := server.State.ServiceTokenCredentials("accounts/account-1", accountToken.ID)
	if !found || credentials.ClientSecret != rotated.ClientSecret || credentials.PreviousClientSecret != original.ClientSecret {
		t.Fatalf("rotation credential transition was not preserved; found=%t", found)
	}
	wirePreviousExpiresAt := previousExpiresAt.Format(time.RFC3339)
	if credentials.PreviousClientSecretExpiresAt != wirePreviousExpiresAt {
		t.Fatalf("previous credential expiry = %q, want SDK wire value %q", credentials.PreviousClientSecretExpiresAt, wirePreviousExpiresAt)
	}
	if _, err := api.RefreshServiceToken(ctx, accountToken.ID); err != nil {
		t.Fatalf("refresh account service token: %v", err)
	}
	if err := api.DeleteServiceToken(ctx, zoneScope, zoneToken.ID); err != nil {
		t.Fatalf("delete zone service token: %v", err)
	}
	if err := api.DeleteServiceToken(ctx, accountScope, accountToken.ID); err != nil {
		t.Fatalf("delete account service token: %v", err)
	}

	server.AssertOrder(t,
		`^/accounts/account-1/access/service_tokens$`,
		`^/zones/zone-1/access/service_tokens$`,
		`^/zones/zone-1/access/service_tokens/`,
		`^/zones/zone-1/access/service_tokens/`,
		`^/accounts/account-1/access/service_tokens/.+$`,
		`^/accounts/account-1/access/service_tokens/.+$`,
		`^/accounts/account-1/access/service_tokens`,
		`^/zones/zone-1/access/service_tokens`,
		`^/accounts/account-1/access/service_tokens/.+/rotate$`,
		`^/accounts/account-1/access/service_tokens/.+/refresh$`,
		`^/zones/zone-1/access/service_tokens/.+$`,
		`^/accounts/account-1/access/service_tokens/.+$`,
	)
}

type parityServiceTokenCloudflare struct {
	flarecloudflare.AccessAPI
	now       func() time.Time
	next      int
	tokens    map[string]flarecloudflare.ServiceToken
	secrets   map[string]string
	updates   int
	rotations int
	refreshes int
}

func newParityServiceTokenCloudflare(now func() time.Time) *parityServiceTokenCloudflare {
	return &parityServiceTokenCloudflare{
		now: now, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string),
	}
}

func parityServiceTokenKey(scope flarecloudflare.AccessScope, id string) string {
	if scope.ZoneID == "" {
		return id
	}
	return "zone:" + scope.ZoneID + "/" + id
}

func (f *parityServiceTokenCloudflare) CreateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceTokenSecret, error) {
	f.next++
	id := fmt.Sprintf("token-%d", f.next)
	remote := flarecloudflare.ServiceToken{ID: id, ClientID: "client-" + id, Name: input.Name, Duration: input.Duration, Enabled: input.Enabled, ExpiresAt: f.now().Add(24 * time.Hour)}
	key := parityServiceTokenKey(scope, id)
	f.tokens[key] = remote
	f.secrets[key] = "secret-" + id
	return flarecloudflare.ServiceTokenSecret{ServiceToken: remote, ClientSecret: f.secrets[key]}, nil
}

func (f *parityServiceTokenCloudflare) UpdateServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string, input flarecloudflare.ServiceTokenInput) (flarecloudflare.ServiceToken, error) {
	key := parityServiceTokenKey(scope, id)
	remote, found := f.tokens[key]
	if !found {
		return remote, fmt.Errorf("service token %q not found", id)
	}
	f.updates++
	remote.Name = input.Name
	if input.Duration != "" {
		remote.Duration = input.Duration
	}
	remote.Enabled = input.Enabled
	f.tokens[key] = remote
	return remote, nil
}

func (f *parityServiceTokenCloudflare) GetServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) (flarecloudflare.ServiceToken, error) {
	remote, found := f.tokens[parityServiceTokenKey(scope, id)]
	if !found {
		return remote, fmt.Errorf("service token %q not found", id)
	}
	return remote, nil
}

func (f *parityServiceTokenCloudflare) ListServiceTokens(_ context.Context, scope flarecloudflare.AccessScope) ([]flarecloudflare.ServiceToken, error) {
	result := make([]flarecloudflare.ServiceToken, 0)
	prefix := ""
	if scope.ZoneID != "" {
		prefix = "zone:" + scope.ZoneID + "/"
	}
	for key, remote := range f.tokens {
		if (prefix == "" && !strings.HasPrefix(key, "zone:")) || (prefix != "" && strings.HasPrefix(key, prefix)) {
			result = append(result, remote)
		}
	}
	return result, nil
}

func (f *parityServiceTokenCloudflare) DeleteServiceToken(_ context.Context, scope flarecloudflare.AccessScope, id string) error {
	key := parityServiceTokenKey(scope, id)
	delete(f.tokens, key)
	delete(f.secrets, key)
	return nil
}

func (f *parityServiceTokenCloudflare) RotateServiceToken(_ context.Context, id string, _ time.Time) (flarecloudflare.ServiceTokenSecret, error) {
	remote, found := f.tokens[id]
	if !found {
		return flarecloudflare.ServiceTokenSecret{}, fmt.Errorf("account service token %q not found", id)
	}
	f.rotations++
	secret := fmt.Sprintf("rotated-%d", f.rotations)
	f.secrets[id] = secret
	return flarecloudflare.ServiceTokenSecret{ServiceToken: remote, ClientSecret: secret}, nil
}

func (f *parityServiceTokenCloudflare) RefreshServiceToken(_ context.Context, id string) (flarecloudflare.ServiceToken, error) {
	remote, found := f.tokens[id]
	if !found {
		return remote, fmt.Errorf("account service token %q not found", id)
	}
	f.refreshes++
	remote.ExpiresAt = f.now().Add(24 * time.Hour)
	f.tokens[id] = remote
	return remote, nil
}

func TestServiceTokenReconcilerParity(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := newParityServiceTokenCloudflare(func() time.Time { return clock })
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
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}},
			Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}, Zones: []string{"*"}, PlatformObjects: v1alpha1.GrantPermissionAllowed}},
		},
		Status: v1alpha1.CloudflareAccountStatus{
			Verified: v1alpha1.CloudflareAccountVerifiedStatus{Zones: []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.test"}}},
			Conditions: []metav1.Condition{
				{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
				{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(clock)},
			},
		},
	}
	zoneToken := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-zone", Namespace: "tenant", UID: types.UID("disabled-zone")},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Zone: "example.test", Name: "disabled-zone", Enabled: false, Duration: "24h",
			SecretRef: corev1.LocalObjectReference{Name: "disabled-zone-credentials"}, Rotation: v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.ServiceToken{}).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}},
		account, zoneToken,
	).Build()
	reconciler := &ServiceTokenReconciler{Client: kube, Scheme: scheme, NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil }, Now: func() time.Time { return clock }}
	zoneRequest := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(zoneToken)}
	if _, err := reconciler.Reconcile(ctx, zoneRequest); err != nil {
		t.Fatalf("add finalizer: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, zoneRequest); err != nil {
		t.Fatalf("create disabled zone token: %v", err)
	}
	var currentZone v1alpha1.ServiceToken
	if err := kube.Get(ctx, zoneRequest.NamespacedName, &currentZone); err != nil {
		t.Fatal(err)
	}
	remoteZone, err := api.GetServiceToken(ctx, flarecloudflare.AccessScope{ZoneID: "zone-1"}, currentZone.Status.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if remoteZone.Enabled || currentZone.Status.ObservedEnabled || currentZone.Status.ZoneID != "zone-1" {
		t.Fatalf("disabled zone token drifted: remote=%#v status=%#v", remoteZone, currentZone.Status)
	}
	if _, err := reconciler.Reconcile(ctx, zoneRequest); err != nil {
		t.Fatalf("reconcile converged zone token: %v", err)
	}
	if api.updates != 0 {
		t.Fatalf("converged service token updated %d times", api.updates)
	}

	accountToken := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Name: "account-token", Namespace: "tenant", UID: types.UID("account-token")},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "account-token", Enabled: true, Duration: "24h",
			SecretRef: corev1.LocalObjectReference{Name: "account-token-credentials"}, Rotation: v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	if err := kube.Create(ctx, accountToken); err != nil {
		t.Fatal(err)
	}
	accountRequest := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(accountToken)}
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatal(err)
	}
	var beforeRotation corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "account-token-credentials"}, &beforeRotation); err != nil {
		t.Fatal(err)
	}
	oldClientID := string(beforeRotation.Data[v1alpha1.ServiceTokenClientIDKey])
	oldClientSecret := string(beforeRotation.Data[v1alpha1.ServiceTokenClientSecretKey])
	var currentAccount v1alpha1.ServiceToken
	if err := kube.Get(ctx, accountRequest.NamespacedName, &currentAccount); err != nil {
		t.Fatal(err)
	}
	requestedAt := metav1.NewTime(clock.Add(time.Minute))
	currentAccount.Spec.Rotation.RequestedAt = &requestedAt
	if err := kube.Update(ctx, &currentAccount); err != nil {
		t.Fatal(err)
	}
	clock = requestedAt.Time
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("rotate service token: %v", err)
	}
	var rotatedSecret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "account-token-credentials"}, &rotatedSecret); err != nil {
		t.Fatal(err)
	}
	if string(rotatedSecret.Data[v1alpha1.ServiceTokenPreviousClientIDKey]) != oldClientID || string(rotatedSecret.Data[v1alpha1.ServiceTokenPreviousClientSecretKey]) != oldClientSecret {
		t.Fatal("previous credentials were not preserved under explicit keys")
	}
	if string(rotatedSecret.Data[v1alpha1.ServiceTokenClientSecretKey]) == oldClientSecret {
		t.Fatal("rotation did not replace the current client secret")
	}
	if rotatedSecret.Annotations[v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation] == "" {
		t.Fatal("rotation did not record previous credential expiry")
	}
	var lostRotationStatus v1alpha1.ServiceToken
	if err := kube.Get(ctx, accountRequest.NamespacedName, &lostRotationStatus); err != nil {
		t.Fatal(err)
	}
	lostRotationStatus.Status.ObservedRotationRequest = nil
	if err := kube.Status().Update(ctx, &lostRotationStatus); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("recover applied rotation transition: %v", err)
	}
	if api.rotations != 1 {
		t.Fatalf("rotation request was applied %d times", api.rotations)
	}

	clock = clock.Add(2 * time.Hour)
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("expire previous credentials: %v", err)
	}
	var expiredSecret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "account-token-credentials"}, &expiredSecret); err != nil {
		t.Fatal(err)
	}
	if _, found := expiredSecret.Data[v1alpha1.ServiceTokenPreviousClientSecretKey]; found {
		t.Fatal("expired previous client secret was retained")
	}
	if expiredSecret.Annotations[v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation] != "" {
		t.Fatal("expired previous credential annotation was retained")
	}

	if err := kube.Get(ctx, accountRequest.NamespacedName, &currentAccount); err != nil {
		t.Fatal(err)
	}
	currentAccount.Spec.Rotation.Mode = v1alpha1.ServiceTokenRotationOnExpiry
	if err := kube.Update(ctx, &currentAccount); err != nil {
		t.Fatal(err)
	}
	remoteAccount := api.tokens[currentAccount.Status.TokenID]
	remoteAccount.ExpiresAt = clock.Add(10 * time.Minute)
	api.tokens[currentAccount.Status.TokenID] = remoteAccount
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("refresh expiring token: %v", err)
	}
	if api.refreshes != 1 {
		t.Fatalf("refresh count = %d, want 1", api.refreshes)
	}
	remoteAccount = api.tokens[currentAccount.Status.TokenID]
	remoteAccount.ExpiresAt = clock.Add(10 * time.Minute)
	api.tokens[currentAccount.Status.TokenID] = remoteAccount
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("recover refreshed transition: %v", err)
	}
	if api.refreshes != 1 {
		t.Fatalf("stale read repeated refresh; count=%d", api.refreshes)
	}

	adoptionRequestTime := metav1.NewTime(clock.Add(time.Minute))
	adopted := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: "tenant", UID: types.UID("adopted"), Finalizers: []string{v1alpha1.ServiceTokenFinalizer}},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef: corev1.LocalObjectReference{Name: account.Name}, Name: "adopted", Enabled: true, Duration: "24h", SecretRef: corev1.LocalObjectReference{Name: "adopted-credentials"},
			Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h", RequestedAt: &adoptionRequestTime},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged, ExternalRef: &v1alpha1.ServiceTokenExternalReference{TokenID: "adopted-id"},
			Adoption: v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "flareway/cluster-id/tenant/adopted"}}, DeletionPolicy: v1alpha1.DeletionPolicyDelete,
		},
	}
	api.tokens["adopted-id"] = flarecloudflare.ServiceToken{ID: "adopted-id", ClientID: "adopted-client", Name: "flareway/cluster-id/tenant/adopted", Duration: "24h", Enabled: true, ExpiresAt: clock.Add(24 * time.Hour)}
	if err := kube.Create(ctx, adopted); err != nil {
		t.Fatal(err)
	}
	adoptedSecretController := true
	if err := kube.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant",
			Name:      "adopted-credentials",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(),
				Kind:       "ServiceToken",
				Name:       adopted.Name,
				UID:        adopted.UID,
				Controller: &adoptedSecretController,
			}},
		},
		Data: map[string][]byte{
			v1alpha1.ServiceTokenClientIDKey:     []byte("adopted-client"),
			v1alpha1.ServiceTokenClientSecretKey: []byte("existing-secret"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	rotationsBeforeAdoption := api.rotations
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(adopted)}); err != nil {
		t.Fatalf("adopt service token: %v", err)
	}
	var currentAdopted v1alpha1.ServiceToken
	if err := kube.Get(ctx, client.ObjectKeyFromObject(adopted), &currentAdopted); err != nil {
		t.Fatal(err)
	}
	if api.rotations != rotationsBeforeAdoption || currentAdopted.Status.ObservedRotationRequest == nil || !currentAdopted.Status.OwnershipVerified {
		t.Fatalf("adoption transition rotated or was not recorded: rotations=%d status=%#v", api.rotations, currentAdopted.Status)
	}

	if err := kube.Get(ctx, accountRequest.NamespacedName, &currentAccount); err != nil {
		t.Fatal(err)
	}
	var ownerChangedSecret corev1.Secret
	ownerChangedSecretKey := types.NamespacedName{Namespace: "tenant", Name: "account-token-credentials"}
	if err := kube.Get(ctx, ownerChangedSecretKey, &ownerChangedSecret); err != nil {
		t.Fatal(err)
	}
	foreignController := true
	ownerChangedSecret.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Name:       "foreign-controller",
		UID:        types.UID("foreign-controller"),
		Controller: &foreignController,
	}}
	if err := kube.Update(ctx, &ownerChangedSecret); err != nil {
		t.Fatal(err)
	}
	preservedOwnerChangedSecret := ownerChangedSecret.DeepCopy()
	ownerChangeRotationRequest := metav1.NewTime(clock.Add(2 * time.Minute))
	currentAccount.Spec.Rotation.Mode = v1alpha1.ServiceTokenRotationManual
	currentAccount.Spec.Rotation.RequestedAt = &ownerChangeRotationRequest
	if err := kube.Update(ctx, &currentAccount); err != nil {
		t.Fatal(err)
	}
	clock = ownerChangeRotationRequest.Time
	rotationsBeforeOwnerChange := api.rotations
	if _, err := reconciler.Reconcile(ctx, accountRequest); err != nil {
		t.Fatalf("reject rotation after Secret owner change: %v", err)
	}
	if api.rotations != rotationsBeforeOwnerChange {
		t.Fatalf("rotation proceeded after Secret owner change: before=%d after=%d", rotationsBeforeOwnerChange, api.rotations)
	}
	var preservedAfterConflict corev1.Secret
	if err := kube.Get(ctx, ownerChangedSecretKey, &preservedAfterConflict); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preservedAfterConflict.Data, preservedOwnerChangedSecret.Data) ||
		!reflect.DeepEqual(preservedAfterConflict.Annotations, preservedOwnerChangedSecret.Annotations) ||
		!reflect.DeepEqual(preservedAfterConflict.OwnerReferences, preservedOwnerChangedSecret.OwnerReferences) {
		t.Fatalf("rotation collision modified Secret: before=%#v after=%#v", preservedOwnerChangedSecret, &preservedAfterConflict)
	}
	if err := kube.Get(ctx, accountRequest.NamespacedName, &currentAccount); err != nil {
		t.Fatal(err)
	}
	var accepted *metav1.Condition
	for index := range currentAccount.Status.Conditions {
		if currentAccount.Status.Conditions[index].Type == "Accepted" {
			accepted = &currentAccount.Status.Conditions[index]
			break
		}
	}
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != "Conflict" {
		t.Fatalf("rotation collision status = %#v, want Accepted=False/Conflict", accepted)
	}

	if err := kube.Get(ctx, accountRequest.NamespacedName, &currentAccount); err != nil {
		t.Fatal(err)
	}
	statusJSON, err := json.Marshal(currentAccount.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), oldClientSecret) || strings.Contains(string(statusJSON), string(expiredSecret.Data[v1alpha1.ServiceTokenClientSecretKey])) {
		t.Fatalf("service token status leaked credentials: %s", statusJSON)
	}
}

func TestServiceTokenRejectsOwnerlessSecretBeforeIssuance(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := newParityServiceTokenCloudflare(func() time.Time { return clock })
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
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}},
			Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}, Zones: []string{"*"}, PlatformObjects: v1alpha1.GrantPermissionAllowed}},
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
			Name:       "collision",
			Namespace:  "tenant",
			UID:        types.UID("collision"),
			Finalizers: []string{v1alpha1.ServiceTokenFinalizer},
		},
		Spec: v1alpha1.ServiceTokenSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Name:             "collision",
			Enabled:          true,
			Duration:         "24h",
			SecretRef:        corev1.LocalObjectReference{Name: "collision-credentials"},
			Rotation:         v1alpha1.ServiceTokenRotationSpec{Mode: v1alpha1.ServiceTokenRotationManual, GraceDuration: "1h"},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	collision := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   token.Namespace,
			Name:        token.Spec.SecretRef.Name,
			Annotations: map[string]string{"preserve": "annotation"},
		},
		Data: map[string][]byte{"preserve": []byte("data")},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.ServiceToken{}).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "api-token"}, Data: map[string][]byte{"token": []byte("api-token")}},
		account, token, collision,
	).Build()
	reconciler := &ServiceTokenReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return api, nil },
		Now:                 func() time.Time { return clock },
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(token)}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("reject ownerless Secret collision: %v", err)
	}
	if api.next != 0 || len(api.tokens) != 0 {
		t.Fatalf("remote token was issued before Secret ownership validation: creates=%d tokens=%d", api.next, len(api.tokens))
	}

	var preserved corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(collision), &preserved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preserved.Data, collision.Data) ||
		!reflect.DeepEqual(preserved.Annotations, collision.Annotations) ||
		!reflect.DeepEqual(preserved.OwnerReferences, collision.OwnerReferences) {
		t.Fatalf("Secret collision was modified: before=%#v after=%#v", collision, &preserved)
	}
	var current v1alpha1.ServiceToken
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	var accepted *metav1.Condition
	for index := range current.Status.Conditions {
		if current.Status.Conditions[index].Type == "Accepted" {
			accepted = &current.Status.Conditions[index]
			break
		}
	}
	if accepted == nil || accepted.Status != metav1.ConditionFalse || accepted.Reason != "Conflict" ||
		!strings.Contains(accepted.Message, "not controlled by this ServiceToken") {
		t.Fatalf("ownerless Secret collision status = %#v, want Accepted=False/Conflict", accepted)
	}
}
