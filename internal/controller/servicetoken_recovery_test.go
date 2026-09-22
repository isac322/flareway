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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// serviceTokenFaultClient injects failures at the Secret-write and
// status-patch boundaries so tests can stop the reconciler between durable
// steps. A "credential write" is a Secret write that carries the
// CF-Access-Client-Secret data key; a "journal write" is any other Secret
// write to an object that is not the credential destination. Both are
// detected by content, never by the journal's private name.
type serviceTokenFaultClient struct {
	client.Client
	credentialName string

	secretWrites     int
	credentialWrites int
	journalWrites    int
	statusPatches    int

	failSecretWriteAt     int
	failCredentialWriteAt int
	failJournalWriteAt    int
	commitCredentialAt    int
	failStatusPatchAt     int
}

func serviceTokenSecretCarriesCredential(secret *corev1.Secret) bool {
	return len(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) > 0
}

func (c *serviceTokenFaultClient) failSecretWrite(secret *corev1.Secret) error {
	c.secretWrites++
	credential := serviceTokenSecretCarriesCredential(secret)
	if credential {
		c.credentialWrites++
	} else if secret.Name != c.credentialName {
		c.journalWrites++
	}
	if c.failSecretWriteAt > 0 && c.secretWrites == c.failSecretWriteAt {
		return fmt.Errorf("injected Secret write failure")
	}
	if credential && c.failCredentialWriteAt > 0 && c.credentialWrites == c.failCredentialWriteAt {
		return fmt.Errorf("injected credential Secret write failure")
	}
	if !credential && secret.Name != c.credentialName && c.failJournalWriteAt > 0 && c.journalWrites == c.failJournalWriteAt {
		return fmt.Errorf("injected journal Secret write failure")
	}
	return nil
}

func (c *serviceTokenFaultClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return c.Client.Create(ctx, object, options...)
	}
	if err := c.failSecretWrite(secret); err != nil {
		return err
	}
	if err := c.Client.Create(ctx, object, options...); err != nil {
		return err
	}
	if serviceTokenSecretCarriesCredential(secret) && c.commitCredentialAt > 0 && c.credentialWrites == c.commitCredentialAt {
		return fmt.Errorf("injected credential Secret write timeout after commit")
	}
	return nil
}

func (c *serviceTokenFaultClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return c.Client.Update(ctx, object, options...)
	}
	if err := c.failSecretWrite(secret); err != nil {
		return err
	}
	if err := c.Client.Update(ctx, object, options...); err != nil {
		return err
	}
	if serviceTokenSecretCarriesCredential(secret) && c.commitCredentialAt > 0 && c.credentialWrites == c.commitCredentialAt {
		return fmt.Errorf("injected credential Secret write timeout after commit")
	}
	return nil
}

func (c *serviceTokenFaultClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return c.Client.Patch(ctx, object, patch, options...)
	}
	if err := c.failSecretWrite(secret); err != nil {
		return err
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

func (c *serviceTokenFaultClient) Status() client.SubResourceWriter {
	return &serviceTokenFaultStatusWriter{SubResourceWriter: c.Client.Status(), client: c}
}

type serviceTokenFaultStatusWriter struct {
	client.SubResourceWriter
	client *serviceTokenFaultClient
}

func (w *serviceTokenFaultStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	if _, ok := object.(*v1alpha1.ServiceToken); ok {
		w.client.statusPatches++
		if w.client.failStatusPatchAt > 0 && w.client.statusPatches == w.client.failStatusPatchAt {
			return fmt.Errorf("injected ServiceToken status patch failure")
		}
	}
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
}

// serviceTokenStaleSecretClient simulates an informer cache that has not yet
// observed the credential Secret: reads for it report NotFound while every
// other operation — including writes — reaches the real store. APIReader
// stays authoritative.
type serviceTokenStaleSecretClient struct {
	client.Client
	credentialKey types.NamespacedName
}

func (c *serviceTokenStaleSecretClient) Get(ctx context.Context, key types.NamespacedName, object client.Object, options ...client.GetOption) error {
	if _, ok := object.(*corev1.Secret); ok && key == c.credentialKey {
		return apierrors.NewNotFound(corev1.Resource("secrets"), key.Name)
	}
	return c.Client.Get(ctx, key, object, options...)
}

// serviceTokenJournalSecrets returns the Secrets in the object's namespace
// that are neither the API-token Secret nor the credential destination — the
// controller-owned recovery journal, without pinning its private name.
func serviceTokenJournalSecrets(ctx context.Context, kube client.Client, object *v1alpha1.ServiceToken) ([]corev1.Secret, error) {
	var secrets corev1.SecretList
	if err := kube.List(ctx, &secrets, client.InNamespace(object.Namespace)); err != nil {
		return nil, err
	}
	var journals []corev1.Secret
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if secret.Name == object.Spec.SecretRef.Name || secret.Name == "api-token" {
			continue
		}
		journals = append(journals, *secret)
	}
	return journals, nil
}

// newZoneServiceTokenWorld rebuilds the world with the ServiceToken scoped to
// a zone the account has verified.
func newZoneServiceTokenWorld(t *testing.T, api *serviceTokenFakeAPI, clock time.Time) *serviceTokenWorld {
	t.Helper()
	world := newServiceTokenWorld(t, api, clock)
	ctx := context.Background()

	var account v1alpha1.CloudflareAccount
	if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	account.Spec.Grants[0].Zones = []string{"*"}
	account.Status.Verified.Zones = []v1alpha1.CloudflareVerifiedZone{{ID: "zone-1", Name: "example.test"}}
	if err := world.kube.Update(ctx, &account); err != nil {
		t.Fatal(err)
	}
	world.account = &account

	var token v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &token); err != nil {
		t.Fatal(err)
	}
	token.Spec.Zone = "example.test"
	if err := world.kube.Update(ctx, &token); err != nil {
		t.Fatal(err)
	}
	return world
}

func serviceTokenReady(ctx context.Context, t *testing.T, world *serviceTokenWorld) v1alpha1.ServiceToken {
	t.Helper()
	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("ServiceToken is not Ready: %#v", current.Status.Conditions)
	}
	return current
}

func serviceTokenCredentialSecret(ctx context.Context, t *testing.T, world *serviceTokenWorld) corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "tenant", Name: "token-credentials"}
	if err := world.kube.Get(ctx, key, &secret); err != nil {
		t.Fatalf("credential Secret missing: %v", err)
	}
	return secret
}

// serviceTokenConverge reconciles until the ServiceToken reports Ready or the
// pass bound is exhausted. Recovery spans multiple reconcile passes — a zone
// retirement deletes, requeues, and only then re-creates — so tests assert the
// converged outcome, not a pass count. Every pass must return a nil error.
func serviceTokenConverge(ctx context.Context, t *testing.T, world *serviceTokenWorld, passes int) v1alpha1.ServiceToken {
	t.Helper()
	var current v1alpha1.ServiceToken
	for i := range passes {
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("recovery reconcile %d: %v", i+1, err)
		}
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			return current
		}
	}
	t.Fatalf("ServiceToken did not converge to Ready within %d reconciles: %#v", passes, current.Status.Conditions)
	return current
}

// ST-QA-01: the earliest durable Secret write fails before any remote call —
// no remote mutation may have happened, and nothing may be stranded.
func TestServiceTokenEarlySecretWriteFailureLeavesNoRemoteMutation(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	world.restart(&serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failSecretWriteAt: 1})

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the first Secret write fails")
	}
	if api.mutations() != 0 || len(api.tokens) != 0 {
		t.Fatalf("remote mutation happened before the first durable Secret write: calls=%v tokens=%v", api.calls, api.tokens)
	}
}

// ST-QA-02 + ST-QA-07: the credential-bearing Secret write fails after the
// remote create committed. The next reconcile must recover the same remote
// token — account scope rotates fresh credentials onto it — instead of
// blindly creating a second token. This is the issue-94 invariant restated
// as "no stranded tokens": exactly one remote token ever exists.
func TestServiceTokenCredentialWriteFailureRecoversSameToken(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	if api.creates != 1 || len(api.tokens) != 1 {
		t.Fatalf("expected exactly one committed remote token after the failed credential write: creates=%d tokens=%v", api.creates, api.tokens)
	}
	tokenID := api.tokens["token-1"].ID

	// A fresh reconciler — the process restarted — resumes the recorded
	// attempt instead of issuing a blind create.
	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 {
		t.Fatalf("recovery created a duplicate remote token: creates=%d calls=%v", api.creates, api.calls)
	}
	if api.rotates != 1 {
		t.Fatalf("account-scope recovery did not rotate fresh credentials onto the recovered token: rotates=%d calls=%v", api.rotates, api.calls)
	}
	if api.deletes != 0 {
		t.Fatalf("account-scope recovery deleted a token: deletes=%d calls=%v", api.deletes, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[tokenID] {
		t.Fatalf("published credential does not match the recovered token's committed secret")
	}
	if secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] != tokenID {
		t.Fatalf("credential Secret does not record the recovered token ID: %#v", secret.Annotations)
	}
}

// ST-QA-03: the same credential-write failure on a zone-scoped token recovers
// through verified delete + create — zone scope never rotates.
func TestServiceTokenZoneCredentialWriteFailureDeletesAndRecreates(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newZoneServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	if api.creates != 1 || len(api.tokens) != 1 {
		t.Fatalf("expected exactly one committed zone token after the failed credential write: creates=%d tokens=%v", api.creates, api.tokens)
	}
	var strandedKey, strandedID string
	for key, remote := range api.tokens {
		strandedKey, strandedID = key, remote.ID
	}

	world.restart(nil)
	// Zone recovery spans passes: the retiring token is deleted and requeued,
	// then the next pass confirms the deletion and re-creates.
	current := serviceTokenConverge(ctx, t, world, 3)
	if api.rotates != 0 {
		t.Fatalf("zone-scope recovery attempted a rotate, which zone scope does not support: calls=%v", api.calls)
	}
	if api.deletes == 0 {
		t.Fatalf("zone-scope recovery never deleted the stranded token: calls=%v", api.calls)
	}
	if api.creates != 2 || len(api.tokens) != 1 {
		t.Fatalf("zone-scope recovery did not converge to exactly one recreated token: creates=%d tokens=%v calls=%v", api.creates, api.tokens, api.calls)
	}
	if _, stranded := api.tokens[strandedKey]; stranded {
		t.Fatalf("stranded zone token %q survived recovery", strandedKey)
	}
	if current.Status.TokenID == "" || current.Status.TokenID == strandedID {
		t.Fatalf("status still records the stranded zone token: %#v", current.Status)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[parityServiceTokenKey(flarecloudflare.AccessScope{ZoneID: "zone-1"}, current.Status.TokenID)] {
		t.Fatal("published credential does not match the recreated zone token's committed secret")
	}
}

// ST-QA-04 + ST-QA-25: the remote create committed but its response — and the
// returned token ID — was lost. Resume must find the recorded attempt through
// the scoped list and rotate fresh credentials onto it, not create again.
func TestServiceTokenCreateResponseLossResumesAttempt(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string), commitThenFailCreateAt: 1}
	world := newServiceTokenWorld(t, api, clock)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded after the create response was lost")
	}
	if api.creates != 1 || len(api.tokens) != 1 {
		t.Fatalf("expected exactly one committed remote token after the lost create response: creates=%d tokens=%v", api.creates, api.tokens)
	}
	tokenID := api.tokens["token-1"].ID

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 {
		t.Fatalf("recovery created a duplicate remote token: creates=%d calls=%v", api.creates, api.calls)
	}
	if api.rotates != 1 {
		t.Fatalf("recovery did not rotate fresh credentials onto the resumed token: rotates=%d calls=%v", api.rotates, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[tokenID] {
		t.Fatal("published credential does not match the resumed token's committed secret")
	}
}

// ST-QA-05: the credential Secret write committed but the client observed a
// timeout. The authoritative readback must find the committed credential and
// finish without rotating or recreating.
func TestServiceTokenCommittedCredentialWriteTimeoutKeepsCredential(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", commitCredentialAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential write reported a timeout")
	}
	committed := serviceTokenCredentialSecret(ctx, t, world)
	if len(committed.Data[v1alpha1.ServiceTokenClientSecretKey]) == 0 {
		t.Fatal("credential Secret write did not actually commit")
	}
	tokenID := api.tokens["token-1"].ID

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 || api.rotates != 0 || api.deletes != 0 {
		t.Fatalf("committed credential was not honored — recovery mutated remote state: creates=%d rotates=%d deletes=%d calls=%v", api.creates, api.rotates, api.deletes, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != string(committed.Data[v1alpha1.ServiceTokenClientSecretKey]) {
		t.Fatal("recovery rewrote the committed credential")
	}
}

// ST-QA-06: the provider rejects duplicate names with a committed 409. A
// blind re-create can never succeed, so recovery must resume the recorded
// attempt instead.
func TestServiceTokenDuplicateNameConflictForcesJournalRecovery(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string), rejectDuplicateName: true}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	tokenID := api.tokens["token-1"].ID

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile under duplicate-name rejection: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 || len(api.tokens) != 1 {
		t.Fatalf("recovery under duplicate-name rejection did not converge to the single recorded token: creates=%d tokens=%v calls=%v", api.creates, api.tokens, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
}

// ST-QA-21 + ST-QA-22: a healthy issue leaves no journal behind — only the
// credential destination Secret remains — and a steady-state reconcile
// performs no remote mutation.
func TestServiceTokenHealthyIssueReapsJournalAndStaysIdle(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	journals, err := serviceTokenJournalSecrets(ctx, world.kube, &issued)
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) != 0 {
		names := make([]string, 0, len(journals))
		for i := range journals {
			names = append(names, journals[i].Name)
		}
		t.Fatalf("recovery journal was not reaped after the status checkpoint: %v", names)
	}

	mutations := api.mutations()
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("steady-state reconcile: %v", err)
	}
	if api.mutations() != mutations {
		t.Fatalf("steady-state reconcile mutated remote state: calls=%v", api.calls)
	}
	serviceTokenReady(ctx, t, world)
}

// ST-QA-23: a rotate failure during account-scope recovery is retried on the
// next reconcile — there is no delete fallback and no blind create.
func TestServiceTokenRecoveryRotateFailureRetriesWithoutDelete(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	tokenID := api.tokens["token-1"].ID

	world.restart(nil)
	api.rotateErr = fmt.Errorf("cloudflare returned 500 for service token rotation")
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("recovery reconcile unexpectedly succeeded while rotation fails")
	}
	if api.deletes != 0 {
		t.Fatalf("rotate failure fell back to deleting the remote token: calls=%v", api.calls)
	}
	if _, found := api.tokens[tokenID]; !found {
		t.Fatalf("rotate failure lost the remote token %q", tokenID)
	}

	api.rotateErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile after rotation recovered: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 || api.rotates != 1 || api.deletes != 0 {
		t.Fatalf("recovery did not converge through exactly one create and one rotate: creates=%d rotates=%d deletes=%d calls=%v", api.creates, api.rotates, api.deletes, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
}

// ST-QA-24a: a zone-scope recovery whose delete of the stranded token fails
// must not create a replacement until the delete is confirmed — even across a
// controller restart.
func TestServiceTokenZoneRecoveryDeleteFailureBlocksReplacement(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newZoneServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	if len(api.tokens) != 1 {
		t.Fatalf("expected exactly one committed zone token: %v", api.tokens)
	}

	world.restart(nil)
	api.deleteErr = fmt.Errorf("cloudflare returned 500 for service token deletion")
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("zone recovery unexpectedly succeeded while the remote deletion fails")
	}
	if api.creates != 1 {
		t.Fatalf("zone recovery created a replacement before the old token deletion was confirmed: creates=%d calls=%v", api.creates, api.calls)
	}
	if len(api.tokens) != 1 {
		t.Fatalf("zone recovery lost the stranded token while deletion fails: %v", api.tokens)
	}

	// The controller restarts with the deletion still unconfirmed; the
	// durable checkpoint must keep blocking the replacement create.
	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("zone recovery after restart unexpectedly succeeded while the remote deletion fails")
	}
	if api.creates != 1 {
		t.Fatalf("zone recovery after restart created a replacement before the old token deletion was confirmed: creates=%d calls=%v", api.creates, api.calls)
	}

	api.deleteErr = nil
	serviceTokenConverge(ctx, t, world, 3)
	if api.creates != 2 || len(api.tokens) != 1 {
		t.Fatalf("zone recovery did not converge to exactly one recreated token: creates=%d tokens=%v calls=%v", api.creates, api.tokens, api.calls)
	}
}

// ST-QA-24b: a zone-scope recovery interrupted after the old token's deletion
// but before the replacement create resumes from the checkpoint and creates
// the replacement — it never re-creates blindly.
func TestServiceTokenZoneRecoveryResumesCreateAfterDelete(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newZoneServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	var strandedKey string
	for key := range api.tokens {
		strandedKey = key
	}

	// The recovery reconcile deletes the stranded token and records the
	// checkpoint before replacement creation resumes.
	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("zone recovery unexpectedly failed while deleting the stranded token: %v", err)
	}
	if _, stranded := api.tokens[strandedKey]; stranded {
		t.Fatalf("stranded zone token %q was not deleted before replacement create", strandedKey)
	}
	if len(api.tokens) != 0 {
		t.Fatalf("unexpected remote tokens between delete and replacement create: %v", api.tokens)
	}

	world.restart(nil)
	current := serviceTokenConverge(ctx, t, world, 3)
	if api.creates != 2 || len(api.tokens) != 1 {
		t.Fatalf("zone recovery resume did not converge to exactly one recreated token: creates=%d tokens=%v calls=%v", api.creates, api.tokens, api.calls)
	}
	if current.Status.TokenID == "" {
		t.Fatal("status does not record the recreated zone token")
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[parityServiceTokenKey(flarecloudflare.AccessScope{ZoneID: "zone-1"}, current.Status.TokenID)] {
		t.Fatal("published credential does not match the recreated zone token's committed secret")
	}
}

// ST-QA-26: a remote update failure after the credential was captured retries
// the update on the next reconcile — the committed credential is read back
// durably, so no second rotation happens and no credential is exposed.
func TestServiceTokenRecoveryUpdateFailureRetriesWithoutRotation(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	tokenID := api.tokens["token-1"].ID

	// The resumed token drifted out of band, so recovery must normalize it
	// with an update — which fails once.
	drifted := api.tokens[tokenID]
	drifted.Enabled = false
	api.tokens[tokenID] = drifted

	world.restart(nil)
	api.updateErr = fmt.Errorf("cloudflare returned 500 for service token update")
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("recovery reconcile unexpectedly succeeded while the remote update fails")
	}
	api.updateErr = nil
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile after the remote update recovered: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 || api.rotates != 1 || api.deletes != 0 {
		t.Fatalf("recovery mutated remote state beyond the single create and rotate: creates=%d rotates=%d deletes=%d calls=%v", api.creates, api.rotates, api.deletes, api.calls)
	}
	if !api.tokens[tokenID].Enabled {
		t.Fatalf("recovery never normalized the drifted remote token: %#v", api.tokens[tokenID])
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[tokenID] {
		t.Fatal("published credential does not match the recovered token's committed secret")
	}
}

// ST-QA-27: a status-patch failure after credential capture leaves the
// journal behind; the next reconcile reaps it through the delayed checkpoint
// instead of rotating again.
func TestServiceTokenStatusPatchFailureReapsJournalOnRetry(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	tokenID := api.tokens["token-1"].ID

	faults.failCredentialWriteAt = 0
	faults.failStatusPatchAt = 1
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("recovery reconcile unexpectedly succeeded while the status patch fails")
	}
	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object)
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) == 0 {
		t.Fatal("recovery journal disappeared before the status checkpoint committed")
	}

	faults.failStatusPatchAt = 0
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile after the status patch recovered: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.rotates != 1 {
		t.Fatalf("delayed checkpoint rotated the recovered token again: rotates=%d calls=%v", api.rotates, api.calls)
	}
	if current.Status.TokenID != tokenID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", tokenID, current.Status.TokenID)
	}
	journals, err = serviceTokenJournalSecrets(ctx, world.kube, &object)
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) != 0 {
		t.Fatalf("recovery journal was not reaped after the delayed status checkpoint: %v", journals)
	}
}

// ST-QA-35: a crash between the journal's prepared write and its dispatched
// write leaves a prepared journal; the next reconcile proceeds with the
// create because nothing was ever dispatched.
func TestServiceTokenPreparedJournalRetriesCreate(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	faults := &serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failJournalWriteAt: 2}
	world.restart(faults)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the journal dispatch write fails")
	}
	if api.mutations() != 0 || len(api.tokens) != 0 {
		t.Fatalf("a remote mutation happened before the journal recorded the dispatch: calls=%v tokens=%v", api.calls, api.tokens)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after the prepared journal survived: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.creates != 1 || len(api.tokens) != 1 {
		t.Fatalf("prepared journal did not converge to exactly one created token: creates=%d tokens=%v calls=%v", api.creates, api.tokens, api.calls)
	}
	if current.Status.TokenID == "" {
		t.Fatal("status does not record the created token")
	}
}

// ST-QA-36: a dispatched journal whose scoped list finds zero remote matches
// is "unknown", not "absent" — the reconciler fails closed and never issues a
// blind create.
func TestServiceTokenDispatchedJournalWithZeroRemoteBlocks(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string), createErr: fmt.Errorf("cloudflare returned 500 for service token create")}
	world := newServiceTokenWorld(t, api, clock)

	// The journal records the dispatch, then the remote create fails before
	// commit — the remote may or may not have the token.
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the remote create fails")
	}
	if len(api.tokens) != 0 {
		t.Fatalf("remote create unexpectedly committed: %v", api.tokens)
	}

	api.createErr = nil
	world.restart(nil)
	for i := 0; i < 2; i++ {
		_, _ = world.reconciler.Reconcile(ctx, world.request)
	}
	if api.creates != 0 {
		t.Fatalf("dispatched journal with zero remote matches issued a blind create: creates=%d calls=%v", api.creates, api.calls)
	}
	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
		t.Fatalf("dispatched journal with zero remote matches reported Ready: %#v", current.Status.Conditions)
	}
}

// ST-QA-37: an informer cache that has not yet observed the committed
// credential Secret must not trigger a rotation or recreate — the
// authoritative APIReader read finds the committed credential.
func TestServiceTokenStaleCacheMissKeepsCommittedCredential(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string)}
	world := newServiceTokenWorld(t, api, clock)
	issued := world.issueToken(ctx, t)

	stale := &serviceTokenStaleSecretClient{
		Client:        world.kube,
		credentialKey: types.NamespacedName{Namespace: "tenant", Name: "token-credentials"},
	}
	world.restart(stale)

	mutations := api.mutations()
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile with a stale credential cache: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if api.mutations() != mutations {
		t.Fatalf("stale credential cache triggered a remote mutation: calls=%v", api.calls)
	}
	if current.Status.TokenID != issued.Status.TokenID {
		t.Fatalf("stale credential cache rebound the token: before=%q after=%q", issued.Status.TokenID, current.Status.TokenID)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[issued.Status.TokenID] {
		t.Fatal("stale credential cache rewrote the committed credential")
	}
}

// ST-QA-40: a provider that commits the create under a different name than
// the recorded attempt is divergence — the reconciler blocks instead of
// silently adopting the diverged token or looping creates.
func TestServiceTokenCreateNameDivergenceBlocks(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	api := &serviceTokenFakeAPI{now: func() time.Time { return clock }, tokens: make(map[string]flarecloudflare.ServiceToken), secrets: make(map[string]string), createNameOverride: "diverged-remote-name"}
	world := newServiceTokenWorld(t, api, clock)

	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile returned an unexpected error for create-name divergence: %v", err)
	}
	var firstPass v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &firstPass); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(firstPass.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
		t.Fatalf("create-name divergence reported Ready on first pass: %#v", firstPass.Status.Conditions)
	}
	initialSecret := serviceTokenCredentialSecret(ctx, t, world)
	initialClientSecret := string(initialSecret.Data[v1alpha1.ServiceTokenClientSecretKey])
	for range 2 {
		_, _ = world.reconciler.Reconcile(ctx, world.request)
	}
	if api.creates != 1 {
		t.Fatalf("create-name divergence triggered a create loop: creates=%d calls=%v", api.creates, api.calls)
	}
	if api.rotates != 0 {
		t.Fatalf("create-name divergence triggered credential rotation: rotates=%d calls=%v", api.rotates, api.calls)
	}
	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
		t.Fatalf("create-name divergence reported Ready: %#v", current.Status.Conditions)
	}
	secret := serviceTokenCredentialSecret(ctx, t, world)
	if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != initialClientSecret {
		t.Fatal("create-name divergence changed the captured credential")
	}
}
