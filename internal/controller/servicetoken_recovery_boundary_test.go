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

// Boundary/security QA for the create-intent journal (issue #94). These tests
// cover the fail-closed edges of the recovery design: foreign or unwritable
// destinations, ambiguous or foreign remote candidates, identity drift while
// an attempt is pending, journal loss or corruption, pending deletion, policy
// boundaries, and non-managed paths. The journal is always discovered through
// the Secrets the CR owns — never through its private name or key layout.
//
// QA matrix mapping (docs/qa/servicetoken-create-recovery.md §5):
//   ST-QA-08  TestServiceTokenForeignDestinationSecretBlocksCreate
//   ST-QA-09  TestServiceTokenImmutableDestinationBlocksCreate
//   ST-QA-10  TestServiceTokenAmbiguousRemoteCandidatesBlockResume
//   ST-QA-11  TestServiceTokenForeignClusterTokenIsIgnored
//   ST-QA-12  TestServiceTokenPendingScopeDriftConflicts
//   ST-QA-13  TestServiceTokenDeletedJournalBlocksAdoption
//   ST-QA-14  TestServiceTokenPendingSecretRefChangeConflicts
//   ST-QA-15  TestServiceTokenPendingDeleteCleansRemote
//   ST-QA-16  TestServiceTokenEstablishedMissingSecretNeverRotates
//   ST-QA-17  covered by TestServiceTokenRemoteLossRevokesAccepted
//             (servicetoken_controller_test.go): typed remote 404 revokes
//             Accepted and stops Access rule resolution.
//   ST-QA-18  covered by TestServiceTokenDeletionFailureReportsCleanupBlocked
//             (servicetoken_controller_test.go): failed remote deletion keeps
//             the finalizer and reports CleanupBlocked.
//   ST-QA-19  TestServiceTokenObserveOnlyNeverMutates
//   ST-QA-20  TestServiceTokenGrantRevocationDeniesBeforeRemote
//   ST-QA-28  TestServiceTokenRecreatedCRUIDMismatch
//   ST-QA-29  TestServiceTokenCorruptOrForeignJournalBlocks
//   ST-QA-30  TestServiceTokenOrphanPendingDeleteKeepsRemote
//   ST-QA-31  TestServiceTokenPendingMutableFieldChangeAligns
//   ST-QA-32  TestServiceTokenPendingAccountDriftConflicts
//   ST-QA-33  TestServiceTokenPartialCredentialNeverReady
//   ST-QA-34  TestServiceTokenJournallessPendingDelete* (verified delete and
//             fail-closed variants)
//   ST-QA-38  TestServiceTokenZoneVerificationFlapResumes
//   ST-QA-39  TestServiceTokenStaleJournalAfterCheckpointIsReapOnly
//   ST-QA-41  TestServiceTokenNonManagedPathsSkipJournal
//   ST-QA-42/43/46 TestServiceTokenNeverCreatedDeletionSkipsRemoteMutation
//   ST-QA-44     TestServiceTokenAttemptMarkerProtectsJournalCreateFailure
//   ST-QA-45     TestServiceTokenAttemptMarkerCleanupAndSteadyState
//   RuntimeReview follow-up (pending journal + deleted/immutable/foreign
//   destination): TestServiceTokenPendingDestinationRecreatedBeforeRotate.
import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

var serviceTokenBoundaryClock = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func newServiceTokenBoundaryAPI() *serviceTokenFakeAPI {
	return &serviceTokenFakeAPI{
		now:     func() time.Time { return serviceTokenBoundaryClock },
		tokens:  make(map[string]flarecloudflare.ServiceToken),
		secrets: make(map[string]string),
	}
}

// pendingServiceToken drives a managed create up to the point where the remote
// token exists but its credential was never committed: the journal is
// dispatched, the destination Secret is reserved and empty, and status is
// untouched. It returns the live object and the single remote token.
func pendingServiceToken(ctx context.Context, t *testing.T, world *serviceTokenWorld) (v1alpha1.ServiceToken, flarecloudflare.ServiceToken) {
	t.Helper()
	world.restart(&serviceTokenFaultClient{Client: world.kube, credentialName: "token-credentials", failCredentialWriteAt: 1})
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the credential Secret write fails")
	}
	if world.api.creates != 1 || len(world.api.tokens) != 1 {
		t.Fatalf("expected exactly one committed remote token in the pending state: creates=%d tokens=%v", world.api.creates, world.api.tokens)
	}
	var remote flarecloudflare.ServiceToken
	for _, token := range world.api.tokens {
		remote = token
	}
	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	if object.Status.TokenID != "" {
		t.Fatalf("pending state unexpectedly recorded a token ID: %#v", object.Status)
	}
	journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object)
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) != 1 {
		t.Fatalf("pending state must keep exactly one journal Secret, found %d", len(journals))
	}
	return object, remote
}

// serviceTokenDestinationSecret returns the credential destination Secret, or
// nil when it does not exist.
func serviceTokenDestinationSecret(ctx context.Context, t *testing.T, world *serviceTokenWorld) *corev1.Secret {
	t.Helper()
	secret := new(corev1.Secret)
	key := types.NamespacedName{Namespace: "tenant", Name: "token-credentials"}
	if err := world.kube.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		t.Fatal(err)
	}
	return secret
}

// serviceTokenJournal returns the single journal Secret owned by the object,
// discovered by listing namespace Secrets minus the credential destination and
// the API-token Secret.
func boundaryServiceTokenJournal(ctx context.Context, t *testing.T, world *serviceTokenWorld, object *v1alpha1.ServiceToken) corev1.Secret {
	t.Helper()
	journals, err := serviceTokenJournalSecrets(ctx, world.kube, object)
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) != 1 {
		t.Fatalf("expected exactly one journal Secret, found %d", len(journals))
	}
	return journals[0]
}

// grantServiceTokenZone authorizes and verifies one DNS zone on the world
// account so zone-scoped ServiceTokens pass both the grant gate and zone
// resolution.
func grantServiceTokenZone(ctx context.Context, t *testing.T, world *serviceTokenWorld, zoneName, zoneID string) {
	t.Helper()
	var account v1alpha1.CloudflareAccount
	if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	account.Spec.Grants[0].Zones = []string{zoneName}
	account.Status.Verified.Zones = []v1alpha1.CloudflareVerifiedZone{{ID: zoneID, Name: zoneName}}
	if err := world.kube.Update(ctx, &account); err != nil {
		t.Fatal(err)
	}
}

// newZoneBoundaryWorld builds a zone-scoped world whose account grant actually
// permits the zone (newZoneServiceTokenWorld only sets verified zones).
func newZoneBoundaryWorld(t *testing.T, api *serviceTokenFakeAPI) *serviceTokenWorld {
	t.Helper()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	ctx := context.Background()
	grantServiceTokenZone(ctx, t, world, "example.test", "zone-1")
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

// serviceTokenOwnedSecret builds a Secret controlled by the ServiceToken, the
// shape the controller itself produces for owned destinations.
func serviceTokenOwnedSecret(object *v1alpha1.ServiceToken, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: object.Namespace,
			Name:      name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         v1alpha1.GroupVersion.String(),
				Kind:               "ServiceToken",
				Name:               object.Name,
				UID:                object.UID,
				Controller:         ptr.To(true),
				BlockOwnerDeletion: ptr.To(true),
			}},
		},
	}
}

// serviceTokenConflict fetches the object and requires a Ready=False Conflict.
func serviceTokenConflict(ctx context.Context, t *testing.T, world *serviceTokenWorld) v1alpha1.ServiceToken {
	t.Helper()
	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	ready := serviceTokenCondition(object.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "Conflict" {
		t.Fatalf("expected Ready=False/Conflict, got %#v", object.Status.Conditions)
	}
	return object
}

// serviceTokenImmutableAwareClient mirrors the API server's immutable-Secret
// enforcement that the fake client lacks: updates and patches to an immutable
// Secret are denied, while creates and deletes pass through.
type serviceTokenImmutableAwareClient struct {
	client.Client
}

func (c *serviceTokenImmutableAwareClient) denyImmutableWrite(ctx context.Context, object client.Object) error {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}
	stored := new(corev1.Secret)
	key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
	if err := c.Get(ctx, key, stored); err == nil {
		if ptr.Deref(stored.Immutable, false) {
			return apierrors.NewForbidden(corev1.Resource("secrets"), key.Name, fmt.Errorf("Secret is immutable"))
		}
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if ptr.Deref(secret.Immutable, false) {
		return apierrors.NewForbidden(corev1.Resource("secrets"), key.Name, fmt.Errorf("Secret is immutable"))
	}
	return nil
}

func (c *serviceTokenImmutableAwareClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if err := c.denyImmutableWrite(ctx, object); err != nil {
		return err
	}
	return c.Client.Update(ctx, object, options...)
}

func (c *serviceTokenImmutableAwareClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if err := c.denyImmutableWrite(ctx, object); err != nil {
		return err
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

// serviceTokenNoFinalizerAdditionOnDelete mirrors the apiserver invariant that
// a terminating object cannot gain a new finalizer during an update/patch.
type serviceTokenNoFinalizerAdditionOnDelete struct {
	client.Client
}

func (c *serviceTokenNoFinalizerAdditionOnDelete) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	token, ok := object.(*v1alpha1.ServiceToken)
	if ok && !token.DeletionTimestamp.IsZero() {
		var stored v1alpha1.ServiceToken
		if err := c.Get(ctx, client.ObjectKeyFromObject(token), &stored); err == nil {
			for _, finalizer := range token.Finalizers {
				if !controllerutil.ContainsFinalizer(&stored, finalizer) {
					return fmt.Errorf("cannot add finalizer %q to terminating ServiceToken", finalizer)
				}
			}
		}
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

// serviceTokenJournalDeleteBlocker fails the first delete of the journal
// Secret — any Secret other than the credential destination — so a test can
// leave a genuine journal behind after the status checkpoint.
type serviceTokenJournalDeleteBlocker struct {
	client.Client
	credentialName string
	failed         bool
}

func (c *serviceTokenJournalDeleteBlocker) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if secret, ok := object.(*corev1.Secret); ok && secret.Name != c.credentialName && !c.failed {
		c.failed = true
		return fmt.Errorf("injected journal delete failure")
	}
	return c.Client.Delete(ctx, object, options...)
}

// ST-QA-08: a Secret that already occupies the credential destination and is
// not controlled by this ServiceToken must stop the create before any remote
// mutation — the foreign Secret is never adopted or rewritten.
func TestServiceTokenForeignDestinationSecretBlocksCreate(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)

	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "token-credentials"},
		Data:       map[string][]byte{"preexisting": []byte("value")},
	}
	if err := world.kube.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("collision should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.mutations() != 0 || len(api.tokens) != 0 {
		t.Fatalf("remote mutation happened despite the foreign destination: calls=%v tokens=%v", api.calls, api.tokens)
	}
	var observed corev1.Secret
	if err := world.kube.Get(ctx, client.ObjectKeyFromObject(foreign), &observed); err != nil {
		t.Fatal(err)
	}
	if len(observed.OwnerReferences) != 0 || string(observed.Data["preexisting"]) != "value" {
		t.Fatalf("foreign Secret was adopted or rewritten: owners=%v data=%v", observed.OwnerReferences, observed.Data)
	}
}

// ST-QA-09: an owned but immutable destination cannot accept the credential,
// so the reservation must fail before the remote create — otherwise the token
// is stranded exactly like the original issue.
func TestServiceTokenImmutableDestinationBlocksCreate(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)

	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	immutable := serviceTokenOwnedSecret(&object, "token-credentials")
	immutable.Immutable = ptr.To(true)
	if err := world.kube.Create(ctx, immutable); err != nil {
		t.Fatal(err)
	}

	// The immutable-aware client reproduces the API server's write denial so
	// the reservation cannot mistake the destination for writable.
	world.restart(&serviceTokenImmutableAwareClient{Client: world.kube})
	_, _ = world.reconciler.Reconcile(ctx, world.request)

	if api.mutations() != 0 || len(api.tokens) != 0 {
		t.Fatalf("remote mutation happened although the destination is immutable: calls=%v tokens=%v", api.calls, api.tokens)
	}
	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
		t.Fatalf("ServiceToken reported Ready although its credential could never be written: %#v", current.Status.Conditions)
	}
}

// ST-QA-10: two remote tokens carrying the exact journaled attempt name are
// ambiguous — resume must refuse to pick one and mutate nothing.
func TestServiceTokenAmbiguousRemoteCandidatesBlockResume(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	// A second remote token with the identical attempt name — the provider
	// accepted a duplicate — makes the candidate set ambiguous.
	duplicate := remote
	duplicate.ID = "token-duplicate"
	duplicate.ClientID = "client-duplicate"
	api.tokens[duplicate.ID] = duplicate

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("ambiguous candidates should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.rotates != 0 || api.updates != 0 || api.deletes != 0 || api.creates != 1 {
		t.Fatalf("ambiguous candidates triggered a remote mutation: calls=%v", api.calls)
	}
	if len(api.tokens) != 2 {
		t.Fatalf("ambiguous candidates were mutated or adopted: tokens=%v", api.tokens)
	}
	if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
		t.Fatalf("credential was written while the remote candidate was ambiguous: %#v", secret)
	}
}

// ST-QA-11: a remote token minted by a different cluster — same namespace and
// spec name shape, different cluster UID — is never a candidate: it is not
// adopted, rotated, or deleted, and recovery proceeds on this cluster's token.
func TestServiceTokenForeignClusterTokenIsIgnored(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	foreign := flarecloudflare.ServiceToken{
		ID:        "foreign-token",
		ClientID:  "client-foreign",
		Name:      strings.Replace(remote.Name, "cluster-id", "other-cluster", 1),
		Duration:  "8760h",
		Enabled:   true,
		ExpiresAt: serviceTokenBoundaryClock.Add(24 * time.Hour),
	}
	if foreign.Name == remote.Name {
		t.Fatal("foreign token name did not diverge from the journaled attempt name")
	}
	api.tokens[foreign.ID] = foreign

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if current.Status.TokenID != remote.ID {
		t.Fatalf("recovery adopted the foreign token: before=%q after=%q", remote.ID, current.Status.TokenID)
	}
	if api.rotates != 1 || api.creates != 1 || api.deletes != 0 {
		t.Fatalf("recovery did not rotate exactly the journaled token: calls=%v", api.calls)
	}
	if observed, found := api.tokens[foreign.ID]; !found || observed != foreign {
		t.Fatalf("foreign cluster token was mutated or deleted: %#v found=%v", observed, found)
	}
	if len(api.tokens) != 2 {
		t.Fatalf("unexpected remote token set after recovery: %v", api.tokens)
	}
}

// ST-QA-12: adding spec.zone while an account-scoped attempt is pending
// changes the immutable identity tuple — the journal binding no longer matches
// and the attempt must fail closed instead of resuming cross-scope.
func TestServiceTokenPendingScopeDriftConflicts(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	// The account now verifies and grants a zone, and the operator scopes the
	// pending token to it — an identity change, not a metadata flap.
	grantServiceTokenZone(ctx, t, world, "example.test", "zone-1")
	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	object.Spec.Zone = "example.test"
	if err := world.kube.Update(ctx, &object); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("scope drift should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.rotates != 0 || api.updates != 0 || api.deletes != 0 || api.creates != 1 {
		t.Fatalf("scope drift triggered a remote mutation: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("the pending remote token was deleted during the conflict")
	}
	if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
		t.Fatalf("credential was written despite the scope conflict: %#v", secret)
	}
}

// ST-QA-13: when the journal is deleted out of band while its remote token
// still exists, scoped discovery sees the attempt prefix but has no provenance
// to resume — it must block instead of adopting or re-creating.
func TestServiceTokenDeletedJournalBlocksAdoption(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	object, remote := pendingServiceToken(ctx, t, world)

	journal := boundaryServiceTokenJournal(ctx, t, world, &object)
	if err := world.kube.Delete(ctx, &journal); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("journal loss should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.creates != 1 || api.rotates != 0 || api.updates != 0 || api.deletes != 0 {
		t.Fatalf("journal loss triggered a remote mutation or blind create: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("the stranded remote token was mutated after the journal was lost")
	}
	if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
		t.Fatalf("credential was written without journal provenance: %#v", secret)
	}
}

// ST-QA-14: repointing spec.secretRef while an attempt is pending breaks the
// journaled destination binding — fail closed instead of writing the pending
// credential somewhere new.
func TestServiceTokenPendingSecretRefChangeConflicts(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	object.Spec.SecretRef.Name = "other-credentials"
	if err := world.kube.Update(ctx, &object); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("secretRef drift should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.creates != 1 || api.rotates != 0 || api.updates != 0 || api.deletes != 0 {
		t.Fatalf("secretRef drift triggered a remote mutation: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("the pending remote token was mutated during the conflict")
	}
	var redirected corev1.Secret
	if err := world.kube.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "other-credentials"}, &redirected); err == nil && len(redirected.Data) != 0 {
		t.Fatalf("credential was written to the repointed destination: %#v", redirected.Data)
	}
}

// ST-QA-15: deleting the CR between the remote create and the credential
// capture must still clean up the pending remote token — the journal, not
// status.tokenId, carries the teardown provenance. A failing remote delete
// holds the finalizer with CleanupBlocked instead of leaking the token.
func TestServiceTokenPendingDeleteCleansRemote(t *testing.T) {
	ctx := context.Background()

	t.Run("journal cleans pending remote", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("pending delete reconcile: %v", err)
		}

		var gone v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
			t.Fatalf("ServiceToken still exists after pending delete: %v", err)
		}
		if _, found := api.tokens[remote.ID]; found {
			t.Fatalf("pending remote token %q leaked through deletion", remote.ID)
		}
		if api.deletes == 0 {
			t.Fatalf("pending remote token was never deleted: calls=%v", api.calls)
		}
	})

	t.Run("journal cleans pending remote without adding marker after delete", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)
		object.Finalizers = []string{v1alpha1.ServiceTokenFinalizer}
		if err := world.kube.Update(ctx, &object); err != nil {
			t.Fatal(err)
		}
		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		world.restart(&serviceTokenNoFinalizerAdditionOnDelete{Client: world.kube})
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("pending delete with stripped marker: %v", err)
		}
		var gone v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
			t.Fatalf("ServiceToken still exists after markerless pending delete: %v", err)
		}
		if _, found := api.tokens[remote.ID]; found {
			t.Fatalf("pending remote token %q leaked through markerless deletion", remote.ID)
		}
		if api.deletes == 0 {
			t.Fatalf("pending remote token was never deleted: calls=%v", api.calls)
		}
	})

	t.Run("failed remote delete keeps finalizer", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		api.deleteErr = fmt.Errorf("cloudflare returned 500 for service token deletion")
		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
			t.Fatal("pending delete unexpectedly succeeded while the remote delete fails")
		}

		var terminating v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &terminating); err != nil {
			t.Fatalf("terminating ServiceToken disappeared while the pending delete fails: %v", err)
		}
		if !controllerutil.ContainsFinalizer(&terminating, v1alpha1.ServiceTokenFinalizer) {
			t.Fatal("finalizer was removed while the pending remote delete fails")
		}
		if blocked := serviceTokenCondition(terminating.Status.Conditions, "CleanupBlocked"); blocked == nil || blocked.Status != metav1.ConditionTrue {
			t.Fatalf("pending delete failure did not report CleanupBlocked: %#v", terminating.Status.Conditions)
		}
		if _, found := api.tokens[remote.ID]; !found {
			t.Fatal("the pending remote token vanished while its delete was failing")
		}

		// Once the remote deletion succeeds the finalizer is released.
		api.deleteErr = nil
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("pending delete retry: %v", err)
		}
		var gone v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
			t.Fatalf("ServiceToken still exists after the pending remote delete succeeded: %v", err)
		}
		if _, found := api.tokens[remote.ID]; found {
			t.Fatalf("pending remote token %q survived the retried delete", remote.ID)
		}
	})
}

// ST-QA-16: once the status checkpoint landed, deleting the credential Secret
// out of band reports SecretMissing and never rotates or re-creates — the
// one-time credential cannot be recovered silently.
func TestServiceTokenEstablishedMissingSecretNeverRotates(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	issued := world.issueToken(ctx, t)

	credential := serviceTokenCredentialSecret(ctx, t, world)
	if err := world.kube.Delete(ctx, credential.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile after credential loss: %v", err)
	}

	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	ready := serviceTokenCondition(current.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "SecretMissing" {
		t.Fatalf("expected Ready=False/SecretMissing after credential loss: %#v", current.Status.Conditions)
	}
	if current.Status.TokenID != issued.Status.TokenID {
		t.Fatalf("credential loss rewrote the recorded token ID: %#v", current.Status)
	}
	if api.rotates != 0 || api.creates != 1 || api.deletes != 0 {
		t.Fatalf("established credential loss triggered an automatic rotation or recreate: calls=%v", api.calls)
	}
}

// ST-QA-19: ObserveOnly performs no remote mutation and no credential or
// journal write — including when an unresolved journal is left over from a
// managed attempt on the same object.
func TestServiceTokenObserveOnlyNeverMutates(t *testing.T) {
	ctx := context.Background()

	t.Run("observed remote only", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		api.tokens["external-1"] = flarecloudflare.ServiceToken{
			ID:        "external-1",
			ClientID:  "client-external-1",
			Name:      "flareway/cluster-id/tenant/token",
			Duration:  "8760h",
			Enabled:   true,
			ExpiresAt: serviceTokenBoundaryClock.Add(24 * time.Hour),
		}

		var object v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
			t.Fatal(err)
		}
		object.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		object.Spec.ExternalRef = &v1alpha1.ServiceTokenExternalReference{TokenID: "external-1"}
		if err := world.kube.Update(ctx, &object); err != nil {
			t.Fatal(err)
		}

		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("ObserveOnly reconcile: %v", err)
		}
		serviceTokenReady(ctx, t, world)
		if api.mutations() != 0 {
			t.Fatalf("ObserveOnly performed a remote mutation: calls=%v", api.calls)
		}
		if secret := serviceTokenDestinationSecret(ctx, t, world); secret != nil {
			t.Fatalf("ObserveOnly wrote the credential destination: %#v", secret)
		}
		if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object); err != nil || len(journals) != 0 {
			t.Fatalf("ObserveOnly wrote a journal Secret: %v %v", journals, err)
		}
	})

	t.Run("pending journal blocks observation", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		object.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
		object.Spec.ExternalRef = &v1alpha1.ServiceTokenExternalReference{TokenID: remote.ID}
		if err := world.kube.Update(ctx, &object); err != nil {
			t.Fatal(err)
		}
		calls := len(api.calls)

		world.restart(nil)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("ObserveOnly reconcile with pending journal: %v", err)
		}

		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready == nil || ready.Status == metav1.ConditionTrue {
			t.Fatalf("ObserveOnly reported Ready over an unresolved journal: %#v", current.Status.Conditions)
		}
		if len(api.calls) != calls {
			t.Fatalf("ObserveOnly with a pending journal called the remote API: calls=%v", api.calls[calls:])
		}
		if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
			t.Fatalf("ObserveOnly wrote credential data: %#v", secret)
		}
		if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &current); err != nil || len(journals) != 1 {
			t.Fatalf("ObserveOnly rewrote or reaped the pending journal: %v %v", journals, err)
		}
	})
}

// ST-QA-20: revoking the namespace grant denies the reconcile before any
// Cloudflare client call — fail closed with the remote untouched. The same
// hold applies while a create attempt is pending.
func TestServiceTokenGrantRevocationDeniesBeforeRemote(t *testing.T) {
	ctx := context.Background()

	revoke := func(t *testing.T, world *serviceTokenWorld) {
		t.Helper()
		var account v1alpha1.CloudflareAccount
		if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
			t.Fatal(err)
		}
		account.Spec.Grants = nil
		if err := world.kube.Update(ctx, &account); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("fresh create denied", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		revoke(t, world)

		if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
			t.Fatal("reconcile unexpectedly succeeded after the grant was revoked")
		}
		if len(api.calls) != 0 {
			t.Fatalf("Cloudflare API was called after the grant was revoked: %v", api.calls)
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready == nil || ready.Status == metav1.ConditionTrue {
			t.Fatalf("denied reconcile reported Ready: %#v", current.Status.Conditions)
		}
	})

	t.Run("pending attempt frozen", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)
		revoke(t, world)
		calls := len(api.calls)

		world.restart(nil)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
			t.Fatal("reconcile unexpectedly succeeded after the grant was revoked")
		}
		if len(api.calls) != calls {
			t.Fatalf("Cloudflare API was called for a pending attempt after revocation: %v", api.calls[calls:])
		}
		if _, found := api.tokens[remote.ID]; !found {
			t.Fatal("the pending remote token was mutated after revocation")
		}
		if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object); err != nil || len(journals) != 1 {
			t.Fatalf("the pending journal was touched after revocation: %v %v", journals, err)
		}
	})
}

// ST-QA-28: a CR deleted and recreated under the same name gets a fresh UID.
// The old journal binds the old UID, so the new CR must never adopt the old
// attempt — it proceeds with its own intent while the stale journal stays
// owned by the dead UID for GC.
func TestServiceTokenRecreatedCRUIDMismatch(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	object, remote := pendingServiceToken(ctx, t, world)
	oldJournal := boundaryServiceTokenJournal(ctx, t, world, &object)

	// Delete the CR outright (finalizer removed first) and drop the reserved
	// destination, as GC would; the foreign journal lingers.
	base := client.MergeFrom(object.DeepCopy())
	object.Finalizers = nil
	if err := world.kube.Patch(ctx, &object, base); err != nil {
		t.Fatal(err)
	}
	if err := world.kube.Delete(ctx, &object); err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	if err := world.kube.Delete(ctx, serviceTokenDestinationSecret(ctx, t, world)); err != nil {
		t.Fatal(err)
	}

	recreated := &v1alpha1.ServiceToken{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  object.Namespace,
			Name:       object.Name,
			UID:        types.UID("token-uid-new"),
			Finalizers: []string{v1alpha1.ServiceTokenFinalizer},
		},
		Spec: object.Spec,
	}
	if err := world.kube.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}

	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recreated CR reconcile: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if current.Status.TokenID == "" || current.Status.TokenID == remote.ID {
		t.Fatalf("recreated CR adopted the previous attempt's token: %#v", current.Status)
	}
	if api.deletes != 0 || api.rotates != 0 {
		t.Fatalf("the previous attempt's remote token was mutated by the new CR: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("the previous attempt's remote token disappeared")
	}
	var stale corev1.Secret
	if err := world.kube.Get(ctx, client.ObjectKeyFromObject(&oldJournal), &stale); err != nil {
		t.Fatalf("stale journal vanished instead of waiting for GC: %v", err)
	}
	if metav1.IsControlledBy(&stale, &current) {
		t.Fatal("the new CR adopted the previous UID's journal")
	}
}

// ST-QA-29: a journal that cannot be trusted — wiped contents or foreign
// ownership — fails closed: no remote mutation and no credential write.
func TestServiceTokenCorruptOrForeignJournalBlocks(t *testing.T) {
	ctx := context.Background()

	assertBlocked := func(t *testing.T, world *serviceTokenWorld, remote flarecloudflare.ServiceToken) {
		t.Helper()
		world.restart(nil)
		_, _ = world.reconciler.Reconcile(ctx, world.request)
		if api := world.api; api.rotates != 0 || api.updates != 0 || api.deletes != 0 || api.creates != 1 {
			t.Fatalf("untrusted journal triggered a remote mutation: calls=%v", api.calls)
		}
		if _, found := world.api.tokens[remote.ID]; !found {
			t.Fatal("the pending remote token was mutated behind an untrusted journal")
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			t.Fatalf("untrusted journal reached Ready: %#v", current.Status.Conditions)
		}
		if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
			t.Fatalf("credential was written behind an untrusted journal: %#v", secret)
		}
	}

	t.Run("corrupt journal", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		journal := boundaryServiceTokenJournal(ctx, t, world, &object)
		journal.Data = map[string][]byte{"phase": []byte("bogus")}
		if err := world.kube.Update(ctx, &journal); err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, world, remote)
	})

	t.Run("foreign journal", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		journal := boundaryServiceTokenJournal(ctx, t, world, &object)
		journal.OwnerReferences = nil
		if err := world.kube.Update(ctx, &journal); err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, world, remote)
	})
}

// ST-QA-30: deletionPolicy Orphan keeps the pending remote token — teardown
// releases the finalizer without attempting a remote delete.
func TestServiceTokenOrphanPendingDeleteKeepsRemote(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	object, remote := pendingServiceToken(ctx, t, world)

	object.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
	if err := world.kube.Update(ctx, &object); err != nil {
		t.Fatal(err)
	}
	if err := world.kube.Delete(ctx, &object); err != nil {
		t.Fatal(err)
	}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("orphan pending delete reconcile: %v", err)
	}

	var gone v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
		t.Fatalf("ServiceToken still exists after orphan delete: %v", err)
	}
	if api.deletes != 0 {
		t.Fatalf("orphan policy attempted a remote delete: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("orphaned remote token was deleted")
	}
}

// ST-QA-31: duration and enabled are mutable and not part of the journal
// binding — editing them while pending must not block recovery; the captured
// credential is kept and the remote is aligned before Ready.
func TestServiceTokenPendingMutableFieldChangeAligns(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	var object v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
		t.Fatal(err)
	}
	object.Spec.Duration = "720h"
	object.Spec.Enabled = false
	if err := world.kube.Update(ctx, &object); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("recovery reconcile after mutable field change: %v", err)
	}
	current := serviceTokenReady(ctx, t, world)
	if current.Status.TokenID != remote.ID {
		t.Fatalf("recovery rebound to a different token: before=%q after=%q", remote.ID, current.Status.TokenID)
	}
	observed := api.tokens[remote.ID]
	if observed.Duration != "720h" || observed.Enabled {
		t.Fatalf("mutable fields were not aligned on the recovered token: %#v", observed)
	}
	canonical, err := accessRemoteName(ctx, world.kube, "tenant", "token")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Name != canonical {
		t.Fatalf("recovered token was not normalized to the canonical name: %q", observed.Name)
	}
	if api.creates != 1 || api.deletes != 0 {
		t.Fatalf("mutable field drift caused a recreate: calls=%v", api.calls)
	}
}

// ST-QA-32: switching the account identity under a pending attempt breaks the
// journal binding — the attempt fails closed and neither account is mutated.
func TestServiceTokenPendingAccountDriftConflicts(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	_, remote := pendingServiceToken(ctx, t, world)

	var account v1alpha1.CloudflareAccount
	if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	account.Spec.AccountID = "ffffffffffffffffffffffffffffffff"
	if err := world.kube.Update(ctx, &account); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("account drift should surface as a status Conflict, not an error: %v", err)
	}
	serviceTokenConflict(ctx, t, world)
	if api.rotates != 0 || api.updates != 0 || api.deletes != 0 || api.creates != 1 {
		t.Fatalf("account drift triggered a remote mutation: calls=%v", api.calls)
	}
	if _, found := api.tokens[remote.ID]; !found {
		t.Fatal("the pending remote token was mutated during the account conflict")
	}
}

// ST-QA-33: a destination holding only the reservation marker — or a partial
// credential missing the client secret — never satisfies the committed
// predicate, so Ready is impossible until a full credential is captured.
func TestServiceTokenPartialCredentialNeverReady(t *testing.T) {
	ctx := context.Background()

	t.Run("reserved empty destination", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		_, remote := pendingServiceToken(ctx, t, world)

		// The reserved destination carries no credential; while rotation is
		// still failing the object must not report Ready.
		api.rotateErr = fmt.Errorf("cloudflare returned 500 for service token rotation")
		world.restart(nil)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
			t.Fatal("reconcile unexpectedly succeeded while rotation fails")
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			t.Fatalf("reserved-but-empty destination reported Ready: %#v", current.Status.Conditions)
		}

		api.rotateErr = nil
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("recovery reconcile: %v", err)
		}
		current = serviceTokenReady(ctx, t, world)
		secret := serviceTokenCredentialSecret(ctx, t, world)
		if len(secret.Data[v1alpha1.ServiceTokenClientIDKey]) == 0 ||
			len(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) == 0 ||
			secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] != remote.ID {
			t.Fatalf("Ready was reported without a complete committed credential: %#v", secret)
		}
	})

	t.Run("partial credential", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		_, remote := pendingServiceToken(ctx, t, world)

		// A credential missing the client secret is not committed.
		destination := serviceTokenDestinationSecret(ctx, t, world)
		destination.Data = map[string][]byte{v1alpha1.ServiceTokenClientIDKey: []byte("client-partial")}
		destination.Annotations[v1alpha1.ServiceTokenIDAnnotation] = remote.ID
		if err := world.kube.Update(ctx, destination); err != nil {
			t.Fatal(err)
		}

		api.rotateErr = fmt.Errorf("cloudflare returned 500 for service token rotation")
		world.restart(nil)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
			t.Fatal("reconcile unexpectedly succeeded while rotation fails")
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			t.Fatalf("partial credential reported Ready: %#v", current.Status.Conditions)
		}

		api.rotateErr = nil
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("recovery reconcile: %v", err)
		}
		serviceTokenReady(ctx, t, world)
		secret := serviceTokenCredentialSecret(ctx, t, world)
		if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[remote.ID] {
			t.Fatal("the partial credential was treated as committed instead of being rotated")
		}
	})
}

// ST-QA-34: deleting a pending CR whose journal was lost must fail closed.
// The CR-UID attempt prefix detects the untracked remote but is never
// ownership proof, so teardown reports CleanupBlocked and keeps the
// finalizer — it never deletes a prefix match and never drops the finalizer
// while an unverified pending remote may exist.
func TestServiceTokenJournallessPendingDeleteFailsClosed(t *testing.T) {
	ctx := context.Background()

	assertBlocked := func(t *testing.T, world *serviceTokenWorld, api *serviceTokenFakeAPI, deletesBefore int) {
		t.Helper()
		var terminating v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &terminating); err != nil {
			t.Fatalf("terminating ServiceToken disappeared with an unverified pending remote: %v", err)
		}
		if !controllerutil.ContainsFinalizer(&terminating, v1alpha1.ServiceTokenFinalizer) {
			t.Fatal("finalizer was removed while an unverified pending remote may exist")
		}
		if blocked := serviceTokenCondition(terminating.Status.Conditions, "CleanupBlocked"); blocked == nil || blocked.Status != metav1.ConditionTrue {
			t.Fatalf("journal-less pending delete did not report CleanupBlocked: %#v", terminating.Status.Conditions)
		}
		if api.deletes != deletesBefore {
			t.Fatalf("prefix-matched remote tokens were deleted without journal provenance: calls=%v", api.calls)
		}
	}

	t.Run("single prefix match is not deleted", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		journal := boundaryServiceTokenJournal(ctx, t, world, &object)
		if err := world.kube.Delete(ctx, &journal); err != nil {
			t.Fatal(err)
		}
		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		_, _ = world.reconciler.Reconcile(ctx, world.request)

		assertBlocked(t, world, api, 0)
		if _, found := api.tokens[remote.ID]; !found {
			t.Fatal("the unverified pending remote was deleted without journal provenance")
		}
	})

	t.Run("ambiguous prefix matches are not deleted", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		duplicate := remote
		duplicate.ID = "token-duplicate"
		duplicate.Name = remote.Name + "-dup"
		api.tokens[duplicate.ID] = duplicate

		journal := boundaryServiceTokenJournal(ctx, t, world, &object)
		if err := world.kube.Delete(ctx, &journal); err != nil {
			t.Fatal(err)
		}
		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		_, _ = world.reconciler.Reconcile(ctx, world.request)

		assertBlocked(t, world, api, 0)
		if len(api.tokens) != 2 {
			t.Fatalf("unverified pending remotes were deleted: %v", api.tokens)
		}
	})

	t.Run("unresolvable scope keeps finalizer", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newZoneBoundaryWorld(t, api)
		object, remote := pendingServiceToken(ctx, t, world)

		journal := boundaryServiceTokenJournal(ctx, t, world, &object)
		if err := world.kube.Delete(ctx, &journal); err != nil {
			t.Fatal(err)
		}
		// The zone verification flaps away, so the pending scope cannot be
		// resolved — still no permission to drop the finalizer.
		var account v1alpha1.CloudflareAccount
		if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
			t.Fatal(err)
		}
		account.Status.Verified.Zones = nil
		if err := world.kube.Update(ctx, &account); err != nil {
			t.Fatal(err)
		}
		if err := world.kube.Delete(ctx, &object); err != nil {
			t.Fatal(err)
		}
		_, _ = world.reconciler.Reconcile(ctx, world.request)

		assertBlocked(t, world, api, 0)
		if _, found := api.tokens["zone:zone-1/"+remote.ID]; !found {
			t.Fatal("the unverified pending zone remote was deleted without journal provenance")
		}
	})
}

// ST-QA-38: a verified-zone status flap — the zone disappears from
// status.verified.zones while spec.zone and the account identity are
// unchanged — must not strand a pending attempt: the journaled zone binding
// resumes after normal grant authorization.
func TestServiceTokenZoneVerificationFlapResumes(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newZoneBoundaryWorld(t, api)
	object, remote := pendingServiceToken(ctx, t, world)
	if remote.ID == "" {
		t.Fatal("pending zone token was never created")
	}

	// The zone verification flaps: the zone is temporarily absent from the
	// account's verified list while spec.zone is untouched.
	var account v1alpha1.CloudflareAccount
	if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	account.Status.Verified.Zones = nil
	if err := world.kube.Update(ctx, &account); err != nil {
		t.Fatal(err)
	}

	world.restart(nil)
	// Zone recovery retires the stranded token first, then creates the
	// replacement once the deletion is confirmed — two passes.
	for i := 0; i < 3; i++ {
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("zone recovery reconcile %d: %v", i, err)
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			break
		}
		if i == 2 {
			t.Fatalf("zone recovery did not converge after the verification flap: %#v", current.Status.Conditions)
		}
	}
	current := serviceTokenReady(ctx, t, world)
	if current.Status.TokenID == "" || current.Status.TokenID == remote.ID {
		t.Fatalf("zone recovery kept the credential-less token: %#v", current.Status)
	}
	if api.rotates != 0 {
		t.Fatalf("zone scope attempted an unsupported rotate: calls=%v", api.calls)
	}
	if len(api.tokens) != 1 {
		t.Fatalf("zone recovery did not converge to exactly one token: %v", api.tokens)
	}
	_ = object
}

// ST-QA-39: a journal that outlives the status checkpoint is reap-only. When
// the destination Secret is later deleted, the object reports SecretMissing —
// the stale journal never grounds a resume or rotation.
func TestServiceTokenStaleJournalAfterCheckpointIsReapOnly(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)

	// Fail the journal reap once so the journal survives the checkpoint.
	world.restart(&serviceTokenJournalDeleteBlocker{Client: world.kube, credentialName: "token-credentials"})
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while the journal delete fails")
	}
	var issued v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &issued); err != nil {
		t.Fatal(err)
	}
	if ready := serviceTokenCondition(issued.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("status checkpoint did not land before the failed journal reap: %#v", issued.Status.Conditions)
	}
	if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &issued); err != nil || len(journals) != 1 {
		t.Fatalf("expected the stale journal to survive the checkpoint: %v %v", journals, err)
	}

	world.restart(nil)
	credential := serviceTokenCredentialSecret(ctx, t, world)
	if err := world.kube.Delete(ctx, credential.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
		t.Fatalf("reconcile with stale journal and missing destination: %v", err)
	}

	var current v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	ready := serviceTokenCondition(current.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "SecretMissing" {
		t.Fatalf("stale journal turned credential loss into something other than SecretMissing: %#v", current.Status.Conditions)
	}
	if current.Status.TokenID != issued.Status.TokenID {
		t.Fatalf("stale journal rebound the token ID: %#v", current.Status)
	}
	if api.rotates != 0 || api.creates != 1 || api.deletes != 0 {
		t.Fatalf("stale journal grounded a rotation or recreate: calls=%v", api.calls)
	}
}

// ST-QA-41: non-managed paths — AdoptById and an established token — never
// create a journal or a destination reservation. (ObserveOnly is covered by
// TestServiceTokenObserveOnlyNeverMutates.)
func TestServiceTokenNonManagedPathsSkipJournal(t *testing.T) {
	ctx := context.Background()

	t.Run("AdoptById", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		api.tokens["adopted-1"] = flarecloudflare.ServiceToken{
			ID:        "adopted-1",
			ClientID:  "client-adopted-1",
			Name:      "flareway/cluster-id/tenant/token",
			Duration:  "8760h",
			Enabled:   true,
			ExpiresAt: serviceTokenBoundaryClock.Add(24 * time.Hour),
		}

		var object v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
			t.Fatal(err)
		}
		object.Spec.Adoption.Mode = v1alpha1.AdoptionModeAdoptByID
		object.Spec.ExternalRef = &v1alpha1.ServiceTokenExternalReference{TokenID: "adopted-1"}
		if err := world.kube.Update(ctx, &object); err != nil {
			t.Fatal(err)
		}
		// Adoption never writes credentials; the destination must already be
		// owned by this ServiceToken.
		if err := world.kube.Create(ctx, serviceTokenOwnedSecret(&object, "token-credentials")); err != nil {
			t.Fatal(err)
		}

		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("adopt reconcile: %v", err)
		}
		serviceTokenReady(ctx, t, world)
		if api.mutations() != 0 {
			t.Fatalf("adoption performed a remote mutation: calls=%v", api.calls)
		}
		if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object); err != nil || len(journals) != 0 {
			t.Fatalf("adoption created a journal Secret: %v %v", journals, err)
		}
		if secret := serviceTokenDestinationSecret(ctx, t, world); secret == nil || len(secret.Data) != 0 {
			t.Fatalf("adoption wrote credential data: %#v", secret)
		}
	})

	t.Run("established", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		issued := world.issueToken(ctx, t)

		var object v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &object); err != nil {
			t.Fatal(err)
		}
		if journals, err := serviceTokenJournalSecrets(ctx, world.kube, &object); err != nil || len(journals) != 0 {
			t.Fatalf("journal survived convergence: %v %v", journals, err)
		}
		calls := len(api.calls)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("steady-state reconcile: %v", err)
		}
		for _, call := range api.calls[calls:] {
			if !strings.HasPrefix(call, "get:") && call != "list" {
				t.Fatalf("established token performed a remote mutation: %v", api.calls[calls:])
			}
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if current.Status.TokenID != issued.Status.TokenID {
			t.Fatalf("steady-state reconcile rewrote the token ID: %#v", current.Status)
		}
	})
}

// RuntimeReview follow-up to the matrix: when the credential destination is
// deleted while an attempt is pending, recovery must re-reserve the owned
// destination before rotating — one rotation, one valid credential — and a
// foreign or immutable destination must block before any remote mutation.
func TestServiceTokenPendingDestinationRecreatedBeforeRotate(t *testing.T) {
	ctx := context.Background()

	t.Run("deleted destination is re-reserved", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		_, remote := pendingServiceToken(ctx, t, world)

		if err := world.kube.Delete(ctx, serviceTokenDestinationSecret(ctx, t, world)); err != nil {
			t.Fatal(err)
		}
		world.restart(nil)
		for i := 0; i < 3; i++ {
			if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
				t.Fatalf("recovery reconcile %d: %v", i, err)
			}
			var current v1alpha1.ServiceToken
			if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
				t.Fatal(err)
			}
			if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
				break
			}
			if i == 2 {
				t.Fatalf("recovery never re-reserved the deleted destination: %#v", current.Status.Conditions)
			}
		}
		if api.rotates != 1 {
			t.Fatalf("recovery rotated %d times for one missing destination — the rotate must follow the reservation: calls=%v", api.rotates, api.calls)
		}
		secret := serviceTokenCredentialSecret(ctx, t, world)
		if string(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) != api.secrets[remote.ID] ||
			secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] != remote.ID {
			t.Fatalf("re-reserved destination does not hold the rotated credential: %#v", secret)
		}
	})

	t.Run("foreign destination blocks before rotate", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		_, remote := pendingServiceToken(ctx, t, world)

		if err := world.kube.Delete(ctx, serviceTokenDestinationSecret(ctx, t, world)); err != nil {
			t.Fatal(err)
		}
		foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "token-credentials"}}
		if err := world.kube.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}

		world.restart(nil)
		_, _ = world.reconciler.Reconcile(ctx, world.request)
		serviceTokenConflict(ctx, t, world)
		if api.rotates != 0 || api.creates != 1 || api.deletes != 0 {
			t.Fatalf("foreign destination did not block before the rotate: calls=%v", api.calls)
		}
		if _, found := api.tokens[remote.ID]; !found {
			t.Fatal("the pending remote token was mutated behind a foreign destination")
		}
	})

	t.Run("immutable destination blocks before rotate", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		object, remote := pendingServiceToken(ctx, t, world)

		if err := world.kube.Delete(ctx, serviceTokenDestinationSecret(ctx, t, world)); err != nil {
			t.Fatal(err)
		}
		immutable := serviceTokenOwnedSecret(&object, "token-credentials")
		immutable.Immutable = ptr.To(true)
		if err := world.kube.Create(ctx, immutable); err != nil {
			t.Fatal(err)
		}

		world.restart(&serviceTokenImmutableAwareClient{Client: world.kube})
		_, _ = world.reconciler.Reconcile(ctx, world.request)

		if api.rotates != 0 || api.creates != 1 || api.deletes != 0 {
			t.Fatalf("immutable destination did not block before the rotate: calls=%v", api.calls)
		}
		if _, found := api.tokens[remote.ID]; !found {
			t.Fatal("the pending remote token was mutated behind an immutable destination")
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if ready := serviceTokenCondition(current.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
			t.Fatalf("immutable destination reported Ready: %#v", current.Status.Conditions)
		}
	})
}

// ST-QA-42/43/46: a ServiceToken that never created a remote token must not
// attempt cleanup when its zone/account scope is invalid or absent. The
// markerless legacy empty-status path is intentionally shared with QA-46.
func TestServiceTokenNeverCreatedDeletionSkipsRemoteMutation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(*serviceTokenWorld)
	}{
		{
			name: "invalid zone",
			setup: func(world *serviceTokenWorld) {
				var token v1alpha1.ServiceToken
				if err := world.kube.Get(ctx, world.request.NamespacedName, &token); err != nil {
					t.Fatal(err)
				}
				token.Spec.Zone = "missing.example.test"
				if err := world.kube.Update(ctx, &token); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing account",
			setup: func(world *serviceTokenWorld) {
				var token v1alpha1.ServiceToken
				if err := world.kube.Get(ctx, world.request.NamespacedName, &token); err != nil {
					t.Fatal(err)
				}
				token.Spec.AccountRef.Name = "missing-account"
				if err := world.kube.Update(ctx, &token); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "revoked grant",
			setup: func(world *serviceTokenWorld) {
				var account v1alpha1.CloudflareAccount
				if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
					t.Fatal(err)
				}
				account.Spec.Grants = nil
				if err := world.kube.Update(ctx, &account); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newServiceTokenBoundaryAPI()
			world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
			tc.setup(world)
			var token v1alpha1.ServiceToken
			if err := world.kube.Get(ctx, world.request.NamespacedName, &token); err != nil {
				t.Fatal(err)
			}
			if err := world.kube.Delete(ctx, &token); err != nil {
				t.Fatal(err)
			}
			if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
				t.Fatalf("delete reconcile: %v", err)
			}
			var gone v1alpha1.ServiceToken
			if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
				t.Fatalf("never-created ServiceToken was not deleted: err=%v object=%#v", err, gone)
			}
			if api.mutations() != 0 || len(api.calls) != 0 {
				t.Fatalf("never-created deletion touched Cloudflare: calls=%v", api.calls)
			}
		})
	}
}

// ST-QA-44: the attempt marker is durable before journal creation. If journal
// creation fails, later scope loss must retain the finalizer and never guess
// at a remote token.
func TestServiceTokenAttemptMarkerProtectsJournalCreateFailure(t *testing.T) {
	ctx := context.Background()
	api := newServiceTokenBoundaryAPI()
	world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
	world.restart(&serviceTokenFaultClient{
		Client: world.kube, credentialName: "token-credentials", failJournalWriteAt: 1,
	})
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("reconcile unexpectedly succeeded while journal creation fails")
	}
	var pending v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &pending); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(&pending, serviceTokenAttemptFinalizer) {
		t.Fatalf("journal-create failure lost the attempt marker: %#v", pending.Finalizers)
	}
	var account v1alpha1.CloudflareAccount
	if err := world.kube.Get(ctx, types.NamespacedName{Name: world.account.Name}, &account); err != nil {
		t.Fatal(err)
	}
	account.Spec.Grants = nil
	if err := world.kube.Update(ctx, &account); err != nil {
		t.Fatal(err)
	}
	if err := world.kube.Delete(ctx, &pending); err != nil {
		t.Fatal(err)
	}
	world.restart(nil)
	if _, err := world.reconciler.Reconcile(ctx, world.request); err == nil {
		t.Fatal("blocked deletion unexpectedly succeeded")
	}
	var blocked v1alpha1.ServiceToken
	if err := world.kube.Get(ctx, world.request.NamespacedName, &blocked); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(&blocked, v1alpha1.ServiceTokenFinalizer) ||
		!controllerutil.ContainsFinalizer(&blocked, serviceTokenAttemptFinalizer) {
		t.Fatalf("protected deletion lost finalizers: %#v", blocked.Finalizers)
	}
	if condition := serviceTokenCondition(blocked.Status.Conditions, "CleanupBlocked"); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("deletion did not report CleanupBlocked: %#v", blocked.Status.Conditions)
	}
	if api.mutations() != 0 {
		t.Fatalf("blocked deletion mutated Cloudflare: calls=%v", api.calls)
	}
}

// ST-QA-45: a leftover attempt marker is harmless after a healthy checkpoint,
// but must still be honored during teardown. Missing credentials in this
// established state never rotate the token.
func TestServiceTokenAttemptMarkerCleanupAndSteadyState(t *testing.T) {
	ctx := context.Background()
	t.Run("healthy deletion removes both markers", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		issued := world.issueToken(ctx, t)
		issued.Finalizers = append(issued.Finalizers, serviceTokenAttemptFinalizer)
		if err := world.kube.Update(ctx, &issued); err != nil {
			t.Fatal(err)
		}
		if err := world.kube.Delete(ctx, &issued); err != nil {
			t.Fatal(err)
		}
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("delete reconcile: %v", err)
		}
		var gone v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &gone); !apierrors.IsNotFound(err) {
			t.Fatalf("healthy ServiceToken was not deleted: err=%v object=%#v", err, gone)
		}
		if api.deletes != 1 || len(api.tokens) != 0 {
			t.Fatalf("healthy teardown did not remove remote token: calls=%v tokens=%v", api.calls, api.tokens)
		}
	})
	t.Run("leftover marker does not rotate on missing credential", func(t *testing.T) {
		api := newServiceTokenBoundaryAPI()
		world := newServiceTokenWorld(t, api, serviceTokenBoundaryClock)
		issued := world.issueToken(ctx, t)
		issued.Finalizers = append(issued.Finalizers, serviceTokenAttemptFinalizer)
		if err := world.kube.Update(ctx, &issued); err != nil {
			t.Fatal(err)
		}
		credential := serviceTokenCredentialSecret(ctx, t, world)
		if err := world.kube.Delete(ctx, &credential); err != nil {
			t.Fatal(err)
		}
		before := api.mutations()
		world.restart(nil)
		if _, err := world.reconciler.Reconcile(ctx, world.request); err != nil {
			t.Fatalf("steady-state reconcile: %v", err)
		}
		if api.mutations() != before || api.rotates != 0 || api.creates != 1 {
			t.Fatalf("leftover marker triggered rotation: calls=%v", api.calls)
		}
		var current v1alpha1.ServiceToken
		if err := world.kube.Get(ctx, world.request.NamespacedName, &current); err != nil {
			t.Fatal(err)
		}
		if current.Status.TokenID != issued.Status.TokenID {
			t.Fatalf("steady-state reconcile changed token identity: %#v", current.Status)
		}
	})
}
