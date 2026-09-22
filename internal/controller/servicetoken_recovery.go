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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// Durable create-intent journal. A managed fresh create records its intent in a
// controller-owned Secret before the remote CREATE so a crash between the
// remote call and the credential write can be recovered with provenance instead
// of a blind re-create. All keys and phases are private to this package.
const (
	serviceTokenJournalPrefix = "flareway-st-intent-"

	serviceTokenJournalKeyPhase        = "phase"
	serviceTokenJournalKeyCRUID        = "crUID"
	serviceTokenJournalKeyClusterUID   = "clusterUID"
	serviceTokenJournalKeyAccountName  = "accountName"
	serviceTokenJournalKeyAccountUID   = "accountUID"
	serviceTokenJournalKeyAccountID    = "accountID"
	serviceTokenJournalKeySpecZone     = "specZone"
	serviceTokenJournalKeyZoneID       = "zoneID"
	serviceTokenJournalKeySpecName     = "specName"
	serviceTokenJournalKeyDestination  = "destination"
	serviceTokenJournalKeyNonce        = "nonce"
	serviceTokenJournalKeyAttemptName  = "attemptName"
	serviceTokenJournalKeyIssuedID     = "issuedID"
	serviceTokenJournalKeyRetiringID   = "retiringID"
	serviceTokenJournalKeyRetiringName = "retiringName"

	serviceTokenJournalPhasePrepared   = "prepared"
	serviceTokenJournalPhaseDispatched = "dispatched"
	serviceTokenJournalPhaseRetiring   = "retiring"

	// serviceTokenReservedForAnnotation marks a destination Secret that was
	// reserved by a pending create attempt and carries no credential yet.
	serviceTokenReservedForAnnotation = "flareway.bhyoo.com/service-token-reserved-for"

	// serviceTokenAttemptFinalizer protects a create attempt before its journal
	// exists, including the narrow crash window between the two writes.
	serviceTokenAttemptFinalizer = "flareway.bhyoo.com/service-token-attempt"

	// serviceTokenAttemptNameMaxLength bounds the remote attempt name so the
	// deterministic prefix plus nonce stays within provider name limits.
	serviceTokenAttemptNameMaxLength = 200
)

var (
	// errServiceTokenJournalForeign marks a journal Secret that is not
	// controlled by this ServiceToken; callers surface it as a Conflict.
	errServiceTokenJournalForeign = errors.New("service token journal is not controlled by this ServiceToken")
	// errServiceTokenDestinationForeign marks a credential destination Secret
	// that exists but is not controlled by this ServiceToken.
	errServiceTokenDestinationForeign = errors.New("service token destination Secret is not controlled by this ServiceToken")
)

// serviceTokenJournal is the decoded durable record of one create attempt.
type serviceTokenJournal struct {
	phase        string
	crUID        string
	clusterUID   string
	accountName  string
	accountUID   string
	accountID    string
	specZone     string
	zoneID       string
	specName     string
	destination  string
	nonce        string
	attemptName  string
	issuedID     string
	retiringID   string
	retiringName string
}

func serviceTokenJournalName(object *v1alpha1.ServiceToken) string {
	return serviceTokenJournalPrefix + string(object.UID)
}

// serviceTokenAttemptPrefix scopes remote discovery to tokens this CR started.
func serviceTokenAttemptPrefix(clusterID string, object *v1alpha1.ServiceToken) string {
	return fmt.Sprintf("flareway/%s/%s/%s/", clusterID, object.Namespace, object.UID)
}

// serviceTokenAttemptName builds the remote name for one create attempt: the
// deterministic CR UID prefix, the (truncated) spec name, and the attempt nonce.
func serviceTokenAttemptName(clusterID string, object *v1alpha1.ServiceToken, nonce string) string {
	prefix := serviceTokenAttemptPrefix(clusterID, object)
	budget := serviceTokenAttemptNameMaxLength - len(prefix) - len(nonce) - 1
	specName := object.Spec.Name
	if budget < 0 {
		budget = 0
	}
	if len(specName) > budget {
		specName = specName[:budget]
	}
	return prefix + specName + "-" + nonce
}

func newServiceTokenNonce() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate service token attempt nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// apiReader returns the authoritative reader used for journal and credential
// readback. SetupWithManager self-initializes it; standalone tests may leave it
// nil, in which case the primary client is used.
func (r *ServiceTokenReconciler) apiReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}
func (r *ServiceTokenReconciler) ensureServiceTokenAttemptFinalizer(ctx context.Context, object *v1alpha1.ServiceToken) error {
	if controllerutil.ContainsFinalizer(object, serviceTokenAttemptFinalizer) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.AddFinalizer(object, serviceTokenAttemptFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *ServiceTokenReconciler) removeServiceTokenAttemptFinalizer(ctx context.Context, object *v1alpha1.ServiceToken) error {
	if !controllerutil.ContainsFinalizer(object, serviceTokenAttemptFinalizer) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, serviceTokenAttemptFinalizer)
	return r.Patch(ctx, object, base)
}

// authoritativeClusterID reads the kube-system Namespace UID through the
// authoritative reader. Recovery and journaling fail closed when it is
// unavailable or empty rather than minting names under an empty cluster ID.
func (r *ServiceTokenReconciler) authoritativeClusterID(ctx context.Context) (string, error) {
	namespace := new(corev1.Namespace)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Name: "kube-system"}, namespace); err != nil {
		return "", fmt.Errorf("read cluster ID from kube-system Namespace UID: %w", err)
	}
	if namespace.UID == "" {
		return "", errors.New("kube-system Namespace has no UID")
	}
	return string(namespace.UID), nil
}

// loadServiceTokenJournal reads the journal Secret authoritatively. A missing
// journal returns (nil, nil, nil); a foreign-owned journal returns
// errServiceTokenJournalForeign.
func (r *ServiceTokenReconciler) loadServiceTokenJournal(ctx context.Context, object *v1alpha1.ServiceToken) (*corev1.Secret, *serviceTokenJournal, error) {
	secret := new(corev1.Secret)
	key := types.NamespacedName{Namespace: object.Namespace, Name: serviceTokenJournalName(object)}
	if err := r.apiReader().Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if !metav1.IsControlledBy(secret, object) {
		return nil, nil, errServiceTokenJournalForeign
	}
	return secret, decodeServiceTokenJournal(secret), nil
}

func decodeServiceTokenJournal(secret *corev1.Secret) *serviceTokenJournal {
	data := secret.Data
	return &serviceTokenJournal{
		phase:        string(data[serviceTokenJournalKeyPhase]),
		crUID:        string(data[serviceTokenJournalKeyCRUID]),
		clusterUID:   string(data[serviceTokenJournalKeyClusterUID]),
		accountName:  string(data[serviceTokenJournalKeyAccountName]),
		accountUID:   string(data[serviceTokenJournalKeyAccountUID]),
		accountID:    string(data[serviceTokenJournalKeyAccountID]),
		specZone:     string(data[serviceTokenJournalKeySpecZone]),
		zoneID:       string(data[serviceTokenJournalKeyZoneID]),
		specName:     string(data[serviceTokenJournalKeySpecName]),
		destination:  string(data[serviceTokenJournalKeyDestination]),
		nonce:        string(data[serviceTokenJournalKeyNonce]),
		attemptName:  string(data[serviceTokenJournalKeyAttemptName]),
		issuedID:     string(data[serviceTokenJournalKeyIssuedID]),
		retiringID:   string(data[serviceTokenJournalKeyRetiringID]),
		retiringName: string(data[serviceTokenJournalKeyRetiringName]),
	}
}

func (journal *serviceTokenJournal) data() map[string][]byte {
	return map[string][]byte{
		serviceTokenJournalKeyPhase:        []byte(journal.phase),
		serviceTokenJournalKeyCRUID:        []byte(journal.crUID),
		serviceTokenJournalKeyClusterUID:   []byte(journal.clusterUID),
		serviceTokenJournalKeyAccountName:  []byte(journal.accountName),
		serviceTokenJournalKeyAccountUID:   []byte(journal.accountUID),
		serviceTokenJournalKeyAccountID:    []byte(journal.accountID),
		serviceTokenJournalKeySpecZone:     []byte(journal.specZone),
		serviceTokenJournalKeyZoneID:       []byte(journal.zoneID),
		serviceTokenJournalKeySpecName:     []byte(journal.specName),
		serviceTokenJournalKeyDestination:  []byte(journal.destination),
		serviceTokenJournalKeyNonce:        []byte(journal.nonce),
		serviceTokenJournalKeyAttemptName:  []byte(journal.attemptName),
		serviceTokenJournalKeyIssuedID:     []byte(journal.issuedID),
		serviceTokenJournalKeyRetiringID:   []byte(journal.retiringID),
		serviceTokenJournalKeyRetiringName: []byte(journal.retiringName),
	}
}

// matchesSpecIdentity reports whether the journal's immutable identity tuple
// still matches the live spec and account. A spec.zone/accountRef edit during a
// pending attempt changes identity and must fail closed; a verified-zone status
// flap does not (specZone is unchanged, so the journaled zoneID may resume).
func (journal *serviceTokenJournal) matchesSpecIdentity(object *v1alpha1.ServiceToken, account *v1alpha1.CloudflareAccount) bool {
	return journal.crUID == string(object.UID) &&
		journal.accountName == object.Spec.AccountRef.Name &&
		journal.accountUID == string(account.UID) &&
		journal.accountID == account.Spec.AccountID &&
		journal.specZone == object.Spec.Zone &&
		journal.specName == object.Spec.Name &&
		journal.destination == object.Spec.SecretRef.Name
}

// matchesIdentity additionally binds the cluster UID; used before any remote
// recovery mutation.
func (journal *serviceTokenJournal) matchesIdentity(object *v1alpha1.ServiceToken, account *v1alpha1.CloudflareAccount, clusterID string) bool {
	return journal.matchesSpecIdentity(object, account) && journal.clusterUID == clusterID
}

// createServiceTokenJournal persists a fresh prepared journal. AlreadyExists is
// returned to the caller so the next pass resumes through the journal path.
func (r *ServiceTokenReconciler) createServiceTokenJournal(ctx context.Context, object *v1alpha1.ServiceToken, account *v1alpha1.CloudflareAccount, scope flarecloudflare.AccessScope, clusterID, nonce string) (*corev1.Secret, *serviceTokenJournal, error) {
	journal := &serviceTokenJournal{
		phase:       serviceTokenJournalPhasePrepared,
		crUID:       string(object.UID),
		clusterUID:  clusterID,
		accountName: object.Spec.AccountRef.Name,
		accountUID:  string(account.UID),
		accountID:   account.Spec.AccountID,
		specZone:    object.Spec.Zone,
		zoneID:      scope.ZoneID,
		specName:    object.Spec.Name,
		destination: object.Spec.SecretRef.Name,
		nonce:       nonce,
		attemptName: serviceTokenAttemptName(clusterID, object, nonce),
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: serviceTokenJournalName(object)}}
	if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
		return nil, nil, err
	}
	secret.Type = corev1.SecretTypeOpaque
	secret.Data = journal.data()
	if err := r.Create(ctx, secret); err != nil {
		return nil, nil, err
	}
	return secret, journal, nil
}

// persistServiceTokenJournal writes the journal state back with a versioned
// update against the object that was read or created this pass.
func (r *ServiceTokenReconciler) persistServiceTokenJournal(ctx context.Context, secret *corev1.Secret, journal *serviceTokenJournal) error {
	secret.Data = journal.data()
	return r.Update(ctx, secret)
}

// committedServiceTokenCredential reads the destination Secret authoritatively
// and returns the recorded token ID only when the full credential predicate is
// committed: non-empty client ID, client secret, and token-id annotation. A
// reserved-but-empty Secret or a partial credential does not qualify.
func (r *ServiceTokenReconciler) committedServiceTokenCredential(ctx context.Context, object *v1alpha1.ServiceToken) (string, error) {
	secret := new(corev1.Secret)
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}
	if err := r.apiReader().Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	if !metav1.IsControlledBy(secret, object) {
		return "", errServiceTokenDestinationForeign
	}
	if len(secret.Data[v1alpha1.ServiceTokenClientIDKey]) == 0 ||
		len(secret.Data[v1alpha1.ServiceTokenClientSecretKey]) == 0 {
		return "", nil
	}
	return secret.Annotations[v1alpha1.ServiceTokenIDAnnotation], nil
}

// reserveServiceTokenDestination claims the credential destination with an
// empty controller-owned Secret before any remote mutation. An existing Secret
// is re-checked authoritatively, must be controlled by this ServiceToken and
// mutable, and must accept a versioned metadata Update — the same write the
// credential commit performs — so an unwritable destination blocks before any
// remote create or rotate. Foreign or unwritable destinations fail closed with
// errServiceTokenDestinationForeign.
func (r *ServiceTokenReconciler) reserveServiceTokenDestination(ctx context.Context, object *v1alpha1.ServiceToken) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}}
	if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
		return err
	}
	secret.Type = corev1.SecretTypeOpaque
	secret.Annotations = map[string]string{serviceTokenReservedForAnnotation: string(object.UID)}
	err := r.Create(ctx, secret)
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	existing := new(corev1.Secret)
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}
	if getErr := r.apiReader().Get(ctx, key, existing); getErr != nil {
		return getErr
	}
	if !metav1.IsControlledBy(existing, object) {
		return errServiceTokenDestinationForeign
	}
	if existing.Immutable != nil && *existing.Immutable {
		return errServiceTokenDestinationForeign
	}
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[serviceTokenReservedForAnnotation] = string(object.UID)
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("service token destination Secret %s/%s is not writable: %w", key.Namespace, key.Name, err)
	}
	return nil
}

// writeInitialSecret commits the one-time credential onto the reserved
// destination with a fresh authoritative read and a versioned update.
func (r *ServiceTokenReconciler) writeInitialSecret(ctx context.Context, object *v1alpha1.ServiceToken, tokenID, clientID, clientSecret string) error {
	secret := new(corev1.Secret)
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}
	if err := r.apiReader().Get(ctx, key, secret); err != nil {
		return err
	}
	if !metav1.IsControlledBy(secret, object) {
		return errServiceTokenDestinationForeign
	}
	prepareServiceTokenSecret(secret)
	secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] = tokenID
	delete(secret.Annotations, v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation)
	delete(secret.Annotations, v1alpha1.ServiceTokenRotatedAtAnnotation)
	delete(secret.Annotations, v1alpha1.ServiceTokenRefreshExpiresAtAnnotation)
	delete(secret.Data, v1alpha1.ServiceTokenPreviousClientIDKey)
	delete(secret.Data, v1alpha1.ServiceTokenPreviousClientSecretKey)
	secret.Data[v1alpha1.ServiceTokenClientIDKey] = []byte(clientID)
	secret.Data[v1alpha1.ServiceTokenClientSecretKey] = []byte(clientSecret)
	delete(secret.Annotations, serviceTokenReservedForAnnotation)
	if object.Spec.Rotation.RequestedAt != nil {
		secret.Annotations[v1alpha1.ServiceTokenRotationRequestAnnotation] = object.Spec.Rotation.RequestedAt.UTC().Format(time.RFC3339Nano)
	} else {
		delete(secret.Annotations, v1alpha1.ServiceTokenRotationRequestAnnotation)
	}
	return r.Update(ctx, secret)
}

// recoverServiceToken resumes a pending create attempt from its journal. It
// runs after normal grant authorization and before the freshness gate, using
// the journaled scope binding rather than re-resolving spec.zone.
func (r *ServiceTokenReconciler) recoverServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, account *v1alpha1.CloudflareAccount, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, clusterID string, journalSecret *corev1.Secret, journal *serviceTokenJournal) (ctrl.Result, error) {
	if err := r.ensureServiceTokenAttemptFinalizer(ctx, object); err != nil {
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
		object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "pending service token journal conflicts with the current management or adoption mode", serviceTokenStatusUpdate{})
	}
	if !journal.matchesIdentity(object, account, clusterID) {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal identity does not match the live spec; refusing to resume", serviceTokenStatusUpdate{})
	}

	// Authoritative credential readback precedes every recovery mutation: a
	// committed credential converges without rotate or recreate.
	committedID, readErr := r.committedServiceTokenCredential(ctx, object)
	if readErr != nil {
		if errors.Is(readErr, errServiceTokenDestinationForeign) {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token destination Secret is not controlled by this ServiceToken", serviceTokenStatusUpdate{})
		}
		return ctrl.Result{}, readErr
	}
	if committedID != "" {
		if journal.issuedID != "" && committedID != journal.issuedID {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "captured credential does not match the journaled service token", serviceTokenStatusUpdate{})
		}
		return r.convergeCommittedServiceToken(ctx, object, api, scope, input, journal, journalSecret, committedID)
	}

	switch journal.phase {
	case serviceTokenJournalPhasePrepared:
		return r.resumePreparedServiceToken(ctx, object, api, scope, input, clusterID, journalSecret, journal, "", nil)
	case serviceTokenJournalPhaseDispatched:
		return r.resumeDispatchedServiceToken(ctx, object, api, scope, input, journalSecret, journal)
	case serviceTokenJournalPhaseRetiring:
		return r.resumeRetiringServiceToken(ctx, object, api, scope, input, clusterID, journalSecret, journal)
	default:
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal is incomplete or malformed", serviceTokenStatusUpdate{})
	}
}

// resumePreparedServiceToken continues a journaled attempt whose create was
// never durably dispatched. Zero remote matches is the only state that
// justifies sending the create.
func (r *ServiceTokenReconciler) resumePreparedServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, clusterID string, journalSecret *corev1.Secret, journal *serviceTokenJournal, excludeID string, tokens []flarecloudflare.ServiceToken) (ctrl.Result, error) {
	if journal.nonce == "" || journal.attemptName == "" {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal is incomplete or malformed", serviceTokenStatusUpdate{})
	}
	if err := r.reserveServiceTokenDestination(ctx, object); err != nil {
		if errors.Is(err, errServiceTokenDestinationForeign) {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token destination Secret is not controlled by this ServiceToken", serviceTokenStatusUpdate{})
		}
		return ctrl.Result{}, err
	}
	if tokens == nil {
		var err error
		tokens, err = api.ListServiceTokens(ctx, scope)
		if err != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
	}
	prefix := serviceTokenAttemptPrefix(clusterID, object)
	for _, remote := range tokens {
		if remote.ID == excludeID {
			continue
		}
		if strings.HasPrefix(remote.Name, prefix) || remote.Name == input.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "an untracked remote service token collides with the pending attempt", serviceTokenStatusUpdate{})
		}
	}
	journal.phase = serviceTokenJournalPhaseDispatched
	journal.issuedID = ""
	if err := r.persistServiceTokenJournal(ctx, journalSecret, journal); err != nil {
		return ctrl.Result{}, err
	}
	return r.dispatchServiceTokenCreate(ctx, object, api, scope, input, journalSecret, journal)
}

// dispatchServiceTokenCreate sends the remote create for a dispatched journal.
// The dispatched phase is committed before the request so a crash afterwards
// resumes through recovery rather than re-creating blindly.
func (r *ServiceTokenReconciler) dispatchServiceTokenCreate(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, journalSecret *corev1.Secret, journal *serviceTokenJournal) (ctrl.Result, error) {
	issued, createErr := api.CreateServiceToken(ctx, scope, flarecloudflare.ServiceTokenInput{
		Name:     journal.attemptName,
		Duration: input.Duration,
		Enabled:  input.Enabled,
	})
	if createErr != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, createErr)
	}
	journal.issuedID = issued.ID
	if err := r.persistServiceTokenJournal(ctx, journalSecret, journal); err != nil {
		return ctrl.Result{}, err
	}
	if issued.Name != journal.attemptName {
		// The provider returned a divergent name. Checkpoint the one-time
		// credential so it is never dropped, then block: the create is never
		// repeated and the divergence is surfaced instead of silently adopted.
		if err := r.writeInitialSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, issued.ServiceToken, metav1.ConditionFalse, "Conflict", "remote service token name diverged from the journaled attempt name", serviceTokenStatusUpdate{})
	}
	if err := r.writeInitialSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret); err != nil {
		return ctrl.Result{}, err
	}
	remote := issued.ServiceToken
	if refreshed, getErr := api.GetServiceToken(ctx, scope, issued.ID); getErr == nil {
		remote = refreshed
	}
	return r.convergeCapturedServiceToken(ctx, object, api, scope, input, journal.attemptName, journalSecret, remote)
}

// resumeDispatchedServiceToken resumes an attempt whose create was dispatched.
// Exactly one verified candidate (full binding plus exact attempt-name match)
// allows recovery; zero matches is unproven and blocks without mutation.
func (r *ServiceTokenReconciler) resumeDispatchedServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, journalSecret *corev1.Secret, journal *serviceTokenJournal) (ctrl.Result, error) {
	if journal.nonce == "" || journal.attemptName == "" {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal is incomplete or malformed", serviceTokenStatusUpdate{})
	}
	tokens, err := api.ListServiceTokens(ctx, scope)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	var candidates []flarecloudflare.ServiceToken
	for _, remote := range tokens {
		if remote.Name == journal.attemptName {
			candidates = append(candidates, remote)
		}
	}
	switch {
	case len(candidates) > 1:
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, candidates[0], metav1.ConditionFalse, "Conflict", "multiple remote service tokens match the journaled attempt", serviceTokenStatusUpdate{})
	case len(candidates) == 0:
		// Absence does not prove the remote create never landed; fail closed
		// and re-list rather than issuing a blind create or rotate.
		if err := r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "RecoveryPending", "journaled service token create is unproven; awaiting remote visibility", serviceTokenStatusUpdate{}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	candidate := candidates[0]
	if journal.issuedID != "" && candidate.ID != journal.issuedID {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, candidate, metav1.ConditionFalse, "Conflict", "remote service token ID does not match the journaled attempt", serviceTokenStatusUpdate{})
	}
	// The destination must be writable before any recovery mutation so a
	// rotated or re-created credential is never discarded by a missing Secret.
	if err := r.reserveServiceTokenDestination(ctx, object); err != nil {
		if errors.Is(err, errServiceTokenDestinationForeign) {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, candidate, metav1.ConditionFalse, "Conflict", "service token destination Secret is not controlled by this ServiceToken", serviceTokenStatusUpdate{})
		}
		return ctrl.Result{}, err
	}
	if journal.issuedID == "" {
		journal.issuedID = candidate.ID
		if err := r.persistServiceTokenJournal(ctx, journalSecret, journal); err != nil {
			return ctrl.Result{}, err
		}
	}
	if scope.ZoneID != "" {
		// Zone scope has no rotate: retire the verified token, then create a
		// replacement only after the deletion is confirmed.
		journal.phase = serviceTokenJournalPhaseRetiring
		journal.retiringID = candidate.ID
		journal.retiringName = candidate.Name
		if err := r.persistServiceTokenJournal(ctx, journalSecret, journal); err != nil {
			return ctrl.Result{}, err
		}
		return r.resumeRetiringServiceToken(ctx, object, api, scope, input, journal.clusterUID, journalSecret, journal)
	}
	grace, parseErr := time.ParseDuration(object.Spec.Rotation.GraceDuration)
	if parseErr != nil || grace < 0 {
		if parseErr == nil {
			parseErr = fmt.Errorf("duration must not be negative")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, candidate, metav1.ConditionFalse, "Invalid", fmt.Sprintf("parse rotation graceDuration: %v", parseErr), serviceTokenStatusUpdate{})
	}
	previousExpiryAt := r.now().Add(grace)
	issued, rotateErr := api.RotateServiceToken(ctx, candidate.ID, previousExpiryAt)
	if rotateErr != nil {
		// No account delete fallback: the journaled attempt stays for retry.
		return ctrl.Result{}, r.finishRemoteError(ctx, object, rotateErr)
	}
	if err := r.writeInitialSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret); err != nil {
		return ctrl.Result{}, err
	}
	remote := issued.ServiceToken
	if refreshed, getErr := api.GetServiceToken(ctx, scope, issued.ID); getErr == nil {
		remote = refreshed
	}
	return r.convergeCapturedServiceToken(ctx, object, api, scope, input, journal.attemptName, journalSecret, remote)
}

// resumeRetiringServiceToken finishes a zone-scope recovery: the retiring
// token must be positively gone before a replacement attempt is prepared.
func (r *ServiceTokenReconciler) resumeRetiringServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, clusterID string, journalSecret *corev1.Secret, journal *serviceTokenJournal) (ctrl.Result, error) {
	if journal.retiringID == "" {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal is incomplete or malformed", serviceTokenStatusUpdate{})
	}
	retiring, getErr := api.GetServiceToken(ctx, scope, journal.retiringID)
	if getErr == nil {
		if retiring.Name != journal.retiringName {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, retiring, metav1.ConditionFalse, "Conflict", "retiring service token name diverged from the journaled identity", serviceTokenStatusUpdate{})
		}
		if err := api.DeleteServiceToken(ctx, scope, journal.retiringID); err != nil && !flarecloudflare.IsNotFound(err) {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
		if err := r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "RecoveryPending", "retiring the journaled service token before re-creating", serviceTokenStatusUpdate{}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	if !flarecloudflare.IsNotFound(getErr) {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, getErr)
	}
	tokens, err := api.ListServiceTokens(ctx, scope)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	// The authoritative Get404 above is the only proof that the retiring token
	// is gone. Keep the list for ambiguous attempt-name peer detection below.
	for _, remote := range tokens {
		if remote.ID == journal.retiringID {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "retiring service token still appears in remote listing after authoritative removal check", serviceTokenStatusUpdate{})
		}
	}
	// The retiring token is confirmed gone; only now prepare the replacement.
	retiredID := journal.retiringID
	nonce, nonceErr := newServiceTokenNonce()
	if nonceErr != nil {
		return ctrl.Result{}, nonceErr
	}
	journal.phase = serviceTokenJournalPhasePrepared
	journal.retiringID = ""
	journal.retiringName = ""
	journal.issuedID = ""
	journal.nonce = nonce
	journal.attemptName = serviceTokenAttemptName(clusterID, object, nonce)
	if err := r.persistServiceTokenJournal(ctx, journalSecret, journal); err != nil {
		return ctrl.Result{}, err
	}
	return r.resumePreparedServiceToken(ctx, object, api, scope, input, clusterID, journalSecret, journal, retiredID, tokens)
}

// convergeCommittedServiceToken finishes a journaled attempt whose credential
// is already committed to the destination Secret: no rotate or recreate, only
// mutable-field alignment, name normalization, checkpoint, and journal reap.
func (r *ServiceTokenReconciler) convergeCommittedServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, journal *serviceTokenJournal, journalSecret *corev1.Secret, tokenID string) (ctrl.Result, error) {
	remote, err := api.GetServiceToken(ctx, scope, tokenID)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	return r.convergeCapturedServiceToken(ctx, object, api, scope, input, journal.attemptName, journalSecret, remote)
}

// convergeCapturedServiceToken aligns mutable fields and the canonical name
// after credential capture, checkpoints status, and only then reaps the
// journal. journalSecret may be nil when the journal was already reaped or is
// not needed for this pass.
func (r *ServiceTokenReconciler) convergeCapturedServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, attemptName string, journalSecret *corev1.Secret, remote flarecloudflare.ServiceToken) (ctrl.Result, error) {
	if attemptName != "" && remote.Name != input.Name && remote.Name != attemptName {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "remote service token name diverged from the journaled attempt name", serviceTokenStatusUpdate{})
	}
	var err error
	if !serviceTokenMatchesInput(remote, input) {
		remote, err = api.UpdateServiceToken(ctx, scope, remote.ID, input)
		if err != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
	}
	if err := r.patchStatus(ctx, object, scope, remote, metav1.ConditionTrue, "Ready", "Service token is created", serviceTokenStatusUpdate{OwnershipVerified: true, ObserveRotationRequest: true}); err != nil {
		return ctrl.Result{}, err
	}
	if journalSecret != nil {
		if err := r.Delete(ctx, journalSecret); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if err := r.removeServiceTokenAttemptFinalizer(ctx, object); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.requeueAfter(remote.ExpiresAt, remote.Duration, nil)}, nil
}

// createServiceToken runs the managed fresh-create path: scoped discovery for
// untracked collisions, journal intent, destination reservation, dispatched
// checkpoint, remote create, credential capture, then convergence.
func (r *ServiceTokenReconciler) createServiceToken(ctx context.Context, object *v1alpha1.ServiceToken, api flarecloudflare.AccessAPI, account *v1alpha1.CloudflareAccount, scope flarecloudflare.AccessScope, input flarecloudflare.ServiceTokenInput, clusterID string) (ctrl.Result, error) {
	tokens, err := api.ListServiceTokens(ctx, scope)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	prefix := serviceTokenAttemptPrefix(clusterID, object)
	for _, remote := range tokens {
		if strings.HasPrefix(remote.Name, prefix) || remote.Name == input.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "an untracked remote service token collides with this ServiceToken; refusing to adopt", serviceTokenStatusUpdate{})
		}
	}
	nonce, err := newServiceTokenNonce()
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureServiceTokenAttemptFinalizer(ctx, object); err != nil {
		return ctrl.Result{}, err
	}
	journalSecret, journal, err := r.createServiceTokenJournal(ctx, object, account, scope, clusterID, nonce)
	if err != nil {
		return ctrl.Result{}, err
	}
	return r.resumePreparedServiceToken(ctx, object, api, scope, input, clusterID, journalSecret, journal, "", tokens)
}

// cleanupPendingServiceTokenJournal removes remote tokens recorded by a
// pending journal during teardown. It uses the journaled account and scope
// binding so pending cleanup works even when status.tokenId is empty.
func (r *ServiceTokenReconciler) cleanupPendingServiceTokenJournal(ctx context.Context, object *v1alpha1.ServiceToken, journal *serviceTokenJournal) error {
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, journal.accountName, authzRequestForJournal(journal), r.NewCloudflareClient)
	if err != nil {
		return err
	}
	clusterID, err := r.authoritativeClusterID(ctx)
	if err != nil {
		return err
	}
	if !journal.matchesIdentity(object, account, clusterID) {
		return errors.New("service token journal identity does not match the live object or authoritative cluster")
	}
	scope := flarecloudflare.AccessScope{ZoneID: journal.zoneID}
	tokens, err := api.ListServiceTokens(ctx, scope)
	if err != nil {
		return err
	}
	exactNames := map[string]bool{}
	for _, name := range []string{journal.attemptName, journal.retiringName} {
		if name != "" {
			exactNames[name] = true
		}
	}
	matches := map[string]flarecloudflare.ServiceToken{}
	for _, remote := range tokens {
		if exactNames[remote.Name] {
			if _, exists := matches[remote.Name]; exists {
				return fmt.Errorf("multiple remote service tokens match journal name %q", remote.Name)
			}
			matches[remote.Name] = remote
		}
	}
	if journal.phase == serviceTokenJournalPhaseDispatched && journal.issuedID == "" && len(matches) == 0 {
		return errors.New("dispatched service token journal has no issued ID or exact remote candidate")
	}
	committedID, err := r.committedServiceTokenCredential(ctx, object)
	if err != nil {
		return err
	}
	committedClientID := ""
	if committedID != "" {
		secret := new(corev1.Secret)
		if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
			return err
		}
		committedClientID = string(secret.Data[v1alpha1.ServiceTokenClientIDKey])
	}
	ids := map[string]bool{}
	if journal.issuedID != "" {
		ids[journal.issuedID] = true
	}
	if journal.retiringID != "" {
		ids[journal.retiringID] = true
	}
	for id := range ids {
		remote, getErr := api.GetServiceToken(ctx, scope, id)
		if flarecloudflare.IsNotFound(getErr) {
			continue
		}
		if getErr != nil {
			return getErr
		}
		allowed := remote.Name == journal.attemptName || remote.Name == journal.retiringName
		if !allowed && committedID == id && committedClientID != "" && remote.ClientID == committedClientID {
			allowed = true
		}
		if !allowed {
			return fmt.Errorf("remote service token %q has unexpected name %q during journal cleanup", id, remote.Name)
		}
		if err := ignoreRemoteNotFound(api.DeleteServiceToken(ctx, scope, id)); err != nil {
			return err
		}
	}
	return nil
}

// cleanupUntrackedServiceTokenAttempts refuses to mutate any remote token when
// a lost journal leaves either an attempt-prefix or canonical legacy collision.
func (r *ServiceTokenReconciler) cleanupUntrackedServiceTokenAttempts(ctx context.Context, object *v1alpha1.ServiceToken) error {
	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{Zone: object.Spec.Zone, PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		return err
	}
	scope, scopeErr := serviceTokenScope(object.Spec.Zone, account.Status.Verified.Zones)
	if scopeErr != nil {
		if object.Status.ZoneID == "" {
			return scopeErr
		}
		scope.ZoneID = object.Status.ZoneID
	}
	clusterID, err := r.authoritativeClusterID(ctx)
	if err != nil {
		return err
	}
	tokens, err := api.ListServiceTokens(ctx, scope)
	if err != nil {
		return err
	}
	prefix := serviceTokenAttemptPrefix(clusterID, object)
	for _, remote := range tokens {
		if strings.HasPrefix(remote.Name, prefix) {
			return fmt.Errorf("unresolved provenance for remote service token %q; refusing cleanup", remote.Name)
		}
	}
	return nil
}

func authzRequestForJournal(journal *serviceTokenJournal) authz.Request {
	return authz.Request{Zone: journal.specZone, PlatformObject: true}
}
