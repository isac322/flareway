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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

const (
	serviceTokenAccountIndex  = accessAccountIndex + ".serviceToken"
	serviceTokenRefreshBefore = 7 * 24 * time.Hour
)

// ServiceTokenReconciler manages Cloudflare Access service tokens and their one-time Secrets.
type ServiceTokenReconciler struct {
	client.Client
	// APIReader reads journals and credential Secrets authoritatively,
	// bypassing the informer cache; SetupWithManager self-initializes it.
	APIReader           client.Reader
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=servicetokens/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile converges one ServiceToken and preserves its one-time credential Secret.
func (r *ServiceTokenReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.ServiceToken)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "ServiceToken", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ServiceTokenFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.ServiceTokenFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{Zone: object.Spec.Zone, PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, flarecloudflare.AccessScope{}, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, privateErrorReason(err), err.Error(), serviceTokenStatusUpdate{})
		return ctrl.Result{}, err
	}
	journalSecret, journal, journalErr := r.loadServiceTokenJournal(ctx, object)
	if journalErr != nil {
		if errors.Is(journalErr, errServiceTokenJournalForeign) {
			return ctrl.Result{}, r.patchStatus(ctx, object, flarecloudflare.AccessScope{}, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal is not controlled by this ServiceToken", serviceTokenStatusUpdate{})
		}
		return ctrl.Result{}, journalErr
	}
	scope, err := serviceTokenScope(object.Spec.Zone, account.Status.Verified.Zones)
	if err != nil {
		if journal != nil && !journal.matchesSpecIdentity(object, account) {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "service token journal identity does not match the live spec; refusing to resume", serviceTokenStatusUpdate{})
		}
		if journal == nil {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Invalid", err.Error(), serviceTokenStatusUpdate{})
		}
		// A verified-zone status flap must not strand a pending attempt: resume
		// under the journaled zone binding after normal grant authorization.
		scope = flarecloudflare.AccessScope{ZoneID: journal.zoneID}
	} else if journal != nil && journal.matchesSpecIdentity(object, account) && journal.zoneID != scope.ZoneID {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Conflict", "journaled service token zone binding no longer resolves", serviceTokenStatusUpdate{})
	}

	id := object.Status.TokenID
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		if journal != nil && object.Status.TokenID == "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "RecoveryPending", "an unresolved service token journal blocks observation", serviceTokenStatusUpdate{})
		}
		if object.Spec.ExternalRef == nil {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Invalid", "ObserveOnly requires externalRef", serviceTokenStatusUpdate{})
		}
		id = object.Spec.ExternalRef.TokenID
		remote, getErr := api.GetServiceToken(ctx, scope, id)
		if getErr != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, getErr)
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "remote service token name does not match expectation", serviceTokenStatusUpdate{})
		}
		return ctrl.Result{RequeueAfter: r.requeueAfter(remote.ExpiresAt, remote.Duration, nil)}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionTrue, "Ready", "Service token is observed", serviceTokenStatusUpdate{})
	}
	if scope.ZoneID != "" && object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationOnExpiry {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, flarecloudflare.ServiceToken{}, metav1.ConditionFalse, "Invalid", "OnExpiry refresh is supported only for account-scoped service tokens", serviceTokenStatusUpdate{OwnershipVerified: object.Status.OwnershipVerified})
	}

	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.ServiceTokenInput{Name: name, Duration: object.Spec.Duration, Enabled: object.Spec.Enabled}
	if rejected, rejectErr := r.rejectServiceTokenSecretCollision(ctx, object, scope, flarecloudflare.ServiceToken{}); rejected || rejectErr != nil {
		return ctrl.Result{}, rejectErr
	}
	clusterID, err := r.authoritativeClusterID(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if journal != nil {
		if object.Status.TokenID != "" {
			// The status checkpoint already landed: a lingering journal is
			// reap-only and never grounds resume or rotation.
			if err := r.Delete(ctx, journalSecret); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			if err := r.removeServiceTokenAttemptFinalizer(ctx, object); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return r.recoverServiceToken(ctx, object, api, account, scope, input, clusterID, journalSecret, journal)
		}
	}
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "ServiceToken", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.TokenID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		requeue := decision.Requeue
		if object.Status.ExpiresAt != nil {
			if untilExpiry := r.requeueAfter(object.Status.ExpiresAt.Time, object.Spec.Duration, nil); untilExpiry < requeue {
				requeue = untilExpiry
			}
		}
		return ctrl.Result{RequeueAfter: requeue}, nil
	}
	if id == "" {
		recoveredID, recoverErr := r.recoverTokenID(ctx, object)
		if recoverErr != nil {
			return ctrl.Result{}, recoverErr
		}
		if recoveredID != "" {
			remote, getErr := api.GetServiceToken(ctx, scope, recoveredID)
			if getErr != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, getErr)
			}
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionTrue, "Recovered", "Recovered service token ownership from its Secret", serviceTokenStatusUpdate{OwnershipVerified: true})
		}
	}

	var remote flarecloudflare.ServiceToken
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			if object.Spec.ExternalRef == nil {
				return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Invalid", "AdoptById requires externalRef", serviceTokenStatusUpdate{})
			}
			id = object.Spec.ExternalRef.TokenID
			remote, err = api.GetServiceToken(ctx, scope, id)
			if err != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "remote service token name does not match adoption expectation", serviceTokenStatusUpdate{})
			}
			if !serviceTokenMatchesInput(remote, input) {
				remote, err = api.UpdateServiceToken(ctx, scope, id, input)
				if err != nil {
					return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
				}
			}
			previousExpiry, secretErr := r.cleanupPreviousCredentials(ctx, object)
			update := serviceTokenStatusUpdate{OwnershipVerified: true, ObserveRotationRequest: true}
			if secretErr != nil {
				if apierrors.IsNotFound(secretErr) {
					return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "SecretMissing", "adopted service token Secret is missing; adoption never rotates credentials", update)
				}
				return ctrl.Result{}, secretErr
			}
			return ctrl.Result{RequeueAfter: r.requeueAfter(remote.ExpiresAt, remote.Duration, previousExpiry)}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionTrue, "Ready", "Service token is adopted without rotating credentials", update)
		}

		return r.createServiceToken(ctx, object, api, account, scope, input, clusterID)
	}

	remote, err = api.GetServiceToken(ctx, scope, id)
	if err != nil {
		return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
	}
	if !object.Status.OwnershipVerified {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", "remote service token ID is not verified as owned or adopted", serviceTokenStatusUpdate{})
	}
	if !serviceTokenMatchesInput(remote, input) {
		remote, err = api.UpdateServiceToken(ctx, scope, id, input)
		if err != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
		if err = r.clearRefreshExpiry(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	previousExpiry, secretErr := r.cleanupPreviousCredentials(ctx, object)
	if secretErr != nil && !apierrors.IsNotFound(secretErr) {
		return ctrl.Result{}, secretErr
	}
	if apierrors.IsNotFound(secretErr) && !rotationRequested(object) {
		return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "SecretMissing", "service token Secret is missing; update rotation.requestedAt to rotate explicitly", serviceTokenStatusUpdate{OwnershipVerified: true})
	}

	update := serviceTokenStatusUpdate{OwnershipVerified: true}
	if object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationManual && rotationRequested(object) {
		if scope.ZoneID != "" {
			return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Invalid", "rotation is supported only for account-scoped service tokens", update)
		}
		applied, appliedAt, appliedErr := r.rotationApplied(ctx, object)
		if appliedErr != nil && !apierrors.IsNotFound(appliedErr) {
			return ctrl.Result{}, appliedErr
		}
		if applied {
			update.ObserveRotationRequest = true
			update.RotatedAt = appliedAt
		} else {
			grace, parseErr := time.ParseDuration(object.Spec.Rotation.GraceDuration)
			if parseErr != nil || grace < 0 {
				if parseErr == nil {
					parseErr = fmt.Errorf("duration must not be negative")
				}
				return ctrl.Result{}, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Invalid", fmt.Sprintf("parse rotation graceDuration: %v", parseErr), update)
			}
			previousExpiryAt := r.now().Add(grace)
			if rejected, rejectErr := r.rejectServiceTokenSecretCollision(ctx, object, scope, remote); rejected || rejectErr != nil {
				return ctrl.Result{}, rejectErr
			}

			issued, rotateErr := api.RotateServiceToken(ctx, id, previousExpiryAt)
			if rotateErr != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, rotateErr)
			}
			rotatedAt := r.now()
			if err = r.writeRotatedSecret(ctx, object, issued.ID, issued.ClientID, issued.ClientSecret, previousExpiryAt, rotatedAt); err != nil {
				return ctrl.Result{}, err
			}
			remote = issued.ServiceToken
			if refreshed, getErr := api.GetServiceToken(ctx, scope, id); getErr == nil {
				remote = refreshed
			}
			previousExpiry = &previousExpiryAt
			stamp := metav1.NewTime(rotatedAt)
			update.RotatedAt = &stamp
			update.ObserveRotationRequest = true
		}
	}

	remote.ExpiresAt = r.effectiveRefreshExpiry(ctx, object, remote.ExpiresAt)
	if object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationOnExpiry &&
		!remote.ExpiresAt.IsZero() && !remote.ExpiresAt.After(r.now().Add(serviceTokenRefreshWindow(remote.Duration))) {
		remote, err = api.RefreshServiceToken(ctx, id)
		if err != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
		if !remote.ExpiresAt.IsZero() {
			if err = r.recordRefreshExpiry(ctx, object, remote.ExpiresAt); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	clearGate(r.Invalidator, "ServiceToken", request.NamespacedName)
	requeue := r.requeueAfter(remote.ExpiresAt, remote.Duration, previousExpiry)
	if ttl := r.Freshness.TTL(freshness.GradeAuthz); ttl > 0 && ttl < requeue {
		requeue = ttl
	}
	if err := r.patchStatus(ctx, object, scope, remote, metav1.ConditionTrue, "Ready", "Service token is synchronized", update); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, r.Invalidator, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

type serviceTokenStatusUpdate struct {
	OwnershipVerified      bool
	ObserveRotationRequest bool
	RotatedAt              *metav1.Time
}

func rotationRequested(object *v1alpha1.ServiceToken) bool {
	return object.Spec.Rotation.Mode == v1alpha1.ServiceTokenRotationManual && object.Spec.Rotation.RequestedAt != nil &&
		(object.Status.ObservedRotationRequest == nil || object.Spec.Rotation.RequestedAt.After(object.Status.ObservedRotationRequest.Time))
}

func serviceTokenScope(zoneName string, zones []v1alpha1.CloudflareVerifiedZone) (flarecloudflare.AccessScope, error) {
	if zoneName == "" {
		return flarecloudflare.AccessScope{}, nil
	}
	wanted := strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, zone := range zones {
		if strings.ToLower(strings.TrimSuffix(zone.Name, ".")) == wanted {
			return flarecloudflare.AccessScope{ZoneID: zone.ID}, nil
		}
	}
	return flarecloudflare.AccessScope{}, fmt.Errorf("zone %q was not verified for the referenced CloudflareAccount", zoneName)
}

func serviceTokenMatchesInput(remote flarecloudflare.ServiceToken, input flarecloudflare.ServiceTokenInput) bool {
	if remote.Name != input.Name || remote.Enabled != input.Enabled {
		return false
	}
	return input.Duration == "" || remote.Duration == input.Duration
}

func (r *ServiceTokenReconciler) rejectServiceTokenSecretCollision(ctx context.Context, object *v1alpha1.ServiceToken, scope flarecloudflare.AccessScope, remote flarecloudflare.ServiceToken) (bool, error) {
	secret := new(corev1.Secret)
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}
	if err := r.Get(ctx, key, secret); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if metav1.IsControlledBy(secret, object) {
		return false, nil
	}
	message := fmt.Sprintf("Secret %s is not controlled by this ServiceToken", key)
	return true, r.patchStatus(ctx, object, scope, remote, metav1.ConditionFalse, "Conflict", message, serviceTokenStatusUpdate{})
}

func (r *ServiceTokenReconciler) writeRotatedSecret(ctx context.Context, object *v1alpha1.ServiceToken, tokenID, clientID, clientSecret string, previousExpiresAt, rotatedAt time.Time) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.UID != "" && !metav1.IsControlledBy(secret, object) {
			return fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
		}
		if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
			return err
		}
		prepareServiceTokenSecret(secret)
		previousID := append([]byte(nil), secret.Data[v1alpha1.ServiceTokenClientIDKey]...)
		previousSecret := append([]byte(nil), secret.Data[v1alpha1.ServiceTokenClientSecretKey]...)
		if len(previousID) != 0 && len(previousSecret) != 0 && previousExpiresAt.After(r.now()) {
			secret.Data[v1alpha1.ServiceTokenPreviousClientIDKey] = previousID
			secret.Data[v1alpha1.ServiceTokenPreviousClientSecretKey] = previousSecret
			secret.Annotations[v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation] = previousExpiresAt.UTC().Format(time.RFC3339Nano)
		} else {
			delete(secret.Data, v1alpha1.ServiceTokenPreviousClientIDKey)
			delete(secret.Data, v1alpha1.ServiceTokenPreviousClientSecretKey)
			delete(secret.Annotations, v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation)
		}
		secret.Annotations[v1alpha1.ServiceTokenIDAnnotation] = tokenID
		secret.Data[v1alpha1.ServiceTokenClientIDKey] = []byte(clientID)
		secret.Data[v1alpha1.ServiceTokenClientSecretKey] = []byte(clientSecret)
		if object.Spec.Rotation.RequestedAt != nil {
			secret.Annotations[v1alpha1.ServiceTokenRotationRequestAnnotation] = object.Spec.Rotation.RequestedAt.UTC().Format(time.RFC3339Nano)
		}
		secret.Annotations[v1alpha1.ServiceTokenRotatedAtAnnotation] = rotatedAt.UTC().Format(time.RFC3339Nano)
		delete(secret.Annotations, v1alpha1.ServiceTokenRefreshExpiresAtAnnotation)
		return nil
	})
	return err
}

func prepareServiceTokenSecret(secret *corev1.Secret) {
	secret.Type = corev1.SecretTypeOpaque
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
}

func (r *ServiceTokenReconciler) cleanupPreviousCredentials(ctx context.Context, object *v1alpha1.ServiceToken) (*time.Time, error) {
	secret := new(corev1.Secret)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
		return nil, err
	}
	if !metav1.IsControlledBy(secret, object) {
		return nil, fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
	}
	text := secret.Annotations[v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation]
	if text == "" {
		return nil, nil
	}
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, text)
	if parseErr != nil || !expiresAt.After(r.now()) {
		base := client.MergeFrom(secret.DeepCopy())
		delete(secret.Data, v1alpha1.ServiceTokenPreviousClientIDKey)
		delete(secret.Data, v1alpha1.ServiceTokenPreviousClientSecretKey)
		delete(secret.Annotations, v1alpha1.ServiceTokenPreviousClientSecretExpiresAtAnnotation)
		if err := r.Patch(ctx, secret, base); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &expiresAt, nil
}

func (r *ServiceTokenReconciler) rotationApplied(ctx context.Context, object *v1alpha1.ServiceToken) (bool, *metav1.Time, error) {
	if object.Spec.Rotation.RequestedAt == nil {
		return false, nil, nil
	}
	secret := new(corev1.Secret)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
		return false, nil, err
	}
	if !metav1.IsControlledBy(secret, object) {
		return false, nil, fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
	}
	appliedAt, err := time.Parse(time.RFC3339Nano, secret.Annotations[v1alpha1.ServiceTokenRotationRequestAnnotation])
	if err != nil || appliedAt.Before(object.Spec.Rotation.RequestedAt.Time) {
		return false, nil, nil
	}
	rotatedAt, err := time.Parse(time.RFC3339Nano, secret.Annotations[v1alpha1.ServiceTokenRotatedAtAnnotation])
	if err != nil {
		return true, nil, nil
	}
	stamp := metav1.NewTime(rotatedAt)
	return true, &stamp, nil
}

func (r *ServiceTokenReconciler) clearRefreshExpiry(ctx context.Context, object *v1alpha1.ServiceToken) error {
	secret := new(corev1.Secret)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
		return err
	}
	if !metav1.IsControlledBy(secret, object) {
		return fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
	}
	if secret.Annotations[v1alpha1.ServiceTokenRefreshExpiresAtAnnotation] == "" {
		return nil
	}
	base := client.MergeFrom(secret.DeepCopy())
	delete(secret.Annotations, v1alpha1.ServiceTokenRefreshExpiresAtAnnotation)
	return r.Patch(ctx, secret, base)
}

func (r *ServiceTokenReconciler) recordRefreshExpiry(ctx context.Context, object *v1alpha1.ServiceToken, expiresAt time.Time) error {
	secret := new(corev1.Secret)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
		return err
	}
	if !metav1.IsControlledBy(secret, object) {
		return fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
	}
	base := client.MergeFrom(secret.DeepCopy())
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[v1alpha1.ServiceTokenRefreshExpiresAtAnnotation] = expiresAt.UTC().Format(time.RFC3339Nano)
	return r.Patch(ctx, secret, base)
}

func (r *ServiceTokenReconciler) effectiveRefreshExpiry(ctx context.Context, object *v1alpha1.ServiceToken, remote time.Time) time.Time {
	secret := new(corev1.Secret)
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, secret); err != nil {
		return remote
	}
	refreshed, err := time.Parse(time.RFC3339Nano, secret.Annotations[v1alpha1.ServiceTokenRefreshExpiresAtAnnotation])
	if err == nil && refreshed.After(remote) {
		return refreshed
	}
	return remote
}

func (r *ServiceTokenReconciler) recoverTokenID(ctx context.Context, object *v1alpha1.ServiceToken) (string, error) {
	var secret corev1.Secret
	err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SecretRef.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return "", fmt.Errorf("secret %s/%s is not controlled by this ServiceToken", secret.Namespace, secret.Name)
	}
	return secret.Annotations[v1alpha1.ServiceTokenIDAnnotation], nil
}
func (r *ServiceTokenReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.ServiceToken) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.ServiceTokenFinalizer) {
		return nil
	}
	journalSecret, journal, journalErr := r.loadServiceTokenJournal(ctx, object)
	if journalErr != nil && !errors.Is(journalErr, errServiceTokenJournalForeign) {
		return r.patchCleanupBlocked(ctx, object, "JournalError", journalErr)
	}
	attemptMarked := controllerutil.ContainsFinalizer(object, serviceTokenAttemptFinalizer)
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete {
		if object.Status.TokenID != "" && object.Status.OwnershipVerified {
			api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{Zone: object.Spec.Zone, PlatformObject: true}, r.NewCloudflareClient)
			if err != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
			}
			scope, scopeErr := serviceTokenScope(object.Spec.Zone, account.Status.Verified.Zones)
			if scopeErr != nil {
				if object.Status.ZoneID == "" {
					return r.patchCleanupBlocked(ctx, object, "Invalid", scopeErr)
				}
				scope.ZoneID = object.Status.ZoneID
			}
			if err = ignoreRemoteNotFound(api.DeleteServiceToken(ctx, scope, object.Status.TokenID)); err != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
			}
		}
		if journal != nil {
			if err := r.cleanupPendingServiceTokenJournal(ctx, object, journal); err != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
			}
		} else if object.Status.TokenID == "" && attemptMarked {
			if err := r.cleanupUntrackedServiceTokenAttempts(ctx, object); err != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
			}
		}
	}
	if journalSecret != nil {
		if err := r.Delete(ctx, journalSecret); err != nil && !apierrors.IsNotFound(err) {
			return r.patchCleanupBlocked(ctx, object, "JournalError", err)
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.ServiceTokenFinalizer)
	controllerutil.RemoveFinalizer(object, serviceTokenAttemptFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *ServiceTokenReconciler) patchStatus(ctx context.Context, object *v1alpha1.ServiceToken, scope flarecloudflare.AccessScope, remote flarecloudflare.ServiceToken, status metav1.ConditionStatus, reason, message string, update serviceTokenStatusUpdate) error {
	base := client.MergeFrom(object.DeepCopy())
	if remote.ID != "" && (status == metav1.ConditionTrue || update.OwnershipVerified) {
		object.Status.TokenID = remote.ID
		object.Status.ClientID = remote.ClientID
		object.Status.ZoneID = scope.ZoneID
		object.Status.OwnershipVerified = update.OwnershipVerified
		object.Status.ObservedName = remote.Name
		object.Status.ObservedDuration = remote.Duration
		object.Status.ObservedEnabled = remote.Enabled
		if !remote.ExpiresAt.IsZero() {
			stamp := metav1.NewTime(remote.ExpiresAt)
			object.Status.ExpiresAt = &stamp
		}
	}
	if update.RotatedAt != nil {
		object.Status.RotatedAt = update.RotatedAt
	}
	if update.ObserveRotationRequest && object.Spec.Rotation.RequestedAt != nil {
		object.Status.ObservedRotationRequest = object.Spec.Rotation.RequestedAt.DeepCopy()
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	return r.Status().Patch(ctx, object, base)
}

// finishRemoteError reports a failed remote call on the object's conditions.
// A typed 404 revokes acceptance because the remote object is gone; any other
// failure is transient, so the existing Accepted condition and the recorded
// remote identifiers are preserved while Ready flips to False.
func (r *ServiceTokenReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.ServiceToken, err error) error {
	conditions := []metav1.Condition{
		accessCondition(object.Generation, "Ready", metav1.ConditionFalse, "RemoteError", err.Error()),
	}
	if flarecloudflare.IsNotFound(err) {
		conditions = []metav1.Condition{
			accessCondition(object.Generation, "Accepted", metav1.ConditionFalse, "RemoteMissing", err.Error()),
			accessCondition(object.Generation, "Ready", metav1.ConditionFalse, "RemoteMissing", err.Error()),
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), conditions...)
	if patchErr := r.Status().Patch(ctx, object, base); patchErr != nil {
		return errors.Join(err, patchErr)
	}
	return err
}

func (r *ServiceTokenReconciler) patchCleanupBlocked(ctx context.Context, object *v1alpha1.ServiceToken, reason string, cause error) error {
	base := client.MergeFrom(object.DeepCopy())
	message := cause.Error()
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		accessCondition(object.Generation, "CleanupBlocked", metav1.ConditionTrue, reason, message),
		accessCondition(object.Generation, "Ready", metav1.ConditionFalse, "CleanupBlocked", message),
	)
	if patchErr := r.Status().Patch(ctx, object, base); patchErr != nil {
		return errors.Join(cause, patchErr)
	}
	return cause
}

func serviceTokenRefreshWindow(duration string) time.Duration {
	parsed, err := time.ParseDuration(duration)
	if err != nil || parsed <= 0 || parsed >= 10*serviceTokenRefreshBefore {
		return serviceTokenRefreshBefore
	}
	window := parsed / 10
	if window < time.Minute {
		return time.Minute
	}
	return window
}

func (r *ServiceTokenReconciler) requeueAfter(expires time.Time, duration string, previousExpiresAt *time.Time) time.Duration {
	next := 6 * time.Hour
	if !expires.IsZero() {
		next = expires.Add(-serviceTokenRefreshWindow(duration)).Sub(r.now())
	}
	if previousExpiresAt != nil {
		untilPreviousExpiry := previousExpiresAt.Sub(r.now())
		if untilPreviousExpiry < next {
			next = untilPreviousExpiry
		}
	}
	if next < time.Minute {
		return time.Minute
	}
	return next
}

func (r *ServiceTokenReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the ServiceToken controller and account watch.
func (r *ServiceTokenReconciler) SetupWithManager(manager ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = manager.GetAPIReader()
	}
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ServiceToken{}, serviceTokenAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.ServiceToken).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index ServiceToken accounts: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.ServiceToken{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Owns(&corev1.Secret{}).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.tokensForAccount)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.tokensForNamespace))
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("service-token", r))
}
func (r *ServiceTokenReconciler) tokensForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ServiceTokenList
	if err := r.List(ctx, &list, client.MatchingFields{serviceTokenAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
func (r *ServiceTokenReconciler) tokensForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.ServiceTokenList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}}
	}
	return out
}
