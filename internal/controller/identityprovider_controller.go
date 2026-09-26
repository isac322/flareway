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
	"reflect"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
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
	identityProviderAccountIndex                = accessAccountIndex + ".identityProvider"
	identityProviderSecretIndex                 = ".spec.identityProviderSecrets"
	identityProviderSCIMLimit                   = int64(50)
	identityProviderSCIMCreateIntentAnnotation  = "flareway.bhyoo.com/scim-create-intent"
	identityProviderSCIMCreateStateAnnotation   = "flareway.bhyoo.com/scim-create-state"
	identityProviderSCIMPendingRemoteNamePrefix = "flareway-scim-pending-"
	identityProviderSCIMCreatePrepared          = "prepared"
	identityProviderSCIMCreateIssued            = "issued"
	identityProviderSCIMCreateConflict          = "conflict"
)

// IdentityProviderReconciler manages Cloudflare Access identity providers.
type IdentityProviderReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	Freshness           freshness.Policy
	Invalidator         *freshness.Latch
	SweepEvents         <-chan event.GenericEvent
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=identityproviders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile converges one IdentityProvider with its Cloudflare identity provider.
func (r *IdentityProviderReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.IdentityProvider)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, releaseGoneObject(r.Invalidator, "IdentityProvider", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.IdentityProviderFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.IdentityProviderFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	api, account, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, flarecloudflare.IdentityProvider{ID: object.Status.IDPID}, nil, metav1.ConditionFalse, privateErrorReason(err), err.Error())
		return ctrl.Result{}, err
	}
	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		remote, getErr := api.GetIdentityProvider(ctx, object.Spec.ExternalRef.IDPID)
		if getErr != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, getErr)
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "Conflict", "remote identity provider name does not match expectation")
		}
		directory, directoryErr := r.readSCIMDirectory(ctx, api, remote)
		if directoryErr != nil {
			_ = r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "Pending", directoryErr.Error())
			return ctrl.Result{}, directoryErr
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, directory, metav1.ConditionTrue, "Ready", "Identity provider is observed")
	}
	if identityProviderSCIMEnabled(object.Spec.SCIMConfig) && (object.Spec.SCIMConfig.SecretRef == nil || object.Spec.SCIMConfig.SecretRef.Name == "") {
		return ctrl.Result{}, r.patchStatus(ctx, object, flarecloudflare.IdentityProvider{ID: object.Status.IDPID}, nil, metav1.ConditionFalse, "Invalid", "SCIM secretRef is required when SCIM is enabled")
	}

	secretValue, err := r.clientSecret(ctx, object)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, flarecloudflare.IdentityProvider{ID: object.Status.IDPID}, nil, metav1.ConditionFalse, "SecretNotFound", err.Error())
	}
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.IdentityProviderInput{Name: name, Type: object.Spec.Type, Config: object.Spec.Config, SCIMConfig: object.Spec.SCIMConfig, ClientSecret: secretValue}
	clusterID := gateClusterID(ctx, r.Client)
	decision := evaluateGate(r.Freshness, r.Invalidator, freshness.GradeAuthz, gateInput{
		Kind: "IdentityProvider", Namespace: object.Namespace, Name: object.Name,
		UID: object.UID, RemoteID: object.Status.IDPID,
		AccountID: account.Spec.AccountID, ClusterID: clusterID,
		Spec: struct {
			Spec  any `json:"spec"`
			Input any `json:"input"`
		}{Spec: object.Spec, Input: input},
	}, object.Status.AppliedHash, object.Status.AppliedAt, r.now())
	if decision.Open {
		return ctrl.Result{RequeueAfter: decision.Requeue}, nil
	}
	id := object.Status.IDPID
	var remote flarecloudflare.IdentityProvider
	created := false
	recovered := false
	if id == "" {
		pendingRemote, pending, pendingErr := r.resumeSCIMCreateIntent(ctx, api, object, input)
		if pendingErr != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, pendingErr)
		}
		if pending {
			if pendingRemote.ID == "" {
				return ctrl.Result{}, fmt.Errorf("remote identity provider create response omitted ID")
			}
			if err := r.checkpointIdentityProvider(ctx, object, pendingRemote.ID); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Millisecond}, nil
		}
	}
	if object.Spec.SCIMConfig != nil && (id == "" || !object.Status.OwnershipVerified) {
		recoveredID, recoverErr := r.recoverSCIMProviderID(ctx, object)
		if recoverErr != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, recoverErr)
		}
		if recoveredID != "" {
			if id != "" && id != recoveredID {
				return ctrl.Result{}, r.patchStatus(ctx, object, flarecloudflare.IdentityProvider{ID: id}, nil, metav1.ConditionFalse, "Conflict", "status and the owned SCIM Secret identify different remote identity providers")
			}
			id = recoveredID
			remote, err = api.GetIdentityProvider(ctx, id)
			if err != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
			}
			recovered = true
		}
	}
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.IDPID
			remote, err = api.GetIdentityProvider(ctx, id)
			if err != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "Conflict", "remote identity provider name does not match adoption expectation")
			}
			if err = r.checkpointIdentityProvider(ctx, object, id); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			scimCreate := identityProviderSCIMEnabled(input.SCIMConfig)
			createInput := input
			if identityProviderWantsSAMLEncryption(input) {
				createInput.Config.EnableEncryption = nil
			}
			if scimCreate {
				pendingName, createState, reserveErr := r.reserveSCIMCreateIntent(ctx, object)
				if reserveErr != nil {
					return ctrl.Result{}, reserveErr
				}
				createInput = identityProviderInputWithSCIMEnabled(createInput, false)
				createInput.Name = pendingName
				pendingRemote, pendingFound, pendingOccupied, pendingErr := findPendingSCIMIdentityProvider(ctx, api, createInput)
				switch createState {
				case identityProviderSCIMCreatePrepared:
					if pendingErr != nil && !pendingOccupied {
						return ctrl.Result{}, r.finishRemoteError(ctx, object, pendingErr)
					}
					if pendingOccupied {
						conflictErr := r.setSCIMCreateIntentState(ctx, object, pendingName, identityProviderSCIMCreatePrepared, identityProviderSCIMCreateConflict)
						if pendingErr == nil {
							pendingErr = fmt.Errorf("the journaled remote identity provider create marker was occupied before this create attempt")
						}
						return ctrl.Result{}, errors.Join(pendingErr, conflictErr)
					}
					if err = r.setSCIMCreateIntentState(ctx, object, pendingName, identityProviderSCIMCreatePrepared, identityProviderSCIMCreateIssued); err != nil {
						return ctrl.Result{}, err
					}
					remote, err = api.CreateIdentityProvider(ctx, createInput)
				case identityProviderSCIMCreateIssued:
					if pendingErr != nil {
						return ctrl.Result{}, r.finishRemoteError(ctx, object, pendingErr)
					}
					if pendingFound {
						remote = pendingRemote
					} else {
						remote, err = api.CreateIdentityProvider(ctx, createInput)
					}
				default:
					return ctrl.Result{}, fmt.Errorf("the SCIM Secret contains unsupported remote create state %q", createState)
				}
			} else {
				remote, err = api.CreateIdentityProvider(ctx, createInput)
			}
			if err != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
			}
			created = true
			id = remote.ID
			if id == "" {
				return ctrl.Result{}, fmt.Errorf("remote identity provider create response omitted ID")
			}
			if checkpointErr := r.checkpointIdentityProvider(ctx, object, id); checkpointErr != nil {
				if scimCreate {
					return ctrl.Result{}, checkpointErr
				}
				rollbackErr := ignoreRemoteNotFound(api.DeleteIdentityProvider(ctx, id))
				if rollbackErr != nil {
					retryCheckpointErr := r.checkpointIdentityProvider(ctx, object, id)
					return ctrl.Result{}, errors.Join(checkpointErr, rollbackErr, retryCheckpointErr)
				}
				return ctrl.Result{}, checkpointErr
			}
			if scimCreate {
				return ctrl.Result{RequeueAfter: time.Millisecond}, nil
			}
		}
	} else {
		if !recovered && !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, flarecloudflare.IdentityProvider{ID: id}, nil, metav1.ConditionFalse, "Conflict", "remote identity provider ID is not verified as owned or adopted")
		}
		if remote.ID == "" {
			remote, err = api.GetIdentityProvider(ctx, id)
			if err != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
			}
		}
		if recovered {
			if err = r.checkpointIdentityProvider(ctx, object, id); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	if remote.ReadOnly {
		return ctrl.Result{}, r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "ReadOnly", "remote identity provider is read-only and cannot be managed")
	}

	if identityProviderWantsSAMLEncryption(input) {
		input.SAMLCertificateSetID = remote.SAMLCertificateSetID
		if input.SAMLCertificateSetID == "" {
			certificate, certificateErr := api.CreateIdentityProviderSAMLCertificate(ctx, id)
			if certificateErr != nil {
				return ctrl.Result{}, r.finishRemoteError(ctx, object, certificateErr)
			}
			input.SAMLCertificateSetID = certificate.ID
			remote.SAMLCertificateSetID = certificate.ID
			remote.SAMLCertificateSet = &certificate
		}
	}

	wasSCIMEnabled := identityProviderRemoteSCIMEnabled(remote.SCIMConfig)
	if !identityProviderMatchesInput(remote, input) {
		enablingSCIM := !wasSCIMEnabled && identityProviderSCIMEnabled(input.SCIMConfig)
		if enablingSCIM {
			if err = r.prepareSCIMSecretForEnable(ctx, object, id); err != nil {
				return ctrl.Result{}, err
			}
		}
		remote, err = api.UpdateIdentityProvider(ctx, id, input)
		if err != nil {
			return ctrl.Result{}, r.finishRemoteError(ctx, object, err)
		}
		if enablingSCIM {
			if err = r.captureSCIMSecret(ctx, object, id, remote.SCIMSecret); err != nil {
				_, disableErr := api.UpdateIdentityProvider(ctx, id, identityProviderInputWithSCIMEnabled(input, false))
				return ctrl.Result{}, errors.Join(err, disableErr)
			}
		}
	} else if created {
		remote.ID = id
	}

	if identityProviderSCIMEnabled(input.SCIMConfig) {
		if err = r.requireSCIMSecret(ctx, object, remote.ID); err != nil {
			if identityProviderRemoteSCIMEnabled(remote.SCIMConfig) {
				if prepareErr := r.prepareSCIMSecretForEnable(ctx, object, remote.ID); prepareErr == nil {
					if _, disableErr := api.UpdateIdentityProvider(ctx, id, identityProviderInputWithSCIMEnabled(input, false)); disableErr != nil {
						return ctrl.Result{}, r.finishRemoteError(ctx, object, disableErr)
					}
					return ctrl.Result{RequeueAfter: time.Millisecond}, nil
				}
			}
			return ctrl.Result{}, r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "SecretMissing", "SCIM is enabled, but its one-time credential Secret is unavailable")
		}
	}
	directory, err := r.readSCIMDirectory(ctx, api, remote)
	if err != nil {
		_ = r.patchStatus(ctx, object, remote, nil, metav1.ConditionFalse, "Pending", err.Error())
		return ctrl.Result{}, err
	}
	if err := r.patchStatus(ctx, object, remote, directory, metav1.ConditionTrue, "Ready", "Identity provider is synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	if err := persistGateStamp(ctx, r.Client, r.Invalidator, object, newGateStamp(decision.DesiredHash, r.now())); err != nil {
		return ctrl.Result{}, err
	}
	clearGate(r.Invalidator, "IdentityProvider", request.NamespacedName)
	return ctrl.Result{RequeueAfter: r.Freshness.TTL(freshness.GradeAuthz)}, nil
}

func (r *IdentityProviderReconciler) clientSecret(ctx context.Context, object *v1alpha1.IdentityProvider) (string, error) {
	ref := object.Spec.Config.ClientSecretRef
	if ref == nil {
		return "", nil
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: ref.Name}, &secret); err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = "clientSecret"
	}
	value := trimSecret(secret.Data[key])
	if value == "" {
		return "", fmt.Errorf("secret %s/%s has no non-empty %q key", object.Namespace, ref.Name, key)
	}
	return value, nil
}

func (r *IdentityProviderReconciler) reserveSCIMSecret(ctx context.Context, object *v1alpha1.IdentityProvider, id string) error {
	if object.Spec.SCIMConfig == nil || object.Spec.SCIMConfig.SecretRef == nil || object.Spec.SCIMConfig.SecretRef.Name == "" {
		return fmt.Errorf("the SCIM secretRef is not configured")
	}
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}
	secret := new(corev1.Secret)
	err := r.Get(ctx, key, secret)
	if apierrors.IsNotFound(err) {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Type:       corev1.SecretTypeOpaque,
		}
		if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, secret); err == nil {
			return nil
		} else if !apierrors.IsAlreadyExists(err) {
			return err
		}
		secret = new(corev1.Secret)
		if err := r.Get(ctx, key, secret); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return validateSCIMSecretDestination(secret, object, id)
}

func (r *IdentityProviderReconciler) reserveSCIMCreateIntent(ctx context.Context, object *v1alpha1.IdentityProvider) (string, string, error) {
	if err := r.reserveSCIMSecret(ctx, object, ""); err != nil {
		return "", "", err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}
	pendingName := identityProviderSCIMPendingRemoteNamePrefix + hex.EncodeToString(random)
	state := identityProviderSCIMCreatePrepared
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret := new(corev1.Secret)
		if err := r.Get(ctx, key, secret); err != nil {
			return err
		}
		if err := validateSCIMSecretDestination(secret, object, ""); err != nil {
			return err
		}
		if secret.Immutable != nil && *secret.Immutable {
			return fmt.Errorf("the SCIM Secret %s/%s is immutable and cannot journal remote creation", secret.Namespace, secret.Name)
		}
		intent := secret.Annotations[identityProviderSCIMCreateIntentAnnotation]
		currentState := secret.Annotations[identityProviderSCIMCreateStateAnnotation]
		if intent != "" {
			if currentState == identityProviderSCIMCreateConflict {
				return fmt.Errorf("the SCIM Secret %s/%s records a conflicting remote create marker", secret.Namespace, secret.Name)
			}
			if currentState != identityProviderSCIMCreatePrepared && currentState != identityProviderSCIMCreateIssued {
				return fmt.Errorf("the SCIM Secret %s/%s contains unsupported remote create state %q", secret.Namespace, secret.Name, currentState)
			}
			pendingName = intent
			state = currentState
			return nil
		}
		if currentState != "" {
			return fmt.Errorf("the SCIM Secret %s/%s contains a create state without a create intent", secret.Namespace, secret.Name)
		}
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[identityProviderSCIMCreateIntentAnnotation] = pendingName
		secret.Annotations[identityProviderSCIMCreateStateAnnotation] = identityProviderSCIMCreatePrepared
		return r.Update(ctx, secret)
	})
	return pendingName, state, err
}

func (r *IdentityProviderReconciler) findOwnedSCIMCreateJournal(ctx context.Context, object *v1alpha1.IdentityProvider) (*corev1.Secret, error) {
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, client.InNamespace(object.Namespace)); err != nil {
		return nil, err
	}
	var found *corev1.Secret
	for index := range secrets.Items {
		secret := &secrets.Items[index]
		if !metav1.IsControlledBy(secret, object) ||
			(secret.Annotations[identityProviderSCIMCreateIntentAnnotation] == "" &&
				secret.Annotations[identityProviderSCIMCreateStateAnnotation] == "") {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple owned SCIM Secrets contain remote create journals")
		}
		found = secret.DeepCopy()
	}
	return found, nil
}

func (r *IdentityProviderReconciler) setSCIMCreateIntentState(ctx context.Context, object *v1alpha1.IdentityProvider, pendingName, expected, state string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret, err := r.findOwnedSCIMCreateJournal(ctx, object)
		if err != nil {
			return err
		}
		if secret == nil ||
			secret.Annotations[identityProviderSCIMCreateIntentAnnotation] != pendingName ||
			secret.Annotations[identityProviderSCIMCreateStateAnnotation] != expected {
			return fmt.Errorf("the SCIM Secret create journal changed concurrently")
		}
		secret.Annotations[identityProviderSCIMCreateStateAnnotation] = state
		return r.Update(ctx, secret)
	})
}

func (r *IdentityProviderReconciler) resumeSCIMCreateIntent(ctx context.Context, api flarecloudflare.IdentityProviderAPI, object *v1alpha1.IdentityProvider, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, bool, error) {
	secret, err := r.findOwnedSCIMCreateJournal(ctx, object)
	if err != nil {
		return flarecloudflare.IdentityProvider{}, false, err
	}
	if secret == nil {
		return flarecloudflare.IdentityProvider{}, false, nil
	}
	pendingName := secret.Annotations[identityProviderSCIMCreateIntentAnnotation]
	state := secret.Annotations[identityProviderSCIMCreateStateAnnotation]
	if state == identityProviderSCIMCreateConflict {
		return flarecloudflare.IdentityProvider{}, false, fmt.Errorf("the SCIM Secret %s/%s records a conflicting remote create marker", secret.Namespace, secret.Name)
	}
	if state != identityProviderSCIMCreatePrepared && state != identityProviderSCIMCreateIssued {
		return flarecloudflare.IdentityProvider{}, false, fmt.Errorf("the SCIM Secret %s/%s contains unsupported remote create state %q", secret.Namespace, secret.Name, state)
	}
	createInput := identityProviderInputWithSCIMEnabled(input, false)
	createInput.Name = pendingName
	if identityProviderWantsSAMLEncryption(input) {
		createInput.Config.EnableEncryption = nil
	}
	pendingRemote, pendingFound, pendingOccupied, pendingErr := findPendingSCIMIdentityProvider(ctx, api, createInput)
	if state == identityProviderSCIMCreatePrepared {
		if pendingErr != nil && !pendingOccupied {
			return flarecloudflare.IdentityProvider{}, true, pendingErr
		}
		if pendingOccupied {
			conflictErr := r.setSCIMCreateIntentState(ctx, object, pendingName, identityProviderSCIMCreatePrepared, identityProviderSCIMCreateConflict)
			if pendingErr == nil {
				pendingErr = fmt.Errorf("the journaled remote identity provider create marker was occupied before this create attempt")
			}
			return flarecloudflare.IdentityProvider{}, true, errors.Join(pendingErr, conflictErr)
		}
		if err := r.setSCIMCreateIntentState(ctx, object, pendingName, identityProviderSCIMCreatePrepared, identityProviderSCIMCreateIssued); err != nil {
			return flarecloudflare.IdentityProvider{}, true, err
		}
		returned, createErr := api.CreateIdentityProvider(ctx, createInput)
		return returned, true, createErr
	}
	if pendingErr != nil {
		return flarecloudflare.IdentityProvider{}, true, pendingErr
	}
	if pendingFound {
		return pendingRemote, true, nil
	}
	returned, createErr := api.CreateIdentityProvider(ctx, createInput)
	return returned, true, createErr
}
func findPendingSCIMIdentityProvider(ctx context.Context, api flarecloudflare.IdentityProviderAPI, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, bool, bool, error) {
	providers, err := api.ListIdentityProviders(ctx)
	if err != nil {
		return flarecloudflare.IdentityProvider{}, false, false, err
	}
	var found flarecloudflare.IdentityProvider
	for _, remote := range providers {
		if remote.Name != input.Name {
			continue
		}
		if found.ID != "" {
			return flarecloudflare.IdentityProvider{}, false, true, fmt.Errorf("multiple remote identity providers use the journaled pending create marker")
		}
		if remote.ReadOnly || !identityProviderMatchesInput(remote, input) {
			return flarecloudflare.IdentityProvider{}, false, true, fmt.Errorf("the journaled pending create marker is occupied by a non-matching remote identity provider")
		}
		found = remote
	}
	return found, found.ID != "", found.ID != "", nil
}

func validateSCIMSecretDestination(secret *corev1.Secret, object *v1alpha1.IdentityProvider, id string) error {
	if !metav1.IsControlledBy(secret, object) {
		return fmt.Errorf("the SCIM Secret %s/%s is not owned by this IdentityProvider", secret.Namespace, secret.Name)
	}
	boundID := secret.Annotations[v1alpha1.IdentityProviderIDAnnotation]
	hasToken := len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) > 0
	if boundID != "" && boundID != id {
		return fmt.Errorf("the SCIM Secret %s/%s belongs to a different remote IdentityProvider", secret.Namespace, secret.Name)
	}
	if hasToken && boundID == "" {
		return fmt.Errorf("the SCIM Secret %s/%s contains a credential without an exact remote IdentityProvider binding", secret.Namespace, secret.Name)
	}
	return nil
}

func (r *IdentityProviderReconciler) prepareSCIMSecretForEnable(ctx context.Context, object *v1alpha1.IdentityProvider, id string) error {
	if err := r.reserveSCIMSecret(ctx, object, id); err != nil {
		return err
	}
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret := new(corev1.Secret)
		if err := r.Get(ctx, key, secret); err != nil {
			return err
		}
		if err := validateSCIMSecretDestination(secret, object, id); err != nil {
			return err
		}
		if secret.Immutable != nil && *secret.Immutable {
			return fmt.Errorf("the SCIM Secret %s/%s is immutable and cannot capture a one-time credential", secret.Namespace, secret.Name)
		}
		if len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) == 0 &&
			secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] == "" &&
			secret.Annotations[identityProviderSCIMCreateIntentAnnotation] == "" &&
			secret.Annotations[identityProviderSCIMCreateStateAnnotation] == "" {
			return nil
		}
		delete(secret.Data, v1alpha1.IdentityProviderSCIMSecretKey)
		delete(secret.Annotations, v1alpha1.IdentityProviderIDAnnotation)
		delete(secret.Annotations, identityProviderSCIMCreateIntentAnnotation)
		delete(secret.Annotations, identityProviderSCIMCreateStateAnnotation)
		return r.Update(ctx, secret)
	})
}

func (r *IdentityProviderReconciler) captureSCIMSecret(ctx context.Context, object *v1alpha1.IdentityProvider, id, value string) error {
	if value == "" {
		return nil
	}
	if err := r.reserveSCIMSecret(ctx, object, id); err != nil {
		return err
	}
	key := types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}
	return retry.OnError(retry.DefaultBackoff, func(err error) bool {
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}, func() error {
		secret := new(corev1.Secret)
		if err := r.Get(ctx, key, secret); err != nil {
			return err
		}
		if err := validateSCIMSecretDestination(secret, object, id); err != nil {
			return err
		}
		if len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) > 0 {
			if secret.Annotations[identityProviderSCIMCreateIntentAnnotation] == "" &&
				secret.Annotations[identityProviderSCIMCreateStateAnnotation] == "" {
				return nil
			}
			delete(secret.Annotations, identityProviderSCIMCreateIntentAnnotation)
			delete(secret.Annotations, identityProviderSCIMCreateStateAnnotation)
			return r.Update(ctx, secret)
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] = id
		secret.Data[v1alpha1.IdentityProviderSCIMSecretKey] = []byte(value)
		delete(secret.Annotations, identityProviderSCIMCreateIntentAnnotation)
		delete(secret.Annotations, identityProviderSCIMCreateStateAnnotation)
		return r.Update(ctx, secret)
	})
}

func (r *IdentityProviderReconciler) recoverSCIMProviderID(ctx context.Context, object *v1alpha1.IdentityProvider) (string, error) {
	if object.Spec.SCIMConfig == nil || object.Spec.SCIMConfig.SecretRef == nil || object.Spec.SCIMConfig.SecretRef.Name == "" {
		return "", nil
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return "", fmt.Errorf("the SCIM Secret %s/%s is not owned by this IdentityProvider", object.Namespace, secret.Name)
	}
	id := secret.Annotations[v1alpha1.IdentityProviderIDAnnotation]
	if id == "" {
		if len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) > 0 {
			return "", fmt.Errorf("the SCIM Secret %s/%s contains a credential without an exact remote IdentityProvider binding", object.Namespace, secret.Name)
		}
		return "", nil
	}
	return id, nil
}

func (r *IdentityProviderReconciler) recoverSCIMProviderIDForDeletion(ctx context.Context, object *v1alpha1.IdentityProvider) (string, error) {
	if object.Spec.SCIMConfig == nil || object.Spec.SCIMConfig.SecretRef == nil || object.Spec.SCIMConfig.SecretRef.Name == "" {
		return "", nil
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return "", nil
	}
	return secret.Annotations[v1alpha1.IdentityProviderIDAnnotation], nil
}

func (r *IdentityProviderReconciler) requireSCIMSecret(ctx context.Context, object *v1alpha1.IdentityProvider, id string) error {
	if object.Spec.SCIMConfig == nil || object.Spec.SCIMConfig.SecretRef == nil {
		return fmt.Errorf("the SCIM secretRef is not configured")
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Spec.SCIMConfig.SecretRef.Name}, &secret); err != nil {
		return err
	}
	if !metav1.IsControlledBy(&secret, object) {
		return fmt.Errorf("the SCIM Secret %s/%s is not owned by this IdentityProvider", object.Namespace, secret.Name)
	}
	if len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) == 0 {
		return fmt.Errorf("the SCIM Secret %s/%s has no non-empty %q key", object.Namespace, secret.Name, v1alpha1.IdentityProviderSCIMSecretKey)
	}
	if id == "" || secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] != id {
		return fmt.Errorf("the SCIM Secret %s/%s is not bound to remote IdentityProvider %q", object.Namespace, secret.Name, id)
	}
	return nil
}

func (r *IdentityProviderReconciler) recoverSCIMCreateIntentForDeletion(ctx context.Context, object *v1alpha1.IdentityProvider) (string, string, error) {
	secret, err := r.findOwnedSCIMCreateJournal(ctx, object)
	if err != nil {
		return "", "", err
	}
	if secret == nil {
		return "", "", nil
	}
	return secret.Annotations[identityProviderSCIMCreateIntentAnnotation], secret.Annotations[identityProviderSCIMCreateStateAnnotation], nil
}

func (r *IdentityProviderReconciler) checkpointIdentityProvider(ctx context.Context, object *v1alpha1.IdentityProvider, id string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current := new(v1alpha1.IdentityProvider)
		if err := r.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
			return err
		}
		if current.Status.IDPID == id && current.Status.OwnershipVerified {
			*object = *current
			return nil
		}
		base := client.MergeFrom(current.DeepCopy())
		current.Status.IDPID = id
		current.Status.OwnershipVerified = true
		if err := r.Status().Patch(ctx, current, base); err != nil {
			return err
		}
		*object = *current
		return nil
	})
}

func (r *IdentityProviderReconciler) readSCIMDirectory(ctx context.Context, api flarecloudflare.IdentityProviderAPI, remote flarecloudflare.IdentityProvider) (*v1alpha1.IdentityProviderSCIMDirectoryStatus, error) {
	if !identityProviderRemoteSCIMEnabled(remote.SCIMConfig) {
		return nil, nil
	}
	users, usersTruncated, err := api.ListIdentityProviderSCIMUsers(ctx, remote.ID, identityProviderSCIMLimit)
	if err != nil {
		return nil, err
	}
	groups, groupsTruncated, err := api.ListIdentityProviderSCIMGroups(ctx, remote.ID, identityProviderSCIMLimit)
	if err != nil {
		return nil, err
	}
	directory := &v1alpha1.IdentityProviderSCIMDirectoryStatus{BaseURL: remote.SCIMBaseURL, UsersTruncated: usersTruncated, GroupsTruncated: groupsTruncated}
	for _, user := range users {
		directory.Users = append(directory.Users, v1alpha1.IdentityProviderSCIMUserStatus{ID: user.ID, ExternalID: user.ExternalID, DisplayName: user.DisplayName, Active: user.Active, Emails: append([]string(nil), user.Emails...)})
	}
	for _, group := range groups {
		directory.Groups = append(directory.Groups, v1alpha1.IdentityProviderSCIMGroupStatus{ID: group.ID, ExternalID: group.ExternalID, DisplayName: group.DisplayName})
	}
	return directory, nil
}

func identityProviderInputWithSCIMEnabled(input flarecloudflare.IdentityProviderInput, enabled bool) flarecloudflare.IdentityProviderInput {
	if input.SCIMConfig == nil {
		return input
	}
	config := *input.SCIMConfig
	config.Enabled = &enabled
	input.SCIMConfig = &config
	return input
}

func identityProviderWantsSAMLEncryption(input flarecloudflare.IdentityProviderInput) bool {
	return input.Type == v1alpha1.IdentityProviderTypeSAML && input.Config.EnableEncryption != nil && *input.Config.EnableEncryption
}

func identityProviderSCIMEnabled(config *v1alpha1.IdentityProviderSCIMConfig) bool {
	return config != nil && config.Enabled != nil && *config.Enabled
}

func identityProviderRemoteSCIMEnabled(config *v1alpha1.IdentityProviderSCIMConfig) bool {
	return identityProviderSCIMEnabled(config)
}

func identityProviderMatchesInput(remote flarecloudflare.IdentityProvider, input flarecloudflare.IdentityProviderInput) bool {
	if remote.Name != input.Name || remote.Type != input.Type {
		return false
	}
	if input.SAMLCertificateSetID != "" && remote.SAMLCertificateSetID != input.SAMLCertificateSetID {
		return false
	}
	return identityProviderConfigMatches(remote.Config, input.Config) && identityProviderSCIMMatches(remote.SCIMConfig, input.SCIMConfig)
}

func identityProviderConfigMatches(remote, desired v1alpha1.IdentityProviderConfig) bool {
	if desired.ClientID != "" && remote.ClientID != desired.ClientID ||
		desired.EmailClaimName != "" && remote.EmailClaimName != desired.EmailClaimName ||
		desired.DirectoryID != "" && remote.DirectoryID != desired.DirectoryID ||
		desired.Prompt != "" && remote.Prompt != desired.Prompt ||
		desired.AppsDomain != "" && remote.AppsDomain != desired.AppsDomain ||
		desired.CentrifyAccount != "" && remote.CentrifyAccount != desired.CentrifyAccount ||
		desired.CentrifyAppID != "" && remote.CentrifyAppID != desired.CentrifyAppID ||
		desired.AuthorizationServerID != "" && remote.AuthorizationServerID != desired.AuthorizationServerID ||
		desired.OktaAccount != "" && remote.OktaAccount != desired.OktaAccount ||
		desired.OneloginAccount != "" && remote.OneloginAccount != desired.OneloginAccount ||
		desired.PingEnvironmentID != "" && remote.PingEnvironmentID != desired.PingEnvironmentID ||
		desired.AuthURL != "" && remote.AuthURL != desired.AuthURL ||
		desired.CertsURL != "" && remote.CertsURL != desired.CertsURL ||
		desired.TokenURL != "" && remote.TokenURL != desired.TokenURL ||
		desired.EmailAttributeName != "" && remote.EmailAttributeName != desired.EmailAttributeName ||
		desired.IssuerURL != "" && remote.IssuerURL != desired.IssuerURL ||
		desired.SSOTargetURL != "" && remote.SSOTargetURL != desired.SSOTargetURL {
		return false
	}
	if desired.ConditionalAccessEnabled != nil && !equalOptionalBool(remote.ConditionalAccessEnabled, desired.ConditionalAccessEnabled) ||
		desired.SupportGroups != nil && !equalOptionalBool(remote.SupportGroups, desired.SupportGroups) ||
		desired.PKCEEnabled != nil && !equalOptionalBool(remote.PKCEEnabled, desired.PKCEEnabled) ||
		desired.EnableEncryption != nil && !equalOptionalBool(remote.EnableEncryption, desired.EnableEncryption) ||
		desired.ForceAuthn != nil && !equalOptionalBool(remote.ForceAuthn, desired.ForceAuthn) ||
		desired.SignRequest != nil && !equalOptionalBool(remote.SignRequest, desired.SignRequest) ||
		desired.RestrictToAccountMembers != nil && !equalOptionalBool(remote.RestrictToAccountMembers, desired.RestrictToAccountMembers) {
		return false
	}
	if desired.MaxSSOURLLength != nil && (remote.MaxSSOURLLength == nil || *remote.MaxSSOURLLength != *desired.MaxSSOURLLength) {
		return false
	}
	return equalStringSet(remote.Claims, desired.Claims) &&
		equalStringSet(remote.Scopes, desired.Scopes) &&
		equalStringSet(remote.Attributes, desired.Attributes) &&
		equalStringSet(remote.IDPPublicCerts, desired.IDPPublicCerts) &&
		(len(desired.HeaderAttributes) == 0 || reflect.DeepEqual(remote.HeaderAttributes, desired.HeaderAttributes))
}

func identityProviderSCIMMatches(remote, desired *v1alpha1.IdentityProviderSCIMConfig) bool {
	if desired == nil {
		return true
	}
	if desired.Enabled != nil && (remote == nil || !equalOptionalBool(remote.Enabled, desired.Enabled)) ||
		desired.SeatDeprovision != nil && (remote == nil || !equalOptionalBool(remote.SeatDeprovision, desired.SeatDeprovision)) ||
		desired.UserDeprovision != nil && (remote == nil || !equalOptionalBool(remote.UserDeprovision, desired.UserDeprovision)) ||
		desired.IdentityUpdateBehavior != "" && (remote == nil || remote.IdentityUpdateBehavior != desired.IdentityUpdateBehavior) {
		return false
	}
	return true
}

func equalOptionalBool(observed, desired *bool) bool {
	return observed != nil && desired != nil && *observed == *desired
}

func equalStringSet(observed, desired []string) bool {
	if len(desired) == 0 {
		return true
	}
	observed = append([]string(nil), observed...)
	desired = append([]string(nil), desired...)
	slices.Sort(observed)
	slices.Sort(desired)
	return slices.Equal(observed, desired)
}

func (r *IdentityProviderReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.IdentityProvider) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.IdentityProviderFinalizer) {
		return nil
	}
	shouldDeleteRemote := object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete
	id := object.Status.IDPID
	ownershipVerified := object.Status.OwnershipVerified
	pendingName := ""
	pendingState := ""
	if shouldDeleteRemote {
		if id == "" {
			recoveredID, err := r.recoverSCIMProviderIDForDeletion(ctx, object)
			if err != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
			}
			if recoveredID != "" {
				id = recoveredID
				ownershipVerified = true
			}
		}
		var err error
		pendingName, pendingState, err = r.recoverSCIMCreateIntentForDeletion(ctx, object)
		if err != nil {
			return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
		}
	}
	if shouldDeleteRemote && ((id != "" && ownershipVerified) || (pendingName != "" && pendingState == identityProviderSCIMCreateIssued)) {
		api, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
		}
		if id != "" && ownershipVerified {
			remote, getErr := api.GetIdentityProvider(ctx, id)
			if getErr != nil {
				if err = ignoreRemoteNotFound(getErr); err != nil {
					return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
				}
			} else if !remote.ReadOnly {
				if err = ignoreRemoteNotFound(api.DeleteIdentityProvider(ctx, id)); err != nil {
					return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
				}
			}
		}
		if pendingName != "" && pendingState == identityProviderSCIMCreateIssued {
			input := flarecloudflare.IdentityProviderInput{
				Name:       pendingName,
				Type:       object.Spec.Type,
				Config:     object.Spec.Config,
				SCIMConfig: object.Spec.SCIMConfig,
			}
			input = identityProviderInputWithSCIMEnabled(input, false)
			if identityProviderWantsSAMLEncryption(input) {
				input.Config.EnableEncryption = nil
			}
			pendingRemote, found, _, findErr := findPendingSCIMIdentityProvider(ctx, api, input)
			if findErr != nil {
				return r.patchCleanupBlocked(ctx, object, "RemoteError", findErr)
			}
			if found && pendingRemote.ID != id && !pendingRemote.ReadOnly {
				if err = ignoreRemoteNotFound(api.DeleteIdentityProvider(ctx, pendingRemote.ID)); err != nil {
					return r.patchCleanupBlocked(ctx, object, "RemoteError", err)
				}
			}
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.IdentityProviderFinalizer)
	return r.Patch(ctx, object, base)
}
func (r *IdentityProviderReconciler) patchStatus(ctx context.Context, object *v1alpha1.IdentityProvider, remote flarecloudflare.IdentityProvider, directory *v1alpha1.IdentityProviderSCIMDirectoryStatus, status metav1.ConditionStatus, reason, message string) error {
	beforeStatus := object.Status
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.IDPID = remote.ID
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && !remote.ReadOnly
	}
	object.Status.ReadOnly = remote.ReadOnly
	switch remote.Type {
	case v1alpha1.IdentityProviderTypeOneTimePIN, v1alpha1.IdentityProviderTypeCloudflare:
		object.Status.RedirectURL = remote.RedirectURL
	default:
		object.Status.RedirectURL = ""
	}
	if remote.SAMLCertificateSet != nil {
		object.Status.SAMLCertificateSet = identityProviderSAMLCertificateStatus(remote.SAMLCertificateSet)
	}
	if directory != nil || status == metav1.ConditionTrue {
		object.Status.SCIMDirectory = directory
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	if reflect.DeepEqual(beforeStatus, object.Status) {
		return nil
	}
	return r.Status().Patch(ctx, object, base)
}

// finishRemoteError reports a failed remote call on the object's conditions.
// A typed 404 revokes acceptance because the remote object is gone; any other
// failure is transient, so the existing Accepted condition and the recorded
// remote identifiers are preserved while Ready flips to False.
func (r *IdentityProviderReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.IdentityProvider, err error) error {
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

func (r *IdentityProviderReconciler) patchCleanupBlocked(ctx context.Context, object *v1alpha1.IdentityProvider, reason string, cause error) error {
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

func identityProviderSAMLCertificateStatus(value *flarecloudflare.IdentityProviderSAMLCertificateSet) *v1alpha1.IdentityProviderSAMLCertificateSetStatus {
	if value == nil || value.ID == "" {
		return nil
	}
	result := &v1alpha1.IdentityProviderSAMLCertificateSetStatus{ID: value.ID}
	if !value.CreatedAt.IsZero() {
		stamp := metav1.NewTime(value.CreatedAt)
		result.CreatedAt = &stamp
	}
	if !value.UpdatedAt.IsZero() {
		stamp := metav1.NewTime(value.UpdatedAt)
		result.UpdatedAt = &stamp
	}
	result.Current = identityProviderCertificateStatus(value.Current)
	result.Previous = identityProviderCertificateStatus(value.Previous)
	return result
}

func identityProviderCertificateStatus(value *flarecloudflare.IdentityProviderSAMLCertificate) *v1alpha1.IdentityProviderSAMLCertificateStatus {
	if value == nil || value.ID == "" {
		return nil
	}
	result := &v1alpha1.IdentityProviderSAMLCertificateStatus{ID: value.ID, Current: value.Current, PublicCertificate: value.PublicCertificate}
	if !value.NotAfter.IsZero() {
		stamp := metav1.NewTime(value.NotAfter)
		result.NotAfter = &stamp
	}
	return result
}

func (r *IdentityProviderReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the IdentityProvider controller and dependency watches.
func (r *IdentityProviderReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.IdentityProvider{}, identityProviderAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.IdentityProvider).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index IdentityProvider accounts: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.IdentityProvider{}, identityProviderSecretIndex, func(object client.Object) []string {
		provider := object.(*v1alpha1.IdentityProvider)
		var keys []string
		if ref := provider.Spec.Config.ClientSecretRef; ref != nil && ref.Name != "" {
			keys = append(keys, object.GetNamespace()+"/"+ref.Name)
		}
		if provider.Spec.SCIMConfig != nil && provider.Spec.SCIMConfig.SecretRef != nil && provider.Spec.SCIMConfig.SecretRef.Name != "" {
			keys = append(keys, object.GetNamespace()+"/"+provider.Spec.SCIMConfig.SecretRef.Name)
		}
		return keys
	}); err != nil {
		return fmt.Errorf("index IdentityProvider Secrets: %w", err)
	}
	b := ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.IdentityProvider{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.providersForAccount)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.providersForSecret)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.providersForNamespace))
	if r.SweepEvents != nil {
		b = b.WatchesRawSource(source.Channel(r.SweepEvents, &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(observedReconciler("identity-provider", r))
}

func (r *IdentityProviderReconciler) providersForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.IdentityProviderList
	if err := r.List(ctx, &list, client.MatchingFields{identityProviderAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return identityProviderRequests(list.Items)
}

func (r *IdentityProviderReconciler) providersForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.IdentityProviderList
	if err := r.List(ctx, &list, client.MatchingFields{identityProviderSecretIndex: object.GetNamespace() + "/" + object.GetName()}); err != nil {
		return nil
	}
	return identityProviderRequests(list.Items)
}

func (r *IdentityProviderReconciler) providersForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.IdentityProviderList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return identityProviderRequests(list.Items)
}

func identityProviderRequests(items []v1alpha1.IdentityProvider) []reconcile.Request {
	out := make([]reconcile.Request, len(items))
	for i := range items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}}
	}
	return out
}
