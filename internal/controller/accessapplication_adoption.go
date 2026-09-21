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
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func (r *AccessApplicationReconciler) reconcileRemoteApplication(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
	ownerTag string,
) (flarecloudflare.AccessApplication, error) {
	// T0: every remote read in this function is a fresh read by contract.
	// The desired-hash gate in reconcileActive decides whether this function
	// runs at all; once it runs, ObserveOnly observation, AdoptByID
	// verification, ownership checks, and create-conflict recovery must see
	// the live remote — a stale snapshot would let an adoption claim or a
	// destructive update proceed on outdated ownership evidence.
	if input.Type == flarecloudflare.AccessApplicationTypeProxyEndpoint && len(application.Spec.Application.Tags) > 0 {
		return flarecloudflare.AccessApplication{}, errors.New("ProxyEndpoint Access applications do not support application tags")
	}
	policy := effectiveManagementPolicy(application.Spec.ManagementPolicy)
	if policy == v1alpha1.ManagementPolicyObserveOnly {
		if application.Spec.ExternalRef == nil {
			return flarecloudflare.AccessApplication{}, errors.New("management policy ObserveOnly for AccessApplication requires externalRef")
		}
		observed, err := remote.GetAccessApplication(ctx, scope, application.Spec.ExternalRef.ApplicationID)
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if err := verifyAccessApplicationExpectation(observed, application.Spec.Adoption.Expect); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return observed, nil
	}
	if input.Type == flarecloudflare.AccessApplicationTypeProxyEndpoint {
		return r.reconcileProxyEndpointApplication(ctx, remote, scope, application, input)
	}
	// D13: writes carry exactly one owner marker — the HMAC tag when the
	// cluster ownership key is available, the legacy plaintext tag otherwise.
	// Reads still accept either form, so legacy-marked remotes are recognized
	// and upgraded to the signed marker on the next write.
	_, ownerTags, writeTag := r.accessOwnerTags(ctx, application, ownerTag)
	if writeTag != ownerTag {
		input.Tags = append(removeAccessTags(input.Tags, ownerTag), writeTag)
		slices.Sort(input.Tags)
		input.Tags = slices.Compact(input.Tags)
	}
	if application.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
		if application.Spec.ExternalRef == nil {
			return flarecloudflare.AccessApplication{}, errors.New("adoption mode AdoptById for AccessApplication requires externalRef")
		}
		observed, err := remote.GetAccessApplication(ctx, scope, application.Spec.ExternalRef.ApplicationID)
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		managedRecovery := observed.Name == input.Name &&
			hasAccessTag(observed.Tags, accessManagedTag) &&
			hasAnyAccessTag(observed.Tags, ownerTags)
		if !managedRecovery {
			if err := verifyAccessApplicationExpectation(observed, application.Spec.Adoption.Expect); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
		}
		if accessApplicationMatchesInput(observed, input) {
			return observed, nil
		}
		if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return remote.UpdateAccessApplication(ctx, scope, observed.ID, input)
	}
	if application.Status.ApplicationID != "" {
		current, err := remote.GetAccessApplication(ctx, scope, application.Status.ApplicationID)
		if err == nil {
			if !hasAnyAccessTag(current.Tags, ownerTags) || !hasAccessTag(current.Tags, accessManagedTag) {
				return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: Access application %q is not owned by this resource", application.Status.ApplicationID)
			}
			if accessApplicationMatchesInput(current, input) {
				return current, nil
			}
			if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
			return remote.UpdateAccessApplication(ctx, scope, current.ID, input)
		}
		if !isRemoteNotFound(err) {
			return flarecloudflare.AccessApplication{}, err
		}
	}
	if application.Spec.ExternalRef != nil {
		return flarecloudflare.AccessApplication{}, errors.New("managed AccessApplication externalRef requires adoption.mode AdoptById")
	}
	recovered, found, err := findOwnedParentApplication(ctx, remote, scope, ownerTags, input.Name)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if found {
		if accessApplicationMatchesInput(recovered, input) {
			return recovered, nil
		}
		if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return remote.UpdateAccessApplication(ctx, scope, recovered.ID, input)
	}
	if err := ensureAccessTags(ctx, remote, input.Tags...); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	created, createErr := remote.CreateAccessApplication(ctx, scope, input)
	if createErr == nil {
		return created.Application, nil
	}
	recovered, found, recoveryErr := findOwnedParentApplication(ctx, remote, scope, ownerTags, input.Name)
	if recoveryErr != nil {
		return flarecloudflare.AccessApplication{}, errors.Join(createErr, recoveryErr)
	}
	if found {
		return recovered, nil
	}
	return flarecloudflare.AccessApplication{}, createErr
}

func verifyAccessApplicationExpectation(observed flarecloudflare.AccessApplication, expected v1alpha1.AdoptionExpect) error {
	if expected.Name != "" && observed.Name != expected.Name {
		return fmt.Errorf("adoption conflict: Access application name %q does not match expected %q", observed.Name, expected.Name)
	}
	if expected.Domain != "" && observed.Domain != expected.Domain {
		return fmt.Errorf("adoption conflict: Access application domain %q does not match expected %q", observed.Domain, expected.Domain)
	}
	return nil
}

// findOwnedParentApplication recovers a managed parent by name and ownership
// marker. During the HMAC transition ownerTags carries the legacy plaintext
// tag and, when the cluster key is available, the signed tag; either proves
// ownership. A candidate that also carries a foreign owner marker is a
// contradiction (D8): it is never adopted.
func findOwnedParentApplication(ctx context.Context, remote AccessApplicationCloudflareClient, scope flarecloudflare.AccessScope, ownerTags []string, name string) (flarecloudflare.AccessApplication, bool, error) {
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return flarecloudflare.AccessApplication{}, false, fmt.Errorf("list Access applications for ownership recovery: %w", err)
	}
	var found flarecloudflare.AccessApplication
	for _, application := range applications {
		if application.Name != name ||
			!hasAccessTag(application.Tags, accessManagedTag) ||
			!hasAnyAccessTag(application.Tags, ownerTags) {
			continue
		}
		if foreign := foreignAccessOwnerTags(application.Tags, ownerTags); len(foreign) > 0 {
			return flarecloudflare.AccessApplication{}, false, fmt.Errorf(
				"access application %q (%s) carries conflicting owner markers %v", name, application.ID, foreign)
		}
		if found.ID != "" && found.ID != application.ID {
			return flarecloudflare.AccessApplication{}, false, fmt.Errorf("multiple Access applications carry owner tags %v and name %q", ownerTags, name)
		}
		found = application
	}
	return found, found.ID != "", nil
}

func (r *AccessApplicationReconciler) persistParentID(ctx context.Context, application *v1alpha1.AccessApplication, id string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current v1alpha1.AccessApplication
		if err := r.Get(ctx, client.ObjectKeyFromObject(application), &current); err != nil {
			return err
		}
		before := current.DeepCopy()
		current.Status.ApplicationID = id
		return r.Status().Patch(ctx, &current, client.MergeFrom(before))
	})
}

const accessApplicationProxyIdentityKey = "identity.json"

type accessApplicationProxyCheckpoint struct {
	ApplicationID string                                         `json:"applicationId,omitempty"`
	Type          flarecloudflare.AccessApplicationType          `json:"type"`
	Domain        string                                         `json:"domain"`
	Destinations  []flarecloudflare.AccessApplicationDestination `json:"destinations"`
	ExistingIDs   []string                                       `json:"existingIds,omitempty"`
}

func proxyEndpointCheckpointName(uid types.UID) string {
	return "access-proxy-identity-" + string(uid)
}

func proxyEndpointCheckpointFromInput(id string, input flarecloudflare.AccessApplicationInput) accessApplicationProxyCheckpoint {
	return accessApplicationProxyCheckpoint{
		ApplicationID: id,
		Type:          input.Type,
		Domain:        input.Domain,
		Destinations:  slices.Clone(input.Destinations),
	}
}

func proxyEndpointCheckpointFromStatus(application *v1alpha1.AccessApplication) accessApplicationProxyCheckpoint {
	applicationType := flarecloudflare.AccessApplicationType(application.Status.Type)
	if applicationType == "" {
		applicationType = flarecloudflare.AccessApplicationType(application.Spec.Type)
	}
	destinations := make([]flarecloudflare.AccessApplicationDestination, 0, len(application.Status.Destinations))
	for _, destination := range application.Status.Destinations {
		protocol := flarecloudflare.AccessApplicationL4Protocol("")
		if destination.L4Protocol != nil {
			protocol = flarecloudflare.AccessApplicationL4Protocol(*destination.L4Protocol)
		}
		destinations = append(destinations, flarecloudflare.AccessApplicationDestination{
			Type:        flarecloudflare.AccessApplicationDestinationType(destination.Type),
			URI:         destination.URI,
			Hostname:    destination.Hostname,
			CIDR:        destination.CIDR,
			PortRange:   destination.PortRange,
			L4Protocol:  protocol,
			VNetID:      destination.VNetID,
			MCPServerID: destination.MCPServerID,
			WorkerID:    destination.WorkerID,
		})
	}
	return accessApplicationProxyCheckpoint{
		ApplicationID: application.Status.ApplicationID,
		Type:          applicationType,
		Domain:        application.Status.Domain,
		Destinations:  destinations,
	}
}

func proxyEndpointCheckpointMatchesInput(checkpoint accessApplicationProxyCheckpoint, input flarecloudflare.AccessApplicationInput) bool {
	return checkpoint.Type == input.Type &&
		checkpoint.Domain == input.Domain &&
		slices.Equal(checkpoint.Destinations, input.Destinations)
}

func proxyEndpointCheckpointsSameIdentity(left, right accessApplicationProxyCheckpoint) bool {
	return left.Type == right.Type &&
		left.Domain == right.Domain &&
		slices.Equal(left.Destinations, right.Destinations)
}

func proxyEndpointCheckpointMatchesApplication(checkpoint accessApplicationProxyCheckpoint, application flarecloudflare.AccessApplication) bool {
	// ProxyEndpoint destinations are a controller-side identity component but are
	// not part of Cloudflare's wire shape. The pre-create ID baseline distinguishes
	// an exact type/domain response from every object that existed before the intent.
	return checkpoint.Type == application.Type && checkpoint.Domain == application.Domain
}

func (r *AccessApplicationReconciler) prepareProxyEndpointCreateIntent(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
) (accessApplicationProxyCheckpoint, error) {
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return accessApplicationProxyCheckpoint{}, fmt.Errorf("list Access applications before ProxyEndpoint create: %w", err)
	}
	existingIDs := make([]string, 0, len(applications))
	for _, existing := range applications {
		if existing.ID != "" {
			existingIDs = append(existingIDs, existing.ID)
		}
	}
	slices.Sort(existingIDs)
	existingIDs = slices.Compact(existingIDs)
	intent := proxyEndpointCheckpointFromInput("", input)
	intent.ExistingIDs = existingIDs
	if err := r.persistProxyEndpointCheckpoint(ctx, application, intent); err != nil {
		return accessApplicationProxyCheckpoint{}, err
	}
	return intent, nil
}

func findProxyEndpointIntentCandidate(
	checkpoint accessApplicationProxyCheckpoint,
	applications []flarecloudflare.AccessApplication,
) (flarecloudflare.AccessApplication, bool, error) {
	existing := make(map[string]struct{}, len(checkpoint.ExistingIDs))
	for _, id := range checkpoint.ExistingIDs {
		existing[id] = struct{}{}
	}
	var found flarecloudflare.AccessApplication
	for _, candidate := range applications {
		if _, wasPresent := existing[candidate.ID]; wasPresent ||
			!proxyEndpointCheckpointMatchesApplication(checkpoint, candidate) {
			continue
		}
		if found.ID != "" && found.ID != candidate.ID {
			return flarecloudflare.AccessApplication{}, false, errors.New("multiple Access applications match the pending ProxyEndpoint create intent")
		}
		found = candidate
	}
	return found, found.ID != "", nil
}

func (r *AccessApplicationReconciler) recoverProxyEndpointCreateIntent(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
	intent accessApplicationProxyCheckpoint,
) (flarecloudflare.AccessApplication, error) {
	applications, err := remote.ListAccessApplications(ctx, scope)
	if err != nil {
		return flarecloudflare.AccessApplication{}, fmt.Errorf("list Access applications for ProxyEndpoint create recovery: %w", err)
	}
	recovered, found, err := findProxyEndpointIntentCandidate(intent, applications)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if !found {
		return r.createCheckpointedProxyEndpoint(ctx, remote, scope, application, input)
	}
	completed := proxyEndpointCheckpointFromInput(recovered.ID, input)
	if err := r.persistProxyEndpointCheckpoint(ctx, application, completed); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	return r.updateCheckpointedProxyEndpoint(ctx, remote, scope, application, recovered, input, completed)
}

func (r *AccessApplicationReconciler) reconcileProxyEndpointApplication(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
) (flarecloudflare.AccessApplication, error) {
	checkpoint, err := r.proxyEndpointCheckpoint(ctx, application)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if application.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
		if application.Spec.ExternalRef == nil {
			return flarecloudflare.AccessApplication{}, errors.New("adoption mode AdoptById for AccessApplication requires externalRef")
		}
		id := application.Spec.ExternalRef.ApplicationID
		if checkpoint != nil && checkpoint.ApplicationID != "" && checkpoint.ApplicationID != id {
			return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: ProxyEndpoint checkpoint identifies Access application %q, not adopted application %q", checkpoint.ApplicationID, id)
		}
		observed, err := remote.GetAccessApplication(ctx, scope, id)
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if err := verifyAccessApplicationExpectation(observed, application.Spec.Adoption.Expect); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if err := verifyProxyEndpointType(observed, id); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if checkpoint == nil || checkpoint.ApplicationID == "" {
			candidate := proxyEndpointCheckpointFromInput(id, input)
			if checkpoint != nil && !proxyEndpointCheckpointMatchesInput(*checkpoint, input) {
				return flarecloudflare.AccessApplication{}, errors.New("ownership conflict: pending ProxyEndpoint create intent does not exactly match the adopted type, domain, and destinations")
			}
			if err := r.persistProxyEndpointCheckpoint(ctx, application, candidate); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
			checkpoint = &candidate
		}
		return r.updateCheckpointedProxyEndpoint(ctx, remote, scope, application, observed, input, *checkpoint)
	}
	if checkpoint != nil {
		if checkpoint.ApplicationID == "" {
			if application.Status.ApplicationID != "" {
				return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: ProxyEndpoint status identifies Access application %q while its create checkpoint is still pending", application.Status.ApplicationID)
			}
			if !proxyEndpointCheckpointMatchesInput(*checkpoint, input) {
				return flarecloudflare.AccessApplication{}, errors.New("ownership conflict: pending ProxyEndpoint create intent does not exactly match the desired type, domain, and destinations")
			}
			return r.recoverProxyEndpointCreateIntent(ctx, remote, scope, application, input, *checkpoint)
		}
		if application.Status.ApplicationID != "" && application.Status.ApplicationID != checkpoint.ApplicationID {
			return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: ProxyEndpoint status identifies Access application %q, but its checkpoint identifies %q", application.Status.ApplicationID, checkpoint.ApplicationID)
		}
		if application.Status.ApplicationID == "" && !proxyEndpointCheckpointMatchesInput(*checkpoint, input) {
			return flarecloudflare.AccessApplication{}, errors.New("ownership conflict: ProxyEndpoint status is missing and its identity checkpoint does not exactly match the desired type, domain, and destinations")
		}
		observed, err := remote.GetAccessApplication(ctx, scope, checkpoint.ApplicationID)
		if isRemoteNotFound(err) {
			if err := r.deleteProxyEndpointCheckpoint(ctx, application); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
			if _, err := r.prepareProxyEndpointCreateIntent(ctx, remote, scope, application, input); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
			return r.createCheckpointedProxyEndpoint(ctx, remote, scope, application, input)
		}
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if err := verifyProxyEndpointType(observed, checkpoint.ApplicationID); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return r.updateCheckpointedProxyEndpoint(ctx, remote, scope, application, observed, input, *checkpoint)
	}
	if application.Status.ApplicationID != "" {
		observed, err := remote.GetAccessApplication(ctx, scope, application.Status.ApplicationID)
		if err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		if err := verifyProxyEndpointType(observed, application.Status.ApplicationID); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		recovered := proxyEndpointCheckpointFromStatus(application)
		if recovered.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
			return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: ProxyEndpoint status records type %q", recovered.Type)
		}
		if err := r.persistProxyEndpointCheckpoint(ctx, application, recovered); err != nil {
			return flarecloudflare.AccessApplication{}, err
		}
		return r.updateCheckpointedProxyEndpoint(ctx, remote, scope, application, observed, input, recovered)
	}
	if application.Spec.ExternalRef != nil {
		return flarecloudflare.AccessApplication{}, errors.New("managed AccessApplication externalRef requires adoption.mode AdoptById")
	}
	if _, err := r.prepareProxyEndpointCreateIntent(ctx, remote, scope, application, input); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	return r.createCheckpointedProxyEndpoint(ctx, remote, scope, application, input)
}

func (r *AccessApplicationReconciler) createCheckpointedProxyEndpoint(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
) (flarecloudflare.AccessApplication, error) {
	created, err := remote.CreateAccessApplication(ctx, scope, input)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if created.Application.ID == "" {
		return flarecloudflare.AccessApplication{}, errors.New("created ProxyEndpoint Access application has no ID")
	}
	if err := verifyProxyEndpointType(created.Application, created.Application.ID); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	checkpoint := proxyEndpointCheckpointFromInput(created.Application.ID, input)
	if err := r.persistProxyEndpointCheckpoint(ctx, application, checkpoint); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	return created.Application, nil
}

func (r *AccessApplicationReconciler) updateCheckpointedProxyEndpoint(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
	observed flarecloudflare.AccessApplication,
	input flarecloudflare.AccessApplicationInput,
	checkpoint accessApplicationProxyCheckpoint,
) (flarecloudflare.AccessApplication, error) {
	if checkpoint.ApplicationID != observed.ID {
		return flarecloudflare.AccessApplication{}, fmt.Errorf("ownership conflict: ProxyEndpoint checkpoint identifies Access application %q, not %q", checkpoint.ApplicationID, observed.ID)
	}
	if accessApplicationMatchesInput(observed, input) {
		if !proxyEndpointCheckpointMatchesInput(checkpoint, input) {
			if err := r.persistProxyEndpointCheckpoint(ctx, application, proxyEndpointCheckpointFromInput(observed.ID, input)); err != nil {
				return flarecloudflare.AccessApplication{}, err
			}
		}
		return observed, nil
	}
	updated, err := remote.UpdateAccessApplication(ctx, scope, observed.ID, input)
	if err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if err := verifyProxyEndpointType(updated, observed.ID); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	if err := r.persistProxyEndpointCheckpoint(ctx, application, proxyEndpointCheckpointFromInput(updated.ID, input)); err != nil {
		return flarecloudflare.AccessApplication{}, err
	}
	return updated, nil
}

func verifyProxyEndpointType(observed flarecloudflare.AccessApplication, id string) error {
	if observed.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
		return fmt.Errorf("ownership conflict: Access application %q has type %q, not ProxyEndpoint", id, observed.Type)
	}
	return nil
}

func (r *AccessApplicationReconciler) proxyEndpointCheckpoint(ctx context.Context, application *v1alpha1.AccessApplication) (*accessApplicationProxyCheckpoint, error) {
	if application.UID == "" {
		return nil, errors.New("ProxyEndpoint identity checkpoint requires a non-empty AccessApplication UID")
	}
	key := types.NamespacedName{Namespace: application.Namespace, Name: proxyEndpointCheckpointName(application.UID)}
	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get ProxyEndpoint identity checkpoint Secret: %w", err)
	}
	if !metav1.IsControlledBy(&secret, application) {
		return nil, fmt.Errorf("ProxyEndpoint identity checkpoint Secret %s/%s is not controlled by this AccessApplication", key.Namespace, key.Name)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		return nil, fmt.Errorf("ProxyEndpoint identity checkpoint Secret %s/%s has type %q", key.Namespace, key.Name, secret.Type)
	}
	var checkpoint accessApplicationProxyCheckpoint
	if err := json.Unmarshal(secret.Data[accessApplicationProxyIdentityKey], &checkpoint); err != nil {
		return nil, fmt.Errorf("decode ProxyEndpoint identity checkpoint Secret: %w", err)
	}
	if checkpoint.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
		return nil, errors.New("ProxyEndpoint identity checkpoint Secret contains an invalid identity")
	}
	return &checkpoint, nil
}

func (r *AccessApplicationReconciler) persistProxyEndpointCheckpoint(ctx context.Context, application *v1alpha1.AccessApplication, checkpoint accessApplicationProxyCheckpoint) error {
	if application.UID == "" {
		return errors.New("ProxyEndpoint identity checkpoint requires a non-empty AccessApplication UID")
	}
	if checkpoint.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
		return errors.New("refuse to persist an invalid ProxyEndpoint identity checkpoint")
	}
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("encode ProxyEndpoint identity checkpoint: %w", err)
	}
	key := types.NamespacedName{Namespace: application.Namespace, Name: proxyEndpointCheckpointName(application.UID)}
	var secret corev1.Secret
	getErr := r.Get(ctx, key, &secret)
	if apierrors.IsNotFound(getErr) {
		secret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
		if err := controllerutil.SetControllerReference(application, &secret, r.Scheme); err != nil {
			return fmt.Errorf("set AccessApplication owner on ProxyEndpoint identity checkpoint Secret: %w", err)
		}
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{accessApplicationProxyIdentityKey: payload}
		if err := r.Create(ctx, &secret); err != nil {
			return fmt.Errorf("create ProxyEndpoint identity checkpoint Secret: %w", err)
		}
		return nil
	}
	if getErr != nil {
		return fmt.Errorf("get ProxyEndpoint identity checkpoint Secret: %w", getErr)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		return fmt.Errorf("ProxyEndpoint identity checkpoint Secret %s/%s has type %q", key.Namespace, key.Name, secret.Type)
	}
	if !metav1.IsControlledBy(&secret, application) {
		return fmt.Errorf("ProxyEndpoint identity checkpoint Secret %s/%s is not controlled by this AccessApplication", key.Namespace, key.Name)
	}
	var current accessApplicationProxyCheckpoint
	if err := json.Unmarshal(secret.Data[accessApplicationProxyIdentityKey], &current); err != nil {
		return fmt.Errorf("decode existing ProxyEndpoint identity checkpoint Secret: %w", err)
	}
	if current.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
		return errors.New("existing ProxyEndpoint identity checkpoint Secret contains an invalid identity")
	}
	if current.ApplicationID == "" && !proxyEndpointCheckpointsSameIdentity(current, checkpoint) {
		return errors.New("refuse to change the exact type, domain, or destinations of a pending ProxyEndpoint create intent")
	}
	if current.ApplicationID != "" && current.ApplicationID != checkpoint.ApplicationID {
		return fmt.Errorf("refuse to repoint ProxyEndpoint identity checkpoint from Access application %q to %q", current.ApplicationID, checkpoint.ApplicationID)
	}
	before := secret.DeepCopy()
	secret.Type = corev1.SecretTypeOpaque
	secret.Data = map[string][]byte{accessApplicationProxyIdentityKey: payload}
	if err := r.Patch(ctx, &secret, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("update ProxyEndpoint identity checkpoint Secret: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) deleteProxyEndpointCheckpoint(ctx context.Context, application *v1alpha1.AccessApplication) error {
	if application.UID == "" {
		return errors.New("ProxyEndpoint identity checkpoint requires a non-empty AccessApplication UID")
	}
	key := types.NamespacedName{Namespace: application.Namespace, Name: proxyEndpointCheckpointName(application.UID)}
	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get ProxyEndpoint identity checkpoint Secret for deletion: %w", err)
	}
	if !metav1.IsControlledBy(&secret, application) {
		return fmt.Errorf("refuse to delete ProxyEndpoint identity checkpoint Secret %s/%s not controlled by this AccessApplication", key.Namespace, key.Name)
	}
	if err := r.Delete(ctx, &secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete ProxyEndpoint identity checkpoint Secret: %w", err)
	}
	return nil
}

func (r *AccessApplicationReconciler) deleteManagedProxyEndpointApplication(
	ctx context.Context,
	remote AccessApplicationCloudflareClient,
	scope flarecloudflare.AccessScope,
	application *v1alpha1.AccessApplication,
) error {
	checkpoint, err := r.proxyEndpointCheckpoint(ctx, application)
	if err != nil {
		return err
	}
	if checkpoint == nil {
		if application.Status.ApplicationID == "" {
			return nil
		}
		recovered := proxyEndpointCheckpointFromStatus(application)
		if recovered.Type != flarecloudflare.AccessApplicationTypeProxyEndpoint {
			return fmt.Errorf("ownership conflict: ProxyEndpoint status records type %q", recovered.Type)
		}
		if err := r.persistProxyEndpointCheckpoint(ctx, application, recovered); err != nil {
			return err
		}
		checkpoint = &recovered
	}
	if checkpoint.ApplicationID == "" {
		if application.Status.ApplicationID != "" {
			return fmt.Errorf("ownership conflict: ProxyEndpoint status identifies Access application %q while its create checkpoint is still pending", application.Status.ApplicationID)
		}
		applications, err := remote.ListAccessApplications(ctx, scope)
		if err != nil {
			return fmt.Errorf("list Access applications for pending ProxyEndpoint deletion: %w", err)
		}
		recovered, found, err := findProxyEndpointIntentCandidate(*checkpoint, applications)
		if err != nil {
			return err
		}
		if !found {
			return r.deleteProxyEndpointCheckpoint(ctx, application)
		}
		completed := *checkpoint
		completed.ApplicationID = recovered.ID
		completed.ExistingIDs = nil
		if err := r.persistProxyEndpointCheckpoint(ctx, application, completed); err != nil {
			return err
		}
		checkpoint = &completed
	}
	if application.Status.ApplicationID != "" && application.Status.ApplicationID != checkpoint.ApplicationID {
		return fmt.Errorf("ownership conflict: ProxyEndpoint status identifies Access application %q, but its checkpoint identifies %q", application.Status.ApplicationID, checkpoint.ApplicationID)
	}
	observed, err := remote.GetAccessApplication(ctx, scope, checkpoint.ApplicationID)
	if isRemoteNotFound(err) {
		return r.deleteProxyEndpointCheckpoint(ctx, application)
	}
	if err != nil {
		return fmt.Errorf("get ProxyEndpoint Access application %s for deletion: %w", checkpoint.ApplicationID, err)
	}
	if err := verifyProxyEndpointType(observed, checkpoint.ApplicationID); err != nil {
		return err
	}
	if err := remote.DeleteAccessApplication(ctx, scope, checkpoint.ApplicationID); err != nil && !isRemoteNotFound(err) {
		return fmt.Errorf("delete ProxyEndpoint Access application %s: %w", checkpoint.ApplicationID, err)
	}
	return r.deleteProxyEndpointCheckpoint(ctx, application)
}

func effectiveManagementPolicy(policy v1alpha1.ManagementPolicy) v1alpha1.ManagementPolicy {
	if policy == "" {
		return v1alpha1.ManagementPolicyManaged
	}
	return policy
}

func effectiveDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyDelete
	}
	return policy
}
