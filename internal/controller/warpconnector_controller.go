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
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	warpConnectorAccountIndex       = "flareway.warpConnector.account"
	warpConnectorRequeue            = 30 * time.Second
	warpConnectorSecretPrefix       = "flareway-warp-"
	warpConnectorTunnelIDAnnotation = "flareway.bhyoo.com/warp-connector-tunnel-id"
)

// NewWARPConnectorCloudflareClient constructs an account-scoped WARP Connector client.
type NewWARPConnectorCloudflareClient func(token, accountID string) (flarecloudflare.WARPConnectorAPI, error)

// WARPConnectorClientFromFactory adapts the shared production Cloudflare factory.
func WARPConnectorClientFromFactory(factory flarecloudflare.ClientFactory) NewWARPConnectorCloudflareClient {
	return func(token, accountID string) (flarecloudflare.WARPConnectorAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		api := factory.Client(token, accountID)
		warp, ok := api.(flarecloudflare.WARPConnectorAPI)
		if !ok {
			return nil, errors.New("cloudflare client does not implement WARP Connector API")
		}
		return warp, nil
	}
}

// WARPConnectorReconciler owns the distinct WARP Connector lifecycle, HA
// configuration, connector token, client observations, and declarative failover.
// It has no Gateway, Envoy, cloudflared ingress, or DNS responsibilities.
type WARPConnectorReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewWARPConnectorCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=warpconnectors;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=networkroutes;hostnameroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=warpconnectors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=warpconnectors/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch;create;update;patch;delete

// Reconcile converges one WARPConnector with Cloudflare's WARP Connector APIs.
func (r *WARPConnectorReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(flarewayv1alpha1.WARPConnector)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, flarewayv1alpha1.WARPConnectorFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, flarewayv1alpha1.WARPConnectorFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add WARPConnector finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if staleWARPConnectorCreateAttempt(object) {
		if err := r.clearWARPConnectorCreateAttempt(ctx, object); err != nil {
			return ctrl.Result{}, fmt.Errorf("clear stale WARP Connector create attempt: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	api, account, err := r.clientForObject(ctx, object)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	prepared, err := r.prepareCreate(ctx, api, object)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if prepared {
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	remote, owned, err := r.ensureRemote(ctx, api, account, object)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if object.Status.TunnelID == "" && owned {
		if err := r.checkpointIdentity(ctx, object, remote); err != nil {
			return ctrl.Result{}, err
		}
		object.Status.TunnelID = remote.ID
		object.Status.OwnershipVerified = true
	}

	conflicts := make([]string, 0, 2)
	desiredName := normalizedWARPConnectorName(object.Spec.Name)
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyObserveOnly {
		if remote.Name != desiredName {
			conflicts = append(conflicts, fmt.Sprintf("remote name %q differs from normalized spec.name %q", remote.Name, desiredName))
		}
		if err := r.removeTokenSecret(ctx, object); err != nil {
			return r.finishError(ctx, object, err)
		}
	} else {
		if remote.Name != desiredName {
			remote, err = api.UpdateWARPConnector(ctx, remote.ID, flarecloudflare.WARPConnectorUpdateInput{Name: new(desiredName)})
			if err != nil {
				return r.finishError(ctx, object, err)
			}
		}
		if err := r.ensureTokenSecret(ctx, api, object, remote.ID); err != nil {
			return r.finishError(ctx, object, err)
		}
	}

	configuration, configurationDrift, err := r.ensureConfiguration(ctx, api, object, remote.ID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if configurationDrift != "" {
		conflicts = append(conflicts, configurationDrift)
	}
	clients, err := api.ListWARPConnectorClients(ctx, remote.ID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	failover, err := r.ensureFailover(ctx, api, object, remote.ID, clients)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	clients = boundedWARPConnectorClients(clients)
	return ctrl.Result{RequeueAfter: warpConnectorRequeue}, r.patchReadyStatus(ctx, object, remote, configuration, clients, failover, owned, conflicts, configurationDrift != "")
}

func (r *WARPConnectorReconciler) clientForObject(ctx context.Context, object *flarewayv1alpha1.WARPConnector) (flarecloudflare.WARPConnectorAPI, *flarewayv1alpha1.CloudflareAccount, error) {
	account, err := loadPrivateAccount(ctx, r.Client, object.Spec.AccountRef.Name)
	if err != nil {
		return nil, nil, err
	}
	if _, err = authorizePrivateNamespace(ctx, r.Client, account, object.Namespace, authz.Request{PlatformObject: true}); err != nil {
		return nil, nil, err
	}
	if r.NewCloudflareClient == nil {
		return nil, nil, errors.New("cloudflare WARP Connector client factory is required")
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, nil, fmt.Errorf("get Cloudflare API token Secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	token := secret.Data[key]
	if len(token) == 0 {
		return nil, nil, fmt.Errorf("cloudflare API token Secret %s/%s has no non-empty %q key", ref.Namespace, ref.Name, key)
	}
	api, err := r.NewCloudflareClient(string(token), account.Spec.AccountID)
	if err != nil {
		return nil, nil, err
	}
	return api, account, nil
}

func (r *WARPConnectorReconciler) prepareCreate(ctx context.Context, api flarecloudflare.WARPConnectorAPI, object *flarewayv1alpha1.WARPConnector) (bool, error) {
	attemptName := normalizedWARPConnectorName(object.Spec.Name)
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyObserveOnly ||
		object.Status.TunnelID != "" || object.Spec.ExternalRef != nil ||
		object.Spec.Adoption.Mode == flarewayv1alpha1.AdoptionModeAdoptByID ||
		hasWARPConnectorCreateAttempt(object) {
		return false, nil
	}
	if attemptName == "" {
		return false, privateInvalid("Invalid", "spec.name must contain a non-whitespace WARP Connector name")
	}
	existing, err := api.ListWARPConnectors(ctx, flarecloudflare.WARPConnectorListFilter{Name: new(attemptName), IsDeleted: new(false)})
	if err != nil {
		return false, err
	}
	for index := range existing {
		if !validWARPConnectorListCandidate(existing[index]) {
			continue
		}
		if existing[index].Deleted() {
			continue
		}
		if existing[index].Name != attemptName {
			return false, privateInvalid("Conflict", "preexisting WARP Connector name %q does not exactly match normalized spec.name %q; use adoption.mode AdoptById", existing[index].Name, attemptName)
		}
		return false, privateInvalid("Conflict", "the WARP Connector %q already exists; use adoption.mode AdoptById", attemptName)
	}
	base := client.MergeFrom(object.DeepCopy())
	object.Status.CreateAttemptName = attemptName
	object.Status.CreateAttemptGeneration = object.Generation
	if err := r.Status().Patch(ctx, object, base); err != nil {
		return false, fmt.Errorf("checkpoint WARP Connector create attempt: %w", err)
	}
	return true, nil
}

func hasWARPConnectorCreateAttempt(object *flarewayv1alpha1.WARPConnector) bool {
	return object.Status.CreateAttemptName != "" ||
		object.Status.CreateAttemptGeneration != 0
}

func staleWARPConnectorCreateAttempt(object *flarewayv1alpha1.WARPConnector) bool {
	name := normalizedWARPConnectorName(object.Spec.Name)
	return hasWARPConnectorCreateAttempt(object) &&
		(name == "" ||
			object.Status.CreateAttemptGeneration != object.Generation ||
			object.Status.CreateAttemptName != name)
}

func currentWARPConnectorCreateAttempt(object *flarewayv1alpha1.WARPConnector) (string, bool) {
	name := normalizedWARPConnectorName(object.Spec.Name)
	return name, name != "" &&
		hasWARPConnectorCreateAttempt(object) &&
		object.Status.CreateAttemptGeneration == object.Generation &&
		object.Status.CreateAttemptName == name
}

func normalizedWARPConnectorName(value string) string {
	return strings.TrimSpace(value)
}

func validWARPConnectorListCandidate(connector flarecloudflare.WARPConnector) bool {
	return connector.ID != "" && connector.Name != ""
}

func (r *WARPConnectorReconciler) clearWARPConnectorCreateAttempt(ctx context.Context, object *flarewayv1alpha1.WARPConnector) error {
	if !hasWARPConnectorCreateAttempt(object) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	object.Status.CreateAttemptName = ""
	object.Status.CreateAttemptGeneration = 0
	return r.Status().Patch(ctx, object, base)
}

func (r *WARPConnectorReconciler) ensureRemote(ctx context.Context, api flarecloudflare.WARPConnectorAPI, account *flarewayv1alpha1.CloudflareAccount, object *flarewayv1alpha1.WARPConnector) (flarecloudflare.WARPConnector, bool, error) {
	policy := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy)
	var remote flarecloudflare.WARPConnector
	var owned bool
	var err error

	switch {
	case policy == flarewayv1alpha1.ManagementPolicyObserveOnly:
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.TunnelID == "" {
			return remote, false, privateInvalid("Invalid", "management policy ObserveOnly requires externalRef.tunnelId")
		}
		remote, err = api.GetWARPConnector(ctx, object.Spec.ExternalRef.TunnelID)
		owned = false
	case object.Status.TunnelID != "":
		if !object.Status.OwnershipVerified {
			return remote, false, privateInvalid("Conflict", "remote WARP Connector ID is not verified as owned or adopted")
		}
		remote, err = api.GetWARPConnector(ctx, object.Status.TunnelID)
		owned = true
	case object.Spec.Adoption.Mode == flarewayv1alpha1.AdoptionModeAdoptByID:
		if object.Spec.ExternalRef == nil || object.Spec.ExternalRef.TunnelID == "" {
			return remote, false, privateInvalid("Invalid", "adoption mode AdoptById requires externalRef.tunnelId")
		}
		expected := object.Spec.Adoption.Expect.Name
		if strings.TrimSpace(expected) == "" {
			return remote, false, privateInvalid("Invalid", "adoption mode AdoptById requires adoption.expect.name")
		}
		remote, err = api.GetWARPConnector(ctx, object.Spec.ExternalRef.TunnelID)
		if err == nil && remote.Name != expected {
			return remote, false, privateInvalid("Conflict", "remote WARP Connector name %q does not match adoption expectation %q", remote.Name, expected)
		}
		owned = true
	case object.Spec.ExternalRef != nil:
		return remote, false, privateInvalid("Conflict", "managed externalRef requires adoption.mode AdoptById")
	default:
		attemptName, currentAttempt := currentWARPConnectorCreateAttempt(object)
		if !currentAttempt {
			return remote, false, privateInvalid("Pending", "WARP Connector creation requires a controller-owned status checkpoint")
		}
		candidates, listErr := api.ListWARPConnectors(ctx, flarecloudflare.WARPConnectorListFilter{Name: new(attemptName), IsDeleted: new(false)})
		if listErr != nil {
			return remote, false, listErr
		}
		for index := range candidates {
			if !validWARPConnectorListCandidate(candidates[index]) {
				continue
			}
			if candidates[index].Deleted() {
				continue
			}
			if candidates[index].Name != attemptName {
				return remote, false, privateInvalid("Conflict", "preexisting WARP Connector name %q does not exactly match the checkpointed name %q; use adoption.mode AdoptById", candidates[index].Name, attemptName)
			}
			if remote.ID != "" {
				return remote, false, privateInvalid("Conflict", "multiple WARP Connectors named %q exist after a create attempt; use adoption.mode AdoptById", attemptName)
			}
			remote = candidates[index]
		}
		if remote.ID == "" {
			remote, err = api.CreateWARPConnector(ctx, warpConnectorCreateInput(object, attemptName))
		} else if recoveryErr := r.validateWARPConnectorCreateRecovery(ctx, api, account, object, remote); recoveryErr != nil {
			return remote, false, recoveryErr
		}
		owned = true
	}
	if err != nil {
		return remote, owned, err
	}
	if remote.ID == "" {
		return remote, owned, privateInvalid("InvalidRemote", "the Cloudflare service returned a WARP Connector without an ID")
	}
	if remote.Deleted() {
		return remote, owned, privateInvalid("Conflict", "remote WARP Connector %q is deleted", remote.ID)
	}
	if remote.TunnelType != flarecloudflare.TunnelTypeWARPConnector {
		return remote, owned, privateInvalid("TunnelTypeMismatch", "remote tunnel %q has type %q, not WARPConnector", remote.ID, remote.TunnelType)
	}
	if remote.AccountTag != account.Spec.AccountID {
		return remote, owned, privateInvalid("Conflict", "remote WARP Connector belongs to account %q, not %q", remote.AccountTag, account.Spec.AccountID)
	}
	return remote, owned, nil
}

func warpConnectorCreateInput(object *flarewayv1alpha1.WARPConnector, name string) flarecloudflare.WARPConnectorCreateInput {
	var highlyAvailable *bool
	if object.Spec.HighAvailability.Enabled != nil {
		highlyAvailable = new(*object.Spec.HighAvailability.Enabled)
	}
	return flarecloudflare.WARPConnectorCreateInput{Name: name, HighlyAvailable: highlyAvailable}
}

func (r *WARPConnectorReconciler) validateWARPConnectorCreateRecovery(ctx context.Context, api flarecloudflare.WARPConnectorAPI, account *flarewayv1alpha1.CloudflareAccount, object *flarewayv1alpha1.WARPConnector, remote flarecloudflare.WARPConnector) error {
	attemptName, currentAttempt := currentWARPConnectorCreateAttempt(object)
	if !currentAttempt ||
		remote.ID == "" ||
		remote.Deleted() ||
		remote.AccountTag != account.Spec.AccountID ||
		remote.TunnelType != flarecloudflare.TunnelTypeWARPConnector ||
		remote.Name != attemptName {
		return privateInvalid("Conflict", "preexisting WARP Connector %q does not match the controller create checkpoint; use adoption.mode AdoptById", remote.Name)
	}
	configuration, err := api.GetWARPConnectorConfiguration(ctx, remote.ID)
	if err != nil {
		return err
	}
	expectedHA := object.Spec.HighAvailability.Enabled != nil && *object.Spec.HighAvailability.Enabled
	observedHA, knownHA := warpConnectorConfigurationHAEnabled(configuration.Mode)
	if configuration.TunnelID != remote.ID || !knownHA || observedHA != expectedHA {
		return privateInvalid("Conflict", "preexisting WARP Connector %q does not match the checkpointed HA create contract; use adoption.mode AdoptById", remote.Name)
	}
	return nil
}

func warpConnectorConfigurationHAEnabled(mode flarecloudflare.WARPConnectorHAMode) (bool, bool) {
	switch mode {
	case flarecloudflare.WARPConnectorHAModeDisabled:
		return false, true
	case flarecloudflare.WARPConnectorHAModeNone, flarecloudflare.WARPConnectorHAModeAWS, flarecloudflare.WARPConnectorHAModeLocal:
		return true, true
	default:
		return false, false
	}
}

func (r *WARPConnectorReconciler) checkpointIdentity(ctx context.Context, object *flarewayv1alpha1.WARPConnector, remote flarecloudflare.WARPConnector) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.TunnelID = remote.ID
	object.Status.OwnershipVerified = true
	object.Status.CreateAttemptName = ""
	object.Status.CreateAttemptGeneration = 0
	return r.Status().Patch(ctx, object, base)
}

func (r *WARPConnectorReconciler) ensureTokenSecret(ctx context.Context, api flarecloudflare.WARPConnectorAPI, object *flarewayv1alpha1.WARPConnector, tunnelID string) error {
	name := warpConnectorSecretPrefix + object.Name
	key := types.NamespacedName{Namespace: object.Namespace, Name: name}
	secret := new(corev1.Secret)
	err := r.Get(ctx, key, secret)
	creating := apierrors.IsNotFound(err)
	switch {
	case err == nil:
		if !metav1.IsControlledBy(secret, object) {
			return privateInvalid("Conflict", "the WARP Connector token Secret %s is not owned by this WARPConnector", key)
		}
		if secret.Annotations[warpConnectorTunnelIDAnnotation] == tunnelID && len(secret.Data[flarewayv1alpha1.WARPConnectorTokenSecretKey]) > 0 {
			return nil
		}
	case creating:
		secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: object.Namespace}}
	default:
		return err
	}

	token, err := api.GetWARPConnectorToken(ctx, tunnelID)
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("the Cloudflare service returned an empty WARP Connector token")
	}
	var base client.Patch
	if !creating {
		base = client.MergeFrom(secret.DeepCopy())
	}
	if err := controllerutil.SetControllerReference(object, secret, r.Scheme); err != nil {
		return err
	}
	secret.Type = corev1.SecretTypeOpaque
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[warpConnectorTunnelIDAnnotation] = tunnelID
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[flarewayv1alpha1.WARPConnectorTokenSecretKey] = []byte(token)
	if creating {
		if err := r.Create(ctx, secret); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return privateInvalid("Conflict", "the WARP Connector token Secret %s appeared before it could be created", key)
			}
			return fmt.Errorf("create WARP Connector token Secret %s: %w", key, err)
		}
		return nil
	}
	if err := r.Patch(ctx, secret, base); err != nil {
		return fmt.Errorf("update WARP Connector token Secret %s: %w", key, err)
	}
	return nil
}

func (r *WARPConnectorReconciler) removeTokenSecret(ctx context.Context, object *flarewayv1alpha1.WARPConnector) error {
	name := warpConnectorSecretPrefix + object.Name
	secret := new(corev1.Secret)
	if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: name}, secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(secret, object) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, secret))
}

func (r *WARPConnectorReconciler) ensureConfiguration(ctx context.Context, api flarecloudflare.WARPConnectorAPI, object *flarewayv1alpha1.WARPConnector, tunnelID string) (flarecloudflare.WARPConnectorConfiguration, string, error) {
	desired, err := desiredWARPConnectorConfiguration(object.Spec.HighAvailability)
	if err != nil {
		return flarecloudflare.WARPConnectorConfiguration{}, "", err
	}
	observed, err := api.GetWARPConnectorConfiguration(ctx, tunnelID)
	if err != nil {
		return observed, "", err
	}
	drift := warpConnectorConfigurationDrift(desired, observed)
	if drift == "" || effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyObserveOnly {
		return observed, drift, nil
	}
	updated, err := api.UpdateWARPConnectorConfiguration(ctx, tunnelID, desired)
	return updated, "", err
}

func desiredWARPConnectorConfiguration(input flarewayv1alpha1.WARPConnectorHighAvailability) (flarecloudflare.WARPConnectorConfigurationInput, error) {
	result := flarecloudflare.WARPConnectorConfigurationInput{}
	switch input.Mode {
	case "", flarewayv1alpha1.WARPConnectorHAModeDisabled:
		result.Mode = flarecloudflare.WARPConnectorHAModeDisabled
	case flarewayv1alpha1.WARPConnectorHAModeNone:
		result.Mode = flarecloudflare.WARPConnectorHAModeNone
	case flarewayv1alpha1.WARPConnectorHAModeAWS:
		if input.AWS == nil {
			return result, privateInvalid("Invalid", "high availability mode AWS requires highAvailability.aws")
		}
		result.Mode = flarecloudflare.WARPConnectorHAModeAWS
		result.AWS = &flarecloudflare.WARPConnectorAWSConfiguration{FloatingNetworkResourceID: input.AWS.FNRID}
	case flarewayv1alpha1.WARPConnectorHAModeLocal:
		if input.Local == nil {
			return result, privateInvalid("Invalid", "high availability mode Local requires highAvailability.local")
		}
		result.Mode = flarecloudflare.WARPConnectorHAModeLocal
		result.Local = &flarecloudflare.WARPConnectorLocalConfiguration{VIPs: warpVirtualIPAddresses(input.Local.VIPs), VIPsPrevious: warpVirtualIPAddresses(input.Local.VIPsPrevious)}
	default:
		return result, privateInvalid("Invalid", "unsupported WARP Connector HA mode %q", input.Mode)
	}
	return result, nil
}

func warpConnectorConfigurationDrift(desired flarecloudflare.WARPConnectorConfigurationInput, observed flarecloudflare.WARPConnectorConfiguration) string {
	fields := make([]string, 0, 3)
	if desired.Mode != observed.Mode {
		fields = append(fields, "mode")
	}
	switch desired.Mode {
	case flarecloudflare.WARPConnectorHAModeAWS:
		if desired.AWS == nil || observed.AWS == nil || desired.AWS.FloatingNetworkResourceID != observed.AWS.FloatingNetworkResourceID {
			fields = append(fields, "aws.fnrId")
		}
	case flarecloudflare.WARPConnectorHAModeLocal:
		if desired.Local == nil || observed.Local == nil || !equalStringSets(desired.Local.VIPs, observed.Local.VIPs) {
			fields = append(fields, "local.vips")
		}
		if desired.Local == nil || observed.Local == nil || !equalStringSets(desired.Local.VIPsPrevious, observed.Local.VIPsPrevious) {
			fields = append(fields, "local.vipsPrevious")
		}
	case flarecloudflare.WARPConnectorHAModeNone, flarecloudflare.WARPConnectorHAModeDisabled:
		if observed.AWS != nil || observed.Local != nil {
			fields = append(fields, "provider configuration")
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return "remote HA configuration differs in " + strings.Join(fields, ", ")
}

func equalStringSets(left, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func warpVirtualIPAddresses(values []flarewayv1alpha1.WARPConnectorVirtualIP) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].Address
	}
	return result
}

func (r *WARPConnectorReconciler) ensureFailover(ctx context.Context, api flarecloudflare.WARPConnectorAPI, object *flarewayv1alpha1.WARPConnector, tunnelID string, clients []flarecloudflare.WARPConnectorClient) (*flarewayv1alpha1.WARPConnectorFailoverStatus, error) {
	if object.Spec.Failover == nil {
		return nil, nil
	}
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyObserveOnly {
		return object.Status.Failover, privateInvalid("Invalid", "management policy ObserveOnly cannot request WARP Connector failover")
	}
	targetFound := false
	for index := range clients {
		if clients[index].ID == object.Spec.Failover.ClientID {
			targetFound = true
			break
		}
	}
	if !targetFound {
		return object.Status.Failover, privateInvalid("Pending", "failover client %q is not linked to WARP Connector %q", object.Spec.Failover.ClientID, tunnelID)
	}
	if object.Status.Failover != nil && object.Status.Failover.RequestID == object.Spec.Failover.RequestID && object.Status.Failover.ClientID == object.Spec.Failover.ClientID {
		failoverCopy := new(*object.Status.Failover)
		if object.Status.Failover.AppliedAt != nil {
			failoverCopy.AppliedAt = object.Status.Failover.AppliedAt.DeepCopy()
		}
		return failoverCopy, nil
	}
	if err := api.FailoverWARPConnector(ctx, tunnelID, object.Spec.Failover.ClientID); err != nil {
		return object.Status.Failover, err
	}
	return &flarewayv1alpha1.WARPConnectorFailoverStatus{
		ClientID: object.Spec.Failover.ClientID, RequestID: object.Spec.Failover.RequestID,
		AppliedAt: new(metav1.NewTime(r.now())),
	}, nil
}

func boundedWARPConnectorClients(values []flarecloudflare.WARPConnectorClient) []flarecloudflare.WARPConnectorClient {
	values = append([]flarecloudflare.WARPConnectorClient(nil), values...)
	slices.SortFunc(values, func(left, right flarecloudflare.WARPConnectorClient) int { return strings.Compare(left.ID, right.ID) })
	if len(values) > 25 {
		values = values[:25]
	}
	for index := range values {
		values[index].Features = append([]string(nil), values[index].Features...)
		slices.Sort(values[index].Features)
		values[index].Features = slices.Compact(values[index].Features)
		if len(values[index].Features) > 64 {
			values[index].Features = values[index].Features[:64]
		}
		slices.SortFunc(values[index].Connections, func(left, right flarecloudflare.WARPConnectorConnection) int {
			return strings.Compare(left.ID, right.ID)
		})
		if len(values[index].Connections) > 16 {
			values[index].Connections = values[index].Connections[:16]
		}
	}
	return values
}

func (r *WARPConnectorReconciler) reconcileDelete(ctx context.Context, object *flarewayv1alpha1.WARPConnector) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(object, flarewayv1alpha1.WARPConnectorFinalizer) {
		return ctrl.Result{}, nil
	}
	if hasWARPConnectorCreateAttempt(object) {
		if err := r.clearWARPConnectorCreateAttempt(ctx, object); err != nil {
			return ctrl.Result{}, fmt.Errorf("clear WARP Connector create attempt during deletion: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	references, err := r.routeReferences(ctx, object)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(references) > 0 {
		message := "WARP Connector is still referenced by " + strings.Join(references, ", ")
		if err := r.patchCleanupBlocked(ctx, object, message); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: warpConnectorRequeue}, nil
	}
	needsRemoteDelete := effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) != flarewayv1alpha1.ManagementPolicyObserveOnly &&
		effectivePrivateDeletionPolicy(object.Spec.DeletionPolicy) == flarewayv1alpha1.DeletionPolicyDelete &&
		object.Status.TunnelID != "" && object.Status.OwnershipVerified
	if !needsRemoteDelete && object.Status.TunnelID != "" && object.Status.OrphanedTunnelID != object.Status.TunnelID {
		if err := r.patchOrphaned(ctx, object); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	if needsRemoteDelete {
		api, _, err := r.clientForObject(ctx, object)
		if err != nil {
			return ctrl.Result{}, err
		}
		if _, err := api.DeleteWARPConnector(ctx, object.Status.TunnelID); err != nil && !flarecloudflare.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, flarewayv1alpha1.WARPConnectorFinalizer)
	if err := r.Patch(ctx, object, base); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
func (r *WARPConnectorReconciler) routeReferences(ctx context.Context, object *flarewayv1alpha1.WARPConnector) ([]string, error) {
	references := make([]string, 0)
	var networkRoutes flarewayv1alpha1.NetworkRouteList
	if err := r.List(ctx, &networkRoutes); err != nil {
		return nil, fmt.Errorf("list NetworkRoutes referencing WARPConnector: %w", err)
	}
	for index := range networkRoutes.Items {
		route := &networkRoutes.Items[index]
		if route.DeletionTimestamp.IsZero() && warpTunnelReferenceMatches(route.Namespace, route.Spec.TunnelRef, object.Namespace, object.Name) {
			references = append(references, "NetworkRoute "+client.ObjectKeyFromObject(route).String())
		}
	}
	var hostnameRoutes flarewayv1alpha1.HostnameRouteList
	if err := r.List(ctx, &hostnameRoutes); err != nil {
		return nil, fmt.Errorf("list HostnameRoutes referencing WARPConnector: %w", err)
	}
	for index := range hostnameRoutes.Items {
		route := &hostnameRoutes.Items[index]
		if route.DeletionTimestamp.IsZero() && warpTunnelReferenceMatches(route.Namespace, route.Spec.TunnelRef, object.Namespace, object.Name) {
			references = append(references, "HostnameRoute "+client.ObjectKeyFromObject(route).String())
		}
	}
	slices.Sort(references)
	return references, nil
}

func (r *WARPConnectorReconciler) patchCleanupBlocked(ctx context.Context, object *flarewayv1alpha1.WARPConnector, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionCleanupBlocked, metav1.ConditionTrue, "Referenced", message),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionReady, metav1.ConditionFalse, "CleanupBlocked", message),
	)
	return r.Status().Patch(ctx, object, base)
}

func warpTunnelReferenceMatches(sourceNamespace string, reference flarewayv1alpha1.TunnelReference, targetNamespace, targetName string) bool {
	if reference.Kind != flarewayv1alpha1.TunnelReferenceKindWARPConnector {
		return false
	}
	namespace := reference.Namespace
	if namespace == "" {
		namespace = sourceNamespace
	}
	return namespace == targetNamespace && reference.Name == targetName
}

func (r *WARPConnectorReconciler) patchOrphaned(ctx context.Context, object *flarewayv1alpha1.WARPConnector) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.OrphanedTunnelID = object.Status.TunnelID
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionCleanupBlocked, metav1.ConditionFalse, "Orphaned", "Remote WARP Connector is intentionally retained"),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionReady, metav1.ConditionFalse, "Deleting", "WARPConnector deletion is finalizing"),
	)
	return r.Status().Patch(ctx, object, base)
}

func (r *WARPConnectorReconciler) patchReadyStatus(ctx context.Context, object *flarewayv1alpha1.WARPConnector, remote flarecloudflare.WARPConnector, configuration flarecloudflare.WARPConnectorConfiguration, clients []flarecloudflare.WARPConnectorClient, failover *flarewayv1alpha1.WARPConnectorFailoverStatus, owned bool, conflicts []string, configurationDrift bool) error {
	base := client.MergeFrom(object.DeepCopy())
	object.Status.TunnelID = remote.ID
	object.Status.AccountID = remote.AccountTag
	object.Status.Name = remote.Name
	object.Status.TunnelType = warpConnectorTunnelType(remote.TunnelType)
	object.Status.ConnectorState = warpConnectorState(remote.Status)
	object.Status.CreatedAt = warpMetaTime(remote.CreatedAt)
	object.Status.DeletedAt = warpMetaTime(remote.DeletedAt)
	object.Status.ConnectionsActiveAt = warpMetaTime(remote.ConnsActiveAt)
	object.Status.ConnectionsInactiveAt = warpMetaTime(remote.ConnsInactiveAt)
	object.Status.OwnershipVerified = owned
	object.Status.CreateAttemptName = ""
	object.Status.CreateAttemptGeneration = 0
	object.Status.ObservedGeneration = object.Generation
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyManaged {
		object.Status.TokenSecretRef = &corev1.LocalObjectReference{Name: warpConnectorSecretPrefix + object.Name}
	} else {
		object.Status.TokenSecretRef = nil
	}
	object.Status.Configuration = warpConfigurationStatus(configuration)
	object.Status.Failover = failover
	object.Status.Clients = warpClientStatuses(clients)

	configurationStatus := metav1.ConditionTrue
	configurationReason := "Ready"
	configurationMessage := "WARP Connector HA configuration is synchronized"
	if effectivePrivateManagementPolicy(object.Spec.ManagementPolicy) == flarewayv1alpha1.ManagementPolicyObserveOnly {
		configurationReason = "Observed"
		configurationMessage = "WARP Connector HA configuration is observed without mutation"
		if configurationDrift {
			configurationStatus = metav1.ConditionFalse
			configurationReason = "DriftDetected"
			configurationMessage = "Observed WARP Connector HA configuration differs from the desired configuration"
		}
	}
	conditions := []metav1.Condition{
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionAccepted, metav1.ConditionTrue, "Accepted", "WARP Connector is valid and authorized"),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionTunnelReady, metav1.ConditionTrue, "Ready", fmt.Sprintf("WARP Connector %s exists", remote.ID)),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionConfigurationReady, configurationStatus, configurationReason, configurationMessage),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionClientsReady, metav1.ConditionTrue, "Observed", fmt.Sprintf("Observed %d WARP Connector clients", len(clients))),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionCleanupBlocked, metav1.ConditionFalse, "NotBlocked", "No cleanup is pending"),
	}
	if len(conflicts) > 0 {
		message := strings.Join(conflicts, "; ")
		conditions = append(conditions,
			warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionConflict, metav1.ConditionTrue, "DriftDetected", message),
			warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionReady, metav1.ConditionFalse, "DriftDetected", message),
		)
	} else {
		conditions = append(conditions,
			warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionConflict, metav1.ConditionFalse, "NoConflict", "No ownership or configuration conflict was detected"),
			warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionReady, metav1.ConditionTrue, "Ready", "WARP Connector is synchronized"),
		)
	}
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), conditions...)
	return r.Status().Patch(ctx, object, base)
}

func (r *WARPConnectorReconciler) finishError(ctx context.Context, object *flarewayv1alpha1.WARPConnector, err error) (ctrl.Result, error) {
	reason := privateErrorReason(err)
	message := privateErrorMessage(err)
	base := client.MergeFrom(object.DeepCopy())
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionAccepted, metav1.ConditionFalse, reason, message),
		warpCondition(object.Generation, flarewayv1alpha1.WARPConnectorConditionReady, metav1.ConditionFalse, reason, message),
	)
	if patchErr := r.Status().Patch(ctx, object, base); patchErr != nil {
		return ctrl.Result{}, errors.Join(err, patchErr)
	}
	if privateIsValidationError(err) {
		if reason == "Pending" {
			return ctrl.Result{RequeueAfter: warpConnectorRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func warpConfigurationStatus(value flarecloudflare.WARPConnectorConfiguration) flarewayv1alpha1.WARPConnectorHAConfigurationStatus {
	result := flarewayv1alpha1.WARPConnectorHAConfigurationStatus{
		TunnelID:             value.TunnelID,
		ConfigurationVersion: value.Version,
		CreatedAt:            warpMetaTime(value.CreatedAt),
		UpdatedAt:            warpMetaTime(value.UpdatedAt),
		Mode:                 publicWARPConnectorHAMode(value.Mode),
	}
	if value.AWS != nil {
		result.AWS = &flarewayv1alpha1.WARPConnectorAWSHAConfig{FNRID: value.AWS.FloatingNetworkResourceID}
	}
	if value.Local != nil {
		result.Local = &flarewayv1alpha1.WARPConnectorLocalHAConfig{VIPs: publicVirtualIPs(value.Local.VIPs), VIPsPrevious: publicVirtualIPs(value.Local.VIPsPrevious)}
	}
	return result
}

func warpClientStatuses(values []flarecloudflare.WARPConnectorClient) []flarewayv1alpha1.WARPConnectorClientStatus {
	result := make([]flarewayv1alpha1.WARPConnectorClientStatus, len(values))
	for index := range values {
		connections := make([]flarewayv1alpha1.WARPConnectorConnectionStatus, len(values[index].Connections))
		for connectionIndex := range values[index].Connections {
			connection := values[index].Connections[connectionIndex]
			connections[connectionIndex] = flarewayv1alpha1.WARPConnectorConnectionStatus{ID: connection.ID, ClientID: connection.ClientID, ClientVersion: connection.ClientVersion, ColoName: connection.ColoName, OpenedAt: warpMetaTime(connection.OpenedAt), OriginIP: connection.OriginIP}
		}
		result[index] = flarewayv1alpha1.WARPConnectorClientStatus{ID: values[index].ID, Arch: values[index].Arch, HAStatus: publicWARPConnectorClientHAStatus(values[index].HAStatus), Features: values[index].Features, RunAt: warpMetaTime(values[index].RunAt), Version: values[index].Version, Connections: connections}
	}
	return result
}

func publicVirtualIPs(values []string) []flarewayv1alpha1.WARPConnectorVirtualIP {
	result := make([]flarewayv1alpha1.WARPConnectorVirtualIP, len(values))
	for index := range values {
		result[index].Address = values[index]
	}
	return result
}

func publicWARPConnectorHAMode(value flarecloudflare.WARPConnectorHAMode) flarewayv1alpha1.WARPConnectorHAMode {
	switch value {
	case flarecloudflare.WARPConnectorHAModeNone:
		return flarewayv1alpha1.WARPConnectorHAModeNone
	case flarecloudflare.WARPConnectorHAModeAWS:
		return flarewayv1alpha1.WARPConnectorHAModeAWS
	case flarecloudflare.WARPConnectorHAModeLocal:
		return flarewayv1alpha1.WARPConnectorHAModeLocal
	default:
		return flarewayv1alpha1.WARPConnectorHAModeDisabled
	}
}

func publicWARPConnectorClientHAStatus(value flarecloudflare.WARPConnectorClientHAStatus) flarewayv1alpha1.WARPConnectorClientHAStatus {
	switch value {
	case flarecloudflare.WARPConnectorClientHAStatusActive:
		return flarewayv1alpha1.WARPConnectorClientHAStatusActive
	case flarecloudflare.WARPConnectorClientHAStatusPassive:
		return flarewayv1alpha1.WARPConnectorClientHAStatusPassive
	default:
		return flarewayv1alpha1.WARPConnectorClientHAStatusOffline
	}
}

func warpConnectorTunnelType(value flarecloudflare.TunnelType) flarewayv1alpha1.TunnelRemoteType {
	if value == flarecloudflare.TunnelTypeWARPConnector {
		return flarewayv1alpha1.TunnelRemoteTypeWARPConnector
	}
	return ""
}

func warpConnectorState(value flarecloudflare.TunnelStatus) flarewayv1alpha1.ConnectorState {
	switch value {
	case flarecloudflare.TunnelStatusHealthy:
		return flarewayv1alpha1.ConnectorStateHealthy
	case flarecloudflare.TunnelStatusDegraded:
		return flarewayv1alpha1.ConnectorStateDegraded
	case flarecloudflare.TunnelStatusDown:
		return flarewayv1alpha1.ConnectorStateDown
	default:
		return flarewayv1alpha1.ConnectorStateInactive
	}
}

func warpMetaTime(value *time.Time) *metav1.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	return new(metav1.NewTime(*value))
}

func warpCondition(generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: generation}
}

func (r *WARPConnectorReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers WARPConnector and its account/token Secret watches.
func (r *WARPConnectorReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &flarewayv1alpha1.WARPConnector{}, warpConnectorAccountIndex, func(object client.Object) []string {
		return []string{object.(*flarewayv1alpha1.WARPConnector).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index WARPConnector accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&flarewayv1alpha1.WARPConnector{}).
		Owns(&corev1.Secret{}).
		Watches(&flarewayv1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.warpConnectorsForAccount)).
		Watches(&flarewayv1alpha1.NetworkRoute{}, handler.EnqueueRequestsFromMapFunc(r.warpConnectorForNetworkRoute)).
		Watches(&flarewayv1alpha1.HostnameRoute{}, handler.EnqueueRequestsFromMapFunc(r.warpConnectorForHostnameRoute)).
		Named("warpconnector").
		Complete(observedReconciler("warp-connector", r))
}

func warpConnectorForTunnelReference(sourceNamespace string, reference flarewayv1alpha1.TunnelReference) []reconcile.Request {
	if reference.Kind != flarewayv1alpha1.TunnelReferenceKindWARPConnector || reference.Name == "" {
		return nil
	}
	namespace := reference.Namespace
	if namespace == "" {
		namespace = sourceNamespace
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: namespace, Name: reference.Name}}}
}

func (r *WARPConnectorReconciler) warpConnectorForNetworkRoute(_ context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*flarewayv1alpha1.NetworkRoute)
	if !ok {
		return nil
	}
	return warpConnectorForTunnelReference(route.Namespace, route.Spec.TunnelRef)
}

func (r *WARPConnectorReconciler) warpConnectorForHostnameRoute(_ context.Context, object client.Object) []reconcile.Request {
	route, ok := object.(*flarewayv1alpha1.HostnameRoute)
	if !ok {
		return nil
	}
	return warpConnectorForTunnelReference(route.Namespace, route.Spec.TunnelRef)
}

func (r *WARPConnectorReconciler) warpConnectorsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	list := new(flarewayv1alpha1.WARPConnectorList)
	if err := r.List(ctx, list, client.MatchingFields{warpConnectorAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for index := range list.Items {
		requests[index] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[index])}
	}
	return requests
}
