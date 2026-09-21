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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	devicePostureIntegrationAccountIndex = accessAccountIndex + ".devicePostureIntegration"
	devicePostureIntegrationSecretIndex  = ".spec.config.devicePostureIntegrationSecrets"
)

var devicePostureIntegrationIntervalPattern = regexp.MustCompile(`^[1-9][0-9]*[mh]$`)

// DevicePostureIntegrationReconciler manages Cloudflare posture integrations.
type DevicePostureIntegrationReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	NewCloudflareClient NewAccessCloudflareClient
	Now                 func() time.Time
	credentialRevisions sync.Map
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicepostureintegrations;cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicepostureintegrations,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicepostureintegrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicepostureintegrations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges one DevicePostureIntegration with Cloudflare.
func (r *DevicePostureIntegrationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.DevicePostureIntegration)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureIntegrationFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.DevicePostureIntegrationFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	accessAPI, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
	if err != nil {
		_ = r.patchStatus(ctx, object, nil, object.Status.IntegrationID, metav1.ConditionFalse, privateErrorReason(err), err.Error())
		return ctrl.Result{}, err
	}
	api, ok := accessAPI.(flarecloudflare.DevicePostureIntegrationAPI)
	if !ok {
		err = errors.New("the Cloudflare client does not support device posture integrations")
		return ctrl.Result{}, r.patchStatus(ctx, object, nil, object.Status.IntegrationID, metav1.ConditionFalse, "Unsupported", err.Error())
	}

	if object.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly {
		id := object.Spec.ExternalRef.IntegrationID
		remote, getErr := api.GetDevicePostureIntegration(ctx, id)
		if getErr != nil {
			return ctrl.Result{}, getErr
		}
		if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
			return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionFalse, "Conflict", "remote device posture integration name does not match expectation")
		}
		return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionTrue, "Ready", "Device posture integration is observed")
	}
	if err = validateDevicePostureIntegrationSpec(&object.Spec); err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, nil, object.Status.IntegrationID, metav1.ConditionFalse, "Invalid", err.Error())
	}
	credentials, revision, err := r.integrationCredentials(ctx, object)
	if err != nil {
		return ctrl.Result{}, r.patchStatus(ctx, object, nil, object.Status.IntegrationID, metav1.ConditionFalse, "SecretNotFound", err.Error())
	}
	credentialsChanged := r.credentialsRevisionChanged(object, revision)
	name, err := accessRemoteName(ctx, r.Client, object.Namespace, object.Spec.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	input := flarecloudflare.DevicePostureIntegrationInput{Name: name, Type: object.Spec.Type, Interval: object.Spec.Interval, Config: object.Spec.Config, ClientSecret: credentials.clientSecret, ClientKey: credentials.clientKey, AccessClientID: credentials.accessClientID, AccessClientSecret: credentials.accessClientSecret}

	id := object.Status.IntegrationID
	var remote flarecloudflare.DevicePostureIntegration
	if id == "" {
		if object.Spec.Adoption.Mode == v1alpha1.AdoptionModeAdoptByID {
			id = object.Spec.ExternalRef.IntegrationID
			remote, err = api.GetDevicePostureIntegration(ctx, id)
			if err != nil {
				return ctrl.Result{}, err
			}
			if object.Spec.Adoption.Expect.Name != "" && remote.Name != object.Spec.Adoption.Expect.Name {
				return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionFalse, "Conflict", "remote device posture integration name does not match adoption expectation")
			}
			if !devicePostureIntegrationMatches(input, remote) || credentialsChanged {
				remote, err = api.UpdateDevicePostureIntegration(ctx, id, input)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
		} else {
			remote, err = api.CreateDevicePostureIntegration(ctx, input)
			if err != nil {
				return ctrl.Result{}, err
			}
			id = remote.ID
		}
	} else {
		if !object.Status.OwnershipVerified {
			return ctrl.Result{}, r.patchStatus(ctx, object, nil, id, metav1.ConditionFalse, "Conflict", "remote device posture integration ID is not verified as owned or adopted")
		}
		remote, err = api.GetDevicePostureIntegration(ctx, id)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !devicePostureIntegrationMatches(input, remote) || credentialsChanged {
			remote, err = api.UpdateDevicePostureIntegration(ctx, id, input)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	r.rememberCredentialsRevision(object, revision)
	return ctrl.Result{}, r.patchStatus(ctx, object, &remote, id, metav1.ConditionTrue, "Ready", "Device posture integration is synchronized")
}

type devicePostureIntegrationCredentials struct {
	clientSecret       string
	clientKey          string
	accessClientID     string
	accessClientSecret string
}

func (r *DevicePostureIntegrationReconciler) integrationCredentials(ctx context.Context, object *v1alpha1.DevicePostureIntegration) (devicePostureIntegrationCredentials, string, error) {
	cache := map[string]*corev1.Secret{}
	var revisions []string
	read := func(ref *v1alpha1.DevicePostureIntegrationSecretReference) (string, error) {
		if ref == nil {
			return "", nil
		}
		secret := cache[ref.Name]
		if secret == nil {
			secret = new(corev1.Secret)
			if err := r.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: ref.Name}, secret); err != nil {
				return "", err
			}
			cache[ref.Name] = secret
		}
		value := trimSecret(secret.Data[ref.Key])
		if value == "" {
			return "", fmt.Errorf("secret %s/%s has no non-empty %q key", object.Namespace, ref.Name, ref.Key)
		}
		revisions = append(revisions, ref.Name+":"+ref.Key+":"+string(secret.UID)+":"+secret.ResourceVersion)
		return value, nil
	}
	var result devicePostureIntegrationCredentials
	var err error
	if result.clientSecret, err = read(object.Spec.Config.ClientSecretRef); err != nil {
		return result, "", err
	}
	if result.clientKey, err = read(object.Spec.Config.ClientKeyRef); err != nil {
		return result, "", err
	}
	if result.accessClientID, err = read(object.Spec.Config.AccessClientIDRef); err != nil {
		return result, "", err
	}
	if result.accessClientSecret, err = read(object.Spec.Config.AccessClientSecretRef); err != nil {
		return result, "", err
	}
	slices.Sort(revisions)
	return result, strings.Join(revisions, ";"), nil
}

func validateDevicePostureIntegrationSpec(spec *v1alpha1.DevicePostureIntegrationSpec) error {
	if spec.Name == "" {
		return errors.New("name is required")
	}
	if !devicePostureIntegrationIntervalPattern.MatchString(spec.Interval) {
		return errors.New("interval must be a positive number followed by m or h")
	}
	fields := devicePostureIntegrationConfigFieldSet(spec.Config)
	var allowed, required []string
	switch spec.Type {
	case v1alpha1.DevicePostureIntegrationTypeWorkspaceOne:
		allowed, required = []string{"apiUrl", "authUrl", "clientId", "clientSecretRef"}, []string{"apiUrl", "authUrl", "clientId", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeCrowdstrikeS2S:
		allowed, required = []string{"apiUrl", "clientId", "customerId", "clientSecretRef"}, []string{"apiUrl", "clientId", "customerId", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeUptycs:
		allowed, required = []string{"apiUrl", "customerId", "clientKeyRef", "clientSecretRef"}, []string{"apiUrl", "customerId", "clientKeyRef", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeIntune:
		allowed, required = []string{"clientId", "customerId", "clientSecretRef"}, []string{"clientId", "customerId", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeKolide:
		allowed, required = []string{"clientId", "clientSecretRef"}, []string{"clientId", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeTaniumS2S:
		allowed, required = []string{"apiUrl", "clientSecretRef", "accessClientIdRef", "accessClientSecretRef"}, []string{"apiUrl", "clientSecretRef"}
		if fields["accessClientIdRef"] != fields["accessClientSecretRef"] {
			return errors.New("the TaniumS2S Access client credential references must be supplied together")
		}
	case v1alpha1.DevicePostureIntegrationTypeSentinelOneS2S:
		allowed, required = []string{"apiUrl", "clientSecretRef"}, []string{"apiUrl", "clientSecretRef"}
	case v1alpha1.DevicePostureIntegrationTypeCustomS2S:
		allowed, required = []string{"apiUrl", "accessClientIdRef", "accessClientSecretRef"}, []string{"apiUrl", "accessClientIdRef", "accessClientSecretRef"}
	default:
		return fmt.Errorf("unsupported device posture integration type %q", spec.Type)
	}
	for field := range fields {
		if !slices.Contains(allowed, field) {
			return fmt.Errorf("config.%s is not valid for %s", field, spec.Type)
		}
	}
	for _, field := range required {
		if !fields[field] {
			return fmt.Errorf("config.%s is required for %s", field, spec.Type)
		}
	}
	for name, ref := range map[string]*v1alpha1.DevicePostureIntegrationSecretReference{"clientSecretRef": spec.Config.ClientSecretRef, "clientKeyRef": spec.Config.ClientKeyRef, "accessClientIdRef": spec.Config.AccessClientIDRef, "accessClientSecretRef": spec.Config.AccessClientSecretRef} {
		if ref != nil && (ref.Name == "" || ref.Key == "") {
			return fmt.Errorf("config.%s requires non-empty name and key", name)
		}
	}
	return nil
}

func devicePostureIntegrationConfigFieldSet(config v1alpha1.DevicePostureIntegrationConfig) map[string]bool {
	fields := map[string]bool{}
	add := func(name string, present bool) {
		if present {
			fields[name] = true
		}
	}
	add("apiUrl", config.APIURL != "")
	add("authUrl", config.AuthURL != "")
	add("clientId", config.ClientID != "")
	add("customerId", config.CustomerID != "")
	add("clientSecretRef", config.ClientSecretRef != nil)
	add("clientKeyRef", config.ClientKeyRef != nil)
	add("accessClientIdRef", config.AccessClientIDRef != nil)
	add("accessClientSecretRef", config.AccessClientSecretRef != nil)
	return fields
}

func (r *DevicePostureIntegrationReconciler) credentialsRevisionChanged(object *v1alpha1.DevicePostureIntegration, revision string) bool {
	value, ok := r.credentialRevisions.Load(devicePostureIntegrationRevisionKey(object))
	return !ok || value != revision
}

func (r *DevicePostureIntegrationReconciler) rememberCredentialsRevision(object *v1alpha1.DevicePostureIntegration, revision string) {
	r.credentialRevisions.Store(devicePostureIntegrationRevisionKey(object), revision)
}

func devicePostureIntegrationRevisionKey(object *v1alpha1.DevicePostureIntegration) string {
	if object.UID != "" {
		return string(object.UID)
	}
	return object.Namespace + "/" + object.Name
}

func devicePostureIntegrationMatches(input flarecloudflare.DevicePostureIntegrationInput, remote flarecloudflare.DevicePostureIntegration) bool {
	desired := v1alpha1.DevicePostureIntegrationObservedConfig{APIURL: input.Config.APIURL, AuthURL: input.Config.AuthURL, ClientID: input.Config.ClientID, CustomerID: input.Config.CustomerID}
	return remote.Name == input.Name && remote.Type == input.Type && remote.Interval == input.Interval && reflect.DeepEqual(remote.Config, desired)
}

func (r *DevicePostureIntegrationReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.DevicePostureIntegration) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DevicePostureIntegrationFinalizer) {
		return nil
	}
	if object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly && object.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete && object.Status.IntegrationID != "" && object.Status.OwnershipVerified {
		accessAPI, _, err := accessClientForAccount(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name, authz.Request{PlatformObject: true}, r.NewCloudflareClient)
		if err != nil {
			return err
		}
		api, ok := accessAPI.(flarecloudflare.DevicePostureIntegrationAPI)
		if !ok {
			return errors.New("the Cloudflare client does not support device posture integrations")
		}
		if err = ignoreRemoteNotFound(api.DeleteDevicePostureIntegration(ctx, object.Status.IntegrationID)); err != nil {
			return err
		}
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.DevicePostureIntegrationFinalizer)
	r.credentialRevisions.Delete(devicePostureIntegrationRevisionKey(object))
	return r.Patch(ctx, object, base)
}

func (r *DevicePostureIntegrationReconciler) patchStatus(ctx context.Context, object *v1alpha1.DevicePostureIntegration, remote *flarecloudflare.DevicePostureIntegration, id string, status metav1.ConditionStatus, reason, message string) error {
	baseObject := object.DeepCopy()
	if remote != nil {
		object.Status.IntegrationID = id
		object.Status.OwnershipVerified = object.Spec.ManagementPolicy != v1alpha1.ManagementPolicyObserveOnly
		object.Status.Observed = &v1alpha1.DevicePostureIntegrationObservedState{Name: remote.Name, Type: remote.Type, Interval: remote.Interval, Config: remote.Config}
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = mergeAccessConditions(object.Status.Conditions, r.now(), accessCondition(object.Generation, "Accepted", status, reason, message), accessCondition(object.Generation, "Ready", status, reason, message))
	if reflect.DeepEqual(baseObject.Status, object.Status) {
		return nil
	}
	return r.Status().Patch(ctx, object, client.MergeFrom(baseObject))
}

func (r *DevicePostureIntegrationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the integration controller and dependency watches.
func (r *DevicePostureIntegrationReconciler) SetupWithManager(manager ctrl.Manager) error {
	indexer := manager.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &v1alpha1.DevicePostureIntegration{}, devicePostureIntegrationAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.DevicePostureIntegration).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index DevicePostureIntegration accounts: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &v1alpha1.DevicePostureIntegration{}, devicePostureIntegrationSecretIndex, func(object client.Object) []string {
		integration := object.(*v1alpha1.DevicePostureIntegration)
		refs := []*v1alpha1.DevicePostureIntegrationSecretReference{integration.Spec.Config.ClientSecretRef, integration.Spec.Config.ClientKeyRef, integration.Spec.Config.AccessClientIDRef, integration.Spec.Config.AccessClientSecretRef}
		seen := map[string]struct{}{}
		for _, ref := range refs {
			if ref != nil {
				seen[integration.Namespace+"/"+ref.Name] = struct{}{}
			}
		}
		keys := make([]string, 0, len(seen))
		for key := range seen {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		return keys
	}); err != nil {
		return fmt.Errorf("index DevicePostureIntegration Secrets: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).For(&v1alpha1.DevicePostureIntegration{}).Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.integrationsForAccount)).Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.integrationsForSecret)).Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.integrationsForNamespace)).Complete(observedReconciler("device-posture-integration", r))
}

func (r *DevicePostureIntegrationReconciler) integrationsForAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureIntegrationList
	if err := r.List(ctx, &list, client.MatchingFields{devicePostureIntegrationAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	return devicePostureIntegrationRequests(list.Items)
}

func (r *DevicePostureIntegrationReconciler) integrationsForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureIntegrationList
	key := object.GetNamespace() + "/" + object.GetName()
	if err := r.List(ctx, &list, client.MatchingFields{devicePostureIntegrationSecretIndex: key}); err != nil {
		return nil
	}
	return devicePostureIntegrationRequests(list.Items)
}

func (r *DevicePostureIntegrationReconciler) integrationsForNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DevicePostureIntegrationList
	if err := r.List(ctx, &list, client.InNamespace(object.GetName())); err != nil {
		return nil
	}
	return devicePostureIntegrationRequests(list.Items)
}

func devicePostureIntegrationRequests(items []v1alpha1.DevicePostureIntegration) []reconcile.Request {
	out := make([]reconcile.Request, len(items))
	for i := range items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: items[i].Namespace, Name: items[i].Name}}
	}
	return out
}
