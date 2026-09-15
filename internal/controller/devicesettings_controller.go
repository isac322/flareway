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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// DeviceSettingsReconciler owns the account-wide device settings singleton.
type DeviceSettingsReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	APIReader           client.Reader
	NewCloudflareClient NewDeviceCloudflareClient
	Now                 func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicesettings;cloudflareaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicesettings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=devicesettings/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch

// Reconcile converges the DeviceSettings singleton with Cloudflare.
func (r *DeviceSettingsReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	object := new(v1alpha1.DeviceSettings)
	if err := r.Get(ctx, request.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.reconcileDelete(ctx, object)
	}
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DeviceSettingsFinalizer) {
		base := client.MergeFrom(object.DeepCopy())
		controllerutil.AddFinalizer(object, v1alpha1.DeviceSettingsFinalizer)
		if err := r.Patch(ctx, object, base); err != nil {
			return ctrl.Result{}, fmt.Errorf("add DeviceSettings finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}
	account, token, err := globalAccountToken(ctx, r.Client, object.Namespace, object.Spec.AccountRef.Name)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyManaged {
		if err := r.checkSingleWriter(ctx, object, account.Spec.AccountID); err != nil {
			return r.finishError(ctx, object, err)
		}
	}
	if r.NewCloudflareClient == nil {
		return r.finishError(ctx, object, fmt.Errorf("cloudflare device client factory is required"))
	}
	api, err := r.NewCloudflareClient(token, account.Spec.AccountID)
	if err != nil {
		return r.finishError(ctx, object, err)
	}
	observed, err := api.GetDeviceSettings(ctx)
	if err != nil {
		return r.finishRemoteError(ctx, object, err)
	}
	if effectiveGlobalManagementPolicy(object.Spec.ManagementPolicy) == v1alpha1.ManagementPolicyObserveOnly {
		return ctrl.Result{}, r.patchStatus(ctx, object, observed, deviceSettingsDiff(object.Spec, observed), metav1.ConditionTrue, "Observed", "Device settings are observed without mutation")
	}
	if deviceSettingsDiff(object.Spec, observed) != nil {
		if _, err = api.UpdateDeviceSettings(ctx, deviceSettingsInput(object.Spec)); err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
		observed, err = api.GetDeviceSettings(ctx)
		if err != nil {
			return r.finishRemoteError(ctx, object, err)
		}
	}
	if err := r.patchStatus(ctx, object, observed, nil, metav1.ConditionTrue, "Ready", "Device settings are synchronized"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: globalRequeue}, nil
}
func (r *DeviceSettingsReconciler) checkSingleWriter(ctx context.Context, object *v1alpha1.DeviceSettings, accountID string) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var list v1alpha1.DeviceSettingsList
	if err := reader.List(ctx, &list); err != nil {
		return err
	}
	key := client.ObjectKeyFromObject(object)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == object.UID || !other.DeletionTimestamp.IsZero() ||
			effectiveGlobalManagementPolicy(other.Spec.ManagementPolicy) != v1alpha1.ManagementPolicyManaged {
			continue
		}
		otherAccountID, eligible := globalContenderAccountID(ctx, reader, other.Namespace, other.Spec.AccountRef.Name, other.Status.Conditions, false)
		if !eligible || otherAccountID != accountID {
			continue
		}
		otherKey := client.ObjectKeyFromObject(other)
		if globalObjectPrecedes(other.CreationTimestamp, otherKey, object.CreationTimestamp, key) {
			return privateInvalid("Conflict", "the DeviceSettings %s is the earlier authorized writer for Cloudflare account ID %q", otherKey, accountID)
		}
	}
	return nil
}

func deviceSettingsInput(spec v1alpha1.DeviceSettingsSpec) flarecloudflare.DeviceSettingsInput {
	return flarecloudflare.DeviceSettingsInput{
		GatewayProxyEnabled:                spec.GatewayProxyEnabled,
		GatewayUDPProxyEnabled:             spec.GatewayUDPProxyEnabled,
		RootCertificateInstallationEnabled: spec.RootCertificateInstallationEnabled,
		UseZTVirtualIP:                     spec.UseZTVirtualIP,
		DisableForTime:                     spec.DisableForTime,
	}
}

func deviceSettingsObserved(remote flarecloudflare.DeviceSettings) v1alpha1.DeviceSettingsValues {
	return v1alpha1.DeviceSettingsValues{
		GatewayProxyEnabled:                boolPointerValue(remote.GatewayProxyEnabled),
		GatewayUDPProxyEnabled:             boolPointerValue(remote.GatewayUDPProxyEnabled),
		RootCertificateInstallationEnabled: boolPointerValue(remote.RootCertificateInstallationEnabled),
		UseZTVirtualIP:                     boolPointerValue(remote.UseZTVirtualIP),
		DisableForTime:                     int64PointerValue(remote.DisableForTime),
	}
}

func deviceSettingsDiff(spec v1alpha1.DeviceSettingsSpec, remote flarecloudflare.DeviceSettings) *v1alpha1.DeviceSettingsValues {
	diff := &v1alpha1.DeviceSettingsValues{}
	changed := false
	if spec.GatewayProxyEnabled != nil && *spec.GatewayProxyEnabled != remote.GatewayProxyEnabled {
		diff.GatewayProxyEnabled = spec.GatewayProxyEnabled
		changed = true
	}
	if spec.GatewayUDPProxyEnabled != nil && *spec.GatewayUDPProxyEnabled != remote.GatewayUDPProxyEnabled {
		diff.GatewayUDPProxyEnabled = spec.GatewayUDPProxyEnabled
		changed = true
	}
	if spec.RootCertificateInstallationEnabled != nil && *spec.RootCertificateInstallationEnabled != remote.RootCertificateInstallationEnabled {
		diff.RootCertificateInstallationEnabled = spec.RootCertificateInstallationEnabled
		changed = true
	}
	if spec.UseZTVirtualIP != nil && *spec.UseZTVirtualIP != remote.UseZTVirtualIP {
		diff.UseZTVirtualIP = spec.UseZTVirtualIP
		changed = true
	}
	if spec.DisableForTime != nil && *spec.DisableForTime != remote.DisableForTime {
		diff.DisableForTime = spec.DisableForTime
		changed = true
	}
	if !changed {
		return nil
	}
	return diff
}

func (r *DeviceSettingsReconciler) reconcileDelete(ctx context.Context, object *v1alpha1.DeviceSettings) error {
	if !controllerutil.ContainsFinalizer(object, v1alpha1.DeviceSettingsFinalizer) {
		return nil
	}
	base := client.MergeFrom(object.DeepCopy())
	controllerutil.RemoveFinalizer(object, v1alpha1.DeviceSettingsFinalizer)
	return r.Patch(ctx, object, base)
}

func (r *DeviceSettingsReconciler) finishError(ctx context.Context, object *v1alpha1.DeviceSettings, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.DeviceSettings{}, nil, metav1.ConditionFalse, privateErrorReason(err), privateErrorMessage(err)); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	if privateIsValidationError(err) {
		if privateErrorReason(err) == "Pending" {
			return ctrl.Result{RequeueAfter: globalRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func (r *DeviceSettingsReconciler) finishRemoteError(ctx context.Context, object *v1alpha1.DeviceSettings, err error) (ctrl.Result, error) {
	if patchErr := r.patchStatus(ctx, object, flarecloudflare.DeviceSettings{}, nil, metav1.ConditionFalse, "CloudflareError", err.Error()); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	return ctrl.Result{}, err
}

func (r *DeviceSettingsReconciler) patchStatus(ctx context.Context, object *v1alpha1.DeviceSettings, remote flarecloudflare.DeviceSettings, wouldApply *v1alpha1.DeviceSettingsValues, status metav1.ConditionStatus, reason, message string) error {
	base := client.MergeFrom(object.DeepCopy())
	if status == metav1.ConditionTrue {
		object.Status.Observed = deviceSettingsObserved(remote)
		object.Status.WouldApply = wouldApply
	}
	object.Status.ObservedGeneration = object.Generation
	object.Status.Conditions = globalConditions(object.Status.Conditions, object.Generation, status, reason, message, r.now())
	return r.Status().Patch(ctx, object, base)
}

func (r *DeviceSettingsReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the DeviceSettings controller and singleton watches.
func (r *DeviceSettingsReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.DeviceSettings{}, deviceSettingsAccountIndex, func(object client.Object) []string {
		return []string{object.(*v1alpha1.DeviceSettings).Spec.AccountRef.Name}
	}); err != nil {
		return fmt.Errorf("index DeviceSettings accountRef: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.DeviceSettings{}).
		Watches(&v1alpha1.DeviceSettings{}, handler.EnqueueRequestsFromMapFunc(r.forWriterChange)).
		Watches(&v1alpha1.CloudflareAccount{}, handler.EnqueueRequestsFromMapFunc(r.forAccount)).
		Complete(observedReconciler("device-settings", r))
}

func (r *DeviceSettingsReconciler) forWriterChange(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.DeviceSettingsList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func (r *DeviceSettingsReconciler) forAccount(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.DeviceSettingsList
	if err := r.List(ctx, &list, client.MatchingFields{deviceSettingsAccountIndex: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return requests
}

func boolPointerValue(value bool) *bool    { result := value; return &result }
func int64PointerValue(value int64) *int64 { result := value; return &result }
