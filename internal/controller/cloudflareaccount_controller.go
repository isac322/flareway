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
	"net/http"
	"slices"
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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

const (
	cloudflareAccountSecretIndex = ".spec.credentials.apiTokenSecretRef"
	cloudflareAccountRefresh     = 10 * time.Minute
)

// CloudflareAccountReconciler verifies account credentials and publishes safe metadata.
type CloudflareAccountReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Cloudflare flarecloudflare.AccountClientFactory
	Now        func() time.Time
}

// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflareaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=flareway.bhyoo.com,resources=cloudflareaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile verifies the token, lists account zones, and observes the Zero Trust organization.
// No desiredHash gate: token verification, zone discovery, and organization reads are the
// account's liveness/authorization evidence (T0 verification reads) and already run on the
// 10-minute cloudflareAccountRefresh cycle, so a freshness gate would add no savings.
func (r *CloudflareAccountReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	account := new(v1alpha1.CloudflareAccount)
	if err := r.Get(ctx, request.NamespacedName, account); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.NewTime(r.now())
	secretRef := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err := r.Get(ctx, types.NamespacedName{Namespace: secretRef.Namespace, Name: secretRef.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return r.fail(ctx, account, now, "SecretNotFound", fmt.Sprintf("API token Secret %s/%s was not found", secretRef.Namespace, secretRef.Name), false, nil)
		}
		return ctrl.Result{}, err
	}

	key := secretRef.Key
	if key == "" {
		key = "token"
	}
	token := secret.Data[key]
	if len(token) == 0 {
		return r.fail(ctx, account, now, "SecretKeyNotFound", fmt.Sprintf("API token Secret %s/%s has no non-empty %q key", secretRef.Namespace, secretRef.Name, key), false, nil)
	}
	if r.Cloudflare == nil {
		return ctrl.Result{}, fmt.Errorf("cloudflare client factory is required")
	}

	api := r.Cloudflare.AccountClient(string(token), account.Spec.AccountID)
	verification, err := api.VerifyToken(ctx)
	if err != nil {
		if permanentCredentialError(err) {
			return r.fail(ctx, account, now, "CredentialsInvalid", "Cloudflare API token verification failed", false, nil)
		}
		return ctrl.Result{}, err
	}
	if !verification.Active() {
		return r.fail(ctx, account, now, "CredentialsInvalid", fmt.Sprintf("Cloudflare API token status is %q", verification.Status), false, nil)
	}

	zones, err := api.ListZones(ctx)
	if err != nil {
		return r.fail(ctx, account, now, "CloudflareAPIError", "Cloudflare zones could not be listed", true, err)
	}
	organization, err := api.GetOrganization(ctx)
	if err != nil {
		return r.fail(ctx, account, now, "CloudflareAPIError", "Cloudflare Zero Trust organization could not be read", true, err)
	}

	authDomain := normalizeAuthDomain(organization.AuthDomain)
	teamName, ok := teamNameFromAuthDomain(authDomain)
	if !ok {
		return r.fail(ctx, account, now, "InvalidOrganization", "Cloudflare Zero Trust organization returned an invalid auth domain", true, nil)
	}

	verifiedZones := make([]v1alpha1.CloudflareVerifiedZone, 0, len(zones))
	accountName := ""
	for _, zone := range zones {
		if zone.AccountID != "" && zone.AccountID != account.Spec.AccountID {
			continue
		}
		if accountName == "" && zone.AccountName != "" {
			accountName = zone.AccountName
		}
		verifiedZones = append(verifiedZones, v1alpha1.CloudflareVerifiedZone{ID: zone.ID, Name: zone.Name})
	}
	if accountName == "" {
		accountName = organization.Name
	}
	slices.SortFunc(verifiedZones, func(left, right v1alpha1.CloudflareVerifiedZone) int {
		if compared := strings.Compare(left.Name, right.Name); compared != 0 {
			return compared
		}
		return strings.Compare(left.ID, right.ID)
	})

	base := client.MergeFromWithOptions(account.DeepCopy(), client.MergeFromWithOptimisticLock{})
	account.Status.Verified = v1alpha1.CloudflareAccountVerifiedStatus{
		AccountName: accountName,
		AuthDomain:  authDomain,
		TeamName:    teamName,
		Zones:       verifiedZones,
		// user/tokens/verify intentionally does not expose assigned permissions.
		TokenPermissions: nil,
	}
	account.Status.Conditions = statusutil.MergeConditions(account.Status.Conditions, now,
		accountCondition(account, v1alpha1.CloudflareAccountConditionCredentialsValid, metav1.ConditionTrue, "Verified", "Cloudflare API token is active"),
		accountCondition(account, v1alpha1.CloudflareAccountConditionAccepted, metav1.ConditionTrue, "Accepted", "Cloudflare account is verified"),
	)
	if err := r.Status().Patch(ctx, account, base); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: cloudflareAccountRefresh}, nil
}

func (r *CloudflareAccountReconciler) fail(ctx context.Context, account *v1alpha1.CloudflareAccount, now metav1.Time, reason, message string, credentialsValid bool, retryErr error) (ctrl.Result, error) {
	if err := r.patchFailure(ctx, account, now, reason, message, credentialsValid); err != nil {
		return ctrl.Result{}, err
	}
	if retryErr != nil {
		return ctrl.Result{}, retryErr
	}
	return ctrl.Result{RequeueAfter: cloudflareAccountRefresh}, nil
}

func (r *CloudflareAccountReconciler) patchFailure(ctx context.Context, account *v1alpha1.CloudflareAccount, now metav1.Time, reason, message string, credentialsValid bool) error {
	base := client.MergeFromWithOptions(account.DeepCopy(), client.MergeFromWithOptimisticLock{})
	account.Status.Verified = v1alpha1.CloudflareAccountVerifiedStatus{}
	credentialsStatus := metav1.ConditionFalse
	credentialsReason := reason
	credentialsMessage := message
	if credentialsValid {
		credentialsStatus = metav1.ConditionTrue
		credentialsReason = "Verified"
		credentialsMessage = "Cloudflare API token is active"
	}
	account.Status.Conditions = statusutil.MergeConditions(account.Status.Conditions, now,
		accountCondition(account, v1alpha1.CloudflareAccountConditionCredentialsValid, credentialsStatus, credentialsReason, credentialsMessage),
		accountCondition(account, v1alpha1.CloudflareAccountConditionAccepted, metav1.ConditionFalse, reason, message),
	)
	return r.Status().Patch(ctx, account, base)
}

func accountCondition(account *v1alpha1.CloudflareAccount, conditionType string, conditionStatus metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: account.Generation,
	}
}

func (r *CloudflareAccountReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the account controller and its Secret watch.
func (r *CloudflareAccountReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.CloudflareAccount{}, cloudflareAccountSecretIndex, func(object client.Object) []string {
		account := object.(*v1alpha1.CloudflareAccount)
		ref := account.Spec.Credentials.APITokenSecretRef
		if ref.Namespace == "" || ref.Name == "" {
			return nil
		}
		return []string{ref.Namespace + "/" + ref.Name}
	}); err != nil {
		return fmt.Errorf("index CloudflareAccount API token Secrets: %w", err)
	}

	return ctrl.NewControllerManagedBy(manager).
		For(&v1alpha1.CloudflareAccount{}, builder.WithPredicates(desiredStateChangedPredicate)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.accountsForSecret)).
		Complete(observedReconciler("cloudflare-account", r))
}

func (r *CloudflareAccountReconciler) accountsForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}
	accounts := new(v1alpha1.CloudflareAccountList)
	if err := r.List(ctx, accounts, client.MatchingFields{cloudflareAccountSecretIndex: secret.Namespace + "/" + secret.Name}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(accounts.Items))
	for index := range accounts.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: accounts.Items[index].Name}})
	}
	return requests
}

func permanentCredentialError(err error) bool {
	statusCode, ok := flarecloudflare.StatusCode(err)
	if !ok {
		return false
	}
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func normalizeAuthDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func teamNameFromAuthDomain(authDomain string) (string, bool) {
	const suffix = ".cloudflareaccess.com"
	if !strings.HasSuffix(authDomain, suffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(authDomain, suffix)
	if prefix == "" || strings.Contains(prefix, ".") {
		return "", false
	}
	return prefix, true
}
