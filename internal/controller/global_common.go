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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	globalRequeue              = 5 * time.Second
	deviceSettingsAccountIndex = "flareway.deviceSettings.account"
	organizationAccountIndex   = "flareway.zeroTrustOrganization.account"
	gatewayPolicyAccountIndex  = "flareway.zeroTrustGatewayPolicy.account"
	gatewayPolicyListIndex     = "flareway.zeroTrustGatewayPolicy.list"
	zeroTrustListAccountIndex  = "flareway.zeroTrustList.account"
)

// NewDeviceCloudflareClient constructs an account-scoped device-settings API.
type NewDeviceCloudflareClient func(token, accountID string) (flarecloudflare.DeviceSettingsAPI, error)

// NewOrganizationCloudflareClient constructs an account-scoped organization API.
type NewOrganizationCloudflareClient func(token, accountID string) (flarecloudflare.OrganizationAPI, error)

// NewGatewayCloudflareClient constructs an account-scoped Gateway API.
type NewGatewayCloudflareClient func(token, accountID string) (flarecloudflare.GatewayAPI, error)

// DeviceClientFromFactory adapts the shared production Cloudflare factory.
func DeviceClientFromFactory(factory flarecloudflare.ClientFactory) NewDeviceCloudflareClient {
	return func(token, accountID string) (flarecloudflare.DeviceSettingsAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

// OrganizationClientFromFactory adapts the shared production Cloudflare factory.
func OrganizationClientFromFactory(factory flarecloudflare.ClientFactory) NewOrganizationCloudflareClient {
	return func(token, accountID string) (flarecloudflare.OrganizationAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

// GatewayClientFromFactory adapts the shared production Cloudflare factory.
func GatewayClientFromFactory(factory flarecloudflare.ClientFactory) NewGatewayCloudflareClient {
	return func(token, accountID string) (flarecloudflare.GatewayAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

func globalAccountToken(ctx context.Context, kube client.Client, namespace, accountName string) (*v1alpha1.CloudflareAccount, string, error) {
	account, err := loadPrivateAccount(ctx, kube, accountName)
	if err != nil {
		return nil, "", err
	}
	if _, err = authorizePrivateNamespace(ctx, kube, account, namespace, authz.Request{PlatformObject: true}); err != nil {
		return nil, "", err
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err = kube.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, "", fmt.Errorf("get Cloudflare API token Secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	token := strings.TrimSpace(string(secret.Data[key]))
	if token == "" {
		return nil, "", fmt.Errorf("cloudflare API token Secret %s/%s has no non-empty %q key", ref.Namespace, ref.Name, key)
	}
	return account, token, nil
}

func globalContenderAccountID(ctx context.Context, kube client.Reader, namespace, accountName string, conditions []metav1.Condition, preserveRejectedOwner bool) (string, bool) {
	if !preserveRejectedOwner && globalConditionFalse(conditions, "Accepted") {
		return "", false
	}
	account := new(v1alpha1.CloudflareAccount)
	if err := kube.Get(ctx, types.NamespacedName{Name: accountName}, account); err != nil {
		return "", false
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
		!metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return "", false
	}
	namespaceObject := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: namespace}, namespaceObject); err != nil {
		return "", false
	}
	if decision := authz.Evaluate(account, namespaceObject, authz.Request{PlatformObject: true}); !decision.Allowed {
		return "", false
	}
	return account.Spec.AccountID, true
}

func globalConditionFalse(conditions []metav1.Condition, conditionType string) bool {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return conditions[i].Status == metav1.ConditionFalse
		}
	}
	return false
}

func effectiveGlobalManagementPolicy(policy v1alpha1.ManagementPolicy) v1alpha1.ManagementPolicy {
	if policy == "" {
		return v1alpha1.ManagementPolicyObserveOnly
	}
	return policy
}

func effectiveGlobalDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

func globalConditions(existing []metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string, now time.Time) []metav1.Condition {
	return mergeAccessConditions(existing, now,
		accessCondition(generation, "Accepted", status, reason, message),
		accessCondition(generation, "Ready", status, reason, message),
	)
}

func globalOwnerDescription(ctx context.Context, kube client.Client, object client.Object, description string) (string, error) {
	clusterID, err := flarecloudflare.ClusterID(ctx, kube)
	if err != nil {
		return "", err
	}
	return flarecloudflare.PrivateResourceComment(clusterID, object.GetNamespace(), object.GetName(), description), nil
}

func globalOwnedDescription(remote, expected string) bool {
	return privateCommentOwnedBy(remote, expected)
}

func globalUserDescription(description string) string {
	owner, user, found := strings.Cut(description, " | ")
	if found {
		return user
	}
	if strings.HasPrefix(owner, "flareway ") &&
		strings.Count(strings.TrimPrefix(owner, "flareway "), "/") == 2 {
		return ""
	}
	return description
}

func globalObjectPrecedes(leftTime metav1.Time, leftKey client.ObjectKey, rightTime metav1.Time, rightKey client.ObjectKey) bool {
	if leftTime.Equal(&rightTime) {
		return leftKey.String() < rightKey.String()
	}
	return leftTime.Before(&rightTime)
}
