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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	statusutil "github.com/isac322/flareway/internal/gatewayapi/status"
)

const accessAccountIndex = ".spec.accountRef.name"

// NewAccessCloudflareClient constructs an account-scoped M3 Access client.
type NewAccessCloudflareClient func(token, accountID string) (flarecloudflare.AccessAPI, error)

// AccessClientFromFactory adapts the shared production Cloudflare factory.
func AccessClientFromFactory(factory flarecloudflare.ClientFactory) NewAccessCloudflareClient {
	return func(token, accountID string) (flarecloudflare.AccessAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

func accessClientForAccount(
	ctx context.Context,
	kube client.Client,
	namespaceName string,
	accountName string,
	operation authz.Request,
	factory NewAccessCloudflareClient,
) (flarecloudflare.AccessAPI, *v1alpha1.CloudflareAccount, error) {
	if namespaceName == "" {
		return nil, nil, errors.New("request namespace is required")
	}
	if accountName == "" {
		return nil, nil, errors.New("accountRef.name is required")
	}
	if factory == nil {
		return nil, nil, errors.New("cloudflare Access client factory is required")
	}
	account := new(v1alpha1.CloudflareAccount)
	if err := kube.Get(ctx, types.NamespacedName{Name: accountName}, account); err != nil {
		return nil, nil, fmt.Errorf("get CloudflareAccount %q: %w", accountName, err)
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) ||
		!metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return nil, nil, fmt.Errorf("the CloudflareAccount %q is not ready", accountName)
	}
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: namespaceName}, namespace); err != nil {
		return nil, nil, fmt.Errorf("get request Namespace %q: %w", namespaceName, err)
	}
	decision := authz.Evaluate(account, namespace, operation)
	if !decision.Allowed {
		return nil, nil, privateInvalid(decision.Reason, "%s: %s", decision.Reason, decision.Message)
	}

	ref := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err := kube.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
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
	api, err := factory(string(token), account.Spec.AccountID)
	if err != nil {
		return nil, nil, err
	}
	return api, account, nil
}

func metaConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return conditions[i].Status == metav1.ConditionTrue
		}
	}
	return false
}

func accessRemoteName(ctx context.Context, kube client.Client, namespace, name string) (string, error) {
	clusterNamespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: "kube-system"}, clusterNamespace); err != nil {
		return "", fmt.Errorf("read cluster ID from kube-system Namespace UID: %w", err)
	}
	if clusterNamespace.UID == "" {
		return "", errors.New("kube-system Namespace has no UID")
	}
	return fmt.Sprintf("flareway/%s/%s/%s", clusterNamespace.UID, namespace, name), nil
}

func accessCondition(generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: generation}
}

func mergeAccessConditions(existing []metav1.Condition, now time.Time, conditions ...metav1.Condition) []metav1.Condition {
	return statusutil.MergeConditions(existing, metav1.NewTime(now), conditions...)
}

func referenceNamespace(namespace string, ref v1alpha1.AccessObjectReference) string {
	if ref.Namespace != "" {
		return ref.Namespace
	}
	return namespace
}

func resolveAccessRules(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, rules []v1alpha1.AccessRule) ([]flarecloudflare.ResolvedAccessRule, error) {
	result := make([]flarecloudflare.ResolvedAccessRule, 0, len(rules))
	for i := range rules {
		resolved, err := resolveAccessRule(ctx, kube, namespace, account, api, rules[i])
		if err != nil {
			return nil, fmt.Errorf("resolve Access rule %d: %w", i, err)
		}
		result = append(result, resolved)
	}
	return result, nil
}

func resolveAccessRule(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, rule v1alpha1.AccessRule) (flarecloudflare.ResolvedAccessRule, error) {
	set := 0
	for _, present := range []bool{rule.Email != nil, rule.EmailDomain != nil, rule.EmailList != nil, rule.Everyone != nil, rule.IP != nil, rule.IPList != nil, rule.Certificate != nil, rule.CommonName != nil, rule.Group != nil, rule.AzureAD != nil, rule.GitHubOrganization != nil, rule.GSuite != nil, rule.Okta != nil, rule.SAML != nil, rule.OIDC != nil, rule.ServiceToken != nil, rule.AnyValidServiceToken != nil, rule.ExternalEvaluation != nil, rule.Geo != nil, rule.AuthMethod != nil, rule.DevicePosture != nil, rule.LoginMethod != nil, rule.AuthContext != nil, rule.LinkedAppToken != nil, rule.UserRiskScore != nil, rule.CloudflareAccountMember != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return flarecloudflare.ResolvedAccessRule{}, fmt.Errorf("expected exactly one rule field, got %d", set)
	}
	switch {
	case rule.Email != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "email", Value: rule.Email.Email}, nil
	case rule.EmailDomain != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "emailDomain", Value: rule.EmailDomain.Domain}, nil
	case rule.EmailList != nil:
		id, err := resolveListID(ctx, kube, namespace, account, *rule.EmailList)
		return flarecloudflare.ResolvedAccessRule{Kind: "emailList", ID: id}, err
	case rule.Everyone != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "everyone"}, nil
	case rule.IP != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "ip", Value: rule.IP.IP}, nil
	case rule.IPList != nil:
		id, err := resolveListID(ctx, kube, namespace, account, *rule.IPList)
		return flarecloudflare.ResolvedAccessRule{Kind: "ipList", ID: id}, err
	case rule.Certificate != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "certificate"}, nil
	case rule.CommonName != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "commonName", Value: rule.CommonName.CommonName}, nil
	case rule.Group != nil:
		id, err := resolveGroupID(ctx, kube, namespace, account, api, rule.Group.GroupRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "group", ID: id}, err
	case rule.AzureAD != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.AzureAD.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "azureAD", ID: rule.AzureAD.ID, IdentityProviderID: id}, err
	case rule.GitHubOrganization != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.GitHubOrganization.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "githubOrganization", Value: rule.GitHubOrganization.Name, Value2: rule.GitHubOrganization.Team, IdentityProviderID: id}, err
	case rule.GSuite != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.GSuite.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "gsuite", Value: rule.GSuite.Email, IdentityProviderID: id}, err
	case rule.Okta != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.Okta.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "okta", Value: rule.Okta.Name, IdentityProviderID: id}, err
	case rule.SAML != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.SAML.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "saml", Value: rule.SAML.AttributeName, Value2: rule.SAML.AttributeValue, IdentityProviderID: id}, err
	case rule.OIDC != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.OIDC.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "oidc", Value: rule.OIDC.ClaimName, Value2: rule.OIDC.ClaimValue, IdentityProviderID: id}, err
	case rule.ServiceToken != nil:
		id, err := resolveServiceTokenID(ctx, kube, namespace, account, api, rule.ServiceToken.TokenRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "serviceToken", ID: id}, err
	case rule.AnyValidServiceToken != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "anyValidServiceToken"}, nil
	case rule.ExternalEvaluation != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "externalEvaluation", Value: rule.ExternalEvaluation.EvaluateURL, Value2: rule.ExternalEvaluation.KeysURL}, nil
	case rule.Geo != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "geo", Value: rule.Geo.CountryCode}, nil
	case rule.AuthMethod != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "authMethod", Value: rule.AuthMethod.AuthMethod}, nil
	case rule.DevicePosture != nil:
		id, err := resolvePostureID(ctx, kube, namespace, account, api, rule.DevicePosture.RuleRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "devicePosture", ID: id, AccountID: account.Spec.AccountID}, err
	case rule.LoginMethod != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.LoginMethod.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "loginMethod", IdentityProviderID: id}, err
	case rule.AuthContext != nil:
		id, err := resolveIDPID(ctx, kube, namespace, account, api, rule.AuthContext.IdentityProviderRef)
		return flarecloudflare.ResolvedAccessRule{Kind: "authContext", Value: rule.AuthContext.ID, Value2: rule.AuthContext.ACID, IdentityProviderID: id}, err
	case rule.LinkedAppToken != nil:
		return flarecloudflare.ResolvedAccessRule{Kind: "linkedAppToken", ID: rule.LinkedAppToken.AppID}, nil
	case rule.UserRiskScore != nil:
		values := make([]string, len(rule.UserRiskScore.Levels))
		for i := range rule.UserRiskScore.Levels {
			values[i] = string(rule.UserRiskScore.Levels[i])
		}
		return flarecloudflare.ResolvedAccessRule{Kind: "userRiskScore", Values: values}, nil
	default:
		id := rule.CloudflareAccountMember.AccountID
		if id == "" {
			id = account.Spec.AccountID
		}
		return flarecloudflare.ResolvedAccessRule{Kind: "cloudflareAccountMember", AccountID: id}, nil
	}
}

func authorizeAccessReference(ctx context.Context, kube client.Client, sourceNamespace, targetNamespace string, account *v1alpha1.CloudflareAccount, kind string) error {
	if targetNamespace == sourceNamespace {
		return nil
	}
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: sourceNamespace}, namespace); err != nil {
		return err
	}
	var request authz.Request
	switch kind {
	case "AccessCustomPage":
		request.AccessCustomPageRef = true
	default:
		request.AccessPolicyRef = true
	}
	decision := authz.Evaluate(account, namespace, request)
	if !decision.Allowed {
		return privateInvalid(decision.Reason, "%s: %s", decision.Reason, decision.Message)
	}
	return nil
}

func validateAccessReference(_, _, kind, accountName string, deletionTimestamp *metav1.Time, conditions []metav1.Condition, referencedAccount string) error {
	if deletionTimestamp != nil && !deletionTimestamp.IsZero() {
		return fmt.Errorf("referenced %s is deleting", kind)
	}
	if referencedAccount != accountName {
		return fmt.Errorf("referenced %s uses CloudflareAccount %q, want %q", kind, referencedAccount, accountName)
	}
	if !metaConditionTrue(conditions, "Accepted") {
		return fmt.Errorf("referenced %s is not Accepted", kind)
	}
	return nil
}

func resolveGroupID(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetAccessGroup(ctx, flarecloudflare.AccessScope{}, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external AccessGroup: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(namespace, ref)
	if err := authorizeAccessReference(ctx, kube, namespace, targetNamespace, account, "AccessGroup"); err != nil {
		return "", err
	}
	var object v1alpha1.AccessGroup
	if err := kube.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &object); err != nil {
		return "", err
	}
	if err := validateAccessReference(namespace, targetNamespace, "AccessGroup", account.Name, object.DeletionTimestamp, object.Status.Conditions, object.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if object.Status.GroupID == "" {
		return "", errors.New("referenced AccessGroup is not ready")
	}
	return object.Status.GroupID, nil
}

func resolveIDPID(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetIdentityProvider(ctx, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external IdentityProvider: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(namespace, ref)
	if err := authorizeAccessReference(ctx, kube, namespace, targetNamespace, account, "IdentityProvider"); err != nil {
		return "", err
	}
	var object v1alpha1.IdentityProvider
	if err := kube.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &object); err != nil {
		return "", err
	}
	if err := validateAccessReference(namespace, targetNamespace, "IdentityProvider", account.Name, object.DeletionTimestamp, object.Status.Conditions, object.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if object.Status.IDPID == "" {
		return "", errors.New("referenced IdentityProvider is not ready")
	}
	return object.Status.IDPID, nil
}

func resolveServiceTokenID(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetServiceToken(ctx, flarecloudflare.AccessScope{}, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external ServiceToken: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(namespace, ref)
	if err := authorizeAccessReference(ctx, kube, namespace, targetNamespace, account, "ServiceToken"); err != nil {
		return "", err
	}
	var object v1alpha1.ServiceToken
	if err := kube.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &object); err != nil {
		return "", err
	}
	if err := validateAccessReference(namespace, targetNamespace, "ServiceToken", account.Name, object.DeletionTimestamp, object.Status.Conditions, object.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if object.Status.TokenID == "" {
		return "", errors.New("referenced ServiceToken is not ready")
	}
	return object.Status.TokenID, nil
}

func resolvePostureID(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, api flarecloudflare.AccessAPI, ref v1alpha1.AccessObjectReference) (string, error) {
	if ref.ExternalID != "" {
		if _, err := api.GetDevicePostureRule(ctx, ref.ExternalID); err != nil {
			return "", fmt.Errorf("validate external DevicePostureRule: %w", err)
		}
		return ref.ExternalID, nil
	}
	targetNamespace := referenceNamespace(namespace, ref)
	if err := authorizeAccessReference(ctx, kube, namespace, targetNamespace, account, "DevicePostureRule"); err != nil {
		return "", err
	}
	var object v1alpha1.DevicePostureRule
	if err := kube.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, &object); err != nil {
		return "", err
	}
	if err := validateAccessReference(namespace, targetNamespace, "DevicePostureRule", account.Name, object.DeletionTimestamp, object.Status.Conditions, object.Spec.AccountRef.Name); err != nil {
		return "", err
	}
	if object.Status.RuleID == "" {
		return "", errors.New("referenced DevicePostureRule is not ready")
	}
	return object.Status.RuleID, nil
}

func resolveListID(ctx context.Context, kube client.Client, namespace string, account *v1alpha1.CloudflareAccount, rule v1alpha1.AccessListRule) (string, error) {
	if rule.ListID != "" {
		return rule.ListID, nil
	}
	if rule.ListRef == nil {
		return "", errors.New("listId or listRef is required")
	}
	ref := *rule.ListRef
	targetNamespace := referenceNamespace(namespace, ref)
	if err := authorizeAccessReference(ctx, kube, namespace, targetNamespace, account, "ZeroTrustList"); err != nil {
		return "", err
	}
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: v1alpha1.Group, Version: v1alpha1.Version, Kind: "ZeroTrustList"})
	if err := kube.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: ref.Name}, object); err != nil {
		return "", err
	}
	if timestamp := object.GetDeletionTimestamp(); timestamp != nil && !timestamp.IsZero() {
		return "", errors.New("referenced ZeroTrustList is deleting")
	}
	referencedAccount, _, err := unstructured.NestedString(object.Object, "spec", "accountRef", "name")
	if err != nil {
		return "", err
	}
	if referencedAccount != account.Name {
		return "", fmt.Errorf("referenced ZeroTrustList uses CloudflareAccount %q, want %q", referencedAccount, account.Name)
	}
	conditions, _, err := unstructured.NestedSlice(object.Object, "status", "conditions")
	if err != nil {
		return "", err
	}
	accepted := false
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if ok && condition["type"] == "Accepted" && condition["status"] == "True" {
			accepted = true
			break
		}
	}
	if !accepted {
		return "", errors.New("referenced ZeroTrustList is not Accepted")
	}
	id, found, err := unstructured.NestedString(object.Object, "status", "listId")
	if err != nil {
		return "", err
	}
	if !found || id == "" {
		return "", errors.New("referenced ZeroTrustList is not ready")
	}
	return id, nil
}

func ignoreRemoteNotFound(err error) error {
	if err == nil || flarecloudflare.IsNotFound(err) || apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func trimSecret(value []byte) string { return strings.TrimSpace(string(value)) }
