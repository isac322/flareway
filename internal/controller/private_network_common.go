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
	"net/netip"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	privateNetworkRequeue = 5 * time.Second

	virtualNetworkAccountIndex        = "flareway.virtualNetwork.account"
	networkRouteAccountIndex          = "flareway.networkRoute.account"
	networkRouteTunnelIndex           = "flareway.networkRoute.tunnel"
	networkRouteVNetIndex             = "flareway.networkRoute.virtualNetwork"
	hostnameRouteAccountIndex         = "flareway.hostnameRoute.account"
	hostnameRouteTunnelIndex          = "flareway.hostnameRoute.tunnel"
	hostnameRouteSourceNamespaceIndex = "flareway.hostnameRoute.sourceNamespace"

	generatedPlatformObjectLabel  = "flareway.bhyoo.com/platform-object"
	generatedSourceNamespaceLabel = "flareway.bhyoo.com/source-namespace"
	generatedGatewayLabel         = "flareway.bhyoo.com/gateway"
	sourceGatewayUIDAnnotation    = "flareway.bhyoo.com/source-gateway-uid"
)

// NewPrivateNetworkCloudflareClient constructs an account-scoped private-network client.
type NewPrivateNetworkCloudflareClient func(token, accountID string) (flarecloudflare.NetworkAPI, error)

// PrivateNetworkClientFromFactory adapts the shared production Cloudflare factory.
func PrivateNetworkClientFromFactory(factory flarecloudflare.ClientFactory) NewPrivateNetworkCloudflareClient {
	return func(token, accountID string) (flarecloudflare.NetworkAPI, error) {
		if factory == nil {
			return nil, errors.New("cloudflare client factory is nil")
		}
		return factory.Client(token, accountID), nil
	}
}

type privateValidationError struct {
	reason  string
	message string
}

func (err privateValidationError) Error() string { return err.message }

func privateInvalid(reason, format string, args ...any) error {
	return privateValidationError{reason: reason, message: fmt.Sprintf(format, args...)}
}

func privateErrorReason(err error) string {
	var validation privateValidationError
	if errors.As(err, &validation) {
		return validation.reason
	}
	return "Pending"
}

func privateErrorMessage(err error) string {
	var validation privateValidationError
	if errors.As(err, &validation) {
		return validation.message
	}
	return err.Error()
}

func privateIsValidationError(err error) bool {
	var validation privateValidationError
	return errors.As(err, &validation)
}

func loadPrivateAccount(ctx context.Context, kube client.Client, accountName string) (*v1alpha1.CloudflareAccount, error) {
	if accountName == "" {
		return nil, privateInvalid("InvalidAccountRef", "accountRef.name is required")
	}
	account := new(v1alpha1.CloudflareAccount)
	if err := kube.Get(ctx, types.NamespacedName{Name: accountName}, account); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("InvalidAccountRef", "CloudflareAccount %q was not found", accountName)
		}
		return nil, fmt.Errorf("get CloudflareAccount %q: %w", accountName, err)
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) || !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return nil, privateInvalid("Pending", "CloudflareAccount %q is not accepted with valid credentials", accountName)
	}
	return account, nil
}

func authorizePrivateNamespace(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, namespaceName string, request authz.Request) (*corev1.Namespace, error) {
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: namespaceName}, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("RefNotPermitted", "Namespace %q was not found", namespaceName)
		}
		return nil, fmt.Errorf("get Namespace %q: %w", namespaceName, err)
	}
	decision := authz.Evaluate(account, namespace, request)
	if !decision.Allowed {
		return nil, privateInvalid(decision.Reason, "%s", decision.Message)
	}
	return namespace, nil
}

func privateNetworkClient(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, factory NewPrivateNetworkCloudflareClient) (flarecloudflare.NetworkAPI, error) {
	if factory == nil {
		return nil, errors.New("cloudflare private-network client factory is required")
	}
	ref := account.Spec.Credentials.APITokenSecretRef
	secret := new(corev1.Secret)
	if err := kube.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, fmt.Errorf("get Cloudflare API token Secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	token := strings.TrimSpace(string(secret.Data[key]))
	if token == "" {
		return nil, fmt.Errorf("cloudflare API token Secret %s/%s has no non-empty %q key", ref.Namespace, ref.Name, key)
	}
	return factory(token, account.Spec.AccountID)
}

func privateOwnerComment(ctx context.Context, kube client.Client, object client.Object, comment string) (string, error) {
	clusterID, err := flarecloudflare.ClusterID(ctx, kube)
	if err != nil {
		return "", err
	}
	return flarecloudflare.PrivateResourceComment(clusterID, object.GetNamespace(), object.GetName(), comment), nil
}

func privateCondition(generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{Type: conditionType, Status: status, Reason: reason, Message: message, ObservedGeneration: generation}
}

func privateConditions(existing []metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string, now time.Time) []metav1.Condition {
	return mergeAccessConditions(existing, now,
		privateCondition(generation, v1alpha1.PrivateNetworkConditionAccepted, status, reason, message),
		privateCondition(generation, v1alpha1.PrivateNetworkConditionReady, status, reason, message),
	)
}

func privateCommentOwner(comment string) string {
	owner, _, _ := strings.Cut(comment, " | ")
	return owner
}

func privateCommentOwnedBy(comment, ownerComment string) bool {
	owner := privateCommentOwner(ownerComment)
	return comment == owner || strings.HasPrefix(comment, owner+" | ")
}

func effectivePrivateManagementPolicy(policy v1alpha1.ManagementPolicy) v1alpha1.ManagementPolicy {
	if policy == "" {
		return v1alpha1.ManagementPolicyManaged
	}
	return policy
}

func effectivePrivateDeletionPolicy(policy v1alpha1.DeletionPolicy) v1alpha1.DeletionPolicy {
	if policy == "" {
		return v1alpha1.DeletionPolicyOrphan
	}
	return policy
}

func namespacedReferenceKey(sourceNamespace string, ref v1alpha1.NamespacedObjectReference) types.NamespacedName {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = sourceNamespace
	}
	return types.NamespacedName{Namespace: namespace, Name: ref.Name}
}

// privateRouteAllowsNamespace reports whether a route's consumer namespace is allowed.
// AccessApplication and route reconcilers share this check so neither path can bypass it.
func privateRouteAllowsNamespace(routeNamespace string, allowed v1alpha1.AllowedNamespaces, namespace *corev1.Namespace) (bool, error) {
	if namespace == nil {
		return false, errors.New("consumer Namespace is required")
	}
	switch allowed.From {
	case "", v1alpha1.AllowedNamespaceFromSame:
		return namespace.Name == routeNamespace, nil
	case v1alpha1.AllowedNamespaceFromAll:
		return true, nil
	case v1alpha1.AllowedNamespaceFromSelector:
		if allowed.Selector == nil {
			return false, errors.New("allowedNamespaces.selector is required when from is Selector")
		}
		selector, err := metav1.LabelSelectorAsSelector(allowed.Selector)
		if err != nil {
			return false, fmt.Errorf("compile allowedNamespaces selector: %w", err)
		}
		return selector.Matches(labels.Set(namespace.Labels)), nil
	default:
		return false, fmt.Errorf("unsupported allowedNamespaces.from %q", allowed.From)
	}
}

type resolvedPrivateTunnel struct {
	object    *v1alpha1.CloudflareTunnel
	namespace *corev1.Namespace
	id        string
}

func resolvePrivateTunnel(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, routeNamespace string, ref v1alpha1.NamespacedObjectReference, allowed v1alpha1.AllowedNamespaces, kind authz.PrivateRouteKind, routeLabels map[string]string, hostname string) (*resolvedPrivateTunnel, error) {
	key := namespacedReferenceKey(routeNamespace, ref)
	if key.Name == "" {
		return nil, privateInvalid("TargetNotFound", "tunnelRef.name is required")
	}
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: key.Namespace}, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("TargetNotFound", "Tunnel Namespace %q was not found", key.Namespace)
		}
		return nil, err
	}
	allowedNamespace, err := privateRouteAllowsNamespace(routeNamespace, allowed, namespace)
	if err != nil {
		return nil, privateInvalid("Invalid", "%v", err)
	}
	if !allowedNamespace {
		return nil, privateInvalid("RefNotPermitted", "Namespace %q is not allowed by this route", namespace.Name)
	}
	decision := authz.Evaluate(account, namespace, authz.Request{
		Hostname:     hostname,
		Exposure:     v1alpha1.ExposurePrivate,
		PrivateRoute: &authz.PrivateRouteRequest{Kind: kind, Labels: routeLabels},
	})
	if !decision.Allowed {
		return nil, privateInvalid(decision.Reason, "%s", decision.Message)
	}
	tunnel := new(v1alpha1.CloudflareTunnel)
	if err := kube.Get(ctx, key, tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("TargetNotFound", "CloudflareTunnel %s was not found", key)
		}
		return nil, err
	}
	if !tunnel.DeletionTimestamp.IsZero() {
		return nil, privateInvalid("TargetNotFound", "CloudflareTunnel %s is deleting", key)
	}
	if tunnel.Spec.AccountRef.Name != account.Name {
		return nil, privateInvalid("RefNotPermitted", "CloudflareTunnel %s uses CloudflareAccount %q, want %q", key, tunnel.Spec.AccountRef.Name, account.Name)
	}
	if !metaConditionTrue(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted) || tunnel.Status.TunnelID == "" {
		return nil, privateInvalid("Pending", "CloudflareTunnel %s is not accepted with a remote tunnel ID", key)
	}
	return &resolvedPrivateTunnel{object: tunnel, namespace: namespace, id: tunnel.Status.TunnelID}, nil
}

func resolvePrivateVirtualNetwork(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, namespace, name string) (*v1alpha1.VirtualNetwork, error) {
	if name == "" {
		return nil, privateInvalid("TargetNotFound", "virtualNetworkRef.name is required")
	}
	object := new(v1alpha1.VirtualNetwork)
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := kube.Get(ctx, key, object); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("TargetNotFound", "VirtualNetwork %s was not found", key)
		}
		return nil, err
	}
	if !object.DeletionTimestamp.IsZero() {
		return nil, privateInvalid("TargetNotFound", "VirtualNetwork %s is deleting", key)
	}
	if object.Spec.AccountRef.Name != account.Name {
		return nil, privateInvalid("RefNotPermitted", "VirtualNetwork %s uses CloudflareAccount %q, want %q", key, object.Spec.AccountRef.Name, account.Name)
	}
	if !metaConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) || object.Status.VirtualNetworkID == "" {
		return nil, privateInvalid("Pending", "VirtualNetwork %s is not accepted with a remote ID", key)
	}
	return object, nil
}

func parseMaskedPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("network %q is not a valid CIDR: %w", value, err)
	}
	masked := prefix.Masked()
	if prefix != masked {
		return netip.Prefix{}, fmt.Errorf("network %q is not masked; use %q", value, masked.String())
	}
	return masked, nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func normalizedPrivateHostname(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	hostname := strings.ToLower(trimmed)
	if value != trimmed || trimmed != hostname {
		return "", errors.New("hostname must use normalized lowercase DNS form without surrounding whitespace")
	}
	if hostname == "" || strings.HasSuffix(hostname, ".") {
		return "", errors.New("hostname must be a non-empty absolute DNS name without a trailing dot")
	}
	if strings.Count(hostname, "*") > 0 {
		if !strings.HasPrefix(hostname, "*.") || strings.Count(hostname, "*") != 1 {
			return "", errors.New("hostname wildcard must occupy exactly the first DNS label")
		}
	}
	labels := strings.Split(strings.TrimPrefix(hostname, "*."), ".")
	if len(labels) < 2 {
		return "", errors.New("hostname must contain at least two DNS labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("hostname %q contains an invalid DNS label", value)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("hostname %q contains an invalid DNS character", value)
			}
		}
	}
	return hostname, nil
}

// cloudflarePrivateHostname converts a single-label wildcard to Cloudflare's suffix form.
func cloudflarePrivateHostname(hostname string) string {
	return strings.TrimPrefix(hostname, "*.")
}

func privateHostnamesOverlap(left, right string) bool {
	if left == right {
		return true
	}
	leftWildcard := strings.HasPrefix(left, "*.")
	rightWildcard := strings.HasPrefix(right, "*.")
	if leftWildcard && rightWildcard {
		return strings.TrimPrefix(left, "*.") == strings.TrimPrefix(right, "*.")
	}
	if leftWildcard {
		return wildcardPrivateHostnameMatches(left, right)
	}
	if rightWildcard {
		return wildcardPrivateHostnameMatches(right, left)
	}
	return false
}

func wildcardPrivateHostnameMatches(wildcard, exact string) bool {
	suffix := strings.TrimPrefix(wildcard, "*.")
	if !strings.HasSuffix(exact, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(exact, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func privateObjectPrecedes(leftCreation metav1.Time, leftKey types.NamespacedName, rightCreation metav1.Time, rightKey types.NamespacedName) bool {
	if !leftCreation.Equal(&rightCreation) {
		return leftCreation.Before(&rightCreation)
	}
	return leftKey.String() < rightKey.String()
}
