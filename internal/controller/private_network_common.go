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
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

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
			return nil, privateInvalid("InvalidAccountRef", "the CloudflareAccount %q was not found", accountName)
		}
		return nil, fmt.Errorf("get CloudflareAccount %q: %w", accountName, err)
	}
	if !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) || !metaConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid) {
		return nil, privateInvalid("Pending", "the CloudflareAccount %q is not accepted with valid credentials", accountName)
	}
	return account, nil
}

func authorizePrivateNamespace(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, namespaceName string, request authz.Request) (*corev1.Namespace, error) {
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: namespaceName}, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("RefNotPermitted", "the Namespace %q was not found", namespaceName)
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
	owner := flarecloudflare.PrivateResourceComment(clusterID, object.GetNamespace(), object.GetName(), "")
	if utf8.RuneCountInString(owner) > 100 {
		sum := sha256.Sum256([]byte(owner))
		owner = fmt.Sprintf("flareway sha256:%x", sum[:16])
	}
	if comment == "" {
		return owner, nil
	}
	const separator = " | "
	remaining := 100 - utf8.RuneCountInString(owner) - utf8.RuneCountInString(separator)
	if remaining <= 0 {
		return owner, nil
	}
	runes := []rune(comment)
	if len(runes) > remaining {
		runes = runes[:remaining]
	}
	return owner + separator + string(runes), nil
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

func namespacedReferenceKey(sourceNamespace string, ref v1alpha1.TunnelReference) types.NamespacedName {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = sourceNamespace
	}
	return types.NamespacedName{Namespace: namespace, Name: ref.Name}
}

func privateVirtualNetworkReferenceName(ref *corev1.LocalObjectReference) string {
	if ref == nil {
		return ""
	}
	return ref.Name
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
	id         string
	tunnelType flarecloudflare.NetworkTunnelType
}

func resolvePrivateTunnel(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, routeNamespace string, ref v1alpha1.TunnelReference, allowed v1alpha1.AllowedNamespaces, routeKind authz.PrivateRouteKind, routeLabels map[string]string, hostname string) (*resolvedPrivateTunnel, error) {
	key := namespacedReferenceKey(routeNamespace, ref)
	if key.Name == "" {
		return nil, privateInvalid("TargetNotFound", "tunnelRef.name is required")
	}
	namespace := new(corev1.Namespace)
	if err := kube.Get(ctx, types.NamespacedName{Name: key.Namespace}, namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("TargetNotFound", "the Tunnel Namespace %q was not found", key.Namespace)
		}
		return nil, err
	}
	allowedNamespace, err := privateRouteAllowsNamespace(routeNamespace, allowed, namespace)
	if err != nil {
		return nil, privateInvalid("Invalid", "%v", err)
	}
	if !allowedNamespace {
		return nil, privateInvalid("RefNotPermitted", "the Namespace %q is not allowed by this route", namespace.Name)
	}
	decision := authz.Evaluate(account, namespace, authz.Request{
		Hostname:     hostname,
		Exposure:     v1alpha1.ExposurePrivate,
		PrivateRoute: &authz.PrivateRouteRequest{Kind: routeKind, Labels: routeLabels},
	})
	if !decision.Allowed {
		return nil, privateInvalid(decision.Reason, "%s", decision.Message)
	}
	switch effectiveTunnelReferenceKind(ref.Kind) {
	case v1alpha1.TunnelReferenceKindCloudflareTunnel:
		tunnel := new(v1alpha1.CloudflareTunnel)
		if err := kube.Get(ctx, key, tunnel); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, privateInvalid("TargetNotFound", "the CloudflareTunnel %s was not found", key)
			}
			return nil, err
		}
		if !tunnel.DeletionTimestamp.IsZero() {
			return nil, privateInvalid("TargetNotFound", "the CloudflareTunnel %s is deleting", key)
		}
		if tunnel.Spec.AccountRef.Name != account.Name {
			return nil, privateInvalid("RefNotPermitted", "the CloudflareTunnel %s uses CloudflareAccount %q, want %q", key, tunnel.Spec.AccountRef.Name, account.Name)
		}
		if tunnel.Spec.ManagementPolicy == v1alpha1.ManagementPolicyObserveOnly ||
			!metaConditionTrue(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted) ||
			tunnel.Status.TunnelID == "" || !tunnel.Status.OwnershipVerified {
			return nil, privateInvalid("Pending", "the CloudflareTunnel %s is not accepted with an ownership-verified remote tunnel ID", key)
		}
		return &resolvedPrivateTunnel{id: tunnel.Status.TunnelID, tunnelType: flarecloudflare.NetworkTunnelTypeCloudflareTunnel}, nil
	case v1alpha1.TunnelReferenceKindWARPConnector:
		tunnel := new(v1alpha1.WARPConnector)
		if err := kube.Get(ctx, key, tunnel); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, privateInvalid("TargetNotFound", "the WARPConnector %s was not found", key)
			}
			return nil, err
		}
		if !tunnel.DeletionTimestamp.IsZero() {
			return nil, privateInvalid("TargetNotFound", "the WARPConnector %s is deleting", key)
		}
		if tunnel.Spec.AccountRef.Name != account.Name {
			return nil, privateInvalid("RefNotPermitted", "the WARPConnector %s uses CloudflareAccount %q, want %q", key, tunnel.Spec.AccountRef.Name, account.Name)
		}
		if !metaConditionTrue(tunnel.Status.Conditions, v1alpha1.WARPConnectorConditionAccepted) || tunnel.Status.TunnelID == "" {
			return nil, privateInvalid("Pending", "the WARPConnector %s is not accepted with a remote tunnel ID", key)
		}
		return &resolvedPrivateTunnel{id: tunnel.Status.TunnelID, tunnelType: flarecloudflare.NetworkTunnelTypeWARPConnector}, nil
	default:
		return nil, privateInvalid("Invalid", "unsupported tunnelRef.kind %q", ref.Kind)
	}
}

func effectiveTunnelReferenceKind(kind v1alpha1.TunnelReferenceKind) v1alpha1.TunnelReferenceKind {
	if kind == "" {
		return v1alpha1.TunnelReferenceKindCloudflareTunnel
	}
	return kind
}

func privateTunnelTypeForReference(kind v1alpha1.TunnelReferenceKind) (flarecloudflare.NetworkTunnelType, error) {
	switch effectiveTunnelReferenceKind(kind) {
	case v1alpha1.TunnelReferenceKindCloudflareTunnel:
		return flarecloudflare.NetworkTunnelTypeCloudflareTunnel, nil
	case v1alpha1.TunnelReferenceKindWARPConnector:
		return flarecloudflare.NetworkTunnelTypeWARPConnector, nil
	default:
		return "", privateInvalid("Invalid", "unsupported tunnelRef.kind %q", kind)
	}
}

func validatePrivateTunnelType(expected, observed flarecloudflare.NetworkTunnelType, resource, id string) string {
	switch expected {
	case flarecloudflare.NetworkTunnelTypeCloudflareTunnel, flarecloudflare.NetworkTunnelTypeWARPConnector:
	default:
		return fmt.Sprintf("resolved %s %q has unsupported expected tunnel type %q", resource, id, expected)
	}
	if observed != "" && observed != expected {
		return fmt.Sprintf("remote %s %q has tunnel type %q, want %q", resource, id, observed, expected)
	}
	return ""
}

func privateTunnelRemoteType(value flarecloudflare.NetworkTunnelType) v1alpha1.TunnelRemoteType {
	switch value {
	case flarecloudflare.NetworkTunnelTypeCloudflareTunnel:
		return v1alpha1.TunnelRemoteTypeCloudflareTunnel
	case flarecloudflare.NetworkTunnelTypeWARPConnector:
		return v1alpha1.TunnelRemoteTypeWARPConnector
	case flarecloudflare.NetworkTunnelTypeWARP:
		return v1alpha1.TunnelRemoteTypeWARP
	case flarecloudflare.NetworkTunnelTypeMagic:
		return v1alpha1.TunnelRemoteTypeMagic
	case flarecloudflare.NetworkTunnelTypeIPSec:
		return v1alpha1.TunnelRemoteTypeIPSec
	case flarecloudflare.NetworkTunnelTypeGRE:
		return v1alpha1.TunnelRemoteTypeGRE
	case flarecloudflare.NetworkTunnelTypeCNI:
		return v1alpha1.TunnelRemoteTypeCNI
	default:
		return ""
	}
}

func privateMetaTime(value time.Time) *metav1.Time {
	if value.IsZero() {
		return nil
	}
	result := metav1.NewTime(value)
	return &result
}

func privateMetaTimePointer(value *time.Time) *metav1.Time {
	if value == nil {
		return nil
	}
	result := metav1.NewTime(*value)
	return &result
}

func resolvePrivateVirtualNetwork(ctx context.Context, kube client.Client, account *v1alpha1.CloudflareAccount, namespace, name string) (*v1alpha1.VirtualNetwork, error) {
	if name == "" {
		return nil, privateInvalid("TargetNotFound", "virtualNetworkRef.name is required")
	}
	object := new(v1alpha1.VirtualNetwork)
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := kube.Get(ctx, key, object); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, privateInvalid("TargetNotFound", "the VirtualNetwork %s was not found", key)
		}
		return nil, err
	}
	if !object.DeletionTimestamp.IsZero() {
		return nil, privateInvalid("TargetNotFound", "the VirtualNetwork %s is deleting", key)
	}
	if object.Spec.AccountRef.Name != account.Name {
		return nil, privateInvalid("RefNotPermitted", "the VirtualNetwork %s uses CloudflareAccount %q, want %q", key, object.Spec.AccountRef.Name, account.Name)
	}
	if !metaConditionTrue(object.Status.Conditions, v1alpha1.PrivateNetworkConditionAccepted) || object.Status.VirtualNetworkID == "" {
		return nil, privateInvalid("Pending", "the VirtualNetwork %s is not accepted with a remote ID", key)
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
