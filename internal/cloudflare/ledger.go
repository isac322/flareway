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

package cloudflare

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ManagedByTag is retained for taggable Cloudflare resources. DNS ownership is
// established by its deterministic comment instead of this optional tag.
const ManagedByTag = "managed-by=flareway"

// ClusterID returns the stable UID of the kube-system Namespace.
func ClusterID(ctx context.Context, client kubeclient.Client) (string, error) {
	namespace := new(corev1.Namespace)
	if err := client.Get(ctx, types.NamespacedName{Name: metav1NamespaceSystem}, namespace); err != nil {
		return "", fmt.Errorf("get kube-system namespace UID: %w", err)
	}
	if namespace.UID == "" {
		return "", fmt.Errorf("kube-system namespace has no UID")
	}
	return string(namespace.UID), nil
}

const metav1NamespaceSystem = "kube-system"

// OwnerTag returns the exact ownership ledger tag attached to taggable objects.
func OwnerTag(clusterID, namespace, name string, uid types.UID) string {
	return fmt.Sprintf("flareway.bhyoo.com/owner=%s/%s/%s/%s", clusterID, namespace, name, uid)
}

// DNSRecordComment returns a deterministic DNS ownership marker no longer than
// Cloudflare's 100-code-point comment limit. Long identities use a stable hash.
func DNSRecordComment(clusterID, namespace, gatewayName string) string {
	identity := fmt.Sprintf("%s/%s/%s", clusterID, namespace, gatewayName)
	comment := "flareway " + identity
	if utf8.RuneCountInString(comment) <= dnsRecordCommentLimit {
		return comment
	}
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("flareway sha256:%x", sum)
}

// DNSRecordCommentWithText appends a human comment without exceeding the
// Cloudflare DNS comment limit. The ownership marker is never truncated.
func DNSRecordCommentWithText(clusterID, namespace, gatewayName, text string) string {
	owner := DNSRecordComment(clusterID, namespace, gatewayName)
	text = strings.TrimSpace(text)
	if text == "" || text == ManagedByTag {
		return owner
	}
	remaining := dnsRecordCommentLimit - utf8.RuneCountInString(owner) - utf8.RuneCountInString(dnsRecordCommentSeparator)
	if remaining <= 0 {
		return owner
	}
	runes := []rune(text)
	if len(runes) > remaining {
		runes = runes[:remaining]
	}
	return owner + dnsRecordCommentSeparator + string(runes)
}

const (
	dnsRecordCommentLimit     = 100
	dnsRecordCommentSeparator = " "
)

// PrivateResourceComment returns a stable ownership prefix and optional human comment
// for Cloudflare network resources, whose APIs do not support tags.
func PrivateResourceComment(clusterID, namespace, name, comment string) string {
	owner := fmt.Sprintf("flareway %s/%s/%s", clusterID, namespace, name)
	if comment == "" {
		return owner
	}
	return owner + " | " + comment
}

// IsOwnedPrivateResource reports whether a network resource comment carries the
// exact ownership prefix for one Kubernetes object.
func IsOwnedPrivateResource(comment, clusterID, namespace, name string) bool {
	owner := fmt.Sprintf("flareway %s/%s/%s", clusterID, namespace, name)
	return comment == owner || strings.HasPrefix(comment, owner+" | ")
}

// IsOwnedBy reports whether markers contain the exact expected ownership marker.
func IsOwnedBy(markers []string, expected string) bool {
	return expected != "" && slices.Contains(markers, expected)
}

// IsOwnedDNSRecord reports whether a DNS record carries the exact expected
// comment marker, optionally followed by its user-facing comment.
func IsOwnedDNSRecord(record DNSRecord, expectedComment string) bool {
	return expectedComment != "" &&
		(record.Comment == expectedComment || strings.HasPrefix(record.Comment, expectedComment+dnsRecordCommentSeparator))
}
