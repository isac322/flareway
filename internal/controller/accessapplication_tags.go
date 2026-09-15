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
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

const (
	accessTagNameMaxLength = flarecloudflare.AccessTagNameMaxLength
	accessManagedTag       = "flareway-managed"
	accessOwnerTagPrefix   = "flareway-owner-"
	accessBypassTagPrefix  = "flareway-bypass-"
)

func ensureAccessTags(ctx context.Context, remote flarecloudflare.AccessTagAPI, names ...string) error {
	names, err := desiredAccessTags(names)
	if err != nil {
		return err
	}
	existing, err := remote.ListAccessTags(ctx)
	if err != nil {
		return fmt.Errorf("list Access tags: %w", err)
	}
	known := make(map[string]struct{}, len(existing))
	for _, tag := range existing {
		known[tag.Name] = struct{}{}
	}
	for _, name := range names {
		if _, found := known[name]; found {
			continue
		}
		created, createErr := remote.CreateAccessTag(ctx, name)
		if createErr == nil {
			if created.Name != name {
				return fmt.Errorf("create Access tag %q returned name %q", name, created.Name)
			}
			continue
		}
		if !flarecloudflare.IsConflict(createErr) {
			return fmt.Errorf("create Access tag %q: %w", name, createErr)
		}
		if err := confirmAccessTagCreateConflict(ctx, remote, name, createErr); err != nil {
			return err
		}
	}
	return nil
}

func confirmAccessTagCreateConflict(ctx context.Context, remote flarecloudflare.AccessTagAPI, name string, createErr error) error {
	confirmed, getErr := remote.GetAccessTag(ctx, name)
	if getErr != nil {
		return errors.Join(
			fmt.Errorf("create Access tag %q raced: %w", name, createErr),
			fmt.Errorf("confirm Access tag %q after conflict: %w", name, getErr),
		)
	}
	if confirmed.Name != name {
		return fmt.Errorf("confirm Access tag %q after conflict returned name %q", name, confirmed.Name)
	}
	return nil
}

func desiredAccessTags(names []string) ([]string, error) {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > flarecloudflare.AccessApplicationTagLimit {
		return nil, fmt.Errorf("access application has %d tags; Cloudflare permits at most %d", len(names), flarecloudflare.AccessApplicationTagLimit)
	}
	for _, name := range names {
		if name == "" {
			return nil, errors.New("access tag name is required")
		}
		if len(name) > accessTagNameMaxLength {
			return nil, fmt.Errorf("access tag name %q exceeds Cloudflare's %d-character limit", name, accessTagNameMaxLength)
		}
		for index := range len(name) {
			value := name[index]
			if (value >= 'a' && value <= 'z') ||
				(value >= 'A' && value <= 'Z') ||
				(value >= '0' && value <= '9') ||
				value == '_' || value == '-' {
				continue
			}
			return nil, fmt.Errorf("access tag name %q contains unsupported character %q", name, value)
		}
	}
	return names, nil
}

func desiredStandaloneAccessTags(applicationType v1alpha1.AccessStandaloneApplicationType, names []string) ([]string, error) {
	switch applicationType {
	case v1alpha1.AccessStandaloneApplicationTypeSaaS,
		v1alpha1.AccessStandaloneApplicationTypeBookmark,
		v1alpha1.AccessStandaloneApplicationTypeMCPPortal:
		tags, err := desiredAccessTags(names)
		if err != nil {
			return nil, accessValidationError{reason: "Invalid", message: err.Error()}
		}
		return tags, nil
	default:
		if len(names) != 0 {
			return nil, accessValidationError{
				reason:  "UnsupportedField",
				message: fmt.Sprintf("standalone Access application type %q does not support tags", applicationType),
			}
		}
		return nil, nil
	}
}

func (r *AccessApplicationReconciler) resolveCustomPages(ctx context.Context, application *v1alpha1.AccessApplication, account *v1alpha1.CloudflareAccount, remote AccessApplicationCloudflareClient) ([]string, error) {
	authorization := authz.Request{}
	for _, reference := range application.Spec.Application.CustomPageRefs {
		if reference.ExternalID != "" {
			authorization.PlatformObject = true
			continue
		}
		if reference.ObjectRef != nil && reference.ObjectRef.Namespace != "" && reference.ObjectRef.Namespace != application.Namespace {
			authorization.AccessCustomPageRef = true
		}
	}
	if authorization.PlatformObject || authorization.AccessCustomPageRef {
		if err := authorizeCustomPageReferences(ctx, r.Client, application.Namespace, account, authorization); err != nil {
			return nil, err
		}
	}

	ids := make([]string, 0, len(application.Spec.Application.CustomPageRefs))
	pageTypes := make(map[v1alpha1.AccessCustomPageType]string, len(application.Spec.Application.CustomPageRefs))
	for index, reference := range application.Spec.Application.CustomPageRefs {
		var page flarecloudflare.AccessCustomPage
		if reference.ExternalID != "" {
			observed, err := remote.GetAccessCustomPage(ctx, reference.ExternalID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("external Access custom page %q could not be resolved: %v", reference.ExternalID, err)}
			}
			page = observed
		} else {
			if reference.ObjectRef == nil {
				return nil, accessValidationError{reason: "Invalid", message: fmt.Sprintf("customPageRefs[%d] is empty", index)}
			}
			targetNamespace := reference.ObjectRef.Namespace
			if targetNamespace == "" {
				targetNamespace = application.Namespace
			}
			var object v1alpha1.AccessCustomPage
			key := types.NamespacedName{Namespace: targetNamespace, Name: reference.ObjectRef.Name}
			if err := r.Get(ctx, key, &object); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessCustomPage %s was not found", key)}
				}
				return nil, fmt.Errorf("get AccessCustomPage %s: %w", key, err)
			}
			if !object.DeletionTimestamp.IsZero() {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessCustomPage %s is deleting", key)}
			}
			if object.Spec.AccountRef.Name != account.Name {
				return nil, accessValidationError{reason: "RefNotPermitted", message: fmt.Sprintf("the AccessCustomPage %s uses CloudflareAccount %q, want %q", key, object.Spec.AccountRef.Name, account.Name)}
			}
			if object.Status.CustomPageID == "" || !metaConditionTrue(object.Status.Conditions, v1alpha1.AccessCustomPageConditionAccepted) {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessCustomPage %s is not accepted", key)}
			}
			observed, err := remote.GetAccessCustomPage(ctx, object.Status.CustomPageID)
			if err != nil {
				return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the AccessCustomPage %s remote page could not be resolved: %v", key, err)}
			}
			page = observed
		}
		if page.ID == "" {
			return nil, accessValidationError{reason: "TargetNotFound", message: fmt.Sprintf("the Access custom page reference %d resolved without an ID", index)}
		}
		if existing, found := pageTypes[page.Type]; found {
			return nil, accessValidationError{
				reason:  "Conflict",
				message: fmt.Sprintf("the Access custom pages %q and %q both have type %s", existing, page.ID, page.Type),
			}
		}
		pageTypes[page.Type] = page.ID
		ids = append(ids, page.ID)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

func authorizeCustomPageReferences(ctx context.Context, kube client.Client, namespaceName string, account *v1alpha1.CloudflareAccount, request authz.Request) error {
	var namespace corev1.Namespace
	if err := kube.Get(ctx, types.NamespacedName{Name: namespaceName}, &namespace); err != nil {
		return fmt.Errorf("get AccessApplication namespace %q: %w", namespaceName, err)
	}
	decision := authz.Evaluate(account, &namespace, request)
	if !decision.Allowed {
		return accessValidationError{reason: decision.Reason, message: decision.Message}
	}
	return nil
}

func hasAccessTag(tags []string, expected string) bool {
	return slices.Contains(tags, expected)
}

func accessBypassTag(ownerTag, childName string) string {
	return accessDigestTag(accessBypassTagPrefix, ownerTag+"\x00"+childName)
}

func accessDigestTag(prefix, identity string) string {
	digest := sha256.Sum256([]byte(identity))
	hexDigest := fmt.Sprintf("%x", digest)
	return prefix + hexDigest[:accessTagNameMaxLength-len(prefix)]
}

func validInternalDigestTag(tag, prefix string) bool {
	if len(tag) != accessTagNameMaxLength || !strings.HasPrefix(tag, prefix) {
		return false
	}
	for index := len(prefix); index < len(tag); index++ {
		if !strings.ContainsRune("0123456789abcdef", rune(tag[index])) {
			return false
		}
	}
	return true
}

func (r *AccessApplicationReconciler) accessIdentity(ctx context.Context, application *v1alpha1.AccessApplication) (string, string, error) {
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: "kube-system"}, &namespace); err != nil {
		return "", "", fmt.Errorf("get kube-system namespace: %w", err)
	}
	clusterID := string(namespace.UID)
	identity := flarecloudflare.OwnerTag(clusterID, application.Namespace, application.Name, application.UID)
	return accessDigestTag(accessOwnerTagPrefix, identity), clusterID, nil
}
