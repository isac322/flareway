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

// Package ownership manages the cluster-local HMAC key that signs remote
// ownership markers (D8). The key lives in a controller-owned Secret in the
// operator namespace so markers cannot be forged from public identifiers.
package ownership

import (
	"context"
	"crypto/rand"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// SecretName is the Secret holding the cluster HMAC ownership key.
	SecretName = "flareway-ownership-key"
	// SecretKey is the data map key inside the Secret.
	SecretKey = "key"
	// KeyLengthBytes is the length of the 256-bit HMAC key.
	KeyLengthBytes = 32
)

// SecretKeyProvider loads or creates the cluster-local HMAC key backed by a
// Kubernetes Secret in the operator namespace.
type SecretKeyProvider struct {
	Client            client.Client
	OperatorNamespace string
}

// NewSecretKeyProvider returns a SecretKeyProvider reading the ownership key
// Secret from operatorNamespace.
func NewSecretKeyProvider(c client.Client, operatorNamespace string) *SecretKeyProvider {
	return &SecretKeyProvider{Client: c, OperatorNamespace: operatorNamespace}
}

// GetOrCreateKey returns the cluster HMAC key, creating the backing Secret
// with fresh randomness when absent. A Secret that exists but carries no key
// material is repaired in place. Concurrent creators converge through
// AlreadyExists plus a re-read, matching the EnsureCA convention.
func (p *SecretKeyProvider) GetOrCreateKey(ctx context.Context) ([]byte, error) {
	key := types.NamespacedName{Namespace: p.OperatorNamespace, Name: SecretName}
	current := &corev1.Secret{}
	if err := p.Client.Get(ctx, key, current); err == nil {
		if len(current.Data[SecretKey]) == KeyLengthBytes {
			return current.Data[SecretKey], nil
		}
		material, err := newKeyMaterial()
		if err != nil {
			return nil, err
		}
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		current.Data[SecretKey] = material
		if err := p.Client.Update(ctx, current); err != nil {
			return nil, fmt.Errorf("repair ownership key Secret %s: %w", key, err)
		}
		return material, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get ownership key Secret %s: %w", key, err)
	}

	material, err := newKeyMaterial()
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: p.OperatorNamespace, Name: SecretName},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{SecretKey: material},
	}
	if err := p.Client.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("create ownership key Secret %s: %w", key, err)
		}
		if err := p.Client.Get(ctx, key, current); err != nil {
			return nil, fmt.Errorf("get concurrently created ownership key Secret %s: %w", key, err)
		}
		if len(current.Data[SecretKey]) != KeyLengthBytes {
			return nil, fmt.Errorf("concurrently created ownership key Secret %s carries no valid key", key)
		}
		return current.Data[SecretKey], nil
	}
	return material, nil
}

func newKeyMaterial() ([]byte, error) {
	material := make([]byte, KeyLengthBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("generate ownership key: %w", err)
	}
	return material, nil
}
