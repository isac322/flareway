/*
Copyright 2026 The Flareway Authors.

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

package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestNeedsRotationAtTwoThirdsLifetime(t *testing.T) {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour)}

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "before threshold", now: notBefore.Add(60*24*time.Hour - time.Nanosecond), want: false},
		{name: "at threshold", now: notBefore.Add(60 * 24 * time.Hour), want: true},
		{name: "after threshold", now: notBefore.Add(89 * 24 * time.Hour), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NeedsRotation(cert, test.now); got != test.want {
				t.Fatalf("NeedsRotation() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNeedsRotationRejectsInvalidCertificate(t *testing.T) {
	if !NeedsRotation(nil, time.Now()) {
		t.Fatal("nil certificate must rotate")
	}
	if !NeedsRotation(&x509.Certificate{}, time.Now()) {
		t.Fatal("invalid lifetime must rotate")
	}
}

func TestClientLabelsHashLongGatewayKey(t *testing.T) {
	key := types.NamespacedName{
		Namespace: "gateway-conformance-infra",
		Name:      "unresolved-gateway-with-one-attached-unresolved-route",
	}
	value := clientLabels(key)["flareway.bhyoo.com/gateway"]
	if len(value) > 63 {
		t.Fatalf("label value length = %d, want at most 63: %q", len(value), value)
	}
	if value != "gateway-conformance-infra--unresolved-gateway-with-one-05be8fee" {
		t.Fatalf("label value = %q, want deterministic truncated hash", value)
	}
}

func TestEnsureClientCertCreatesSecretWithOwner(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	owner := testGatewayOwner(gwKey, "gateway-uid")
	kube := newTestClientWithCA(t)

	secret, err := EnsureClientCert(context.Background(), kube, gwKey, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{owner}) {
		t.Fatalf("OwnerReferences = %#v, want exact Gateway owner %#v", secret.OwnerReferences, owner)
	}
	cert, err := parseLeaf(secret.Data[corev1.TLSCertKey])
	if err != nil {
		t.Fatalf("parse created certificate: %v", err)
	}
	caSecret := &corev1.Secret{}
	if err := kube.Get(context.Background(), types.NamespacedName{Namespace: SystemNamespace, Name: CASecretName}, caSecret); err != nil {
		t.Fatal(err)
	}
	caCert, _, err := parseCA(caSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !clientSecretMatches(secret, cert, caCert, gwKey) {
		t.Fatal("created client Secret does not contain the expected certificate identity")
	}
}

func TestEnsureClientCertRejectsUnownedOrForeignSecretBeforeRotation(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	owner := testGatewayOwner(gwKey, "gateway-uid")
	tests := []struct {
		name   string
		owners []metav1.OwnerReference
	}{
		{name: "ownerless"},
		{name: "foreign owner", owners: []metav1.OwnerReference{testGatewayOwner(gwKey, "foreign-uid")}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collision := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       gwKey.Namespace,
					Name:            ClientSecretName(gwKey.Name),
					Labels:          map[string]string{"foreign": "keep"},
					Annotations:     map[string]string{"foreign": "keep"},
					OwnerReferences: test.owners,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foreign": []byte("keep"), corev1.TLSCertKey: []byte("invalid")},
			}
			kube := newTestClientWithCA(t, collision)
			before := &corev1.Secret{}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(collision), before); err != nil {
				t.Fatal(err)
			}

			_, err := EnsureClientCert(context.Background(), kube, gwKey, owner)
			if err == nil || !strings.Contains(err.Error(), "not controlled by expected Gateway") {
				t.Fatalf("EnsureClientCert() error = %v, want ownership rejection", err)
			}
			after := &corev1.Secret{}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(collision), after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("foreign Secret was modified: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestEnsureClientCertRotatesOwnedSecret(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	owner := testGatewayOwner(gwKey, "gateway-uid")
	kube := newTestClientWithCA(t)
	secret, err := EnsureClientCert(context.Background(), kube, gwKey, owner)
	if err != nil {
		t.Fatal(err)
	}
	secret.Type = corev1.SecretTypeOpaque
	secret.Data = map[string][]byte{
		corev1.TLSCertKey:       []byte("invalid"),
		corev1.TLSPrivateKeyKey: []byte("invalid"),
		"ca.crt":                []byte("invalid"),
	}
	secret.Labels = map[string]string{"stale": "label"}
	if err := kube.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}

	rotated, err := EnsureClientCert(context.Background(), kube, gwKey, owner)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Type != corev1.SecretTypeTLS {
		t.Fatalf("Secret type = %q, want %q", rotated.Type, corev1.SecretTypeTLS)
	}
	if !reflect.DeepEqual(rotated.OwnerReferences, []metav1.OwnerReference{owner}) {
		t.Fatalf("OwnerReferences = %#v, want exact Gateway owner %#v", rotated.OwnerReferences, owner)
	}
	if bytes.Equal(rotated.Data[corev1.TLSCertKey], []byte("invalid")) {
		t.Fatal("owned invalid certificate was not rotated")
	}
	cert, err := parseLeaf(rotated.Data[corev1.TLSCertKey])
	if err != nil {
		t.Fatalf("parse rotated certificate: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != SPIFFEURI(gwKey).String() {
		t.Fatalf("rotated certificate URIs = %v, want %s", cert.URIs, SPIFFEURI(gwKey))
	}
}

func TestEnsureClientCertDoesNotOverwriteOwnerChangedDuringRotation(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	owner := testGatewayOwner(gwKey, "gateway-uid")
	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       gwKey.Namespace,
			Name:            ClientSecretName(gwKey.Name),
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{corev1.TLSCertKey: []byte("invalid")},
	}
	base := newTestClientWithCA(t, owned)
	foreignOwner := testGatewayOwner(gwKey, "foreign-uid")
	kube := &ownerChangeOnUpdateClient{
		Client:       base,
		key:          client.ObjectKeyFromObject(owned),
		foreignOwner: foreignOwner,
	}

	if _, err := EnsureClientCert(context.Background(), kube, gwKey, owner); err == nil {
		t.Fatal("EnsureClientCert() succeeded after ownership changed during rotation")
	}
	preserved := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(owned), preserved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preserved.OwnerReferences, []metav1.OwnerReference{foreignOwner}) ||
		!reflect.DeepEqual(preserved.Data, map[string][]byte{"foreign": []byte("keep")}) {
		t.Fatalf("ownership race overwrote foreign Secret: %#v", preserved)
	}
}

func TestEnsureClientCertRejectsConcurrentForeignCreation(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	owner := testGatewayOwner(gwKey, "gateway-uid")
	collision := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       gwKey.Namespace,
			Name:            ClientSecretName(gwKey.Name),
			Labels:          map[string]string{"foreign": "keep"},
			OwnerReferences: []metav1.OwnerReference{testGatewayOwner(gwKey, "foreign-uid")},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"foreign": []byte("keep")},
	}
	base := newTestClientWithCA(t)
	kube := &createCollisionClient{Client: base, collision: collision}

	_, err := EnsureClientCert(context.Background(), kube, gwKey, owner)
	if err == nil || !strings.Contains(err.Error(), "not controlled by expected Gateway") {
		t.Fatalf("EnsureClientCert() error = %v, want concurrent ownership rejection", err)
	}
	preserved := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(collision), preserved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(preserved.Data, collision.Data) ||
		!reflect.DeepEqual(preserved.Labels, collision.Labels) ||
		!reflect.DeepEqual(preserved.OwnerReferences, collision.OwnerReferences) {
		t.Fatalf("concurrently created foreign Secret was modified: %#v", preserved)
	}
}

func newTestClientWithCA(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ca, err := newCASecret(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(append([]client.Object{ca}, objects...)...).
		Build()
}

func testGatewayOwner(gwKey types.NamespacedName, uid types.UID) metav1.OwnerReference {
	controller := true
	blockOwnerDeletion := true
	return metav1.OwnerReference{
		APIVersion:         gatewayv1.GroupVersion.String(),
		Kind:               "Gateway",
		Name:               gwKey.Name,
		UID:                uid,
		Controller:         &controller,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}
}

type createCollisionClient struct {
	client.Client
	collision *corev1.Secret
	created   bool
}

func (c *createCollisionClient) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	if !c.created && object.GetNamespace() == c.collision.Namespace && object.GetName() == c.collision.Name {
		c.created = true
		if err := c.Client.Create(ctx, c.collision.DeepCopy(), opts...); err != nil {
			return err
		}
		return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, object.GetName())
	}
	return c.Client.Create(ctx, object, opts...)
}

type ownerChangeOnUpdateClient struct {
	client.Client
	key          types.NamespacedName
	foreignOwner metav1.OwnerReference
	changed      bool
}

func (c *ownerChangeOnUpdateClient) Update(ctx context.Context, object client.Object, opts ...client.UpdateOption) error {
	if !c.changed && client.ObjectKeyFromObject(object) == c.key {
		c.changed = true
		current := &corev1.Secret{}
		if err := c.Get(ctx, c.key, current); err != nil {
			return err
		}
		current.OwnerReferences = []metav1.OwnerReference{c.foreignOwner}
		current.Type = corev1.SecretTypeOpaque
		current.Data = map[string][]byte{"foreign": []byte("keep")}
		if err := c.Client.Update(ctx, current, opts...); err != nil {
			return err
		}
		return apierrors.NewConflict(
			schema.GroupResource{Resource: "secrets"},
			object.GetName(),
			errors.New("owner changed during rotation"),
		)
	}
	return c.Client.Update(ctx, object, opts...)
}
