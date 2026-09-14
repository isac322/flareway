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

// Package pki manages the private certificate authority and per-Gateway
// client certificates used by the xDS mTLS connection.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PKI defaults shared by certificate provisioning and consumers.
const (
	SystemNamespace = "flareway-system"
	CASecretName    = "flareway-xds-ca"

	clientCertificateLifetime = 90 * 24 * time.Hour
	caCertificateLifetime     = 10 * 365 * 24 * time.Hour
	certificateClockSkew      = 5 * time.Minute
)

var serverDNSNames = []string{
	"flareway-xds",
	"flareway-xds.flareway-system",
	"flareway-xds.flareway-system.svc",
	"flareway-xds.flareway-system.svc.cluster.local",
}

// EnsureCA returns the xDS CA Secret, creating it when absent. The Secret
// contains tls.crt and tls.key and is intentionally not owned by a transient
// controller object.
func EnsureCA(ctx context.Context, c client.Client) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: SystemNamespace, Name: CASecretName}
	current := &corev1.Secret{}
	if err := c.Get(ctx, key, current); err == nil {
		if _, _, err := parseCA(current); err != nil {
			return nil, fmt.Errorf("validate xDS CA Secret %s: %w", key, err)
		}
		return current, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get xDS CA Secret %s: %w", key, err)
	}

	secret, err := newCASecret(time.Now())
	if err != nil {
		return nil, err
	}
	if err := c.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("create xDS CA Secret %s: %w", key, err)
		}
		if err := c.Get(ctx, key, current); err != nil {
			return nil, fmt.Errorf("get concurrently created xDS CA Secret %s: %w", key, err)
		}
		if _, _, err := parseCA(current); err != nil {
			return nil, fmt.Errorf("validate concurrently created xDS CA Secret %s: %w", key, err)
		}
		return current, nil
	}
	return secret, nil
}

// EnsureClientCert returns a valid client certificate Secret for gwKey. An
// existing certificate is replaced after two thirds of its lifetime or when
// its key material or SPIFFE identity is invalid.
func EnsureClientCert(ctx context.Context, c client.Client, gwKey types.NamespacedName) (*corev1.Secret, error) {
	if gwKey.Namespace == "" || gwKey.Name == "" {
		return nil, errors.New("gateway namespace and name are required")
	}

	caSecret, err := EnsureCA(ctx, c)
	if err != nil {
		return nil, err
	}
	caCert, caKey, err := parseCA(caSecret)
	if err != nil {
		return nil, fmt.Errorf("parse xDS CA: %w", err)
	}

	key := types.NamespacedName{Namespace: gwKey.Namespace, Name: ClientSecretName(gwKey.Name)}
	current := &corev1.Secret{}
	now := time.Now()
	if err := c.Get(ctx, key, current); err == nil {
		if cert, certErr := parseLeaf(current.Data[corev1.TLSCertKey]); certErr == nil &&
			clientSecretMatches(current, cert, caCert, gwKey) && !NeedsRotation(cert, now) {
			return current, nil
		}
		data, dataErr := newClientData(caCert, caKey, gwKey, now)
		if dataErr != nil {
			return nil, dataErr
		}
		current.Type = corev1.SecretTypeTLS
		current.Data = data
		current.Labels = clientLabels(gwKey)
		if err := c.Update(ctx, current); err != nil {
			return nil, fmt.Errorf("rotate xDS client certificate Secret %s: %w", key, err)
		}
		return current, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get xDS client certificate Secret %s: %w", key, err)
	}

	data, err := newClientData(caCert, caKey, gwKey, now)
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwKey.Namespace,
			Name:      ClientSecretName(gwKey.Name),
			Labels:    clientLabels(gwKey),
		},
		Type: corev1.SecretTypeTLS,
		Data: data,
	}
	if err := c.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("create xDS client certificate Secret %s: %w", key, err)
		}
		if err := c.Get(ctx, key, current); err != nil {
			return nil, fmt.Errorf("get concurrently created xDS client certificate Secret %s: %w", key, err)
		}
		return current, nil
	}
	return secret, nil
}

// ClientSecretName returns the deterministic Secret name for a Gateway.
func ClientSecretName(gatewayName string) string {
	return "flareway-xds-" + gatewayName
}

// SPIFFEURI returns the sole URI SAN authorized for a Gateway xDS client.
func SPIFFEURI(gwKey types.NamespacedName) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   "flareway.bhyoo.com",
		Path:   "/ns/" + gwKey.Namespace + "/gateway/" + gwKey.Name,
	}
}

// NeedsRotation reports whether now is at or beyond two thirds of the
// certificate's validity interval. Invalid or nil certificates rotate.
func NeedsRotation(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || !cert.NotAfter.After(cert.NotBefore) {
		return true
	}
	rotationTime := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	return !now.Before(rotationTime)
}

// ServerTLSConfig creates an ephemeral server certificate signed by the xDS
// CA and returns a TLS configuration that requires a verified client
// certificate. The certificate covers every Kubernetes service DNS form used
// by Envoy.
func ServerTLSConfig(caSecret *corev1.Secret) (*tls.Config, error) {
	caCert, caKey, err := parseCA(caSecret)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate xDS server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverDNSNames[len(serverDNSNames)-1]},
		NotBefore:    now.Add(-certificateClockSkew),
		NotAfter:     minTime(now.Add(clientCertificateLifetime), caCert.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), serverDNSNames...),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign xDS server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("marshal xDS server key: %w", err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, fmt.Errorf("load xDS server key pair: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

func newCASecret(now time.Time) (*corev1.Secret, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate xDS CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flareway-xds-ca"},
		NotBefore:             now.Add(-certificateClockSkew),
		NotAfter:              now.Add(caCertificateLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create xDS CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal xDS CA key: %w", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: SystemNamespace, Name: CASecretName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		},
	}, nil
}

func newClientData(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, gwKey types.NamespacedName, now time.Time) (map[string][]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate xDS client key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: gwKey.String()},
		NotBefore:    now.Add(-certificateClockSkew),
		NotAfter:     minTime(now.Add(clientCertificateLifetime), caCert.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{SPIFFEURI(gwKey)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign xDS client certificate for %s: %w", gwKey, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal xDS client key for %s: %w", gwKey, err)
	}
	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"ca.crt":                append([]byte(nil), caSecretCertificatePEM(caCert)...),
	}, nil
}

func parseCA(secret *corev1.Secret) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if secret == nil {
		return nil, nil, errors.New("CA Secret is nil")
	}
	cert, err := parseLeaf(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, nil, fmt.Errorf("parse tls.crt: %w", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("tls.crt is not a certificate authority")
	}
	block, _ := pem.Decode(secret.Data[corev1.TLSPrivateKeyKey])
	if block == nil {
		return nil, nil, errors.New("tls.key does not contain PEM data")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS#8 tls.key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("tls.key is not an ECDSA P-256 key")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("tls.key does not match tls.crt")
	}
	return cert, key, nil
}

func parseLeaf(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate data does not contain a CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func clientSecretMatches(secret *corev1.Secret, cert, caCert *x509.Certificate, gwKey types.NamespacedName) bool {
	if secret.Type != corev1.SecretTypeTLS || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 || len(secret.Data["ca.crt"]) == 0 {
		return false
	}
	if _, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]); err != nil {
		return false
	}
	if cert.CheckSignatureFrom(caCert) != nil || string(secret.Data["ca.crt"]) != string(caSecretCertificatePEM(caCert)) {
		return false
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != SPIFFEURI(gwKey).String() {
		return false
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func clientLabels(gwKey types.NamespacedName) map[string]string {
	return map[string]string{"flareway.bhyoo.com/gateway": labelValue(gwKey.Namespace + "--" + gwKey.Name)}
}

func labelValue(value string) string {
	if len(value) <= 63 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	hash := hex.EncodeToString(digest[:4])
	keep := 63 - len(hash) - 1
	return strings.Trim(value[:keep], "-_.") + "-" + hash
}

func caSecretCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
