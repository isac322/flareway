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
	"crypto/x509"
	"k8s.io/apimachinery/pkg/types"
	"testing"
	"time"
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
