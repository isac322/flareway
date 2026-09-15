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

package server

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestAuthorizeCertificate(t *testing.T) {
	allowed, err := url.Parse("spiffe://flareway.bhyoo.com/ns/default/gateway/public")
	if err != nil {
		t.Fatal(err)
	}
	other, err := url.Parse("spiffe://flareway.bhyoo.com/ns/other/gateway/public")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		cert      *x509.Certificate
		cluster   string
		wantError bool
	}{
		{name: "matching URI", cert: &x509.Certificate{URIs: []*url.URL{allowed}}, cluster: "default/public"},
		{name: "unrelated URI", cert: &x509.Certificate{URIs: []*url.URL{other}}, cluster: "default/public", wantError: true},
		{name: "missing URI", cert: &x509.Certificate{}, cluster: "default/public", wantError: true},
		{name: "missing certificate", cluster: "default/public", wantError: true},
		{name: "malformed cluster", cert: &x509.Certificate{URIs: []*url.URL{allowed}}, cluster: "default/public/extra", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := AuthorizeCertificate(test.cert, test.cluster)
			if (err != nil) != test.wantError {
				t.Fatalf("AuthorizeCertificate() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
