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

package bootstrap

import (
	"strings"
	"testing"
)

func TestRenderDeltaMTLSBootstrap(t *testing.T) {
	files, err := Render(Options{NodeCluster: "default/gateway"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cluster: \"default/gateway\"",
		"api_type: DELTA_GRPC",
		"address: 127.0.0.1",
		"port_value: 19000",
		"address: 0.0.0.0",
		"port_value: 19001",
		"exact: \"/healthz\"",
		"path: /etc/flareway/xds/client-secret.yaml",
		"path: /etc/flareway/xds/ca-secret.yaml",
		"tls_minimum_protocol_version: TLSv1_3",
		"tls_maximum_protocol_version: TLSv1_3",
	} {
		if !strings.Contains(files.BootstrapYAML, want) {
			t.Fatalf("bootstrap does not contain %q", want)
		}
	}
	if !strings.Contains(files.ClientSecretYAML, "watched_directory: {path: /etc/flareway/xds}") {
		t.Fatal("client file-SDS resource does not watch the projected Secret directory")
	}
	if !strings.Contains(files.CASecretYAML, "watched_directory: {path: /etc/flareway/xds}") {
		t.Fatal("CA file-SDS resource does not watch the projected Secret directory")
	}
}
