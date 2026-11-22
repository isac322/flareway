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
	"time"
)

func TestRenderIncludesDefaultHTTP2Keepalive(t *testing.T) {
	files, err := Render(Options{NodeCluster: "apps/edge"})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for _, want := range []string{
		"connection_keepalive:",
		"interval: 30s",
		"timeout: 5s",
		"connection_idle_interval: 30s",
	} {
		if !strings.Contains(files.BootstrapYAML, want) {
			t.Fatalf("BootstrapYAML missing %q:\n%s", want, files.BootstrapYAML)
		}
	}
}

func TestRenderFormatsAndValidatesKeepaliveDurations(t *testing.T) {
	files, err := Render(Options{
		NodeCluster:                     "apps/edge",
		KeepaliveInterval:               90 * time.Second,
		KeepaliveTimeout:                1500 * time.Millisecond,
		KeepaliveConnectionIdleInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for _, want := range []string{
		"interval: 90s",
		"timeout: 1.5s",
		"connection_idle_interval: 0.001s",
	} {
		if !strings.Contains(files.BootstrapYAML, want) {
			t.Fatalf("BootstrapYAML missing %q:\n%s", want, files.BootstrapYAML)
		}
	}
	if strings.Contains(files.BootstrapYAML, "e-") || strings.Contains(files.BootstrapYAML, "1m30s") {
		t.Fatalf("BootstrapYAML contains invalid protobuf Duration syntax:\n%s", files.BootstrapYAML)
	}

	invalidCases := []struct {
		name string
		opts Options
	}{
		{
			name: "sub-millisecond interval",
			opts: Options{NodeCluster: "apps/edge", KeepaliveInterval: 500 * time.Microsecond},
		},
		{
			name: "negative timeout",
			opts: Options{NodeCluster: "apps/edge", KeepaliveTimeout: -time.Second},
		},
		{
			name: "sub-millisecond idle interval",
			opts: Options{NodeCluster: "apps/edge", KeepaliveConnectionIdleInterval: time.Nanosecond},
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render(tc.opts); err == nil {
				t.Fatalf("Render(%+v) succeeded, want error", tc.opts)
			}
		})
	}
}
