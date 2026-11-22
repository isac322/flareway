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

package dataplane

import "testing"

func TestEnvoyNodeID(t *testing.T) {
	if got := EnvoyNodeID("apps", "edge", "pod-uid-1"); got != "apps/edge/pod-uid-1" {
		t.Fatalf("EnvoyNodeID() = %q, want apps/edge/pod-uid-1", got)
	}
	for _, tc := range []struct {
		ns, gw, uid string
	}{
		{"", "edge", "uid"},
		{"apps", "", "uid"},
		{"apps", "edge", ""},
	} {
		if got := EnvoyNodeID(tc.ns, tc.gw, tc.uid); got != "" {
			t.Fatalf("EnvoyNodeID(%q, %q, %q) = %q, want empty", tc.ns, tc.gw, tc.uid, got)
		}
	}
}
