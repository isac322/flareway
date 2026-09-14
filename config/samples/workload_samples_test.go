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

package samples

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestWorkloadSamplesContainCompleteMappings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path               string
		accessApplications int
		publicRules        []string
	}{
		{path: "workload_cc_lb.yaml", accessApplications: 1, publicRules: []string{"v1"}},
		{path: "workload_codex_lb.yaml", accessApplications: 2, publicRules: []string{"public-v1", "public-codex"}},
		{path: "workload_cliproxyapi.yaml", accessApplications: 2, publicRules: []string{"public-v1", "public-v1beta", "public-openai-v1", "public-codex"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			objects := decodeSample(t, tc.path)
			counts := map[string]int{}
			rules := map[string]bool{}
			for _, object := range objects {
				counts[object.GetKind()]++
				if object.GetKind() == "HTTPRoute" {
					collectNamedRules(t, object, rules)
				}
				if object.GetKind() == "AccessPolicy" || object.GetKind() == "IdentityProvider" {
					management, found, err := unstructured.NestedString(object.Object, "spec", "managementPolicy")
					if err != nil || !found || management != "ObserveOnly" {
						t.Fatalf("%s %s managementPolicy=%q found=%t err=%v", object.GetKind(), object.GetName(), management, found, err)
					}
					deletion, found, err := unstructured.NestedString(object.Object, "spec", "deletionPolicy")
					if err != nil || !found || deletion != "Orphan" {
						t.Fatalf("%s %s deletionPolicy=%q found=%t err=%v", object.GetKind(), object.GetName(), deletion, found, err)
					}
				}
			}

			for _, kind := range []string{"Namespace", "Secret", "CloudflareAccount", "CloudflareTunnel", "Service", "Gateway", "HTTPRoute", "IdentityProvider", "AccessPolicy", "AccessApplication"} {
				if counts[kind] == 0 {
					t.Errorf("missing %s", kind)
				}
			}
			if counts["AccessApplication"] != tc.accessApplications {
				t.Errorf("AccessApplication count=%d, want %d", counts["AccessApplication"], tc.accessApplications)
			}
			for _, rule := range tc.publicRules {
				if !rules[rule] {
					t.Errorf("missing public rule %q", rule)
				}
			}
		})
	}
}

func collectNamedRules(t *testing.T, route *unstructured.Unstructured, names map[string]bool) {
	t.Helper()
	rules, found, err := unstructured.NestedSlice(route.Object, "spec", "rules")
	if err != nil {
		t.Fatalf("HTTPRoute %s rules: %v", route.GetName(), err)
	}
	if !found {
		return
	}
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("HTTPRoute %s rule has type %T", route.GetName(), item)
		}
		name, _ := rule["name"].(string)
		if name != "" {
			names[name] = true
		}
	}
}
