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

package rbac

import (
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestM3ResourcesHaveLifecycleRBAC(t *testing.T) {
	role := readRole(t)
	for _, resource := range []string{
		"accessapplications",
		"accessgroups",
		"accesspolicies",
		"deviceposturerules",
		"identityproviders",
		"servicetokens",
	} {
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource,
			"create", "delete", "get", "list", "patch", "update", "watch")
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource+"/status",
			"get", "patch", "update")
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource+"/finalizers",
			"patch", "update")
	}
	assertRuleVerbs(t, role, "", "secrets",
		"create", "delete", "get", "list", "patch", "update", "watch")
}

func TestM4PrivateNetworkResourcesHaveLifecycleRBAC(t *testing.T) {
	role := readRole(t)
	for _, resource := range []string{"hostnameroutes", "networkroutes", "virtualnetworks"} {
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource,
			"create", "delete", "get", "list", "patch", "update", "watch")
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource+"/status",
			"get", "patch", "update")
		assertRuleVerbs(t, role, "flareway.bhyoo.com", resource+"/finalizers",
			"patch", "update")
	}
}

func readRole(t *testing.T) rbacv1.ClusterRole {
	t.Helper()
	content, err := os.ReadFile("role.yaml")
	if err != nil {
		t.Fatalf("read role.yaml: %v", err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(content, &role); err != nil {
		t.Fatalf("decode role.yaml: %v", err)
	}
	return role
}

func assertRuleVerbs(t *testing.T, role rbacv1.ClusterRole, group, resource string, expected ...string) {
	t.Helper()
	found := false
	for _, rule := range role.Rules {
		if !slices.Contains(rule.APIGroups, group) || !slices.Contains(rule.Resources, resource) {
			continue
		}
		found = true
		if len(rule.Verbs) != len(expected) {
			t.Errorf("%s/%s verbs = %v, want exactly %v", group, resource, rule.Verbs, expected)
			continue
		}
		for _, verb := range expected {
			if !slices.Contains(rule.Verbs, verb) {
				t.Errorf("%s/%s is missing %q; got %v", group, resource, verb, rule.Verbs)
			}
		}
	}
	if !found {
		t.Errorf("missing RBAC rule for %s/%s", group, resource)
	}
}
