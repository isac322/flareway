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
		bypassPaths        []string
	}{
		{
			path:               "workload_application.yaml",
			accessApplications: 2,
			publicRules:        []string{"public-api", "public-health"},
			bypassPaths:        []string{"/api", "/health"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			objects := decodeSample(t, tc.path)
			counts := map[string]int{}
			rules := map[string]bool{}
			bypassPaths := map[string]bool{}
			for _, object := range objects {
				counts[object.GetKind()]++
				if object.GetKind() == "HTTPRoute" {
					collectNamedRules(t, object, rules)
				}
				if object.GetKind() == "AccessApplication" {
					assertApplicationVariant(t, object, map[string]string{"SelfHosted": "selfHosted"})
					collectBypassPaths(t, object, bypassPaths)
				}
				if object.GetKind() == "AccessPolicy" {
					decision, found, err := unstructured.NestedString(object.Object, "spec", "decision")
					if err != nil || !found || (decision != "Allow" && decision != "Deny") {
						t.Fatalf("AccessPolicy %s decision=%q found=%t err=%v", object.GetName(), decision, found, err)
					}
				}
				if object.GetKind() == "IdentityProvider" {
					typeName, found, err := unstructured.NestedString(object.Object, "spec", "type")
					if err != nil || !found || typeName != "Google" {
						t.Fatalf("IdentityProvider %s type=%q found=%t err=%v", object.GetName(), typeName, found, err)
					}
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
			for _, path := range tc.bypassPaths {
				if !bypassPaths[path] {
					t.Errorf("missing bypass declaration for %q", path)
				}
			}
		})
	}
}

func TestAccessSamplesCoverEveryApplicationType(t *testing.T) {
	t.Parallel()

	gatewayVariants := map[string]string{
		"SelfHosted":    "selfHosted",
		"SSH":           "ssh",
		"VNC":           "vnc",
		"RDP":           "rdp",
		"MCP":           "mcp",
		"ProxyEndpoint": "proxyEndpoint",
	}
	standaloneVariants := map[string]string{
		"SaaS":           "saas",
		"Bookmark":       "bookmark",
		"Infrastructure": "infrastructure",
		"AppLauncher":    "appLauncher",
		"WARP":           "warp",
		"BISO":           "biso",
		"DashSSO":        "dashSso",
		"MCPPortal":      "mcpPortal",
	}
	seen := map[string]bool{}
	for _, sample := range []struct {
		path     string
		kind     string
		variants map[string]string
	}{
		{path: "flareway_v1alpha1_accessapplication_variants.yaml", kind: "AccessApplication", variants: gatewayVariants},
		{path: "flareway_v1alpha1_accessstandaloneapplication.yaml", kind: "AccessStandaloneApplication", variants: standaloneVariants},
	} {
		for _, object := range decodeSample(t, sample.path) {
			if object.GetKind() != sample.kind {
				continue
			}
			typeName := assertApplicationVariant(t, object, sample.variants)
			seen[typeName] = true
		}
	}
	for typeName := range gatewayVariants {
		if !seen[typeName] {
			t.Errorf("missing AccessApplication type %s", typeName)
		}
	}
	for typeName := range standaloneVariants {
		if !seen[typeName] {
			t.Errorf("missing AccessStandaloneApplication type %s", typeName)
		}
	}
}

func TestAccessSamplesDemonstrateAdoptedBypassAndHostnameAudienceScope(t *testing.T) {
	t.Parallel()
	application := sampleByKindAndName(t, decodeSample(t, "flareway_v1alpha1_accessapplication_public_carveout.yaml"), "AccessApplication", "demo-dashboard")
	children, found, err := unstructured.NestedSlice(application.Object, "spec", "bypass", "children")
	if err != nil || !found || len(children) < 1 {
		t.Fatalf("public carve-out children=%#v found=%t err=%v", children, found, err)
	}
	adopted := children[0].(map[string]any)
	applicationID, found, err := unstructured.NestedString(adopted, "externalRef", "applicationId")
	if err != nil || !found || applicationID != "replace-with-existing-bypass-application-id" {
		t.Fatalf("adopted bypass applicationId=%q found=%t err=%v", applicationID, found, err)
	}
	mode, found, err := unstructured.NestedString(adopted, "adoption", "mode")
	if err != nil || !found || mode != "AdoptById" {
		t.Fatalf("adopted bypass mode=%q found=%t err=%v", mode, found, err)
	}

	variantObjects := decodeSample(t, "flareway_v1alpha1_accessapplication_variants.yaml")
	for _, name := range []string{"analytics-ui", "analytics-reports"} {
		application := sampleByKindAndName(t, variantObjects, "AccessApplication", name)
		scope, found, err := unstructured.NestedString(application.Object, "spec", "originJWT", "audienceScope")
		if err != nil || !found || scope != "Hostname" {
			t.Fatalf("AccessApplication %s audienceScope=%q found=%t err=%v", name, scope, found, err)
		}
		if _, found, err := unstructured.NestedMap(application.Object, "spec", "externalRef"); err != nil || found {
			t.Fatalf("AccessApplication %s must not embed an application ID; found=%t err=%v", name, found, err)
		}
	}
}

func TestNewAccessResourceSamplesContainRequiredFields(t *testing.T) {
	t.Parallel()

	page := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_accesscustompage.yaml"), "AccessCustomPage")
	assertAccountRef(t, page)
	for _, field := range []string{"name", "type", "html"} {
		if value, found, err := unstructured.NestedString(page.Object, "spec", field); err != nil || !found || value == "" {
			t.Errorf("AccessCustomPage spec.%s=%q found=%t err=%v", field, value, found, err)
		}
	}

	target := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_accessinfrastructuretarget.yaml"), "AccessInfrastructureTarget")
	assertAccountRef(t, target)
	if _, found, err := unstructured.NestedMap(target.Object, "spec", "ip", "ipv4"); err != nil || !found {
		t.Errorf("AccessInfrastructureTarget missing IPv4 address: found=%t err=%v", found, err)
	}
	if _, found, err := unstructured.NestedMap(target.Object, "spec", "ip", "ipv6"); err != nil || !found {
		t.Errorf("AccessInfrastructureTarget missing IPv6 address: found=%t err=%v", found, err)
	}

	integration := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_devicepostureintegration.yaml"), "DevicePostureIntegration")
	assertAccountRef(t, integration)
	if typeName, found, err := unstructured.NestedString(integration.Object, "spec", "type"); err != nil || !found || typeName != "CustomS2S" {
		t.Errorf("DevicePostureIntegration type=%q found=%t err=%v", typeName, found, err)
	}
	for _, field := range []string{"accessClientIdRef", "accessClientSecretRef"} {
		if _, found, err := unstructured.NestedMap(integration.Object, "spec", "config", field); err != nil || !found {
			t.Errorf("DevicePostureIntegration config.%s missing: found=%t err=%v", field, found, err)
		}
	}

	token := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_servicetoken.yaml"), "ServiceToken")
	if enabled, found, err := unstructured.NestedBool(token.Object, "spec", "enabled"); err != nil || !found || !enabled {
		t.Errorf("ServiceToken enabled=%t found=%t err=%v", enabled, found, err)
	}
}

func assertApplicationVariant(t *testing.T, object *unstructured.Unstructured, variants map[string]string) string {
	t.Helper()
	assertAccountRef(t, object)
	typeName, found, err := unstructured.NestedString(object.Object, "spec", "type")
	if err != nil || !found || typeName == "" {
		t.Fatalf("%s %s type=%q found=%t err=%v", object.GetKind(), object.GetName(), typeName, found, err)
	}
	variant, ok := variants[typeName]
	if !ok {
		t.Fatalf("%s %s has unexpected type %q", object.GetKind(), object.GetName(), typeName)
	}
	if _, found, err := unstructured.NestedMap(object.Object, "spec", variant); err != nil || !found {
		t.Fatalf("%s %s type %s missing spec.%s: found=%t err=%v", object.GetKind(), object.GetName(), typeName, variant, found, err)
	}
	return typeName
}

func assertAccountRef(t *testing.T, object *unstructured.Unstructured) {
	t.Helper()
	name, found, err := unstructured.NestedString(object.Object, "spec", "accountRef", "name")
	if err != nil || !found || name == "" {
		t.Fatalf("%s %s accountRef.name=%q found=%t err=%v", object.GetKind(), object.GetName(), name, found, err)
	}
}

func collectBypassPaths(t *testing.T, application *unstructured.Unstructured, paths map[string]bool) {
	t.Helper()
	children, found, err := unstructured.NestedSlice(application.Object, "spec", "bypass", "children")
	if err != nil {
		t.Fatalf("AccessApplication %s bypass children: %v", application.GetName(), err)
	}
	if !found {
		return
	}
	for _, item := range children {
		child, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("AccessApplication %s bypass child has type %T", application.GetName(), item)
		}
		path, _ := child["path"].(string)
		if path != "" {
			paths[path] = true
		}
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

func sampleByKindAndName(t *testing.T, objects []*unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	t.Helper()
	for _, object := range objects {
		if object.GetKind() == kind && object.GetName() == name {
			return object
		}
	}
	t.Fatalf("sample has no %s %s", kind, name)
	return nil
}
