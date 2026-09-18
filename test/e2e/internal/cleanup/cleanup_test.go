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

package cleanup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// crdNames is the subset of a CustomResourceDefinition needed to enumerate
// the kinds the repository ships and the storage version discovery prefers.
type crdNames struct {
	Spec struct {
		Group string `json:"group"`
		Names struct {
			Kind   string `json:"kind"`
			Plural string `json:"plural"`
		} `json:"names"`
		Scope    string `json:"scope"`
		Versions []struct {
			Name    string `json:"name"`
			Storage bool   `json:"storage"`
		} `json:"versions"`
	} `json:"spec"`
}

// discoveredResources reads every Flareway CRD the chart and kustomize ship
// and returns the APIResourceList discovery would report for them. A new CRD
// therefore fails this test until it is placed in a tier.
func discoveredResources(t *testing.T) []*metav1.APIResourceList {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "config", "crd", "bases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read CRD directory: %v", err)
	}
	byGroupVersion := map[string][]metav1.APIResource{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var crd crdNames
		if err := yaml.Unmarshal(content, &crd); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		version := ""
		for _, candidate := range crd.Spec.Versions {
			if candidate.Storage {
				version = candidate.Name
			}
		}
		if version == "" {
			t.Fatalf("%s has no storage version", entry.Name())
		}
		gv := crd.Spec.Group + "/" + version
		byGroupVersion[gv] = append(byGroupVersion[gv], metav1.APIResource{
			Name:       crd.Spec.Names.Plural,
			Kind:       crd.Spec.Names.Kind,
			Namespaced: crd.Spec.Scope == "Namespaced",
			Verbs:      metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete"},
		})
	}
	lists := make([]*metav1.APIResourceList, 0, len(byGroupVersion))
	for gv, resources := range byGroupVersion {
		lists = append(lists, &metav1.APIResourceList{GroupVersion: gv, APIResources: resources})
	}
	return lists
}

// gatewayAPIResources mirrors the Gateway API v1.6.2 standard channel the e2e
// workflow installs. It is pinned to that release: update it when the
// installed channel changes.
func gatewayAPIResources() *metav1.APIResourceList {
	kinds := []struct {
		plural     string
		kind       string
		namespaced bool
	}{
		{"gatewayclasses", "GatewayClass", false},
		{"gateways", "Gateway", true},
		{"httproutes", "HTTPRoute", true},
		{"grpcroutes", "GRPCRoute", true},
		{"tlsroutes", "TLSRoute", true},
		{"tcproutes", "TCPRoute", true},
		{"udproutes", "UDPRoute", true},
		{"listenersets", "ListenerSet", true},
		{"referencegrants", "ReferenceGrant", true},
		{"backendtlspolicies", "BackendTLSPolicy", true},
	}
	resources := make([]metav1.APIResource, 0, len(kinds))
	for _, entry := range kinds {
		resources = append(resources, metav1.APIResource{
			Name:       entry.plural,
			Kind:       entry.kind,
			Namespaced: entry.namespaced,
			Verbs:      metav1.Verbs{"get", "list", "watch", "delete"},
		})
	}
	return &metav1.APIResourceList{
		GroupVersion: "gateway.networking.k8s.io/v1",
		APIResources: resources,
	}
}

func tierOf(t *testing.T, plan Plan, kind string) Tier {
	t.Helper()
	for tier, resources := range plan.Tiers {
		for _, resource := range resources {
			if resource.Kind == kind {
				return Tier(tier)
			}
		}
	}
	t.Fatalf("kind %s missing from plan", kind)
	return -1
}

func TestPlanTeardown(t *testing.T) {
	lists := append(discoveredResources(t), gatewayAPIResources())

	t.Run("drains dependents before dependencies", func(t *testing.T) {
		plan, err := PlanTeardown(lists)
		if err != nil {
			t.Fatalf("PlanTeardown: %v", err)
		}

		// The dependency contract: every earlier tier must drain before the
		// tier that holds what it references.
		if tierOf(t, plan, "AccessApplication") != TierApplications {
			t.Error("AccessApplication must drain first")
		}
		for _, kind := range []string{"Gateway", "HTTPRoute", "HostnameRoute", "NetworkRoute"} {
			if tierOf(t, plan, kind) != TierRoutesAndGateways {
				t.Errorf("%s must drain with routes and gateways", kind)
			}
		}
		for _, kind := range []string{"AccessPolicy", "AccessGroup", "VirtualNetwork", "ReferenceGrant", "BackendTLSPolicy"} {
			if tierOf(t, plan, kind) != TierShared {
				t.Errorf("%s must drain with shared policies and networks", kind)
			}
		}
		for _, kind := range []string{"ServiceToken", "IdentityProvider", "AccessCustomPage", "DevicePostureIntegration"} {
			if tierOf(t, plan, kind) != TierLeaves {
				t.Errorf("%s must drain with leaf resources", kind)
			}
		}
		for _, kind := range []string{"CloudflareTunnel", "WARPConnector"} {
			if tierOf(t, plan, kind) != TierTunnels {
				t.Errorf("%s must drain last while credentials remain", kind)
			}
		}
	})

	t.Run("fails on an unknown namespaced kind", func(t *testing.T) {
		unknown := append([]*metav1.APIResourceList{}, lists...)
		unknown = append(unknown, &metav1.APIResourceList{
			GroupVersion: "flareway.bhyoo.com/v1alpha1",
			APIResources: []metav1.APIResource{{
				Name:       "newwidgets",
				Kind:       "NewWidget",
				Namespaced: true,
				Verbs:      metav1.Verbs{"get", "list", "delete"},
			}},
		})
		if _, err := PlanTeardown(unknown); err == nil || !strings.Contains(err.Error(), "NewWidget") {
			t.Fatalf("PlanTeardown must fail loudly on an unknown kind, got %v", err)
		}
	})

	t.Run("fails on an unknown cluster-scoped kind", func(t *testing.T) {
		unknown := append([]*metav1.APIResourceList{}, lists...)
		unknown = append(unknown, &metav1.APIResourceList{
			GroupVersion: "flareway.bhyoo.com/v1alpha1",
			APIResources: []metav1.APIResource{{
				Name:  "clusterwidgets",
				Kind:  "ClusterWidget",
				Verbs: metav1.Verbs{"get", "list", "delete"},
			}},
		})
		if _, err := PlanTeardown(unknown); err == nil || !strings.Contains(err.Error(), "ClusterWidget") {
			t.Fatalf("PlanTeardown must fail loudly on an unknown cluster kind, got %v", err)
		}
	})

	t.Run("fails when a sentinel kind is not discovered", func(t *testing.T) {
		for _, missing := range []string{"CloudflareTunnel", "Gateway"} {
			var filtered []*metav1.APIResourceList
			for _, list := range lists {
				kept := &metav1.APIResourceList{GroupVersion: list.GroupVersion}
				for _, resource := range list.APIResources {
					if resource.Kind != missing {
						kept.APIResources = append(kept.APIResources, resource)
					}
				}
				filtered = append(filtered, kept)
			}
			_, err := PlanTeardown(filtered)
			if err == nil || !strings.Contains(err.Error(), "required kind") || !strings.Contains(err.Error(), missing) {
				t.Fatalf("PlanTeardown without %s must fail with a required-kind error, got %v", missing, err)
			}
		}
	})
}
