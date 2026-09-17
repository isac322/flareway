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

// Package cleanup plans the e2e suite's reverse-dependency teardown. It is
// deliberately free of Ginkgo and e2e build tags so the dependency contract
// can be exercised by a plain unit test.
package cleanup

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/isac322/flareway/api/v1alpha1"
)

// Tier is a deletion stage. Tiers drain in ascending order so dependents are
// removed before the objects they reference while the CloudflareAccount and
// its credential Secret are still available.
type Tier int

const (
	// TierApplications removes Access applications first: their finalizers
	// delete remote bypass children and detach the policies they reference.
	TierApplications Tier = iota
	// TierRoutesAndGateways removes routes and Gateways. Deleting a Gateway
	// cascades to controller-created CloudflareTunnels, which drain in
	// TierTunnels.
	TierRoutesAndGateways
	// TierShared removes shared policies, groups, virtual networks, and
	// Gateway API policy/grant objects that applications and routes
	// reference.
	TierShared
	// TierLeaves removes leaf resources that shared objects reference:
	// service tokens, identity providers, custom pages, and posture
	// integrations.
	TierLeaves
	// TierTunnels removes remaining CloudflareTunnels and WARPConnectors
	// last: their finalizers need the CloudflareAccount and its API-token
	// Secret, which must outlive every namespaced dependent.
	TierTunnels
	// TierCount is the number of deletion stages.
	TierCount
)

// String names the stage for teardown error reporting.
func (t Tier) String() string {
	switch t {
	case TierApplications:
		return "applications"
	case TierRoutesAndGateways:
		return "routes and gateways"
	case TierShared:
		return "shared policies and networks"
	case TierLeaves:
		return "leaf resources"
	case TierTunnels:
		return "tunnels"
	default:
		return fmt.Sprintf("tier %d", int(t))
	}
}

// Resource pairs a kind with the preferred-version resource used to list and
// delete it.
type Resource struct {
	schema.GroupVersionResource
	Kind string
}

// Plan is the ordered teardown for one run namespace.
type Plan struct {
	// Tiers[i] holds the namespaced resources to delete and drain at stage i.
	Tiers [TierCount][]Resource
}

var (
	gatewayGroup = schema.GroupKind{Group: gatewayv1.GroupName}
	flarewayGK   = func(kind string) schema.GroupKind {
		return schema.GroupKind{Group: v1alpha1.Group, Kind: kind}
	}
	gatewayGK = func(kind string) schema.GroupKind {
		return schema.GroupKind{Group: gatewayv1.GroupName, Kind: kind}
	}
)

// namespacedTierByKind is the explicit dependency contract. Every namespaced
// kind served by the Flareway or Gateway API groups must appear here; an
// unmapped discovered kind fails planning loudly.
var namespacedTierByKind = map[schema.GroupKind]Tier{
	// Applications own remote Access children and reference policies.
	flarewayGK("AccessApplication"):           TierApplications,
	flarewayGK("AccessStandaloneApplication"): TierApplications,

	// Routes attach to Gateways; Flareway routes reference tunnels and
	// virtual networks. Gateways own managed CloudflareTunnels.
	gatewayGK("Gateway"):        TierRoutesAndGateways,
	gatewayGK("HTTPRoute"):      TierRoutesAndGateways,
	gatewayGK("GRPCRoute"):      TierRoutesAndGateways,
	gatewayGK("TLSRoute"):       TierRoutesAndGateways,
	gatewayGK("TCPRoute"):       TierRoutesAndGateways,
	gatewayGK("UDPRoute"):       TierRoutesAndGateways,
	gatewayGK("ListenerSet"):    TierRoutesAndGateways,
	flarewayGK("HostnameRoute"): TierRoutesAndGateways,
	flarewayGK("NetworkRoute"):  TierRoutesAndGateways,

	// Shared objects referenced by applications and routes.
	flarewayGK("AccessPolicy"):               TierShared,
	flarewayGK("AccessGroup"):                TierShared,
	flarewayGK("VirtualNetwork"):             TierShared,
	flarewayGK("AccessInfrastructureTarget"): TierShared,
	flarewayGK("DeviceProfile"):              TierShared,
	flarewayGK("DevicePostureRule"):          TierShared,
	flarewayGK("DeviceSettings"):             TierShared,
	flarewayGK("ZeroTrustGatewayPolicy"):     TierShared,
	flarewayGK("ZeroTrustList"):              TierShared,
	flarewayGK("ZeroTrustOrganization"):      TierShared,
	gatewayGK("ReferenceGrant"):              TierShared,
	gatewayGK("BackendTLSPolicy"):            TierShared,

	// Leaves referenced by shared objects.
	flarewayGK("ServiceToken"):             TierLeaves,
	flarewayGK("IdentityProvider"):         TierLeaves,
	flarewayGK("AccessCustomPage"):         TierLeaves,
	flarewayGK("DevicePostureIntegration"): TierLeaves,

	// Tunnel finalizers need the account and its credential Secret.
	flarewayGK("CloudflareTunnel"): TierTunnels,
	flarewayGK("WARPConnector"):    TierTunnels,
}

// clusterKinds is the complete set of cluster-scoped kinds the suite owns.
var clusterKinds = map[schema.GroupKind]struct{}{
	flarewayGK("CloudflareAccount"):  {},
	flarewayGK("GatewayClassConfig"): {},
	gatewayGK("GatewayClass"):        {},
}

// RelevantGroup reports whether group is one the suite must tear down.
func RelevantGroup(group string) bool {
	return group == v1alpha1.Group || group == gatewayGroup.Group
}

// PlanTeardown buckets discovered resources into deletion tiers. lists are
// preferred-version APIResourceLists (for example from
// DiscoveryClient.ServerPreferredResources). Any namespaced or cluster-scoped
// kind in a relevant group that is not explicitly tiered is an error: a newly
// introduced kind must be placed deliberately, never skipped.
func PlanTeardown(lists []*metav1.APIResourceList) (Plan, error) {
	var plan Plan
	seen := map[schema.GroupVersionResource]struct{}{}
	var problems []string

	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			problems = append(problems, fmt.Sprintf("unparseable groupVersion %q", list.GroupVersion))
			continue
		}
		if !RelevantGroup(gv.Group) {
			continue
		}
		for _, resource := range list.APIResources {
			if strings.Contains(resource.Name, "/") {
				continue // subresource
			}
			gk := schema.GroupKind{Group: gv.Group, Kind: resource.Kind}
			if !resource.Namespaced {
				if _, known := clusterKinds[gk]; !known {
					problems = append(problems, fmt.Sprintf("unknown cluster-scoped kind %s", gk))
				}
				continue
			}
			tier, known := namespacedTierByKind[gk]
			if !known {
				problems = append(problems, fmt.Sprintf("unknown namespaced kind %s", gk))
				continue
			}
			for _, verb := range []string{"list", "delete"} {
				if !supportsVerb(resource.Verbs, verb) {
					problems = append(problems, fmt.Sprintf("%s does not support %q", gk, verb))
				}
			}
			gvr := gv.WithResource(resource.Name)
			if _, dup := seen[gvr]; dup {
				continue
			}
			seen[gvr] = struct{}{}
			plan.Tiers[tier] = append(plan.Tiers[tier], Resource{GroupVersionResource: gvr, Kind: resource.Kind})
		}
	}

	// Completeness guard: without these sentinels the drain cannot converge
	// and deleting the namespace would wedge tunnel finalizers.
	for _, sentinel := range []schema.GroupKind{flarewayGK("CloudflareTunnel"), gatewayGK("Gateway")} {
		found := false
		for _, resources := range plan.Tiers {
			for _, resource := range resources {
				if resource.Group == sentinel.Group && resource.Kind == sentinel.Kind {
					found = true
				}
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("required kind %s not discovered", sentinel))
		}
	}

	if len(problems) != 0 {
		sort.Strings(problems)
		return Plan{}, fmt.Errorf("e2e teardown cannot plan discovered resources: %s", strings.Join(problems, "; "))
	}
	return plan, nil
}

func supportsVerb(verbs metav1.Verbs, verb string) bool {
	for _, candidate := range verbs {
		if candidate == verb {
			return true
		}
	}
	return false
}
