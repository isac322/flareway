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

package sweep

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/freshness"
)

// Access ownership tag markers, mirroring internal/controller's
// accessapplication_tags.go. They are replicated here because the sweep
// package must not import the controller package (the controllers will
// import this package for Events()).
const (
	accessManagedTag      = "flareway-managed"
	accessOwnerTagPrefix  = flarecloudflare.AccessOwnerTagPrefix
	accessBypassTagPrefix = flarecloudflare.AccessBypassTagPrefix
)

// defaultTargets registers every sweepable kind. Kinds without a
// list-capable remote API are documented in the package doc instead.
//
// Grades are not chosen here. They come from freshness.GradeForKind so the
// sweep period and the reconciler gate TTL for a kind can never disagree: a
// sweep slower than its gate would let the operator claim a drift-detection
// bound it does not actually honour. A kind missing from that table is a
// programming error and panics at startup rather than silently sweeping on
// some invented period.
func defaultTargets() []TargetDescriptor {
	specs := []struct {
		kind  string
		sweep func(ctx context.Context, runner *AccountSweeper) ([]DriftItem, error)
	}{
		{"AccessApplication", sweepAccessApplications},
		{"AccessStandaloneApplication", sweepAccessStandaloneApplications},
		{"AccessPolicy", sweepAccessPolicies},
		{"AccessGroup", sweepAccessGroups},
		{"ServiceToken", sweepServiceTokens},
		{"IdentityProvider", sweepIdentityProviders},
		{"AccessCustomPage", sweepAccessCustomPages},
		{"AccessInfrastructureTarget", sweepAccessInfrastructureTargets},
		{"DNSRecord", sweepDNSRecords},
		{"CloudflareTunnel", sweepCloudflareTunnels},
		{"ZeroTrustGatewayPolicy", sweepZeroTrustGatewayPolicies},
		{"ZeroTrustList", sweepZeroTrustLists},
		{"VirtualNetwork", sweepVirtualNetworks},
		{"NetworkRoute", sweepNetworkRoutes},
		{"HostnameRoute", sweepHostnameRoutes},
		{"DeviceProfile", sweepDeviceProfiles},
		{"DevicePostureRule", sweepDevicePostureRules},
		{"DevicePostureIntegration", sweepDevicePostureIntegrations},
		{"WARPConnector", sweepWARPConnectors},
	}
	targets := make([]TargetDescriptor, 0, len(specs))
	for _, spec := range specs {
		grade, found := freshness.GradeForKind(spec.kind)
		if !found {
			panic("sweep: no canonical freshness grade for kind " + spec.kind)
		}
		targets = append(targets, TargetDescriptor{Kind: spec.kind, Grade: grade, SweepFunc: spec.sweep})
	}
	return targets
}

// accountScopeListed reports whether the account-scope listing happened;
// every zone-scoped kind lists account scope unconditionally, so refs with
// an empty scope are always covered.
func accountScopeListed(ref localRef) bool {
	return ref.scope == ""
}

// scopeListed returns a predicate over the scopes that were listed.
func scopeListed(listed map[string]bool) func(localRef) bool {
	return func(ref localRef) bool {
		return listed[ref.scope]
	}
}

// accessDigestTag reproduces the controller's legacy plaintext digest tag:
// prefix plus a truncated sha256 hex of the identity.
func accessDigestTag(prefix, identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return prefix + fmt.Sprintf("%x", digest)[:flarecloudflare.AccessTagNameMaxLength-len(prefix)]
}

// accessOwnerMarkers returns every owner tag a reader must accept for one
// AccessApplication: the legacy plaintext digest and the HMAC marker.
func accessOwnerMarkers(key []byte, clusterID, namespace, name string, uid types.UID) []string {
	identity := flarecloudflare.OwnerTag(clusterID, namespace, name, uid)
	legacy := accessDigestTag(accessOwnerTagPrefix, identity)
	signed := flarecloudflare.SignAccessOwnerTag(key, clusterID, namespace, name, uid)
	if signed == legacy {
		return []string{legacy}
	}
	return []string{legacy, signed}
}

// hasAnyTag reports whether tags carries at least one expected marker.
func hasAnyTag(tags, expected []string) bool {
	for _, tag := range expected {
		if slices.Contains(tags, tag) {
			return true
		}
	}
	return false
}

// foreignOwnerTags returns owner-prefixed tags that are not among mine:
// evidence that another cluster (or a forger) claims the object.
func foreignOwnerTags(tags, mine []string) []string {
	var foreign []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, accessOwnerTagPrefix) && !slices.Contains(mine, tag) {
			foreign = append(foreign, tag)
		}
	}
	return foreign
}

// hasBypassTag reports whether the remote application is a bypass child.
// Bypass children share the parent's owner tag but are managed through the
// parent, so they are never orphan candidates.
func hasBypassTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, accessBypassTagPrefix) {
			return true
		}
	}
	return false
}

// observeOnly reports whether the object is observed without mutation. Such
// objects have no desired-hash gate to invalidate and their reconciler
// already observes the remote every pass, so the sweep skips them: judging
// a foreign-owned remote against generated names would only produce false
// mismatches the controller can never fix.
func observeOnly(policy v1alpha1.ManagementPolicy) bool {
	return policy == v1alpha1.ManagementPolicyObserveOnly
}

// deleting reports whether the object is being torn down; its remote
// object is the finalizer's job, not drift.
func deleting(object client.Object) bool {
	return !object.GetDeletionTimestamp().IsZero()
}
