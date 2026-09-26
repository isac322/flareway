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
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/freshness"
)

// Invalidator is the path the sweep uses to close an object's desired-hash
// gate when drift is found (00-architecture.md §5 contract). The latch is the
// source of truth: even when the Events() wakeup is lost, the gate stays
// closed until the owning controller reconciles and clears it.
type Invalidator interface {
	Invalidate(kind string, key types.NamespacedName, reason string)
	IsInvalidated(kind string, key types.NamespacedName) bool
	Clear(kind string, key types.NamespacedName)
}

// ContentConfirmer is the optional path the sweep uses to check a listed
// remote object against the desired content its reconciler last verified
// (freshness.Latch implements it). ConfirmContent reports true when the
// listed object no longer matches; a match counts as a fresh verify of the
// object as of at, which must not be later than the start of the listing.
// An Invalidator that does not implement it gets identity-only checks.
type ContentConfirmer interface {
	ConfirmContent(kind string, key types.NamespacedName, observed any, at time.Time) bool
}

// DriftCase is the classified drift type for one remote/local pair.
type DriftCase string

const (
	// DriftCaseOrphan marks a remote object that carries our ownership marker
	// but has no matching Kubernetes object. Orphans are observe-only: the
	// sweep never deletes them (see package doc).
	DriftCaseOrphan DriftCase = "orphan"
	// DriftCaseMissing marks a Kubernetes object whose status records a remote
	// ID that no longer appears in the remote listing.
	DriftCaseMissing DriftCase = "missing"
	// DriftCaseMismatch marks a pair present on both sides whose compared
	// fields disagree.
	DriftCaseMismatch DriftCase = "mismatch"
)

// DriftItem is one classified drift result.
type DriftItem struct {
	// Kind is the metric label kind (flareway_drift_detected_total{kind}).
	Kind string
	// TargetKind is the Kubernetes kind whose gate is invalidated and whose
	// object is enqueued. It usually equals Kind; DNS record drift targets
	// the owning CloudflareTunnel instead.
	TargetKind string
	// NamespacedName identifies the target Kubernetes object. It may be the
	// zero value for unattributable orphans (HMAC markers do not encode the
	// owner identity).
	NamespacedName types.NamespacedName
	RemoteID       string
	Case           DriftCase
	Reason         string
}

// TargetDescriptor describes one sweepable resource kind: its freshness
// grade (which fixes the period) and the function that performs one pass.
type TargetDescriptor struct {
	// Kind is the metric label kind for this target's sweep passes.
	Kind string
	// Grade selects the period via freshness.Policy.TTL.
	Grade freshness.Grade
	// InitialDelay, when positive, overrides the randomized startup offset
	// drawn from [0, min(T, 60s)). It exists so tests can shorten the first
	// pass below the grade period (spec defect #10).
	InitialDelay time.Duration
	// SweepFunc performs one pass and returns the classified drift items.
	//
	// Result contract:
	//   - (items, nil) with items != nil: complete listing, judgement done.
	//   - (nil, nil): the listing could not be completed; judgement is
	//     abandoned for this pass (result=partial). Equivalent to returning
	//     an error wrapping errIncompleteListing.
	//   - (nil, err): definitive failure (result=error).
	//   - (items, err) where err is a *scopedListingError: scoped partial —
	//     some listing scopes failed but the returned items were judged only
	//     against completed scopes and are safe to dispatch (result=partial,
	//     non-nil aggregate error). Items returned with any other error are
	//     unsafe and are discarded.
	SweepFunc func(ctx context.Context, runner *AccountSweeper) ([]DriftItem, error)
}

// localRef is one Kubernetes object's claim on a remote object.
type localRef struct {
	// kind is the CR kind (invalidation target and default metric kind).
	kind string
	key  types.NamespacedName
	uid  types.UID
	// remoteID is the remote object ID recorded in status. Empty means the
	// object never converged; it still counts for orphan attribution.
	remoteID string
	// expectedName is the remote name the reconciler would write. Empty
	// disables the name comparison.
	expectedName string
	// specName is the spec-level name used inside generated remote names
	// (accessRemoteName embeds spec.name, not metadata.name).
	specName string
	// scope is the listing scope the remote object must appear in: "" for
	// account scope, otherwise the zone ID.
	scope string
}

// kindGVK maps invalidation target kinds to their API identity for the
// GenericEvent objects emitted on Events().
var kindGVK = map[string]schema.GroupVersionKind{
	"AccessApplication":           v1alpha1.GroupVersion.WithKind("AccessApplication"),
	"AccessStandaloneApplication": v1alpha1.GroupVersion.WithKind("AccessStandaloneApplication"),
	"AccessCustomPage":            v1alpha1.GroupVersion.WithKind("AccessCustomPage"),
	"AccessGroup":                 v1alpha1.GroupVersion.WithKind("AccessGroup"),
	"AccessInfrastructureTarget":  v1alpha1.GroupVersion.WithKind("AccessInfrastructureTarget"),
	"AccessPolicy":                v1alpha1.GroupVersion.WithKind("AccessPolicy"),
	"CloudflareTunnel":            v1alpha1.GroupVersion.WithKind("CloudflareTunnel"),
	"DevicePostureIntegration":    v1alpha1.GroupVersion.WithKind("DevicePostureIntegration"),
	"DevicePostureRule":           v1alpha1.GroupVersion.WithKind("DevicePostureRule"),
	"DeviceProfile":               v1alpha1.GroupVersion.WithKind("DeviceProfile"),
	"HostnameRoute":               v1alpha1.GroupVersion.WithKind("HostnameRoute"),
	"IdentityProvider":            v1alpha1.GroupVersion.WithKind("IdentityProvider"),
	"NetworkRoute":                v1alpha1.GroupVersion.WithKind("NetworkRoute"),
	"ServiceToken":                v1alpha1.GroupVersion.WithKind("ServiceToken"),
	"VirtualNetwork":              v1alpha1.GroupVersion.WithKind("VirtualNetwork"),
	"WARPConnector":               v1alpha1.GroupVersion.WithKind("WARPConnector"),
	"ZeroTrustGatewayPolicy":      v1alpha1.GroupVersion.WithKind("ZeroTrustGatewayPolicy"),
	"ZeroTrustList":               v1alpha1.GroupVersion.WithKind("ZeroTrustList"),
}
