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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
)

// classifyOptions parameterizes classify for one resource kind.
type classifyOptions[R any] struct {
	// kind is the metric label kind for items this classifier emits.
	kind string
	// idOf extracts the remote object ID.
	idOf func(R) string
	// listed reports whether ref.scope was covered by the remote listing.
	// Objects in unlisted scopes are skipped so a partial view can never
	// produce a false "missing" verdict.
	listed func(ref localRef) bool
	// nameOf extracts the remote name used for the expected-name check.
	nameOf func(R) string
	// nameEqual compares remote and expected names; nil means ==.
	nameEqual func(remote, expected string) bool
	// extra performs kind-specific content checks on a matched pair and
	// returns a mismatch reason, or "" when the pair agrees.
	extra func(ref localRef, remote R) string
	// orphan inspects one unclaimed remote object and reports whether it is
	// an orphan candidate plus the owning object's key when attributable.
	// claimed contains every remote ID referenced by a local status.
	orphan func(remote R, claimed map[string]bool) (types.NamespacedName, bool)
}

// classify compares one complete remote listing against the local refs and
// returns the drift items. It must only be called with a fully collected
// listing; callers convert listing failures into the partial result before
// reaching this function.
func classify[R any](refs []localRef, remotes []R, opts classifyOptions[R]) []DriftItem {
	items := make([]DriftItem, 0)
	remoteByID := make(map[string]R, len(remotes))
	for _, remote := range remotes {
		remoteByID[opts.idOf(remote)] = remote
	}
	claimed := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if ref.remoteID != "" {
			claimed[ref.remoteID] = true
		}
	}

	for _, ref := range refs {
		if ref.remoteID == "" || !opts.listed(ref) {
			continue
		}
		remote, found := remoteByID[ref.remoteID]
		if !found {
			items = append(items, DriftItem{
				Kind: opts.kind, TargetKind: ref.kind, NamespacedName: ref.key,
				RemoteID: ref.remoteID, Case: DriftCaseMissing,
				Reason: "remote object recorded in status is absent from the listing",
			})
			continue
		}
		if reason := matchReason(ref, remote, opts); reason != "" {
			items = append(items, DriftItem{
				Kind: opts.kind, TargetKind: ref.kind, NamespacedName: ref.key,
				RemoteID: ref.remoteID, Case: DriftCaseMismatch, Reason: reason,
			})
		}
	}

	if opts.orphan != nil {
		for _, remote := range remotes {
			id := opts.idOf(remote)
			if id == "" || claimed[id] {
				continue
			}
			if key, ok := opts.orphan(remote, claimed); ok {
				items = append(items, DriftItem{
					Kind: opts.kind, TargetKind: opts.kind, NamespacedName: key,
					RemoteID: id, Case: DriftCaseOrphan,
					Reason: "remote object carries a Flareway ownership marker but no matching Kubernetes object exists",
				})
			}
		}
	}
	return items
}

// matchReason reports why a matched pair disagrees, or "" when it agrees.
func matchReason[R any](ref localRef, remote R, opts classifyOptions[R]) string {
	if ref.expectedName != "" {
		equal := opts.nameEqual
		if equal == nil {
			equal = func(remote, expected string) bool { return remote == expected }
		}
		if !equal(opts.nameOf(remote), ref.expectedName) {
			return fmt.Sprintf("remote name %q does not match expected %q", opts.nameOf(remote), ref.expectedName)
		}
	}
	if opts.extra != nil {
		return opts.extra(ref, remote)
	}
	return ""
}

// accessRemoteNameValue reproduces the controller's accessRemoteName:
// "flareway/<clusterID>/<namespace>/<specName>".
func accessRemoteNameValue(clusterID, namespace, specName string) string {
	return "flareway/" + clusterID + "/" + namespace + "/" + specName
}

// parseAccessRemoteName splits a "flareway/<clusterID>/<ns>/<name>" remote
// name. The final segment may itself contain "/" (spec names are not
// Kubernetes names), so only the first three separators are structural.
func parseAccessRemoteName(name string) (clusterID, namespace, specName string, ok bool) {
	rest, found := strings.CutPrefix(name, "flareway/")
	if !found {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// parsePrivateOwnerComment splits a legacy private-resource ownership
// comment "flareway <clusterID>/<ns>/<name>[ | human comment]". Signed
// (hmac:) and truncated (sha256:) markers are not parseable and report
// ok=false so callers can fall back to per-object verification.
func parsePrivateOwnerComment(comment string) (clusterID, namespace, name string, ok bool) {
	owner, _, _ := strings.Cut(comment, " | ")
	rest, found := strings.CutPrefix(owner, "flareway ")
	if !found {
		return "", "", "", false
	}
	if strings.HasPrefix(rest, "hmac:") || strings.HasPrefix(rest, "sha256:") {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
