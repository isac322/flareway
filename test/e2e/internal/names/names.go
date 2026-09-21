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

// Package names creates collision-resistant, janitor-recognizable e2e names.
package names

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// OwnerPrefix marks resources created by the e2e suite.
const OwnerPrefix = "flareway-e2e-"

// RunIDLength is the exact length of the hexadecimal run ID produced by
// NewRunID. Ownership markers always carry the run ID immediately after
// OwnerPrefix so janitor matching can distinguish runs exactly.
const RunIDLength = 8

// CreatedMarkerPrefix prefixes the RFC3339 creation timestamp embedded in a
// resource's description so stale sweeps can date resources whose API omits
// created_at, such as device profiles.
const CreatedMarkerPrefix = "flareway-e2e-at="

// NewRunID returns eight lowercase hexadecimal characters.
func NewRunID() (string, error) {
	var value [4]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

// Namespace returns the isolated namespace for a run.
func Namespace(runID string) string {
	return OwnerPrefix + runID
}

// Resource returns a globally recognizable remote resource name.
func Resource(runID, suffix string) string {
	return OwnerPrefix + runID + "-" + suffix
}

// Hostname returns a one-label hostname covered by Universal SSL.
func Hostname(runID string, ordinal int, zone string) string {
	return fmt.Sprintf("e2e-%s-%d.%s", runID, ordinal, strings.Trim(zone, "."))
}

// BackendCluster returns the xDS identity for a Kubernetes Service port.
// Kubernetes namespaces and Service names cannot contain '/' or ':'.
func BackendCluster(namespace, service string, port int32) string {
	return fmt.Sprintf("k8s://%s/%s:%d", namespace, service, port)
}

// BelongsToRun reports whether text carries this run's ownership marker.
func BelongsToRun(text, runID string) bool {
	return HasOwnerMarker(text, OwnerPrefix+runID)
}

// IsOwned reports whether text carries any Flareway e2e ownership marker.
func IsOwned(text string) bool {
	return HasOwnerMarker(text, OwnerPrefix)
}

// IsRunID reports whether value is exactly one lowercase hexadecimal run ID.
func IsRunID(value string) bool {
	if len(value) != RunIDLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !isHexDigit(value[i]) {
			return false
		}
	}
	return true
}

// HasOwnerMarker reports whether text carries the ownership prefix as a
// delimited token rather than a bare substring. The marker may start the text
// or follow a delimiter such as '/', '=', or whitespace, and must end at a
// non-name character or the end of the text. A '-' immediately before the
// marker does not count as a delimiter, so look-alike names such as
// "prod-flareway-e2e-<runid>" stay foreign. When prefix is the bare
// OwnerPrefix, the marker must continue with a complete run ID so global
// sweeps never match truncated or extended look-alikes.
func HasOwnerMarker(text, prefix string) bool {
	if prefix == "" {
		return false
	}
	lowered := strings.ToLower(text)
	prefix = strings.ToLower(prefix)
	offset := 0
	for {
		index := strings.Index(lowered[offset:], prefix)
		if index < 0 {
			return false
		}
		index += offset
		if markerStartsAtBoundary(lowered, index) && markerEndsAtBoundary(lowered, index, prefix) {
			return true
		}
		offset = index + 1
	}
}

func markerStartsAtBoundary(text string, index int) bool {
	return index == 0 || !isMarkerChar(text[index-1])
}

func markerEndsAtBoundary(text string, index int, prefix string) bool {
	end := index + len(prefix)
	if prefix == OwnerPrefix {
		if end+RunIDLength > len(text) || !IsRunID(text[end:end+RunIDLength]) {
			return false
		}
		end += RunIDLength
	}
	return end == len(text) || !isMarkerNameChar(text[end])
}

// isMarkerChar reports whether c may sit inside a resource name token. '-',
// '_', and '.' are excluded as leading delimiters so look-alike prefixes such
// as "prod-flareway-e2e-<runid>" or "ci_flareway-e2e-<runid>" stay foreign.
func isMarkerChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// isMarkerNameChar reports whether c extends the matched marker itself. '-'
// is a valid trailing delimiter because run-scoped names append "-<suffix>",
// while '_' and '.' extend foreign tokens such as "flareway-e2e-<id>_extra".
func isMarkerNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}
