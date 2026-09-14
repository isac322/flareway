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

// BelongsToRun reports whether text contains this run's ownership prefix.
func BelongsToRun(text, runID string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(OwnerPrefix+runID))
}

// IsOwned reports whether text carries any Flareway e2e ownership prefix.
func IsOwned(text string) bool {
	return strings.Contains(strings.ToLower(text), OwnerPrefix)
}
