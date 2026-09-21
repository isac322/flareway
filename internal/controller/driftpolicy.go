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

package controller

import "fmt"

// DriftPolicy controls how reconcilers react when remote Cloudflare state
// diverges from the state Flareway last applied out of band.
type DriftPolicy string

const (
	// DriftPolicyOverwrite restores the desired configuration over drifted
	// remote state. This is the default and preserves historical behavior.
	DriftPolicyOverwrite DriftPolicy = "Overwrite"

	// DriftPolicyHold skips the remote write when out-of-band drift is
	// detected, leaving the resource NotReady until an operator intervenes.
	DriftPolicyHold DriftPolicy = "Hold"
)

// ParseDriftPolicy validates a --drift-policy flag value. An empty value
// selects the default Overwrite policy; anything else unknown is an error so
// the manager refuses to start with a misspelled policy.
func ParseDriftPolicy(value string) (DriftPolicy, error) {
	switch DriftPolicy(value) {
	case "", DriftPolicyOverwrite:
		return DriftPolicyOverwrite, nil
	case DriftPolicyHold:
		return DriftPolicyHold, nil
	default:
		return "", fmt.Errorf("unknown drift policy %q: expected %q or %q", value, DriftPolicyOverwrite, DriftPolicyHold)
	}
}
