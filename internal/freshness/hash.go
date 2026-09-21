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

package freshness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
)

// HashEnvelope is the canonical desired-hash input shape (D2): spec plus
// the identity fields that bind the desired state to one remote object.
// It contains no status, condition, resourceVersion, or timestamp field —
// adding one would make the hash vibrate and keep the gate closed forever.
type HashEnvelope struct {
	Spec      any       `json:"spec"`
	UID       types.UID `json:"uid"`
	RemoteID  string    `json:"remoteId,omitempty"`
	AccountID string    `json:"accountId,omitempty"`
	ClusterID string    `json:"clusterId,omitempty"`
}

// DesiredHash serializes input in normalized form and returns the SHA-256
// digest as a 64-character lowercase hex string.
//
// Normalization is provided by encoding/json: map keys are sorted and
// struct fields serialize in declaration order, so logically equal inputs
// always produce the same digest regardless of map insertion order. A nil
// input marshals to "null" and stays distinguishable from any non-nil
// value. Inputs that cannot be serialized (channels, funcs, cyclic values)
// return an error; callers must treat an error as a closed gate.
func DesiredHash(input any) (string, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshal desired-state input for hash: %w", err)
	}

	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
