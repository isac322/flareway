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

// Package report writes small, secret-free end-to-end classification artifacts.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	// PrivateWARPPass is part of the Flareway API.
	PrivateWARPPass = "pass"
	// PrivateWARPBlockedPlan is part of the Flareway API.
	PrivateWARPBlockedPlan = "blocked: plan"
	// PrivateWARPBlockedRunner is part of the Flareway API.
	PrivateWARPBlockedRunner = "blocked: runner"
)

// PrivateWARPResult records whether the live private-hostname contract ran.
type PrivateWARPResult struct {
	Result                    string   `json:"result"`
	Reason                    string   `json:"reason,omitempty"`
	DNSAddresses              []string `json:"dnsAddresses,omitempty"`
	UnregisteredPathChecked   bool     `json:"unregisteredPathChecked"`
	UnregisteredPathReachable *bool    `json:"unregisteredPathReachable,omitempty"`
	RecordedAt                string   `json:"recordedAt"`
}

// WritePrivateWARP validates and writes one deterministic JSON artifact.
func WritePrivateWARP(path string, result PrivateWARPResult) error {
	switch result.Result {
	case PrivateWARPPass, PrivateWARPBlockedPlan, PrivateWARPBlockedRunner:
	default:
		return fmt.Errorf("unsupported private WARP result %q", result.Result)
	}
	if result.RecordedAt == "" {
		result.RecordedAt = time.Now().UTC().Format(time.RFC3339)
	}
	result.DNSAddresses = append([]string(nil), result.DNSAddresses...)
	sort.Strings(result.DNSAddresses)
	content, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode private WARP result: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create private WARP artifact directory: %w", err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o644); err != nil {
		return fmt.Errorf("write private WARP result: %w", err)
	}
	return nil
}
