//go:build exploratory

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

package exploratory

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	// traceSchemaVersion identifies the persisted trace artifact layout. Bump
	// it whenever the JSON shape changes so archived artifacts stay
	// interpretable.
	traceSchemaVersion = 1

	// traceArtifactDirEnv names the environment variable that selects the
	// directory receiving failure artifacts. When it is unset or empty the
	// recorder writes nothing anywhere.
	traceArtifactDirEnv = "FLAREWAY_EXPLORATORY_ARTIFACT_DIR"

	// traceProjectionPrefix marks every HMAC-SHA256 projected value in the
	// artifact so readers can distinguish projections from fixed enums.
	traceProjectionPrefix = "hmac256:"
)

// traceProjectionKey is a fixed, public, non-secret HMAC key. It exists only
// to make projections deterministic across runs and machines; it is not a
// credential and provides no confidentiality beyond one-way projection.
var traceProjectionKey = []byte("flareway-exploratory-trace-v1")

// traceArtifact is the sanitized, persistable record of one exploration run.
// It contains no raw object names, bodies, tokens, account IDs, hostnames, or
// remote IDs: every free-form name or value is an HMAC-SHA256 projection and
// the only verbatim strings are fixed enums owned by this package or by the
// public Kubernetes/Gateway API surface.
type traceArtifact struct {
	SchemaVersion int              `json:"schemaVersion"`
	Family        string           `json:"family"`
	Flags         traceFlags       `json:"flags"`
	Iterations    []traceIteration `json:"iterations"`
}

// traceFlags carries the reproduction parameters. failfile is reduced to its
// base name so local directory layouts never leak into a public artifact.
type traceFlags struct {
	Seed     string `json:"seed"`
	Failfile string `json:"failfile"`
	Checks   string `json:"checks"`
	Steps    string `json:"steps"`
}

// traceIteration is one exploration iteration: an ordered list of sanitized
// actions and the conditions observed while it ran.
type traceIteration struct {
	Index      int              `json:"index"`
	Actions    []traceAction    `json:"actions"`
	Conditions []traceCondition `json:"conditions"`
}

// traceAction is one recorded step. Action and outcome are HMAC-SHA256
// projections; remoteCalls is a count, never an identifier.
type traceAction struct {
	Action      string `json:"action"`
	Outcome     string `json:"outcome"`
	RemoteCalls int    `json:"remoteCalls"`
}

// traceCondition is one observed status condition. Status is a fixed enum
// (True/False/Unknown); kind, type, and reason are projections unless they
// are members of the fixed public enum allowlist.
type traceCondition struct {
	Kind   string `json:"kind"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// traceSecret is the artifact-safe projection of a Secret: existence plus
// key/value shape only. Key names and values are never recorded.
type traceSecret struct {
	Exists     bool `json:"exists"`
	KeyCount   int  `json:"keyCount"`
	TotalBytes int  `json:"totalBytes"`
}

// fixedEnumValues is the complete set of strings the artifact may store
// verbatim: condition statuses and the public kind/condition-type vocabulary
// of the Kubernetes, Gateway API, and Flareway APIs. Anything else is
// projected.
var fixedEnumValues = map[string]bool{
	// metav1.ConditionStatus.
	"True": true, "False": true, "Unknown": true,
	// Public kinds.
	"CloudflareAccount": true, "CloudflareTunnel": true, "Gateway": true,
	"GatewayClass": true, "HTTPRoute": true, "TCPRoute": true, "UDPRoute": true,
	"TLSRoute": true, "GRPCRoute": true, "Secret": true, "Service": true,
	"AccessApplication": true, "AccessStandaloneApplication": true,
	"AccessInfrastructureTarget": true, "AccessCustomPage": true,
	"AccessPolicy": true, "AccessGroup": true, "AccessRule": true,
	"IdentityProvider":  true,
	"DevicePostureRule": true, "DevicePostureIntegration": true,
	"ServiceToken": true, "VirtualNetwork": true, "NetworkRoute": true,
	"HostnameRoute": true, "WARPConnector": true, "DeviceProfile": true,
	"DeviceSettings": true, "ZeroTrustOrganization": true,
	"ZeroTrustGatewayPolicy": true, "ZeroTrustList": true,
	"GatewayClassConfig": true,
	// Public condition types.
	"Accepted": true, "Programmed": true, "ResolvedRefs": true,
	"Ready": true, "Available": true, "CredentialsValid": true,
}

// traceRecorder accumulates a sanitized trace of one exploration family and
// use.
type traceRecorder struct {
	t      *testing.T
	family string

	mu    sync.Mutex
	iters []traceIteration
	cur   int // index into iters of the open iteration, -1 when none
}

// newTraceRecorder creates a recorder for family and registers a cleanup that
// writes the trace artifact when the test fails and traceArtifactDirEnv names
// a directory. When the variable is unset or the test passes, nothing is
// written anywhere.
func newTraceRecorder(t *testing.T, family string) *traceRecorder {
	r := &traceRecorder{t: t, family: sanitizeFileComponent(family), cur: -1}
	t.Cleanup(func() {
		r.flushOnFailure(t.Failed(), t.Errorf)
	})
	return r
}

// BeginIteration closes the current iteration and opens the next one. Record
// and RecordCondition append to the open iteration; calling them without
// BeginIteration implicitly opens iteration 0.
func (r *traceRecorder) BeginIteration() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.iters = append(r.iters, traceIteration{Index: len(r.iters)})
	r.cur = len(r.iters) - 1
}

// Record appends one sanitized action to the open iteration. action and
// outcome are stored only as HMAC-SHA256 projections; remoteCalls is a count.
// The raw values go to the test log, which stays local, never to the
// artifact.
func (r *traceRecorder) Record(action, outcome string, remoteCalls int) {
	r.t.Logf("trace %s iter: action=%q outcome=%q remoteCalls=%d", r.family, action, outcome, remoteCalls)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.openLocked()
	r.iters[r.cur].Actions = append(r.iters[r.cur].Actions, traceAction{
		Action:      projectValue("action", action),
		Outcome:     projectValue("outcome", outcome),
		RemoteCalls: remoteCalls,
	})
}

// RecordCondition appends one observed condition to the open iteration.
// status is stored verbatim only when it is a fixed enum; kind,
// conditionType, and reason are stored verbatim only when they belong to the
// fixed public enum allowlist and are projected otherwise.
func (r *traceRecorder) RecordCondition(kind, conditionType, status, reason string) {
	r.t.Logf("trace %s iter: condition kind=%q type=%q status=%q reason=%q",
		r.family, kind, conditionType, status, reason)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.openLocked()
	r.iters[r.cur].Conditions = append(r.iters[r.cur].Conditions, traceCondition{
		Kind:   enumOrProjection("kind", kind),
		Type:   enumOrProjection("type", conditionType),
		Status: enumOrProjection("status", status),
		Reason: enumOrProjection("reason", reason),
	})
}

// RecordSecret appends an artifact-safe projection of a Secret-shaped value
// to the open iteration: existence, key count, and total key+value bytes
// only. Key names and values are never recorded.
func (r *traceRecorder) RecordSecret(data map[string][]byte) {
	projection := projectSecret(data)
	r.t.Logf("trace %s iter: secret exists=%t keyCount=%d totalBytes=%d",
		r.family, projection.Exists, projection.KeyCount, projection.TotalBytes)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.openLocked()
	r.iters[r.cur].Actions = append(r.iters[r.cur].Actions, traceAction{
		Action:  projectValue("action", "secret"),
		Outcome: fmt.Sprintf("keys=%d,bytes=%d", projection.KeyCount, projection.TotalBytes),
	})
}

// Snapshot returns a deep copy of the accumulated trace with the current
// reproduction flags embedded. It is safe to marshal while recording
// continues.
func (r *traceRecorder) Snapshot() traceArtifact {
	r.mu.Lock()
	defer r.mu.Unlock()
	iters := make([]traceIteration, len(r.iters))
	for i, iter := range r.iters {
		actions := make([]traceAction, len(iter.Actions))
		copy(actions, iter.Actions)
		conditions := make([]traceCondition, len(iter.Conditions))
		copy(conditions, iter.Conditions)
		iters[i] = traceIteration{Index: iter.Index, Actions: actions, Conditions: conditions}
	}
	return traceArtifact{
		SchemaVersion: traceSchemaVersion,
		Family:        artifactStem(r.family),
		Flags:         currentTraceFlags(),
		Iterations:    iters,
	}
}

// openLocked ensures an iteration is open; the caller must hold r.mu.
func (r *traceRecorder) openLocked() {
	if r.cur < 0 {
		r.iters = append(r.iters, traceIteration{Index: 0})
		r.cur = 0
	}
}

// flushResult reports what flushOnFailure did, so tests can assert the
// no-write guarantee without inspecting the filesystem.
type flushResult int

const (
	flushPassed       flushResult = iota // test passed; nothing attempted
	flushSkippedNoDir                    // artifact dir unset; nothing attempted
	flushWritten                         // artifact written
	flushFailed                          // write attempted and failed
)

// flushOnFailure persists the trace when failed is true and the artifact
// directory is configured. A write failure is reported through errorf so it
// adds to, and never replaces, the original test failure.
func (r *traceRecorder) flushOnFailure(failed bool, errorf func(string, ...any)) flushResult {
	if !failed {
		return flushPassed
	}
	dir := os.Getenv(traceArtifactDirEnv)
	if dir == "" {
		return flushSkippedNoDir
	}
	if err := writeTraceArtifact(dir, r.artifactFileName(), r.Snapshot()); err != nil {
		errorf("exploratory: writing trace artifact for family %q: %v", r.family, err)
		return flushFailed
	}
	return flushWritten
}

// artifactFileName is deterministic and date-free: the normalized family plus
// the seed projection, so rerunning the same seed overwrites the same file.
func (r *traceRecorder) artifactFileName() string {
	seed := flagValue("rapid.seed")
	return fmt.Sprintf("%s-%s.trace.json", artifactStem(r.family), projectHex("seed", seed))
}

func artifactStem(family string) string {
	var stem strings.Builder
	separator := false
	for _, char := range strings.ToLower(family) {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			if separator && stem.Len() > 0 {
				stem.WriteByte('-')
			}
			stem.WriteRune(char)
			separator = false
		default:
			separator = true
		}
	}
	if stem.Len() == 0 {
		return "exploration"
	}
	return stem.String()
}

// writeTraceArtifact serializes artifact to dir/name atomically: the JSON is
// written to a temporary file in the same directory, synced, and renamed over
// the destination so a crash never leaves a partial artifact.
func writeTraceArtifact(dir, name string, artifact traceArtifact) error {
	payload, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".trace-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// currentTraceFlags reads the reproduction flags. Missing flags record as
// empty strings; failfile is reduced to its base name.
func currentTraceFlags() traceFlags {
	return traceFlags{
		Seed:     flagValue("rapid.seed"),
		Failfile: filepath.Base(flagValue("rapid.failfile")),
		Checks:   flagValue("rapid.checks"),
		Steps:    flagValue("rapid.steps"),
	}
}

// flagValue returns the current value of the named flag, or "" when the flag
// is not registered.
func flagValue(name string) string {
	f := flag.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Value.String()
}

// projectValue returns the deterministic HMAC-SHA256 projection of value
// under the domain separator domain. The raw value is never recoverable from
// the projection.
func projectValue(domain, value string) string {
	return traceProjectionPrefix + projectHex(domain, value)
}

// projectHex returns the first 16 hex characters of HMAC-SHA256(domain|value).
func projectHex(domain, value string) string {
	mac := hmac.New(sha256.New, traceProjectionKey)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// enumOrProjection stores value verbatim when it is a member of the fixed
// public enum allowlist and projects it otherwise.
func enumOrProjection(domain, value string) string {
	if fixedEnumValues[value] {
		return value
	}
	return projectValue(domain, value)
}

// projectSecret reduces Secret data to existence, key count, and total
// key+value bytes.
func projectSecret(data map[string][]byte) traceSecret {
	projection := traceSecret{Exists: data != nil}
	for key, value := range data {
		projection.KeyCount++
		projection.TotalBytes += len(key) + len(value)
	}
	return projection
}

// sanitizeFileComponent reduces family to a filename-safe identifier:
// lowercase alphanumerics and single hyphens, so the artifact name is
// deterministic and cannot escape the artifact directory.
func sanitizeFileComponent(family string) string {
	var b strings.Builder
	b.Grow(len(family))
	lastDash := true // trims a leading hyphen
	for _, r := range strings.ToLower(family) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.TrimSuffix(b.String(), "-")
	if name == "" {
		return "exploration"
	}
	return name
}
