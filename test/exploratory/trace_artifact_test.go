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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestTraceArtifactOmitsSensitiveStrings marshals a snapshot seeded with
// tenant-identifying values and asserts none of them survive into the JSON.
// This is the guarantee that lets artifacts live in a public repository.
func TestTraceArtifactOmitsSensitiveStrings(t *testing.T) {
	sensitive := []string{
		"tenant-gateway-name",
		"acct_0123456789abcdef0123456789abcdef",
		"cf-api-token-s3cr3t",
		"tunnel.example.internal",
		"remote-id-9f8e7d6c5b",
		"supersecretvalue",
		"/home/alice/rapid-failures",
	}

	r := &traceRecorder{t: t, family: "gateway", cur: -1}
	r.BeginIteration()
	r.Record("create-"+sensitive[0], "ok-"+sensitive[2], 3)
	r.RecordCondition("kind-"+sensitive[1], "type-"+sensitive[3], "True", "reason-"+sensitive[4])
	r.RecordSecret(map[string][]byte{
		"token":     []byte(sensitive[2]),
		"ca.crt":    []byte(sensitive[5]),
		"hostname":  []byte(sensitive[3]),
		"accountID": []byte(sensitive[1]),
	})

	payload, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, value := range sensitive {
		if strings.Contains(string(payload), value) {
			t.Fatalf("artifact leaks sensitive value %q:\n%s", value, payload)
		}
	}
	// The failfile flag is unset in this test, so its base name must be "."
	// and no raw path may appear.
	if strings.Contains(string(payload), "/home/") {
		t.Fatalf("artifact leaks a local path:\n%s", payload)
	}
}

// TestTraceArtifactFixedEnumsStoredVerbatim confirms the fixed public enum
// vocabulary is stored verbatim so artifacts stay readable.
func TestTraceArtifactFixedEnumsStoredVerbatim(t *testing.T) {
	r := &traceRecorder{t: t, family: "access", cur: -1}
	r.BeginIteration()
	r.RecordCondition("Gateway", "Programmed", "False", "Pending")

	payload, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, want := range []string{`"Gateway"`, `"Programmed"`, `"False"`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("artifact missing fixed enum %s:\n%s", want, payload)
		}
	}
	// "Pending" is not in the allowlist and must be projected.
	if strings.Contains(string(payload), `"Pending"`) {
		t.Fatalf("non-enum reason stored verbatim:\n%s", payload)
	}
	if !strings.Contains(string(payload), traceProjectionPrefix) {
		t.Fatalf("artifact missing projected values:\n%s", payload)
	}
}

// TestTraceRecorderConcurrentRecord exercises Record, RecordCondition, and
// BeginIteration from many goroutines and asserts every record lands exactly
// once. Run with -race to prove the mutex discipline.
func TestTraceRecorderConcurrentRecord(t *testing.T) {
	const workers = 8
	const perWorker = 25

	r := &traceRecorder{t: t, family: "race", cur: -1}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			r.BeginIteration()
			for i := 0; i < perWorker; i++ {
				r.Record("act", "done", i)
				r.RecordCondition("Gateway", "Ready", "True", "Ready")
			}
		}(w)
	}
	wg.Wait()

	snapshot := r.Snapshot()
	actions, conditions := 0, 0
	for _, iter := range snapshot.Iterations {
		actions += len(iter.Actions)
		conditions += len(iter.Conditions)
	}
	if want := workers * perWorker; actions != want {
		t.Fatalf("recorded %d actions, want %d", actions, want)
	}
	if want := workers * perWorker; conditions != want {
		t.Fatalf("recorded %d conditions, want %d", conditions, want)
	}
}

// TestTraceFlushWritesNothingWithoutDir proves the no-artifact guarantee:
// with the directory variable unset, a failed run attempts no write and
// reports no error.
func TestTraceFlushWritesNothingWithoutDir(t *testing.T) {
	t.Setenv(traceArtifactDirEnv, "")

	r := &traceRecorder{t: t, family: "nodir", cur: -1}
	r.BeginIteration()
	r.Record("act", "done", 1)

	var errors []string
	result := r.flushOnFailure(true, func(format string, args ...any) {
		errors = append(errors, format)
	})
	if result != flushSkippedNoDir {
		t.Fatalf("flushOnFailure = %v, want flushSkippedNoDir", result)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected error reports: %v", errors)
	}
}

// TestTraceFlushWritesNothingOnPass proves a passing run never writes.
func TestTraceFlushWritesNothingOnPass(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(traceArtifactDirEnv, dir)

	r := &traceRecorder{t: t, family: "pass", cur: -1}
	r.BeginIteration()
	r.Record("act", "done", 1)

	var errors []string
	result := r.flushOnFailure(false, func(format string, args ...any) {
		errors = append(errors, format)
	})
	if result != flushPassed {
		t.Fatalf("flushOnFailure = %v, want flushPassed", result)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("passing run wrote %d artifact files", len(entries))
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected error reports: %v", errors)
	}
}

// TestTraceFlushWritesArtifactOnFailure proves a failed run writes one
// deterministic, valid artifact into the configured directory.
func TestTraceFlushWritesArtifactOnFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(traceArtifactDirEnv, dir)

	r := &traceRecorder{t: t, family: "Gateway Family", cur: -1}
	r.BeginIteration()
	r.Record("act", "done", 2)

	var errors []string
	result := r.flushOnFailure(true, func(format string, args ...any) {
		errors = append(errors, format)
	})
	if result != flushWritten {
		t.Fatalf("flushOnFailure = %v, want flushWritten", result)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected error reports: %v", errors)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("found %d artifact files, want 1", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "gateway-family-") || !strings.HasSuffix(name, ".trace.json") {
		t.Fatalf("unexpected artifact name %q", name)
	}
	payload, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var artifact traceArtifact
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatalf("artifact is not valid JSON: %v", err)
	}
	if artifact.SchemaVersion != traceSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", artifact.SchemaVersion, traceSchemaVersion)
	}
	if artifact.Family != "gateway-family" {
		t.Fatalf("family = %q, want %q", artifact.Family, "gateway-family")
	}
	if len(artifact.Iterations) != 1 || len(artifact.Iterations[0].Actions) != 1 {
		t.Fatalf("artifact lost the recorded iteration: %+v", artifact.Iterations)
	}
}

// TestTraceFlushFailureAddsError proves a failed artifact write surfaces
// through errorf instead of replacing the original test failure.
func TestTraceFlushFailureAddsError(t *testing.T) {
	// Point the artifact dir at a regular file so MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker: %v", err)
	}
	t.Setenv(traceArtifactDirEnv, blocker)

	r := &traceRecorder{t: t, family: "broken", cur: -1}
	r.BeginIteration()
	r.Record("act", "done", 1)

	var errors []string
	result := r.flushOnFailure(true, func(format string, args ...any) {
		errors = append(errors, format)
	})
	if result != flushFailed {
		t.Fatalf("flushOnFailure = %v, want flushFailed", result)
	}
	if len(errors) != 1 {
		t.Fatalf("got %d error reports, want 1", len(errors))
	}
}

// TestTraceArtifactFileNameDeterministic proves the artifact name depends
// only on family and seed, never on the clock.
func TestTraceArtifactFileNameDeterministic(t *testing.T) {
	r := &traceRecorder{t: t, family: "gw", cur: -1}
	first := r.artifactFileName()
	second := r.artifactFileName()
	if first != second {
		t.Fatalf("artifactFileName not deterministic: %q vs %q", first, second)
	}
	if strings.ContainsAny(first, "/\\:") {
		t.Fatalf("artifact name %q contains path separators", first)
	}
}
