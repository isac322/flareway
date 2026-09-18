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

package cfstub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestResetIterationClearsRuntimeStateAndKeepsIDsMonotonic(t *testing.T) {
	server := New(t)
	server.State.AddZone(Zone{ID: "zone-1", Name: "example.com", AccountID: "account-1"})
	server.Fault(http.MethodGet, `^/user/tokens/verify$`, Fault{Status: http.StatusTooManyRequests})
	server.State.Set("key", "value")
	var first Tunnel
	requestResult(t, server, http.MethodPost, "/accounts/account-1/cfd_tunnel", map[string]any{
		"name": "first", "config_src": "cloudflare",
	}, &first)

	faulted := request(t, server, http.MethodGet, "/user/tokens/verify", nil)
	if err := faulted.Body.Close(); err != nil {
		t.Errorf("close faulted response: %v", err)
	}
	if faulted.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("faulted verify returned %d", faulted.StatusCode)
	}
	unregistered := request(t, server, http.MethodGet, "/does/not/exist", nil)
	if err := unregistered.Body.Close(); err != nil {
		t.Errorf("close unregistered response: %v", err)
	}
	if len(server.Journal()) != 3 || len(server.Violations()) != 1 {
		t.Fatalf("journal=%d violations=%d before reset", len(server.Journal()), len(server.Violations()))
	}

	server.ResetIteration()

	if got := server.Journal(); len(got) != 0 {
		t.Fatalf("journal after reset = %#v", got)
	}
	if got := server.Violations(); len(got) != 0 {
		t.Fatalf("violations after reset = %#v", got)
	}
	if got := server.State.Tunnels("account-1"); len(got) != 0 {
		t.Fatalf("tunnels after reset = %#v", got)
	}
	if got := server.State.DNSRecords("zone-1"); len(got) != 0 {
		t.Fatalf("zones after reset = %#v", got)
	}
	if value, ok := server.State.Get("key"); ok {
		t.Fatalf("generic value after reset = %#v", value)
	}

	// The server and its routes survive the reset, and the consumed fault is
	// cleared with the rest of the iteration runtime.
	var verified TokenVerification
	requestResult(t, server, http.MethodGet, "/user/tokens/verify", nil, &verified)
	if verified.Status != "active" {
		t.Fatalf("token status after reset = %q", verified.Status)
	}

	var second Tunnel
	requestResult(t, server, http.MethodPost, "/accounts/account-1/cfd_tunnel", map[string]any{
		"name": "second", "config_src": "cloudflare",
	}, &second)
	if second.ID <= first.ID {
		t.Fatalf("tunnel IDs not monotonic across reset: %q then %q", first.ID, second.ID)
	}
}

func TestUnregisteredEndpointRecordedAsViolation(t *testing.T) {
	server := New(t)

	response := request(t, server, http.MethodGet, "/client/v4/not/registered?token=abc123", nil)
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response: %v", err)
		}
	}()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("unregistered endpoint returned %d", response.StatusCode)
	}

	violations := server.Violations()
	if len(violations) != 1 {
		t.Fatalf("violations = %#v", violations)
	}
	violation := violations[0]
	if violation.Method != http.MethodGet || violation.Reason != "unregistered endpoint" {
		t.Fatalf("violation = %#v", violation)
	}
	if !strings.Contains(violation.Path, "/client/v4/not/registered") {
		t.Fatalf("violation path = %q", violation.Path)
	}
	if violation.At.IsZero() {
		t.Fatal("violation timestamp is zero")
	}

	// The violation is acknowledged so the cleanup assertion stays green.
	server.ResetIteration()
}

func TestCleanupAssertionFailsOnRecordedViolations(t *testing.T) {
	fake := &stubTB{}
	server := New(fake)

	response, err := http.Get(server.URL + "/unregistered")
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Errorf("close response: %v", err)
	}

	for _, cleanup := range fake.cleanups {
		cleanup()
	}
	if len(fake.errors) == 0 {
		t.Fatal("cleanup did not fail on a recorded violation")
	}
	if !strings.Contains(fake.errors[0], "unregistered endpoint") {
		t.Fatalf("cleanup error = %q", fake.errors[0])
	}
}

func TestPublicJournalMasksNonAllowlistedSegments(t *testing.T) {
	server := New(t)

	zones := request(t, server, http.MethodGet, "/client/v4/zones?name=secret-zone.example.com", nil)
	if err := zones.Body.Close(); err != nil {
		t.Errorf("close zones response: %v", err)
	}
	hostname := request(t, server, http.MethodGet,
		"/accounts/account-secret/zerotrust/routes/hostname/private-tenant.example.com", nil)
	if err := hostname.Body.Close(); err != nil {
		t.Errorf("close hostname response: %v", err)
	}
	unknown := request(t, server, http.MethodGet, "/totally/unknown/path", nil)
	if err := unknown.Body.Close(); err != nil {
		t.Errorf("close unknown response: %v", err)
	}

	want := []PublicCall{
		{Method: http.MethodGet, Path: "/zones"},
		{Method: http.MethodGet, Path: "/accounts/{id}/zerotrust/routes/hostname/{id}"},
		{Method: http.MethodGet, Path: "/{id}/{id}/{id}"},
	}
	if got := server.PublicJournal(); !reflect.DeepEqual(got, want) {
		t.Fatalf("public journal = %#v, want %#v", got, want)
	}

	encoded, err := json.Marshal(server.PublicJournal())
	if err != nil {
		t.Fatalf("marshal public journal: %v", err)
	}
	for _, leaked := range []string{"account-secret", "private-tenant.example.com", "secret-zone.example.com", "unknown"} {
		if bytes.Contains(encoded, []byte(leaked)) {
			t.Fatalf("public journal leaked %q: %s", leaked, encoded)
		}
	}

	// The unregistered call recorded a violation; acknowledge it.
	server.ResetIteration()
}

func TestFaultAttemptsCountsHTTPAttempts(t *testing.T) {
	if got := (Fault{}).Attempts(); got != 1 {
		t.Fatalf("zero Times attempts = %d, want 1", got)
	}
	if got := (Fault{Times: 3}).Attempts(); got != 3 {
		t.Fatalf("Times=3 attempts = %d, want 3", got)
	}
	if got := (Fault{Times: -1}).Attempts(); got != -1 {
		t.Fatalf("Times=-1 attempts = %d, want -1", got)
	}

	server := New(t)
	server.Fault(http.MethodGet, `^/user/tokens/verify$`, Fault{Status: http.StatusTooManyRequests, Times: 2})

	for attempt := 1; attempt <= 2; attempt++ {
		response := request(t, server, http.MethodGet, "/user/tokens/verify", nil)
		if err := response.Body.Close(); err != nil {
			t.Errorf("close attempt %d response: %v", attempt, err)
		}
		if response.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("attempt %d returned %d, want 429", attempt, response.StatusCode)
		}
	}

	var verified TokenVerification
	requestResult(t, server, http.MethodGet, "/user/tokens/verify", nil, &verified)
	if verified.Status != "active" {
		t.Fatalf("token status after two attempts = %q", verified.Status)
	}
}

// stubTB is a minimal testing.TB used to observe cleanup behavior without
// failing the real test.
type stubTB struct {
	testing.TB

	cleanups []func()
	errors   []string
}

func (s *stubTB) Helper() {}

func (s *stubTB) Cleanup(cleanup func()) {
	s.cleanups = append(s.cleanups, cleanup)
}

func (s *stubTB) Errorf(format string, args ...any) {
	s.errors = append(s.errors, fmt.Sprintf(format, args...))
}
