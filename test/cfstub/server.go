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

// Package cfstub provides a strict, stateful Cloudflare API test server.
package cfstub

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type route struct {
	method  string
	pattern *regexp.Regexp
	handler http.Handler
}

// Server is an isolated Cloudflare API stub owned by one test.
type Server struct {
	URL   string
	State *State

	t testing.TB

	server     *httptest.Server
	mu         sync.RWMutex
	routes     []route
	calls      []Call
	faults     []*faultRule
	violations []Violation
}

// New starts an isolated server and registers its cleanup with t. The cleanup
// fails the test when requests recorded contract violations such as calls to
// unregistered endpoints.
func New(t testing.TB) *Server {
	t.Helper()

	s := &Server{
		t:     t,
		State: NewState(),
	}
	s.registerCloudflareRoutes()
	s.registerAccessRoutes()
	s.registerPrivateNetworkRoutes()
	s.registerGlobalRoutes()
	s.server = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	s.URL = s.server.URL
	t.Cleanup(s.server.Close)
	t.Cleanup(func() { s.AssertNoViolations(t) })
	return s
}

// Handle registers an endpoint. Routes are matched in registration order.
func (s *Server) Handle(method, pathRegex string, handler http.HandlerFunc) {
	s.t.Helper()

	pattern, err := regexp.Compile(pathRegex)
	if err != nil {
		s.t.Fatalf("cfstub: compile route pattern %q: %v", pathRegex, err)
	}
	if handler == nil {
		s.t.Fatalf("cfstub: handler for %s %s is nil", method, pathRegex)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, route{
		method:  strings.ToUpper(method),
		pattern: pattern,
		handler: handler,
	})
}

// Violation records a request that broke the stub contract. Violations are
// collected instead of failing the owning test immediately so a caller can
// inspect or reset them between iterations; New registers a cleanup that
// fails the test when violations remain unacknowledged.
type Violation struct {
	Method string
	Path   string
	Reason string
	At     time.Time
}

// Violations returns a snapshot of recorded contract violations in arrival
// order.
func (s *Server) Violations() []Violation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	violations := make([]Violation, len(s.violations))
	copy(violations, s.violations)
	return violations
}

// AssertNoViolations fails t once per recorded contract violation. New
// registers it as a cleanup so unregistered endpoints still fail tests that
// never inspect Violations.
func (s *Server) AssertNoViolations(t testing.TB) {
	t.Helper()

	for _, violation := range s.Violations() {
		t.Errorf("cfstub: %s: %s %s", violation.Reason, violation.Method, violation.Path)
	}
}

// ResetIteration clears remote state, faults, the journal, and violations so
// the next exploration iteration starts clean while the server, its routes,
// and the remote ID counter keep running. IDs issued after a reset never
// collide with IDs issued before it.
func (s *Server) ResetIteration() {
	s.mu.Lock()
	s.calls = nil
	s.faults = nil
	s.violations = nil
	s.mu.Unlock()

	s.State.Reset()
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	call := captureCall(r)
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	if path == "" {
		path = "/"
	}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	route := s.matchRouteLocked(r.Method, path)
	var fault *Fault
	if route != nil {
		fault = s.takeFaultLocked(r.Method, path)
	} else {
		s.violations = append(s.violations, Violation{
			Method: call.Method, Path: call.Path, Reason: "unregistered endpoint", At: call.At,
		})
	}
	s.mu.Unlock()

	if fault != nil {
		fault.write(w, r)
		return
	}
	if route != nil {
		request := r.Clone(r.Context())
		request.URL.Path = path
		route.ServeHTTP(w, request)
		return
	}

	WriteError(w, http.StatusInternalServerError, 10000, fmt.Sprintf("unregistered endpoint %s %s", r.Method, r.URL.Path))
}

func (s *Server) matchRouteLocked(method, path string) http.Handler {
	method = strings.ToUpper(method)
	for _, candidate := range s.routes {
		if candidate.method == method && candidate.pattern.MatchString(path) {
			return candidate.handler
		}
	}
	return nil
}
