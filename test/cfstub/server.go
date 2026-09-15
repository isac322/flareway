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

	server *httptest.Server
	mu     sync.RWMutex
	routes []route
	calls  []Call
	faults []*faultRule
}

// New starts an isolated server and registers its cleanup with t.
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

	s.t.Errorf("cfstub: unregistered endpoint %s %s", call.Method, call.Path)
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
