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
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const redactedValue = "[REDACTED]"

var bearerPattern = regexp.MustCompile(`(?i)(bearer[[:space:]]+)[^[:space:]]+`)

// Call is a redacted record of one HTTP request received by the stub.
type Call struct {
	Method string
	Path   string
	Body   string
	At     time.Time
}

// Journal returns a snapshot of received calls in arrival order.
func (s *Server) Journal() []Call {
	s.mu.RLock()
	defer s.mu.RUnlock()

	calls := make([]Call, len(s.calls))
	copy(calls, s.calls)
	return calls
}

// PublicCall is the artifact-safe projection of a journaled call. It keeps
// only the method and the allowlisted route shape; account IDs, tokens,
// hostnames, and query values are replaced by placeholders so persisted
// artifacts never contain tenant-identifying raw values.
type PublicCall struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// PublicJournal returns the artifact projection of the journal in arrival
// order. Unlike Journal it never carries bodies or query strings, and every
// path segment outside the Cloudflare API literal allowlist is masked.
func (s *Server) PublicJournal() []PublicCall {
	calls := s.Journal()

	projected := make([]PublicCall, 0, len(calls))
	for _, call := range calls {
		projected = append(projected, PublicCall{Method: call.Method, Path: publicPath(call.Path)})
	}
	return projected
}

// publicPathSegments is the allowlist of literal Cloudflare API path segments
// that may appear in a public artifact. Every other segment is masked.
var publicPathSegments = map[string]bool{
	"access": true, "accounts": true, "apps": true, "cfd_tunnel": true,
	"configurations": true, "connections": true, "connectors": true,
	"devices": true, "dns_records": true, "exclude": true,
	"fallback_domains": true, "gateway": true, "groups": true, "hostname": true,
	"identity_providers": true, "include": true, "items": true, "lists": true,
	"management": true, "organizations": true, "policies": true, "policy": true,
	"posture": true, "refresh": true, "revoke_tokens": true, "rotate": true,
	"routes": true, "rules": true, "service_tokens": true, "settings": true,
	"tags": true, "teamnet": true, "token": true, "tokens": true, "user": true,
	"verify": true, "virtual_networks": true, "zerotrust": true, "zones": true,
}

func publicPath(path string) string {
	path = strings.TrimPrefix(path, "/client/v4")
	path, _, _ = strings.Cut(path, "?")

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != "" && !publicPathSegments[segment] {
			segments[i] = "{id}"
		}
	}
	projected := strings.Join(segments, "/")
	if projected == "" {
		return "/"
	}
	return projected
}

// AssertOrder verifies that each path regular expression appears after the
// previous expression. Calls between expected entries are allowed.
func (s *Server) AssertOrder(t testing.TB, pathRegex ...string) {
	t.Helper()

	patterns := make([]*regexp.Regexp, 0, len(pathRegex))
	for _, expression := range pathRegex {
		pattern, err := regexp.Compile(expression)
		if err != nil {
			t.Fatalf("cfstub: compile assertion pattern %q: %v", expression, err)
		}
		patterns = append(patterns, pattern)
	}

	calls := s.Journal()
	next := 0
	for _, call := range calls {
		if next < len(patterns) && patterns[next].MatchString(call.Path) {
			next++
		}
	}
	if next == len(patterns) {
		return
	}

	t.Fatalf("cfstub: expected path matching %q after position %d; calls were %s", pathRegex[next], next, formatCalls(calls))
}

func captureCall(r *http.Request) Call {
	body := ""
	if r.Body != nil {
		original := r.Body
		content, err := io.ReadAll(original)
		_ = original.Close()
		if err != nil {
			body = "[UNREADABLE BODY]"
		} else {
			r.Body = io.NopCloser(bytes.NewReader(content))
			body = redactBody(content, r.Header.Get("Content-Type"))
		}
	}

	return Call{
		Method: r.Method,
		Path:   redactRequestURI(r.URL),
		Body:   body,
		At:     time.Now().UTC(),
	}
}

func redactRequestURI(source *url.URL) string {
	values := source.Query()
	for key := range values {
		if sensitiveKey(key) {
			values[key] = []string{redactedValue}
		}
	}
	if encoded := values.Encode(); encoded != "" {
		return source.EscapedPath() + "?" + encoded
	}
	return source.EscapedPath()
}

func redactBody(content []byte, contentType string) string {
	if len(content) == 0 {
		return ""
	}

	mediaType := strings.ToLower(contentType)
	if strings.Contains(mediaType, "json") || json.Valid(content) {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err == nil {
			redactJSON(value)
			if redacted, err := json.Marshal(value); err == nil {
				return string(redacted)
			}
		}
		return "[REDACTED INVALID JSON BODY]"
	}

	if strings.Contains(mediaType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(content))
		if err != nil {
			return "[REDACTED INVALID FORM BODY]"
		}
		for key := range values {
			if sensitiveKey(key) {
				values[key] = []string{redactedValue}
			}
		}
		return values.Encode()
	}

	redacted := bearerPattern.ReplaceAllString(string(content), `${1}`+redactedValue)
	if redacted != string(content) {
		return redacted
	}
	return "[REDACTED BODY]"
}

func redactJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveKey(key) {
				typed[key] = redactedValue
				continue
			}
			redactJSON(child)
		}
	case []any:
		for _, child := range typed {
			redactJSON(child)
		}
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(key))
	for _, fragment := range []string{"token", "secret", "password", "authorization", "credential", "apikey"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func formatCalls(calls []Call) string {
	if len(calls) == 0 {
		return "(none)"
	}

	formatted := make([]string, 0, len(calls))
	for _, call := range calls {
		formatted = append(formatted, fmt.Sprintf("%s %s", call.Method, call.Path))
	}
	return strings.Join(formatted, ", ")
}
