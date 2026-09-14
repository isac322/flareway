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
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Fault describes a deterministic response injected before a registered
// endpoint handler. Times defaults to one; a negative value repeats forever.
type Fault struct {
	Status     int
	Body       string
	Delay      time.Duration
	Times      int
	RetryAfter string
}

type faultRule struct {
	method    string
	pattern   *regexp.Regexp
	fault     Fault
	remaining int
}

// Fault injects a response for matching calls. Fault rules are considered in
// registration order.
func (s *Server) Fault(method, pathRegex string, fault Fault) {
	s.t.Helper()

	pattern, err := regexp.Compile(pathRegex)
	if err != nil {
		s.t.Fatalf("cfstub: compile fault pattern %q: %v", pathRegex, err)
	}
	if fault.Status == 0 {
		fault.Status = http.StatusInternalServerError
	}
	remaining := fault.Times
	if remaining == 0 {
		remaining = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &faultRule{
		method:    strings.ToUpper(method),
		pattern:   pattern,
		fault:     fault,
		remaining: remaining,
	})
}

func (s *Server) takeFaultLocked(method, path string) *Fault {
	method = strings.ToUpper(method)
	for _, candidate := range s.faults {
		if candidate.method != method || !candidate.pattern.MatchString(path) || candidate.remaining == 0 {
			continue
		}
		if candidate.remaining > 0 {
			candidate.remaining--
		}
		return new(candidate.fault)
	}
	return nil
}

func (f Fault) write(w http.ResponseWriter, r *http.Request) {
	if f.Delay > 0 {
		timer := time.NewTimer(f.Delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}

	if f.Status == http.StatusTooManyRequests {
		retryAfter := f.RetryAfter
		if retryAfter == "" {
			retryAfter = "1"
		}
		w.Header().Set("Retry-After", retryAfter)
	}
	if f.Body != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.Status)
		_, _ = w.Write([]byte(f.Body))
		return
	}
	WriteError(w, f.Status, 10000, http.StatusText(f.Status))
}
