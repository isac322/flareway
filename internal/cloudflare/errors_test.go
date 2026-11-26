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

package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
)

func sdkError(status int) error {
	return &cloudflaresdk.Error{
		StatusCode: status,
		Request:    httptest.NewRequest(http.MethodPost, "https://api.cloudflare.com/client/v4/test", nil),
		Response:   &http.Response{StatusCode: status},
	}
}

func TestIsDefiniteNonCreationClientError(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "non cloudflare error", err: errors.New("connection reset"), want: false},
		{name: "400 bad request", err: sdkError(http.StatusBadRequest), want: true},
		{name: "401 unauthorized", err: sdkError(http.StatusUnauthorized), want: true},
		{name: "403 forbidden", err: fmt.Errorf("wrapped: %w", sdkError(http.StatusForbidden)), want: true},
		{name: "404 not found", err: sdkError(http.StatusNotFound), want: true},
		{name: "422 unprocessable", err: sdkError(http.StatusUnprocessableEntity), want: true},
		{name: "408 timeout is ambiguous", err: sdkError(http.StatusRequestTimeout), want: false},
		{name: "409 conflict is ambiguous", err: sdkError(http.StatusConflict), want: false},
		{name: "429 rate limited is ambiguous", err: sdkError(http.StatusTooManyRequests), want: false},
		{name: "500 server error is ambiguous", err: sdkError(http.StatusInternalServerError), want: false},
		{name: "503 unavailable is ambiguous", err: sdkError(http.StatusServiceUnavailable), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsDefiniteNonCreationClientError(tc.err); got != tc.want {
				t.Fatalf("IsDefiniteNonCreationClientError(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestCreateServiceTokenNeverRetriesTransient5xx(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":500,"message":"internal error"}],"messages":[],"result":null}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":403,"message":"forbidden"}],"messages":[],"result":null}`))
	}))
	defer server.Close()

	client := New("token", "acct-1", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	_, err := client.CreateServiceToken(context.Background(), AccessScope{}, ServiceTokenInput{Name: "attempt-1", Enabled: true})
	if err == nil {
		t.Fatal("CreateServiceToken unexpectedly succeeded on HTTP 500")
	}
	if got, ok := StatusCode(err); !ok || got != http.StatusInternalServerError {
		t.Fatalf("StatusCode(err) = (%d, %t), want (%d, true) (err=%v)", got, ok, http.StatusInternalServerError, err)
	}
	if IsDefiniteNonCreationClientError(err) {
		t.Fatalf("HTTP 500 was misclassified as definite non-creation 4xx: %v", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("CreateServiceToken sent %d HTTP requests, want 1 (retries must be disabled on non-idempotent POST)", got)
	}
}
