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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
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
