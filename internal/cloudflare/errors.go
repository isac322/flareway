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
	"net/http"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
)

// StatusCode returns the Cloudflare HTTP status wrapped by err.
func StatusCode(err error) (int, bool) {
	var apiError *cloudflaresdk.Error
	if !errors.As(err, &apiError) {
		return 0, false
	}
	return apiError.StatusCode, true
}

// IsNotFound reports whether err wraps a Cloudflare HTTP 404 response.
func IsNotFound(err error) bool {
	statusCode, ok := StatusCode(err)
	return ok && statusCode == http.StatusNotFound
}

// IsConflict reports whether err wraps a Cloudflare HTTP 409 response.
func IsConflict(err error) bool {
	statusCode, ok := StatusCode(err)
	return ok && statusCode == http.StatusConflict
}

// IsRateLimited reports whether err wraps a Cloudflare HTTP 429 response.
func IsRateLimited(err error) bool {
	statusCode, ok := StatusCode(err)
	return ok && statusCode == http.StatusTooManyRequests
}
