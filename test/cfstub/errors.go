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
	"encoding/json"
	"net/http"
)

// APIError is one error in a Cloudflare API error envelope.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorEnvelope matches Cloudflare API v4 error responses.
type ErrorEnvelope struct {
	Success bool       `json:"success"`
	Errors  []APIError `json:"errors"`
}

// WriteError writes a Cloudflare API v4 error envelope.
func WriteError(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{
		Success: false,
		Errors: []APIError{{
			Code:    code,
			Message: message,
		}},
	})
}
