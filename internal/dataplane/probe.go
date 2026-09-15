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

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

const (
	defaultProbeTimeout = 5 * time.Second
	maximumProbeTimeout = 10 * time.Second
	maximumConfigBody   = 64 << 10
)

// Prober reports the configuration version and readiness of a cloudflared
// process running in a dataplane Pod.
type Prober interface {
	ConfigVersion(ctx context.Context, podIP string) (int64, error)
	Ready(ctx context.Context, podIP string) error
}

// ProbeError describes a failed dataplane probe without including response
// bodies, which may contain sensitive configuration.
type ProbeError struct {
	Operation  string
	PodIP      string
	Endpoint   string
	StatusCode int
	Err        error
}

func (e *ProbeError) Error() string {
	switch {
	case e.Err != nil:
		return fmt.Sprintf("dataplane %s probe for Pod %q failed at %s: %v", e.Operation, e.PodIP, e.Endpoint, e.Err)
	case e.StatusCode != 0:
		return fmt.Sprintf("dataplane %s probe for Pod %q returned HTTP status %d at %s", e.Operation, e.PodIP, e.StatusCode, e.Endpoint)
	default:
		return fmt.Sprintf("dataplane %s probe for Pod %q failed at %s", e.Operation, e.PodIP, e.Endpoint)
	}
}

// Unwrap exposes the underlying transport or decoding error.
func (e *ProbeError) Unwrap() error {
	return e.Err
}

type httpProber struct {
	client *http.Client
}

// NewHTTPProber returns a production Prober. Non-positive timeouts use five
// seconds; larger values are capped at ten seconds so reconciliation cannot be
// held indefinitely by an unresponsive Pod.
func NewHTTPProber(timeout time.Duration) Prober {
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	if timeout > maximumProbeTimeout {
		timeout = maximumProbeTimeout
	}

	return &httpProber{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ConfigVersion returns the orchestration configuration version reported by
// cloudflared's /config endpoint.
func (p *httpProber) ConfigVersion(ctx context.Context, podIP string) (int64, error) {
	const operation = "config version"

	resp, endpoint, err := p.get(ctx, podIP, "/config", operation)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, StatusCode: resp.StatusCode}
	}

	var payload struct {
		Version *int64 `json:"version"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maximumConfigBody))
	if err := decoder.Decode(&payload); err != nil {
		return 0, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, Err: fmt.Errorf("decode JSON response: %w", err)}
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return 0, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, Err: err}
	}
	if payload.Version == nil {
		return 0, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, Err: errors.New("JSON response does not contain version")}
	}

	return *payload.Version, nil
}

// Ready succeeds only when cloudflared's /ready endpoint returns HTTP 200.
func (p *httpProber) Ready(ctx context.Context, podIP string) error {
	const operation = "readiness"

	resp, endpoint, err := p.get(ctx, podIP, "/ready", operation)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, StatusCode: resp.StatusCode}
	}

	return nil
}

func (p *httpProber) get(ctx context.Context, podIP, path, operation string) (*http.Response, string, error) {
	addr, err := netip.ParseAddr(podIP)
	if err != nil {
		return nil, path, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: path, Err: fmt.Errorf("parse Pod IP: %w", err)}
	}

	endpoint := (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(addr.String(), "2000"),
		Path:   path,
	}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, endpoint, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, Err: fmt.Errorf("create request: %w", err)}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, endpoint, &ProbeError{Operation: operation, PodIP: podIP, Endpoint: endpoint, Err: fmt.Errorf("send request: %w", err)}
	}
	return resp, endpoint, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return errors.New("response contains more than one JSON value")
}
