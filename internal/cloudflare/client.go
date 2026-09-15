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

// Package cloudflare provides rate-limited, typed adapters around cloudflare-go.
package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"

	"github.com/isac322/flareway/internal/observability"
)

const (
	// DefaultRequestsPerSecond is part of the Flareway API.
	DefaultRequestsPerSecond = 3.5
	// DefaultRequestBurst is part of the Flareway API.
	DefaultRequestBurst = 10
	// GatewayListRequestsPerSecond is part of the Flareway API.
	GatewayListRequestsPerSecond = 8
	// GatewayListRequestBurst is part of the Flareway API.
	GatewayListRequestBurst = 20
	// DefaultMaxRetries is part of the Flareway API.
	DefaultMaxRetries = 3
)

// API is the complete Cloudflare surface used by reconcilers.
type API interface {
	AccountAPI
	TunnelAPI
	TunnelAdministrationAPI
	DNSAPI
	WARPConnectorAPI
	AccessAPI
	NetworkAPI
	DeviceAPI
	OrganizationAPI
	GatewayAPI
}

// ClientFactory creates account-scoped clients without retaining API tokens.
type ClientFactory interface {
	Client(token, accountID string) API
}

// AccountClientFactory is the narrow factory surface used by the account reconciler.
type AccountClientFactory interface {
	AccountClient(token, accountID string) AccountAPI
}

// ClientOption configures the production Cloudflare client adapter.
type ClientOption func(*clientOptions)

type clientOptions struct {
	requestOptions []option.RequestOption
	limiter        *rate.Limiter
	locks          *tunnelLockSet
	listLimiter    *rate.Limiter
}

// WithBaseURL points the SDK at a trusted alternate API endpoint, primarily cfstub.
func WithBaseURL(baseURL string) ClientOption {
	return func(options *clientOptions) {
		options.requestOptions = append(options.requestOptions, option.WithBaseURL(baseURL))
	}
}

// WithRequestOptions appends low-level cloudflare-go request options.
func WithRequestOptions(requestOptions ...option.RequestOption) ClientOption {
	return func(options *clientOptions) {
		options.requestOptions = append(options.requestOptions, requestOptions...)
	}
}

// WithLimiter supplies a limiter, primarily for deterministic unit tests.
func WithLimiter(limiter *rate.Limiter) ClientOption {
	return func(options *clientOptions) {
		options.limiter = limiter
	}
}

// WithListLimiter supplies the dedicated Gateway Lists limiter.
func WithListLimiter(limiter *rate.Limiter) ClientOption {
	return func(options *clientOptions) {
		options.listLimiter = limiter
	}
}

// Client is an account-scoped, rate-limited Cloudflare API adapter.
type Client struct {
	sdk         *cloudflaresdk.Client
	accountID   string
	limiter     *rate.Limiter
	locks       *tunnelLockSet
	listLimiter *rate.Limiter
}

// DefaultFactory shares rate limiters and tunnel locks across clients for an account.
type DefaultFactory struct {
	logger logr.Logger
	opts   []ClientOption

	mu           sync.Mutex
	limiters     map[string]*rate.Limiter
	listLimiters map[string]*rate.Limiter
	locks        *tunnelLockSet
}

// NewFactory returns the production client factory.
func NewFactory(logger logr.Logger, opts ...ClientOption) *DefaultFactory {
	return &DefaultFactory{
		logger:       logger,
		opts:         append([]ClientOption(nil), opts...),
		limiters:     make(map[string]*rate.Limiter),
		listLimiters: make(map[string]*rate.Limiter),
		locks:        newTunnelLockSet(),
	}
}

// AccountClient creates the read-only account verification surface.
func (factory *DefaultFactory) AccountClient(token, accountID string) AccountAPI {
	return factory.Client(token, accountID)
}

// Client creates an SDK adapter using the supplied token while reusing the account limiter.
func (factory *DefaultFactory) Client(token, accountID string) API {
	factory.mu.Lock()
	limiter := factory.limiters[accountID]
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Limit(DefaultRequestsPerSecond), DefaultRequestBurst)
		factory.limiters[accountID] = limiter
	}
	listLimiter := factory.listLimiters[accountID]
	if listLimiter == nil {
		listLimiter = rate.NewLimiter(rate.Limit(GatewayListRequestsPerSecond), GatewayListRequestBurst)
		factory.listLimiters[accountID] = listLimiter
	}
	factory.mu.Unlock()

	opts := append([]ClientOption(nil), factory.opts...)
	opts = append(opts, WithLimiter(limiter), WithListLimiter(listLimiter), func(options *clientOptions) { options.locks = factory.locks })
	return New(token, accountID, factory.logger, opts...)
}

// New constructs an account-scoped Cloudflare client. Tokens are passed only to
// cloudflare-go and are never stored in logs or returned by this package.
func New(token, accountID string, logger logr.Logger, opts ...ClientOption) *Client {
	options := clientOptions{
		limiter:     rate.NewLimiter(rate.Limit(DefaultRequestsPerSecond), DefaultRequestBurst),
		listLimiter: rate.NewLimiter(rate.Limit(GatewayListRequestsPerSecond), GatewayListRequestBurst),
		locks:       newTunnelLockSet(),
	}
	for _, apply := range opts {
		apply(&options)
	}

	requestOptions := []option.RequestOption{
		option.WithAPIToken(token),
		option.WithMaxRetries(DefaultMaxRetries),
		option.WithMiddleware(rateLimitMiddleware(options.limiter), loggingMiddleware(logger)),
	}
	requestOptions = append(requestOptions, options.requestOptions...)

	return &Client{
		sdk:         cloudflaresdk.NewClient(requestOptions...),
		accountID:   accountID,
		limiter:     options.limiter,
		listLimiter: options.listLimiter,
		locks:       options.locks,
	}
}

func rateLimitMiddleware(limiter *rate.Limiter) option.Middleware {
	return func(request *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		if err := limiter.Wait(request.Context()); err != nil {
			return nil, fmt.Errorf("wait for Cloudflare API rate limit: %w", err)
		}
		return next(request)
	}
}

func loggingMiddleware(logger logr.Logger) option.Middleware {
	return func(request *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		response, err := next(request)
		observability.Default.ObserveCloudflareRequest(request.URL.Path, response)
		values := []any{"method", request.Method, "path", request.URL.Path}
		if response != nil {
			values = append(values, "status", response.StatusCode, "cfRay", response.Header.Get("cf-ray"))
		}
		if err != nil {
			// Deliberately omit err.Error(): SDK errors may contain response bodies.
			values = append(values, "errorType", fmt.Sprintf("%T", err))
			logger.Info("Cloudflare API request failed", values...)
			return response, err
		}
		logger.V(1).Info("Cloudflare API request completed", values...)
		return response, nil
	}
}

// WithTunnelLock serializes a read/compare/write sequence for one remote tunnel.
func (client *Client) WithTunnelLock(ctx context.Context, tunnelID string, fn func() error) error {
	release, err := client.locks.acquire(ctx, tunnelID)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

type tunnelLock struct {
	semaphore chan struct{}
	refs      int
}

type tunnelLockSet struct {
	mu    sync.Mutex
	locks map[string]*tunnelLock
}

func newTunnelLockSet() *tunnelLockSet {
	return &tunnelLockSet{locks: make(map[string]*tunnelLock)}
}

func (set *tunnelLockSet) acquire(ctx context.Context, key string) (func(), error) {
	set.mu.Lock()
	lock := set.locks[key]
	if lock == nil {
		lock = &tunnelLock{semaphore: make(chan struct{}, 1)}
		lock.semaphore <- struct{}{}
		set.locks[key] = lock
	}
	lock.refs++
	set.mu.Unlock()

	select {
	case <-ctx.Done():
		set.releaseReference(key, lock)
		return nil, fmt.Errorf("wait for Cloudflare tunnel %q lock: %w", key, ctx.Err())
	case <-lock.semaphore:
		return func() {
			lock.semaphore <- struct{}{}
			set.releaseReference(key, lock)
		}, nil
	}
}

func (set *tunnelLockSet) releaseReference(key string, lock *tunnelLock) {
	set.mu.Lock()
	defer set.mu.Unlock()
	lock.refs--
	if lock.refs == 0 {
		delete(set.locks, key)
	}
}
