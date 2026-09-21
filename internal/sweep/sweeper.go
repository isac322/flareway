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

package sweep

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
)

const (
	// defaultSweepRateLimit is the dedicated remote-call budget. Together
	// with the reconciler budget (3.5 req/s) it stays within the Cloudflare
	// account limit of 4.0 req/s.
	defaultSweepRateLimit = 0.5
	defaultSweepRateBurst = 1
	// defaultEventBuffer bounds the wakeup channel. A full buffer drops the
	// event, not the invalidation — the latch is the source of truth.
	defaultEventBuffer = 256
	// defaultAccountSyncInterval is how often the CloudflareAccount list is
	// re-read to start/stop per-account sweepers.
	defaultAccountSyncInterval = 30 * time.Second
)

// SweeperOptions carries the dependencies NewSweeper needs.
type SweeperOptions struct {
	// Client is the manager's cached client. CloudflareAccount, token
	// Secrets, and every swept CR kind are read through it — never through
	// APIReader — because they are already watched and the sweep is a
	// periodic job that tolerates cache lag.
	Client client.Client
	// APIReader is retained for the optional orphan-cleanup path (spec
	// defect #14): destructive verification must bypass the cache.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	// CloudflareFactory builds account-scoped remote clients. When it also
	// implements sweepClientFactory the returned client is paced by the
	// sweep limiter directly.
	CloudflareFactory flarecloudflare.ClientFactory
	// Invalidator closes the desired-hash gate for drifted objects. It may
	// be nil while the gate implementation is unwired; events are still
	// emitted.
	Invalidator Invalidator
	Policy      freshness.Policy
	Logger      logr.Logger
	// OperatorNamespace hosts the cluster-local ownership key Secret.
	OperatorNamespace string
	// SweepRateLimit is the dedicated remote-call budget in req/s.
	SweepRateLimit float64
	// SweepRateBurst is the limiter burst.
	SweepRateBurst int
	// EventBufferSize bounds Events(); default 256.
	EventBufferSize int
	// AccountSyncInterval overrides the 30s account re-list period (tests).
	AccountSyncInterval time.Duration
	// Targets overrides the default target registry (tests).
	Targets []TargetDescriptor
}

// Sweeper discovers CloudflareAccounts and runs one AccountSweeper per
// ready account. It is a leader-elected runnable: only the active leader
// replica executes it.
type Sweeper struct {
	client            client.Client
	apiReader         client.Reader
	scheme            *runtime.Scheme
	cloudflareFactory flarecloudflare.ClientFactory
	invalidator       Invalidator
	policy            freshness.Policy
	logger            logr.Logger
	operatorNamespace string
	rateLimit         float64
	rateBurst         int
	accountSync       time.Duration
	targets           []TargetDescriptor

	events chan event.GenericEvent

	mu       sync.Mutex
	accounts map[string]*AccountSweeper
}

var _ manager.Runnable = (*Sweeper)(nil)
var _ manager.LeaderElectionRunnable = (*Sweeper)(nil)

// NewSweeper constructs the production sweep worker.
func NewSweeper(opts SweeperOptions) *Sweeper {
	if opts.SweepRateLimit <= 0 {
		opts.SweepRateLimit = defaultSweepRateLimit
	}
	if opts.SweepRateBurst <= 0 {
		opts.SweepRateBurst = defaultSweepRateBurst
	}
	if opts.EventBufferSize <= 0 {
		opts.EventBufferSize = defaultEventBuffer
	}
	if opts.AccountSyncInterval <= 0 {
		opts.AccountSyncInterval = defaultAccountSyncInterval
	}
	if opts.OperatorNamespace == "" {
		opts.OperatorNamespace = dataplane.DefaultOperatorNamespace
	}
	if opts.Targets == nil {
		opts.Targets = defaultTargets()
	}
	return &Sweeper{
		client:            opts.Client,
		apiReader:         opts.APIReader,
		scheme:            opts.Scheme,
		cloudflareFactory: opts.CloudflareFactory,
		invalidator:       opts.Invalidator,
		policy:            opts.Policy,
		logger:            opts.Logger.WithName("sweeper"),
		operatorNamespace: opts.OperatorNamespace,
		rateLimit:         opts.SweepRateLimit,
		rateBurst:         opts.SweepRateBurst,
		accountSync:       opts.AccountSyncInterval,
		targets:           opts.Targets,
		events:            make(chan event.GenericEvent, opts.EventBufferSize),
		accounts:          make(map[string]*AccountSweeper),
	}
}

// Events returns the stream of GenericEvents for objects whose drift was
// confirmed. Controllers subscribe with
// WatchesRawSource(source.Channel(sweeper.Events(), &handler.EnqueueRequestForObject{})).
//
// The channel is a fast-wakeup optimization only. Sends never block: a full
// buffer drops the event and the item is re-emitted on the next pass while
// the Invalidator latch keeps the gate closed. Losing an event can delay a
// reconcile to the latch/TTL path; it can never lose the invalidation.
func (s *Sweeper) Events() <-chan event.GenericEvent {
	return s.events
}

// Start is invoked by the manager on the elected leader only.
func (s *Sweeper) Start(ctx context.Context) error {
	s.logger.Info("starting leader-elected sweep worker", "rateLimit", s.rateLimit, "rateBurst", s.rateBurst)
	defer s.stopAll()

	s.reconcileAccounts(ctx)
	ticker := time.NewTicker(s.accountSync)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping sweep worker")
			return nil
		case <-ticker.C:
			s.reconcileAccounts(ctx)
		}
	}
}

// NeedLeaderElection restricts the worker to the leader replica, matching
// the internal/xds/server precedent.
func (s *Sweeper) NeedLeaderElection() bool {
	return true
}

// reconcileAccounts starts an AccountSweeper for every ready account and
// stops sweepers whose account disappeared or lost readiness.
func (s *Sweeper) reconcileAccounts(ctx context.Context) {
	var accountList v1alpha1.CloudflareAccountList
	if err := s.client.List(ctx, &accountList); err != nil {
		s.logger.Error(err, "failed to list CloudflareAccounts for sweep")
		return
	}

	active := make(map[string]struct{}, len(accountList.Items))
	for i := range accountList.Items {
		account := &accountList.Items[i]
		if !isAccountReadyForSweep(account) {
			continue
		}
		active[account.Name] = struct{}{}
		s.ensureAccountSweeper(ctx, account)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for name, sweeper := range s.accounts {
		if _, ok := active[name]; !ok {
			s.logger.Info("stopping sweeper for removed or unready account", "account", name)
			sweeper.Stop()
			delete(s.accounts, name)
		}
	}
}

func (s *Sweeper) ensureAccountSweeper(ctx context.Context, account *v1alpha1.CloudflareAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[account.Name]; ok {
		return
	}

	token, err := s.resolveAccountToken(ctx, account)
	if err != nil {
		s.logger.Info("cannot start sweeper for account: token resolution failed", "account", account.Name, "error", err.Error())
		return
	}

	accountSweeper := NewAccountSweeper(AccountSweeperOptions{
		AccountName:       account.Name,
		AccountID:         account.Spec.AccountID,
		Token:             token,
		Factory:           s.cloudflareFactory,
		Client:            s.client,
		APIReader:         s.apiReader,
		Invalidator:       s.invalidator,
		Policy:            s.policy,
		OperatorNamespace: s.operatorNamespace,
		RateLimit:         s.rateLimit,
		RateBurst:         s.rateBurst,
		Targets:           s.targets,
		Events:            s.events,
		Logger:            s.logger.WithValues("account", account.Name),
	})
	s.accounts[account.Name] = accountSweeper
	accountSweeper.Start(ctx)
}

// resolveAccountToken reads the API token Secret through the cached client.
func (s *Sweeper) resolveAccountToken(ctx context.Context, account *v1alpha1.CloudflareAccount) (string, error) {
	ref := account.Spec.Credentials.APITokenSecretRef
	var secret corev1.Secret
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &secret); err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	value := secret.Data[key]
	if len(value) == 0 {
		return "", apierrors.NewNotFound(corev1.Resource("secretKey"), key)
	}
	return string(value), nil
}

// isAccountReadyForSweep requires both the Accepted and CredentialsValid
// conditions so an account with a broken token never starts a sweeper.
func isAccountReadyForSweep(account *v1alpha1.CloudflareAccount) bool {
	var accepted, credentialsValid bool
	for _, condition := range account.Status.Conditions {
		switch condition.Type {
		case v1alpha1.CloudflareAccountConditionAccepted:
			accepted = condition.Status == metav1.ConditionTrue
		case v1alpha1.CloudflareAccountConditionCredentialsValid:
			credentialsValid = condition.Status == metav1.ConditionTrue
		}
	}
	return accepted && credentialsValid
}

// stopAll terminates every account sweeper and waits for their goroutines.
func (s *Sweeper) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, sweeper := range s.accounts {
		sweeper.Stop()
		delete(s.accounts, name)
	}
}
