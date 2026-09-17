//go:build exploratory

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

// Package exploratory hosts the state-exploration harness. It runs the real
// controllers against a private envtest API server and a cfstub Cloudflare
// endpoint without sharing the Ginkgo controller suite globals.
package exploratory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/controller"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/xds/translator"
	"github.com/isac322/flareway/test/cfstub"
)

const (
	// stabilityPollInterval is the observation cadence for waitStable.
	stabilityPollInterval = 50 * time.Millisecond
	// stabilityConsecutive is the number of identical consecutive observations
	// required before the system is considered stable.
	stabilityConsecutive = 4
	// stabilityMaxWait bounds waitStable when the caller context has no
	// deadline of its own.
	stabilityMaxWait = 30 * time.Second
)

// explorationHarness owns one envtest environment, one cfstub server, and the
// current controller manager. The environment and stub survive manager
// restarts and iteration resets; only the manager is recreated.
type explorationHarness struct {
	client    client.Client
	apiReader client.Reader
	stub      *cfstub.Server
	snapshots *snapshotPublisher

	env     *envtest.Environment
	scheme  *runtime.Scheme
	config  *rest.Config
	factory *flarecloudflare.DefaultFactory
	manager ctrl.Manager
	cancel  context.CancelFunc
	done    chan error
}

// stabilityExpectation observes one aspect of the system. The returned string
// is a fingerprint of the observed state (typically a resourceVersion); a
// non-nil error means the expectation is not yet satisfied.
type stabilityExpectation func(ctx context.Context, h *explorationHarness) (string, error)

// newExplorationHarness starts envtest with the Flareway and Gateway API
// standard CRDs, starts cfstub, wires the production client factory at the
// stub URL, registers the minimal controller set, and starts the manager.
func newExplorationHarness(t *testing.T) *explorationHarness {
	t.Helper()
	ctrl.SetLogger(logr.Discard())

	repositoryRoot := exploratoryRepositoryRoot()
	h := &explorationHarness{
		env: &envtest.Environment{
			CRDDirectoryPaths: []string{
				filepath.Join(repositoryRoot, "config", "crd", "bases"),
				filepath.Join(gatewayAPIModuleDirectory(t, repositoryRoot), "config", "crd", "standard"),
			},
			ErrorIfCRDPathMissing: true,
		},
		snapshots: newSnapshotPublisher(),
	}

	config, err := h.env.Start()
	must(t, err, "start envtest")
	if config == nil {
		t.Fatal("envtest returned a nil rest.Config")
	}
	h.config = config
	t.Cleanup(func() {
		h.stopManager(t)
		must(t, h.env.Stop(), "stop envtest")
	})

	h.scheme = runtime.NewScheme()
	must(t, clientgoscheme.AddToScheme(h.scheme), "register client-go scheme")
	must(t, gatewayv1.Install(h.scheme), "register Gateway API scheme")
	must(t, v1alpha1.AddToScheme(h.scheme), "register Flareway scheme")

	h.stub = cfstub.New(t)
	h.factory = flarecloudflare.NewFactory(
		logr.Discard(),
		flarecloudflare.WithBaseURL(h.stub.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
		flarecloudflare.WithListLimiter(rate.NewLimiter(rate.Inf, 0)),
	)

	h.startManager(t)
	return h
}

// resetIteration clears remote state, faults, journal, and violations so the
// next exploration iteration starts clean. The stub keeps running and remote
// IDs stay monotonic across resets. The manager is untouched; callers that
// need the controllers to observe the cleared remote state should restart it
// or re-seed the remote fixtures they depend on.
func (h *explorationHarness) resetIteration(t *testing.T) {
	t.Helper()
	h.stub.ResetIteration()
	h.snapshots.Reset()
}

// waitStable polls every expectation plus the stub journal signature until all
// expectations succeed and the combined signature is unchanged for
// stabilityConsecutive consecutive observations, or ctx times out. A context
// without a deadline is bounded by stabilityMaxWait. Recorded stub contract
// violations fail immediately.
func (h *explorationHarness) waitStable(ctx context.Context, expectations ...stabilityExpectation) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, stabilityMaxWait)
		defer cancel()
	}

	var lastSignature string
	var lastErrs []error
	stable := 0

	for {
		if violations := h.stub.Violations(); len(violations) > 0 {
			return fmt.Errorf("cfstub contract violations: %s", formatViolations(violations))
		}

		var signature strings.Builder
		var errs []error
		for index, expectation := range expectations {
			fingerprint, err := expectation(ctx, h)
			fmt.Fprintf(&signature, "e%d=%s;", index, fingerprint)
			if err != nil {
				errs = append(errs, err)
			}
		}
		for _, call := range h.stub.PublicJournal() {
			signature.WriteString(call.Method)
			signature.WriteString(call.Path)
			signature.WriteString(";")
		}

		if len(errs) == 0 && signature.String() == lastSignature {
			stable++
			if stable >= stabilityConsecutive {
				return nil
			}
		} else {
			stable = 0
		}
		lastSignature = signature.String()
		lastErrs = errs

		select {
		case <-ctx.Done():
			return fmt.Errorf("system did not stabilize: %w (unmet expectations: %s)", ctx.Err(), joinErrs(lastErrs))
		case <-time.After(stabilityPollInterval):
		}
	}
}

// restartManager stops the current manager and starts a fresh one against the
// same envtest environment, stub, and snapshot publisher. A restarted manager
// re-lists every watched object, so existing resources are reconciled again.
func (h *explorationHarness) restartManager(t *testing.T) {
	t.Helper()
	h.stopManager(t)
	h.startManager(t)
}

func (h *explorationHarness) startManager(t *testing.T) {
	t.Helper()

	manager, err := ctrl.NewManager(h.config, ctrl.Options{
		Scheme:                 h.scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller:             controllerconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	must(t, err, "create manager")
	h.registerControllers(t, manager)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- manager.Start(ctx)
	}()
	if !manager.GetCache().WaitForCacheSync(ctx) {
		cancel()
		t.Fatal("manager cache did not sync")
	}

	h.manager = manager
	h.cancel = cancel
	h.done = done
	h.client = manager.GetClient()
	h.apiReader = manager.GetAPIReader()
}

func (h *explorationHarness) stopManager(t *testing.T) {
	t.Helper()
	if h.cancel == nil {
		return
	}
	h.cancel()
	must(t, <-h.done, "stop manager")
	h.cancel = nil
	h.done = nil
	h.manager = nil
}

// registerControllers installs the minimal controller set: account
// verification, the Access application and service-token surfaces, the
// private-network pair, the Gateway API reconciler with its in-package
// snapshot publisher, and the tunnel reconciler. Every Cloudflare client goes
// through the production factory pointed at cfstub.
func (h *explorationHarness) registerControllers(t *testing.T, manager ctrl.Manager) {
	t.Helper()

	kube := manager.GetClient()
	scheme := manager.GetScheme()
	apiReader := manager.GetAPIReader()

	must(t, (&controller.GatewayClassReconciler{
		Client: kube,
		Scheme: scheme,
	}).SetupWithManager(manager), "setup GatewayClass controller")

	must(t, (&controller.CloudflareAccountReconciler{
		Client:     kube,
		Scheme:     scheme,
		Cloudflare: h.factory,
	}).SetupWithManager(manager), "setup CloudflareAccount controller")

	must(t, (&controller.AccessApplicationReconciler{
		Client:              kube,
		APIReader:           apiReader,
		Scheme:              scheme,
		NewCloudflareClient: controller.AccessApplicationClientFromFactory(h.factory),
		OperatorNamespace:   dataplane.DefaultOperatorNamespace,
	}).SetupWithManager(manager), "setup AccessApplication controller")

	must(t, (&controller.ServiceTokenReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: controller.AccessClientFromFactory(h.factory),
	}).SetupWithManager(manager), "setup ServiceToken controller")

	must(t, (&controller.VirtualNetworkReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: controller.PrivateNetworkClientFromFactory(h.factory),
	}).SetupWithManager(manager), "setup VirtualNetwork controller")

	must(t, (&controller.NetworkRouteReconciler{
		Client:              kube,
		Scheme:              scheme,
		NewCloudflareClient: controller.PrivateNetworkClientFromFactory(h.factory),
	}).SetupWithManager(manager), "setup NetworkRoute controller")

	must(t, (&controller.GatewayReconciler{
		Client:            kube,
		Scheme:            scheme,
		Snapshots:         h.snapshots,
		BuildSnapshot:     translator.Build,
		OperatorNamespace: dataplane.DefaultOperatorNamespace,
		CloudflareFactory: h.factory,
	}).SetupWithManager(manager), "setup Gateway controller")

	must(t, (&controller.CloudflareTunnelReconciler{
		Client:              kube,
		APIReader:           apiReader,
		Scheme:              scheme,
		NewCloudflareClient: controller.TunnelClientFromFactory(h.factory),
	}).SetupWithManager(manager), "setup CloudflareTunnel controller")
}

// accountExpectation returns a stabilityExpectation that is satisfied when the
// CloudflareAccount carries the Accepted and CredentialsValid conditions. The
// fingerprint is the resourceVersion so status writes reset the stability
// counter.
func accountExpectation(name string) stabilityExpectation {
	return expectObject(types.NamespacedName{Name: name}, &v1alpha1.CloudflareAccount{}, func(object client.Object) error {
		account := object.(*v1alpha1.CloudflareAccount)
		for _, conditionType := range []string{
			v1alpha1.CloudflareAccountConditionAccepted,
			v1alpha1.CloudflareAccountConditionCredentialsValid,
		} {
			if !meta.IsStatusConditionTrue(account.Status.Conditions, conditionType) {
				return fmt.Errorf("CloudflareAccount %q condition %s is not True", name, conditionType)
			}
		}
		return nil
	})
}

// expectObject builds a stabilityExpectation around one object fetched through
// the uncached API reader. The fingerprint is the object's resourceVersion.
func expectObject(key types.NamespacedName, object client.Object, check func(client.Object) error) stabilityExpectation {
	return func(ctx context.Context, h *explorationHarness) (string, error) {
		if err := h.apiReader.Get(ctx, key, object); err != nil {
			return "", fmt.Errorf("get %T %s: %w", object, key, err)
		}
		return object.GetResourceVersion(), check(object)
	}
}

func exploratoryRepositoryRoot() string {
	if root := os.Getenv("FLAREWAY_REPOSITORY_ROOT"); root != "" {
		return root
	}
	return filepath.Join("..", "..")
}

func gatewayAPIModuleDirectory(t *testing.T, repositoryRoot string) string {
	t.Helper()
	command := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api")
	command.Dir = repositoryRoot
	output, err := command.Output()
	must(t, err, "locate sigs.k8s.io/gateway-api module")
	directory := strings.TrimSpace(string(output))
	if directory == "" {
		t.Fatal("go list returned an empty gateway-api module directory")
	}
	return directory
}

type fatalTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

func must(t fatalTB, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func formatViolations(violations []cfstub.Violation) string {
	parts := make([]string, 0, len(violations))
	for _, violation := range violations {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", violation.Method, violation.Path, violation.Reason))
	}
	return strings.Join(parts, ", ")
}

func joinErrs(errs []error) string {
	if len(errs) == 0 {
		return "none"
	}
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}
