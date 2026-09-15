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

// Package observability owns Flareway's bounded Prometheus metrics and
// transition-only Kubernetes Events.
package observability

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Reconcile result labels.
const (
	ReconcileResultSuccess = "success"
	ReconcileResultRequeue = "requeue"
	ReconcileResultError   = "error"
)

// Metrics contains Flareway's collectors. A separate value can be registered
// with an isolated registry in tests; production uses Default.
type Metrics struct {
	reconciles          *prometheus.CounterVec
	cloudflareRequests  *prometheus.CounterVec
	cloudflareRateLimit prometheus.Counter
	gatewayProgrammed   *prometheus.GaugeVec
	configVersion       *prometheus.GaugeVec
}

// Default is registered with controller-runtime's registry, which is served by
// the manager metrics endpoint.
var Default = NewMetrics(controllermetrics.Registry)

// NewMetrics constructs and registers all Flareway collectors.
func NewMetrics(registerer prometheus.Registerer) *Metrics {
	metrics := &Metrics{
		reconciles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flareway_reconcile_total",
			Help: "Total Flareway reconciliations by controller and result.",
		}, []string{"controller", "result"}),
		cloudflareRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flareway_cloudflare_requests_total",
			Help: "Total Cloudflare API requests by bounded service and status.",
		}, []string{"service", "status"}),
		cloudflareRateLimit: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flareway_cloudflare_ratelimited_total",
			Help: "Total Cloudflare API HTTP 429 responses.",
		}),
		gatewayProgrammed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flareway_gateway_programmed",
			Help: "Whether a Gateway's Programmed condition is True.",
		}, []string{"gateway"}),
		configVersion: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flareway_config_version",
			Help: "Cloudflared configuration version desired or applied for a Gateway.",
		}, []string{"gateway", "kind"}),
	}
	registerer.MustRegister(
		metrics.reconciles,
		metrics.cloudflareRequests,
		metrics.cloudflareRateLimit,
		metrics.gatewayProgrammed,
		metrics.configVersion,
	)
	return metrics
}

// ObserveReconcile records exactly one outcome for a completed reconcile call.
func (metrics *Metrics) ObserveReconcile(controller string, result ctrl.Result, err error) {
	outcome := ReconcileResultSuccess
	if err != nil {
		outcome = ReconcileResultError
	} else if result.RequeueAfter > 0 {
		outcome = ReconcileResultRequeue
	}
	metrics.reconciles.WithLabelValues(controller, outcome).Inc()
}

// ObserveCloudflareRequest records one SDK request without retaining the
// URL, request body, response body, credentials, account ID, or object IDs.
func (metrics *Metrics) ObserveCloudflareRequest(path string, response *http.Response) {
	status := "error"
	if response != nil && response.StatusCode >= 100 && response.StatusCode <= 599 {
		status = strconv.Itoa(response.StatusCode)
	}
	metrics.cloudflareRequests.WithLabelValues(cloudflareService(path), status).Inc()
	if response != nil && response.StatusCode == http.StatusTooManyRequests {
		metrics.cloudflareRateLimit.Inc()
	}
}

// SetGatewayProgrammed publishes the current Programmed state. Invalid keys
// are ignored rather than becoming an unbounded label source.
func (metrics *Metrics) SetGatewayProgrammed(gateway string, programmed bool) {
	if !validGatewayLabel(gateway) {
		return
	}
	value := 0.0
	if programmed {
		value = 1
	}
	metrics.gatewayProgrammed.WithLabelValues(gateway).Set(value)
}

// SetConfigVersions publishes both bounded config-version series.
func (metrics *Metrics) SetConfigVersions(gateway string, desired, applied int64) {
	if !validGatewayLabel(gateway) {
		return
	}
	metrics.configVersion.WithLabelValues(gateway, "desired").Set(float64(desired))
	metrics.configVersion.WithLabelValues(gateway, "applied").Set(float64(applied))
}

// DeleteGateway removes every gauge series owned by a deleted Gateway.
func (metrics *Metrics) DeleteGateway(gateway string) {
	if !validGatewayLabel(gateway) {
		return
	}
	metrics.gatewayProgrammed.DeleteLabelValues(gateway)
	metrics.configVersion.DeleteLabelValues(gateway, "desired")
	metrics.configVersion.DeleteLabelValues(gateway, "applied")
}

// ObserveReconciler wraps a controller without changing its behavior.
func ObserveReconciler(controller string, next reconcile.Reconciler) reconcile.Reconciler {
	return Default.observeReconciler(controller, next)
}

func (metrics *Metrics) observeReconciler(controller string, next reconcile.Reconciler) reconcile.Reconciler {
	return reconcile.Func(func(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
		result, err := next.Reconcile(ctx, request)
		metrics.ObserveReconcile(controller, result, err)
		return result, err
	})
}

func validGatewayLabel(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func cloudflareService(path string) string {
	path = strings.ToLower(path)
	switch {
	case strings.Contains(path, "/dns_records"):
		return "dns"
	case strings.Contains(path, "/cfd_tunnel"):
		return "tunnel"
	case strings.Contains(path, "/access/"):
		return "access"
	case strings.Contains(path, "/teamnet/") || strings.Contains(path, "/networks/"):
		return "network"
	case strings.Contains(path, "/devices"):
		return "device"
	case strings.Contains(path, "/organizations"):
		return "organization"
	case strings.Contains(path, "/gateway/"):
		return "gateway"
	case strings.Contains(path, "/zones") || strings.Contains(path, "/user/tokens/verify"):
		return "account"
	default:
		return "unknown"
	}
}
