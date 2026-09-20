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

package observability

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func TestMetricsUpdateAndGatewayDeletion(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.ObserveReconcile("gateway", ctrl.Result{}, nil)
	metrics.ObserveReconcile("gateway", ctrl.Result{RequeueAfter: time.Second}, nil)
	metrics.ObserveReconcile("gateway", ctrl.Result{}, errors.New("failed"))
	metrics.ObserveCloudflareRequest("/accounts/account/cfd_tunnel/tunnel/configurations", &http.Response{StatusCode: http.StatusTooManyRequests})
	metrics.ObserveCloudflareRequest("/unclassified", nil)
	metrics.SetGatewayProgrammed("apps/public", true)
	metrics.SetConfigVersions("apps/public", 12, 11)
	metrics.SetGatewayProgrammed("invalid", true)

	families := gatherFamilies(t, registry)
	assertMetricValue(t, families, "flareway_reconcile_total", map[string]string{"controller": "gateway", "result": "success"}, 1)
	assertMetricValue(t, families, "flareway_reconcile_total", map[string]string{"controller": "gateway", "result": "requeue"}, 1)
	assertMetricValue(t, families, "flareway_reconcile_total", map[string]string{"controller": "gateway", "result": "error"}, 1)
	assertMetricValue(t, families, "flareway_cloudflare_requests_total", map[string]string{"service": "tunnel", "status": "429"}, 1)
	assertMetricValue(t, families, "flareway_cloudflare_requests_total", map[string]string{"service": "unknown", "status": "error"}, 1)
	assertMetricValue(t, families, "flareway_cloudflare_ratelimited_total", nil, 1)
	assertMetricValue(t, families, "flareway_gateway_programmed", map[string]string{"gateway": "apps/public"}, 1)
	assertMetricValue(t, families, "flareway_config_version", map[string]string{"gateway": "apps/public", "kind": "desired"}, 12)
	assertMetricValue(t, families, "flareway_config_version", map[string]string{"gateway": "apps/public", "kind": "applied"}, 11)

	metrics.DeleteGateway("apps/public")
	families = gatherFamilies(t, registry)
	assertMetricAbsent(t, families, "flareway_gateway_programmed", map[string]string{"gateway": "apps/public"})
	assertMetricAbsent(t, families, "flareway_config_version", map[string]string{"gateway": "apps/public", "kind": "desired"})
	assertMetricAbsent(t, families, "flareway_config_version", map[string]string{"gateway": "apps/public", "kind": "applied"})
}

func TestReconcileObserverCountsOneOutcome(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	wantResult := ctrl.Result{RequeueAfter: time.Second}
	observer := metrics.observeReconciler("access-application", reconcile.Func(func(context.Context, reconcile.Request) (ctrl.Result, error) {
		return wantResult, nil
	}))

	gotResult, err := observer.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "apps", Name: "access"}})
	if err != nil || gotResult != wantResult {
		t.Fatalf("observed reconcile = %#v, %v; want %#v, nil", gotResult, err, wantResult)
	}
	families := gatherFamilies(t, registry)
	assertMetricValue(t, families, "flareway_reconcile_total", map[string]string{"controller": "access-application", "result": "requeue"}, 1)
}

func TestConditionEventsOnlyOnEntryAndNeverExposeMessages(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	before := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "protected"}}
	after := before.DeepCopy()
	after.Status.Conditions = []metav1.Condition{{
		Type: "Accepted", Status: metav1.ConditionFalse, Reason: "RefNotPermitted",
		Message: "Bearer super-secret-token", LastTransitionTime: metav1.Now(),
	}}

	EmitConditionTransitions(recorder, after, before, after)
	event := receiveEvent(t, recorder)
	if !strings.Contains(event, EventReasonSecurityBlocked) {
		t.Fatalf("event %q does not contain reason %q", event, EventReasonSecurityBlocked)
	}
	if strings.Contains(event, "super-secret-token") || strings.Contains(event, "Bearer") {
		t.Fatalf("event exposed condition message: %q", event)
	}

	EmitConditionTransitions(recorder, after, after, after)
	select {
	case duplicate := <-recorder.Events:
		t.Fatalf("unchanged state emitted duplicate event %q", duplicate)
	case <-time.After(50 * time.Millisecond):
	}

	cleared := after.DeepCopy()
	cleared.Status.Conditions[0] = metav1.Condition{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.Now()}
	EmitConditionTransitions(recorder, after, cleared, after)
	if event = receiveEvent(t, recorder); !strings.Contains(event, EventReasonSecurityBlocked) {
		t.Fatalf("re-entered state event = %q", event)
	}
}

func TestEventingClientEmitsPersistedTransitionsOnce(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Flareway scheme: %v", err)
	}
	object := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "protected"}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(object).WithObjects(object).Build()
	recorder := record.NewFakeRecorder(10)
	eventing := NewEventingClient(base, base, recorder)
	ctx := context.Background()

	current := new(v1alpha1.AccessApplication)
	if err := eventing.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		t.Fatalf("get AccessApplication: %v", err)
	}
	before := current.DeepCopy()
	current.Status.Conditions = []metav1.Condition{{
		Type: "Accepted", Status: metav1.ConditionFalse, Reason: EventReasonConflict,
		Message: "response body contains super-secret-token", LastTransitionTime: metav1.Now(),
	}}
	if err := eventing.Status().Patch(ctx, current, client.MergeFrom(before)); err != nil {
		t.Fatalf("patch conflict status: %v", err)
	}
	event := receiveEvent(t, recorder)
	if !strings.Contains(event, EventReasonConflict) || strings.Contains(event, "super-secret-token") {
		t.Fatalf("conflict event was not sanitized: %q", event)
	}

	if err := eventing.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		t.Fatalf("get updated AccessApplication: %v", err)
	}
	before = current.DeepCopy()
	current.Status.Conditions[0].Message = "a different sensitive message"
	if err := eventing.Status().Patch(ctx, current, client.MergeFrom(before)); err != nil {
		t.Fatalf("patch unchanged conflict state: %v", err)
	}
	select {
	case duplicate := <-recorder.Events:
		t.Fatalf("persisted conflict state emitted duplicate event %q", duplicate)
	case <-time.After(50 * time.Millisecond):
	}

	if err := eventing.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		t.Fatalf("get conflict AccessApplication: %v", err)
	}
	before = current.DeepCopy()
	current.Status.Conditions = []metav1.Condition{{
		Type: EventReasonCleanupBlocked, Status: metav1.ConditionTrue, Reason: "DependenciesRemain",
		Message: "dependency details", LastTransitionTime: metav1.Now(),
	}}
	if err := eventing.Status().Patch(ctx, current, client.MergeFrom(before)); err != nil {
		t.Fatalf("patch cleanup-blocked status: %v", err)
	}
	if event = receiveEvent(t, recorder); !strings.Contains(event, EventReasonCleanupBlocked) {
		t.Fatalf("cleanup event = %q", event)
	}
}

func TestEventingClientStatusApplyEmitsTransitionEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Flareway scheme: %v", err)
	}
	object := &v1alpha1.AccessApplication{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "apply-status"}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(object).WithObjects(object).Build()
	recorder := record.NewFakeRecorder(10)
	eventing := NewEventingClient(base, base, recorder)
	apply := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "flareway.bhyoo.com/v1alpha1",
		"kind":       "AccessApplication",
		"metadata": map[string]any{"namespace": "apps", "name": "apply-status"},
		"status": map[string]any{"conditions": []any{map[string]any{
			"type": "CleanupBlocked", "status": "True", "reason": "DependenciesRemain",
		}}},
	}}
	if err := eventing.Status().Apply(context.Background(), client.ApplyConfigurationFromUnstructured(apply), client.FieldOwner("test")); err != nil {
		t.Fatalf("status apply: %v", err)
	}
	if event := receiveEvent(t, recorder); !strings.Contains(event, EventReasonCleanupBlocked) {
		t.Fatalf("status apply event = %q", event)
	}
}


func receiveEvent(t *testing.T, recorder *record.FakeRecorder) string {
	t.Helper()
	select {
	case event := <-recorder.Events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return ""
	}
}

func gatherFamilies(t *testing.T, registry *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	result := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		result[family.GetName()] = family
	}
	return result
}

func assertMetricValue(t *testing.T, families map[string]*dto.MetricFamily, name string, labels map[string]string, want float64) {
	t.Helper()
	family := families[name]
	if family == nil {
		t.Fatalf("metric family %q is absent", name)
	}
	for _, metric := range family.Metric {
		if labelsMatch(metric.Label, labels) {
			got := metric.GetCounter().GetValue()
			if metric.Gauge != nil {
				got = metric.GetGauge().GetValue()
			}
			if got != want {
				t.Fatalf("metric %s%v = %v, want %v", name, labels, got, want)
			}
			return
		}
	}
	t.Fatalf("metric %s%v is absent", name, labels)
}

func assertMetricAbsent(t *testing.T, families map[string]*dto.MetricFamily, name string, labels map[string]string) {
	t.Helper()
	family := families[name]
	if family == nil {
		return
	}
	for _, metric := range family.Metric {
		if labelsMatch(metric.Label, labels) {
			t.Fatalf("metric %s%v still exists", name, labels)
		}
	}
}

func labelsMatch(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(pairs) != len(want) {
		return false
	}
	for _, pair := range pairs {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
