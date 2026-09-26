/*
Copyright 2026 The Flareway Authors.

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

package controller

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/ir"
)

// Issue #112: Cloudflare-mode Envoy listeners bind loopback ports, so the
// conformance listener Service must not exist for a Cloudflare-mode Gateway,
// and a Service left by v0.3.0 (or by a previous conformance-mode class) must
// be removed without disturbing convergence.
func TestCloudflareModeGatewayRemovesListenerService(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	key := listenerServiceKey(f)
	if err := h.direct.Get(h.ctx, key, &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Fatalf("converged Cloudflare-mode Gateway owns listener Service %s (get error %v), want none", key, err)
	}

	h.createV030ListenerService(t, f)
	h.waitListenerServiceRemoved(t, f)

	current := h.getGateway(t, f.gatewayKey)
	programmed := meta.FindStatusCondition(current.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programmed == nil || programmed.Status != metav1.ConditionTrue {
		t.Fatalf("Programmed after listener Service removal = %#v, want True", programmed)
	}
}

// A Cloudflare-mode Gateway that cannot provision yet (no CloudflareAccount)
// returns before applying dataplane objects; the leftover Service must still
// go, because no Cloudflare-mode state ever wants it.
func TestCloudflareModeGatewayWithoutAccountRemovesListenerService(t *testing.T) {
	h := newManagerHarness(t)
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: false})
	defer h.deleteFixture(t, f)
	h.waitFor(t, 20*time.Second, "gateway waiting on missing account", func() (bool, error) {
		gateway := h.getGateway(t, f.gatewayKey)
		programmed := meta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
		return programmed != nil && programmed.Status == metav1.ConditionFalse, nil
	})

	h.createV030ListenerService(t, f)
	h.waitListenerServiceRemoved(t, f)
}

// An admission rejection of the delete keeps the Service and surfaces as a
// Warning event, but does not hold the Gateway hostage: the Service carries
// no Cloudflare-mode traffic, so the Gateway stays Programmed. Once the delete
// is admitted, the next reconcile removes the Service.
func TestCloudflareModeListenerServiceDeleteRejectionDoesNotBlockGateway(t *testing.T) {
	var reject atomic.Bool
	events := &capturingEventRecorder{}
	h := newManagerHarnessWith(t, func(gw *GatewayReconciler, _ *CloudflareTunnelReconciler) {
		gw.Client = &serviceDeleteRejectingClient{Client: gw.Client, reject: &reject}
		gw.Recorder = events
	})
	f := h.buildFixture(t, managerFixtureSpec{dnsMode: v1alpha1.DNSModeManaged, withAccount: true})
	defer h.deleteFixture(t, f)
	h.waitConverged(t, f)

	reject.Store(true)
	h.createV030ListenerService(t, f)
	key := listenerServiceKey(f)
	h.waitFor(t, 20*time.Second, "rejected listener Service delete event", func() (bool, error) {
		for _, event := range events.rejections() {
			if event.eventType == corev1.EventTypeWarning && strings.Contains(event.note, key.String()) && strings.HasSuffix(event.note, "Forbidden") {
				return true, nil
			}
		}
		return false, nil
	})
	if err := h.direct.Get(h.ctx, key, &corev1.Service{}); err != nil {
		t.Fatalf("rejected delete removed the listener Service: %v", err)
	}
	if _, err := h.gatewayReconciler.Reconcile(h.ctx, ctrl.Request{NamespacedName: f.gatewayKey}); err != nil {
		t.Fatalf("reconcile with a rejected listener Service delete failed: %v", err)
	}
	programmed := meta.FindStatusCondition(h.getGateway(t, f.gatewayKey).Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programmed == nil || programmed.Status != metav1.ConditionTrue {
		t.Fatalf("Programmed after rejected listener Service delete = %#v, want True", programmed)
	}

	// Admit deletes and wake the Gateway through its owned-Service watch.
	reject.Store(false)
	var service corev1.Service
	if err := h.direct.Get(h.ctx, key, &service); err != nil {
		t.Fatalf("get listener Service: %v", err)
	}
	service.Labels = map[string]string{"example.com/touched": "true"}
	if err := h.direct.Update(h.ctx, &service); err != nil {
		t.Fatalf("touch listener Service: %v", err)
	}
	h.waitListenerServiceRemoved(t, f)
	h.waitConverged(t, f)
}

type serviceDeleteRejectingClient struct {
	client.Client
	reject *atomic.Bool
}

func (c *serviceDeleteRejectingClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, ok := object.(*corev1.Service); ok && c.reject.Load() {
		return apierrors.NewForbidden(corev1.Resource("services"), object.GetName(), errors.New("admission webhook denied the request"))
	}
	return c.Client.Delete(ctx, object, options...)
}

func listenerServiceKey(f *managerFixture) types.NamespacedName {
	return types.NamespacedName{Namespace: f.namespace, Name: dataplane.ResourceName(&ir.Gateway{Key: f.gatewayKey})}
}

// createV030ListenerService recreates the object v0.3.0 applied: controlled
// by this Gateway UID, selecting the dataplane Pods, and targeting a loopback
// Envoy port. Creating it wakes the Gateway through its owned-Service watch.
func (h *managerHarness) createV030ListenerService(t *testing.T, f *managerFixture) {
	t.Helper()
	key := listenerServiceKey(f)
	gateway := h.getGateway(t, f.gatewayKey)
	leftover := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            key.Name,
			Namespace:       key.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gateway, gatewayControllerGVK())},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{dataplane.GatewayLabelKey: f.namespace + "--" + f.gatewayName},
			Ports:    []corev1.ServicePort{{Name: "listener-0", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(18080)}},
		},
	}
	if err := h.direct.Create(h.ctx, leftover, client.FieldOwner(gatewayFieldManager)); err != nil {
		t.Fatalf("create v0.3.0 listener Service: %v", err)
	}
}

func (h *managerHarness) waitListenerServiceRemoved(t *testing.T, f *managerFixture) {
	t.Helper()
	key := listenerServiceKey(f)
	h.waitFor(t, 20*time.Second, "v0.3.0 listener Service removal", func() (bool, error) {
		err := h.direct.Get(h.ctx, key, &corev1.Service{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}
