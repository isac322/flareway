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

package exploratory

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"pgregory.net/rapid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/test/cfstub"
	"github.com/isac322/flareway/test/envtesthelpers"
)

// gatewayProbePort is the fixed cloudflared metrics/probe port the production
// prober dials on every dataplane Pod IP.
const gatewayProbePort = 2000

// TestGatewayStateMachine explores the Gateway family: CloudflareAccount,
// GatewayClassConfig, GatewayClass, Gateway, HTTPRoute, and CloudflareTunnel
// create/update/delete, Gateway vs Direct configuration mode, xDS ACK/NACK,
// synthesized connector readiness, and transient Cloudflare faults.
//
// envtest has no kubelet, so Deployment availability and Pod readiness are
// synthesized explicitly: Pods get PodIP 127.0.0.1 and a local HTTP server on
// the cloudflared probe port answers /ready and /config the way a converged
// connector would.
//
// Invariants checked at stable points:
//   - G1: no remote mutation is journaled while the account is unverified or
//     the tunnel is unauthorized; cleanup of verified objects stays allowed.
//   - G4: after a writer boundary settles, a tunnel configuration write
//     requires the current writer to hold ownership; in Direct mode the
//     recorded Gateway dataplane must be drained first.
//   - G5: Programmed=True implies desired/applied config versions, remote
//     version, xDS ACK, a probed dataplane Pod, and managed DNS records all
//     converged.
//   - Journal order: token verification precedes account-scoped calls and
//     tunnel creation precedes tunnel-scoped calls.
func TestGatewayStateMachine(t *testing.T) {
	recorder := newTraceRecorder(t, "gateway")
	h := newExplorationHarness(t)
	probe := newGatewayProbeServer()
	t.Cleanup(probe.close)

	rapid.Check(t, func(rt *rapid.T) {
		if violations := h.stub.Violations(); len(violations) > 0 {
			rt.Fatalf("cfstub violations from previous iteration: %s", formatViolations(violations))
		}
		h.stopManager(t)
		purgeGatewayObjects(rt, h)
		h.resetIteration(t)
		h.startManager(t)
		recorder.BeginIteration()
		machine := newGatewayMachine(t, h, recorder, probe)
		machine.seedRemote()
		rt.Repeat(rapid.StateMachineActions(machine))
	})
}

// gatewayMachine is the rapid state machine for the Gateway family. It owns
// one iteration's object names; every name embeds the iteration index so
// objects never collide across iterations.
type gatewayMachine struct {
	t        *testing.T
	h        *explorationHarness
	recorder *traceRecorder
	probe    *gatewayProbeServer

	iteration int
	namespace string
	account   string
	accountID string
	zoneID    string
	zoneName  string
	secret    string
	config    string
	class     string
	gateway   string
	tunnel    string
	route     string
	backend   string
	hostname  string
	altHost   string

	nsCreated          bool
	accountCreated     bool
	accountDenied      bool
	configCreated      bool
	classCreated       bool
	gatewayCreated     bool
	gatewayRefExplicit bool
	tunnelCreated      bool
	routeCreated       bool
	podCreated         bool
	remoteConnector    bool

	// accountUnverifiedMark and tunnelUnauthorizedMark bound the journal
	// windows used by the G1 invariant. writerBoundary bounds the G4 window.
	accountUnverifiedMark  int
	tunnelUnauthorizedMark int
	grantDeniedMark        int
	writerBoundary         int
	writerBoundarySettled  bool
}

func newGatewayMachine(t *testing.T, h *explorationHarness, recorder *traceRecorder, probe *gatewayProbeServer) *gatewayMachine {
	iteration := int(gatewayIterationCounter.Add(1))
	suffix := fmt.Sprintf("%d", iteration)
	return &gatewayMachine{
		t:         t,
		h:         h,
		recorder:  recorder,
		probe:     probe,
		iteration: iteration,
		namespace: "expl-gw-" + suffix,
		account:   "acct-" + suffix,
		accountID: fmt.Sprintf("%032x", 0x1000+iteration),
		zoneID:    "zone-" + suffix,
		zoneName:  "expl" + suffix + ".example.com",
		secret:    "cf-token-" + suffix,
		config:    "gwcc-" + suffix,
		class:     "gwc-" + suffix,
		gateway:   "gw-" + suffix,
		tunnel:    "tun-" + suffix,
		route:     "route-" + suffix,
		backend:   "backend-" + suffix,
		hostname:  "app.expl" + suffix + ".example.com",
		altHost:   "alt.expl" + suffix + ".example.com",
	}
}

var gatewayIterationCounter atomic.Int64

// seedRemote installs the organization and zone fixtures the account
// verification flow needs. Remote IDs stay monotonic across resets.
func (m *gatewayMachine) seedRemote() {
	m.h.stub.State.SetOrganization(m.accountID, cfstub.Organization{
		ID:         "org-" + m.account,
		Name:       "Exploration Org",
		AuthDomain: "exploration.cloudflareaccess.com",
	})
	m.h.stub.State.AddZone(cfstub.Zone{
		ID:          m.zoneID,
		Name:        m.zoneName,
		Account:     cfstub.ZoneAccount{ID: m.accountID, Name: "Exploration Org"},
		AccountID:   m.accountID,
		AccountName: "Exploration Org",
	})
}

// Check runs after every action: it waits for the controllers to quiesce,
// records conditions, and evaluates the complete Gateway invariant set.
func (m *gatewayMachine) Check(rt *rapid.T) {
	m.refreshProbeTunnel()
	m.waitForStable(rt)
	m.checkJournalOrder(rt)
	m.checkAuthorizedMutation(rt)
	m.checkSingleWriter(rt)
	m.checkProgrammedConverged(rt)
	m.checkGrantDenial(rt)
	m.recordConditions(rt)
}

// --- actions ---------------------------------------------------------------

// CreateAccount creates the tenant namespace, the API token Secret, and the
// CloudflareAccount with a grant covering this iteration's hostnames.
func (m *gatewayMachine) CreateAccount(rt *rapid.T) {
	if m.accountCreated {
		rt.Skip("account already exists")
	}
	m.ensureNamespace(rt)
	ctx := context.Background()
	m.accountUnverifiedMark = len(m.h.stub.Journal())
	must2(rt, m.h.client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.secret},
		Data:       map[string][]byte{"token": []byte("exploration-token")},
	}), "create token Secret")
	must2(rt, m.h.client.Create(ctx, &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: m.account},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID: m.accountID,
			Credentials: v1alpha1.CloudflareAccountCredentials{
				APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{
					Namespace: m.namespace,
					Name:      m.secret,
					Key:       "token",
				},
			},
			Grants: []v1alpha1.CloudflareAccountGrant{m.accountGrants()},
		},
	}), "create CloudflareAccount")
	m.accountCreated = true
	m.record(rt, "CreateAccount", "created")
}

// UpdateAccount toggles the grant between allowing this iteration's hostnames
// and denying every hostname, exercising authorization loss.
func (m *gatewayMachine) UpdateAccount(rt *rapid.T) {
	if !m.accountCreated {
		rt.Skip("no account to update")
	}
	m.waitForStable(rt)
	ctx := context.Background()
	m.accountDenied = !m.accountDenied
	must2(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var account v1alpha1.CloudflareAccount
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Name: m.account}, &account); err != nil {
			return err
		}
		account.Spec.Grants = []v1alpha1.CloudflareAccountGrant{m.accountGrants()}
		return m.h.client.Update(ctx, &account)
	}), "update CloudflareAccount grants")
	if m.accountDenied {
		m.waitForGrantDenialObserved(rt)
		m.grantDeniedMark = len(m.h.stub.Journal())
		m.tunnelUnauthorizedMark = m.grantDeniedMark
	}
	m.record(rt, "UpdateAccount", map[bool]string{true: "denied", false: "allowed"}[m.accountDenied])
}

// DeleteAccount removes the CloudflareAccount while dependents may still
// reference it.
func (m *gatewayMachine) DeleteAccount(rt *rapid.T) {
	if !m.accountCreated {
		rt.Skip("no account to delete")
	}
	m.waitForStable(rt)
	m.accountUnverifiedMark = len(m.h.stub.Journal())
	m.tunnelUnauthorizedMark = m.accountUnverifiedMark
	ctx := context.Background()
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(ctx, &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: m.account},
	})), "delete CloudflareAccount")
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.secret},
	})), "delete token Secret")
	m.accountCreated = false
	m.accountDenied = false
	m.record(rt, "DeleteAccount", "deleted")
}

// CreateClassConfig creates the GatewayClassConfig bound to this iteration's
// account.
func (m *gatewayMachine) CreateClassConfig(rt *rapid.T) {
	if m.configCreated {
		rt.Skip("config already exists")
	}
	must2(rt, m.h.client.Create(context.Background(), &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: m.config},
		Spec: v1alpha1.GatewayClassConfigSpec{
			AccountRef: &corev1.LocalObjectReference{Name: m.account},
		},
	}), "create GatewayClassConfig")
	m.configCreated = true
	m.record(rt, "CreateClassConfig", "created")
}

// UpdateClassConfig toggles the default origin JWT mode, a spec change that
// re-renders the cloudflared configuration for Gateways in the class.
func (m *gatewayMachine) UpdateClassConfig(rt *rapid.T) {
	if !m.configCreated {
		rt.Skip("no config to update")
	}
	ctx := context.Background()
	var mode v1alpha1.OriginJWTMode
	must2(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var config v1alpha1.GatewayClassConfig
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Name: m.config}, &config); err != nil {
			return err
		}
		if config.Spec.OriginJWT.Mode == v1alpha1.OriginJWTModeDisabled {
			config.Spec.OriginJWT.Mode = v1alpha1.OriginJWTModeRequired
		} else {
			config.Spec.OriginJWT.Mode = v1alpha1.OriginJWTModeDisabled
		}
		mode = config.Spec.OriginJWT.Mode
		return m.h.client.Update(ctx, &config)
	}), "update GatewayClassConfig")
	m.record(rt, "UpdateClassConfig", string(mode))
}

// DeleteClassConfig removes the config while a GatewayClass may still
// reference it.
func (m *gatewayMachine) DeleteClassConfig(rt *rapid.T) {
	if !m.configCreated {
		rt.Skip("no config to delete")
	}
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(context.Background(), &v1alpha1.GatewayClassConfig{
		ObjectMeta: metav1.ObjectMeta{Name: m.config},
	})), "delete GatewayClassConfig")
	m.configCreated = false
	m.record(rt, "DeleteClassConfig", "deleted")
}

// CreateGatewayClass creates the GatewayClass pointing at the config.
func (m *gatewayMachine) CreateGatewayClass(rt *rapid.T) {
	if m.classCreated {
		rt.Skip("class already exists")
	}
	group := gatewayv1.Group(v1alpha1.Group)
	kind := gatewayv1.Kind("GatewayClassConfig")
	must2(rt, m.h.client.Create(context.Background(), &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: m.class},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef:  &gatewayv1.ParametersReference{Group: group, Kind: kind, Name: m.config},
		},
	}), "create GatewayClass")
	m.classCreated = true
	m.record(rt, "CreateGatewayClass", "created")
}

// DeleteGatewayClass removes the class while a Gateway may still use it.
func (m *gatewayMachine) DeleteGatewayClass(rt *rapid.T) {
	if !m.classCreated {
		rt.Skip("no class to delete")
	}
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(context.Background(), &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: m.class},
	})), "delete GatewayClass")
	m.classCreated = false
	m.record(rt, "DeleteGatewayClass", "deleted")
}

// CreateTunnel creates an explicit CloudflareTunnel the next Gateway may
// reference through infrastructure.parametersRef.
func (m *gatewayMachine) CreateTunnel(rt *rapid.T) {
	if m.tunnelCreated {
		rt.Skip("tunnel already exists")
	}
	m.ensureNamespace(rt)
	var existing v1alpha1.CloudflareTunnel
	err := m.h.apiReader.Get(context.Background(), types.NamespacedName{Namespace: m.namespace, Name: m.tunnel}, &existing)
	if err == nil {
		rt.Skip("tunnel still exists or is terminating")
	}
	if !apierrors.IsNotFound(err) {
		must2(rt, err, "check existing CloudflareTunnel")
	}
	m.tunnelUnauthorizedMark = len(m.h.stub.Journal())
	must2(rt, m.h.client.Create(context.Background(), &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.tunnel},
		Spec: v1alpha1.CloudflareTunnelSpec{
			AccountRef: corev1.LocalObjectReference{Name: m.account},
		},
	}), "create CloudflareTunnel")
	m.tunnelCreated = true
	m.record(rt, "CreateTunnel", "created")
}

// UpdateTunnel flips the bound tunnel between Gateway and Direct mode, the
// G4 single-writer transition. The incumbent writer may tear down; the
// successor must not write until ownership and drain resolve.
func (m *gatewayMachine) UpdateTunnel(rt *rapid.T) {
	name := m.boundTunnelName()
	if name == "" {
		rt.Skip("no bound tunnel to update")
	}
	ctx := context.Background()
	var mode v1alpha1.CloudflareTunnelConfigurationMode
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var tunnel v1alpha1.CloudflareTunnel
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel); err != nil {
			return err
		}
		if tunnel.Spec.Configuration.Mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
			tunnel.Spec.Configuration.Mode = v1alpha1.CloudflareTunnelConfigurationModeGateway
			tunnel.Spec.Configuration.Direct = nil
		} else {
			tunnel.Spec.Configuration.Mode = v1alpha1.CloudflareTunnelConfigurationModeDirect
			tunnel.Spec.Configuration.Direct = &v1alpha1.CloudflareTunnelDirectConfiguration{
				Ingress: []v1alpha1.CloudflareTunnelIngressRule{
					{
						Hostname: m.hostname,
						Service: v1alpha1.CloudflareTunnelIngressService{
							HTTP: &v1alpha1.CloudflareTunnelAddressService{Address: "127.0.0.1:8080"},
						},
					},
					{
						Service: v1alpha1.CloudflareTunnelIngressService{
							HTTPStatus: &v1alpha1.CloudflareTunnelHTTPStatusService{Code: 404},
						},
					},
				},
			}
		}
		mode = tunnel.Spec.Configuration.Mode
		return m.h.client.Update(ctx, &tunnel)
	})
	if apierrors.IsNotFound(err) {
		rt.Skip("bound tunnel disappeared before update")
	}
	must2(rt, err, "flip CloudflareTunnel mode")
	m.writerBoundary = len(m.h.stub.Journal())
	m.writerBoundarySettled = false
	m.record(rt, "UpdateTunnel", string(mode))
}

// DeleteTunnel deletes the bound tunnel (explicit or implicit).
func (m *gatewayMachine) DeleteTunnel(rt *rapid.T) {
	name := m.boundTunnelName()
	if name == "" {
		rt.Skip("no bound tunnel to delete")
	}
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(context.Background(), &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: name},
	})), "delete CloudflareTunnel")
	m.writerBoundary = len(m.h.stub.Journal())
	m.writerBoundarySettled = false
	if name == m.tunnel {
		m.tunnelCreated = false
	}
	m.record(rt, "DeleteTunnel", "deleted")
}

// CreateGateway creates the Gateway. When an explicit tunnel exists the
// Gateway references it; otherwise the controller auto-provisions a tunnel
// named after the Gateway.
func (m *gatewayMachine) CreateGateway(rt *rapid.T) {
	if m.gatewayCreated {
		rt.Skip("gateway already exists")
	}
	m.ensureNamespace(rt)
	hostname := gatewayv1.Hostname(m.hostname)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.gateway},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(m.class),
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Hostname: &hostname,
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	if m.tunnelCreated && rapid.Bool().Draw(rt, "explicitRef") {
		group := gatewayv1.Group(v1alpha1.Group)
		kind := gatewayv1.Kind("CloudflareTunnel")
		gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: group,
				Kind:  kind,
				Name:  m.tunnel,
			},
		}
		m.gatewayRefExplicit = true
	}
	m.tunnelUnauthorizedMark = len(m.h.stub.Journal())
	must2(rt, m.h.client.Create(context.Background(), gateway), "create Gateway")
	m.gatewayCreated = true
	m.writerBoundary = len(m.h.stub.Journal())
	m.writerBoundarySettled = false
	m.record(rt, "CreateGateway", "created")
}

// UpdateGateway swaps the listener hostname, forcing DNS record replacement.
func (m *gatewayMachine) UpdateGateway(rt *rapid.T) {
	if !m.gatewayCreated {
		rt.Skip("no gateway to update")
	}
	ctx := context.Background()
	next := m.altHost
	must2(rt, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var gateway gatewayv1.Gateway
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gateway); err != nil {
			return err
		}
		current := string(*gateway.Spec.Listeners[0].Hostname)
		next = m.altHost
		if current == m.altHost {
			next = m.hostname
		}
		hostname := gatewayv1.Hostname(next)
		gateway.Spec.Listeners[0].Hostname = &hostname
		return m.h.client.Update(ctx, &gateway)
	}), "update Gateway hostname")
	m.record(rt, "UpdateGateway", next)
}

// DeleteGateway removes the Gateway; the bound tunnel loses its owner.
func (m *gatewayMachine) DeleteGateway(rt *rapid.T) {
	if !m.gatewayCreated {
		rt.Skip("no gateway to delete")
	}
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(context.Background(), &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.gateway},
	})), "delete Gateway")
	m.gatewayCreated = false
	m.gatewayRefExplicit = false
	m.writerBoundary = len(m.h.stub.Journal())
	m.writerBoundarySettled = false
	m.record(rt, "DeleteGateway", "deleted")
}

// CreateHTTPRoute creates the backend Service, a synthesized EndpointSlice,
// and the HTTPRoute bound to the Gateway listener hostname.
func (m *gatewayMachine) CreateHTTPRoute(rt *rapid.T) {
	if m.routeCreated {
		rt.Skip("route already exists")
	}
	m.ensureNamespace(rt)
	ctx := context.Background()
	must2(rt, m.h.client.Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.backend},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports:     []corev1.ServicePort{{Name: "http", Port: 8080}},
		},
	}), "create backend Service")
	must2(rt, m.h.client.Create(ctx, &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: m.namespace,
			Name:      m.backend + "-eps",
			Labels:    map[string]string{discoveryv1.LabelServiceName: m.backend},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.10"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
		Ports: []discoveryv1.EndpointPort{{Name: ptr.To("http"), Port: ptr.To[int32](8080)}},
	}), "create backend EndpointSlice")
	port := gatewayv1.PortNumber(8080)
	routeHostname := gatewayv1.Hostname(m.hostname)
	must2(rt, m.h.client.Create(ctx, &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.route},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(m.gateway)}},
			},
			Hostnames: []gatewayv1.Hostname{routeHostname},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(m.backend),
							Port: &port,
						},
					},
				}},
			}},
		},
	}), "create HTTPRoute")
	m.routeCreated = true
	m.record(rt, "CreateHTTPRoute", "created")
}

// DeleteHTTPRoute removes the route and its backend fixtures.
func (m *gatewayMachine) DeleteHTTPRoute(rt *rapid.T) {
	if !m.routeCreated {
		rt.Skip("no route to delete")
	}
	ctx := context.Background()
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(ctx, &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.route},
	})), "delete HTTPRoute")
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(ctx, &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.backend + "-eps"},
	})), "delete backend EndpointSlice")
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.backend},
	})), "delete backend Service")
	m.routeCreated = false
	m.record(rt, "DeleteHTTPRoute", "deleted")
}

// StartConnector synthesizes one ready dataplane Pod: the kubelet does not
// exist in envtest, so the Pod status is written directly and the local probe
// server answers the cloudflared /ready and /config endpoints.
func (m *gatewayMachine) StartConnector(rt *rapid.T) {
	if m.podCreated || !m.gatewayCreated {
		rt.Skip("no gateway or pod already running")
	}
	if err := m.probe.ensure(); err != nil {
		rt.Skipf("probe port %d unavailable: %v", gatewayProbePort, err)
	}
	m.refreshProbeTunnel()
	ctx := context.Background()
	tokenSecret := "flareway-tunnel-" + m.boundTunnelName()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: m.namespace,
			Name:      "connector-" + m.gateway,
			Labels: map[string]string{
				dataplane.StandardGatewayLabelKey: m.gateway,
				dataplane.GatewayLabelKey:         m.namespace + "--" + m.gateway,
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "cloudflared",
			Image: "example.invalid/cloudflared",
			Env: []corev1.EnvVar{{
				Name: "TUNNEL_TOKEN",
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: tokenSecret},
					Key:                  "token",
				}},
			}},
		}}},
	}
	must2(rt, m.h.client.Create(ctx, pod), "create connector Pod")
	pod.Status.PodIP = "127.0.0.1"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	must2(rt, m.h.client.Status().Update(ctx, pod), "mark connector Pod ready")
	m.podCreated = true
	m.probe.setReady(true)
	m.markDeploymentAvailable(rt)
	m.record(rt, "StartConnector", "ready")
}

// StopConnector deletes the synthesized Pod and flips the probe to not-ready.
func (m *gatewayMachine) StopConnector(rt *rapid.T) {
	if !m.podCreated {
		rt.Skip("no connector pod")
	}
	m.probe.setReady(false)
	must2(rt, client.IgnoreNotFound(m.h.client.Delete(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: "connector-" + m.gateway},
	})), "delete connector Pod")
	m.podCreated = false
	m.record(rt, "StopConnector", "stopped")
}

// SeedRemoteConnector registers a cloudflared connector with an active edge
// connection on the remote tunnel, the remote half of connector readiness.
func (m *gatewayMachine) SeedRemoteConnector(rt *rapid.T) {
	tunnelID := m.currentTunnelID()
	if tunnelID == "" {
		rt.Skip("no remote tunnel")
	}
	version := int64(0)
	if configuration, ok := m.h.stub.State.TunnelConfiguration(tunnelID); ok {
		version = configuration.Version
	}
	m.h.stub.State.AddTunnelConnector(tunnelID, cfstub.TunnelConnector{
		ID:            "conn-" + m.gateway,
		ConfigVersion: version,
		Conns: []cfstub.TunnelConnection{{
			ID:       "edge-" + m.gateway,
			ClientID: "conn-" + m.gateway,
			OpenedAt: time.Now(),
		}},
	})
	m.remoteConnector = true
	m.record(rt, "SeedRemoteConnector", "connected")
}

// SyncConnectorConfig advances the synthesized connector's observed config
// version independently of the Cloudflare API state, creating a real lag
// window for the G5 Programmed invariant.
func (m *gatewayMachine) SyncConnectorConfig(rt *rapid.T) {
	if !m.podCreated {
		rt.Skip("no connector pod")
	}
	tunnelID := m.currentTunnelID()
	configuration, ok := m.h.stub.State.TunnelConfiguration(tunnelID)
	if tunnelID == "" || !ok {
		rt.Skip("no remote tunnel configuration")
	}
	m.refreshProbeTunnel()
	m.probe.setVersion(configuration.Version)
	m.record(rt, "SyncConnectorConfig", fmt.Sprintf("version=%d", configuration.Version))
}

// AckSnapshot acknowledges the currently published xDS snapshot.
func (m *gatewayMachine) AckSnapshot(rt *rapid.T) {
	key := m.namespace + "/" + m.gateway
	if m.h.snapshots.Version(key) == "" {
		rt.Skip("no published snapshot")
	}
	must2(rt, m.h.snapshots.ACK(key), "ACK snapshot")
	m.record(rt, "AckSnapshot", "acked")
}

// NackSnapshot rejects the currently published xDS snapshot.
func (m *gatewayMachine) NackSnapshot(rt *rapid.T) {
	key := m.namespace + "/" + m.gateway
	if m.h.snapshots.Version(key) == "" {
		rt.Skip("no published snapshot")
	}
	must2(rt, m.h.snapshots.NACK(key, "synthesized dataplane rejection"), "NACK snapshot")
	m.record(rt, "NackSnapshot", "nacked")
}

// InjectFault installs a bounded transient fault on a Cloudflare endpoint
// used by this iteration's account.
func (m *gatewayMachine) InjectFault(rt *rapid.T) {
	targets := [][2]string{
		{http.MethodGet, "^/accounts/" + m.accountID + "/cfd_tunnel"},
		{http.MethodPut, "^/accounts/" + m.accountID + "/cfd_tunnel/[^/]+/configurations$"},
		{http.MethodGet, "^/accounts/" + m.accountID + "/cfd_tunnel/[^/]+/configurations$"},
		{http.MethodGet, "^/zones/" + m.zoneID + "/dns_records$"},
		{http.MethodPost, "^/zones/" + m.zoneID + "/dns_records$"},
		{http.MethodGet, "^/user/tokens/verify$"},
	}
	target := targets[rapid.IntRange(0, len(targets)-1).Draw(rt, "faultTarget")]
	status := rapid.SampledFrom([]int{
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusTooManyRequests,
	}).Draw(rt, "faultStatus")
	times := rapid.IntRange(1, 3).Draw(rt, "faultTimes")
	m.h.stub.Fault(target[0], target[1], cfstub.Fault{Status: status, Times: times})
	m.record(rt, "InjectFault", fmt.Sprintf("%s %s -> %d x%d", target[0], target[1], status, times))
}

// RestartManager restarts the controller manager against the same envtest
// environment, forcing a full re-list and re-reconcile.
func (m *gatewayMachine) RestartManager(rt *rapid.T) {
	m.h.restartManager(m.t)
	m.refreshProbeTunnel()
	m.record(rt, "RestartManager", "restarted")
}

func (m *gatewayMachine) waitForStable(rt *rapid.T) {
	rt.Helper()
	expectations := []stabilityExpectation{
		m.softObject(types.NamespacedName{Name: m.account}, &v1alpha1.CloudflareAccount{}),
		m.softObject(types.NamespacedName{Name: m.config}, &v1alpha1.GatewayClassConfig{}),
		m.softObject(types.NamespacedName{Name: m.class}, &gatewayv1.GatewayClass{}),
		m.softObject(types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gatewayv1.Gateway{}),
	}
	if name := m.boundTunnelName(); name != "" {
		expectations = append(expectations,
			m.softObject(types.NamespacedName{Namespace: m.namespace, Name: name}, &v1alpha1.CloudflareTunnel{}))
	}
	if m.routeCreated {
		expectations = append(expectations,
			m.softObject(types.NamespacedName{Namespace: m.namespace, Name: m.route}, &gatewayv1.HTTPRoute{}))
	}
	if err := m.h.waitStable(context.Background(), expectations...); err != nil {
		rt.Fatalf("waitStable: %v", err)
	}
}

// waitForGrantDenialObserved keeps revocation on the warm account-watch path
// and waits until a bound tunnel with hostname work reports the new denial.
func (m *gatewayMachine) waitForGrantDenialObserved(rt *rapid.T) {
	rt.Helper()
	name := m.boundTunnelName()
	if name == "" {
		return
	}
	ctx := context.Background()
	var current v1alpha1.CloudflareTunnel
	if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, &current); err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		must2(rt, err, "get tunnel before grant denial")
	}
	if current.DeletionTimestamp != nil {
		return
	}
	hasBinding := m.gatewayCreated
	if current.Spec.Configuration.Mode == v1alpha1.CloudflareTunnelConfigurationModeDirect &&
		current.Spec.Configuration.Direct != nil {
		for _, ingress := range current.Spec.Configuration.Direct.Ingress {
			if ingress.Hostname == m.hostname || ingress.Hostname == m.altHost {
				hasBinding = true
			}
		}
	}
	if !hasBinding {
		return
	}
	denial := func(ctx context.Context, h *explorationHarness) (string, error) {
		var tunnel v1alpha1.CloudflareTunnel
		err := h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel)
		if apierrors.IsNotFound(err) {
			return "absent", nil
		}
		if err != nil {
			return "", err
		}
		accepted := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
		cleanupReason := accepted != nil && (accepted.Reason == "WaitingForDrain" ||
			accepted.Reason == "WaitingForOwnerDrain" || accepted.Reason == "TargetNotFound")
		if accepted == nil || accepted.Status != metav1.ConditionFalse ||
			!cleanupReason && !strings.Contains(strings.ToLower(accepted.Message), "not granted") {
			return "", fmt.Errorf("CloudflareTunnel %s has not observed hostname grant denial", name)
		}
		return tunnel.ResourceVersion, nil
	}
	if err := m.h.waitStable(ctx, denial); err != nil {
		rt.Fatalf("wait for grant denial: %v", err)
	}
}

// --- invariants ------------------------------------------------------------

// checkJournalOrder verifies two historical facts that can never become true
// retroactively: token verification precedes every account-scoped call, and
// tunnel creation precedes every tunnel-scoped call.
func (m *gatewayMachine) checkJournalOrder(rt *rapid.T) {
	journal := m.h.stub.Journal()
	accountPrefix := "/accounts/" + m.accountID + "/"
	collectionPath := accountPrefix + "cfd_tunnel"
	tunnelPrefix := collectionPath + "/"
	firstVerify, firstAccountCall := -1, -1
	firstTunnelCreate, firstTunnelCall := -1, -1
	for index, call := range journal {
		if firstVerify < 0 && call.Method == http.MethodGet && call.Path == "/user/tokens/verify" {
			firstVerify = index
		}
		if firstAccountCall < 0 && strings.HasPrefix(call.Path, accountPrefix) {
			firstAccountCall = index
		}
		if call.Path == collectionPath || strings.HasPrefix(call.Path, tunnelPrefix) {
			if firstTunnelCall < 0 {
				firstTunnelCall = index
			}
			if firstTunnelCreate < 0 && call.Method == http.MethodPost && call.Path == collectionPath {
				firstTunnelCreate = index
			}
		}
	}
	if firstAccountCall >= 0 && (firstVerify < 0 || firstVerify > firstAccountCall) {
		rt.Fatalf("journal order: account-scoped call at index %d precedes token verification at %d", firstAccountCall, firstVerify)
	}
	if firstTunnelCall >= 0 && (firstTunnelCreate < 0 || firstTunnelCreate > firstTunnelCall) {
		rt.Fatalf("journal order: tunnel-scoped call at index %d precedes tunnel creation at %d", firstTunnelCall, firstTunnelCreate)
	}
}

// checkAuthorizedMutation is the G1 invariant: while the account is
// unverified or a live tunnel has an authorization failure, no new remote
// object may be provisioned. Ownership-verified cleanup and withdrawal remain
// permitted by G1.
func (m *gatewayMachine) checkAuthorizedMutation(rt *rapid.T) {
	journal := m.h.stub.Journal()
	provisions := func(call cfstub.Call) bool {
		path := strings.SplitN(call.Path, "?", 2)[0]
		tunnelCollection := "/accounts/" + m.accountID + "/cfd_tunnel"
		if call.Method == http.MethodPost && path == tunnelCollection {
			return true
		}
		if call.Method == http.MethodPost && strings.HasSuffix(path, "/management") ||
			call.Method == http.MethodGet && strings.HasSuffix(path, "/token") {
			return true
		}
		if call.Method == http.MethodPatch && strings.HasPrefix(path, tunnelCollection+"/") &&
			!strings.Contains(path, "/configurations") {
			return true
		}
		if call.Method != http.MethodPost && call.Method != http.MethodPut && call.Method != http.MethodPatch {
			return false
		}
		if !strings.Contains(path, "/configurations") && !strings.Contains(path, "/dns_records") {
			return false
		}
		return strings.Contains(call.Body, m.hostname) || strings.Contains(call.Body, m.altHost)
	}

	if m.accountCreated {
		var account v1alpha1.CloudflareAccount
		if err := m.h.apiReader.Get(context.Background(), types.NamespacedName{Name: m.account}, &account); err == nil {
			verified := meta.IsStatusConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionAccepted) &&
				meta.IsStatusConditionTrue(account.Status.Conditions, v1alpha1.CloudflareAccountConditionCredentialsValid)
			if !verified {
				for _, call := range journal[m.accountUnverifiedMark:] {
					if provisions(call) {
						rt.Fatalf("G1: remote provisioning %s %s while account %s unverified", call.Method, call.Path, m.account)
					}
				}
			}
			m.accountUnverifiedMark = len(journal)
		}
	} else {
		m.accountUnverifiedMark = len(journal)
	}

	name := m.boundTunnelName()
	if name == "" {
		m.tunnelUnauthorizedMark = len(journal)
		return
	}
	var tunnel v1alpha1.CloudflareTunnel
	err := m.h.apiReader.Get(context.Background(), types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel)
	if apierrors.IsNotFound(err) {
		m.tunnelUnauthorizedMark = len(journal)
		return
	}
	must2(rt, err, "get bound CloudflareTunnel")
	if tunnel.DeletionTimestamp != nil {
		m.tunnelUnauthorizedMark = len(journal)
		return
	}
	accepted := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
	cleanupReason := accepted != nil && (accepted.Reason == "WaitingForDrain" ||
		accepted.Reason == "WaitingForOwnerDrain" || accepted.Reason == "TargetNotFound")
	if accepted == nil || accepted.Status != metav1.ConditionTrue && !cleanupReason {
		for _, call := range journal[m.tunnelUnauthorizedMark:] {
			if provisions(call) {
				rt.Fatalf("G1: remote provisioning %s %s while CloudflareTunnel %s is unauthorized", call.Method, call.Path, name)
			}
		}
	}
	m.tunnelUnauthorizedMark = len(journal)
}

// checkSingleWriter is the G4 invariant: configuration writes after a stable
// boundary require the current writer's ownership and drain prerequisites.
// During a transition, incumbent teardown writes remain allowed until the
// successor first reaches its valid write boundary.
func (m *gatewayMachine) checkSingleWriter(rt *rapid.T) {
	name := m.boundTunnelName()
	if name == "" {
		return
	}
	var tunnel v1alpha1.CloudflareTunnel
	err := m.h.apiReader.Get(context.Background(), types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel)
	if apierrors.IsNotFound(err) {
		return
	}
	must2(rt, err, "get bound CloudflareTunnel")
	if tunnel.DeletionTimestamp != nil {
		return
	}
	journal := m.h.stub.Journal()
	writes := 0
	for _, call := range journal[m.writerBoundary:] {
		if call.Method == http.MethodPut &&
			strings.HasSuffix(call.Path, "/configurations") &&
			strings.HasPrefix(call.Path, "/accounts/"+m.accountID+"/cfd_tunnel/") {
			writes++
		}
	}
	if writes == 0 {
		return
	}
	ready, reason := m.currentWriterReady(rt, &tunnel)
	if !ready {
		if m.writerBoundarySettled {
			rt.Fatalf("G4: %d tunnel configuration writes without current-writer prerequisites: %s", writes, reason)
		}
		return
	}
	m.writerBoundary = len(journal)
	m.writerBoundarySettled = true
}

func (m *gatewayMachine) currentWriterReady(rt *rapid.T, tunnel *v1alpha1.CloudflareTunnel) (bool, string) {
	if tunnel.Spec.Configuration.Mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		if !m.dataplaneDrained(rt, tunnel) {
			return false, "Direct-mode successor has an undrained Gateway dataplane"
		}
		return true, ""
	}
	var gateway gatewayv1.Gateway
	if err := m.h.apiReader.Get(context.Background(), types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gateway); err != nil {
		return false, "no live Gateway holds the tunnel"
	}
	if tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name != gateway.Name ||
		tunnel.Status.GatewayUID != gateway.UID || !tunnel.Status.OwnershipVerified {
		return false, "Gateway ownership is not UID-bound and verified"
	}
	return true, ""
}

// checkProgrammedConverged is the G5 invariant: Programmed=True is only
// reported when the desired and applied configuration versions, the remote
// version, the xDS ACK, the dataplane probe, and managed DNS have all
// converged.
func (m *gatewayMachine) checkProgrammedConverged(rt *rapid.T) {
	if !m.gatewayCreated {
		return
	}
	ctx := context.Background()
	var gateway gatewayv1.Gateway
	err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gateway)
	if apierrors.IsNotFound(err) {
		rt.Fatalf("Gateway %s unexpectedly absent", m.gateway)
	}
	must2(rt, err, "get Gateway")
	var gatewayClass gatewayv1.GatewayClass
	if err := m.h.apiReader.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, &gatewayClass); err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		must2(rt, err, "get GatewayClass for Programmed invariant")
	}
	if !meta.IsStatusConditionTrue(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed)) {
		return
	}

	name := m.boundTunnelName()
	var tunnel v1alpha1.CloudflareTunnel
	must2(rt, m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel), "get bound CloudflareTunnel")
	config := tunnel.Status.ConfigVersion
	if config.Desired == 0 || config.Applied != config.Desired {
		rt.Fatalf("G5: Programmed=True but config desired=%d applied=%d", config.Desired, config.Applied)
	}
	remote, ok := m.h.stub.State.TunnelConfiguration(tunnel.Status.TunnelID)
	if !ok || remote.Version != config.Applied {
		rt.Fatalf("G5: Programmed=True but remote config version %d != applied %d", remote.Version, config.Applied)
	}
	key := m.namespace + "/" + m.gateway
	version := m.h.snapshots.Version(key)
	if version == "" || !m.h.snapshots.IsACKed(key, version) {
		rt.Fatalf("G5: Programmed=True but snapshot %q is not ACKed", version)
	}
	var pods corev1.PodList
	must2(rt, m.h.apiReader.List(ctx, &pods,
		client.InNamespace(m.namespace),
		client.MatchingLabels{dataplane.StandardGatewayLabelKey: m.gateway}), "list dataplane Pods")
	probed := false
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.DeletionTimestamp == nil && pod.Status.PodIP != "" &&
			pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
			probed = true
		}
	}
	if !probed {
		rt.Fatalf("G5: Programmed=True but no active dataplane Pod with an IP exists")
	}
	if got := m.probe.version.Load(); got != config.Applied {
		rt.Fatalf("G5: Programmed=True but connector probe config version %d != applied %d", got, config.Applied)
	}
	if tunnel.Spec.DNS.Mode != v1alpha1.DNSModeExternal {
		statusRecords := make(map[string]bool, len(tunnel.Status.DNSRecords))
		for _, record := range tunnel.Status.DNSRecords {
			statusRecords[strings.ToLower(record.Hostname)] = true
		}
		remoteRecords := make(map[string]bool)
		for _, record := range m.h.stub.State.DNSRecords(m.zoneID) {
			if record.Proxied {
				remoteRecords[strings.ToLower(record.Name)] = true
			}
		}
		for _, listener := range gateway.Spec.Listeners {
			if listener.Hostname == nil {
				continue
			}
			hostname := strings.ToLower(string(*listener.Hostname))
			if !statusRecords[hostname] {
				rt.Fatalf("G5: Programmed=True but no managed DNS status for %s", *listener.Hostname)
			}
			if !remoteRecords[hostname] {
				rt.Fatalf("G5: Programmed=True but no proxied remote DNS record for %s", *listener.Hostname)
			}
		}
	}
}

// checkGrantDenial proves that a hostname grant revocation fails closed:
// listeners report the denial and no later write republishes either hostname.
func (m *gatewayMachine) checkGrantDenial(rt *rapid.T) {
	journal := m.h.stub.Journal()
	if !m.accountDenied || !m.accountCreated || !m.gatewayCreated {
		m.grantDeniedMark = len(journal)
		return
	}
	name := m.boundTunnelName()
	if name == "" {
		m.grantDeniedMark = len(journal)
		return
	}
	var tunnel v1alpha1.CloudflareTunnel
	if err := m.h.apiReader.Get(context.Background(),
		types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			m.grantDeniedMark = len(journal)
			return
		}
		must2(rt, err, "get denied CloudflareTunnel")
	}
	if tunnel.DeletionTimestamp != nil {
		m.grantDeniedMark = len(journal)
		return
	}
	accepted := meta.FindStatusCondition(tunnel.Status.Conditions, v1alpha1.CloudflareTunnelConditionAccepted)
	if accepted != nil && (accepted.Reason == "WaitingForDrain" ||
		accepted.Reason == "WaitingForOwnerDrain" || accepted.Reason == "TargetNotFound") {
		m.grantDeniedMark = len(journal)
		return
	}
	if tunnel.Spec.Configuration.Mode == v1alpha1.CloudflareTunnelConfigurationModeDirect {
		m.grantDeniedMark = len(journal)
		return
	}
	var gatewayClass gatewayv1.GatewayClass
	if err := m.h.apiReader.Get(context.Background(),
		types.NamespacedName{Name: m.class}, &gatewayClass); err != nil {
		if apierrors.IsNotFound(err) {
			m.grantDeniedMark = len(journal)
			return
		}
		must2(rt, err, "get denied GatewayClass")
	}
	var classConfig v1alpha1.GatewayClassConfig
	if err := m.h.apiReader.Get(context.Background(),
		types.NamespacedName{Name: m.config}, &classConfig); err != nil {
		if apierrors.IsNotFound(err) {
			m.grantDeniedMark = len(journal)
			return
		}
		must2(rt, err, "get denied GatewayClassConfig")
	}
	var gateway gatewayv1.Gateway
	must2(rt, m.h.apiReader.Get(context.Background(),
		types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gateway), "get denied Gateway")
	denied := false
	for _, listener := range gateway.Status.Listeners {
		for _, condition := range listener.Conditions {
			if condition.Type == string(gatewayv1.ListenerConditionAccepted) &&
				condition.Status == metav1.ConditionFalse &&
				strings.Contains(strings.ToLower(condition.Message), "not granted") {
				denied = true
			}
		}
	}
	if !denied {
		rt.Fatalf("G1/G3: Gateway listeners did not report hostname grant denial")
	}
	republishesHostname := func(call cfstub.Call) bool {
		if call.Method != http.MethodPost && call.Method != http.MethodPut {
			return false
		}
		if !strings.Contains(call.Path, "/configurations") && !strings.Contains(call.Path, "/dns_records") {
			return false
		}
		return strings.Contains(call.Body, m.hostname) || strings.Contains(call.Body, m.altHost)
	}
	for _, call := range journal[m.grantDeniedMark:] {
		if republishesHostname(call) {
			rt.Fatalf("G1/G3: grant-denied hostname was republished by %s %s", call.Method, call.Path)
		}
	}
	m.grantDeniedMark = len(journal)
}

// --- helpers ---------------------------------------------------------------

// boundTunnelName returns the tunnel the current Gateway binds to: the
// explicit parametersRef target, or the implicit tunnel named after the
// Gateway. It returns "" when no Gateway exists and no explicit tunnel was
// created.
func (m *gatewayMachine) boundTunnelName() string {
	if m.gatewayCreated {
		if m.gatewayRefExplicit {
			return m.tunnel
		}
		return m.gateway
	}
	if m.tunnelCreated {
		return m.tunnel
	}
	return ""
}

func (m *gatewayMachine) accountGrants() v1alpha1.CloudflareAccountGrant {
	hostnames := []string{"*"}
	unprotected := []string{m.hostname, m.altHost}
	if m.accountDenied {
		hostnames = []string{"denied." + m.zoneName}
		unprotected = nil
	}
	return v1alpha1.CloudflareAccountGrant{
		NamespaceSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": "gw-" + fmt.Sprint(m.iteration)},
		},
		Hostnames:            hostnames,
		Zones:                []string{"*"},
		Exposures:            []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate},
		UnprotectedHostnames: unprotected,
		PlatformObjects:      v1alpha1.GrantPermissionAllowed,
		Backends: &v1alpha1.CloudflareBackendGrant{
			Namespaces: v1alpha1.BackendNamespaceSame,
			Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
		},
	}
}

func (m *gatewayMachine) ensureNamespace(rt *rapid.T) {
	if m.nsCreated {
		return
	}
	must2(rt, m.h.client.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   m.namespace,
			Labels: map[string]string{"exploratory.flareway.bhyoo.com/tenant": "gw-" + fmt.Sprint(m.iteration)},
		},
	}), "create tenant namespace")
	m.nsCreated = true
}

func purgeGatewayObjects(rt *rapid.T, h *explorationHarness) {
	rt.Helper()
	ctx := context.Background()
	var namespaces corev1.NamespaceList
	must2(rt, h.apiReader.List(ctx, &namespaces), "list namespaces for purge")
	for index := range namespaces.Items {
		namespace := &namespaces.Items[index]
		if _, owned := namespace.Labels["exploratory.flareway.bhyoo.com/tenant"]; !owned {
			continue
		}
		for _, list := range []client.ObjectList{
			&gatewayv1.HTTPRouteList{},
			&gatewayv1.GatewayList{},
			&v1alpha1.CloudflareTunnelList{},
			&appsv1.DeploymentList{},
			&corev1.PodList{},
			&discoveryv1.EndpointSliceList{},
			&corev1.ServiceList{},
			&corev1.SecretList{},
		} {
			must2(rt, h.apiReader.List(ctx, list, client.InNamespace(namespace.Name)), "list namespaced gateway leftovers")
			purgeObjectList(rt, h, list)
		}
		purgeOne(rt, h, namespace)
	}
	for _, list := range []client.ObjectList{
		&gatewayv1.GatewayClassList{},
		&v1alpha1.GatewayClassConfigList{},
		&v1alpha1.CloudflareAccountList{},
	} {
		must2(rt, h.apiReader.List(ctx, list), "list cluster-scoped gateway leftovers")
		purgeObjectList(rt, h, list)
	}
}

func purgeObjectList(rt *rapid.T, h *explorationHarness, list client.ObjectList) {
	rt.Helper()
	objects, err := meta.ExtractList(list)
	must2(rt, err, "extract gateway leftovers")
	for _, item := range objects {
		object, ok := item.(client.Object)
		if !ok {
			rt.Fatalf("purge object %T does not implement client.Object", item)
		}
		purgeOne(rt, h, object)
	}
}

func purgeOne(rt *rapid.T, h *explorationHarness, object client.Object) {
	rt.Helper()
	ctx := context.Background()
	if len(object.GetFinalizers()) > 0 {
		base := object.DeepCopyObject().(client.Object)
		object.SetFinalizers(nil)
		must2(rt, h.client.Patch(ctx, object, client.MergeFrom(base)), "strip gateway leftover finalizers")
	}
	must2(rt, client.IgnoreNotFound(h.client.Delete(ctx, object)), "delete gateway leftover")
}

// softObject returns a stabilityExpectation satisfied by either presence or
// absence; the fingerprint is the resourceVersion so status writes reset the
// stability counter.
func (m *gatewayMachine) softObject(key types.NamespacedName, object client.Object) stabilityExpectation {
	return func(ctx context.Context, h *explorationHarness) (string, error) {
		if err := h.apiReader.Get(ctx, key, object); err != nil {
			if apierrors.IsNotFound(err) {
				return "absent", nil
			}
			return "", err
		}
		return object.GetResourceVersion(), nil
	}
}

// dataplaneDrained mirrors the production drain predicate: only the recorded
// owner's Deployment and Pods carrying the current tunnel token can block.
func (m *gatewayMachine) dataplaneDrained(rt *rapid.T, tunnel *v1alpha1.CloudflareTunnel) bool {
	if tunnel.Status.GatewayRef == nil || tunnel.Status.GatewayRef.Name == "" {
		return true
	}
	tokenSecret := ""
	if tunnel.Status.ConnectorTokenSecretRef != nil {
		tokenSecret = tunnel.Status.ConnectorTokenSecretRef.Name
	}
	ctx := context.Background()
	var deployment appsv1.Deployment
	err := m.h.apiReader.Get(ctx, types.NamespacedName{
		Namespace: m.namespace,
		Name:      dataplane.ResourceName(&ir.Gateway{Key: types.NamespacedName{Namespace: m.namespace, Name: tunnel.Status.GatewayRef.Name}}),
	}, &deployment)
	if err != nil && !apierrors.IsNotFound(err) {
		must2(rt, err, "get recorded dataplane Deployment")
	}
	deploymentRelevant := err == nil && gatewayDeploymentBelongsToRecordedTunnelOwner(&deployment, tunnel, tokenSecret)
	if deploymentRelevant && (deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0) {
		return false
	}
	var pods corev1.PodList
	must2(rt, m.h.apiReader.List(ctx, &pods,
		client.InNamespace(m.namespace),
		client.MatchingLabels{dataplane.GatewayLabelKey: m.namespace + "--" + tunnel.Status.GatewayRef.Name}), "list recorded dataplane Pods")
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if tokenSecret != "" && gatewayPodSpecUsesToken(&pod.Spec, tokenSecret) ||
			tokenSecret == "" && deploymentRelevant {
			return false
		}
	}
	return true
}

func gatewayDeploymentBelongsToRecordedTunnelOwner(
	deployment *appsv1.Deployment,
	tunnel *v1alpha1.CloudflareTunnel,
	tokenSecret string,
) bool {
	if tunnel.Status.GatewayUID != "" {
		for _, owner := range deployment.OwnerReferences {
			if owner.APIVersion == gatewayv1.GroupVersion.String() &&
				owner.Kind == "Gateway" &&
				owner.UID == tunnel.Status.GatewayUID {
				return true
			}
		}
	}
	return tokenSecret != "" && gatewayPodSpecUsesToken(&deployment.Spec.Template.Spec, tokenSecret)
}

func gatewayPodSpecUsesToken(spec *corev1.PodSpec, secretName string) bool {
	if spec == nil {
		return false
	}
	for index := range spec.Containers {
		container := &spec.Containers[index]
		if container.Name != "cloudflared" {
			continue
		}
		if secretName == "" {
			return true
		}
		for envIndex := range container.Env {
			env := &container.Env[envIndex]
			if env.Name == "TUNNEL_TOKEN" && env.ValueFrom != nil &&
				env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == secretName {
				return true
			}
		}
	}
	return false
}

// markDeploymentAvailable synthesizes the Deployment Available condition a
// kubelet-driven rollout would produce.
func (m *gatewayMachine) markDeploymentAvailable(rt *rapid.T) {
	key := types.NamespacedName{
		Namespace: m.namespace,
		Name:      dataplane.ResourceName(&ir.Gateway{Key: types.NamespacedName{Namespace: m.namespace, Name: m.gateway}}),
	}
	if err := envtesthelpers.MarkDeploymentAvailable(context.Background(), m.h.client, key); err != nil {
		rt.Logf("synthesize Deployment Available: %v", err)
	}
}

// currentTunnelID returns the remote tunnel ID recorded on the bound tunnel.
func (m *gatewayMachine) currentTunnelID() string {
	name := m.boundTunnelName()
	if name == "" {
		return ""
	}
	var tunnel v1alpha1.CloudflareTunnel
	if err := m.h.apiReader.Get(context.Background(),
		types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel); err != nil {
		return ""
	}
	return tunnel.Status.TunnelID
}

// refreshProbeTunnel points the probe server at the bound tunnel so /config
// reports that tunnel's remote configuration version.
func (m *gatewayMachine) refreshProbeTunnel() {
	m.probe.setTunnel(m.currentTunnelID())
}

// recordConditions appends the observable status of every object in this
// iteration to the trace.
func (m *gatewayMachine) recordConditions(rt *rapid.T) {
	ctx := context.Background()
	var account v1alpha1.CloudflareAccount
	if err := m.h.apiReader.Get(ctx, types.NamespacedName{Name: m.account}, &account); err == nil {
		for _, condition := range account.Status.Conditions {
			m.recorder.RecordCondition("CloudflareAccount", condition.Type, string(condition.Status), condition.Reason)
		}
	}
	var gateway gatewayv1.Gateway
	if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: m.gateway}, &gateway); err == nil {
		for _, condition := range gateway.Status.Conditions {
			m.recorder.RecordCondition("Gateway", condition.Type, string(condition.Status), condition.Reason)
		}
	}
	if name := m.boundTunnelName(); name != "" {
		var tunnel v1alpha1.CloudflareTunnel
		if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: name}, &tunnel); err == nil {
			for _, condition := range tunnel.Status.Conditions {
				m.recorder.RecordCondition("CloudflareTunnel", condition.Type, string(condition.Status), condition.Reason)
			}
			var tokenSecret corev1.Secret
			if tunnel.Status.ConnectorTokenSecretRef != nil {
				key := types.NamespacedName{Namespace: m.namespace, Name: tunnel.Status.ConnectorTokenSecretRef.Name}
				if err := m.h.apiReader.Get(ctx, key, &tokenSecret); err == nil {
					m.recorder.RecordSecret(tokenSecret.Data)
				}
			}
		}
	}
	var route gatewayv1.HTTPRoute
	if err := m.h.apiReader.Get(ctx, types.NamespacedName{Namespace: m.namespace, Name: m.route}, &route); err == nil {
		for _, parent := range route.Status.Parents {
			for _, condition := range parent.Conditions {
				m.recorder.RecordCondition("HTTPRoute", condition.Type, string(condition.Status), condition.Reason)
			}
		}
	}
}

func (m *gatewayMachine) record(rt *rapid.T, action, outcome string) {
	m.recorder.Record(action, outcome, len(m.h.stub.Journal()))
}

func must2(rt *rapid.T, err error, what string) {
	rt.Helper()
	if err != nil {
		rt.Fatalf("%s: %v", what, err)
	}
}

// gatewayProbeServer answers the cloudflared /ready and /config endpoints the
// production prober dials on <podIP>:2000. Its observed version advances only
// through SyncConnectorConfig, independently of the remote API version.
type gatewayProbeServer struct {
	listener net.Listener
	server   *http.Server
	tunnelID atomic.Value
	version  atomic.Int64
	ready    atomic.Bool
}

func newGatewayProbeServer() *gatewayProbeServer {
	server := &gatewayProbeServer{}
	server.tunnelID.Store("")
	return server
}

func (p *gatewayProbeServer) setTunnel(tunnelID string) {
	current, _ := p.tunnelID.Load().(string)
	if current != tunnelID {
		p.tunnelID.Store(tunnelID)
		p.version.Store(0)
	}
}

func (p *gatewayProbeServer) setVersion(version int64) {
	p.version.Store(version)
}

func (p *gatewayProbeServer) setReady(ready bool) {
	p.ready.Store(ready)
}

// ensure lazily binds the probe port.
func (p *gatewayProbeServer) ensure() error {
	if p.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", gatewayProbePort))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		if p.ready.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, _ *http.Request) {
		version := p.version.Load()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"version":%d}`, version)
	})
	p.listener = listener
	p.server = &http.Server{Handler: mux}
	go func() { _ = p.server.Serve(listener) }()
	return nil
}

func (p *gatewayProbeServer) close() {
	if p.server != nil {
		_ = p.server.Close()
	}
}
