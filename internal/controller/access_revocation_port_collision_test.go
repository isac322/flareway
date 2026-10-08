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
	"testing"
	"time"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
	"github.com/isac322/flareway/internal/ir"
	"github.com/isac322/flareway/internal/xds/translator"
)

const revokedPreviewDomain = "preview-access-default-app-a-9f8e7d6c"

// revokedTombstoneInputs models a Gateway whose wildcard listener "preview"
// lost its last HTTPRoute. AccessApplication app-a protected it, is now
// revocation-latched, and its status still records the Envoy port the applied
// tunnel configuration routes pr-123.example.com to. app-b protects the live
// listener "web".
func revokedTombstoneInputs(tombstonePort int32) gatewayapi.Inputs {
	wildcard := gatewayv1.Hostname("*.example.com")
	hostB := gatewayv1.Hostname("b.example.com")
	sectionPreview := gatewayv1.SectionName("preview")
	sectionWeb := gatewayv1.SectionName("web")
	pathPrefix := gatewayv1.PathMatchPathPrefix
	root := "/"
	target := func(section *gatewayv1.SectionName) []gatewayv1.LocalPolicyTargetReferenceWithSectionName {
		return []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
				Group: gatewayv1.Group(gatewayv1.GroupName), Kind: "Gateway", Name: "edge-gw",
			},
			SectionName: section,
		}}
	}
	appA := v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app-a", Namespace: "default", UID: types.UID("app-a-uid"),
			CreationTimestamp: metav1.NewTime(time.Unix(10, 0)),
			Annotations: map[string]string{
				accessApplicationRevocationAnnotation: `{"claims":[{"tunnel":"edge","protectionDomain":"` + revokedPreviewDomain + `","hostname":"pr-123.example.com","baselineVersion":1}]}`,
			},
		},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: target(&sectionPreview),
			OriginJWT:  v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
		},
		Status: v1alpha1.AccessApplicationStatus{
			Destinations: []v1alpha1.AccessApplicationDestinationStatus{{URI: "pr-123.example.com"}},
			DataPlanes: []v1alpha1.AccessApplicationDataPlaneStatus{{
				Tunnel: "edge", Listener: sectionPreview, ProtectionDomain: revokedPreviewDomain, EnvoyPort: tombstonePort,
			}},
		},
	}
	appB := v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app-b", Namespace: "default", UID: types.UID("app-b-uid"),
			CreationTimestamp: metav1.NewTime(time.Unix(11, 0)),
		},
		Spec: v1alpha1.AccessApplicationSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"},
			Type:       v1alpha1.AccessApplicationTypeSelfHosted,
			SelfHosted: &v1alpha1.AccessSelfHostedApplicationSpec{},
			TargetRefs: target(&sectionWeb),
			OriginJWT:  v1alpha1.AccessOriginJWTSpec{Mode: v1alpha1.AccessOriginJWTModeRequired},
		},
	}
	tunnel := &v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"},
		Spec:       v1alpha1.CloudflareTunnelSpec{ManagementPolicy: v1alpha1.ManagementPolicyManaged},
		Status: v1alpha1.CloudflareTunnelStatus{
			OwnershipVerified:       true,
			TunnelID:                "tunnel-id",
			ConnectorTokenSecretRef: &corev1.LocalObjectReference{Name: "edge-token"},
			GatewayRef:              &corev1.LocalObjectReference{Name: "edge-gw"},
			GatewayUID:              types.UID("edge-gw-uid"),
			ConfigVersion:           v1alpha1.CloudflareTunnelConfigVersion{DesiredHash: "stale-hash", Applied: 3},
			// The applied tunnel config still forwards the revoked host to
			// the tombstone port until the Blocked guard is applied.
			Hostnames: []v1alpha1.CloudflareTunnelHostnameStatus{{
				Hostname: "pr-123.example.com", ProtectionDomain: revokedPreviewDomain,
				AccessApplication: "default/app-a", Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 3,
			}},
		},
	}
	return gatewayapi.Inputs{
		Now: metav1.NewTime(time.Unix(100, 0).UTC()),
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "edge-gw", Namespace: "default", UID: types.UID("edge-gw-uid"), Generation: 2},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "flareway",
				Listeners: []gatewayv1.Listener{
					// Edge-terminated HTTPS: Envoy serves cleartext on loopback.
					{Name: "preview", Hostname: &wildcard, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
					{Name: "web", Hostname: &hostB, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		},
		GatewayClass: &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "flareway"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayapi.ControllerName},
		},
		GatewayClassConfig: &v1alpha1.GatewayClassConfig{},
		CloudflareTunnel:   tunnel,
		CloudflareAccount: &v1alpha1.CloudflareAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "account"},
			Spec: v1alpha1.CloudflareAccountSpec{
				AccountID: "0123456789abcdef0123456789abcdef",
				Grants: []v1alpha1.CloudflareAccountGrant{{
					NamespaceSelector: metav1.LabelSelector{},
					Hostnames:         []string{"*.example.com", "b.example.com"},
					Zones:             []string{"example.com"},
					Exposures:         []v1alpha1.Exposure{v1alpha1.ExposurePublic},
					Backends: &v1alpha1.CloudflareBackendGrant{
						Namespaces: v1alpha1.BackendNamespaceSame,
						Kinds:      []v1alpha1.BackendKind{v1alpha1.BackendKindService},
					},
				}},
			},
			Status: v1alpha1.CloudflareAccountStatus{
				Verified: v1alpha1.CloudflareAccountVerifiedStatus{TeamName: "team", AuthDomain: "team.cloudflareaccess.com"},
			},
		},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		HTTPRoutes: []gatewayv1.HTTPRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "b-route", Namespace: "default", Generation: 1},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{
					Name: "edge-gw", SectionName: &sectionWeb,
				}}},
				Hostnames: []gatewayv1.Hostname{"b.example.com"},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: &root}}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: new(gatewayv1.PortNumber(8080))},
					}}},
				}},
			},
		}},
		AccessApplications: []v1alpha1.AccessApplication{appA, appB},
		AUDSecrets: map[types.NamespacedName]gatewayapi.AUDSecret{
			{Namespace: "default", Name: "app-b"}: {AUD: "aud-b", ApplicationID: "app-b-id", Ready: true},
		},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
		}},
	}
}

// buildRevokedGateway runs the Gateway reconcile pipeline on inputs —
// Translate, tombstone retention, the block-first transition, and the xDS
// build — and returns the IR the snapshot was built from.
func buildRevokedGateway(t *testing.T, inputs gatewayapi.Inputs) (*ir.Gateway, gatewayapi.Statuses) {
	t.Helper()
	compiled, statuses := gatewayapi.Translate(inputs)
	if compiled == nil {
		t.Fatal("Translate returned nil Gateway")
	}
	retainAccessRevocationDomains(compiled, inputs.CloudflareTunnel, inputs.AccessApplications)
	compiled, _, err := accessBlockFirstGateway(compiled, inputs.CloudflareTunnel)
	if err != nil {
		t.Fatalf("accessBlockFirstGateway: %v", err)
	}
	if _, err := translator.Build(compiled, nil); err != nil {
		t.Fatalf("xDS snapshot must build: %v", err)
	}
	return compiled, statuses
}

func domainOf(gateway *ir.Gateway, application string) *ir.ProtectionDomain {
	for index := range gateway.Domains {
		if gateway.Domains[index].AccessApplication == application {
			return &gateway.Domains[index]
		}
	}
	return nil
}

func listenerPort(t *testing.T, gateway *ir.Gateway, name string) int32 {
	t.Helper()
	for _, listener := range gateway.Listeners {
		if listener.Name == name {
			return listener.EnvoyPort
		}
	}
	t.Fatalf("listener %q missing from %#v", name, gateway.Listeners)
	return 0
}

func assertTombstoneAt(t *testing.T, gateway *ir.Gateway, port int32) {
	t.Helper()
	tombstone := domainOf(gateway, "default/app-a")
	if tombstone == nil || tombstone.Name != revokedPreviewDomain || tombstone.Guard != ir.GuardBlocked {
		t.Fatalf("revocation tombstone = %#v, want Blocked %s", tombstone, revokedPreviewDomain)
	}
	if tombstone.EnvoyPort != port {
		t.Fatalf("tombstone port = %d, want the applied tunnel port %d", tombstone.EnvoyPort, port)
	}
}

// assertLiveAppBAvoids checks that app-b's live domain stays off the
// tombstone port and that its compiled status records the port it binds.
func assertLiveAppBAvoids(t *testing.T, gateway *ir.Gateway, statuses gatewayapi.Statuses, port int32) {
	t.Helper()
	live := domainOf(gateway, "default/app-b")
	if live == nil || live.Guard != ir.GuardForwarding {
		t.Fatalf("app-b live protected domain = %#v in %#v", live, gateway.Domains)
	}
	if live.EnvoyPort == port {
		t.Fatalf("app-b live domain shares the tombstone port %d", port)
	}
	compiled := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "app-b"}]
	if len(compiled.DataPlanes) != 1 || compiled.DataPlanes[0].EnvoyPort != live.EnvoyPort ||
		compiled.DataPlanes[0].ProtectionDomain != live.Name {
		t.Fatalf("app-b status data planes = %#v, want %s on %d", compiled.DataPlanes, live.Name, live.EnvoyPort)
	}
}

// A revoked application's tombstone keeps the Access port the applied tunnel
// config routes its host to; the next live Access host must not take it
// (isac322/flareway#141).
func TestRevokedAccessTombstoneKeepsItsPortFromLiveAccessHosts(t *testing.T) {
	const tombstonePort = int32(18082)
	gateway, statuses := buildRevokedGateway(t, revokedTombstoneInputs(tombstonePort))
	if got := statuses.AccessApplications[types.NamespacedName{Namespace: "default", Name: "app-a"}]; got.Accepted || got.Reason != "TargetNotFound" {
		t.Fatalf("app-a after route deletion = %#v, want rejected TargetNotFound", got)
	}
	assertTombstoneAt(t, gateway, tombstonePort)
	assertLiveAppBAvoids(t, gateway, statuses, tombstonePort)
}

// A tombstone holding a port that a public listener takes by position pushes
// that listener, and every port after it, past the tombstone. The "api"
// listener is granted as unprotected and serves a public route, so it binds an
// unprotected cleartext chain on its Envoy port.
func TestRevokedAccessTombstoneKeepsItsPortFromShiftedListeners(t *testing.T) {
	const tombstonePort = int32(18081)
	inputs := revokedTombstoneInputs(tombstonePort)
	hostAPI := gatewayv1.Hostname("api.example.com")
	sectionAPI := gatewayv1.SectionName("api")
	inputs.Gateway.Spec.Listeners = []gatewayv1.Listener{
		inputs.Gateway.Spec.Listeners[0],
		{Name: sectionAPI, Hostname: &hostAPI, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		inputs.Gateway.Spec.Listeners[1],
	}
	apiRoute := *inputs.HTTPRoutes[0].DeepCopy()
	apiRoute.Name = "api-route"
	apiRoute.Spec.ParentRefs[0].SectionName = &sectionAPI
	apiRoute.Spec.Hostnames = []gatewayv1.Hostname{hostAPI}
	inputs.HTTPRoutes = append(inputs.HTTPRoutes, apiRoute)
	inputs.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{string(hostAPI)}

	gateway, statuses := buildRevokedGateway(t, inputs)
	for listener, want := range map[string]int32{"preview": 18080, "api": 18082, "web": 18083} {
		if port := listenerPort(t, gateway, listener); port != want {
			t.Fatalf("%s listener port = %d, want %d past the tombstone", listener, port, want)
		}
	}
	assertTombstoneAt(t, gateway, tombstonePort)
	assertLiveAppBAvoids(t, gateway, statuses, tombstonePort)
}

// When a tombstone pushes the positional public sequence past its port, the
// moved ports must also stay off the fixed spec.Port of a private listener:
// private domains always bind that port, and a shifted public bind landing on
// it collides the same way the tombstone did.
func TestRevokedAccessTombstoneShiftKeepsPublicPortsOffPrivateListener(t *testing.T) {
	const tombstonePort = int32(18080)
	inputs := revokedTombstoneInputs(tombstonePort)
	inputs.AccessApplications = inputs.AccessApplications[:1]
	gomega.RegisterTestingT(t)
	hostAPI := gatewayv1.Hostname("api.example.com")
	hostPrivate := gatewayv1.Hostname("private.example.com")
	inputs.Gateway.Spec.Listeners = []gatewayv1.Listener{
		inputs.Gateway.Spec.Listeners[0],
		{Name: "api", Hostname: &hostAPI, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "private", Hostname: &hostPrivate, Port: 18082, Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "private-cert"}}}},
	}
	inputs.CloudflareTunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{
		Name: "private", Exposure: v1alpha1.ExposurePrivate,
	}}
	inputs.CloudflareAccount.Spec.Grants[0].Hostnames = append(inputs.CloudflareAccount.Spec.Grants[0].Hostnames, "api.example.com", "private.example.com")
	inputs.CloudflareAccount.Spec.Grants[0].Exposures = append(inputs.CloudflareAccount.Spec.Grants[0].Exposures, v1alpha1.ExposurePrivate)
	inputs.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{string(hostAPI)}
	inputs.Secrets = []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "private-cert", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       qa92TLSSecretData(t),
	}}

	apiRoute := *inputs.HTTPRoutes[0].DeepCopy()
	apiRoute.Name = "api-route"
	apiRoute.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("api"))
	apiRoute.Spec.Hostnames = []gatewayv1.Hostname{hostAPI}
	privateRoute := *inputs.HTTPRoutes[0].DeepCopy()
	privateRoute.Name = "private-route"
	privateRoute.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("private"))
	privateRoute.Spec.Hostnames = []gatewayv1.Hostname{hostPrivate}
	inputs.HTTPRoutes = append(inputs.HTTPRoutes, apiRoute, privateRoute)

	gateway, _ := buildRevokedGateway(t, inputs)
	for listener, want := range map[string]int32{"preview": 18081, "api": 18083} {
		if port := listenerPort(t, gateway, listener); port != want {
			t.Fatalf("%s listener port = %d, want %d past the tombstone and private ports", listener, port, want)
		}
	}
	assertTombstoneAt(t, gateway, tombstonePort)
}

// A revoked application whose data plane belongs to another tunnel has no
// tombstone on this Gateway and reserves no port.
func TestRevokedAccessDataPlaneOnOtherTunnelReservesNoPort(t *testing.T) {
	inputs := revokedTombstoneInputs(18081)
	inputs.AccessApplications[0].Status.DataPlanes[0].Tunnel = "other"
	gateway, statuses := buildRevokedGateway(t, inputs)
	if tombstone := domainOf(gateway, "default/app-a"); tombstone != nil {
		t.Fatalf("tombstone for another tunnel retained: %#v", tombstone)
	}
	if port := listenerPort(t, gateway, "web"); port != 18081 {
		t.Fatalf("web listener port = %d, want positional 18081", port)
	}
	if live := domainOf(gateway, "default/app-b"); live == nil || live.EnvoyPort != 18082 {
		t.Fatalf("app-b live domain = %#v, want positional port 18082", live)
	}
	assertLiveAppBAvoids(t, gateway, statuses, 0)
}

// A revocation-latched application that still compiles its recorded domain
// keeps that domain live, so its recorded port is not reserved and the
// allocation stays positional instead of moving on every reconcile.
func TestRevokedAccessDomainStillLiveKeepsPositionalPort(t *testing.T) {
	inputs := revokedTombstoneInputs(18082)
	inputs.AccessApplications = inputs.AccessApplications[1:]
	appB := &inputs.AccessApplications[0]
	appB.Annotations = map[string]string{accessApplicationRevocationAnnotation: `{"claims":[]}`}
	first, _ := gatewayapi.Translate(inputs)
	live := domainOf(first, "default/app-b")
	if live == nil || live.EnvoyPort != 18082 {
		t.Fatalf("app-b live domain = %#v, want positional port 18082", live)
	}
	appB.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
		Tunnel: "edge", Listener: "web", ProtectionDomain: live.Name, EnvoyPort: live.EnvoyPort,
	}}
	appB.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{URI: "b.example.com"}}
	inputs.CloudflareTunnel.Status.Hostnames = []v1alpha1.CloudflareTunnelHostnameStatus{{
		Hostname: "b.example.com", ProtectionDomain: live.Name, AccessApplication: "default/app-b",
		Guard: v1alpha1.HostnameGuardForwarding, AppliedVersion: 3,
	}}
	gateway, _ := buildRevokedGateway(t, inputs)
	if again := domainOf(gateway, "default/app-b"); again == nil || again.Name != live.Name || again.EnvoyPort != 18082 {
		t.Fatalf("latched but live app-b domain = %#v, want %s to keep port 18082", again, live.Name)
	}
}
