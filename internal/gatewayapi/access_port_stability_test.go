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

package gatewayapi

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

func TestStickyPublicEnvoyPortsSurviveListenerAdditionsRemovalsAndUpgrade(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"public.example.com", "front.example.com", "back.example.com"}
	hostPublic := gatewayv1.Hostname("public.example.com")
	hostA := gatewayv1.Hostname("a.example.com")
	hostB := gatewayv1.Hostname("b.example.com")
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: "public", Hostname: &hostPublic, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "a", Hostname: &hostA, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "b", Hostname: &hostB, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
	}
	routePublic := routeWithBackend("public", "backend", 8080)
	routePublic.Spec.Hostnames = []gatewayv1.Hostname{hostPublic}
	routePublic.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("public"))
	routeA := routeWithBackend("a", "backend", 8080)
	routeA.Spec.Hostnames = []gatewayv1.Hostname{hostA}
	routeA.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("a"))
	routeB := routeWithBackend("b", "backend", 8080)
	routeB.Spec.Hostnames = []gatewayv1.Hostname{hostB}
	routeB.Spec.ParentRefs[0].SectionName = new(gatewayv1.SectionName("b"))
	in.HTTPRoutes = []gatewayv1.HTTPRoute{routePublic, routeA, routeB}

	appA := accessApplication("app-a", "Gateway", "gateway", "a")
	appB := accessApplication("app-b", "Gateway", "gateway", "b")
	in.AccessApplications = []v1alpha1.AccessApplication{appA, appB}
	in.AUDSecrets = map[types.NamespacedName]AUDSecret{
		{Namespace: "default", Name: "app-a"}: {AUD: "aud-a", ApplicationID: "id-a", Ready: true},
		{Namespace: "default", Name: "app-b"}: {AUD: "aud-b", ApplicationID: "id-b", Ready: true},
	}

	// Simulate an existing v0.4.1 Tunnel status with sequential ports.
	initial, _ := Translate(in)
	portPublic := findDomainByName(t, initial.Domains, "public").EnvoyPort
	domainA := findAccessDomain(initial.Domains, "default/app-a")
	domainB := findAccessDomain(initial.Domains, "default/app-b")
	if domainA == nil || domainB == nil {
		t.Fatalf("missing initial protected domains: %#v", initial.Domains)
	}
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{
		{Name: "public", Exposure: v1alpha1.ExposurePublic, ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: "public", EnvoyPort: portPublic}}},
		{Name: "a", Exposure: v1alpha1.ExposurePublic, ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: domainA.Name, EnvoyPort: domainA.EnvoyPort, Protected: true}}},
		{Name: "b", Exposure: v1alpha1.ExposurePublic, ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: domainB.Name, EnvoyPort: domainB.EnvoyPort, Protected: true}}},
	}

	// Insert a new public listener at index 0 and append another at the end:
	// none of the existing listeners or protected domains may shift ports.
	hostFront := gatewayv1.Hostname("front.example.com")
	hostBack := gatewayv1.Hostname("back.example.com")
	in.Gateway.Spec.Listeners = append(
		[]gatewayv1.Listener{{Name: "front", Hostname: &hostFront, Port: 443, Protocol: gatewayv1.HTTPSProtocolType}},
		append(in.Gateway.Spec.Listeners, gatewayv1.Listener{Name: "back", Hostname: &hostBack, Port: 443, Protocol: gatewayv1.HTTPSProtocolType})...,
	)
	afterAdd, _ := Translate(in)
	if got := findDomainByName(t, afterAdd.Domains, "public").EnvoyPort; got != portPublic {
		t.Fatalf("public listener shifted port on add: got %d, want %d", got, portPublic)
	}
	if got := findAccessDomain(afterAdd.Domains, "default/app-a").EnvoyPort; got != domainA.EnvoyPort {
		t.Fatalf("app-a shifted port on add: got %d, want %d", got, domainA.EnvoyPort)
	}
	if got := findAccessDomain(afterAdd.Domains, "default/app-b").EnvoyPort; got != domainB.EnvoyPort {
		t.Fatalf("app-b shifted port on add: got %d, want %d", got, domainB.EnvoyPort)
	}
	portFront := findDomainByName(t, afterAdd.Domains, "front").EnvoyPort
	portBack := findDomainByName(t, afterAdd.Domains, "back").EnvoyPort
	used := map[int32]bool{portPublic: true, domainA.EnvoyPort: true, domainB.EnvoyPort: true}
	if used[portFront] || used[portBack] || portFront == portBack {
		t.Fatalf("new listeners collided with existing ports: front=%d back=%d existing=%v", portFront, portBack, used)
	}

	// Remove "public" and "front"; "a" and "b" must still keep their recorded ports.
	in.Gateway.Spec.Listeners = in.Gateway.Spec.Listeners[2:]
	afterRemove, _ := Translate(in)
	if got := findAccessDomain(afterRemove.Domains, "default/app-a").EnvoyPort; got != domainA.EnvoyPort {
		t.Fatalf("app-a shifted port on removal: got %d, want %d", got, domainA.EnvoyPort)
	}
	if got := findAccessDomain(afterRemove.Domains, "default/app-b").EnvoyPort; got != domainB.EnvoyPort {
		t.Fatalf("app-b shifted port on removal: got %d, want %d", got, domainB.EnvoyPort)
	}
}

func TestStickyPublicPortsAvoidPrivateAndTombstonePorts(t *testing.T) {
	in := accessInputs(true)
	in.CloudflareAccount.Spec.Grants[0].Hostnames = []string{"*.example.com"}
	in.CloudflareAccount.Spec.Grants[0].UnprotectedHostnames = []string{"public.example.com"}
	in.CloudflareAccount.Spec.Grants[0].Exposures = []v1alpha1.Exposure{v1alpha1.ExposurePublic, v1alpha1.ExposurePrivate}
	hostPublic := gatewayv1.Hostname("public.example.com")
	hostPrivate := gatewayv1.Hostname("private.example.com")
	// Intentionally test a private listener on a port in the public range.
	in.Gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: "public", Hostname: &hostPublic, Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "private", Hostname: &hostPrivate, Port: 18085, Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "cert"}}}},
	}
	in.Secrets = []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "cert", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: []byte("c"), corev1.TLSPrivateKeyKey: []byte("k")},
	}}
	in.CloudflareTunnel.Name = "edge"
	in.CloudflareTunnel.Spec.Listeners = []v1alpha1.CloudflareTunnelListener{{Name: "private", Exposure: v1alpha1.ExposurePrivate}}
	// Simulate stale status where public was previously on 18085 or 18086, while 18086 is now a tombstone.
	in.CloudflareTunnel.Status.Listeners = []v1alpha1.CloudflareTunnelListenerStatus{
		{Name: "public", Exposure: v1alpha1.ExposurePublic, ProtectionDomains: []v1alpha1.CloudflareProtectionDomainStatus{{Name: "public", EnvoyPort: 18085}}},
	}
	appOld := accessApplication("app-old", "Gateway", "gateway", "gone")
	appOld.CreationTimestamp = metav1.NewTime(time.Unix(9, 0))
	appOld.Annotations = map[string]string{AccessRevocationAnnotation: `{"claims":[]}`}
	appOld.Status.DataPlanes = []v1alpha1.AccessApplicationDataPlaneStatus{{
		Tunnel: "edge", Listener: "gone", ProtectionDomain: "old-domain", EnvoyPort: 18086,
	}}
	appOld.Status.Destinations = []v1alpha1.AccessApplicationDestinationStatus{{Hostname: "gone.example.com"}}
	in.AccessApplications = []v1alpha1.AccessApplication{appOld}

	gw, _ := Translate(in)
	publicDomain := findDomainByName(t, gw.Domains, "public")
	if publicDomain.EnvoyPort == 18085 || publicDomain.EnvoyPort == 18086 {
		t.Fatalf("public domain reused reserved private/tombstone port %d", publicDomain.EnvoyPort)
	}
}

func findDomainByName(t *testing.T, domains []ir.ProtectionDomain, name string) ir.ProtectionDomain {
	t.Helper()
	for _, domain := range domains {
		if domain.Name == name {
			return domain
		}
	}
	t.Fatalf("domain %q not found in %#v", name, domains)
	return ir.ProtectionDomain{}
}
