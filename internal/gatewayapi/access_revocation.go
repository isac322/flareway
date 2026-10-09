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
	"fmt"
	"slices"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
)

// AccessRevocationAnnotation latches an AccessApplication revocation until
// every issued token is revoked and the data plane blocks its hosts.
const AccessRevocationAnnotation = "flareway.bhyoo.com/access-revocation"

// AccessRevocationTombstone is a data plane of a revoked AccessApplication
// that keeps serving its hosts as a Blocked protection domain. The applied
// tunnel configuration still routes those hosts to EnvoyPort, so the
// tombstone must stay bound there, no live listener or domain may take it, and
// nothing else may serve its hosts except as Blocked: on every public listener
// for a public tombstone, or on its own listener for a private one.
type AccessRevocationTombstone struct {
	// Key identifies the tombstone as ProtectionDomain + "\x00" + Application.
	Key string
	// Application is the AccessApplication key in namespace/name form.
	Application string
	DataPlane   v1alpha1.AccessApplicationDataPlaneStatus
	// Hostnames are the sorted, lower-case hostnames the tombstone blocks.
	Hostnames []string
}

// AccessRevocationTombstones returns the data planes of revoked
// AccessApplications that the Gateway keeps serving as Blocked tombstones on
// tunnel, sorted by Key. A data plane is retained when its application is
// deleting or carries a revocation latch, it records tunnel, it names a
// protection domain, it still has hostnames to block, and live does not
// already compile the same protection domain for the same application.
func AccessRevocationTombstones(tunnel *v1alpha1.CloudflareTunnel, applications []v1alpha1.AccessApplication, live []ir.ProtectionDomain) []AccessRevocationTombstone {
	if tunnel == nil {
		return nil
	}
	existing := make(map[string]struct{}, len(live))
	for _, domain := range live {
		existing[domain.Name+"\x00"+domain.AccessApplication] = struct{}{}
	}
	tombstones := make([]AccessRevocationTombstone, 0)
	for index := range applications {
		application := &applications[index]
		if application.DeletionTimestamp.IsZero() && application.Annotations[AccessRevocationAnnotation] == "" {
			continue
		}
		applicationKey := application.Namespace + "/" + application.Name
		for _, dataPlane := range application.Status.DataPlanes {
			if dataPlane.Tunnel != tunnel.Name || dataPlane.ProtectionDomain == "" {
				continue
			}
			key := dataPlane.ProtectionDomain + "\x00" + applicationKey
			if _, found := existing[key]; found {
				continue
			}
			hostnames := retainedAccessHostnames(tunnel, application, dataPlane.ProtectionDomain, applicationKey)
			if len(hostnames) == 0 {
				continue
			}
			tombstones = append(tombstones, AccessRevocationTombstone{
				Key: key, Application: applicationKey, DataPlane: dataPlane, Hostnames: hostnames,
			})
			existing[key] = struct{}{}
		}
	}
	slices.SortFunc(tombstones, func(left, right AccessRevocationTombstone) int {
		return strings.Compare(left.Key, right.Key)
	})
	return tombstones
}

// accessRevocationHolds is what the retained revocation tombstones hold in a
// translation: the Envoy ports they stay bound to and the hostnames they keep
// blocked. A nil *accessRevocationHolds holds nothing.
type accessRevocationHolds struct {
	// ports are the Envoy ports no live listener or Access host may bind.
	ports map[int32]struct{}
	// private hosts are held per listener: a private data plane only serves a
	// host inside that listener's virtual network.
	private map[accessRevocationListenerHost][]string
	// public hosts are held on the tunnel's public listeners: a public
	// hostname reaches any of them over the edge's ingress rules, so it cannot
	// be forwarded on one while a tombstone holds it on another. A private
	// domain gated by its own application's JWT never served a public host,
	// so a public hold does not apply there.
	public map[string][]string
}

type accessRevocationListenerHost struct {
	listener string
	hostname string
}

func (holds *accessRevocationHolds) addHost(m *map[string][]string, hostname string, application string) {
	applications := (*m)[hostname]
	if slices.Contains(applications, application) {
		return
	}
	if *m == nil {
		*m = make(map[string][]string)
	}
	(*m)[hostname] = append(applications, application)
	slices.Sort((*m)[hostname])
}

// newAccessRevocationHolds returns what the tombstones retained for
// in.CloudflareTunnel hold, given the live domains a translation produced, or
// nil when no tombstone is retained. Liveness depends only on domain names
// and owners, which neither reserved ports nor blocked guards change, so the
// holds computed from an unreserved translation are exact for the translation
// that applies them. When a tombstone holds a port, the fixed ports of private
// listeners are reserved too, so shifting the positional public sequence past
// the tombstone cannot land a public bind on a private bind.
func newAccessRevocationHolds(in Inputs, live []ir.ProtectionDomain) *accessRevocationHolds {
	tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, live)
	if len(tombstones) == 0 {
		return nil
	}
	holds := &accessRevocationHolds{ports: make(map[int32]struct{}, len(tombstones))}
	for _, tombstone := range tombstones {
		if tombstone.DataPlane.EnvoyPort > 0 {
			holds.ports[tombstone.DataPlane.EnvoyPort] = struct{}{}
		}
		private := listenerExposure(in.CloudflareTunnel, tombstone.DataPlane.Listener) == v1alpha1.ExposurePrivate
		for _, hostname := range tombstone.Hostnames {
			if private {
				if holds.private == nil {
					holds.private = make(map[accessRevocationListenerHost][]string)
				}
				key := accessRevocationListenerHost{listener: string(tombstone.DataPlane.Listener), hostname: hostname}
				if !slices.Contains(holds.private[key], tombstone.Application) {
					holds.private[key] = append(holds.private[key], tombstone.Application)
					slices.Sort(holds.private[key])
				}
			} else {
				holds.addHost(&holds.public, hostname, tombstone.Application)
			}
		}
	}
	if len(holds.ports) > 0 {
		for _, listener := range in.Gateway.Spec.Listeners {
			if listenerExposure(in.CloudflareTunnel, listener.Name) == v1alpha1.ExposurePrivate {
				holds.ports[int32(listener.Port)] = struct{}{}
			}
		}
	}
	return holds
}

func (holds *accessRevocationHolds) reservedPorts() map[int32]struct{} {
	if holds == nil {
		return nil
	}
	return holds.ports
}

// holders returns the revoked AccessApplications whose tombstones keep
// hostname blocked on a listener with the given exposure. The holder of a
// public host applies on any public listener, the holder of a private host
// only on its own. A tombstone holding a wildcard holds every host under it:
// the edge and Envoy both resolve an exact host before a matching wildcard,
// so serving one would bypass the wildcard's block.
func (holds *accessRevocationHolds) holders(exposure, listener, hostname string) []string {
	if holds == nil || hostname == "" || hostname == "*" {
		return nil
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	candidates := []string{hostname}
	labels := strings.Split(strings.TrimPrefix(hostname, "*."), ".")
	for index := 1; index+1 < len(labels); index++ {
		candidates = append(candidates, "*."+strings.Join(labels[index:], "."))
	}
	result := make([]string, 0)
	for _, candidate := range candidates {
		if exposure == ir.ExposurePrivate {
			result = append(result, holds.private[accessRevocationListenerHost{listener: listener, hostname: candidate}]...)
		} else {
			result = append(result, holds.public[candidate]...)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

// held reports whether a tombstone keeps hostname blocked on a listener with
// the given exposure. Until that revocation is acknowledged, nothing else may
// serve the host there.
func (holds *accessRevocationHolds) held(exposure, listener, hostname string) bool {
	return len(holds.holders(exposure, listener, hostname)) > 0
}

// describe explains which of application's claimed hosts another revoked
// application's tombstone keeps blocked, or returns "" when none is.
func (holds *accessRevocationHolds) describe(in Inputs, claims []accessClaim, application string) string {
	notes := make([]string, 0)
	for _, claim := range claims {
		for _, holder := range holds.holders(string(listenerExposure(in.CloudflareTunnel, gatewayv1.SectionName(claim.listener))), claim.listener, claim.hostname) {
			if holder != application {
				notes = append(notes, fmt.Sprintf("%s on listener %s stays blocked until the revocation of AccessApplication %s is acknowledged", claim.hostname, claim.listener, holder))
			}
		}
	}
	slices.Sort(notes)
	return strings.Join(slices.Compact(notes), "; ")
}

// apply reshapes the domains serving a host a tombstone holds so nothing but
// a block serves it until the revocation is acknowledged. Each domain
// applyAccessApplications emits serves one host.
// Listener-level domains (unprotected, public carve-out, or blocked) are
// dropped: they share the listener's Envoy port with the listener's other
// hosts, so changing their guard there would split one bind into two, and the
// tombstone already blocks the host. Access domains take the tombstone's
// Blocked shape, so a private listener merges them into the tombstone's filter
// chain instead of adding a second chain for the same server name. It runs
// after domain names are final, so it never changes a name the tombstone set
// was computed from.
func (holds *accessRevocationHolds) apply(gateway *ir.Gateway) {
	if holds == nil {
		return
	}
	kept := gateway.Domains[:0]
	for _, domain := range gateway.Domains {
		held := false
		exposure := ""
		for _, listener := range gateway.Listeners {
			if listener.Name == domain.ListenerName {
				exposure = listener.Exposure
			}
		}
		for _, virtualHost := range domain.VirtualHosts {
			held = held || holds.held(exposure, domain.ListenerName, virtualHost.Hostname)
		}
		if held {
			if domain.AccessApplication == "" {
				continue
			}
			domain.Protected = true
			domain.Guard = ir.GuardBlocked
			domain.Access = nil
			domain.StripAccessHeaders = false
		}
		kept = append(kept, domain)
	}
	clear(gateway.Domains[len(kept):])
	gateway.Domains = kept
}

// publicEnvoyPorts hands out positional loopback Envoy ports for public
// listeners and public Access hosts, skipping every port a revocation
// tombstone holds.
type publicEnvoyPorts struct {
	next     int32
	reserved map[int32]struct{}
}

func (ports *publicEnvoyPorts) take() int32 {
	for {
		port := ports.next
		ports.next++
		if _, taken := ports.reserved[port]; !taken {
			return port
		}
	}
}

// retainedAccessHostnames returns the hostnames a revoked application's data
// plane blocks: the hosts the tunnel reports for its protection domain, or,
// before the tunnel reported any, every destination the application recorded.
// Destinations carry no listener or protection domain, so the fallback cannot
// tell which of them this data plane served; it holds them all rather than
// risk serving one of them before the revocation is acknowledged.
func retainedAccessHostnames(tunnel *v1alpha1.CloudflareTunnel, application *v1alpha1.AccessApplication, protectionDomain, applicationKey string) []string {
	hostnames := make([]string, 0)
	for _, status := range tunnel.Status.Hostnames {
		if status.ProtectionDomain == protectionDomain && status.AccessApplication == applicationKey && status.Hostname != "" {
			hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(status.Hostname, ".")))
		}
	}
	if len(hostnames) == 0 {
		for _, destination := range application.Status.Destinations {
			hostname := destination.Hostname
			if hostname == "" && destination.URI != "" {
				hostname, _, _ = strings.Cut(destination.URI, "/")
			}
			hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
			if hostname != "" {
				hostnames = append(hostnames, hostname)
			}
		}
	}
	slices.Sort(hostnames)
	return slices.Compact(hostnames)
}
