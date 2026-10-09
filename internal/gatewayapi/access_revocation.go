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
	"strconv"
	"strings"

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
// nothing else may serve its hosts on its listener except as Blocked.
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
			hostnames := retainedAccessHostnames(tunnel, application, dataPlane, applicationKey)
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
// blocked on each tunnel listener. A nil *accessRevocationHolds holds nothing.
type accessRevocationHolds struct {
	// ports are the Envoy ports no live listener or Access host may bind.
	ports map[int32]struct{}
	// hosts maps a listener and lower-case hostname to the sorted keys of the
	// revoked AccessApplications whose tombstones block that host there.
	hosts map[accessRevocationHost][]string
}

type accessRevocationHost struct {
	listener string
	hostname string
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
	holds := &accessRevocationHolds{
		ports: make(map[int32]struct{}, len(tombstones)),
		hosts: make(map[accessRevocationHost][]string),
	}
	for _, tombstone := range tombstones {
		if tombstone.DataPlane.EnvoyPort > 0 {
			holds.ports[tombstone.DataPlane.EnvoyPort] = struct{}{}
		}
		for _, hostname := range tombstone.Hostnames {
			key := accessRevocationHost{listener: string(tombstone.DataPlane.Listener), hostname: hostname}
			if !slices.Contains(holds.hosts[key], tombstone.Application) {
				holds.hosts[key] = append(holds.hosts[key], tombstone.Application)
				slices.Sort(holds.hosts[key])
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
// hostname blocked on listener.
func (holds *accessRevocationHolds) holders(listener, hostname string) []string {
	if holds == nil {
		return nil
	}
	return holds.hosts[accessRevocationHost{listener: listener, hostname: strings.ToLower(strings.TrimSuffix(hostname, "."))}]
}

// held reports whether a tombstone keeps hostname blocked on listener. Until
// that revocation is acknowledged, nothing else may serve the host there.
func (holds *accessRevocationHolds) held(listener, hostname string) bool {
	return len(holds.holders(listener, hostname)) > 0
}

// describe explains which of application's claimed hosts another revoked
// application's tombstone keeps blocked, or returns "" when none is.
func (holds *accessRevocationHolds) describe(claims []accessClaim, application string) string {
	notes := make([]string, 0)
	for _, claim := range claims {
		for _, holder := range holds.holders(claim.listener, claim.hostname) {
			if holder != application {
				notes = append(notes, fmt.Sprintf("%s on listener %s stays blocked until the revocation of AccessApplication %s is acknowledged", claim.hostname, claim.listener, holder))
			}
		}
	}
	slices.Sort(notes)
	return strings.Join(slices.Compact(notes), "; ")
}

// apply reshapes the domains serving a host a tombstone holds on their
// listener so nothing but a block serves it until the revocation is
// acknowledged. Each domain applyAccessApplications emits serves one host.
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
		for _, virtualHost := range domain.VirtualHosts {
			held = held || holds.held(domain.ListenerName, virtualHost.Hostname)
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
// before the tunnel reported any, the application's recorded destinations
// that the data plane can have served. A public listener's data plane serves
// Public destinations. A private listener's data plane serves the Private
// hostname destinations compiled for that listener, which carry the listener
// port its protection domains bind as their port range. Other destinations,
// such as a standalone private HostnameRoute or CIDR destination, never
// reached this data plane and are not held on its listener. An untyped
// destination predates the required type and is kept, as before.
func retainedAccessHostnames(tunnel *v1alpha1.CloudflareTunnel, application *v1alpha1.AccessApplication, dataPlane v1alpha1.AccessApplicationDataPlaneStatus, applicationKey string) []string {
	hostnames := make([]string, 0)
	for _, status := range tunnel.Status.Hostnames {
		if status.ProtectionDomain == dataPlane.ProtectionDomain && status.AccessApplication == applicationKey && status.Hostname != "" {
			hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(status.Hostname, ".")))
		}
	}
	if len(hostnames) == 0 {
		private := false
		for _, listener := range tunnel.Spec.Listeners {
			if listener.Name == dataPlane.Listener {
				private = listener.Exposure == v1alpha1.ExposurePrivate
				break
			}
		}
		for _, destination := range application.Status.Destinations {
			switch destination.Type {
			case "":
			case v1alpha1.AccessApplicationDestinationPublic:
				if private {
					continue
				}
			case v1alpha1.AccessApplicationDestinationPrivate:
				if !private || destination.PortRange != strconv.Itoa(int(dataPlane.EnvoyPort)) {
					continue
				}
			default:
				continue
			}
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
