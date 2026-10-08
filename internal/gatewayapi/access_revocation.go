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
	"slices"
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
// tombstone must stay bound there and no live listener or domain may take it.
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

// accessRevocationEnvoyPorts returns the Envoy ports the tombstones retained
// for in.CloudflareTunnel occupy, given the live domains a translation
// produced. Liveness depends only on domain names, never on ports, so the set
// computed from an unreserved translation is exact for the reserved one.
func accessRevocationEnvoyPorts(in Inputs, live []ir.ProtectionDomain) map[int32]struct{} {
	tombstones := AccessRevocationTombstones(in.CloudflareTunnel, in.AccessApplications, live)
	if len(tombstones) == 0 {
		return nil
	}
	reserved := make(map[int32]struct{}, len(tombstones))
	for _, tombstone := range tombstones {
		if tombstone.DataPlane.EnvoyPort > 0 {
			reserved[tombstone.DataPlane.EnvoyPort] = struct{}{}
		}
	}
	return reserved
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
