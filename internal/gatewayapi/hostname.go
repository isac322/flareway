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

This file is adapted from Envoy Gateway's
internal/gatewayapi/helpers.go at v1.9.1
(commit 0260554fd4f33b787aad77a129fc0ffeb00c1f29),
Copyright Envoy Gateway Authors, licensed under Apache-2.0.
*/

package gatewayapi

import (
	"slices"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ComputeHosts returns the intersection of routeHostnames and listenerHostname.
// Hostnames already claimed by another listener on the same port can be passed
// in claimedByOtherListeners; they are removed from the result.
//
// A nil listener hostname matches every route hostname. When neither the Route
// nor the Listener specifies a hostname, the result is the catch-all hostname
// "*". The returned slice is sorted and contains no duplicates.
func ComputeHosts(
	routeHostnames []gatewayv1.Hostname,
	listenerHostname *gatewayv1.Hostname,
	claimedByOtherListeners []gatewayv1.Hostname,
) []gatewayv1.Hostname {
	var listenerHostnameValue gatewayv1.Hostname
	if listenerHostname != nil {
		listenerHostnameValue = *listenerHostname
	}

	if len(routeHostnames) == 0 {
		if listenerHostnameValue != "" {
			return []gatewayv1.Hostname{listenerHostnameValue}
		}
		return []gatewayv1.Hostname{"*"}
	}

	hostnames := make(map[gatewayv1.Hostname]struct{}, len(routeHostnames))
	for _, routeHostname := range routeHostnames {
		switch {
		case listenerHostnameValue == "":
			hostnames[routeHostname] = struct{}{}
		case listenerHostnameValue == routeHostname:
			hostnames[routeHostname] = struct{}{}
		case strings.HasPrefix(string(listenerHostnameValue), "*") && strings.HasPrefix(string(routeHostname), "*"):
			if WildcardHostnameMatchesHostname(routeHostname, listenerHostnameValue) {
				hostnames[listenerHostnameValue] = struct{}{}
			}
			if WildcardHostnameMatchesHostname(listenerHostnameValue, routeHostname) {
				hostnames[routeHostname] = struct{}{}
			}
		case strings.HasPrefix(string(listenerHostnameValue), "*"):
			if WildcardHostnameMatchesHostname(listenerHostnameValue, routeHostname) {
				hostnames[routeHostname] = struct{}{}
			}
		case strings.HasPrefix(string(routeHostname), "*"):
			if WildcardHostnameMatchesHostname(routeHostname, listenerHostnameValue) {
				hostnames[listenerHostnameValue] = struct{}{}
			}
		}
	}

	for _, hostname := range claimedByOtherListeners {
		delete(hostnames, hostname)
	}

	result := make([]gatewayv1.Hostname, 0, len(hostnames))
	for hostname := range hostnames {
		result = append(result, hostname)
	}
	slices.Sort(result)
	return result
}

// WildcardHostnameMatchesHostname reports whether wildcardHostname contains
// hostname according to Gateway API wildcard semantics. Unlike RFC 2818, a
// wildcard may cover more than one label: *.example.com matches both
// foo.example.com and bar.foo.example.com, but does not match example.com.
func WildcardHostnameMatchesHostname(wildcardHostname, hostname gatewayv1.Hostname) bool {
	wildcardSuffix := strings.TrimPrefix(string(wildcardHostname), "*")
	hostnameValue := string(hostname)

	if !strings.HasPrefix(hostnameValue, "*") {
		if !strings.HasSuffix(hostnameValue, wildcardSuffix) {
			return false
		}
		return strings.TrimSuffix(hostnameValue, wildcardSuffix) != ""
	}

	hostnameSuffix := strings.TrimPrefix(hostnameValue, "*")
	if !strings.HasSuffix(hostnameSuffix, wildcardSuffix) {
		return false
	}

	remaining := strings.TrimSuffix(hostnameSuffix, wildcardSuffix)
	return remaining != "" && strings.HasPrefix(remaining, ".")
}
