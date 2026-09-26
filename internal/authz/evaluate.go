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

// Package authz evaluates CloudflareAccount grants before credentials are read
// or remote Cloudflare APIs are called.
package authz

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// Authorization result reasons.
const (
	ReasonAllowed          = "Allowed"
	ReasonRefNotPermitted  = "RefNotPermitted"
	ReasonUnsupportedValue = "UnsupportedValue"
)

// PrivateRouteKind identifies the platform route selector to evaluate.
type PrivateRouteKind string

// Private route kinds.
const (
	PrivateRouteNetwork  PrivateRouteKind = "NetworkRoute"
	PrivateRouteHostname PrivateRouteKind = "HostnameRoute"
)

// PrivateRouteRequest describes a platform route object being referenced.
type PrivateRouteRequest struct {
	Kind   PrivateRouteKind
	Labels map[string]string
}

// BackendRequest describes a Kubernetes backend subject to the SSRF boundary.
type BackendRequest struct {
	Namespace *corev1.Namespace
	Kind      v1alpha1.BackendKind
}

// Request describes every grant gate needed for one proposed operation. Empty
// scalar fields and nil nested requests do not activate their corresponding gate.
type Request struct {
	Hostname string
	Zone     string
	Exposure v1alpha1.Exposure

	Unprotected                 bool
	AccessPolicyRef             bool
	AccessCustomPageRef         bool
	DevicePostureIntegrationRef bool
	PlatformObject              bool
	PrivateRoute                *PrivateRouteRequest
	Backend                     *BackendRequest
}

// Decision is the deterministic result of evaluating account grants.
type Decision struct {
	Allowed    bool
	Reason     string
	Message    string
	GrantIndex int
}

// Evaluate always requires a namespace-matching grant, including when no
// operation-specific gates are activated. One matching grant must permit every
// activated gate; combining permissions across grants is forbidden.
func Evaluate(account *v1alpha1.CloudflareAccount, namespace *corev1.Namespace, request Request) Decision {
	if account == nil {
		return denied(ReasonRefNotPermitted, "CloudflareAccount is required")
	}
	if namespace == nil {
		return denied(ReasonRefNotPermitted, "request namespace is required")
	}

	matchedNamespace := false
	lastDenial := denied(ReasonRefNotPermitted, fmt.Sprintf("namespace %q is not granted by CloudflareAccount %q", namespace.Name, account.Name))
	for index := range account.Spec.Grants {
		grant := &account.Spec.Grants[index]
		matches, err := selectorMatches(grant.NamespaceSelector, namespace.Labels)
		if err != nil {
			lastDenial = denied(ReasonRefNotPermitted, fmt.Sprintf("grant %d has an invalid namespace selector: %v", index, err))
			continue
		}
		if !matches {
			continue
		}
		matchedNamespace = true

		decision := evaluateGrant(grant, namespace, request)
		decision.GrantIndex = index
		if decision.Allowed {
			return decision
		}
		lastDenial = decision
	}

	if !matchedNamespace {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("namespace %q is not granted by CloudflareAccount %q", namespace.Name, account.Name))
	}
	return lastDenial
}

func evaluateGrant(grant *v1alpha1.CloudflareAccountGrant, namespace *corev1.Namespace, request Request) Decision {
	if request.Hostname != "" && !matchesHostnameSet(grant.Hostnames, request.Hostname) {
		return denied(ReasonUnsupportedValue, fmt.Sprintf("hostname %q is not granted", request.Hostname))
	}
	if request.Zone != "" && !ZoneMatches(grant.Zones, request.Zone) {
		return denied(ReasonUnsupportedValue, fmt.Sprintf("zone %q is not granted", request.Zone))
	}
	if request.Exposure != "" && !containsExposure(grant.Exposures, request.Exposure) {
		return denied(ReasonUnsupportedValue, fmt.Sprintf("exposure %q is not granted", request.Exposure))
	}
	if request.Unprotected && !matchesHostnameSet(grant.UnprotectedHostnames, request.Hostname) {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("unprotected hostname %q is not granted", request.Hostname))
	}
	if request.AccessPolicyRef && grant.AccessPolicyRefs != v1alpha1.GrantPermissionAllowed {
		return denied(ReasonRefNotPermitted, "platform Access policy references are not granted")
	}
	if request.AccessCustomPageRef && grant.AccessCustomPageRefs != v1alpha1.GrantPermissionAllowed {
		return denied(ReasonRefNotPermitted, "managed Access custom page references are not granted")
	}
	if request.DevicePostureIntegrationRef && grant.DevicePostureIntegrationRefs != v1alpha1.GrantPermissionAllowed {
		return denied(ReasonRefNotPermitted, "managed device posture integration references are not granted")
	}
	if request.PlatformObject && grant.PlatformObjects != v1alpha1.GrantPermissionAllowed {
		return denied(ReasonRefNotPermitted, "platform object management is not granted")
	}
	if request.PrivateRoute != nil {
		if decision := evaluatePrivateRoute(grant.PrivateRoutes, request.PrivateRoute); !decision.Allowed {
			return decision
		}
	}
	if request.Backend != nil {
		if decision := evaluateBackend(grant.Backends, namespace, request.Backend); !decision.Allowed {
			return decision
		}
	}
	return Decision{Allowed: true, Reason: ReasonAllowed, Message: "request is allowed", GrantIndex: -1}
}

func evaluatePrivateRoute(grant *v1alpha1.CloudflarePrivateRouteGrant, request *PrivateRouteRequest) Decision {
	if grant == nil {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("%s references are not granted", request.Kind))
	}

	var selector *metav1.LabelSelector
	switch request.Kind {
	case PrivateRouteNetwork:
		selector = grant.NetworkRouteSelector
	case PrivateRouteHostname:
		selector = grant.HostnameRouteSelector
	default:
		return denied(ReasonRefNotPermitted, fmt.Sprintf("private route kind %q is not supported", request.Kind))
	}
	if selector == nil {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("%s references are not granted", request.Kind))
	}
	matches, err := selectorMatches(*selector, request.Labels)
	if err != nil {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("invalid %s selector: %v", request.Kind, err))
	}
	if !matches {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("%s labels are not granted", request.Kind))
	}
	return Decision{Allowed: true}
}

func evaluateBackend(grant *v1alpha1.CloudflareBackendGrant, sourceNamespace *corev1.Namespace, request *BackendRequest) Decision {
	if grant == nil || request.Namespace == nil {
		return denied(ReasonRefNotPermitted, "backend namespace is not granted")
	}
	if !containsBackendKind(grant.Kinds, request.Kind) {
		return denied(ReasonRefNotPermitted, fmt.Sprintf("backend kind %q is not granted", request.Kind))
	}

	switch grant.Namespaces {
	case "", v1alpha1.BackendNamespaceSame:
		if request.Namespace.Name != sourceNamespace.Name {
			return denied(ReasonRefNotPermitted, fmt.Sprintf("backend namespace %q is not the source namespace", request.Namespace.Name))
		}
	case v1alpha1.BackendNamespaceSelector:
		if grant.Selector == nil {
			return denied(ReasonRefNotPermitted, "backend namespace selector is required")
		}
		matches, err := selectorMatches(*grant.Selector, request.Namespace.Labels)
		if err != nil {
			return denied(ReasonRefNotPermitted, fmt.Sprintf("invalid backend namespace selector: %v", err))
		}
		if !matches {
			return denied(ReasonRefNotPermitted, fmt.Sprintf("backend namespace %q is not granted", request.Namespace.Name))
		}
	default:
		return denied(ReasonRefNotPermitted, fmt.Sprintf("backend namespace mode %q is not supported", grant.Namespaces))
	}
	return Decision{Allowed: true}
}

func selectorMatches(selector metav1.LabelSelector, objectLabels map[string]string) (bool, error) {
	compiled, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return false, err
	}
	return compiled.Matches(labels.Set(objectLabels)), nil
}

func matchesHostnameSet(patterns []string, hostname string) bool {
	for _, pattern := range patterns {
		if HostnameMatches(pattern, hostname) {
			return true
		}
	}
	return false
}

// HostnameMatches reports whether a grant pattern contains a requested exact or
// wildcard hostname. Wildcards match exactly one DNS label and never the apex.
func HostnameMatches(pattern, hostname string) bool {
	pattern = normalizeDNSName(pattern)
	hostname = normalizeDNSName(hostname)
	if pattern == "*" {
		return hostname != ""
	}
	if pattern == hostname {
		return pattern != ""
	}
	if !strings.HasPrefix(pattern, "*.") || strings.HasPrefix(hostname, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(hostname, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// ZoneMatches reports whether a grant's zones list contains zone: an exact
// zone name or "*", compared after DNS name normalization. It is the single
// zone rule shared by grant evaluation and the DNS drift sweep's scan set.
func ZoneMatches(patterns []string, value string) bool {
	value = normalizeDNSName(value)
	for _, pattern := range patterns {
		pattern = normalizeDNSName(pattern)
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

func normalizeDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func containsExposure(exposures []v1alpha1.Exposure, exposure v1alpha1.Exposure) bool {
	for _, candidate := range exposures {
		if candidate == exposure {
			return true
		}
	}
	return false
}

func containsBackendKind(kinds []v1alpha1.BackendKind, kind v1alpha1.BackendKind) bool {
	for _, candidate := range kinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func denied(reason, message string) Decision {
	return Decision{Reason: reason, Message: message, GrantIndex: -1}
}
