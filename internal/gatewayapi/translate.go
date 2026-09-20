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
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"

	"github.com/isac322/flareway/internal/gatewayapi/status"
	"github.com/isac322/flareway/internal/ir"
)

const gatewayGroup = gatewayv1.GroupName

type listenerTranslation struct {
	spec            gatewayv1.Listener
	ir              *ir.Listener
	accepted        bool
	resolved        bool
	conflicted      bool
	conflictReason  gatewayv1.ListenerConditionReason
	acceptedReason  gatewayv1.ListenerConditionReason
	acceptedMessage string
	resolvedReason  gatewayv1.ListenerConditionReason
	resolvedMessage string
	attachedRoutes  map[types.NamespacedName]struct{}
	exposure        v1alpha1.Exposure
	guard           string
	protected       bool
}

type routeOutcome struct {
	accepted       bool
	acceptedReason gatewayv1.RouteConditionReason
	message        string
	resolved       bool
	resolvedReason gatewayv1.RouteConditionReason
	resolvedMsg    string
	dropped        []string
}

type compiledRoute struct {
	route      ir.Route
	creation   metav1.Time
	objectKey  string
	ruleIndex  int
	matchIndex int
}

// Translate deterministically converts cached Kubernetes objects into the
// Flareway IR and desired statuses. It returns nil IR only when Gateway is nil.
func Translate(in Inputs) (*ir.Gateway, Statuses) {
	outStatuses := Statuses{
		HTTPRoutes:         make(map[types.NamespacedName]gatewayv1.HTTPRouteStatus),
		BackendTLSPolicies: make(map[types.NamespacedName]gatewayv1.PolicyStatus),
		AccessApplications: make(map[types.NamespacedName]AccessApplicationCompilation),
	}
	if in.Gateway == nil {
		return nil, outStatuses
	}

	now := in.Now
	if now.IsZero() {
		now = metav1.NewTime(time.Unix(0, 0).UTC())
	}
	conformanceMode := in.GatewayClassConfig != nil && in.GatewayClassConfig.Spec.ConformanceMode
	out := &ir.Gateway{
		Key: types.NamespacedName{
			Namespace: in.Gateway.Namespace,
			Name:      in.Gateway.Name,
		},
		UID:                       in.Gateway.UID,
		ConformanceMode:           conformanceMode,
		InfrastructureLabels:      infrastructureLabels(in.Gateway.Spec.Infrastructure),
		InfrastructureAnnotations: infrastructureAnnotations(in.Gateway.Spec.Infrastructure),
	}
	if !conformanceMode && in.CloudflareTunnel != nil && in.CloudflareAccount != nil {
		policy := in.CloudflareTunnel.Spec.ManagementPolicy
		if policy == "" {
			policy = v1alpha1.ManagementPolicyManaged
		}
		ownershipVerified := policy == v1alpha1.ManagementPolicyManaged &&
			in.CloudflareTunnel.Status.DeletedAt == nil &&
			in.CloudflareTunnel.Status.OwnershipVerified &&
			in.CloudflareTunnel.Status.ConnectorTokenSecretRef != nil &&
			in.CloudflareTunnel.Status.ConnectorTokenSecretRef.Name != "" &&
			in.CloudflareTunnel.Status.GatewayRef != nil &&
			in.CloudflareTunnel.Status.GatewayRef.Name == in.Gateway.Name &&
			in.CloudflareTunnel.Status.GatewayUID != "" &&
			in.CloudflareTunnel.Status.GatewayUID == in.Gateway.UID
		if ownershipVerified {
			tunnelName := in.CloudflareTunnel.Spec.Tunnel.Name
			if tunnelName == "" {
				tunnelName = in.CloudflareTunnel.Name
			}
			out.Cloudflare = &ir.Cloudflare{
				AccountID:        in.CloudflareAccount.Spec.AccountID,
				TunnelName:       tunnelName,
				TunnelID:         in.CloudflareTunnel.Status.TunnelID,
				TokenSecretName:  in.CloudflareTunnel.Status.ConnectorTokenSecretRef.Name,
				ManagementPolicy: string(policy),
				Teardown:         in.CloudflareTunnel.Annotations[v1alpha1.CloudflareTunnelTeardownAnnotation] == "true",
				WARPRouting:      privateRoutesRequireWARP(in),
				OriginRequest:    gatewayOriginRequestIR(in.GatewayClassConfig),
			}
		}
	}

	listeners, gatewayReason, gatewayMessage := translateListeners(in, out)
	globalInvalid := false
	if len(in.Gateway.Spec.Addresses) > 0 {
		globalInvalid = true
		gatewayReason = gatewayv1.GatewayReasonUnsupportedAddress
		gatewayMessage = "spec.addresses is not supported"
	}
	if in.Gateway.Spec.AllowedListeners != nil {
		globalInvalid = true
		gatewayReason = gatewayv1.GatewayReasonListenersNotValid
		gatewayMessage = "spec.allowedListeners is not supported"
	}
	if infrastructure := in.Gateway.Spec.Infrastructure; infrastructure != nil && infrastructure.ParametersRef != nil {
		ref := infrastructure.ParametersRef
		supportedTunnelRef := !conformanceMode &&
			in.CloudflareTunnel != nil &&
			string(ref.Group) == v1alpha1.Group &&
			string(ref.Kind) == "CloudflareTunnel" &&
			ref.Name == in.CloudflareTunnel.Name
		if !supportedTunnelRef {
			globalInvalid = true
			gatewayReason = gatewayv1.GatewayReasonInvalidParameters
			gatewayMessage = fmt.Sprintf("infrastructure parametersRef %s/%s is not supported", ref.Group, ref.Kind)
		}
	}
	if globalInvalid {
		for _, listener := range listeners {
			listener.accepted = false
			listener.acceptedReason = gatewayv1.ListenerReasonUnsupportedValue
			listener.acceptedMessage = gatewayMessage
			listener.ir = nil
		}
		out.Listeners = nil
		out.Domains = nil
		out.Secrets = nil
	}

	compileHTTPRoutes(in, out, listeners, &outStatuses, now)
	applyAccessApplications(in, out, &outStatuses, now)
	populateBackendTLSPolicyStatuses(in, out, &outStatuses, now)
	out.Clusters = buildClusters(in, out)
	finalizeIR(out)

	accepted := false
	if gatewayReason == gatewayv1.GatewayReasonAccepted {
		acceptedListeners := 0
		invalidListeners := 0
		for _, listener := range listeners {
			if listener.accepted && !listener.conflicted {
				acceptedListeners++
			} else {
				invalidListeners++
			}
		}
		accepted = acceptedListeners > 0
		if invalidListeners > 0 {
			gatewayReason = gatewayv1.GatewayReasonListenersNotValid
			gatewayMessage = "one or more listeners are invalid"
		}
	}

	gatewayStatus := *in.Gateway.Status.DeepCopy()
	gatewayStatus.Conditions = status.MergeConditions(
		gatewayStatus.Conditions,
		now,
		status.NewCondition(
			string(gatewayv1.GatewayConditionAccepted),
			conditionStatus(accepted),
			string(gatewayReason),
			gatewayMessage,
			in.Gateway.Generation,
			now,
		),
	)
	gatewayStatus.Listeners = make([]gatewayv1.ListenerStatus, 0, len(listeners))
	for _, translated := range listeners {
		gatewayStatus.Listeners = append(gatewayStatus.Listeners, listenerStatus(in.Gateway, translated, now))
	}
	outStatuses.Gateway = gatewayStatus
	return out, outStatuses
}
func gatewayOriginRequestIR(config *v1alpha1.GatewayClassConfig) ir.GatewayOriginRequest {
	if config == nil {
		return ir.GatewayOriginRequest{}
	}
	origin := config.Spec.OriginRequest
	result := ir.GatewayOriginRequest{
		KeepAliveConnections:   cloneInt64Pointer(origin.KeepAliveConnections),
		NoHappyEyeballs:        cloneBoolPointer(origin.NoHappyEyeballs),
		DisableChunkedEncoding: cloneBoolPointer(origin.DisableChunkedEncoding),
		HTTP2Origin:            cloneBoolPointer(origin.HTTP2Origin),
	}
	if origin.ConnectTimeout != nil {
		value := origin.ConnectTimeout.Duration
		result.ConnectTimeout = &value
	}
	if origin.KeepAliveTimeout != nil {
		value := origin.KeepAliveTimeout.Duration
		result.KeepAliveTimeout = &value
	}
	if origin.TCPKeepAlive != nil {
		value := origin.TCPKeepAlive.Duration
		result.TCPKeepAlive = &value
	}
	return result
}

func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func infrastructureLabels(infrastructure *gatewayv1.GatewayInfrastructure) map[string]string {
	if infrastructure == nil || len(infrastructure.Labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(infrastructure.Labels))
	for key, value := range infrastructure.Labels {
		result[string(key)] = string(value)
	}
	return result
}

func infrastructureAnnotations(infrastructure *gatewayv1.GatewayInfrastructure) map[string]string {
	if infrastructure == nil || len(infrastructure.Annotations) == 0 {
		return nil
	}
	result := make(map[string]string, len(infrastructure.Annotations))
	for key, value := range infrastructure.Annotations {
		result[string(key)] = string(value)
	}
	return result
}

func listenerExposure(tunnel *v1alpha1.CloudflareTunnel, listenerName gatewayv1.SectionName) v1alpha1.Exposure {
	if tunnel != nil {
		for _, listener := range tunnel.Spec.Listeners {
			if listener.Name == listenerName && listener.Exposure != "" {
				return listener.Exposure
			}
		}
	}
	return v1alpha1.ExposurePublic
}

func listenerBinding(tunnel *v1alpha1.CloudflareTunnel, listenerName gatewayv1.SectionName) string {
	if tunnel != nil && tunnel.Status.DeletedAt == nil {
		for _, listener := range tunnel.Status.Listeners {
			if listener.Name == listenerName && listener.Binding == v1alpha1.ListenerBindingPodIP {
				return ir.ListenerBindingPodIP
			}
		}
	}
	return ir.ListenerBindingLoopback
}

func namespaceByName(namespaces []corev1.Namespace, name string) *corev1.Namespace {
	for index := range namespaces {
		if namespaces[index].Name == name {
			return &namespaces[index]
		}
	}
	return nil
}

func translateListeners(in Inputs, out *ir.Gateway) ([]*listenerTranslation, gatewayv1.GatewayConditionReason, string) {
	publicPort := int32(18080)
	listeners := make([]*listenerTranslation, 0, len(in.Gateway.Spec.Listeners))
	conformance := out.ConformanceMode
	for i := range in.Gateway.Spec.Listeners {
		spec := in.Gateway.Spec.Listeners[i]
		exposure := listenerExposure(in.CloudflareTunnel, spec.Name)
		translated := &listenerTranslation{
			spec:            spec,
			accepted:        true,
			resolved:        true,
			conflictReason:  gatewayv1.ListenerReasonNoConflicts,
			acceptedReason:  gatewayv1.ListenerReasonAccepted,
			acceptedMessage: "listener accepted",
			resolvedReason:  gatewayv1.ListenerReasonResolvedRefs,
			resolvedMessage: "references resolved",
			attachedRoutes:  make(map[types.NamespacedName]struct{}),
			exposure:        exposure,
		}
		envoyPort := publicPort
		if exposure == v1alpha1.ExposurePrivate {
			envoyPort = int32(spec.Port)
		} else {
			publicPort++
		}
		validateListener(in, translated, conformance, envoyPort, out)
		listeners = append(listeners, translated)
	}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			reason := listenerConflictReason(listeners[i].spec, listeners[j].spec)
			if reason == gatewayv1.ListenerReasonNoConflicts {
				continue
			}
			for _, item := range []*listenerTranslation{listeners[i], listeners[j]} {
				item.conflicted = true
				if item.conflictReason == gatewayv1.ListenerReasonNoConflicts || reason == gatewayv1.ListenerReasonProtocolConflict {
					item.conflictReason = reason
				}
				item.accepted = false
				item.acceptedReason = gatewayv1.ListenerReasonUnsupportedValue
				item.acceptedMessage = "listener conflicts with another listener on the same port"
				item.ir = nil
			}
		}
	}

	out.Listeners = make([]ir.Listener, 0, len(listeners))
	out.Domains = make([]ir.ProtectionDomain, 0, len(listeners))
	for _, listener := range listeners {
		if listener.ir == nil || !listener.accepted || listener.conflicted {
			continue
		}
		out.Listeners = append(out.Listeners, *listener.ir)
		out.Domains = append(out.Domains, ir.ProtectionDomain{
			Name:         listener.ir.Name,
			ListenerName: listener.ir.Name,
			EnvoyPort:    listener.ir.EnvoyPort,
			Protected:    listener.protected,
			Guard:        listener.guard,
			VirtualHosts: []ir.VirtualHost{},
		})
	}

	if len(listeners) == 0 {
		return listeners, gatewayv1.GatewayReasonListenersNotValid, "Gateway has no listeners"
	}
	return listeners, gatewayv1.GatewayReasonAccepted, "Gateway accepted"
}

func validateListener(in Inputs, translated *listenerTranslation, conformance bool, cloudflarePort int32, out *ir.Gateway) {
	listener := translated.spec
	if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
		invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedProtocol, "only HTTP and HTTPS listeners are supported")
		return
	}
	if !conformance {
		if listener.Hostname == nil || *listener.Hostname == "" {
			invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "listener hostname is required")
			return
		}
		if in.CloudflareTunnel != nil && in.CloudflareAccount != nil {
			decision := authz.Evaluate(in.CloudflareAccount, namespaceByName(in.Namespaces, in.Gateway.Namespace), authz.Request{
				Hostname: string(*listener.Hostname),
				Exposure: translated.exposure,
			})
			if !decision.Allowed {
				invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, decision.Message)
				return
			}
			unprotected := authz.Evaluate(in.CloudflareAccount, namespaceByName(in.Namespaces, in.Gateway.Namespace), authz.Request{
				Hostname:    string(*listener.Hostname),
				Exposure:    translated.exposure,
				Unprotected: true,
			})
			if unprotected.Allowed {
				translated.guard = ir.GuardUnprotected
			} else {
				translated.protected = true
				translated.guard = ir.GuardBlocked
			}
		}
		if translated.exposure == v1alpha1.ExposurePublic &&
			((listener.Protocol == gatewayv1.HTTPProtocolType && listener.Port != 80) ||
				(listener.Protocol == gatewayv1.HTTPSProtocolType && listener.Port != 443)) {
			invalidateListener(translated, gatewayv1.ListenerReasonPortUnavailable, "public HTTP and HTTPS listeners require ports 80 and 443")
			return
		}
	}
	if !validHTTPRouteKinds(listener.AllowedRoutes) {
		translated.resolved = false
		translated.resolvedReason = gatewayv1.ListenerReasonInvalidRouteKinds
		translated.resolvedMessage = "allowedRoutes.kinds contains a kind other than HTTPRoute"
	}

	hostname := ""
	if listener.Hostname != nil {
		hostname = string(*listener.Hostname)
	}
	envoyPort := cloudflarePort
	if conformance {
		envoyPort = int32(listener.Port) + 10000
	}
	binding := ""
	if translated.exposure == v1alpha1.ExposurePrivate {
		binding = listenerBinding(in.CloudflareTunnel, listener.Name)
	}
	translated.ir = &ir.Listener{
		Name:      string(listener.Name),
		Hostname:  hostname,
		Port:      int32(listener.Port),
		EnvoyPort: envoyPort,
		Protocol:  string(listener.Protocol),
		Exposure:  string(translated.exposure),
		Binding:   binding,
	}
	if translated.exposure == v1alpha1.ExposurePrivate && listener.Protocol != gatewayv1.HTTPSProtocolType {
		invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedProtocol, "Private listener requires HTTPS so Envoy can terminate TLS")
		return
	}

	if listener.Protocol == gatewayv1.HTTPProtocolType {
		if listener.TLS != nil {
			invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "HTTP listener must not configure TLS")
		}
		return
	}
	if listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode != gatewayv1.TLSModeTerminate {
		invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "HTTPS listener requires TLS mode Terminate")
		return
	}
	if !conformance {
		if translated.exposure == v1alpha1.ExposurePrivate {
			if listener.TLS == nil || len(listener.TLS.CertificateRefs) == 0 {
				invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "Private HTTPS listener requires certificateRefs")
				return
			}
			if len(listener.TLS.CertificateRefs) != 1 {
				invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "Private HTTPS listener requires exactly one certificateRef")
				return
			}
			if len(listener.TLS.Options) > 0 {
				invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "Private HTTPS listener does not support TLS options")
				return
			}
			ref := listener.TLS.CertificateRefs[0]
			secret, reason, message := resolveListenerSecret(in, ref)
			if secret == nil {
				translated.resolved = false
				translated.resolvedReason = reason
				translated.resolvedMessage = message
				translated.ir = nil
				return
			}
			secretName := "listener-" + string(listener.Name)
			translated.ir.TLS = &ir.TLSRef{Secret: secretName}
			out.Secrets = append(out.Secrets, ir.TLSSecret{
				Name:        secretName,
				Certificate: slices.Clone(secret.Data[corev1.TLSCertKey]),
				PrivateKey:  slices.Clone(secret.Data[corev1.TLSPrivateKeyKey]),
			})
			return
		}
		if listener.TLS == nil {
			return
		}
		if len(listener.TLS.CertificateRefs) > 0 {
			invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "edge-terminated listener must not reference certificates")
			return
		}
		for key, value := range listener.TLS.Options {
			if string(key) != "flareway.bhyoo.com/edge-tls-mode" || (value != "Full" && value != "Strict") {
				invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, fmt.Sprintf("unsupported TLS option %s=%s", key, value))
				return
			}
		}
		return
	}
	if listener.TLS == nil || len(listener.TLS.CertificateRefs) == 0 {
		invalidateListener(translated, gatewayv1.ListenerReasonUnsupportedValue, "HTTPS listener requires certificateRefs in conformance mode")
		return
	}
	ref := listener.TLS.CertificateRefs[0]
	secret, reason, message := resolveListenerSecret(in, ref)
	if secret == nil {
		translated.resolved = false
		translated.resolvedReason = reason
		translated.resolvedMessage = message
		translated.ir = nil
		return
	}
	secretName := "listener-" + string(listener.Name)
	translated.ir.TLS = &ir.TLSRef{Secret: secretName}
	out.Secrets = append(out.Secrets, ir.TLSSecret{
		Name:        secretName,
		Certificate: slices.Clone(secret.Data[corev1.TLSCertKey]),
		PrivateKey:  slices.Clone(secret.Data[corev1.TLSPrivateKeyKey]),
	})
}

func resolveListenerSecret(in Inputs, ref gatewayv1.SecretObjectReference) (*corev1.Secret, gatewayv1.ListenerConditionReason, string) {
	group := ""
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := "Secret"
	if ref.Kind != nil && *ref.Kind != "" {
		kind = string(*ref.Kind)
	}
	if group != "" || kind != "Secret" {
		return nil, gatewayv1.ListenerReasonInvalidCertificateRef, "certificateRef must reference a core Secret"
	}
	namespace := in.Gateway.Namespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}
	if namespace != in.Gateway.Namespace && !IsCrossNamespaceReferencePermitted(
		ReferenceSource{Group: gatewayv1.Group(gatewayGroup), Kind: gatewayv1.Kind("Gateway"), Namespace: gatewayv1.Namespace(in.Gateway.Namespace)},
		ReferenceTarget{Group: "", Kind: "Secret", Namespace: gatewayv1.Namespace(namespace), Name: ref.Name},
		in.ReferenceGrants,
	) {
		return nil, gatewayv1.ListenerReasonRefNotPermitted, fmt.Sprintf("certificate Secret %s/%s is not permitted by a ReferenceGrant", namespace, ref.Name)
	}
	for i := range in.Secrets {
		secret := &in.Secrets[i]
		if secret.Namespace == namespace && secret.Name == string(ref.Name) {
			if secret.Type != corev1.SecretTypeTLS || len(secret.Data[corev1.TLSCertKey]) == 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
				return nil, gatewayv1.ListenerReasonInvalidCertificateRef, fmt.Sprintf("certificate Secret %s/%s is not a valid TLS Secret", namespace, ref.Name)
			}
			if _, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]); err != nil {
				return nil, gatewayv1.ListenerReasonInvalidCertificateRef, fmt.Sprintf("certificate Secret %s/%s contains malformed or mismatched TLS data", namespace, ref.Name)
			}
			return secret, gatewayv1.ListenerReasonResolvedRefs, "references resolved"
		}
	}
	return nil, gatewayv1.ListenerReasonInvalidCertificateRef, fmt.Sprintf("certificate Secret %s/%s was not found", namespace, ref.Name)
}

func compileHTTPRoutes(in Inputs, out *ir.Gateway, listeners []*listenerTranslation, statuses *Statuses, now metav1.Time) {
	domainByListener := make(map[string]*ir.ProtectionDomain, len(out.Domains))
	for i := range out.Domains {
		domainByListener[out.Domains[i].ListenerName] = &out.Domains[i]
	}
	compiledByHost := make(map[string]map[string][]compiledRoute)

	routes := slices.Clone(in.HTTPRoutes)
	slices.SortFunc(routes, func(a, b gatewayv1.HTTPRoute) int {
		if cmp := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	for i := range routes {
		route := &routes[i]
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		replacements := make([]gatewayv1.RouteParentStatus, 0)
		routeCompiled, routeResolvedReason, routeResolvedMessage, allDropped, droppedReason := compileRules(in, route)

		for _, parentRef := range route.Spec.ParentRefs {
			if !parentTargetsGateway(parentRef, route.Namespace, in.Gateway) {
				continue
			}
			targets, outcome := matchingListeners(in, route, parentRef, listeners)
			if outcome.accepted && len(routeCompiled) == 0 && len(allDropped) > 0 {
				outcome.accepted = false
				outcome.acceptedReason = droppedReason
				outcome.message = "all Route rules were dropped"
			}
			for _, listener := range targets {
				if !outcome.accepted {
					continue
				}
				listener.attachedRoutes[key] = struct{}{}
				if listener.ir == nil {
					continue
				}
				hosts := ComputeHosts(route.Spec.Hostnames, listener.spec.Hostname, nil)
				for _, host := range hosts {
					if !listenerClaimsHost(listener, string(host), listeners) {
						continue
					}
					if compiledByHost[listener.ir.Name] == nil {
						compiledByHost[listener.ir.Name] = make(map[string][]compiledRoute)
					}
					compiledByHost[listener.ir.Name][string(host)] = append(compiledByHost[listener.ir.Name][string(host)], routeCompiled...)
				}
			}
			outcome.resolved = routeResolvedReason == gatewayv1.RouteReasonResolvedRefs
			outcome.resolvedReason = routeResolvedReason
			outcome.resolvedMsg = routeResolvedMessage
			outcome.dropped = slices.Clone(allDropped)
			replacements = append(replacements, routeParentStatus(route, parentRef, outcome, now))
		}

		if len(replacements) > 0 || hasOwnedRouteParent(route.Status.Parents) {
			current := *route.Status.DeepCopy()
			for index := range current.Parents {
				if current.Parents[index].ControllerName == ControllerName {
					current.Parents[index].Conditions = status.RemoveCondition(current.Parents[index].Conditions, string(gatewayv1.RouteConditionPartiallyInvalid))
				}
			}
			current.Parents = status.ReplaceRouteParentStatuses(current.Parents, ControllerName, now, replacements...)
			statuses.HTTPRoutes[key] = current
		}
	}

	for listenerName, hosts := range compiledByHost {
		domain := domainByListener[listenerName]
		if domain == nil {
			continue
		}
		hostNames := make([]string, 0, len(hosts))
		for host := range hosts {
			hostNames = append(hostNames, host)
		}
		slices.SortFunc(hostNames, compareHostnames)
		for _, hostname := range hostNames {
			routesForHost := hosts[hostname]
			slices.SortFunc(routesForHost, compareCompiledRoutes)
			virtualHost := ir.VirtualHost{Name: virtualHostName(listenerName, hostname), Hostname: hostname}
			for _, item := range routesForHost {
				virtualHost.Routes = append(virtualHost.Routes, item.route)
			}
			domain.VirtualHosts = append(domain.VirtualHosts, virtualHost)
		}
	}

	if !out.ConformanceMode {
		for domainIndex := range out.Domains {
			domain := &out.Domains[domainIndex]
			listener := listenerByName(out.Listeners, domain.ListenerName)
			if listener == nil || listener.Hostname == "" || hasVirtualHost(domain.VirtualHosts, listener.Hostname) {
				continue
			}
			domain.VirtualHosts = append(domain.VirtualHosts, ir.VirtualHost{
				Name:     virtualHostName(domain.ListenerName, listener.Hostname),
				Hostname: listener.Hostname,
			})
		}
	}
}

func listenerByName(listeners []ir.Listener, name string) *ir.Listener {
	for index := range listeners {
		if listeners[index].Name == name {
			return &listeners[index]
		}
	}
	return nil
}

func hasVirtualHost(hosts []ir.VirtualHost, hostname string) bool {
	for _, host := range hosts {
		if host.Hostname == hostname {
			return true
		}
	}
	return false
}

func matchingListeners(in Inputs, route *gatewayv1.HTTPRoute, parent gatewayv1.ParentReference, listeners []*listenerTranslation) ([]*listenerTranslation, routeOutcome) {
	outcome := routeOutcome{acceptedReason: gatewayv1.RouteReasonAccepted, message: "Route accepted", resolved: true, resolvedReason: gatewayv1.RouteReasonResolvedRefs, resolvedMsg: "references resolved"}
	candidates := make([]*listenerTranslation, 0)
	matchedParent := false
	allowedNamespace := false
	matchedHostname := false
	for _, listener := range listeners {
		if parent.SectionName != nil && *parent.SectionName != listener.spec.Name {
			continue
		}
		if parent.Port != nil && *parent.Port != listener.spec.Port {
			continue
		}
		matchedParent = true
		if !routeNamespaceAllowed(in, listener.spec, route.Namespace) || !listenerAllowsHTTPRoute(listener.spec) {
			continue
		}
		allowedNamespace = true
		if len(ComputeHosts(route.Spec.Hostnames, listener.spec.Hostname, nil)) == 0 {
			continue
		}
		matchedHostname = true
		if listener.accepted && !listener.conflicted {
			candidates = append(candidates, listener)
		}
	}
	switch {
	case len(candidates) > 0:
		outcome.accepted = true
	case !matchedParent:
		outcome.acceptedReason = gatewayv1.RouteReasonNoMatchingParent
		outcome.message = "parentRef sectionName or port does not match a listener"
	case !allowedNamespace:
		outcome.acceptedReason = gatewayv1.RouteReasonNotAllowedByListeners
		outcome.message = "Route namespace or kind is not allowed by the selected listeners"
	case !matchedHostname:
		outcome.acceptedReason = gatewayv1.RouteReasonNoMatchingListenerHostname
		outcome.message = "Route hostnames do not intersect with the selected listeners"
	default:
		outcome.acceptedReason = gatewayv1.RouteReasonNoMatchingParent
		outcome.message = "all selected listeners are invalid"
	}
	return candidates, outcome
}

func parentTargetsGateway(parent gatewayv1.ParentReference, routeNamespace string, gateway *gatewayv1.Gateway) bool {
	group := gatewayGroup
	if parent.Group != nil {
		group = string(*parent.Group)
	}
	kind := "Gateway"
	if parent.Kind != nil {
		kind = string(*parent.Kind)
	}
	namespace := routeNamespace
	if parent.Namespace != nil {
		namespace = string(*parent.Namespace)
	}
	return group == gatewayGroup && kind == "Gateway" && namespace == gateway.Namespace && string(parent.Name) == gateway.Name
}
func hasOwnedRouteParent(parents []gatewayv1.RouteParentStatus) bool {
	for _, parent := range parents {
		if parent.ControllerName == ControllerName {
			return true
		}
	}
	return false
}

func routeNamespaceAllowed(in Inputs, listener gatewayv1.Listener, routeNamespace string) bool {
	from := gatewayv1.NamespacesFromSame
	var selector *metav1.LabelSelector
	if listener.AllowedRoutes != nil && listener.AllowedRoutes.Namespaces != nil {
		if listener.AllowedRoutes.Namespaces.From != nil {
			from = *listener.AllowedRoutes.Namespaces.From
		}
		selector = listener.AllowedRoutes.Namespaces.Selector
	}
	switch from {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return routeNamespace == in.Gateway.Namespace
	case gatewayv1.NamespacesFromSelector:
		if selector == nil {
			return false
		}
		compiled, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return false
		}
		for i := range in.Namespaces {
			if in.Namespaces[i].Name == routeNamespace {
				return compiled.Matches(labels.Set(in.Namespaces[i].Labels))
			}
		}
	}
	return false
}

func listenerAllowsHTTPRoute(listener gatewayv1.Listener) bool {
	if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
		return true
	}
	for _, kind := range listener.AllowedRoutes.Kinds {
		group := gatewayGroup
		if kind.Group != nil {
			group = string(*kind.Group)
		}
		if group == gatewayGroup && kind.Kind == "HTTPRoute" {
			return true
		}
	}
	return false
}

func validHTTPRouteKinds(allowed *gatewayv1.AllowedRoutes) bool {
	if allowed == nil || len(allowed.Kinds) == 0 {
		return true
	}
	for _, kind := range allowed.Kinds {
		group := gatewayGroup
		if kind.Group != nil {
			group = string(*kind.Group)
		}
		if group != gatewayGroup || kind.Kind != "HTTPRoute" {
			return false
		}
	}
	return true
}
func supportedKinds(translated *listenerTranslation) []gatewayv1.RouteGroupKind {
	if translated.spec.Protocol != gatewayv1.HTTPProtocolType && translated.spec.Protocol != gatewayv1.HTTPSProtocolType {
		return nil
	}
	supported := gatewayv1.RouteGroupKind{
		Group: new(gatewayv1.Group(gatewayGroup)),
		Kind:  gatewayv1.Kind("HTTPRoute"),
	}
	if translated.spec.AllowedRoutes == nil || len(translated.spec.AllowedRoutes.Kinds) == 0 {
		return []gatewayv1.RouteGroupKind{supported}
	}
	if listenerAllowsHTTPRoute(translated.spec) {
		return []gatewayv1.RouteGroupKind{supported}
	}
	return nil
}

func listenerClaimsHost(candidate *listenerTranslation, host string, listeners []*listenerTranslation) bool {
	for _, other := range listeners {
		if other == candidate || other.ir == nil || !other.accepted || other.conflicted {
			continue
		}
		if other.spec.Port != candidate.spec.Port || other.spec.Protocol != candidate.spec.Protocol {
			continue
		}
		if !hostnameMatches(other.spec.Hostname, host) {
			continue
		}
		if listenerHostnameSpecificity(other.spec.Hostname) > listenerHostnameSpecificity(candidate.spec.Hostname) {
			return false
		}
	}
	return true
}

func hostnameMatches(listenerHostname *gatewayv1.Hostname, host string) bool {
	if listenerHostname == nil || *listenerHostname == "" {
		return true
	}
	value := string(*listenerHostname)
	if value == host {
		return true
	}
	if strings.HasPrefix(value, "*.") {
		return WildcardHostnameMatchesHostname(*listenerHostname, gatewayv1.Hostname(host))
	}
	return false
}

func listenerHostnameSpecificity(hostname *gatewayv1.Hostname) int {
	if hostname == nil || *hostname == "" {
		return 0
	}
	value := string(*hostname)
	if strings.HasPrefix(value, "*.") {
		return len(value)
	}
	return 10000 + len(value)
}

func listenerConflictReason(a, b gatewayv1.Listener) gatewayv1.ListenerConditionReason {
	if a.Port != b.Port {
		return gatewayv1.ListenerReasonNoConflicts
	}
	if a.Protocol != b.Protocol {
		return gatewayv1.ListenerReasonProtocolConflict
	}
	if a.Hostname == nil || b.Hostname == nil {
		if a.Hostname == nil && b.Hostname == nil {
			return gatewayv1.ListenerReasonHostnameConflict
		}
		return gatewayv1.ListenerReasonNoConflicts
	}
	if *a.Hostname == *b.Hostname {
		return gatewayv1.ListenerReasonHostnameConflict
	}
	return gatewayv1.ListenerReasonNoConflicts
}

func invalidateListener(listener *listenerTranslation, reason gatewayv1.ListenerConditionReason, message string) {
	listener.accepted = false
	listener.acceptedReason = reason
	listener.acceptedMessage = message
	listener.ir = nil
}

func listenerStatus(gateway *gatewayv1.Gateway, translated *listenerTranslation, now metav1.Time) gatewayv1.ListenerStatus {
	var previous []metav1.Condition
	for _, current := range gateway.Status.Listeners {
		if current.Name == translated.spec.Name {
			previous = current.Conditions
			break
		}
	}
	conditions := status.MergeConditions(
		previous,
		now,
		status.NewCondition(string(gatewayv1.ListenerConditionAccepted), conditionStatus(translated.accepted), string(translated.acceptedReason), translated.acceptedMessage, gateway.Generation, now),
		status.NewCondition(string(gatewayv1.ListenerConditionResolvedRefs), conditionStatus(translated.resolved), string(translated.resolvedReason), translated.resolvedMessage, gateway.Generation, now),
		status.NewCondition(string(gatewayv1.ListenerConditionConflicted), conditionStatus(translated.conflicted), string(translated.conflictReason), conflictMessage(translated.conflicted), gateway.Generation, now),
	)
	return gatewayv1.ListenerStatus{
		Name:           translated.spec.Name,
		SupportedKinds: supportedKinds(translated),
		AttachedRoutes: int32(len(translated.attachedRoutes)),
		Conditions:     conditions,
	}
}

func routeParentStatus(route *gatewayv1.HTTPRoute, parent gatewayv1.ParentReference, outcome routeOutcome, now metav1.Time) gatewayv1.RouteParentStatus {
	conditions := []metav1.Condition{
		status.NewCondition(string(gatewayv1.RouteConditionAccepted), conditionStatus(outcome.accepted), string(outcome.acceptedReason), outcome.message, route.Generation, now),
		status.NewCondition(string(gatewayv1.RouteConditionResolvedRefs), conditionStatus(outcome.resolved), string(outcome.resolvedReason), outcome.resolvedMsg, route.Generation, now),
	}
	if outcome.accepted && len(outcome.dropped) > 0 {
		conditions = append(conditions, status.NewCondition(
			string(gatewayv1.RouteConditionPartiallyInvalid),
			metav1.ConditionTrue,
			string(gatewayv1.RouteReasonUnsupportedValue),
			"Dropped Rule: "+strings.Join(outcome.dropped, "; "),
			route.Generation,
			now,
		))
	}
	return gatewayv1.RouteParentStatus{ParentRef: parent, ControllerName: ControllerName, Conditions: conditions}
}

func compareCompiledRoutes(a, b compiledRoute) int {
	if a.route.Match.Type != b.route.Match.Type {
		return pathTypeRank(a.route.Match.Type) - pathTypeRank(b.route.Match.Type)
	}
	if a.route.Match.Type == ir.PathMatchPathPrefix && len(a.route.Match.Value) != len(b.route.Match.Value) {
		return len(b.route.Match.Value) - len(a.route.Match.Value)
	}
	if (a.route.Method != nil) != (b.route.Method != nil) {
		if a.route.Method != nil {
			return -1
		}
		return 1
	}
	if len(a.route.Headers) != len(b.route.Headers) {
		return len(b.route.Headers) - len(a.route.Headers)
	}
	if len(a.route.Query) != len(b.route.Query) {
		return len(b.route.Query) - len(a.route.Query)
	}
	if cmp := a.creation.Compare(b.creation.Time); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(a.objectKey, b.objectKey); cmp != 0 {
		return cmp
	}
	if a.ruleIndex != b.ruleIndex {
		return a.ruleIndex - b.ruleIndex
	}
	return a.matchIndex - b.matchIndex
}

func pathTypeRank(matchType string) int {
	switch matchType {
	case ir.PathMatchExact:
		return 0
	case ir.PathMatchRegularExpression:
		return 1
	default:
		return 2
	}
}

func compareHostnames(a, b string) int {
	aWildcard := strings.HasPrefix(a, "*.")
	bWildcard := strings.HasPrefix(b, "*.")
	if aWildcard != bWildcard {
		if aWildcard {
			return 1
		}
		return -1
	}
	if len(a) != len(b) {
		return len(b) - len(a)
	}
	return strings.Compare(a, b)
}

func virtualHostName(listener, hostname string) string {
	encoded := hex.EncodeToString([]byte(hostname))
	if encoded == "" {
		encoded = "empty"
	}
	return listener + "-" + encoded
}

func finalizeIR(out *ir.Gateway) {
	slices.SortFunc(out.Clusters, func(a, b ir.Cluster) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(out.Secrets, func(a, b ir.TLSSecret) int { return strings.Compare(a.Name, b.Name) })

	for i := range out.Clusters {
		slices.SortFunc(out.Clusters[i].Endpoints, func(a, b ir.Endpoint) int {
			if cmp := strings.Compare(a.Address, b.Address); cmp != 0 {
				return cmp
			}
			return int(a.Port - b.Port)
		})
	}
}
func conditionStatus(value bool) metav1.ConditionStatus {
	if value {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func conflictMessage(conflicted bool) string {
	if conflicted {
		return "listener conflicts with another listener"
	}
	return "no listener conflicts"
}
